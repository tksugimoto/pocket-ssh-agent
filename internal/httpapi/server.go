// Package httpapi is the HTTP API the phone's PWA talks to.
//
// The server listens on loopback only and is exposed to the tailnet with
// "tailscale serve", which terminates TLS with a valid certificate.
//
// Endpoints (all JSON):
//
//	POST /v1/pair              {code, publicKey, deviceName} -> {secret, pcName, proof}
//	GET  /v1/requests?wait=N&known=id,id
//	                           long poll until the pending set differs from
//	                           "known" -> {requests: [...], serverTime}
//	POST /v1/requests/{id}     {decision: "approve"|"deny", signature}
//
// # Authentication
//
// Pairing hands the phone a random 32-byte secret K. The secret then never
// travels again; both directions are authenticated with HMAC-SHA256 under K
// (see Mac for the exact message layout):
//
//   - The phone signs every request:
//     "Authorization: PSA-HMAC t=<unix>,n=<nonce>,m=<mac>" over the method,
//     request URI, timestamp, nonce and body hash. Replays are rejected.
//   - The agent signs every sign request it hands out, and the phone drops
//     requests whose MAC does not verify.
//
// So a process that squats the loopback port while the agent is not
// running learns nothing reusable and cannot feed requests to the phone.
// The pairing response carries a proof made with the one-time pairing code,
// which only the real agent knows.
package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/tksugimoto/pocket-ssh-agent/internal/broker"
	"github.com/tksugimoto/pocket-ssh-agent/internal/config"
)

const (
	maxBody          = 16 << 10
	maxWaitSeconds   = 25
	maxKnown         = 64
	pairingCodeBytes = 16
	secretBytes      = 32
	maxClockSkew     = 2 * time.Minute

	authScheme = "PSA-HMAC "

	labelPair = "pocket-ssh-agent pair v1"
	labelAuth = "pocket-ssh-agent auth v1"
	labelReq  = "pocket-ssh-agent request v1"
)

// Mac returns HMAC-SHA256(key, label || "\n" || part1 || "\n" || ...).
// The PWA computes the same values (web/lib/protocol.js).
func Mac(key []byte, label string, parts ...string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	for _, p := range parts {
		h.Write([]byte{'\n'})
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

var b64url = base64.RawURLEncoding

// Server serves the phone API.
type Server struct {
	Store  *config.Store
	Broker *broker.Broker
	// AllowedOrigin is the exact origin of the PWA, e.g.
	// "https://example.github.io". Browser requests from any other origin are
	// rejected.
	AllowedOrigin string
	PCName        string
	Log           *log.Logger
	// OnPaired is called after a successful pairing.
	OnPaired func(*config.Pairing)

	mu          sync.Mutex
	pairCode    string
	pairExpires time.Time
	seenNonces  map[string]time.Time // replay protection for auth headers
}

// StartPairing creates a one-time pairing code valid for ttl and returns it.
// Any previous code is invalidated.
func (s *Server) StartPairing(ttl time.Duration) (string, error) {
	b := make([]byte, pairingCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := b64url.EncodeToString(b)
	s.mu.Lock()
	s.pairCode, s.pairExpires = code, time.Now().Add(ttl)
	s.mu.Unlock()
	return code, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/pair", s.handlePair)
	mux.HandleFunc("GET /v1/requests", s.auth(s.handleRequests))
	mux.HandleFunc("POST /v1/requests/{id}", s.auth(s.handleAnswer))
	return s.cors(mux)
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if origin != "" {
			if origin != s.AllowedOrigin {
				writeError(w, http.StatusForbidden, "origin_not_allowed", "origin not allowed")
				return
			}
			h.Set("Access-Control-Allow-Origin", origin)
		}
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
				h.Set("Access-Control-Allow-Private-Network", "true")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth verifies the phone's HMAC Authorization header. It reads the body
// (bounded) to hash it and makes it available to next again.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := s.Store.Secret()
		if key == nil {
			writeError(w, http.StatusUnauthorized, "not_paired", "not paired")
			return
		}
		t, nonce, mac, ok := parseAuth(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "bad_auth", "missing or malformed Authorization")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		bodyHash := sha256.Sum256(body)
		want := Mac(key, labelAuth, r.Method, r.URL.RequestURI(), strconv.FormatInt(t, 10), nonce, b64url.EncodeToString(bodyHash[:]))
		if !hmac.Equal(mac, want) {
			writeError(w, http.StatusUnauthorized, "bad_auth", "not paired with this PC")
			return
		}
		now := time.Now()
		if d := now.Sub(time.Unix(t, 0)); d > maxClockSkew || d < -maxClockSkew {
			writeError(w, http.StatusUnauthorized, "clock_skew", "phone and PC clocks differ too much")
			return
		}
		if !s.markSeen(nonce, now) {
			writeError(w, http.StatusUnauthorized, "replay", "replayed request")
			return
		}
		next(w, r)
	}
}

func parseAuth(h string) (t int64, nonce string, mac []byte, ok bool) {
	rest, found := strings.CutPrefix(h, authScheme)
	if !found {
		return 0, "", nil, false
	}
	var ts, m string
	for _, kv := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		switch k {
		case "t":
			ts = v
		case "n":
			nonce = v
		case "m":
			m = v
		}
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return 0, "", nil, false
	}
	mac, err = b64url.DecodeString(m)
	if err != nil || len(mac) != sha256.Size {
		return 0, "", nil, false
	}
	return t, nonce, mac, true
}

// markSeen records a nonce and reports whether it is new. Entries older
// than the allowed clock skew are dropped, since they would be rejected by
// the timestamp check anyway.
func (s *Server) markSeen(nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenNonces == nil {
		s.seenNonces = make(map[string]time.Time)
	}
	for k, at := range s.seenNonces {
		if now.Sub(at) > 2*maxClockSkew {
			delete(s.seenNonces, k)
		}
	}
	if _, dup := s.seenNonces[nonce]; dup {
		return false
	}
	s.seenNonces[nonce] = now
	return true
}

type pairRequest struct {
	Code       string `json:"code"`
	PublicKey  string `json:"publicKey"`
	DeviceName string `json:"deviceName"`
}

type pairResponse struct {
	Secret string `json:"secret"`
	PCName string `json:"pcName"`
	// Proof is Mac(code, labelPair, secret, publicKey, pcName): it shows the
	// phone that this response comes from the agent that showed the code.
	Proof string `json:"proof"`
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	var req pairRequest
	if !decode(w, r, &req) {
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil || pub.Type() != ssh.KeyAlgoED25519 {
		writeError(w, http.StatusBadRequest, "bad_key", "publicKey must be an ssh-ed25519 key")
		return
	}
	if ok, expired := s.consumePairingCode(req.Code); !ok {
		if expired {
			s.logf("pairing failed: the pairing code has expired; restart the agent with -pair for a new one")
		}
		writeError(w, http.StatusForbidden, "bad_code", "invalid or expired pairing code")
		return
	}
	k := make([]byte, secretBytes)
	if _, err := rand.Read(k); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	secret := b64url.EncodeToString(k)
	p := &config.Pairing{
		PublicKey:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Secret:     secret,
		DeviceName: printable(truncate(req.DeviceName, 64)),
		PairedAt:   time.Now().UTC(),
	}
	if err := s.Store.SetPairing(p); err != nil {
		s.logf("saving pairing: %v", err)
		writeError(w, http.StatusInternalServerError, "internal", "could not save pairing")
		return
	}
	s.logf("paired with %q", p.DeviceName)
	if s.OnPaired != nil {
		s.OnPaired(p)
	}
	proof := Mac([]byte(req.Code), labelPair, secret, req.PublicKey, s.PCName)
	writeJSON(w, pairResponse{Secret: secret, PCName: s.PCName, Proof: b64url.EncodeToString(proof)})
}

// consumePairingCode checks code against the active pairing code. A correct
// code is single-use. The code has 128 bits of entropy, so wrong guesses
// are not rate limited (which would only let others cancel pairing).
// expired reports that a pairing code was issued but is no longer valid.
func (s *Server) consumePairingCode(code string) (ok, expired bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairCode == "" {
		return false, false
	}
	if time.Now().After(s.pairExpires) {
		return false, true
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(s.pairCode)) != 1 {
		return false, false
	}
	s.pairCode = ""
	return true, false
}

type wireRequest struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Data           string    `json:"data"`                     // base64 (standard)
	ClaimedHostKey string    `json:"claimedHostKey,omitempty"` // base64 (standard)
	Forwarded      bool      `json:"forwarded"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      string    `json:"expiresAt"` // RFC 3339
	// Mac authenticates the fields the phone acts on (see requestMac).
	Mac string `json:"mac"`
}

func requestMac(key []byte, q wireRequest) string {
	fwd := "0"
	if q.Forwarded {
		fwd = "1"
	}
	return b64url.EncodeToString(Mac(key, labelReq, q.ID, q.Kind, q.Data, q.ClaimedHostKey, fwd, q.ExpiresAt))
}

type requestsResponse struct {
	Requests   []wireRequest `json:"requests"`
	ServerTime time.Time     `json:"serverTime"`
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	wait := 0
	if v := q.Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "bad wait")
			return
		}
		wait = min(n, maxWaitSeconds)
	}
	// "known" lists the request IDs the phone already shows; the long poll
	// returns as soon as the pending set differs from it.
	known := map[string]bool{}
	if v := q.Get("known"); v != "" {
		ids := strings.Split(v, ",")
		if len(ids) > maxKnown {
			writeError(w, http.StatusBadRequest, "bad_request", "too many known IDs")
			return
		}
		for _, id := range ids {
			known[id] = true
		}
	}
	var reqs []*broker.Request
	if wait > 0 {
		reqs = s.Broker.Wait(r.Context(), time.Duration(wait)*time.Second, known)
	} else {
		reqs = s.Broker.Pending()
	}
	key := s.Store.Secret()
	out := requestsResponse{Requests: []wireRequest{}, ServerTime: time.Now().UTC()}
	for _, p := range reqs {
		wr := wireRequest{
			ID:        p.ID,
			Kind:      p.Kind,
			Data:      base64.StdEncoding.EncodeToString(p.Data),
			Forwarded: p.Forwarded,
			CreatedAt: p.CreatedAt.UTC(),
			ExpiresAt: p.ExpiresAt.UTC().Format(time.RFC3339Nano),
		}
		if len(p.ClaimedHostKey) > 0 {
			wr.ClaimedHostKey = base64.StdEncoding.EncodeToString(p.ClaimedHostKey)
		}
		wr.Mac = requestMac(key, wr)
		out.Requests = append(out.Requests, wr)
	}
	writeJSON(w, out)
}

type answerRequest struct {
	Decision  string `json:"decision"`
	Signature []byte `json:"signature"` // base64 (standard), raw Ed25519 signature
}

func (s *Server) handleAnswer(w http.ResponseWriter, r *http.Request) {
	var req answerRequest
	if !decode(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	pending, ok := s.Broker.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "request not found or already finished")
		return
	}
	var res broker.Result
	switch req.Decision {
	case "deny":
		res.Denied = true
	case "approve":
		_, pub := s.Store.Pairing()
		edPub, ok := pub.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
		if !ok || len(req.Signature) != ed25519.SignatureSize || !ed25519.Verify(edPub, pending.Data, req.Signature) {
			writeError(w, http.StatusBadRequest, "bad_signature", "signature does not verify")
			return
		}
		res.Signature = req.Signature
	default:
		writeError(w, http.StatusBadRequest, "bad_request", `decision must be "approve" or "deny"`)
		return
	}
	if err := s.Broker.Resolve(id, res); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "request not found or already finished")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log.Printf(format, args...)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "body too large")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code})
}

// printable drops control and other non-printable characters (escape
// sequences, bidi overrides), since the device name ends up in terminals,
// e.g. in the key comment shown by "ssh-add -l".
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
