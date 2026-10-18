package httpapi_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/tksugimoto/pocket-ssh-agent/internal/broker"
	"github.com/tksugimoto/pocket-ssh-agent/internal/config"
	"github.com/tksugimoto/pocket-ssh-agent/internal/httpapi"
	"github.com/tksugimoto/pocket-ssh-agent/internal/sshagent"
)

const origin = "https://pwa.example"

var b64url = base64.RawURLEncoding

type env struct {
	t      *testing.T
	api    *httpapi.Server
	agent  *sshagent.Agent
	http   *httptest.Server
	priv   ed25519.PrivateKey
	sshPub ssh.PublicKey
	secret []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := broker.New()
	api := &httpapi.Server{Store: store, Broker: b, AllowedOrigin: origin, PCName: "test-pc"}
	hs := httptest.NewServer(api.Handler())
	t.Cleanup(hs.Close)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	return &env{
		t: t, api: api, http: hs, priv: priv, sshPub: sshPub,
		agent: &sshagent.Agent{Store: store, Broker: b, Timeout: 5 * time.Second},
	}
}

// client opens a new SSH agent connection.
func (e *env) client() (agent.ExtendedAgent, func()) {
	c1, c2 := net.Pipe()
	go e.agent.ServeConn(c1)
	return agent.NewClient(c2).(agent.ExtendedAgent), func() { c2.Close() }
}

func authHeader(key []byte, method, uri string, t int64, body []byte) string {
	h := sha256.Sum256(body)
	n := make([]byte, 16)
	rand.Read(n)
	nonce := b64url.EncodeToString(n)
	m := httpapi.Mac(key, "pocket-ssh-agent auth v1", method, uri, strconv.FormatInt(t, 10), nonce, b64url.EncodeToString(h[:]))
	return fmt.Sprintf("PSA-HMAC t=%d,n=%s,m=%s", t, nonce, b64url.EncodeToString(m))
}

type reqOpts struct {
	header string // explicit Authorization header
	noAuth bool
	origin string
}

func (e *env) do(method, path string, body any, o reqOpts) (*http.Response, []byte) {
	e.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, e.http.URL+path, bytes.NewReader(raw))
	if o.origin != "" {
		req.Header.Set("Origin", o.origin)
	} else {
		req.Header.Set("Origin", origin)
	}
	switch {
	case o.header != "":
		req.Header.Set("Authorization", o.header)
	case !o.noAuth && e.secret != nil:
		req.Header.Set("Authorization", authHeader(e.secret, method, req.URL.RequestURI(), time.Now().Unix(), raw))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (e *env) pair() {
	e.t.Helper()
	code, err := e.api.StartPairing(time.Minute)
	if err != nil {
		e.t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(e.sshPub))
	resp, body := e.do("POST", "/v1/pair", map[string]string{"code": code, "publicKey": pubLine, "deviceName": "phone"}, reqOpts{noAuth: true})
	if resp.StatusCode != 200 {
		e.t.Fatalf("pair: %d %s", resp.StatusCode, body)
	}
	var pr struct{ Secret, PCName, Proof string }
	json.Unmarshal(body, &pr)
	proof, _ := b64url.DecodeString(pr.Proof)
	want := httpapi.Mac([]byte(code), "pocket-ssh-agent pair v1", pr.Secret, pubLine, pr.PCName)
	if pr.PCName != "test-pc" || !hmac.Equal(proof, want) {
		e.t.Fatalf("pair response does not prove knowledge of the code: %s", body)
	}
	e.secret, _ = b64url.DecodeString(pr.Secret)
	if len(e.secret) != 32 {
		e.t.Fatalf("secret length %d", len(e.secret))
	}

	// The code is single use.
	resp, _ = e.do("POST", "/v1/pair", map[string]string{"code": code, "publicKey": pubLine}, reqOpts{noAuth: true})
	if resp.StatusCode != http.StatusForbidden {
		e.t.Fatalf("reused pairing code: %d", resp.StatusCode)
	}
}

type wireReq struct {
	ID, Kind, Data, ClaimedHostKey, ExpiresAt, Mac string
	Forwarded                                      bool
}

func (e *env) poll(wait int) []wireReq {
	e.t.Helper()
	resp, body := e.do("GET", "/v1/requests?wait="+strconv.Itoa(wait), nil, reqOpts{})
	if resp.StatusCode != 200 {
		e.t.Fatalf("poll: %d %s", resp.StatusCode, body)
	}
	var rr struct{ Requests []wireReq }
	json.Unmarshal(body, &rr)
	for _, r := range rr.Requests {
		fwd := "0"
		if r.Forwarded {
			fwd = "1"
		}
		want := httpapi.Mac(e.secret, "pocket-ssh-agent request v1", r.ID, r.Kind, r.Data, r.ClaimedHostKey, fwd, r.ExpiresAt)
		got, _ := b64url.DecodeString(r.Mac)
		if !hmac.Equal(got, want) {
			e.t.Errorf("request MAC does not verify: %+v", r)
		}
	}
	return rr.Requests
}

// phone answers the next request with fn.
func (e *env) phone(fn func(r wireReq, data []byte) map[string]any) <-chan error {
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 50; i++ {
			reqs := e.poll(1)
			if len(reqs) == 0 {
				continue
			}
			data, _ := base64.StdEncoding.DecodeString(reqs[0].Data)
			resp, body := e.do("POST", "/v1/requests/"+reqs[0].ID, fn(reqs[0], data), reqOpts{})
			if resp.StatusCode != http.StatusNoContent {
				done <- fmt.Errorf("answer: %d %s", resp.StatusCode, body)
				return
			}
			done <- nil
			return
		}
		done <- errors.New("no request arrived")
	}()
	return done
}

func str(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }

func userAuthData(pub ssh.PublicKey, session string) []byte {
	var b []byte
	b = append(b, str([]byte(session))...)
	b = append(b, 50)
	b = append(b, str([]byte("git"))...)
	b = append(b, str([]byte("ssh-connection"))...)
	b = append(b, str([]byte("publickey"))...)
	b = append(b, 1)
	b = append(b, str([]byte(pub.Type()))...)
	b = append(b, str(pub.Marshal())...)
	return b
}

func sessionBind(t *testing.T, sessionID string, forwarding bool) ([]byte, ssh.PublicKey) {
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hostPriv)
	sig, err := signer.Sign(rand.Reader, []byte(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Forwarding                    bool
	}{signer.PublicKey().Marshal(), []byte(sessionID), ssh.Marshal(sig), forwarding}), signer.PublicKey()
}

func TestUnpaired(t *testing.T) {
	e := newEnv(t)
	c, done := e.client()
	defer done()
	keys, err := c.List()
	if err != nil || len(keys) != 0 {
		t.Fatalf("List before pairing = %v, %v", keys, err)
	}
	resp, _ := e.do("GET", "/v1/requests", nil, reqOpts{header: "PSA-HMAC t=1,m=x"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("requests without pairing: %d", resp.StatusCode)
	}
}

func TestApproveDenyAndBadSignature(t *testing.T) {
	e := newEnv(t)
	e.pair()
	c, closeConn := e.client()
	defer closeConn()

	keys, err := c.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, e.sshPub.Marshal()) {
		t.Fatalf("List = %v, %v", keys, err)
	}
	data := userAuthData(e.sshPub, "session-1")

	// Approve.
	done := e.phone(func(r wireReq, d []byte) map[string]any {
		if r.Kind != "ssh-userauth" || !bytes.Equal(d, data) || r.Forwarded {
			t.Errorf("unexpected request %+v", r)
		}
		return map[string]any{"decision": "approve", "signature": ed25519.Sign(e.priv, d)}
	})
	sig, err := c.Sign(e.sshPub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := e.sshPub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	// Deny.
	done = e.phone(func(wireReq, []byte) map[string]any { return map[string]any{"decision": "deny"} })
	if _, err := c.Sign(e.sshPub, data); err == nil {
		t.Fatal("expected error after deny")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A wrong signature is rejected and the request stays pending.
	errc := make(chan error, 1)
	go func() { _, err := c.Sign(e.sshPub, data); errc <- err }()
	var id string
	for id == "" {
		if reqs := e.poll(1); len(reqs) > 0 {
			id = reqs[0].ID
		}
	}
	bad := ed25519.Sign(e.priv, []byte("something else"))
	resp, _ := e.do("POST", "/v1/requests/"+id, map[string]any{"decision": "approve", "signature": bad}, reqOpts{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad signature accepted: %d", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/v1/requests/"+id, map[string]any{"decision": "approve", "signature": ed25519.Sign(e.priv, data)}, reqOpts{})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("good signature after bad: %d", resp.StatusCode)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestRejectsArbitraryAndOversizedData(t *testing.T) {
	e := newEnv(t)
	e.pair()
	c, closeConn := e.client()
	defer closeConn()
	if _, err := c.Sign(e.sshPub, []byte("transfer $1000 to mallory")); err == nil {
		t.Fatal("arbitrary data was forwarded")
	}
	if _, err := c.Sign(e.sshPub, userAuthData(e.sshPub, string(make([]byte, 5000)))); err == nil {
		t.Fatal("oversized data was forwarded")
	}
	if len(e.api.Broker.Pending()) != 0 {
		t.Fatal("rejected data reached the broker")
	}
}

func TestDisconnectWithdrawsRequest(t *testing.T) {
	e := newEnv(t)
	e.pair()
	c, closeConn := e.client()
	go c.Sign(e.sshPub, userAuthData(e.sshPub, "session-1"))
	for len(e.api.Broker.Pending()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	closeConn()
	deadline := time.Now().Add(2 * time.Second)
	for len(e.api.Broker.Pending()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("request still pending after the client disconnected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSessionBind(t *testing.T) {
	e := newEnv(t)
	e.pair()

	// Local connection: the bound host key is passed to the phone.
	c, closeConn := e.client()
	defer closeConn()
	bind, hostKey := sessionBind(t, "session-1", false)
	if _, err := c.Extension("session-bind@openssh.com", bind); err != nil {
		t.Fatal(err)
	}
	// A connection bound for authentication cannot be bound again.
	again, _ := sessionBind(t, "session-2", false)
	if _, err := c.Extension("session-bind@openssh.com", again); err == nil {
		t.Fatal("second binding accepted")
	}
	done := e.phone(func(r wireReq, _ []byte) map[string]any {
		if r.ClaimedHostKey != base64.StdEncoding.EncodeToString(hostKey.Marshal()) || r.Forwarded {
			t.Errorf("request = %+v", r)
		}
		return map[string]any{"decision": "deny"}
	})
	c.Sign(e.sshPub, userAuthData(e.sshPub, "session-1"))
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A binding whose host signature does not verify is rejected.
	c2, close2 := e.client()
	defer close2()
	forged, _ := sessionBind(t, "session-3", false)
	forged[len(forged)-10] ^= 1 // corrupt the signature
	if _, err := c2.Extension("session-bind@openssh.com", forged); err == nil {
		t.Fatal("forged binding accepted")
	}

	// Forwarded connection: requests are flagged.
	c3, close3 := e.client()
	defer close3()
	fwd, _ := sessionBind(t, "session-4", true)
	if _, err := c3.Extension("session-bind@openssh.com", fwd); err != nil {
		t.Fatal(err)
	}
	done = e.phone(func(r wireReq, _ []byte) map[string]any {
		if !r.Forwarded {
			t.Errorf("forwarded request not flagged: %+v", r)
		}
		return map[string]any{"decision": "deny"}
	})
	c3.Sign(e.sshPub, userAuthData(e.sshPub, "remote-session"))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPendingLimit(t *testing.T) {
	e := newEnv(t)
	e.pair()
	errs := make(chan error, broker.MaxPending+1)
	for i := 0; i < broker.MaxPending; i++ {
		c, closeConn := e.client()
		defer closeConn()
		go func() { _, err := c.Sign(e.sshPub, userAuthData(e.sshPub, "s")); errs <- err }()
	}
	for len(e.api.Broker.Pending()) < broker.MaxPending {
		time.Sleep(10 * time.Millisecond)
	}
	c, closeConn := e.client()
	defer closeConn()
	if _, err := c.Sign(e.sshPub, userAuthData(e.sshPub, "s")); err == nil {
		t.Fatal("request beyond the limit accepted")
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	e.pair()
	uri := "/v1/requests"
	now := time.Now().Unix()

	check := func(name, header string, want int) {
		t.Helper()
		resp, body := e.do("GET", uri, nil, reqOpts{header: header})
		if resp.StatusCode != want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	good := authHeader(e.secret, "GET", uri, now, nil)
	check("valid", good, 200)
	check("replay", good, 401)
	check("wrong key", authHeader(bytes.Repeat([]byte{1}, 32), "GET", uri, now, nil), 401)
	check("wrong path", authHeader(e.secret, "GET", "/v1/requests?wait=1", now, nil), 401)
	check("old timestamp", authHeader(e.secret, "GET", uri, now-600, nil), 401)
	check("bearer token", "Bearer "+b64url.EncodeToString(e.secret), 401)
	check("garbage", "PSA-HMAC t=x,m=y", 401)

	// The body is covered by the MAC.
	c, closeConn := e.client()
	defer closeConn()
	go c.Sign(e.sshPub, userAuthData(e.sshPub, "s"))
	var id string
	for id == "" {
		if reqs := e.poll(1); len(reqs) > 0 {
			id = reqs[0].ID
		}
	}
	signed, _ := json.Marshal(map[string]any{"decision": "deny"})
	h := authHeader(e.secret, "POST", "/v1/requests/"+id, time.Now().Unix(), signed)
	resp, _ := e.do("POST", "/v1/requests/"+id, map[string]any{"decision": "approve", "signature": ed25519.Sign(e.priv, []byte("x"))}, reqOpts{header: h})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("body swap accepted: %d", resp.StatusCode)
	}
}

func TestOriginAndPreflight(t *testing.T) {
	e := newEnv(t)
	e.pair()
	resp, _ := e.do("GET", "/v1/requests", nil, reqOpts{})
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != origin {
		t.Fatalf("status %d, ACAO %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp, _ = e.do("GET", "/v1/requests", nil, reqOpts{origin: "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", resp.StatusCode)
	}

	u, _ := url.Parse(e.http.URL + "/v1/requests")
	req := &http.Request{Method: "OPTIONS", URL: u, Header: http.Header{
		"Origin":                                 {origin},
		"Access-Control-Request-Private-Network": {"true"},
	}}
	r3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != http.StatusNoContent || r3.Header.Get("Access-Control-Allow-Private-Network") != "true" ||
		r3.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
		t.Fatalf("preflight: %d %v", r3.StatusCode, r3.Header)
	}
}

func TestPairingValidation(t *testing.T) {
	e := newEnv(t)
	code, _ := e.api.StartPairing(time.Minute)
	key := string(ssh.MarshalAuthorizedKey(e.sshPub))
	for i := 0; i < 10; i++ {
		resp, _ := e.do("POST", "/v1/pair", map[string]string{"code": "guess", "publicKey": key}, reqOpts{noAuth: true})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("guess %d: %d", i, resp.StatusCode)
		}
	}
	// A bad key does not consume the code.
	resp, _ := e.do("POST", "/v1/pair", map[string]string{"code": code, "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC"}, reqOpts{noAuth: true})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-ed25519 key: %d", resp.StatusCode)
	}
	resp, body := e.do("POST", "/v1/pair", map[string]string{"code": code, "publicKey": key, "deviceName": "\x1b[31mi\u202ePhone\n"}, reqOpts{noAuth: true})
	if resp.StatusCode != 200 {
		t.Fatalf("pairing after wrong guesses failed: %d %s", resp.StatusCode, body)
	}
	// The device name ends up in terminals (ssh-add -l), so control
	// characters are dropped.
	if p, _ := e.api.Store.Pairing(); p.DeviceName != "[31miPhone" {
		t.Fatalf("device name not sanitized: %q", p.DeviceName)
	}
}

func TestExpiredPairingCode(t *testing.T) {
	e := newEnv(t)
	code, _ := e.api.StartPairing(-time.Second)
	key := string(ssh.MarshalAuthorizedKey(e.sshPub))
	resp, _ := e.do("POST", "/v1/pair", map[string]string{"code": code, "publicKey": key}, reqOpts{noAuth: true})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired code: %d", resp.StatusCode)
	}
}
