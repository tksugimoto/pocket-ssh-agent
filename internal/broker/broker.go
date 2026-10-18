// Package broker holds sign requests while they wait for a decision from
// the phone.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	// ErrDenied is returned when the user rejects a request on the phone.
	ErrDenied = errors.New("request denied on phone")
	// ErrTimeout is returned when nobody answers in time.
	ErrTimeout = errors.New("no answer from phone before timeout")
	// ErrNotFound is returned by Resolve for unknown or finished requests.
	ErrNotFound = errors.New("request not found")
	// ErrTooMany is returned when too many requests are already pending.
	ErrTooMany = errors.New("too many pending requests")
)

// MaxPending bounds the number of requests waiting for the phone.
const MaxPending = 8

// Submission describes a new sign request.
type Submission struct {
	Kind string
	Data []byte
	// ClaimedHostKey is the server host key reported by the SSH client via
	// the session-bind extension, if any.
	ClaimedHostKey []byte
	// Forwarded is set when the request arrived over a forwarded agent
	// connection, i.e. it comes from a remote host.
	Forwarded bool
}

// Request is a pending sign request.
type Request struct {
	ID   string
	Kind string
	Data []byte
	// ClaimedHostKey is the server host key reported by the SSH client via
	// the session-bind extension, if any. It is supplied by the PC and is
	// therefore informational only.
	ClaimedHostKey []byte
	Forwarded      bool
	CreatedAt      time.Time
	ExpiresAt      time.Time

	result chan Result
}

// Result is the phone's answer.
type Result struct {
	Signature []byte
	Denied    bool
}

// Broker tracks pending requests. The zero value is not usable; use New.
type Broker struct {
	mu      sync.Mutex
	pending map[string]*Request
	changed chan struct{} // closed and replaced whenever pending changes
	now     func() time.Time
}

// New returns an empty Broker.
func New() *Broker {
	return &Broker{
		pending: make(map[string]*Request),
		changed: make(chan struct{}),
		now:     time.Now,
	}
}

// notifyLocked wakes everybody waiting in Wait. b.mu must be held.
func (b *Broker) notifyLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// Submit registers a request and blocks until the phone answers, the
// timeout elapses or ctx is done. It returns the raw signature on approval.
func (b *Broker) Submit(ctx context.Context, sub Submission, timeout time.Duration) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	now := b.now()
	req := &Request{
		ID:             hex.EncodeToString(id),
		Kind:           sub.Kind,
		Data:           append([]byte(nil), sub.Data...),
		ClaimedHostKey: append([]byte(nil), sub.ClaimedHostKey...),
		Forwarded:      sub.Forwarded,
		CreatedAt:      now,
		ExpiresAt:      now.Add(timeout),
		result:         make(chan Result, 1),
	}

	b.mu.Lock()
	if len(b.pending) >= MaxPending {
		b.mu.Unlock()
		return nil, ErrTooMany
	}
	b.pending[req.ID] = req
	b.notifyLocked()
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		if _, ok := b.pending[req.ID]; ok {
			delete(b.pending, req.ID)
			b.notifyLocked()
		}
		b.mu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-req.result:
		if res.Denied {
			return nil, ErrDenied
		}
		return res.Signature, nil
	case <-timer.C:
		return nil, ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Get returns a pending request by ID.
func (b *Broker) Get(id string) (*Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.pending[id]
	return r, ok
}

// Pending returns the pending requests, oldest first.
func (b *Broker) Pending() []*Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pendingLocked()
}

func (b *Broker) pendingLocked() []*Request {
	out := make([]*Request, 0, len(b.pending))
	for _, r := range b.pending {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Wait blocks until the set of pending request IDs differs from known, maxWait
// elapses or ctx is done, and then returns the current pending requests.
// This lets a long-polling client sleep while it already shows every request.
func (b *Broker) Wait(ctx context.Context, maxWait time.Duration, known map[string]bool) []*Request {
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	for {
		b.mu.Lock()
		reqs := b.pendingLocked()
		changed := b.changed
		b.mu.Unlock()
		if !sameIDs(reqs, known) {
			return reqs
		}
		select {
		case <-changed:
		case <-timer.C:
			return reqs
		case <-ctx.Done():
			return reqs
		}
	}
}

func sameIDs(reqs []*Request, known map[string]bool) bool {
	if len(reqs) != len(known) {
		return false
	}
	for _, r := range reqs {
		if !known[r.ID] {
			return false
		}
	}
	return true
}

// Resolve delivers the phone's answer for a pending request. The caller is
// responsible for verifying the signature before calling Resolve.
func (b *Broker) Resolve(id string, res Result) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.pending[id]
	if !ok {
		return ErrNotFound
	}
	delete(b.pending, id)
	b.notifyLocked()
	req.result <- res // buffered, never blocks
	return nil
}
