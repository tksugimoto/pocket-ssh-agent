// Package sshagent implements an SSH agent whose only key lives on the
// phone. Every signature is forwarded to the phone and waits for approval.
package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/tksugimoto/pocket-ssh-agent/internal/broker"
	"github.com/tksugimoto/pocket-ssh-agent/internal/config"
	"github.com/tksugimoto/pocket-ssh-agent/internal/signreq"
)

const (
	extSessionBind = "session-bind@openssh.com"
	// maxSessionBinds matches OpenSSH's AGENT_MAX_SESSION_IDS.
	maxSessionBinds = 16
	// maxSignData bounds the data forwarded to the phone. Userauth requests
	// and SSHSIG blobs for an Ed25519 key are a few hundred bytes.
	maxSignData = 4096
)

var errReadOnly = errors.New("pocket-ssh-agent: keys are managed on the phone")

// Agent holds the shared state. Each client connection is served by
// ServeConn, which keeps per-connection state such as session bindings.
type Agent struct {
	Store   *config.Store
	Broker  *broker.Broker
	Timeout time.Duration
	Log     *log.Logger
}

// ServeConn serves one SSH agent connection until it is closed. A pending
// sign request is withdrawn from the phone as soon as the client
// disconnects (for example when the user presses Ctrl-C).
func (a *Agent) ServeConn(c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read the connection in a separate goroutine so that EOF is noticed
	// while ServeAgent is blocked waiting for the phone.
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, c)
		cancel()
		pw.CloseWithError(err)
	}()
	ca := &connAgent{Agent: a, ctx: ctx}
	_ = agent.ServeAgent(ca, struct {
		io.Reader
		io.Writer
	}{pr, c})
}

type binding struct {
	sessionID []byte
	hostKey   []byte
	forwarded bool
}

// connAgent implements agent.ExtendedAgent for one connection.
type connAgent struct {
	*Agent
	ctx context.Context

	mu    sync.Mutex
	binds []binding
}

var _ agent.ExtendedAgent = (*connAgent)(nil)

// List returns the phone's key, if paired.
func (a *connAgent) List() ([]*agent.Key, error) {
	p, pub := a.Store.Pairing()
	if pub == nil {
		return nil, nil
	}
	comment := "pocket-ssh-agent"
	if p.DeviceName != "" {
		comment += " (" + p.DeviceName + ")"
	}
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: comment}}, nil
}

// Sign forwards the request to the phone.
func (a *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags forwards the request to the phone. Flags only affect RSA
// keys and are ignored.
func (a *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	_, pub := a.Store.Pairing()
	if pub == nil {
		return nil, errors.New("pocket-ssh-agent: not paired with a phone")
	}
	blob := pub.Marshal()
	if !bytes.Equal(key.Marshal(), blob) {
		return nil, errors.New("pocket-ssh-agent: unknown key")
	}
	if len(data) > maxSignData {
		a.logf("rejected sign request: %d bytes is too large", len(data))
		return nil, errors.New("pocket-ssh-agent: data too large")
	}
	info, err := signreq.Classify(data, pub.Type(), blob)
	if err != nil {
		a.logf("rejected sign request: %v", err)
		return nil, err
	}

	var claimed []byte
	if info.Kind == signreq.KindUserAuth {
		claimed = a.lookupSession(info.SessionID)
	}
	forwarded := a.isForwarded()
	desc := describe(info)
	if forwarded {
		desc += " via forwarded agent"
	}
	a.logf("sign request: %s", desc)

	sig, err := a.Broker.Submit(a.ctx, broker.Submission{
		Kind: string(info.Kind), Data: data, ClaimedHostKey: claimed, Forwarded: forwarded,
	}, a.Timeout)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = errors.New("client disconnected")
		}
		a.logf("  -> %v", err)
		return nil, err
	}
	// The HTTP layer already verified this; check again so a bug there can
	// never hand an invalid signature to the SSH client.
	edPub, ok := pub.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if !ok || !ed25519.Verify(edPub, data, sig) {
		a.logf("  -> invalid signature from phone")
		return nil, errors.New("pocket-ssh-agent: invalid signature from phone")
	}
	a.logf("  -> approved")
	return &ssh.Signature{Format: pub.Type(), Blob: sig}, nil
}

// Signers is not supported: the private key never leaves the phone.
func (a *connAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }

// Add is not supported.
func (a *connAgent) Add(agent.AddedKey) error { return errReadOnly }

// Remove is not supported.
func (a *connAgent) Remove(ssh.PublicKey) error { return errReadOnly }

// RemoveAll is not supported.
func (a *connAgent) RemoveAll() error { return errReadOnly }

// Lock is not supported.
func (a *connAgent) Lock([]byte) error { return errReadOnly }

// Unlock is not supported.
func (a *connAgent) Unlock([]byte) error { return errReadOnly }

// Extension handles session-bind@openssh.com, with which OpenSSH clients
// tell the agent which server a connection authenticates to, and whether
// the connection is a forwarded agent. The rules follow OpenSSH's
// ssh-agent: the host key must have signed the session ID, and a
// connection bound for authentication cannot be bound again.
func (a *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != extSessionBind {
		return nil, agent.ErrExtensionUnsupported
	}
	var msg struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &msg); err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	hostKey, err := ssh.ParsePublicKey(msg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(msg.Signature, &sig); err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	if err := hostKey.Verify(msg.SessionID, &sig); err != nil {
		return nil, fmt.Errorf("session-bind: bad host signature: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.binds {
		if !b.forwarded {
			return nil, errors.New("session-bind: connection already bound for authentication")
		}
		if bytes.Equal(b.sessionID, msg.SessionID) {
			if bytes.Equal(b.hostKey, msg.HostKey) {
				return nil, nil
			}
			return nil, errors.New("session-bind: session ID bound to a different host key")
		}
	}
	if len(a.binds) >= maxSessionBinds {
		return nil, errors.New("session-bind: too many bindings")
	}
	a.binds = append(a.binds, binding{
		sessionID: append([]byte(nil), msg.SessionID...),
		hostKey:   append([]byte(nil), msg.HostKey...),
		forwarded: msg.Forwarding,
	})
	return nil, nil
}

// isForwarded reports whether this connection is an agent forwarded to a
// remote host, i.e. requests on it come from that host, not from this PC.
func (a *connAgent) isForwarded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.binds {
		if b.forwarded {
			return true
		}
	}
	return false
}

func (a *connAgent) lookupSession(id []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.binds {
		if !b.forwarded && bytes.Equal(b.sessionID, id) {
			return b.hostKey
		}
	}
	return nil
}

func (a *Agent) logf(format string, args ...any) {
	if a.Log != nil {
		a.Log.Printf(format, args...)
	}
}

func describe(info *signreq.Info) string {
	switch info.Kind {
	case signreq.KindUserAuth:
		return fmt.Sprintf("SSH login as %q", info.User)
	case signreq.KindSSHSig:
		return fmt.Sprintf("SSH signature (namespace %q)", info.Namespace)
	}
	return string(info.Kind)
}
