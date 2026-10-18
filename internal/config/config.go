// Package config persists the agent's settings and the pairing between this
// PC and the phone.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Pairing is the state shared with one paired phone.
type Pairing struct {
	// PublicKey is the phone's SSH public key in authorized_keys format.
	PublicKey string `json:"publicKey"`
	// Secret is the base64url-encoded key shared with the phone. Both sides
	// authenticate their messages with HMAC-SHA256 under it, so the secret
	// itself never travels after pairing.
	Secret     string    `json:"secret"`
	DeviceName string    `json:"deviceName,omitempty"`
	PairedAt   time.Time `json:"pairedAt"`
}

type file struct {
	// WebURL is the URL the phone PWA is served from. Its origin is the only
	// browser origin the phone API accepts, so it is remembered across runs.
	WebURL  string   `json:"webURL,omitempty"`
	Pairing *Pairing `json:"pairing,omitempty"`
}

// Store is a concurrency-safe, file-backed configuration.
type Store struct {
	path string

	mu  sync.RWMutex
	f   file
	pub ssh.PublicKey
}

// DefaultPath returns the default location of the configuration file.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pocket-ssh-agent", "config.json"), nil
}

// Open loads the configuration at path. A missing file is not an error.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.f.Pairing != nil {
		pub, err := parsePublicKey(s.f.Pairing.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		s.pub = pub
	}
	return s, nil
}

// Path returns the file location.
func (s *Store) Path() string { return s.path }

// Pairing returns the current pairing and its parsed key, or nil.
func (s *Store) Pairing() (*Pairing, ssh.PublicKey) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.f.Pairing == nil {
		return nil, nil
	}
	p := *s.f.Pairing
	return &p, s.pub
}

// SetPairing replaces the pairing and writes the file.
func (s *Store) SetPairing(p *Pairing) error {
	pub, err := parsePublicKey(p.PublicKey)
	if err != nil {
		return err
	}
	cp := *p
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.f
	f.Pairing = &cp
	if err := s.saveLocked(f); err != nil {
		return err
	}
	s.pub = pub
	return nil
}

// WebURL returns the remembered PWA URL, or "".
func (s *Store) WebURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.f.WebURL
}

// SetWebURL remembers the PWA URL and writes the file.
func (s *Store) SetWebURL(u string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.f
	f.WebURL = u
	return s.saveLocked(f)
}

// saveLocked writes f and makes it current. s.mu must be held.
func (s *Store) saveLocked(f file) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, b); err != nil {
		return err
	}
	s.f = f
	return nil
}

// Secret returns the key shared with the paired phone, or nil.
func (s *Store) Secret() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.f.Pairing == nil {
		return nil
	}
	k, err := base64.RawURLEncoding.DecodeString(s.f.Pairing.Secret)
	if err != nil || len(k) < 32 {
		return nil
	}
	return k
}

func parsePublicKey(s string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("unsupported key type %q (only %s)", pub.Type(), ssh.KeyAlgoED25519)
	}
	return pub, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	// os.CreateTemp creates the file with mode 0600 on Unix. On Windows the
	// ACL of the user's profile directory applies.
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
