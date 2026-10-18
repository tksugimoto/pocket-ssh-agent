//go:build !windows

// Package listen creates the local endpoint SSH clients connect to: a Unix
// socket, or a named pipe on Windows.
package listen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// DefaultPath returns the default socket path.
func DefaultPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "pocket-ssh-agent", "agent.sock")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".pocket-ssh-agent", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("pocket-ssh-agent-%d", os.Getuid()), "agent.sock")
}

// Listen listens on a Unix socket only the current user can access. The
// socket's directory must be owned by the current user and is made
// private (0700), so the socket is never reachable by others, not even
// briefly before its own mode is set.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%s must be a directory owned by the current user", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}

	if _, err := os.Lstat(path); err == nil {
		// Remove a stale socket left by a previous run, but never steal one
		// that is still in use.
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, errors.New(path + " is in use by another agent")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
