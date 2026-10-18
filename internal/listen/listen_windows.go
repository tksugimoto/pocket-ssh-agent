//go:build windows

// Package listen creates the local endpoint SSH clients connect to: a Unix
// socket, or a named pipe on Windows.
package listen

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// DefaultPath returns the default named pipe.
func DefaultPath() string {
	return `\\.\pipe\pocket-ssh-agent`
}

// Listen listens on a named pipe only the current user (and SYSTEM) can
// access.
func Listen(path string) (net.Listener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}
	// Protected DACL: full access for SYSTEM and the current user only.
	sd := fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", user.User.Sid.String())
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sd})
}
