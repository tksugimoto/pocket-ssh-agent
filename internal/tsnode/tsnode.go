// Package tsnode joins the tailnet from inside the agent process (tsnet),
// so the phone API is served on its own Tailscale node with a valid HTTPS
// certificate. Neither the Tailscale client nor "tailscale serve" is needed
// on the PC, and no local TCP port is opened.
package tsnode

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"

	"tailscale.com/tsnet"
)

// Options configures the embedded Tailscale node.
type Options struct {
	// Hostname is the node's name in the tailnet (its MagicDNS label).
	Hostname string
	// Dir holds the node's state (keys). It is created with mode 0700.
	Dir string
	// Verbose enables tsnet's own backend logs.
	Verbose bool
	Log     *log.Logger
}

// Node is a running embedded Tailscale node.
type Node struct {
	srv *tsnet.Server
	// URL is the HTTPS URL of the node, e.g. "https://pocket-ssh-pc.tail1234.ts.net".
	URL string
}

// Listen joins the tailnet and returns a TLS listener on port 443 of the
// node. On first use it logs a login URL and blocks until the node has been
// authorized (or ctx is done). Set TS_AUTHKEY to log in without a browser.
func Listen(ctx context.Context, o Options) (*Node, net.Listener, error) {
	if o.Hostname == "" || o.Dir == "" {
		return nil, nil, errors.New("tsnode: Hostname and Dir are required")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, nil, err
	}
	srv := &tsnet.Server{
		Hostname: o.Hostname,
		Dir:      o.Dir,
		UserLogf: func(format string, args ...any) { o.Log.Printf("tailscale: "+format, args...) },
		Logf:     func(string, ...any) {},
	}
	if o.Verbose {
		srv.Logf = func(format string, args ...any) { o.Log.Printf("tsnet: "+format, args...) }
	}
	if err := srv.Start(); err != nil {
		return nil, nil, err
	}

	// Up blocks until the node is logged in and running, or ctx is done
	// (e.g. Ctrl-C while waiting for the login).
	if _, err := srv.Up(ctx); err != nil {
		srv.Close()
		return nil, nil, err
	}

	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		srv.Close()
		return nil, nil, err
	}
	domains := srv.CertDomains()
	if len(domains) == 0 {
		ln.Close()
		srv.Close()
		return nil, nil, errors.New("tsnode: the tailnet has no HTTPS domain (enable MagicDNS and HTTPS certificates)")
	}
	return &Node{srv: srv, URL: "https://" + domains[0]}, ln, nil
}

// Close leaves the tailnet.
func (n *Node) Close() error { return n.srv.Close() }

// DefaultHostname returns "pocket-ssh-<hostname>", reduced to a valid DNS
// label.
func DefaultHostname() string {
	h, _ := os.Hostname()
	return SanitizeHostname("pocket-ssh-" + h)
}

// SanitizeHostname lowercases s and replaces everything except a-z, 0-9 and
// '-' so the result is a valid DNS label of at most 63 characters.
func SanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	if out == "" {
		out = "pocket-ssh"
	}
	return out
}
