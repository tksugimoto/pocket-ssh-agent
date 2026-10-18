// Package signreq classifies the data an SSH client asks the agent to sign.
//
// Only two well-known formats are accepted:
//
//   - SSH user authentication requests (RFC 4252 section 7, including
//     OpenSSH's publickey-hostbound-v00@openssh.com variant), and
//   - SSHSIG blobs produced by "ssh-keygen -Y sign" (used by git for
//     commit and tag signing).
//
// Anything else is rejected so that the phone's key cannot be used as a
// generic signing oracle. The phone-side PWA performs the same parsing
// independently; this package only lets the agent reject garbage early and
// log something meaningful.
package signreq

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Kind identifies the format of the data to be signed.
type Kind string

const (
	KindUserAuth Kind = "ssh-userauth"
	KindSSHSig   Kind = "sshsig"
)

const (
	msgUserAuthRequest = 50

	methodPublicKey          = "publickey"
	methodPublicKeyHostbound = "publickey-hostbound-v00@openssh.com"

	sshsigMagic = "SSHSIG"
)

// ErrUnknownFormat is returned for data that is neither a user
// authentication request nor an SSHSIG blob.
var ErrUnknownFormat = errors.New("signreq: data is not an SSH userauth request or SSHSIG blob")

// Info describes a sign request.
type Info struct {
	Kind Kind

	// User authentication fields.
	SessionID []byte
	User      string
	Service   string
	Method    string
	// HostKey is the server host key embedded in the signed data by the
	// publickey-hostbound method. Because it is covered by the signature
	// and checked by the server, it reliably identifies the server.
	HostKey []byte

	// SSHSIG fields.
	Namespace string
	HashAlg   string
}

// Classify parses data and checks that it is a request to sign with the key
// whose wire-format blob is keyBlob and whose algorithm name is keyAlg.
func Classify(data []byte, keyAlg string, keyBlob []byte) (*Info, error) {
	if bytes.HasPrefix(data, []byte(sshsigMagic)) {
		return parseSSHSig(data[len(sshsigMagic):])
	}
	return parseUserAuth(data, keyAlg, keyBlob)
}

func parseUserAuth(data []byte, keyAlg string, keyBlob []byte) (*Info, error) {
	r := reader{b: data}
	info := &Info{Kind: KindUserAuth}
	info.SessionID = r.str()
	if r.byte() != msgUserAuthRequest {
		return nil, ErrUnknownFormat
	}
	info.User = string(r.str())
	info.Service = string(r.str())
	info.Method = string(r.str())
	if info.Method != methodPublicKey && info.Method != methodPublicKeyHostbound {
		return nil, ErrUnknownFormat
	}
	if r.byte() != 1 { // "has signature" must be TRUE
		return nil, ErrUnknownFormat
	}
	alg := string(r.str())
	blob := r.str()
	if info.Method == methodPublicKeyHostbound {
		info.HostKey = r.str()
	}
	if r.err != nil || len(r.b) != 0 || len(info.SessionID) == 0 {
		return nil, ErrUnknownFormat
	}
	if alg != keyAlg {
		return nil, fmt.Errorf("signreq: unexpected algorithm %q", alg)
	}
	if !bytes.Equal(blob, keyBlob) {
		return nil, errors.New("signreq: request is for a different key")
	}
	return info, nil
}

func parseSSHSig(data []byte) (*Info, error) {
	r := reader{b: data}
	info := &Info{Kind: KindSSHSig}
	info.Namespace = string(r.str())
	_ = r.str() // reserved
	info.HashAlg = string(r.str())
	hash := r.str()
	if r.err != nil || len(r.b) != 0 || info.Namespace == "" {
		return nil, ErrUnknownFormat
	}
	switch {
	case info.HashAlg == "sha256" && len(hash) == 32:
	case info.HashAlg == "sha512" && len(hash) == 64:
	default:
		return nil, ErrUnknownFormat
	}
	return info, nil
}

// reader reads SSH wire-format values, recording the first error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) byte() byte {
	if r.err != nil || len(r.b) < 1 {
		r.err = ErrUnknownFormat
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) str() []byte {
	if r.err != nil || len(r.b) < 4 {
		r.err = ErrUnknownFormat
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		r.err = ErrUnknownFormat
		return nil
	}
	v := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return v
}
