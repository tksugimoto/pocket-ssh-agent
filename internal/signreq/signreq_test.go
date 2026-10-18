package signreq

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"testing"
)

func str(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func userAuth(session []byte, user, method, alg string, key, hostKey []byte) []byte {
	var b bytes.Buffer
	b.Write(str(session))
	b.WriteByte(msgUserAuthRequest)
	b.Write(str([]byte(user)))
	b.Write(str([]byte("ssh-connection")))
	b.Write(str([]byte(method)))
	b.WriteByte(1)
	b.Write(str([]byte(alg)))
	b.Write(str(key))
	if hostKey != nil {
		b.Write(str(hostKey))
	}
	return b.Bytes()
}

func sshsig(ns, alg string, hash []byte) []byte {
	b := []byte(sshsigMagic)
	b = append(b, str([]byte(ns))...)
	b = append(b, str(nil)...)
	b = append(b, str([]byte(alg))...)
	return append(b, str(hash)...)
}

func TestClassify(t *testing.T) {
	key := []byte("key-blob")
	other := []byte("other-key")
	session := bytes.Repeat([]byte{7}, 32)
	h := sha512.Sum512([]byte("msg"))

	tests := []struct {
		name    string
		data    []byte
		want    *Info
		wantErr bool
	}{
		{
			name: "publickey",
			data: userAuth(session, "git", methodPublicKey, "ssh-ed25519", key, nil),
			want: &Info{Kind: KindUserAuth, SessionID: session, User: "git", Service: "ssh-connection", Method: methodPublicKey},
		},
		{
			name: "hostbound",
			data: userAuth(session, "alice", methodPublicKeyHostbound, "ssh-ed25519", key, []byte("hostkey")),
			want: &Info{Kind: KindUserAuth, SessionID: session, User: "alice", Service: "ssh-connection", Method: methodPublicKeyHostbound, HostKey: []byte("hostkey")},
		},
		{
			name: "sshsig",
			data: sshsig("git", "sha512", h[:]),
			want: &Info{Kind: KindSSHSig, Namespace: "git", HashAlg: "sha512"},
		},
		{name: "other key", data: userAuth(session, "git", methodPublicKey, "ssh-ed25519", other, nil), wantErr: true},
		{name: "other alg", data: userAuth(session, "git", methodPublicKey, "ssh-rsa", key, nil), wantErr: true},
		{name: "password method", data: userAuth(session, "git", "password", "ssh-ed25519", key, nil), wantErr: true},
		{name: "trailing data", data: append(userAuth(session, "git", methodPublicKey, "ssh-ed25519", key, nil), 0), wantErr: true},
		{name: "empty session", data: userAuth(nil, "git", methodPublicKey, "ssh-ed25519", key, nil), wantErr: true},
		{name: "sshsig bad hash length", data: sshsig("git", "sha512", h[:32]), wantErr: true},
		{name: "sshsig unknown alg", data: sshsig("git", "md5", h[:16]), wantErr: true},
		{name: "sshsig empty namespace", data: sshsig("", "sha512", h[:]), wantErr: true},
		{name: "random", data: []byte("hello world, please sign me"), wantErr: true},
		{name: "empty", data: nil, wantErr: true},
		{name: "huge length", data: []byte{0xff, 0xff, 0xff, 0xff, 1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Classify(tt.data, "ssh-ed25519", key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tt.want.Kind || got.User != tt.want.User || got.Service != tt.want.Service ||
				got.Method != tt.want.Method || got.Namespace != tt.want.Namespace || got.HashAlg != tt.want.HashAlg ||
				!bytes.Equal(got.SessionID, tt.want.SessionID) || !bytes.Equal(got.HostKey, tt.want.HostKey) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(userAuth([]byte("s"), "git", methodPublicKey, "ssh-ed25519", []byte("k"), nil))
	f.Add(sshsig("git", "sha256", make([]byte, 32)))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Classify(data, "ssh-ed25519", []byte("k"))
	})
}
