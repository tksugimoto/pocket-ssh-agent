package tsnode

import "testing"

func TestSanitizeHostname(t *testing.T) {
	for in, want := range map[string]string{
		"pocket-ssh-DESKTOP-ABC123":              "pocket-ssh-desktop-abc123",
		"pocket-ssh-my_pc.local":                 "pocket-ssh-my-pc-local",
		"pocket-ssh-日本語":                         "pocket-ssh",
		"--x--y--":                               "x-y",
		"":                                       "pocket-ssh",
		"pocket-ssh-" + string(make([]byte, 80)): "pocket-ssh",
	} {
		if got := SanitizeHostname(in); got != want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
	long := SanitizeHostname("pocket-ssh-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(long) > 63 {
		t.Errorf("too long: %d", len(long))
	}
}
