package main

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/tksugimoto/pocket-ssh-agent/internal/config"
)

func TestResolveWebURL(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Nothing configured.
	defaultWebURL = ""
	if _, _, err := resolveWebURL(store, ""); err == nil {
		t.Fatal("expected an error when no PWA URL is known")
	}

	// Build-time default is used and remembered.
	defaultWebURL = "https://pwa.example/app"
	u, changed, err := resolveWebURL(store, "")
	if err != nil || u != "https://pwa.example/app/" || changed {
		t.Fatalf("default: %q %v %v", u, changed, err)
	}
	if store.WebURL() != u {
		t.Fatalf("not remembered: %q", store.WebURL())
	}

	// Remembered value wins over the build-time default.
	defaultWebURL = "https://other.example/"
	if u, changed, _ := resolveWebURL(store, ""); u != "https://pwa.example/app/" || changed {
		t.Fatalf("remembered: %q %v", u, changed)
	}

	// The flag wins and is reported as a change.
	u, changed, err = resolveWebURL(store, "https://new.example/")
	if err != nil || u != "https://new.example/" || !changed {
		t.Fatalf("flag: %q %v %v", u, changed, err)
	}

	// Reopening the file keeps it.
	reopened, err := config.Open(store.Path())
	if err != nil || reopened.WebURL() != "https://new.example/" {
		t.Fatalf("reopen: %q %v", reopened.WebURL(), err)
	}

	for _, bad := range []string{"http://pwa.example/", "pwa.example", "javascript:alert(1)", "https:///x"} {
		if _, _, err := resolveWebURL(store, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if u, _, err := resolveWebURL(store, "http://localhost:8080"); err != nil || u != "http://localhost:8080/" {
		t.Errorf("localhost: %q %v", u, err)
	}
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://Example.COM:443/app/": "https://example.com",
		"https://example.com:8443/":    "https://example.com:8443",
		"http://localhost:80/":         "http://localhost",
		"http://localhost:3000/":       "http://localhost:3000",
	} {
		u := mustParse(t, in)
		if got := origin(u); got != want {
			t.Errorf("origin(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
