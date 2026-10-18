// Package tailscale finds this machine's MagicDNS name.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DNSName returns this machine's MagicDNS name, e.g. "pc.tailnet.ts.net",
// by running "tailscale status --json".
func DNSName(ctx context.Context) (string, error) {
	bin, err := findCLI()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "status", "--json").Output()
	if err != nil {
		return "", err
	}
	var st struct {
		Self struct {
			DNSName string
		}
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", err
	}
	name := strings.TrimSuffix(st.Self.DNSName, ".")
	if name == "" {
		return "", errors.New("tailscale reported no DNS name (is MagicDNS enabled?)")
	}
	return name, nil
}

func findCLI() (string, error) {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	candidates := map[string][]string{
		"windows": {`C:\Program Files\Tailscale\tailscale.exe`},
		"darwin":  {"/Applications/Tailscale.app/Contents/MacOS/Tailscale"},
	}[runtime.GOOS]
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", errors.New("tailscale CLI not found")
}
