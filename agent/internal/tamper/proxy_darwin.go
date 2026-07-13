//go:build darwin

package tamper

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// proxyCheckDarwin shells out to `networksetup -getwebproxy` and
// `-getsecurewebproxy` for the active service. It returns true as
// soon as either reports expected as Enabled.
func platformProxyCheckOS(ctx context.Context, expected string) (bool, error) {
	host, port, ok := splitHostPort(expected)
	if !ok {
		// Fall back to the env-var heuristic so unit tests on
		// non-standard expected strings still resolve.
		return proxyCheckEnv(expected), nil
	}
	services := []string{"Wi-Fi", "Ethernet"}
	for _, svc := range services {
		for _, sub := range []string{"-getwebproxy", "-getsecurewebproxy"} {
			tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			cmd := exec.CommandContext(tctx, "networksetup", sub, svc)
			out, err := cmd.Output()
			cancel()
			if err != nil {
				continue
			}
			text := string(out)
			if strings.Contains(text, "Enabled: Yes") &&
				strings.Contains(text, host) &&
				strings.Contains(text, port) {
				return true, nil
			}
		}
	}
	return false, nil
}

func splitHostPort(s string) (string, string, bool) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
