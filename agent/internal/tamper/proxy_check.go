package tamper

import (
	"context"
	"errors"
	"os"
	"strings"
)

// platformProxyCheck reports whether the OS proxy configuration
// includes the agent's local MITM proxy address. Each platform
// provides a platformProxyCheckOS implementation via build-tagged
// files (_darwin, _windows, _linux).
func platformProxyCheck(ctx context.Context, expected string) (bool, error) {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false, errors.New("proxy_check: expected address empty")
	}
	return platformProxyCheckOS(ctx, expected)
}

// proxyCheckEnv looks at the HTTP_PROXY / HTTPS_PROXY environment
// vars. This is the dominant configuration on Linux desktops and the
// only path we can inspect from inside the agent process without
// shelling out to a desktop-specific helper.
func proxyCheckEnv(expected string) bool {
	candidates := []string{
		os.Getenv("HTTPS_PROXY"),
		os.Getenv("https_proxy"),
		os.Getenv("HTTP_PROXY"),
		os.Getenv("http_proxy"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		// Strip optional scheme so "http://127.0.0.1:8443" and
		// "127.0.0.1:8443" both match.
		c = strings.TrimPrefix(c, "https://")
		c = strings.TrimPrefix(c, "http://")
		c = strings.TrimSuffix(c, "/")
		if c == expected {
			return true
		}
	}
	return false
}
