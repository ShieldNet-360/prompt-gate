//go:build linux

package tamper

import "context"

// platformProxyCheckOS on Linux inspects the HTTP_PROXY / HTTPS_PROXY
// environment variables — the agent's installer sets them via
// /etc/profile.d/prompt-gate-proxy.sh.
func platformProxyCheckOS(_ context.Context, expected string) (bool, error) {
	return proxyCheckEnv(expected), nil
}
