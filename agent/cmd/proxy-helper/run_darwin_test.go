//go:build darwin

package main

import "testing"

func TestParseSecureWebProxy(t *testing.T) {
	cases := []struct {
		name        string
		out         string
		wantServer  string
		wantPort    string
		wantEnabled bool
	}{
		{
			name:        "enabled loopback",
			out:         "Enabled: Yes\nServer: 127.0.0.1\nPort: 8443\nAuthenticated Proxy Enabled: 0\n",
			wantServer:  "127.0.0.1",
			wantPort:    "8443",
			wantEnabled: true,
		},
		{
			name:        "disabled",
			out:         "Enabled: No\nServer: 127.0.0.1\nPort: 8443\n",
			wantServer:  "127.0.0.1",
			wantPort:    "8443",
			wantEnabled: false,
		},
		{
			name:        "remote corporate proxy",
			out:         "Enabled: Yes\nServer: proxy.corp.example\nPort: 3128\n",
			wantServer:  "proxy.corp.example",
			wantPort:    "3128",
			wantEnabled: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, port, enabled := parseSecureWebProxy([]byte(tc.out))
			if server != tc.wantServer || port != tc.wantPort || enabled != tc.wantEnabled {
				t.Errorf("parseSecureWebProxy = (%q, %q, %v), want (%q, %q, %v)",
					server, port, enabled, tc.wantServer, tc.wantPort, tc.wantEnabled)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost", "LOCALHOST", "127.1.2.3"}
	for _, h := range loopback {
		if !isLoopback(h) {
			t.Errorf("isLoopback(%q) = false, want true", h)
		}
	}
	remote := []string{"proxy.corp.example", "10.0.0.1", "192.168.1.1", "8.8.8.8", ""}
	for _, h := range remote {
		if isLoopback(h) {
			t.Errorf("isLoopback(%q) = true, want false", h)
		}
	}
}

// The watchdog must only ever revert a proxy that is BOTH loopback and
// not listening. A live loopback proxy (probe succeeds) is left alone:
// proxyListening against a port nothing binds returns false.
func TestProxyListening_DeadPort(t *testing.T) {
	// Port 1 on loopback is never listenable for a normal process.
	if proxyListening("127.0.0.1:1") {
		t.Error("proxyListening(127.0.0.1:1) = true, want false (nothing should listen there)")
	}
}
