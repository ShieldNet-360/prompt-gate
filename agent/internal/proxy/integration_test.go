package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// TestIntegration_Tier2HTTPSBlockedByRealDLP wires a real
// dlp.Pipeline (configured with a single regex pattern) into the
// proxy and verifies that a Tier-2 HTTPS request carrying the
// matching token is blocked with HTTP 451 — exercising the full
// MITM + scan + block path end-to-end.
func TestIntegration_Tier2HTTPSBlockedByRealDLP(t *testing.T) {
	upstreamCalls := atomic.Int64{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host := mustHost(t, upstream.URL)
	policy := PolicyCheckerFunc(func(h string) PolicyAction {
		if h == host {
			return PolicyAllowDLP
		}
		return PolicyAllow
	})
	pipeline := buildIntegrationPipeline(t)
	stats := &fakeStats{}
	srv, ca := newServer(t, policy, pipeline, stats)

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	client := proxyClient(t, proxySrv.URL, &tls.Config{RootCAs: pool})

	req, err := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("here is my OPENAI_KEY=sk-test-EXAMPLE12345"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Request Blocked") {
		t.Errorf("body missing 'Request Blocked' heading")
	}
	if upstreamCalls.Load() != 0 {
		t.Errorf("upstream should not be hit on block, got %d calls", upstreamCalls.Load())
	}
	if srv.BlocksTotal() == 0 || srv.ScansTotal() == 0 {
		t.Errorf("counters not bumped: scans=%d blocks=%d", srv.ScansTotal(), srv.BlocksTotal())
	}
	if stats.scans.Load() == 0 || stats.blocks.Load() == 0 {
		t.Errorf("stats not bumped: scans=%d blocks=%d", stats.scans.Load(), stats.blocks.Load())
	}
}

// TestIntegration_NonTier2HTTPSPassesThroughCleanly verifies that a
// host that the policy engine does NOT classify as Tier 2 reaches
// the upstream untouched: the proxy must use an opaque CONNECT
// tunnel and the client must see the upstream's own certificate.
func TestIntegration_NonTier2HTTPSPassesThroughCleanly(t *testing.T) {
	upstreamCalls := atomic.Int64{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	// Refuse to classify anything as Tier 2 — the proxy should route
	// every CONNECT through opaquely.
	policy := PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow })
	pipeline := buildIntegrationPipeline(t)
	stats := &fakeStats{}
	srv, _ := newServer(t, policy, pipeline, stats)

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	// Trust the upstream's own cert (not the proxy CA). If the proxy
	// MITM'd anyway, the test client would see the proxy's leaf cert
	// and fail verification.
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	client := proxyClient(t, proxySrv.URL, &tls.Config{RootCAs: pool})

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if upstreamCalls.Load() != 1 {
		t.Errorf("upstream calls = %d, want 1", upstreamCalls.Load())
	}
	if srv.ScansTotal() != 0 {
		t.Errorf("scans bumped on non-Tier-2 host: %d", srv.ScansTotal())
	}
	if stats.scans.Load() != 0 {
		t.Errorf("aggregate stats bumped on non-Tier-2 host: %d", stats.scans.Load())
	}
}

// TestIntegration_ProxyDoesNotLogContent redirects stdout + stderr to
// a temp file for the duration of the test, runs a Tier-2 request
// through the proxy with sentinel tokens in both the URL and body,
// and asserts that none of those tokens appear in the captured
// output. The privacy invariant is "no content / no URLs / no hosts
// in logs"; this is the regression test for that invariant.
func TestIntegration_ProxyDoesNotLogContent(t *testing.T) {
	const (
		bodySentinel = "SECRETBODYTOKEN-XYZZY-42"
		hostSentinel = "very-secret-host.example.test"
	)

	captured := captureFDs(t, []int{1, 2})

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Force the proxy to MITM by classifying *every* host as Tier 2,
	// then route the request through a Host header that contains the
	// sentinel hostname (so any naive "log the host" code path would
	// leak it).
	policy := PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP })
	pipeline := buildIntegrationPipeline(t)
	stats := &fakeStats{}
	srv, ca := newServer(t, policy, pipeline, stats)
	// This request is forwarded to the self-signed test upstream after a
	// non-blocking scan. The proxy verifies upstream TLS by default, so
	// trust the test upstream's cert (mirrors proxy_upstream_ca_bundle).
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	srv.SetUpstreamRootCAs(upstreamPool)
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	client := proxyClient(t, proxySrv.URL, &tls.Config{RootCAs: pool})

	req, err := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("payload="+bodySentinel))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = hostSentinel // override the Host header sent on the wire.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	out := captured.read()
	for _, sentinel := range []string{bodySentinel, hostSentinel} {
		if strings.Contains(out, sentinel) {
			t.Errorf("captured proxy output contains %q (length %d bytes):\n%s",
				sentinel, len(out), out)
		}
	}
}

// TestUpstreamVerification_DefaultRejects_BundleTrusts proves the proxy
// verifies upstream TLS by default (rejecting a self-signed upstream) and
// that proxy_upstream_ca_bundle (SetUpstreamCABundle) widens trust to it
// — without ever disabling verification.
func TestUpstreamVerification_DefaultRejects_BundleTrusts(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	policy := PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP })
	srv, ca := newServer(t, policy, buildIntegrationPipeline(t), &fakeStats{})
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	client := proxyClient(t, proxySrv.URL, &tls.Config{RootCAs: pool})

	// Default: system roots only → the self-signed upstream must NOT verify.
	if resp, err := client.Get(upstream.URL); err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Fatalf("expected upstream verification to fail by default for a self-signed upstream")
	} else if resp != nil {
		resp.Body.Close()
	}

	// Write the upstream's cert to a PEM bundle and load it.
	bundle := filepath.Join(t.TempDir(), "upstream-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(bundle, certPEM, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := srv.SetUpstreamCABundle(bundle); err != nil {
		t.Fatalf("SetUpstreamCABundle: %v", err)
	}

	// With the bundle trusted, the forward succeeds.
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("with bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with bundle: status %d, want 200", resp.StatusCode)
	}
}

// buildIntegrationPipeline returns a real dlp.Pipeline configured
// with a single regex that matches "OPENAI_KEY=sk-..." style
// strings. The token used by TestIntegration_Tier2HTTPSBlockedByRealDLP
// is deterministically scored above the High threshold.
func buildIntegrationPipeline(t *testing.T) *dlp.Pipeline {
	t.Helper()
	dir := t.TempDir()
	patternFile := filepath.Join(dir, "patterns.json")
	if err := os.WriteFile(patternFile, []byte(`{
        "version": "integration-test",
        "patterns": [
            {
                "name": "Test OpenAI Key",
                "severity": "critical",
                "score_weight": 5,
                "prefix": "OPENAI_KEY=",
                "regex": "OPENAI_KEY=sk-[A-Za-z0-9-]+"
            }
        ]
    }`), 0o600); err != nil {
		t.Fatalf("write patterns: %v", err)
	}
	patterns, err := dlp.LoadPatterns(patternFile)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	pipeline := dlp.NewPipeline(dlp.DefaultScoreWeights(), dlp.NewThresholdEngine(dlp.DefaultThresholds()))
	pipeline.Rebuild(patterns, nil)
	return pipeline
}

func newServer(t *testing.T, policy PolicyChecker, scanner DLPScanner, stats StatsBumper) (*Server, *CA) {
	t.Helper()
	ca := newTestCA(t)
	srv, err := New(ca, policy, scanner, stats)
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	return srv, ca
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// No port in the URL — return the bare host.
		return u.Host
	}
	return host
}

// fdCapture redirects a set of process-wide file descriptors to a
// pipe for the duration of a test, then restores them on Stop / via
// t.Cleanup. read() returns whatever was written during the capture.
type fdCapture struct {
	orig    map[int]*os.File
	pipes   map[int]*os.File
	readers map[int]*os.File
	bufCh   chan map[int][]byte
}

func captureFDs(t *testing.T, fds []int) *fdCapture {
	t.Helper()
	c := &fdCapture{
		orig:    map[int]*os.File{},
		pipes:   map[int]*os.File{},
		readers: map[int]*os.File{},
		bufCh:   make(chan map[int][]byte, 1),
	}
	for _, fd := range fds {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe(%d): %v", fd, err)
		}
		c.readers[fd] = r
		c.pipes[fd] = w
		switch fd {
		case 1:
			c.orig[fd] = os.Stdout
			os.Stdout = w
		case 2:
			c.orig[fd] = os.Stderr
			os.Stderr = w
		}
	}

	go func() {
		out := map[int][]byte{}
		for fd, r := range c.readers {
			b, _ := io.ReadAll(r)
			out[fd] = b
		}
		c.bufCh <- out
	}()

	t.Cleanup(func() {
		c.stop()
	})
	return c
}

func (c *fdCapture) stop() {
	for fd, w := range c.pipes {
		_ = w.Close()
		switch fd {
		case 1:
			os.Stdout = c.orig[fd]
		case 2:
			os.Stderr = c.orig[fd]
		}
	}
	c.pipes = nil
}

func (c *fdCapture) read() string {
	// stop() in t.Cleanup needs to fire before reading; we replicate
	// the close logic here so callers can read mid-test.
	for fd, w := range c.pipes {
		_ = w.Close()
		switch fd {
		case 1:
			os.Stdout = c.orig[fd]
		case 2:
			os.Stderr = c.orig[fd]
		}
	}
	c.pipes = map[int]*os.File{}

	select {
	case bufs := <-c.bufCh:
		var b strings.Builder
		for _, fd := range []int{1, 2} {
			if v, ok := bufs[fd]; ok {
				b.Write(v)
			}
		}
		return b.String()
	case <-time.After(time.Second):
		return ""
	}
}
