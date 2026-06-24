package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// fakeScanner is a deterministic DLPScanner stand-in. If blockOn
// substring appears anywhere in the scanned content, it returns
// Blocked=true with patternName.
type fakeScanner struct {
	blockOn     string
	patternName string
	calls       atomic.Int64
}

func (f *fakeScanner) Scan(_ context.Context, content string) dlp.ScanResult {
	f.calls.Add(1)
	if f.blockOn != "" && strings.Contains(content, f.blockOn) {
		return dlp.ScanResult{Blocked: true, PatternName: f.patternName, Score: 9}
	}
	return dlp.ScanResult{}
}

// panicScanner panics on every Scan, simulating a parser blowing up on a
// malformed upload. scanBodySafely must absorb it and fail open.
type panicScanner struct{}

func (panicScanner) Scan(context.Context, string) dlp.ScanResult {
	panic("simulated scan/parse panic on untrusted upload")
}

// A panic in the scan/extract path must not crash the agent (which would
// black-hole all traffic). scanBodySafely recovers and fails open
// (Blocked=false → request forwarded unscanned).
func TestScanBodySafely_FailsOpenOnPanic(t *testing.T) {
	srv, err := New(newTestCA(t), PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP }), panicScanner{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/files", nil)
	result := scanBodySafely(srv, req, []byte("anything"))
	if result.Blocked {
		t.Error("scanBodySafely should fail OPEN (Blocked=false) when the scanner panics")
	}
}

// fakeStats counts calls so tests can verify aggregate counters
// flow through.
type fakeStats struct {
	scans  atomic.Int64
	blocks atomic.Int64
}

func (f *fakeStats) BumpDLP(_ context.Context, blocked bool) error {
	f.scans.Add(1)
	if blocked {
		f.blocks.Add(1)
	}
	return nil
}

// newTestCA creates a CA backed by a temp directory.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

func TestServer_RejectsNilDeps(t *testing.T) {
	ca := newTestCA(t)
	cases := []struct {
		name    string
		ca      *CA
		policy  PolicyChecker
		scanner DLPScanner
	}{
		{"nil ca", nil, PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }), &fakeScanner{}},
		{"nil policy", ca, nil, &fakeScanner{}},
		{"nil scanner", ca, PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.ca, tc.policy, tc.scanner, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestServer_HTTPRequestNonTier2PassesThrough(t *testing.T) {
	// Spin up a fake upstream that returns 200 OK with a sentinel
	// body, then run the proxy against it for a domain the policy
	// does not classify as Tier 2.
	const sentinel = "upstream body sentinel"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, sentinel)
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "should-never-trigger", patternName: "x"}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllow }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != sentinel {
		t.Errorf("body = %q, want %q", string(body), sentinel)
	}
	if scanner.calls.Load() != 0 {
		t.Errorf("scanner called %d times for non-Tier-2 host", scanner.calls.Load())
	}
	if srv.ScansTotal() != 0 {
		t.Errorf("scans counter = %d, want 0", srv.ScansTotal())
	}
}

func TestServer_HTTPRequestTier2ScannedAndAllowed(t *testing.T) {
	const sentinel = "harmless content"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key"}
	stats := &fakeStats{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllowDLP }), scanner, stats)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader(sentinel))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if scanner.calls.Load() != 1 {
		t.Errorf("scanner calls = %d, want 1", scanner.calls.Load())
	}
	if got := srv.ScansTotal(); got != 1 {
		t.Errorf("ScansTotal = %d, want 1", got)
	}
	if got := srv.BlocksTotal(); got != 0 {
		t.Errorf("BlocksTotal = %d, want 0", got)
	}
	if got := stats.scans.Load(); got != 1 {
		t.Errorf("stats scans = %d, want 1", got)
	}
	if got := stats.blocks.Load(); got != 0 {
		t.Errorf("stats blocks = %d, want 0", got)
	}
}

func TestServer_HTTPRequestTier2Blocked451(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must never be reached on a blocked request")
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key"}
	stats := &fakeStats{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllowDLP }), scanner, stats)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("payload AKIAIOSFODNN7EXAMPLE moredata"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
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
	if !strings.Contains(bodyStr, "AWS Access Key") {
		t.Errorf("body missing pattern name 'AWS Access Key'")
	}
	if got := srv.ScansTotal(); got != 1 {
		t.Errorf("ScansTotal = %d, want 1", got)
	}
	if got := srv.BlocksTotal(); got != 1 {
		t.Errorf("BlocksTotal = %d, want 1", got)
	}
	if got := stats.blocks.Load(); got != 1 {
		t.Errorf("stats blocks = %d, want 1", got)
	}
}

func TestServer_HTTPSConnectPassthroughNoDecryption(t *testing.T) {
	// Spin up a TLS upstream with a one-off cert that is not trusted
	// by either the proxy CA or the system roots. If the proxy were
	// MITM'ing the connection, the goproxy leaf would be signed by
	// the proxy CA and the client (configured to trust ONLY that
	// upstream's cert) would reject the handshake. Conversely, when
	// the proxy passes the CONNECT through opaquely the client sees
	// the genuine upstream cert and the handshake succeeds.
	const sentinel = "tunnel content"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, sentinel)
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllow }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	upstreamCerts := upstream.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(upstreamCerts)

	tlsCfg := &tls.Config{RootCAs: pool}
	client := proxyClient(t, proxySrv.URL, tlsCfg)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != sentinel {
		t.Errorf("body = %q, want %q", string(body), sentinel)
	}
	if scanner.calls.Load() != 0 {
		t.Errorf("scanner called %d times on opaque tunnel", scanner.calls.Load())
	}
}

func TestServer_HTTPSConnectTier2DecryptedAndBlocked(t *testing.T) {
	// Build an https upstream that records the request body. The
	// proxy MITM-decrypts the CONNECT, sees a DLP match, and returns
	// 451 — the upstream handler must never see the request.
	upstreamHit := atomic.Bool{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = io.WriteString(w, "should not reach upstream")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "SECRETPLACEHOLDER", patternName: "Test Pattern"}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllowDLP }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	// Trust the proxy's Root CA so the MITM'd leaf validates client-
	// side. Without this the client would reject the handshake.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	tlsCfg := &tls.Config{RootCAs: pool}

	client := proxyClient(t, proxySrv.URL, tlsCfg)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("body has SECRETPLACEHOLDER inside"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Error("upstream was hit despite DLP block")
	}
	if srv.BlocksTotal() != 1 {
		t.Errorf("BlocksTotal = %d, want 1", srv.BlocksTotal())
	}
}

func TestServer_ListenAndServeLifecycle(t *testing.T) {
	ca := newTestCA(t)
	srv, err := New(ca,
		PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllow }),
		&fakeScanner{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.Running() {
		t.Fatal("Running should be false before ListenAndServe")
	}

	addr := "127.0.0.1:" + freePort(t)
	if err := srv.ListenAndServe(addr); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !srv.Running() {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.Running() {
		t.Fatal("Running stayed false after ListenAndServe")
	}
	if srv.ListenAddr() != addr {
		t.Errorf("ListenAddr = %q, want %q", srv.ListenAddr(), addr)
	}

	// Second ListenAndServe should fail.
	if err := srv.ListenAndServe(addr); err == nil {
		t.Error("second ListenAndServe should error")
	}
}

// proxyClient builds an http.Client whose transport routes everything
// through the proxy at proxyURL. When tlsCfg is nil the client uses
// InsecureSkipVerify so plain GETs against httptest backends still
// work without trust roots — overridden when tlsCfg is supplied.
func proxyClient(t *testing.T, proxyURL string, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	cfg := tlsCfg
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: cfg,
		},
		Timeout: 5 * time.Second,
	}
}

func TestDecodeScanBody(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		want string
	}{
		{
			name: "json passthrough",
			ct:   "application/json",
			body: `{"text":"Visa 4916338506082832"}`,
			want: `{"text":"Visa 4916338506082832"}`,
		},
		{
			name: "form urlencoded decoded",
			ct:   "application/x-www-form-urlencoded",
			body: "f.req=%5B%5Bnull%2C%22Visa+4916338506082832%22%5D%5D",
			want: `[[null,"Visa 4916338506082832"]]`,
		},
		{
			name: "form urlencoded multiple values",
			ct:   "application/x-www-form-urlencoded;charset=UTF-8",
			body: "a=hello&b=world+123",
			want: "hello\nworld 123",
		},
		{
			name: "empty body",
			ct:   "application/x-www-form-urlencoded",
			body: "",
			want: "",
		},
		{
			name: "nil request",
			ct:   "",
			body: "raw bytes",
			want: "raw bytes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.ct != "" {
				req = &http.Request{Header: http.Header{"Content-Type": []string{tc.ct}}}
			}
			got := decodeScanBody(req, []byte(tc.body))
			if got != tc.want {
				t.Errorf("decodeScanBody() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServer_URLEncodedFormBodyBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must never be reached on a blocked request")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key"}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) PolicyAction { return PolicyAllowDLP }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	// Simulate a Gemini-style URL-encoded form POST with a secret inside.
	encoded := url.Values{"f.req": {`[["AKIAIOSFODNN7EXAMPLE is leaking"]]`}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader(encoded))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451 (URL-encoded body should be decoded before DLP scan)", resp.StatusCode)
	}
	if srv.BlocksTotal() != 1 {
		t.Errorf("BlocksTotal = %d, want 1", srv.BlocksTotal())
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 0: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}
