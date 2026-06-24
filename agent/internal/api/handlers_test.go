package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/profile"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/rules"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

type fakeReloader struct {
	calls int64
	err   error // optional: when set, Reload returns this error
}

func (f *fakeReloader) Reload(_ context.Context) error {
	atomic.AddInt64(&f.calls, 1)
	return f.err
}

type fakeStatsView struct {
	snap   stats.Snapshot
	resets int64
}

func (f *fakeStatsView) GetStats(_ context.Context) (stats.Snapshot, error) { return f.snap, nil }
func (f *fakeStatsView) Reset(_ context.Context) error {
	atomic.AddInt64(&f.resets, 1)
	f.snap = stats.Snapshot{}
	return nil
}

func newTestServer(t *testing.T) (*Server, *fakeReloader, *fakeStatsView) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	rel := &fakeReloader{}
	view := &fakeStatsView{snap: stats.Snapshot{DNSQueriesTotal: 42, DNSBlocksTotal: 5}}
	return NewServer(s, rel, view), rel, view
}

// newLocalRequest builds an httptest request whose Host header is
// 127.0.0.1, matching the loopback-only allowlist enforced by the
// API, and which carries the hardcoded local bearer token so the
// SE-02 mutating-request check accepts it. The
// token is intentionally fixed for local-only agent communication
// (see generateBearerToken in server.go).
func newLocalRequest(method, path string, body interface{}) *http.Request {
	var r *http.Request
	switch b := body.(type) {
	case nil:
		r = httptest.NewRequest(method, path, nil)
	case *bytes.Buffer:
		r = httptest.NewRequest(method, path, b)
	default:
		panic("unsupported body type")
	}
	r.Host = "127.0.0.1:9191"
	r.Header.Set("Authorization", "Bearer prompt-gate-local-token-2025")
	return r
}

func TestStatusEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("status = %q", got.Status)
	}
	if got.Version == "" {
		t.Errorf("version is empty")
	}
	// uptime_seconds is the machine-readable number consumed by the
	// browser extension; it must always be present (>= 0) so the
	// popup doesn't fall back to "—".
	if got.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, want >= 0", got.UptimeSeconds)
	}
}

func TestPoliciesCollection(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/policies", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var pols []store.CategoryPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &pols); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pols) == 0 {
		t.Fatal("expected seeded policies")
	}
}

func TestUpdatePolicyTriggersReload(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt64(&rel.calls) != 1 {
		t.Fatalf("reload calls = %d", rel.calls)
	}
}

func TestUpdatePolicyInvalidAction(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"bogus"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdatePolicyMissingCategory(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got stats.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DNSQueriesTotal != 42 {
		t.Errorf("queries = %d", got.DNSQueriesTotal)
	}
}

func TestStatsResetEndpoint(t *testing.T) {
	srv, _, view := newTestServer(t)
	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if atomic.LoadInt64(&view.resets) != 1 {
		t.Fatalf("resets = %d", view.resets)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/status"},
		{http.MethodPost, "/api/policies"},
		{http.MethodGet, "/api/policies/foo"},
		{http.MethodPost, "/api/stats"},
		{http.MethodGet, "/api/stats/reset"},
	}
	for _, c := range cases {
		r := newLocalRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: code = %d", c.method, c.path, w.Code)
		}
	}
}

func TestCORSPreflightAllowedOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	origins := []string{
		// Electron renderer + Vite dev server.
		"null",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		// Browser extension service worker. The ID is install-time
		// and not knowable here; any chrome-extension:// (Chrome,
		// Edge, Chromium), moz-extension:// (Firefox), or
		// safari-web-extension:// (Safari) origin must be accepted
		// so the popup's /api/status fetch works.
		"chrome-extension://abcdefghijklmnopabcdefghijklmnop",
		"moz-extension://01234567-89ab-cdef-0123-456789abcdef",
		"safari-web-extension://01234567-89ab-cdef-0123-456789abcdef",
		// Content-script origins (Tier-2 AI tools). The browser
		// stamps the page's own origin for content-script fetches,
		// not the extension's, so each Tier-2 host has to be
		// explicitly allowed. Sample two ends of the list.
		"https://chatgpt.com",
		"https://poe.com",
	}
	for _, origin := range origins {
		r := newLocalRequest(http.MethodOptions, "/api/policies", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s: code = %d", origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("%s: ACAO = %q", origin, got)
		}
		if w.Header().Get("Vary") != "Origin" {
			t.Errorf("%s: Vary header missing", origin)
		}
	}
}

// TestCORSRejectsLookalikeExtensionOrigins guards the extension
// prefix checks against trivial spoofs (an attacker page can set an
// arbitrary Origin via fetch on the server side only; from a browser
// the Origin is controlled, but the test pins the parser anyway).
func TestCORSRejectsLookalikeExtensionOrigins(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []string{
		// Bare schemes without an ID component.
		"chrome-extension://",
		"moz-extension://",
		"safari-web-extension://",
		// Embedded but not as scheme prefixes.
		"https://chrome-extension.example.com",
		"https://moz-extension.example.com",
		"https://safari-web-extension.example.com",
	}
	for _, origin := range cases {
		r := newLocalRequest(http.MethodGet, "/api/status", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("origin=%q: code = %d, want 403", origin, w.Code)
		}
	}
}

func TestCORSRejectsUnknownOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/policies", nil)
	r.Header.Set("Origin", "http://evil.example.com")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("ACAO must not be echoed for rejected origin")
	}
}

func TestRejectsNonLoopbackHost(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []string{"evil.example.com", "evil.example.com:9191", ""}
	for _, host := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		r.Host = host
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("host=%q: code = %d, want 403", host, w.Code)
		}
	}
}

func TestAllowsRequestsWithoutOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO unexpectedly set: %q", got)
	}
}

// --- DLP endpoint tests ---

type fakeDLP struct {
	thr     *dlp.ThresholdEngine
	result  dlp.ScanResult
	calls   int64
	weights dlp.ScoreWeights

	// Dispatch-routing tests inspect these.
	lastCall   string // "scan" / "session" / "context"
	lastSource dlp.SourceContext

	// Optionally exposed via Allowlist() for endpoint tests.
	allowlist *dlp.Allowlist
}

func (f *fakeDLP) Scan(_ context.Context, _ string) dlp.ScanResult {
	atomic.AddInt64(&f.calls, 1)
	f.lastCall = "scan"
	return f.result
}
func (f *fakeDLP) ScanSession(_ context.Context, _ string, _ string) dlp.ScanResult {
	atomic.AddInt64(&f.calls, 1)
	f.lastCall = "session"
	return f.result
}
func (f *fakeDLP) ScanWithContext(_ context.Context, _, _ string, source dlp.SourceContext) dlp.ScanResult {
	atomic.AddInt64(&f.calls, 1)
	f.lastCall = "context"
	f.lastSource = source
	return f.result
}
func (f *fakeDLP) Redact(_ context.Context, content, _ string, _ dlp.SourceContext) dlp.RedactionResult {
	atomic.AddInt64(&f.calls, 1)
	f.lastCall = "redact"
	action := dlp.ActionAllow
	if f.result.Blocked {
		action = dlp.ActionBlock
	}
	return dlp.RedactionResult{ScanResult: f.result, Action: action, RedactedContent: content}
}
func (f *fakeDLP) Threshold() *dlp.ThresholdEngine { return f.thr }
func (f *fakeDLP) SetWeights(w dlp.ScoreWeights)   { f.weights = w }
func (f *fakeDLP) Patterns() []*dlp.Pattern        { return nil }
func (f *fakeDLP) Allowlist() *dlp.Allowlist       { return f.allowlist }

func TestDLPScan_WithoutPipelineReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"x"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestDLPScan_ReturnsScanResult(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:    dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		result: dlp.ScanResult{Blocked: true, PatternName: "AWS Access Key", Score: 3},
	})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"placeholder aws credentials test"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	var got dlp.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Blocked || got.PatternName != "AWS Access Key" || got.Score != 3 {
		t.Fatalf("scan result = %+v, want blocked AWS Access Key score=3", got)
	}
}

func TestDLPScan_RejectsNonPOST(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/scan", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestDLPConfig_GetAndPut(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	srv.SetDLP(&fakeDLP{thr: thr})

	// GET returns the defaults seeded by store.Open.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/config", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dlp/config got %d", rec.Code)
	}
	var cfg store.DLPConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.ThresholdCritical == 0 {
		t.Fatalf("expected non-zero defaults, got %+v", cfg)
	}

	// PUT updates thresholds and propagates to the engine.
	cfg.ThresholdCritical = 99
	cfg.ThresholdHigh = 100
	cfg.ThresholdMedium = 101
	cfg.ThresholdLow = 102
	body, _ := json.Marshal(cfg)
	rec = httptest.NewRecorder()
	req = newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := thr.Get(); got.Critical != 99 || got.Low != 102 {
		t.Fatalf("threshold engine not updated: %+v", got)
	}
}

func TestDLPConfig_PutPropagatesWeightsToPipeline(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fake := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(fake)

	cfg := store.DLPConfig{
		ThresholdCritical: 1, ThresholdHigh: 2, ThresholdMedium: 3, ThresholdLow: 4,
		HotwordBoost: 7, EntropyBoost: 8, EntropyPenalty: -9,
		ExclusionPenalty: -11, MultiMatchBoost: 13,
	}
	body, _ := json.Marshal(cfg)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT got %d body=%q", rec.Code, rec.Body.String())
	}
	want := dlp.ScoreWeights{
		HotwordBoost: 7, EntropyBoost: 8, EntropyPenalty: -9,
		ExclusionPenalty: -11, MultiMatchBoost: 13,
	}
	if fake.weights != want {
		t.Fatalf("live pipeline weights = %+v, want %+v", fake.weights, want)
	}
}

// stubUpdater is a minimal RuleUpdater for handler tests.
type stubUpdater struct {
	check      func(ctx context.Context) (rules.Result, error)
	status     rules.Status
	checkCalls int
}

func (s *stubUpdater) CheckNow(ctx context.Context) (rules.Result, error) {
	s.checkCalls++
	if s.check != nil {
		return s.check(ctx)
	}
	return rules.Result{Updated: true, Version: "1.2.3", FilesDownloaded: 2}, nil
}

func (s *stubUpdater) Status() rules.Status { return s.status }

func TestRulesUpdate_RequiresUpdater(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRulesUpdate_PostInvokesCheckNow(t *testing.T) {
	srv, _, _ := newTestServer(t)
	upd := &stubUpdater{}
	srv.SetRuleUpdater(upd)

	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
	if upd.checkCalls != 1 {
		t.Errorf("CheckNow calls = %d, want 1", upd.checkCalls)
	}
	var res rules.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Version != "1.2.3" || !res.Updated || res.FilesDownloaded != 2 {
		t.Errorf("response = %+v", res)
	}
}

func TestRulesUpdate_RejectsNonPost(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleUpdater(&stubUpdater{})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rec.Code)
	}
}

func TestRulesUpdate_PropagatesError(t *testing.T) {
	srv, _, _ := newTestServer(t)
	upd := &stubUpdater{check: func(_ context.Context) (rules.Result, error) {
		return rules.Result{}, fmt.Errorf("manifest 404")
	}}
	srv.SetRuleUpdater(upd)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRulesStatus_WithoutUpdater_ReturnsFallback(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"current_version"`) {
		t.Errorf("body missing current_version: %s", rec.Body.String())
	}
}

func TestRulesStatus_ReturnsSnapshot(t *testing.T) {
	srv, _, _ := newTestServer(t)
	when := time.Now().UTC().Truncate(time.Second)
	srv.SetRuleUpdater(&stubUpdater{status: rules.Status{
		CurrentVersion: "9.9.9",
		LastCheck:      when,
		NextCheck:      when.Add(6 * time.Hour),
		UpdateURL:      "https://example.test/manifest.json",
	}})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
	var got rules.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CurrentVersion != "9.9.9" || got.UpdateURL == "" {
		t.Errorf("status = %+v", got)
	}
	if !got.LastCheck.Equal(when) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, when)
	}
}

func TestRulesStatus_RejectsNonGet(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleUpdater(&stubUpdater{})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rec.Code)
	}
}

// fakeProxyController is a deterministic ProxyController for tests.
type fakeProxyController struct {
	enableCalls  int
	disableCalls int
	lastRemoveCA bool
	statusSnap   ProxyStatus
	enableErr    error
	disableErr   error

	upstreamCASet   []byte
	upstreamCACfg   bool
	upstreamCASubj  []string
	upstreamCAErr   error
	upstreamCAClear bool
}

func (f *fakeProxyController) SetUpstreamCA(pem []byte) ([]string, error) {
	if f.upstreamCAErr != nil {
		return nil, f.upstreamCAErr
	}
	f.upstreamCASet = pem
	f.upstreamCACfg = true
	return f.upstreamCASubj, nil
}

func (f *fakeProxyController) ClearUpstreamCA() error {
	f.upstreamCAClear = true
	f.upstreamCACfg = false
	return nil
}

func (f *fakeProxyController) UpstreamCAStatus() (bool, []string) {
	return f.upstreamCACfg, f.upstreamCASubj
}

func (f *fakeProxyController) Enable(_ context.Context) (string, error) {
	f.enableCalls++
	if f.enableErr != nil {
		return "", f.enableErr
	}
	f.statusSnap.Running = true
	f.statusSnap.CAInstalled = true
	f.statusSnap.ProxyConfigured = true
	if f.statusSnap.ListenAddr == "" {
		f.statusSnap.ListenAddr = "127.0.0.1:8443"
	}
	if f.statusSnap.CACertPath == "" {
		f.statusSnap.CACertPath = "/tmp/ca.crt"
	}
	return f.statusSnap.CACertPath, nil
}

func (f *fakeProxyController) Disable(_ context.Context, removeCA bool) error {
	f.disableCalls++
	f.lastRemoveCA = removeCA
	if f.disableErr != nil {
		return f.disableErr
	}
	f.statusSnap.Running = false
	f.statusSnap.ProxyConfigured = false
	if removeCA {
		f.statusSnap.CAInstalled = false
		f.statusSnap.CACertPath = ""
	}
	return nil
}

func (f *fakeProxyController) Status() ProxyStatus { return f.statusSnap }

func (f *fakeProxyController) SetListenAddr(_ context.Context, addr string) error {
	f.statusSnap.ListenAddr = addr
	return nil
}

func TestProxyEnable_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/enable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxyDisable_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/disable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxyStatus_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/proxy/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxy_EnableDisableLifecycle(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{statusSnap: ProxyStatus{ListenAddr: "127.0.0.1:8443"}}
	srv.SetProxyController(fc)

	// 1) Enable.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/enable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.enableCalls != 1 {
		t.Errorf("enable calls = %d", fc.enableCalls)
	}
	var enableBody proxyEnableResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enableBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enableBody.CACertPath == "" {
		t.Error("ca_cert_path empty in enable response")
	}

	// 2) Status reports running.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/proxy/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var st ProxyStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Running || !st.CAInstalled || !st.ProxyConfigured {
		t.Errorf("post-enable status = %+v", st)
	}
	if st.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("listen_addr = %q", st.ListenAddr)
	}

	// 3) Disable with remove_ca=true.
	rec = httptest.NewRecorder()
	body := bytes.NewBufferString(`{"remove_ca": true}`)
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/disable", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if !fc.lastRemoveCA {
		t.Error("remove_ca=true not propagated to controller")
	}

	// 4) Status reports stopped.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/proxy/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Running || st.CAInstalled {
		t.Errorf("post-disable status = %+v", st)
	}
}

func TestProxy_DisableEmptyBodyAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{}
	_, _ = fc.Enable(context.Background())
	srv.SetProxyController(fc)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/disable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if fc.lastRemoveCA {
		t.Error("remove_ca defaulted to true; expected false on empty body")
	}
}

// TestProxy_DisableEmptyBodyNoContentLength covers the case where a
// client sends an empty POST without a Content-Length header (e.g.
// chunked transfer encoding). net/http reports ContentLength=-1 for
// this case, so a guard like `if r.ContentLength != 0` would attempt
// to decode an empty stream and fail with io.EOF, returning a spurious
// 400. The handler must treat this identically to remove_ca=false.
func TestProxy_DisableEmptyBodyNoContentLength(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{}
	_, _ = fc.Enable(context.Background())
	srv.SetProxyController(fc)

	req := newLocalRequest(http.MethodPost, "/api/proxy/disable", nil)
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if fc.lastRemoveCA {
		t.Error("remove_ca defaulted to true; expected false on empty body")
	}
}

func TestProxy_EnableErrorReturns500(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{enableErr: errors.New("ca disk full")}
	srv.SetProxyController(fc)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/enable", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxy_RejectsNonMatchingMethods(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetProxyController(&fakeProxyController{})
	cases := []struct {
		path   string
		method string
	}{
		{"/api/proxy/enable", http.MethodGet},
		{"/api/proxy/disable", http.MethodGet},
		{"/api/proxy/status", http.MethodPost},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, newLocalRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s -> %d, want 405", tc.method, tc.path, rec.Code)
		}
	}
}

// ---------- profile, tamper, stats export, rule override ----------

type fakeRuleOverride struct {
	allow []string
	block []string
	added []string
	rm    []string
	err   error
}

func (f *fakeRuleOverride) Add(d, list string) error {
	if f.err != nil {
		return f.err
	}
	f.added = append(f.added, list+":"+d)
	switch list {
	case "allow":
		f.allow = append(f.allow, d)
	case "block":
		f.block = append(f.block, d)
	}
	return nil
}
func (f *fakeRuleOverride) Remove(d string) error {
	if f.err != nil {
		return f.err
	}
	f.rm = append(f.rm, d)
	return nil
}
func (f *fakeRuleOverride) List() ([]string, []string) { return f.allow, f.block }

type fakeTamper struct{ st TamperStatus }

func (f fakeTamper) Status() TamperStatus { return f.st }

type fakePolicyStore struct{ calls int64 }

func (f *fakePolicyStore) SetPolicy(_ context.Context, _, _ string) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}
func (f *fakePolicyStore) GetDLPConfig(_ context.Context) (profile.DLPConfigSnapshot, error) {
	return profile.DLPConfigSnapshot{}, nil
}
func (f *fakePolicyStore) SetDLPConfig(_ context.Context, _ profile.DLPConfigSnapshot) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}

func TestProfileGetReturnsHolderContents(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/profile", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no holder wired => 404 expected, got %d", w.Code)
	}

	h := profile.NewHolder(nil)
	if err := h.Set(&profile.Profile{Name: "acme", Version: "1", Managed: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	srv.SetProfile(h, &fakePolicyStore{})

	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/profile", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got profile.Profile
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "acme" || !got.Managed {
		t.Fatalf("unexpected profile: %+v", got)
	}
}

func TestProfileImportLocksPolicies(t *testing.T) {
	srv, _, _ := newTestServer(t)
	h := profile.NewHolder(nil)
	ps := &fakePolicyStore{}
	srv.SetProfile(h, ps)

	body := bytes.NewBufferString(`{"profile":{"name":"acme","version":"1","managed":true,"categories":{"AI Chat":"deny"}}}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import", body))
	if w.Code != http.StatusOK {
		t.Fatalf("import code=%d body=%s", w.Code, w.Body.String())
	}
	if !h.Locked() {
		t.Fatalf("expected holder locked after import")
	}
	if atomic.LoadInt64(&ps.calls) == 0 {
		t.Fatalf("expected policy store calls during apply")
	}

	// Once locked, PUT /api/policies/:cat must return 403.
	put := bytes.NewBufferString(`{"action":"allow"}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat", put))
	if w.Code != http.StatusForbidden {
		t.Fatalf("policy PUT not locked, code=%d", w.Code)
	}

	// And PUT /api/dlp/config too.
	dlp := bytes.NewBufferString(`{"threshold_critical":1}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/dlp/config", dlp))
	if w.Code != http.StatusForbidden {
		t.Fatalf("dlp PUT not locked, code=%d", w.Code)
	}
}

// TestProfileImportPropagatesDLPToPipeline locks in the contract
// fixed for Bug 8: when a profile carries DLP thresholds /
// weights, POST /api/profile/import MUST push them into the live
// DLP pipeline. Before the fix, p.Apply only wrote SQLite and the
// pipeline kept its construction-time values until the next
// restart — silently diverging from GET /api/dlp/config.
func TestProfileImportPropagatesDLPToPipeline(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	fake := &fakeDLP{thr: thr}
	srv.SetDLP(fake)
	srv.SetProfile(profile.NewHolder(nil), &fakePolicyStore{})

	body := bytes.NewBufferString(`{
		"profile": {
			"name": "acme",
			"version": "1",
			"dlp_thresholds": {
				"threshold_critical": 11,
				"threshold_high":     7,
				"hotword_boost":      42,
				"entropy_boost":      13
			}
		}
	}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import", body))
	if w.Code != http.StatusOK {
		t.Fatalf("import code=%d body=%s", w.Code, w.Body.String())
	}

	got := thr.Get()
	if got.Critical != 11 || got.High != 7 {
		t.Fatalf("live thresholds = %+v, want Critical=11 High=7", got)
	}
	if fake.weights.HotwordBoost != 42 || fake.weights.EntropyBoost != 13 {
		t.Fatalf("live weights = %+v, want HotwordBoost=42 EntropyBoost=13", fake.weights)
	}
}

func TestProfileImportRequiresPayload(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetProfile(profile.NewHolder(nil), &fakePolicyStore{})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import",
		bytes.NewBufferString(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty payload code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTamperStatusUnconfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/tamper/status", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured tamper => 503 expected, got %d", w.Code)
	}
}

func TestTamperStatusOK(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetTamperReporter(fakeTamper{st: TamperStatus{DNSOK: true, ProxyOK: false, DetectionsTotal: 7}})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/tamper/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var got TamperStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProxyOK || !got.DNSOK || got.DetectionsTotal != 7 {
		t.Fatalf("unexpected status: %+v", got)
	}
}

func TestStatsExportEnvelope(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/stats/export", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Fatalf("missing Content-Disposition")
	}
	var got statsExportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AgentVersion == "" || got.OSType == "" {
		t.Fatalf("missing envelope metadata: %+v", got)
	}
	if got.Stats.DNSQueriesTotal == 0 {
		t.Fatalf("stats body not forwarded: %+v", got.Stats)
	}
}

func TestRuleOverrideAddListRemove(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	fake := &fakeRuleOverride{}
	srv.SetRuleOverride(fake)

	add := bytes.NewBufferString(`{"domain":"foo.example","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", add))
	if w.Code != http.StatusOK {
		t.Fatalf("add code=%d body=%s", w.Code, w.Body.String())
	}
	if len(fake.added) != 1 || fake.added[0] != "allow:foo.example" {
		t.Fatalf("Add not invoked correctly: %v", fake.added)
	}
	if atomic.LoadInt64(&rel.calls) == 0 {
		t.Fatalf("expected policy reload after override change")
	}

	// GET listing.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/rules/override", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list code=%d", w.Code)
	}

	// DELETE :domain.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodDelete, "/api/rules/override/foo.example", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete code=%d body=%s", w.Code, w.Body.String())
	}
	if len(fake.rm) != 1 || fake.rm[0] != "foo.example" {
		t.Fatalf("Remove not invoked: %v", fake.rm)
	}
}

func TestRuleOverrideValidation(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleOverride(&fakeRuleOverride{})

	bad := bytes.NewBufferString(`{"domain":"","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty domain => 400 expected, got %d", w.Code)
	}

	bad = bytes.NewBufferString(`{"domain":"ok","list":"middle"}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad list => 400 expected, got %d", w.Code)
	}
}

func TestRuleOverrideUnconfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, newLocalRequest(m, "/api/rules/override", nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s => 503 expected, got %d", m, w.Code)
		}
	}
}

// Bug 9 regression: when the underlying policy engine fails to
// reload after a rule-override write, the handler must return 500
// rather than 200. Returning 200 made callers think the override
// was live while the in-memory DNS engine still used the old map.
func TestRuleOverrideAddReloadFailure(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	rel.err = errors.New("boom")
	srv.SetRuleOverride(&fakeRuleOverride{})

	body := bytes.NewBufferString(`{"domain":"foo.example","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", body))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("add => 500 expected when reload fails, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRuleOverrideDeleteReloadFailure(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	rel.err = errors.New("boom")
	srv.SetRuleOverride(&fakeRuleOverride{allow: []string{"foo.example"}})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodDelete, "/api/rules/override/foo.example", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete => 500 expected when reload fails, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestPreferencesDefaultOff confirms a fresh install reports
// block_events_enabled=false on GET /api/preferences. This is the
// audited carve-out: every persistent feature outside the privacy
// invariant has to default OFF.
func TestPreferencesDefaultOff(t *testing.T) {
	srv, _, _ := newTestServer(t)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/preferences", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	var got preferencesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.BlockEventsEnabled {
		t.Error("block_events_enabled is true on a fresh store; want false")
	}
	if got.Managed {
		t.Error("managed=true without a profile holder")
	}
}

// TestPreferencesBlockEventsRoundTrip exercises the consent flip via
// the API surface and verifies the GET reflects the change with a
// stamped consented_at.
func TestPreferencesBlockEventsRoundTrip(t *testing.T) {
	srv, _, _ := newTestServer(t)

	body := bytes.NewBufferString(`{"enabled":true}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/preferences/block-events", body))
	if w.Code != http.StatusOK {
		t.Fatalf("put => %d body=%s", w.Code, w.Body.String())
	}
	var got preferencesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.BlockEventsEnabled {
		t.Fatal("enabled=true didn't stick")
	}
	if got.BlockEventsConsentedAt == 0 {
		t.Fatal("consented_at not stamped on enable")
	}

	// GET reflects the flip.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/preferences", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get => %d", w.Code)
	}
	var got2 preferencesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got2.BlockEventsEnabled || got2.BlockEventsConsentedAt != got.BlockEventsConsentedAt {
		t.Fatalf("get drift: %+v vs %+v", got2, got)
	}

	// Disable.
	body = bytes.NewBufferString(`{"enabled":false}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/preferences/block-events", body))
	if w.Code != http.StatusOK {
		t.Fatalf("disable put => %d body=%s", w.Code, w.Body.String())
	}
	var got3 preferencesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got3); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got3.BlockEventsEnabled {
		t.Error("disable didn't take")
	}
	// consented_at is intentionally preserved across disable so the UI
	// can show "last consented YYYY-MM-DD" even when currently off.
	if got3.BlockEventsConsentedAt != got.BlockEventsConsentedAt {
		t.Errorf("consented_at cleared on disable (%d → %d); should persist",
			got.BlockEventsConsentedAt, got3.BlockEventsConsentedAt)
	}
}

// TestPreferencesBlockEventsLockedByManagedProfile mirrors the
// existing policy-mutation lockdown: a managed profile rejects
// consent toggles with 403 so a central deployment owns the knob.
func TestPreferencesBlockEventsLockedByManagedProfile(t *testing.T) {
	srv, _, _ := newTestServer(t)
	h := profile.NewHolder(nil)
	if err := h.Set(&profile.Profile{Name: "acme", Version: "1", Managed: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	srv.SetProfile(h, &fakePolicyStore{})

	body := bytes.NewBufferString(`{"enabled":true}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/preferences/block-events", body))
	if w.Code != http.StatusForbidden {
		t.Fatalf("managed profile => 403 expected, got %d body=%s", w.Code, w.Body.String())
	}

	// GET still works so the UI can read the locked state.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/preferences", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get => %d", w.Code)
	}
	var got preferencesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Managed {
		t.Error("managed=false in response under a Managed profile")
	}
	if got.BlockEventsEnabled {
		t.Error("default block_events_enabled should stay false under a managed profile")
	}
}
