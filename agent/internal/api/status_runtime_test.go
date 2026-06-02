package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStatus_IncludesRuntimeAndPatternsAndRules verifies that Phase 6
// Task 17's enrichment of /api/status renders the runtime stats block,
// the pattern count when a DLP scanner is wired, and the rule file
// section when rule files are configured.
func TestStatus_IncludesRuntimeAndPatternsAndRules(t *testing.T) {
	srv, _, _ := newTestServer(t)

	dir := t.TempDir()
	a := filepath.Join(dir, "ai_chat_dlp.txt")
	if err := os.WriteFile(a, []byte("# rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.SetRuleFiles([]string{a, filepath.Join(dir, "missing.txt")})
	srv.SetDLP(&fakeDLP{thr: nil})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Runtime.GoVersion == "" {
		t.Errorf("runtime.go_version missing")
	}
	if got.Runtime.NumCPU < 1 {
		t.Errorf("runtime.num_cpu = %d", got.Runtime.NumCPU)
	}
	if len(got.Rules) != 1 {
		t.Errorf("rules len = %d, want 1 (missing file should be skipped)", len(got.Rules))
	}
}

// TestDLPScan_RateLimited_Returns429 confirms the limiter rejects
// over-budget traffic with HTTP 429.
func TestDLPScan_RateLimited_Returns429(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{})
	srv.SetScanRateLimit(1, 1)
	handler := srv.Handler()

	// First request consumes the only token.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"x"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("first call code = %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Second back-to-back call must be throttled.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"y"}`)))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second call code = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
}

// stubAgentUpdater is a minimal AgentSelfUpdater for handler tests.
type stubAgentUpdater struct {
	check      AgentUpdateCheck
	checkErr   error
	stage      AgentUpdateStage
	stageErr   error
	stageCalls int
}

func (s *stubAgentUpdater) CheckLatest(_ context.Context) (AgentUpdateCheck, error) {
	return s.check, s.checkErr
}
func (s *stubAgentUpdater) DownloadAndStage(_ context.Context) (AgentUpdateStage, error) {
	s.stageCalls++
	return s.stage, s.stageErr
}

func TestAgentUpdateCheck_ReturnsManifestResult(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAgentUpdater(&stubAgentUpdater{check: AgentUpdateCheck{
		Latest:          "0.2.0",
		Current:         "0.1.0",
		UpdateAvailable: true,
	}})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/agent/update-check", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "update_available") {
		t.Errorf("body missing update_available field: %s", rec.Body.String())
	}
}

func TestAgentUpdate_WithoutUpdaterReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/agent/update",
		bytes.NewBufferString("")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestAgentUpdate_BubblesUpdaterError(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAgentUpdater(&stubAgentUpdater{stageErr: errors.New("manifest unreachable")})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/agent/update",
		bytes.NewBufferString("")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", rec.Code)
	}
}
