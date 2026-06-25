package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

// newCanaryServer returns a server wired with a real DLP pipeline so
// the pipeline acts as both the scanner and the canary registrar —
// exercising the full create → register → scan → trigger path.
func newCanaryServer(t *testing.T) *Server {
	t.Helper()
	srv, _, _ := newTestServer(t)
	pipe := dlp.NewPipeline(dlp.ScoreWeights{}, dlp.NewThresholdEngine(dlp.DefaultThresholds()))
	pipe.Rebuild(nil, nil)
	srv.SetDLP(pipe)
	srv.SetCanaryRegistrar(pipe)
	return srv
}

func createCanary(t *testing.T, srv *Server, label string) store.Canary {
	t.Helper()
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/canary",
		bytes.NewBufferString(fmt.Sprintf(`{"label":%q}`, label)))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create canary: code=%d body=%q", rec.Code, rec.Body.String())
	}
	var c store.Canary
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return c
}

func listCanaries(t *testing.T, srv *Server) []store.Canary {
	t.Helper()
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/canary", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list canaries: code=%d body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Canaries []store.Canary `json:"canaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return resp.Canaries
}

func scan(t *testing.T, srv *Server, content string) dlp.ScanResult {
	t.Helper()
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(fmt.Sprintf(`{"content":%q}`, content)))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan: code=%d body=%q", rec.Code, rec.Body.String())
	}
	var res dlp.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	return res
}

func TestCanaryLifecycle(t *testing.T) {
	srv := newCanaryServer(t)

	c := createCanary(t, srv, "prod_db_password_file")
	if c.Token == "" || c.ID == "" {
		t.Fatalf("incomplete canary: %+v", c)
	}

	// It is registered and now blocks when its token surfaces in a scan.
	res := scan(t, srv, "leaked config: "+c.Token+" oops")
	if !res.Blocked {
		t.Fatalf("expected canary scan to block, got %+v", res)
	}
	if res.PatternName != "Canary:prod_db_password_file" {
		t.Errorf("PatternName = %q", res.PatternName)
	}

	// The scan recorded a trigger.
	list := listCanaries(t, srv)
	if len(list) != 1 {
		t.Fatalf("len(list) = %d", len(list))
	}
	if list[0].TriggerCount != 1 {
		t.Errorf("trigger_count = %d, want 1", list[0].TriggerCount)
	}
	if list[0].LastTriggered == 0 {
		t.Error("last_triggered should be set after a trigger")
	}

	// Delete removes both the row and the live tripwire.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodDelete, "/api/dlp/canary/"+c.ID, nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := listCanaries(t, srv); len(got) != 0 {
		t.Fatalf("expected empty list after delete, got %d", len(got))
	}
	if res := scan(t, srv, "config: "+c.Token); res.Blocked {
		t.Errorf("deleted canary should no longer block: %+v", res)
	}
}

func TestCanaryCreateValidation(t *testing.T) {
	srv := newCanaryServer(t)

	// Empty label → 400.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/canary",
		bytes.NewBufferString(`{"label":"  "}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty label: code=%d", rec.Code)
	}

	// Missing id on DELETE path → handled by item route; deleting an
	// unknown id → 404.
	rec = httptest.NewRecorder()
	req = newLocalRequest(http.MethodDelete, "/api/dlp/canary/does-not-exist", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: code=%d", rec.Code)
	}
}

func TestCanaryUnconfigured(t *testing.T) {
	// No registrar wired → 503.
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/canary", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without registrar, got %d", rec.Code)
	}
}
