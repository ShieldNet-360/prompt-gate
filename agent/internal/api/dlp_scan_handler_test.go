// Phase 8 Config F — Slice 1 schema tests for POST /api/dlp/scan.
//
// Asserts:
//   1. Request body without a `source` field continues to dispatch
//      to Scan / ScanSession (Config E behaviour unchanged).
//   2. Request body with a non-zero `source` dispatches to
//      ScanWithContext and forwards the struct unchanged.
//   3. Request body with `"source": {}` (zero-valued struct)
//      dispatches to Scan / ScanSession — IsZero() is honoured so an
//      explicitly-empty source object does not waste the bias path.
//   4. Request body with `source` AND `session_id` still dispatches
//      to ScanWithContext (source takes precedence; ScanWithContext
//      handles the session internally).
//
// Privacy invariant note: the handler drops req.Source after
// dispatch (handlers.go). This file does not directly assert that
// drop because the request-level instance is GC'd at scope-exit
// anyway; the existing TestPrivacy_* sweeps catch any persistence.

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

func TestPhase8_DLPScan_NoSource_DispatchesToScan(t *testing.T) {
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"hello"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if f.lastCall != "scan" {
		t.Fatalf("expected dispatch to Scan, got %q", f.lastCall)
	}
}

func TestPhase8_DLPScan_SessionOnly_DispatchesToSession(t *testing.T) {
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"hello","session_id":"tab-1"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if f.lastCall != "session" {
		t.Fatalf("expected dispatch to ScanSession, got %q", f.lastCall)
	}
}

func TestPhase8_DLPScan_EmptySource_DispatchesToScan(t *testing.T) {
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"hello","source":{}}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if f.lastCall != "scan" {
		t.Fatalf("expected dispatch to Scan (empty source), got %q", f.lastCall)
	}
}

func TestPhase8_DLPScan_NonEmptySource_DispatchesToContext(t *testing.T) {
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	body := `{
		"content": "hello",
		"source": {
			"destination_kind": "ai_chat",
			"destination_host": "chat.openai.com",
			"element_kind": "contenteditable",
			"in_code_fence": false,
			"language_hint": "",
			"surrounding_hash": "a1b2c3d4e5f60718",
			"page_url_hash": "f1e2d3c4b5a69788"
		}
	}`
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if f.lastCall != "context" {
		t.Fatalf("expected dispatch to ScanWithContext, got %q", f.lastCall)
	}
	if f.lastSource.DestinationKind != "ai_chat" {
		t.Errorf("DestinationKind = %q, want %q",
			f.lastSource.DestinationKind, "ai_chat")
	}
	if f.lastSource.DestinationHost != "chat.openai.com" {
		t.Errorf("DestinationHost = %q, want %q",
			f.lastSource.DestinationHost, "chat.openai.com")
	}
	if f.lastSource.ElementKind != "contenteditable" {
		t.Errorf("ElementKind = %q, want %q",
			f.lastSource.ElementKind, "contenteditable")
	}
	if f.lastSource.SurroundingHash != "a1b2c3d4e5f60718" {
		t.Errorf("SurroundingHash = %q, want %q",
			f.lastSource.SurroundingHash, "a1b2c3d4e5f60718")
	}
}

func TestPhase8_DLPScan_SessionAndSource_PrefersContext(t *testing.T) {
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	body := `{
		"content": "hello",
		"session_id": "tab-1",
		"source": {"destination_kind": "ai_chat"}
	}`
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if f.lastCall != "context" {
		t.Fatalf("expected ScanWithContext to take precedence over ScanSession, got %q", f.lastCall)
	}
}

func TestPhase8_DLPScan_ResponseShapeUnchanged(t *testing.T) {
	// Regression: response stays {blocked, pattern_name, score}
	// regardless of which dispatch path was taken.
	srv, _, _ := newTestServer(t)
	f := &fakeDLP{
		thr:    dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		result: dlp.ScanResult{Blocked: true, PatternName: "AWS Access Key", Score: 4},
	}
	srv.SetDLP(f)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"x","source":{"destination_kind":"ai_chat"}}`))
	srv.Handler().ServeHTTP(rec, req)
	var got dlp.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Blocked || got.PatternName != "AWS Access Key" || got.Score != 4 {
		t.Fatalf("response shape changed: got %+v", got)
	}
}
