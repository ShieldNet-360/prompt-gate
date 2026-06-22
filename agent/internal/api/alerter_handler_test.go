package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeAlertReporter struct{ st AlertStatus }

func (f fakeAlertReporter) AlertStatus() AlertStatus { return f.st }

func TestAlertStatus_Unconfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/alerter/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without reporter, got %d", rec.Code)
	}
}

func TestAlertStatus_Configured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAlertReporter(fakeAlertReporter{st: AlertStatus{
		Enabled: true, ThresholdBlocks: 10, LastFiredAt: 1750000000, FiresTotal: 3,
	}})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/alerter/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var got AlertStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Enabled || got.ThresholdBlocks != 10 || got.FiresTotal != 3 {
		t.Errorf("status = %+v", got)
	}
}
