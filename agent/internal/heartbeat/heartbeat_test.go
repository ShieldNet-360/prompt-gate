package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
)

type fakeStats struct {
	snap stats.Snapshot
	err  error
}

func (f fakeStats) GetStats(_ context.Context) (stats.Snapshot, error) {
	return f.snap, f.err
}

// relaxURLCheckForTest swaps the package-level strict SE-04 URL check
// for a no-op while a test runs. httptest gives us http://127.0.0.1
// URLs which the production validator refuses; the SE-04 guard itself
// is exercised by security_exploit_test.go, so individual functional
// tests can opt out here without weakening production behaviour.
func relaxURLCheckForTest(t *testing.T) {
	t.Helper()
	orig := checkURL
	checkURL = func(string) error { return nil }
	t.Cleanup(func() { checkURL = orig })
}

func TestNewDisabledWhenURLEmpty(t *testing.T) {
	h, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h != nil {
		t.Fatalf("expected nil heartbeat when URL empty, got %+v", h)
	}
}

func TestNewRequiresStatsView(t *testing.T) {
	if _, err := New(Options{URL: "http://example/"}); err == nil {
		t.Fatalf("expected error when Stats nil")
	}
}

func TestSendOncePayload(t *testing.T) {
	relaxURLCheckForTest(t)
	var got Payload
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		// Make sure no extra fields snuck in.
		var asMap map[string]any
		if err := json.Unmarshal(body, &asMap); err != nil {
			t.Errorf("unmarshal map: %v", err)
		}
		expectKeys := map[string]struct{}{
			"agent_version": {}, "os_type": {}, "os_arch": {},
			"aggregate_counters": {},
		}
		for k := range asMap {
			if _, ok := expectKeys[k]; !ok {
				t.Errorf("unexpected top-level field %q in heartbeat payload", k)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h, err := New(Options{
		URL:          srv.URL,
		AgentVersion: "9.9.9",
		Interval:     time.Hour,
		HTTPClient:   srv.Client(),
		Stats: fakeStats{snap: stats.Snapshot{
			DNSQueriesTotal: 10,
			DNSBlocksTotal:  2,
			DLPScansTotal:   3,
			DLPBlocksTotal:  1,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !h.Enabled() {
		t.Fatalf("heartbeat should be enabled when URL set")
	}
	if err := h.SendOnce(context.Background()); err != nil {
		t.Fatalf("SendOnce: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected one POST, got %d", hits.Load())
	}
	if got.AgentVersion != "9.9.9" {
		t.Fatalf("unexpected agent_version %q", got.AgentVersion)
	}
	if got.Counters.DNSQueriesTotal != 10 || got.Counters.DLPBlocksTotal != 1 {
		t.Fatalf("counters not forwarded: %+v", got.Counters)
	}
}

func TestPayloadShapeHasNoAccessFields(t *testing.T) {
	// Defensive check: marshal a Payload and assert the JSON keys
	// are exactly the four privacy-safe top-level fields.
	body, err := json.Marshal(Payload{Counters: stats.Snapshot{DNSQueriesTotal: 1}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	forbidden := []string{"domain", "url", "request", "ip", "match", "content"}
	flat, _ := json.Marshal(asMap)
	flatStr := string(flat)
	for _, k := range forbidden {
		if contains(flatStr, k) {
			t.Fatalf("payload leaked %q field: %s", k, flatStr)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSendOnceErrorOnNon2xx(t *testing.T) {
	relaxURLCheckForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	h, _ := New(Options{
		URL:        srv.URL,
		HTTPClient: srv.Client(),
		Stats:      fakeStats{},
	})
	if err := h.SendOnce(context.Background()); err == nil {
		t.Fatalf("expected error on 5xx response")
	}
}

func TestStartRespectsCancellation(t *testing.T) {
	relaxURLCheckForTest(t)
	hits := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h, _ := New(Options{
		URL:        srv.URL,
		Interval:   5 * time.Millisecond,
		HTTPClient: srv.Client(),
		Stats:      fakeStats{},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Start(ctx, nil)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Start did not exit on cancel")
	}
	if hits.Load() < 1 {
		t.Fatalf("expected at least one POST, got %d", hits.Load())
	}
}
