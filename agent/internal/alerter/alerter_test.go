package alerter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
)

type fakeStats struct {
	mu     sync.Mutex
	blocks int64
}

func (f *fakeStats) set(n int64) { f.mu.Lock(); f.blocks = n; f.mu.Unlock() }
func (f *fakeStats) GetStats(context.Context) (stats.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return stats.Snapshot{DLPBlocksTotal: f.blocks}, nil
}

func relaxURLCheck(t *testing.T) {
	t.Helper()
	old := checkURL
	checkURL = func(string) error { return nil }
	t.Cleanup(func() { checkURL = old })
}

func TestAlerterFiresAtThreshold(t *testing.T) {
	relaxURLCheck(t)
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fs := &fakeStats{}
	a, err := New(Options{
		URL: srv.URL, AgentVersion: "1.2.3", ThresholdBlocks: 5,
		Stats: fs, HTTPClient: srv.Client(),
		Now: func() time.Time { return time.Unix(1000, 0) },
	})
	if err != nil || a == nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := a.setBaseline(ctx); err != nil {
		t.Fatal(err)
	}

	// Below threshold → no fire.
	fs.set(4)
	if fired, _ := a.Check(ctx); fired {
		t.Fatal("fired below threshold")
	}
	// At threshold → fire.
	fs.set(5)
	fired, err := a.Check(ctx)
	if err != nil || !fired {
		t.Fatalf("expected fire at threshold: fired=%v err=%v", fired, err)
	}

	mu.Lock()
	n := len(bodies)
	last := bodies[len(bodies)-1]
	mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 POST, got %d", n)
	}
	var p Payload
	if err := json.Unmarshal(last, &p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if p.AlertType != AlertType || p.BlocksInWindow != 5 || p.AgentVersion != "1.2.3" {
		t.Errorf("payload = %+v", p)
	}

	// Status reflects the fire.
	st := a.Status()
	if !st.Enabled || st.FiresTotal != 1 || st.LastFiredAt != 1000 {
		t.Errorf("status = %+v", st)
	}

	// Next window accumulates from the new baseline (5).
	fs.set(9) // delta 4 < 5
	if fired, _ := a.Check(ctx); fired {
		t.Error("fired on delta below threshold after reset")
	}
	fs.set(10) // delta 5 → fire
	if fired, _ := a.Check(ctx); !fired {
		t.Error("expected fire after accumulating to threshold")
	}
}

func TestPayloadHasNoAccessData(t *testing.T) {
	p := Payload{AlertType: AlertType, AgentVersion: "1", OSType: "x", OSArch: "y", BlocksInWindow: 3, ExportedAt: 1}
	b, _ := json.Marshal(p)
	forbidden := regexp.MustCompile(`(?i)url|domain|ip|match|host|pattern|content|value`)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k := range m {
		if forbidden.MatchString(k) {
			t.Errorf("payload key %q looks like access data", k)
		}
	}
}

func TestDisabledWhenURLEmpty(t *testing.T) {
	a, err := New(Options{})
	if err != nil || a != nil {
		t.Fatalf("empty URL should yield (nil,nil), got (%v,%v)", a, err)
	}
	if a.Enabled() {
		t.Error("nil alerter should report not enabled")
	}
	if (Status{}) != a.Status() {
		t.Error("nil alerter Status should be zero")
	}
}

func TestRejectsNonHTTPSInProd(t *testing.T) {
	// Default (strict) checkURL rejects http and loopback.
	if _, err := New(Options{URL: "http://example.com", Stats: &fakeStats{}}); err == nil {
		t.Error("expected http URL to be rejected")
	}
}
