package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// slowDLP is a DLPScanner that blocks for the specified duration so
// the shutdown test can prove an in-flight scan finishes before the
// HTTP server returns from Shutdown().
type slowDLP struct {
	delay   time.Duration
	thr     *dlp.ThresholdEngine
	weights dlp.ScoreWeights
	done    int32
}

func (s *slowDLP) Scan(ctx context.Context, _ string) dlp.ScanResult {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
	}
	atomic.StoreInt32(&s.done, 1)
	return dlp.ScanResult{Blocked: false}
}
func (s *slowDLP) ScanSession(ctx context.Context, _ string, _ string) dlp.ScanResult {
	return s.Scan(ctx, "")
}
func (s *slowDLP) ScanWithContext(ctx context.Context, _, _ string, _ dlp.SourceContext) dlp.ScanResult {
	return s.Scan(ctx, "")
}
func (s *slowDLP) Redact(ctx context.Context, _, _ string, _ dlp.SourceContext) dlp.RedactionResult {
	return dlp.RedactionResult{ScanResult: s.Scan(ctx, ""), Action: dlp.ActionAllow}
}
func (s *slowDLP) Threshold() *dlp.ThresholdEngine { return s.thr }
func (s *slowDLP) SetWeights(w dlp.ScoreWeights)   { s.weights = w }
func (s *slowDLP) Patterns() []*dlp.Pattern        { return nil }
func (s *slowDLP) Allowlist() *dlp.Allowlist       { return nil }

// TestGracefulShutdown_WaitsForInFlightScan starts a real *http.Server
// against the API handler, fires a long-running scan, then calls
// Shutdown() with a generous timeout. The shutdown must not return
// until the scan finishes — Phase 6 Task 16's "in-flight scans finish
// before exit" guarantee. A failure here manifests as the response
// arriving truncated or never at all.
func TestGracefulShutdown_WaitsForInFlightScan(t *testing.T) {
	srv, _, _ := newTestServer(t)
	slow := &slowDLP{delay: 200 * time.Millisecond}
	srv.SetDLP(slow)
	srv.SetScanRateLimit(0, 1) // disable limiter for this test

	// Use a real net.Listener so we can read the ephemeral port back.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	httpServer := &http.Server{Handler: srv.Handler()}
	go func() { _ = httpServer.Serve(l) }()
	t.Cleanup(func() { _ = httpServer.Close() })

	respCh := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/api/dlp/scan",
			strings.NewReader(`{"content":"x"}`))
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer prompt-gate-local-token-2025")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			respCh <- -1
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		respCh <- resp.StatusCode
	}()

	// Give the request enough time to land on the server before we
	// trigger shutdown.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// After Shutdown() returns, the in-flight scan must have completed.
	if atomic.LoadInt32(&slow.done) == 0 {
		t.Fatal("Shutdown() returned before in-flight scan finished")
	}

	// And the original request must have observed a 200 OK.
	select {
	case code := <-respCh:
		if code != http.StatusOK {
			t.Fatalf("client got %d, expected 200", code)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client never received a response")
	}
}
