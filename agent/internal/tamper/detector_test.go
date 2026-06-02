package tamper

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeReporter struct{ count int64 }

func (f *fakeReporter) IncrementTamperDetections() { atomic.AddInt64(&f.count, 1) }

func TestDetectorOKByDefault(t *testing.T) {
	d := New(Options{
		ExpectedDNSServer: "127.0.0.1",
		DNSCheck:          func(_ context.Context, _ string) (bool, error) { return true, nil },
		ProxyCheck:        func(_ context.Context, _ string) (bool, error) { return true, nil },
		Now:               func() time.Time { return time.Unix(1700000000, 0) },
	})
	st := d.CheckNow(context.Background())
	if !st.DNSOK || !st.ProxyOK {
		t.Fatalf("expected ok, got %+v", st)
	}
	if st.DetectionsTotal != 0 {
		t.Fatalf("expected no detections, got %d", st.DetectionsTotal)
	}
}

func TestDetectorDNSTamper(t *testing.T) {
	rep := &fakeReporter{}
	tamperHits := atomic.Int64{}
	d := New(Options{
		ExpectedDNSServer: "127.0.0.1",
		DNSCheck:          func(_ context.Context, _ string) (bool, error) { return false, nil },
		Reporter:          rep,
		OnTamper:          func(_ string) { tamperHits.Add(1) },
	})
	d.CheckNow(context.Background())
	st := d.Status()
	if st.DNSOK {
		t.Fatalf("expected dns_ok=false, got true")
	}
	if st.DetectionsTotal != 1 {
		t.Fatalf("expected 1 detection, got %d", st.DetectionsTotal)
	}
	if rep.count != 1 {
		t.Fatalf("reporter not bumped: %d", rep.count)
	}
	if tamperHits.Load() != 1 {
		t.Fatalf("OnTamper not called once: %d", tamperHits.Load())
	}

	// Subsequent checks while DNS is still bad must NOT re-bump
	// the counter — we count *transitions*, not steady-state.
	d.CheckNow(context.Background())
	if rep.count != 1 {
		t.Fatalf("steady-state tamper should not re-bump: %d", rep.count)
	}
}

func TestDetectorProxyTamper(t *testing.T) {
	rep := &fakeReporter{}
	d := New(Options{
		ExpectedDNSServer: "127.0.0.1",
		ExpectedProxyAddr: "127.0.0.1:8443",
		DNSCheck:          func(_ context.Context, _ string) (bool, error) { return true, nil },
		ProxyCheck:        func(_ context.Context, _ string) (bool, error) { return false, nil },
		Reporter:          rep,
	})
	d.CheckNow(context.Background())
	st := d.Status()
	if st.ProxyOK {
		t.Fatalf("expected proxy_ok=false")
	}
	if st.DetectionsTotal != 1 {
		t.Fatalf("expected 1 detection")
	}
}

func TestDetectorErrorsTreatedAsOK(t *testing.T) {
	rep := &fakeReporter{}
	d := New(Options{
		DNSCheck: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("transient")
		},
		Reporter: rep,
	})
	st := d.CheckNow(context.Background())
	// Errors keep the last known good state; default is OK.
	if !st.DNSOK {
		t.Fatalf("transient error must not flip dns_ok: %+v", st)
	}
	if rep.count != 0 {
		t.Fatalf("transient error must not bump reporter")
	}
}

func TestDetectorStart(t *testing.T) {
	d := New(Options{
		Interval: 5 * time.Millisecond,
		DNSCheck: func(_ context.Context, _ string) (bool, error) { return true, nil },
	})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.Start(ctx)
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()
	wg.Wait()
	if d.Status().LastCheck.IsZero() {
		t.Fatalf("Start should have run at least one check")
	}
}

func TestProxyCheckEnvFallback(t *testing.T) {
	// Construct an Options that bypasses platformProxyCheck so we
	// can drive the env-var helper directly.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:8443")
	if !proxyCheckEnv("127.0.0.1:8443") {
		t.Fatalf("expected env-based proxy check to pass")
	}
	t.Setenv("HTTPS_PROXY", "http://192.168.1.1:9191")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("http_proxy", "")
	if proxyCheckEnv("127.0.0.1:8443") {
		t.Fatalf("expected env-based proxy check to fail")
	}
}
