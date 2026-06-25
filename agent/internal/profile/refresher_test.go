package profile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRefresherConditionalReapply(t *testing.T) {
	// httptest binds to loopback, which the SE-01 guard refuses; relax it
	// for the test (the guard itself is covered in profile_test.go).
	orig := rejectPrivateHost
	rejectPrivateHost = func(string) error { return nil }
	t.Cleanup(func() { rejectPrivateHost = orig })

	var mu sync.Mutex
	etag := "v1"
	body := `{"name":"acme","version":"1.0.0"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		curETag, curBody := etag, body
		mu.Unlock()
		if r.Header.Get("If-None-Match") == curETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", curETag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(curBody))
	}))
	defer srv.Close()

	holder := NewHolder(nil)
	applied := 0
	var lastVersion string
	apply := func(_ context.Context, p *Profile) error {
		applied++
		lastVersion = p.Version
		return holder.Set(p)
	}
	r := NewRefresher(holder, srv.URL, time.Minute, apply)
	r.client = srv.Client()
	r.now = func() time.Time { return time.Unix(100, 0) }

	ctx := context.Background()

	// First check: 200 → applied once.
	changed, err := r.checkOnce(ctx)
	if err != nil || !changed {
		t.Fatalf("first check: changed=%v err=%v", changed, err)
	}
	if applied != 1 || lastVersion != "1.0.0" {
		t.Fatalf("apply not called correctly: applied=%d ver=%q", applied, lastVersion)
	}

	// Second check: unchanged → 304 → no re-apply.
	changed, err = r.checkOnce(ctx)
	if err != nil || changed {
		t.Fatalf("second check should be no-op: changed=%v err=%v", changed, err)
	}
	if applied != 1 {
		t.Fatalf("re-applied on 304: applied=%d", applied)
	}

	// Remote changes → new ETag + body → re-apply.
	mu.Lock()
	etag, body = "v2", `{"name":"acme","version":"2.0.0"}`
	mu.Unlock()
	changed, err = r.checkOnce(ctx)
	if err != nil || !changed {
		t.Fatalf("third check should apply: changed=%v err=%v", changed, err)
	}
	if applied != 2 || lastVersion != "2.0.0" {
		t.Fatalf("change not applied: applied=%d ver=%q", applied, lastVersion)
	}

	st := r.Status()
	if !st.Enabled || st.ChecksTotal != 3 || st.ChangesTotal != 2 {
		t.Errorf("status = %+v", st)
	}
}

func TestRefresherDisabled(t *testing.T) {
	if NewRefresher(NewHolder(nil), "", 0, nil).Enabled() {
		t.Error("empty url / zero interval should be disabled")
	}
	// Start on a disabled refresher returns immediately.
	NewRefresher(NewHolder(nil), "", 0, nil).Start(context.Background(), nil)
}

func TestRefresherStopsOnContextCancel(t *testing.T) {
	orig := rejectPrivateHost
	rejectPrivateHost = func(string) error { return nil }
	t.Cleanup(func() { rejectPrivateHost = orig })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "x")
		_, _ = w.Write([]byte(`{"name":"a","version":"1"}`))
	}))
	defer srv.Close()

	r := NewRefresher(NewHolder(nil), srv.URL, 10*time.Millisecond,
		func(_ context.Context, p *Profile) error { return nil })
	r.client = srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Start(ctx, nil); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}
