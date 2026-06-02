package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memVersionStore struct {
	mu       sync.Mutex
	versions []string
}

func (m *memVersionStore) CurrentRuleVersion(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.versions) == 0 {
		return "", nil
	}
	return m.versions[len(m.versions)-1], nil
}

func (m *memVersionStore) AppendRuleVersion(_ context.Context, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versions = append(m.versions, v)
	return nil
}

// mockServer serves a manifest plus a set of rule files. Each fetched
// path increments fetches[path] so tests can assert which files were
// pulled.
type mockServer struct {
	mu       sync.Mutex
	manifest Manifest
	files    map[string][]byte
	fetches  map[string]int
}

func (m *mockServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.fetches[r.URL.Path]++
		m.mu.Unlock()
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(m.manifest)
			return
		}
		key := r.URL.Path[1:] // strip leading /
		body, ok := m.files[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// newServer builds a manifest + files map for a fixed test fixture.
func newServer(t *testing.T, files map[string]string, version string) (*mockServer, *httptest.Server) {
	t.Helper()
	ms := &mockServer{
		manifest: Manifest{Version: version},
		files:    make(map[string][]byte, len(files)),
		fetches:  make(map[string]int),
	}
	for name, content := range files {
		b := []byte(content)
		ms.files[name] = b
		ms.manifest.Files = append(ms.manifest.Files, ManifestFile{
			Name:   name,
			SHA256: sha256Hex(b),
		})
	}
	srv := httptest.NewTLSServer(ms.handler())
	t.Cleanup(srv.Close)
	return ms, srv
}

func TestUpdater_NewValidatesOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatalf("expected error for empty ManifestURL")
	}
	if _, err := New(Options{ManifestURL: "https://x"}); err == nil {
		t.Fatalf("expected error for empty RulesDir")
	}
	u, err := New(Options{ManifestURL: "https://x", RulesDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if u.opts.PollInterval != DefaultPollInterval {
		t.Errorf("default PollInterval = %v, want %v", u.opts.PollInterval, DefaultPollInterval)
	}
}

func TestUpdater_FreshInstall_DownloadsEverything(t *testing.T) {
	dir := t.TempDir()
	ms, srv := newServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
		"phishing.txt":   "evil.test\n",
	}, "1.0.0")

	store := &memVersionStore{}
	var reloads atomic.Int32

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		HTTPClient:   srv.Client(),
		Store:        store,
		Reload: func(_ context.Context) error {
			reloads.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := u.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !res.Updated || res.Version != "1.0.0" || res.FilesDownloaded != 2 {
		t.Fatalf("first run result = %+v", res)
	}
	if reloads.Load() != 1 {
		t.Errorf("reload count = %d, want 1", reloads.Load())
	}

	// Files should exist with the expected contents.
	for _, name := range []string{"ai_allowed.txt", "phishing.txt"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(b) != string(ms.files[name]) {
			t.Errorf("%s content mismatch", name)
		}
	}

	// Version persisted to store.
	v, _ := store.CurrentRuleVersion(context.Background())
	if v != "1.0.0" {
		t.Errorf("store version = %q, want 1.0.0", v)
	}

	// Status snapshot reflects the run.
	st := u.Status()
	if st.CurrentVersion != "1.0.0" || st.UpdateURL == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestUpdater_DeltaSkipsUnchangedFiles(t *testing.T) {
	dir := t.TempDir()
	ms, srv := newServer(t, map[string]string{
		"a.txt": "alpha\n",
		"b.txt": "beta\n",
	}, "1.0.0")

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("first CheckNow: %v", err)
	}
	// One fetch per file expected.
	if ms.fetches["/a.txt"] != 1 || ms.fetches["/b.txt"] != 1 {
		t.Fatalf("first run fetches = %+v", ms.fetches)
	}

	// Bump a.txt; b.txt unchanged. Re-run and assert only a.txt was
	// re-fetched on the delta pass.
	//
	// newServer builds ms.manifest.Files from a Go map, so iteration
	// order — and therefore the index of "a.txt" in the slice — is
	// not deterministic. Look up the entry by name instead of
	// poking Files[0] directly, otherwise this test fails ~50% of
	// the time when "b.txt" happens to land first.
	newA := []byte("alpha-v2\n")
	ms.mu.Lock()
	ms.files["a.txt"] = newA
	found := false
	for i := range ms.manifest.Files {
		if ms.manifest.Files[i].Name == "a.txt" {
			ms.manifest.Files[i] = ManifestFile{Name: "a.txt", SHA256: sha256Hex(newA)}
			found = true
			break
		}
	}
	ms.manifest.Version = "1.0.1"
	ms.mu.Unlock()
	if !found {
		t.Fatalf("a.txt entry not found in manifest")
	}

	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("second CheckNow: %v", err)
	}
	if ms.fetches["/a.txt"] != 2 {
		t.Errorf("a.txt fetch count = %d, want 2", ms.fetches["/a.txt"])
	}
	if ms.fetches["/b.txt"] != 1 {
		t.Errorf("b.txt fetch count = %d, want 1 (unchanged file must NOT be re-fetched)", ms.fetches["/b.txt"])
	}

	got, _ := os.ReadFile(filepath.Join(dir, "a.txt"))
	if string(got) != "alpha-v2\n" {
		t.Errorf("a.txt content = %q", string(got))
	}
}

func TestUpdater_RejectsTamperedFile(t *testing.T) {
	dir := t.TempDir()
	ms, srv := newServer(t, map[string]string{
		"a.txt": "good\n",
	}, "1.0.0")
	// Lie about the SHA in the manifest.
	ms.mu.Lock()
	ms.manifest.Files[0].SHA256 = sha256Hex([]byte("DIFFERENT"))
	ms.mu.Unlock()

	u, err := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		HTTPClient:  srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatalf("expected error for SHA mismatch")
	}
	// The local file must remain absent — tampered downloads never replace.
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); !os.IsNotExist(err) {
		t.Fatalf("a.txt unexpectedly exists after tampered download")
	}
}

func TestUpdater_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	// Pre-create with stale content.
	stale := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(stale, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, srv := newServer(t, map[string]string{
		"a.txt": "fresh\n",
	}, "1.0.0")

	u, _ := New(Options{ManifestURL: srv.URL + "/manifest.json", RulesDir: dir, HTTPClient: srv.Client()})
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	got, _ := os.ReadFile(stale)
	if string(got) != "fresh\n" {
		t.Errorf("file = %q, want fresh", string(got))
	}
	// No leftover .rule-*.tmp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if name := e.Name(); len(name) > 5 && name[:5] == ".rule" {
			t.Errorf("leftover temp file: %s", name)
		}
	}
}

func TestUpdater_VersionTracking(t *testing.T) {
	dir := t.TempDir()
	store := &memVersionStore{}
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "1.0.0")

	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		Store:       store,
		HTTPClient:  srv.Client(),
	})
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.versions) != 1 || store.versions[0] != "1.0.0" {
		t.Fatalf("versions = %v", store.versions)
	}

	// Re-running with the same manifest must NOT append a new row.
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.versions) != 1 {
		t.Errorf("duplicate version appended: %v", store.versions)
	}
}

func TestUpdater_ReloadOnlyOnChange(t *testing.T) {
	dir := t.TempDir()
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "1.0.0")
	var reloads atomic.Int32

	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		HTTPClient:  srv.Client(),
		Reload: func(_ context.Context) error {
			reloads.Add(1)
			return nil
		},
	})
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Errorf("reload after first run = %d", reloads.Load())
	}

	// Second run, nothing changed, no reload.
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reloads.Load() != 1 {
		t.Errorf("reload count after unchanged run = %d, want 1", reloads.Load())
	}
}

// A failing Reload callback must NOT advance the persisted/in-memory
// version. Otherwise the next CheckNow would see all files matching
// SHAs on disk (count=0) AND a version that already equals the
// manifest's (versionChanged=false), skipping the reload entirely —
// the live engine would stay stuck on the previous ruleset until the
// manifest version bumps again.
func TestUpdater_ReloadFailurePreservesVersionForRetry(t *testing.T) {
	dir := t.TempDir()
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "1.0.0")
	store := &memVersionStore{}

	var reloads atomic.Int32
	var failNext atomic.Bool
	failNext.Store(true)

	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		Store:       store,
		HTTPClient:  srv.Client(),
		Reload: func(_ context.Context) error {
			reloads.Add(1)
			if failNext.Load() {
				return fmt.Errorf("simulated reload failure")
			}
			return nil
		},
	})

	// First call: applyManifest writes the file, Reload is called
	// but returns an error. Expect CheckNow to surface that error
	// and leave the persisted version empty.
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatalf("expected reload error on first poll")
	}
	if reloads.Load() != 1 {
		t.Fatalf("reload count after failing first poll = %d, want 1", reloads.Load())
	}
	if len(store.versions) != 0 {
		t.Fatalf("version persisted despite reload failure: %v", store.versions)
	}
	if u.Status().CurrentVersion != "" {
		t.Errorf("in-memory currentVersion advanced despite reload failure: %q", u.Status().CurrentVersion)
	}

	// Second call: files on disk already match the manifest SHA
	// (count=0). The reload MUST still be retried because the
	// persisted version is stale. Let it succeed this time and
	// assert the version is finally committed.
	failNext.Store(false)
	res, err := u.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("second CheckNow: %v", err)
	}
	if reloads.Load() != 2 {
		t.Fatalf("reload count after retry = %d, want 2 (must retry even when count=0)", reloads.Load())
	}
	if !res.Updated || res.Version != "1.0.0" {
		t.Errorf("retry result = %+v", res)
	}
	if got, _ := store.CurrentRuleVersion(context.Background()); got != "1.0.0" {
		t.Errorf("store version after successful retry = %q, want 1.0.0", got)
	}
}

func TestUpdater_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	ms := &mockServer{
		manifest: Manifest{
			Version: "1.0.0",
			Files: []ManifestFile{
				{Name: "../evil.txt", SHA256: sha256Hex([]byte("x"))},
			},
		},
		files:   map[string][]byte{"../evil.txt": []byte("x")},
		fetches: map[string]int{},
	}
	srv := httptest.NewTLSServer(ms.handler())
	defer srv.Close()

	u, _ := New(Options{ManifestURL: srv.URL + "/manifest.json", RulesDir: dir, HTTPClient: srv.Client()})
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatalf("expected error for path traversal in name")
	}
}

func TestUpdater_StartHonoursContext(t *testing.T) {
	dir := t.TempDir()
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "1.0.0")
	u, _ := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		RulesDir:     dir,
		PollInterval: 10 * time.Millisecond,
		HTTPClient:   srv.Client(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Start(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Start did not exit on ctx cancel")
	}
}

func TestUpdater_ManifestFetchError(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := New(Options{ManifestURL: srv.URL + "/manifest.json", RulesDir: dir, HTTPClient: srv.Client()})
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatalf("expected error on 500 manifest")
	}
}

func TestUpdater_ExplicitURLOverride(t *testing.T) {
	dir := t.TempDir()
	// First handler serves the manifest with explicit URLs pointing
	// at a sibling host; the second handler serves the actual file.
	body := []byte("explicit\n")
	fileSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer fileSrv.Close()

	manSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "1.0.0",
			Files: []ManifestFile{
				{Name: "ex.txt", SHA256: sha256Hex(body), URL: fileSrv.URL + "/whatever"},
			},
		})
	}))
	defer manSrv.Close()

	insecureClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	u, _ := New(Options{ManifestURL: manSrv.URL + "/manifest.json", RulesDir: dir, HTTPClient: insecureClient})
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "ex.txt"))
	if string(got) != "explicit\n" {
		t.Errorf("file = %q", string(got))
	}
}

func TestUpdater_StatusBeforeAndAfter(t *testing.T) {
	dir := t.TempDir()
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "9.9.9")

	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u, _ := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: 2 * time.Hour,
		RulesDir:     dir,
		HTTPClient:   srv.Client(),
		Now:          func() time.Time { return fixed },
	})

	// Pre-check status is empty.
	before := u.Status()
	if !before.LastCheck.IsZero() {
		t.Errorf("LastCheck should be zero before any check, got %v", before.LastCheck)
	}

	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := u.Status()
	if after.CurrentVersion != "9.9.9" {
		t.Errorf("CurrentVersion = %q", after.CurrentVersion)
	}
	if !after.LastCheck.Equal(fixed) {
		t.Errorf("LastCheck = %v, want %v", after.LastCheck, fixed)
	}
	if !after.NextCheck.Equal(fixed.Add(2 * time.Hour)) {
		t.Errorf("NextCheck = %v", after.NextCheck)
	}
}

// Sanity: file SHA helper exposes the canonical form.
func TestFileSHA256_MissingReturnsErr(t *testing.T) {
	_, err := fileSHA256(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

// Smoke test that exercises the Start path long enough to make the
// initial check fire. We don't assert further behaviour — the other
// tests cover the update mechanics — only that Start does not panic
// or wedge when given a working endpoint.
func TestUpdater_StartCallsInitialCheck(t *testing.T) {
	dir := t.TempDir()
	_, srv := newServer(t, map[string]string{"x.txt": "1\n"}, "1.0.0")
	u, _ := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		RulesDir:     dir,
		PollInterval: time.Hour,
		HTTPClient:   srv.Client(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := u.Status()
		if st.CurrentVersion == "1.0.0" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Start did not run initial check within timeout")
}

// --- SE-03 signature verification tests ---

func TestUpdater_SignatureVerification_AcceptsValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	files := map[string]string{"x.txt": "1\n"}

	// Build manifest JSON.
	ms := &mockServer{
		manifest: Manifest{Version: "1.0.0"},
		files:    make(map[string][]byte),
		fetches:  make(map[string]int),
	}
	for name, content := range files {
		b := []byte(content)
		ms.files[name] = b
		ms.manifest.Files = append(ms.manifest.Files, ManifestFile{
			Name:   name,
			SHA256: sha256Hex(b),
		})
	}
	manifestJSON, _ := json.Marshal(ms.manifest)
	sig := ed25519.Sign(priv, manifestJSON)
	sigHex := hex.EncodeToString(sig)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ms.mu.Lock()
		defer ms.mu.Unlock()
		ms.fetches[r.URL.Path]++
		switch r.URL.Path {
		case "/manifest.json":
			w.Header().Set("X-Signature", sigHex)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifestJSON)
		default:
			name := r.URL.Path[1:]
			if b, ok := ms.files[name]; ok {
				_, _ = w.Write(b)
			} else {
				http.NotFound(w, r)
			}
		}
	}))
	t.Cleanup(srv.Close)

	u, err := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		HTTPClient:  srv.Client(),
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow with valid signature: %v", err)
	}
}

func TestUpdater_SignatureVerification_RejectsWrongKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()

	manifestJSON := []byte(`{"version":"1.0.0","files":[{"name":"x.txt","sha256":"` +
		sha256Hex([]byte("1\n")) + `"}]}`)
	wrongSig := ed25519.Sign(wrongPriv, manifestJSON)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Signature", hex.EncodeToString(wrongSig))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(manifestJSON)
	}))
	t.Cleanup(srv.Close)

	u, err := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		HTTPClient:  srv.Client(),
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatal("expected signature verification failure for wrong key")
	}
}

func TestUpdater_SignatureVerification_RejectsMissingHeader(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()

	manifestJSON := []byte(`{"version":"1.0.0","files":[{"name":"x.txt","sha256":"` +
		sha256Hex([]byte("1\n")) + `"}]}`)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No X-Signature header.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(manifestJSON)
	}))
	t.Cleanup(srv.Close)

	u, err := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		RulesDir:    dir,
		HTTPClient:  srv.Client(),
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil {
		t.Fatal("expected error for missing X-Signature header")
	}
}

// Mute unused import on systems where filepath is not referenced
// anywhere else; this is required by some -lint passes.
var _ = fmt.Sprintf
