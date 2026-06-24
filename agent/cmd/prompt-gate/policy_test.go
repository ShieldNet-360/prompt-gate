package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// mockAgent serves the policy + dlp-config endpoints the CLI talks to.
type mockAgent struct {
	mu      sync.Mutex
	cats    map[string]string
	dlp     dlpConfig
	putCats map[string]string
	putDLP  bool
	lockDLP bool
}

func newMockAgent() *mockAgent {
	return &mockAgent{
		cats:    map[string]string{"AI Chat": "deny", "AI Code": "allow_with_dlp"},
		dlp:     dlpConfig{ThresholdCritical: 1, ThresholdHigh: 2, ThresholdMedium: 3, ThresholdLow: 4, HotwordBoost: 2},
		putCats: map[string]string{},
	}
}

func (m *mockAgent) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/policies":
			var out []catPolicy
			for k, v := range m.cats {
				out = append(out, catPolicy{Category: k, Action: v})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == "GET" && r.URL.Path == "/api/dlp/config":
			_ = json.NewEncoder(w).Encode(m.dlp)
		case r.Method == "PUT" && len(r.URL.Path) > len("/api/policies/") && r.URL.Path[:14] == "/api/policies/":
			cat := r.URL.Path[len("/api/policies/"):]
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.putCats[cat] = body["action"]
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(catPolicy{Category: cat, Action: body["action"]})
		case r.Method == "PUT" && r.URL.Path == "/api/dlp/config":
			if m.lockDLP {
				w.WriteHeader(403)
				return
			}
			m.putDLP = true
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func capture(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	stdout, stderr = &out, &errb
	t.Cleanup(func() { stdout, stderr = os.Stdout, os.Stderr })
	return &out, &errb
}

func TestPolicyExport(t *testing.T) {
	m := newMockAgent()
	srv := m.server()
	defer srv.Close()
	out, _ := capture(t)

	if code := cmdPolicy([]string{"export", "--api-addr", srv.URL, "--token", "x"}); code != 0 {
		t.Fatalf("export exit = %d", code)
	}
	// Round-trips through YAML.
	var doc policyDoc
	if err := yaml.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("export not valid YAML: %v\n%s", err, out.String())
	}
	if doc.Categories["AI Chat"] != "deny" || doc.DLP.ThresholdCritical != 1 {
		t.Errorf("exported doc = %+v", doc)
	}
}

func TestPolicyDiffAndApply(t *testing.T) {
	m := newMockAgent()
	srv := m.server()
	defer srv.Close()

	// A desired policy that relaxes AI Chat deny->allow and bumps a threshold.
	want := []byte("version: 1\ncategories:\n  \"AI Chat\": allow\ndlp:\n  threshold_critical: 2\n  threshold_high: 2\n  threshold_medium: 3\n  threshold_low: 4\n  hotword_boost: 2\n")
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(file, want, 0o644); err != nil {
		t.Fatal(err)
	}

	// diff → exit 1 (changes present); output names the relaxation.
	out, _ := capture(t)
	if code := cmdPolicy([]string{"diff", file, "--api-addr", srv.URL, "--token", "x"}); code != 1 {
		t.Fatalf("diff exit = %d, want 1", code)
	}
	if !bytes.Contains(out.Bytes(), []byte("RELAXATION")) || !bytes.Contains(out.Bytes(), []byte("threshold_critical")) {
		t.Errorf("diff output unexpected:\n%s", out.String())
	}

	// --fail-on-relaxation also exits 1 because AI Chat was loosened.
	capture(t)
	if code := cmdPolicy([]string{"diff", file, "--api-addr", srv.URL, "--token", "x", "--fail-on-relaxation"}); code != 1 {
		t.Fatalf("diff --fail-on-relaxation exit = %d, want 1", code)
	}

	// apply → PUTs the category and the dlp config.
	out, _ = capture(t)
	if code := cmdPolicy([]string{"apply", file, "--api-addr", srv.URL, "--token", "x"}); code != 0 {
		t.Fatalf("apply exit = %d (%s)", code, out.String())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putCats["AI Chat"] != "allow" {
		t.Errorf("category not applied: %+v", m.putCats)
	}
	if !m.putDLP {
		t.Error("dlp config not applied")
	}
}

func TestPolicyDiffNoChange(t *testing.T) {
	m := newMockAgent()
	srv := m.server()
	defer srv.Close()
	// Export current, then diff that exact doc → no changes, exit 0.
	out, _ := capture(t)
	cmdPolicy([]string{"export", "--api-addr", srv.URL, "--token", "x"})
	dir := t.TempDir()
	file := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(file, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out2, _ := capture(t)
	if code := cmdPolicy([]string{"diff", file, "--api-addr", srv.URL, "--token", "x"}); code != 0 {
		t.Fatalf("diff of identical policy exit = %d, want 0 (%s)", code, out2.String())
	}
	if !bytes.Contains(out2.Bytes(), []byte("no changes")) {
		t.Errorf("expected 'no changes', got: %s", out2.String())
	}
}
