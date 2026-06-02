// Handler tests for /api/dlp/allowlist.

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

func newAllowlistForServer(t *testing.T) *dlp.Allowlist {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "allow.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS dlp_allowlist (
		salted_hash  TEXT PRIMARY KEY,
		scope        TEXT NOT NULL DEFAULT '*',
		pattern_name TEXT NOT NULL DEFAULT '',
		expires_at   INTEGER NOT NULL DEFAULT 0,
		created_at   INTEGER NOT NULL,
		last_hit     INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	a, err := dlp.NewAllowlist(context.Background(), db,
		[]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatalf("new allowlist: %v", err)
	}
	return a
}

func TestAllowlist_503WhenNotConfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec,
		newLocalRequest(http.MethodGet, "/api/dlp/allowlist", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (no allowlist), got %d", rec.Code)
	}
}

func TestAllowlist_AddListRemoveRoundTrip(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:       dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		allowlist: newAllowlistForServer(t),
	})

	// POST — add an entry.
	addRec := httptest.NewRecorder()
	addReq := newLocalRequest(http.MethodPost, "/api/dlp/allowlist",
		bytes.NewBufferString(`{"value":"AKIA1234567890123456","scope":"code_host","pattern_name":"AWS Access Key","ttl_seconds":0}`))
	srv.Handler().ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("POST: expected 201, got %d (body=%q)", addRec.Code, addRec.Body.String())
	}
	var addResp struct {
		SaltedHash string `json:"salted_hash"`
	}
	if err := json.Unmarshal(addRec.Body.Bytes(), &addResp); err != nil {
		t.Fatalf("decode add: %v", err)
	}
	if len(addResp.SaltedHash) != 64 {
		t.Errorf("salted_hash len = %d, want 64 (SHA-256 hex)", len(addResp.SaltedHash))
	}

	// GET — list entries.
	listRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRec,
		newLocalRequest(http.MethodGet, "/api/dlp/allowlist", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", listRec.Code)
	}
	var entries []dlp.AllowlistEntry
	if err := json.Unmarshal(listRec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("list len = %d, want 1", len(entries))
	}
	if entries[0].Scope != "code_host" || entries[0].PatternName != "AWS Access Key" {
		t.Errorf("entry = %+v", entries[0])
	}
	if entries[0].SaltedHash != addResp.SaltedHash {
		t.Errorf("listed hash %q != add response %q", entries[0].SaltedHash, addResp.SaltedHash)
	}

	// DELETE — remove the entry.
	delRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delRec,
		newLocalRequest(http.MethodDelete, "/api/dlp/allowlist/"+addResp.SaltedHash, nil))
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d (body=%q)", delRec.Code, delRec.Body.String())
	}

	// GET again — empty list.
	emptyRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(emptyRec,
		newLocalRequest(http.MethodGet, "/api/dlp/allowlist", nil))
	var afterEntries []dlp.AllowlistEntry
	_ = json.Unmarshal(emptyRec.Body.Bytes(), &afterEntries)
	if len(afterEntries) != 0 {
		t.Errorf("post-delete list len = %d, want 0", len(afterEntries))
	}
}

func TestAllowlist_AddRejectsEmptyValue(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:       dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		allowlist: newAllowlistForServer(t),
	})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/allowlist",
		bytes.NewBufferString(`{"value":""}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty value, got %d", rec.Code)
	}
}

func TestAllowlist_DeleteUnknownReturns404(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:       dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		allowlist: newAllowlistForServer(t),
	})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec,
		newLocalRequest(http.MethodDelete, "/api/dlp/allowlist/deadbeef", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestAllowlist_DeleteRequiresHash(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:       dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		allowlist: newAllowlistForServer(t),
	})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec,
		newLocalRequest(http.MethodDelete, "/api/dlp/allowlist/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
