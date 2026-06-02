// Feedback-allowlist storage + lookup tests.

package dlp

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newAllowlistDB opens a fresh per-test SQLite file (in t.TempDir,
// auto-cleaned), runs the dlp_allowlist migration only, and returns
// the *sql.DB.
func newAllowlistDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.db")
	// busy_timeout(5000) so a concurrent test that grabs the writer
	// lock first does not trip SQLITE_BUSY in the racing test. We
	// deliberately do NOT enable WAL here: WAL leaves *.db-wal and
	// *.db-shm sidecar files that race t.TempDir's RemoveAll on
	// fast machines and surface as "directory not empty" cleanup
	// errors. Single-connection rollback journals are fine for tests.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// One connection only — eliminates the writer-vs-reader race
	// inside a single test process.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = db.Close()
		// modernc.org/sqlite may leave a rollback-journal sidecar
		// (path+"-journal") briefly after Close; if it lingers when
		// t.TempDir's RemoveAll fires we get a flaky "directory not
		// empty" failure. Sweep any sidecar before returning.
		matches, _ := filepath.Glob(path + "*")
		for _, m := range matches {
			_ = os.Remove(m)
		}
	})
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
	return db
}

func testSalt() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

// ── salt ──────────────────────────────────────────────────────────

func TestLoadOrGenerateSalt_CreatesOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist-salt")

	s1, err := LoadOrGenerateSalt(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(s1) != saltSize {
		t.Errorf("salt len = %d, want %d", len(s1), saltSize)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("salt file perm = %o, want 0600", perm)
	}

	// Second call MUST return the same bytes (idempotent).
	s2, err := LoadOrGenerateSalt(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(s1) != string(s2) {
		t.Errorf("salt changed on second load — would invalidate every allowlist entry")
	}
}

func TestLoadOrGenerateSalt_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist-salt")
	if err := os.WriteFile(path, []byte("not-hex"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrGenerateSalt(path); err == nil {
		t.Errorf("expected error on malformed salt file")
	}
}

// ── Allowlist round-trip ──────────────────────────────────────────

func TestAllowlist_AddLookupRemove(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, err := NewAllowlist(ctx, db, testSalt(), nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Unknown value → not allowed.
	if a.Allows("AKIA1234567890123456", "ai_chat") {
		t.Errorf("unknown value must not be allowed")
	}

	// Add → allowed on every destination (scope=*).
	hash, err := a.Add(ctx, "AKIA1234567890123456", "", "AWS Access Key", 0)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !a.Allows("AKIA1234567890123456", "ai_chat") {
		t.Errorf("value must be allowed after Add")
	}
	if !a.Allows("AKIA1234567890123456", "code_host") {
		t.Errorf("scope=* must allow every destination")
	}

	// Remove → no longer allowed.
	ok, err := a.Remove(ctx, hash)
	if err != nil || !ok {
		t.Fatalf("remove: ok=%v err=%v", ok, err)
	}
	if a.Allows("AKIA1234567890123456", "ai_chat") {
		t.Errorf("value must not be allowed after Remove")
	}
}

func TestAllowlist_NormalisesValue(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, _ := NewAllowlist(ctx, db, testSalt(), nil)

	// Allowlist the spaced form; both hyphenated and run-together
	// forms must hit the same hash (mirrors public-example bloom normalisation).
	if _, err := a.Add(ctx, "4111 1111 1111 1111", "", "PCI test card", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, v := range []string{
		"4111111111111111",
		"4111-1111-1111-1111",
		"4111 1111 1111 1111",
		"4111\t1111_1111_1111",
	} {
		if !a.Allows(v, "ai_chat") {
			t.Errorf("normalised form %q must match the allowlisted entry", v)
		}
	}
}

func TestAllowlist_ScopeIsPerDestination(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, _ := NewAllowlist(ctx, db, testSalt(), nil)

	// scope=code_host → only matches on code_host.
	if _, err := a.Add(ctx, "value-a", "code_host", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	if !a.Allows("value-a", "code_host") {
		t.Errorf("scope=code_host must allow on code_host")
	}
	if a.Allows("value-a", "ai_chat") {
		t.Errorf("scope=code_host must NOT allow on ai_chat")
	}
}

func TestAllowlist_TTLExpiry(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()

	clock := time.Unix(1_000_000, 0)
	now := func() time.Time { return clock }

	a, _ := NewAllowlist(ctx, db, testSalt(), now)
	if _, err := a.Add(ctx, "value-ttl", "", "", 10*time.Second); err != nil {
		t.Fatalf("add: %v", err)
	}
	if !a.Allows("value-ttl", "ai_chat") {
		t.Errorf("fresh entry must be allowed")
	}

	// Jump past TTL.
	clock = clock.Add(11 * time.Second)
	if a.Allows("value-ttl", "ai_chat") {
		t.Errorf("expired entry must NOT be allowed")
	}

	// Cleanup removes the row.
	n, err := a.Cleanup(ctx)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Errorf("cleanup removed %d, want 1", n)
	}
	if a.Size() != 0 {
		t.Errorf("size after cleanup = %d, want 0", a.Size())
	}
}

func TestAllowlist_RemoveUnknownReturnsFalse(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, _ := NewAllowlist(ctx, db, testSalt(), nil)
	ok, err := a.Remove(ctx, "deadbeef")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if ok {
		t.Errorf("Remove of unknown hash must return false")
	}
}

func TestAllowlist_ReloadFromDB(t *testing.T) {
	db := newAllowlistDB(t)
	ctx := context.Background()
	a1, _ := NewAllowlist(ctx, db, testSalt(), nil)
	if _, err := a1.Add(ctx, "alpha", "", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := a1.Add(ctx, "beta", "code_host", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}

	// A fresh Allowlist on the same DB sees both entries.
	a2, err := NewAllowlist(ctx, db, testSalt(), nil)
	if err != nil {
		t.Fatalf("new(2): %v", err)
	}
	if a2.Size() != 2 {
		t.Errorf("reload size = %d, want 2", a2.Size())
	}
	if !a2.Allows("alpha", "ai_chat") {
		t.Errorf("alpha must reload as scope=*")
	}
	if !a2.Allows("beta", "code_host") || a2.Allows("beta", "ai_chat") {
		t.Errorf("beta must reload as scope=code_host")
	}
}

func TestAllowlist_DifferentSaltDoesNotCollide(t *testing.T) {
	// Same value, different salt → different hash. Stolen DB
	// without the salt cannot be reverse-looked-up.
	db := newAllowlistDB(t)
	ctx := context.Background()

	a1, _ := NewAllowlist(ctx, db, []byte("salt-one-padding-padding-padding"), nil)
	hash1, _ := a1.Add(ctx, "the-value", "", "", 0)

	// A separate Allowlist with a different salt, sharing the DB,
	// produces a different hash for the same value.
	a2, _ := NewAllowlist(ctx, db, []byte("salt-two-padding-padding-padding"), nil)
	if a2.Allows("the-value", "ai_chat") {
		t.Errorf("different salt must not match the entry inserted with salt-one")
	}
	hash2 := a2.hash("the-value")
	if hash1 == hash2 {
		t.Errorf("same value with different salt produced same hash — salt is not being applied")
	}
}
