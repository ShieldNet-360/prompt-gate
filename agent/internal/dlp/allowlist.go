// Per-user feedback allowlist — Phase 8 Config H.
//
// Allowlist stores user-blessed "never block this exact value again"
// decisions. The wire shape between the toast button and the agent
// is a raw value (the user just clicked "allow this specific paste");
// the agent normalises + salt-hashes that value and persists only
// the hash. The pipeline consults the allowlist immediately after
// the C1/C2 short-circuits and BEFORE scoring, so an allowlisted
// match drops out before any source-context bias even runs.
//
// Scope semantics:
//
//   * "*"             — allowlist this value on every destination
//   * "<dest_kind>"   — allowlist this value only on the given
//                       destination_kind (e.g. "code_host" allows
//                       it on github.com but not chat.openai.com)
//
// TTL semantics:
//
//   * ttl == 0  → entry never expires (default for the toast button)
//   * ttl  > 0  → expires_at = created_at + ttl; Cleanup() and the
//                 in-RAM cache both honour it
//
// Privacy invariant: the table stores ONLY salted SHA-256 hashes
// plus a small amount of metadata (scope, optional pattern_name for
// display, timestamps). The salt itself is a separate per-install
// file (see salt.go). Raw values touch memory only — never disk.

package dlp

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// AllowlistScopeAny is the scope value meaning "any destination".
const AllowlistScopeAny = "*"

// AllowlistEntry is the public shape returned by Allowlist.List().
// SaltedHash is hex-encoded SHA-256 (64 chars).
type AllowlistEntry struct {
	SaltedHash  string `json:"salted_hash"`
	Scope       string `json:"scope"`
	PatternName string `json:"pattern_name"`
	ExpiresAt   int64  `json:"expires_at"`
	CreatedAt   int64  `json:"created_at"`
	LastHit     int64  `json:"last_hit"`
}

// Allowlist owns the dlp_allowlist SQLite table plus an in-RAM
// snapshot for O(1) lookups on the scan hot path.
type Allowlist struct {
	db   *sql.DB
	salt []byte
	now  func() time.Time

	mu      sync.RWMutex
	entries map[string]allowlistRow // key: salted_hash (hex)
}

type allowlistRow struct {
	scope       string
	patternName string
	expiresAt   int64
	createdAt   int64
}

// NewAllowlist constructs an Allowlist backed by db and salted with
// salt. The current contents of the dlp_allowlist table are read
// into the in-RAM cache so subsequent Allows() calls are O(1).
//
// Pass a non-nil time.Now-equivalent (or nil for time.Now) for
// deterministic TTL tests.
func NewAllowlist(ctx context.Context, db *sql.DB, salt []byte, now func() time.Time) (*Allowlist, error) {
	if db == nil {
		return nil, errors.New("allowlist: db is nil")
	}
	if len(salt) == 0 {
		return nil, errors.New("allowlist: salt is empty")
	}
	if now == nil {
		now = time.Now
	}
	a := &Allowlist{db: db, salt: salt, now: now, entries: make(map[string]allowlistRow)}
	if err := a.reload(ctx); err != nil {
		return nil, fmt.Errorf("allowlist: initial reload: %w", err)
	}
	return a, nil
}

// Allows reports whether value is on the allowlist for the given
// destination kind. The match key is SHA-256(salt || normalize(value))
// where normalize mirrors the C1 bloom helper (whitespace, dashes,
// underscores stripped; ASCII-lowercased). Scope semantics: "*" wins
// on any destination, otherwise the scope string must equal the
// destination kind exactly. Expired entries (expires_at > 0 AND
// expires_at <= now) are ignored and not eligible to fire.
//
// Allows updates the entry's last_hit timestamp in the in-RAM cache
// only (the DB write is best-effort, fire-and-forget via the
// touchAsync helper) so it stays on the scan hot path.
func (a *Allowlist) Allows(value, destinationKind string) bool {
	if a == nil || value == "" {
		return false
	}
	key := a.hash(value)
	now := a.now().Unix()

	a.mu.RLock()
	row, ok := a.entries[key]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if row.expiresAt > 0 && row.expiresAt <= now {
		return false
	}
	if row.scope != AllowlistScopeAny && row.scope != destinationKind {
		return false
	}
	a.touchAsync(key, now)
	return true
}

// Add records a new allowlist entry. value is hashed before insert.
// scope == "" is normalised to "*" (any destination). ttl == 0 means
// never expire. patternName is optional display metadata for the
// settings UI.
func (a *Allowlist) Add(ctx context.Context, value, scope, patternName string, ttl time.Duration) (string, error) {
	if value == "" {
		return "", errors.New("allowlist: value is empty")
	}
	if scope == "" {
		scope = AllowlistScopeAny
	}
	now := a.now()
	expiresAt := int64(0)
	if ttl > 0 {
		expiresAt = now.Add(ttl).Unix()
	}
	key := a.hash(value)
	createdAt := now.Unix()
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO dlp_allowlist(salted_hash, scope, pattern_name, expires_at, created_at, last_hit)
		 VALUES(?, ?, ?, ?, ?, 0)
		 ON CONFLICT(salted_hash) DO UPDATE SET
		     scope        = excluded.scope,
		     pattern_name = excluded.pattern_name,
		     expires_at   = excluded.expires_at,
		     created_at   = excluded.created_at`,
		key, scope, patternName, expiresAt, createdAt)
	if err != nil {
		return "", fmt.Errorf("allowlist: add: %w", err)
	}
	a.mu.Lock()
	a.entries[key] = allowlistRow{
		scope: scope, patternName: patternName,
		expiresAt: expiresAt, createdAt: createdAt,
	}
	a.mu.Unlock()
	return key, nil
}

// Remove deletes the entry by salted_hash. Returns true if a row
// was actually removed.
func (a *Allowlist) Remove(ctx context.Context, saltedHash string) (bool, error) {
	if saltedHash == "" {
		return false, errors.New("allowlist: saltedHash is empty")
	}
	res, err := a.db.ExecContext(ctx,
		`DELETE FROM dlp_allowlist WHERE salted_hash = ?`, saltedHash)
	if err != nil {
		return false, fmt.Errorf("allowlist: remove: %w", err)
	}
	n, _ := res.RowsAffected()
	a.mu.Lock()
	delete(a.entries, saltedHash)
	a.mu.Unlock()
	return n > 0, nil
}

// List returns a snapshot of all entries, sorted by created_at
// descending (newest first) so the settings UI shows the most
// recent "never block this" actions at the top.
func (a *Allowlist) List(ctx context.Context) ([]AllowlistEntry, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT salted_hash, scope, pattern_name, expires_at, created_at, last_hit
		 FROM dlp_allowlist
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("allowlist: list: %w", err)
	}
	defer rows.Close()

	var out []AllowlistEntry
	for rows.Next() {
		var e AllowlistEntry
		if err := rows.Scan(&e.SaltedHash, &e.Scope, &e.PatternName,
			&e.ExpiresAt, &e.CreatedAt, &e.LastHit); err != nil {
			return nil, fmt.Errorf("allowlist: list scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Cleanup removes expired entries from both the DB and the in-RAM
// cache. Returns the number of rows removed. Safe to call
// periodically (e.g. once an hour from main.go); the in-RAM Allows
// check honours expiry on its own so this is purely housekeeping.
func (a *Allowlist) Cleanup(ctx context.Context) (int, error) {
	now := a.now().Unix()
	res, err := a.db.ExecContext(ctx,
		`DELETE FROM dlp_allowlist WHERE expires_at > 0 AND expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("allowlist: cleanup: %w", err)
	}
	n, _ := res.RowsAffected()
	a.mu.Lock()
	for k, row := range a.entries {
		if row.expiresAt > 0 && row.expiresAt <= now {
			delete(a.entries, k)
		}
	}
	a.mu.Unlock()
	return int(n), nil
}

// Size reports how many active entries are loaded in the in-RAM
// cache. Used by tests and the /api/status endpoint.
func (a *Allowlist) Size() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

// hash returns SHA-256(salt || normalized(value)) hex-encoded. The
// normalisation matches normalizeForBloom in bloom.go so a user who
// clicks "never block 4111 1111 1111 1111" also allowlists the
// hyphenated and undelimited forms.
func (a *Allowlist) hash(value string) string {
	h := sha256.New()
	h.Write(a.salt)
	h.Write([]byte(normalizeForBloom(value)))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Allowlist) reload(ctx context.Context) error {
	rows, err := a.db.QueryContext(ctx,
		`SELECT salted_hash, scope, pattern_name, expires_at, created_at
		 FROM dlp_allowlist`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fresh := make(map[string]allowlistRow)
	for rows.Next() {
		var (
			key    string
			r      allowlistRow
		)
		if err := rows.Scan(&key, &r.scope, &r.patternName, &r.expiresAt, &r.createdAt); err != nil {
			return err
		}
		fresh[key] = r
	}
	if err := rows.Err(); err != nil {
		return err
	}

	a.mu.Lock()
	a.entries = fresh
	a.mu.Unlock()
	return nil
}

// touchAsync updates last_hit in the DB without blocking the hot
// path. Failures are silent — last_hit is a UX nicety, not a
// correctness signal.
func (a *Allowlist) touchAsync(key string, now int64) {
	db := a.db
	go func() {
		_, _ = db.ExecContext(context.Background(),
			`UPDATE dlp_allowlist SET last_hit = ? WHERE salted_hash = ?`,
			now, key)
	}()
}

// SortedHashesForTest returns the in-RAM entry keys in deterministic
// order. Used by tests; not exported through the API.
func (a *Allowlist) SortedHashesForTest() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.entries))
	for k := range a.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
