// Package store wraps the SQLite persistence layer for the Prompt Gate
// agent. Only configuration and anonymous aggregate counters are
// persisted — no domain names, IP addresses, URLs, or per-event timestamps.
//
// The schema mirrors ARCHITECTURE.md section 6:
//
//	rulesets
//	category_policies
//	aggregate_stats         -- singleton, id = 1
//	rule_versions
//	dlp_config              -- singleton, id = 1
//
// There is intentionally NO alert_events table and NO access_log table.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // SQLite driver (pure Go, no CGO).
)

// schemaVersion is bumped when the schema changes in a non-additive way.
// Pragmatic migrations should be additive (CREATE TABLE IF NOT EXISTS,
// ALTER TABLE ADD COLUMN). The user_version pragma is updated to this
// value after a successful migration run.
const schemaVersion = 1

// Action values stored in category_policies.action.
const (
	ActionAllow        = "allow"
	ActionAllowWithDLP = "allow_with_dlp"
	ActionDeny         = "deny"
)

// CategoryPolicy is a row in the category_policies table.
type CategoryPolicy struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

// AggregateStats is the singleton row in aggregate_stats.
type AggregateStats struct {
	DNSQueriesTotal       int64 `json:"dns_queries_total"`
	DNSBlocksTotal        int64 `json:"dns_blocks_total"`
	DLPScansTotal         int64 `json:"dlp_scans_total"`
	DLPBlocksTotal        int64 `json:"dlp_blocks_total"`
	TamperDetectionsTotal int64 `json:"tamper_detections_total"`
}

// Store is the persistence handle. Methods are safe for concurrent use.
type Store struct {
	db *sql.DB

	mu sync.Mutex
}

// Open connects to the SQLite database at path (creating it if needed)
// in WAL mode and applies all required migrations.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: db path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// Caller is responsible for creating parent directories; we don't
		// silently create directories here to keep behaviour predictable.
		_ = dir
	}

	// SE-09: Pre-create the database file with restricted permissions
	// so it is not world-readable under a permissive umask.
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create db file: %w", createErr)
		}
		f.Close()
	}

	// busy_timeout matters when more than one process holds the DB
	// open concurrently — e.g. the long-lived daemon and a transient
	// Native Messaging host instance both bumping aggregate_stats. WAL
	// keeps reads non-blocking but writers still serialise; without
	// busy_timeout SQLite returns SQLITE_BUSY immediately and the
	// caller has to retry. We retry for up to 5s inside the driver so
	// callers (and ultimately the stats counters) don't have to.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)",
		url.QueryEscape(path))

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; serialise via the pool.

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.seedDefaults(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for callers that need it (e.g. the privacy
// audit test). External users should treat this as a read-only view.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rulesets (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid        TEXT UNIQUE NOT NULL,
			name        TEXT NOT NULL,
			rule_type   TEXT NOT NULL DEFAULT 'dstdomain',
			file_path   TEXT NOT NULL,
			category    TEXT NOT NULL,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS category_policies (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			category    TEXT UNIQUE NOT NULL,
			action      TEXT NOT NULL DEFAULT 'deny',
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS aggregate_stats (
			id                       INTEGER PRIMARY KEY CHECK (id = 1),
			dns_queries_total        INTEGER NOT NULL DEFAULT 0,
			dns_blocks_total         INTEGER NOT NULL DEFAULT 0,
			dlp_scans_total          INTEGER NOT NULL DEFAULT 0,
			dlp_blocks_total         INTEGER NOT NULL DEFAULT 0,
			tamper_detections_total  INTEGER NOT NULL DEFAULT 0,
			last_reset_at            DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rule_versions (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			manifest_version TEXT NOT NULL,
			updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS dlp_config (
			id                      INTEGER PRIMARY KEY CHECK (id = 1),
			threshold_critical      INTEGER NOT NULL DEFAULT 1,
			threshold_high          INTEGER NOT NULL DEFAULT 2,
			threshold_medium        INTEGER NOT NULL DEFAULT 3,
			threshold_low           INTEGER NOT NULL DEFAULT 4,
			hotword_boost           INTEGER NOT NULL DEFAULT 2,
			entropy_boost           INTEGER NOT NULL DEFAULT 1,
			entropy_penalty         INTEGER NOT NULL DEFAULT -2,
			exclusion_penalty       INTEGER NOT NULL DEFAULT -3,
			multi_match_boost       INTEGER NOT NULL DEFAULT 1,
			updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS block_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
			event_type   TEXT NOT NULL DEFAULT 'dlp',
			host         TEXT NOT NULL DEFAULT '',
			pattern_name TEXT NOT NULL DEFAULT '',
			action       TEXT NOT NULL DEFAULT 'blocked'
		)`,
		// Phase 8 Config H — per-user "never block this value
		// again" allowlist. Stores ONLY salted SHA-256 hashes
		// (salt persisted per-install to ~/.prompt-gate/
		// allowlist-salt — see agent/internal/dlp/salt.go) so a
		// stolen DB can't be reverse-looked-up against a wordlist
		// without also stealing the salt file. The optional
		// pattern_name is human-readable display metadata for the
		// settings UI, not a privacy concern.
		`CREATE TABLE IF NOT EXISTS dlp_allowlist (
			salted_hash  TEXT PRIMARY KEY,
			scope        TEXT NOT NULL DEFAULT '*',
			pattern_name TEXT NOT NULL DEFAULT '',
			expires_at   INTEGER NOT NULL DEFAULT 0,
			created_at   INTEGER NOT NULL,
			last_hit     INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS dlp_allowlist_expiry
		 ON dlp_allowlist(expires_at)`,
		// Phase 8.x — opt-in event log consent. The block_events
		// table writes destination hostnames to disk, which is a
		// privacy-invariant violation unless the user has
		// explicitly consented. Default = 0 (disabled). The gate
		// is enforced inside Store.InsertBlockEvent so every
		// caller — proxy hot path, future transports, tests —
		// inherits it automatically. Singleton row (id = 1).
		`CREATE TABLE IF NOT EXISTS agent_preferences (
			id                         INTEGER PRIMARY KEY CHECK (id = 1),
			block_events_enabled       INTEGER NOT NULL DEFAULT 0,
			block_events_consented_at  INTEGER NOT NULL DEFAULT 0,
			updated_at                 DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT OR IGNORE INTO agent_preferences (id, block_events_enabled, block_events_consented_at)
		 VALUES (1, 0, 0)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate: %w (stmt=%s)", err, q[:30])
		}
	}

	// Additive migration: tamper_detections_total was introduced in
	// Phase 5. Older installs don't have the column; ADD COLUMN is
	// idempotent enough via the SQLite error sniff below.
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE aggregate_stats ADD COLUMN tamper_detections_total INTEGER NOT NULL DEFAULT 0`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate: add tamper_detections_total: %w", err)
		}
	}
	// Additive migration: redact_enabled lets the user opt into
	// redaction (mask the secret, send the rest) instead of the
	// default block. Older installs don't have the column; default 0
	// keeps block-as-default for everyone on upgrade.
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE agent_preferences ADD COLUMN redact_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate: add redact_enabled: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx,
		fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return nil
}

func (s *Store) seedDefaults(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO aggregate_stats (id) VALUES (1)`); err != nil {
		return fmt.Errorf("seed aggregate_stats: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO dlp_config (id) VALUES (1)`); err != nil {
		return fmt.Errorf("seed dlp_config: %w", err)
	}

	// Default Phase 1 category policies. These can be updated via the API.
	// The list must cover every category produced by categoryFromPath
	// for a rule file shipped under rules/, otherwise the policy engine
	// falls back to its default-Deny rule and silently blocks a whole
	// category (e.g. news domains).
	defaults := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "AI Code Blocked", Action: ActionDeny},
		{Category: "AI Allowed", Action: ActionAllow},
		{Category: "AI Chat DLP", Action: ActionAllowWithDLP},
		{Category: "Phishing", Action: ActionDeny},
		{Category: "Social", Action: ActionAllow},
		{Category: "News", Action: ActionAllow},
		// Admin override categories produced by rules.OverrideStore.
		// Without these rows the engine's lookup map falls through to
		// Deny (see policy/engine.go), so admin-allowed domains would
		// be silently blocked. Keep these category strings in sync
		// with rules.OverrideAllowCategory / OverrideBlockCategory.
		{Category: "allow_admin", Action: ActionAllow},
		{Category: "block_admin", Action: ActionDeny},
	}
	for _, p := range defaults {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO category_policies (category, action) VALUES (?, ?)`,
			p.Category, p.Action); err != nil {
			return fmt.Errorf("seed category_policies: %w", err)
		}
	}
	return nil
}

// ListPolicies returns all category policies.
func (s *Store) ListPolicies(ctx context.Context) ([]CategoryPolicy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT category, action FROM category_policies ORDER BY category`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []CategoryPolicy
	for rows.Next() {
		var p CategoryPolicy
		if err := rows.Scan(&p.Category, &p.Action); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPolicy upserts the action for a category. Returns ErrInvalidAction
// when the action is not one of the supported values.
var ErrInvalidAction = errors.New("invalid action")

// SetPolicy upserts the action for a category.
func (s *Store) SetPolicy(ctx context.Context, category, action string) error {
	switch action {
	case ActionAllow, ActionAllowWithDLP, ActionDeny:
	default:
		return ErrInvalidAction
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO category_policies (category, action) VALUES (?, ?)
		ON CONFLICT(category) DO UPDATE SET action = excluded.action, updated_at = CURRENT_TIMESTAMP
	`, category, action)
	if err != nil {
		return fmt.Errorf("set policy: %w", err)
	}
	return nil
}

// GetStats reads the singleton aggregate_stats row.
func (s *Store) GetStats(ctx context.Context) (AggregateStats, error) {
	var st AggregateStats
	err := s.db.QueryRowContext(ctx, `
		SELECT dns_queries_total, dns_blocks_total, dlp_scans_total, dlp_blocks_total, tamper_detections_total
		FROM aggregate_stats WHERE id = 1
	`).Scan(&st.DNSQueriesTotal, &st.DNSBlocksTotal, &st.DLPScansTotal, &st.DLPBlocksTotal, &st.TamperDetectionsTotal)
	if err != nil {
		return AggregateStats{}, fmt.Errorf("get stats: %w", err)
	}
	return st, nil
}

// AddStats atomically adds deltas to the aggregate_stats counters.
func (s *Store) AddStats(ctx context.Context, delta AggregateStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_stats SET
			dns_queries_total        = dns_queries_total        + ?,
			dns_blocks_total         = dns_blocks_total         + ?,
			dlp_scans_total          = dlp_scans_total          + ?,
			dlp_blocks_total         = dlp_blocks_total         + ?,
			tamper_detections_total  = tamper_detections_total  + ?
		WHERE id = 1
	`, delta.DNSQueriesTotal, delta.DNSBlocksTotal, delta.DLPScansTotal, delta.DLPBlocksTotal, delta.TamperDetectionsTotal)
	if err != nil {
		return fmt.Errorf("add stats: %w", err)
	}
	return nil
}

// DLPConfig is the singleton row in dlp_config.
type DLPConfig struct {
	ThresholdCritical int `json:"threshold_critical"`
	ThresholdHigh     int `json:"threshold_high"`
	ThresholdMedium   int `json:"threshold_medium"`
	ThresholdLow      int `json:"threshold_low"`
	HotwordBoost      int `json:"hotword_boost"`
	EntropyBoost      int `json:"entropy_boost"`
	EntropyPenalty    int `json:"entropy_penalty"`
	ExclusionPenalty  int `json:"exclusion_penalty"`
	MultiMatchBoost   int `json:"multi_match_boost"`
}

// GetDLPConfig reads the singleton dlp_config row.
func (s *Store) GetDLPConfig(ctx context.Context) (DLPConfig, error) {
	var c DLPConfig
	err := s.db.QueryRowContext(ctx, `
		SELECT threshold_critical, threshold_high, threshold_medium, threshold_low,
		       hotword_boost, entropy_boost, entropy_penalty, exclusion_penalty,
		       multi_match_boost
		FROM dlp_config WHERE id = 1
	`).Scan(
		&c.ThresholdCritical, &c.ThresholdHigh, &c.ThresholdMedium, &c.ThresholdLow,
		&c.HotwordBoost, &c.EntropyBoost, &c.EntropyPenalty, &c.ExclusionPenalty,
		&c.MultiMatchBoost,
	)
	if err != nil {
		return DLPConfig{}, fmt.Errorf("get dlp_config: %w", err)
	}
	return c, nil
}

// SetDLPConfig overwrites the singleton dlp_config row.
func (s *Store) SetDLPConfig(ctx context.Context, c DLPConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		UPDATE dlp_config SET
			threshold_critical = ?,
			threshold_high     = ?,
			threshold_medium   = ?,
			threshold_low      = ?,
			hotword_boost      = ?,
			entropy_boost      = ?,
			entropy_penalty    = ?,
			exclusion_penalty  = ?,
			multi_match_boost  = ?,
			updated_at         = CURRENT_TIMESTAMP
		WHERE id = 1
	`,
		c.ThresholdCritical, c.ThresholdHigh, c.ThresholdMedium, c.ThresholdLow,
		c.HotwordBoost, c.EntropyBoost, c.EntropyPenalty, c.ExclusionPenalty,
		c.MultiMatchBoost,
	)
	if err != nil {
		return fmt.Errorf("set dlp_config: %w", err)
	}
	return nil
}

// ResetStats zeroes the aggregate counters.
func (s *Store) ResetStats(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_stats SET
			dns_queries_total        = 0,
			dns_blocks_total         = 0,
			dlp_scans_total          = 0,
			dlp_blocks_total         = 0,
			tamper_detections_total  = 0,
			last_reset_at            = CURRENT_TIMESTAMP
		WHERE id = 1
	`)
	if err != nil {
		return fmt.Errorf("reset stats: %w", err)
	}
	return nil
}

// CurrentRuleVersion returns the most recent rule manifest version
// recorded in rule_versions. An empty string is returned when no
// version has been written yet (fresh install).
func (s *Store) CurrentRuleVersion(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `
SELECT manifest_version FROM rule_versions ORDER BY id DESC LIMIT 1
`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("current rule_version: %w", err)
	}
	return v, nil
}

// AppendRuleVersion records that the agent successfully synced rules
// to the given manifest version. The append-only history preserves an
// audit trail; CurrentRuleVersion always returns the newest row.
func (s *Store) AppendRuleVersion(ctx context.Context, version string) error {
	if version == "" {
		return errors.New("append rule_version: version is empty")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rule_versions (manifest_version) VALUES (?)`, version)
	if err != nil {
		return fmt.Errorf("append rule_version: %w", err)
	}
	return nil
}

// AgentPreferences mirrors the singleton agent_preferences row. The
// only field today is the opt-in flag for the block_events history,
// which is the privacy-invariant carve-out introduced in Phase 8.x.
// ConsentedAt is unix-seconds and is stamped on every transition to
// enabled=true (it never auto-clears on disable, so the timestamp
// records when the user most recently said yes).
type AgentPreferences struct {
	BlockEventsEnabled     bool  `json:"block_events_enabled"`
	BlockEventsConsentedAt int64 `json:"block_events_consented_at"`
	// RedactEnabled flips the DLP action on a detected secret from the
	// default "block" to "redact" (mask the secret, let the rest
	// through). Default false = block.
	RedactEnabled bool `json:"redact_enabled"`
}

// GetAgentPreferences reads the singleton agent_preferences row.
func (s *Store) GetAgentPreferences(ctx context.Context) (AgentPreferences, error) {
	var p AgentPreferences
	var enabled, redact int
	err := s.db.QueryRowContext(ctx, `
		SELECT block_events_enabled, block_events_consented_at, redact_enabled
		FROM agent_preferences WHERE id = 1
	`).Scan(&enabled, &p.BlockEventsConsentedAt, &redact)
	if err != nil {
		return AgentPreferences{}, fmt.Errorf("get agent_preferences: %w", err)
	}
	p.BlockEventsEnabled = enabled != 0
	p.RedactEnabled = redact != 0
	return p, nil
}

// RedactEnabled reports whether the user has opted into redaction.
// Default false (block). Errors surface as false so the safe default
// (block) is preserved on any read failure.
func (s *Store) RedactEnabled(ctx context.Context) bool {
	var redact int
	err := s.db.QueryRowContext(ctx,
		`SELECT redact_enabled FROM agent_preferences WHERE id = 1`,
	).Scan(&redact)
	if err != nil {
		return false
	}
	return redact != 0
}

// SetRedactEnabled flips the redact opt-in.
func (s *Store) SetRedactEnabled(ctx context.Context, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE agent_preferences SET
			redact_enabled = ?,
			updated_at     = CURRENT_TIMESTAMP
		WHERE id = 1
	`, v)
	if err != nil {
		return fmt.Errorf("set redact_enabled=%d: %w", v, err)
	}
	return nil
}

// SetBlockEventsEnabled flips the opt-in flag. When enabling, the
// consented_at column is stamped with the current unix-seconds so
// the UI can show "consented YYYY-MM-DD"; the timestamp is left in
// place on disable so a re-enable preserves the audit trail.
func (s *Store) SetBlockEventsEnabled(ctx context.Context, enabled bool, nowUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled {
		_, err := s.db.ExecContext(ctx, `
			UPDATE agent_preferences SET
				block_events_enabled      = 1,
				block_events_consented_at = ?,
				updated_at                = CURRENT_TIMESTAMP
			WHERE id = 1
		`, nowUnix)
		if err != nil {
			return fmt.Errorf("set block_events_enabled=1: %w", err)
		}
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE agent_preferences SET
			block_events_enabled = 0,
			updated_at           = CURRENT_TIMESTAMP
		WHERE id = 1
	`)
	if err != nil {
		return fmt.Errorf("set block_events_enabled=0: %w", err)
	}
	return nil
}

// BlockEvent is a row in the block_events table.
type BlockEvent struct {
	ID          int64  `json:"id"`
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`   // "dlp" or "category"
	Host        string `json:"host"`
	PatternName string `json:"pattern_name"` // DLP pattern that triggered, or category name
	Action      string `json:"action"`       // "blocked"
}

// InsertBlockEvent records a single block event, IFF the user has
// explicitly enabled the history via SetBlockEventsEnabled. When
// the consent flag is off, this is a silent no-op so callers (the
// MITM proxy hot path, future transports, tests) cannot accidentally
// leak per-event destination hostnames to disk.
//
// The gate lives at the Store layer (not the recorder adapter in
// cmd/agent/main.go) so every present and future writer inherits
// it automatically — see docs/PRIVACY-AUDIT.md.
func (s *Store) InsertBlockEvent(ctx context.Context, eventType, host, patternName string) error {
	enabled, err := s.blockEventsEnabled(ctx)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO block_events (event_type, host, pattern_name, action)
		VALUES (?, ?, ?, 'blocked')
	`, eventType, host, patternName)
	if err != nil {
		return fmt.Errorf("insert block_event: %w", err)
	}
	// Trim old events to keep the table bounded.
	_, _ = s.db.ExecContext(ctx, `
		DELETE FROM block_events WHERE id NOT IN (
			SELECT id FROM block_events ORDER BY id DESC LIMIT 500
		)
	`)
	return nil
}

// blockEventsEnabled reads the consent flag. Kept private — callers
// that need the full preferences struct use GetAgentPreferences.
func (s *Store) blockEventsEnabled(ctx context.Context) (bool, error) {
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT block_events_enabled FROM agent_preferences WHERE id = 1`,
	).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("read block_events_enabled: %w", err)
	}
	return enabled != 0, nil
}

// ListBlockEvents returns the most recent block events, newest first.
func (s *Store) ListBlockEvents(ctx context.Context, limit int) ([]BlockEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, strftime('%Y-%m-%dT%H:%M:%SZ', timestamp), event_type, host, pattern_name, action
		FROM block_events ORDER BY id DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list block_events: %w", err)
	}
	defer rows.Close()
	var out []BlockEvent
	for rows.Next() {
		var e BlockEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.Host, &e.PatternName, &e.Action); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearBlockEvents deletes all block events.
func (s *Store) ClearBlockEvents(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM block_events`)
	if err != nil {
		return fmt.Errorf("clear block_events: %w", err)
	}
	return nil
}
