package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrivacy_NoAccessTablesAndNoDomainsPersisted is the safety net for
// the privacy-first guarantee: after a sequence of "DNS events" is
// processed via the store API, we scan every text column in the
// database and assert it contains nothing that looks like the domain
// names, IP addresses, URLs, or per-event timestamps that the agent
// observed. Only the aggregate counters may have changed.
func TestPrivacy_NoAccessTablesAndNoDomainsPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "privacy.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	statsBefore, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	// Simulate the events that the DNS resolver would generate.
	events := []struct {
		domain string
		block  bool
	}{
		{"deepseek.com", true},
		{"foo.deepseek.com", true},
		{"chat.openai.com", false},
		{"api.openai.com", false},
		{"203.0.113.45", true}, // also try an IP-shaped string
	}
	for _, ev := range events {
		delta := AggregateStats{DNSQueriesTotal: 1}
		if ev.block {
			delta.DNSBlocksTotal = 1
		}
		if err := s.AddStats(ctx, delta); err != nil {
			t.Fatalf("AddStats: %v", err)
		}
	}

	// Counters moved.
	statsAfter, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if statsAfter.DNSQueriesTotal-statsBefore.DNSQueriesTotal != int64(len(events)) {
		t.Errorf("queries delta = %d", statsAfter.DNSQueriesTotal-statsBefore.DNSQueriesTotal)
	}
	if statsAfter.DNSBlocksTotal-statsBefore.DNSBlocksTotal != 3 {
		t.Errorf("blocks delta = %d", statsAfter.DNSBlocksTotal-statsBefore.DNSBlocksTotal)
	}

	// Forbidden tables MUST NOT exist.
	for _, name := range []string{"access_log", "alert_events", "dns_log", "events", "alerts"} {
		var found string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, name).
			Scan(&found)
		if err == nil {
			t.Errorf("forbidden table %q exists", name)
		} else if err != sql.ErrNoRows {
			t.Fatalf("query forbidden table %q: %v", name, err)
		}
	}

	// Exercise the block_events write path with consent OFF (the
	// default). With the gate wired correctly in Store.InsertBlockEvent,
	// these calls MUST be silent no-ops — host strings cannot land on
	// disk. This is the regression closure for the false-clean reading
	// the original sweep gave (the previous test never called
	// InsertBlockEvent, so it passed only because the table was empty).
	for _, ev := range events {
		if err := s.InsertBlockEvent(ctx, "category", ev.domain, "blocked-domain"); err != nil {
			t.Fatalf("InsertBlockEvent with consent off: %v", err)
		}
	}

	// Now sweep every text column of every table and assert no event
	// fingerprints made it into the DB.
	forbidden := []string{
		"deepseek.com",
		"foo.deepseek.com",
		"chat.openai.com",
		"api.openai.com",
		"203.0.113.45",
	}
	scanTextColumns(t, s.DB(), forbidden)
}

// TestPrivacy_DLPScanContentNotPersisted runs a sequence of DLP scan
// bumps (analogous to what the API handler does for each scan) and
// then sweeps the database for any of the secret values that those
// scans operated on. Only aggregate counters (dlp_scans_total,
// dlp_blocks_total) may have changed.
func TestPrivacy_DLPScanContentNotPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dlp-privacy.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	before, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	// These represent the "did a scan, was/wasn't blocked" calls the
	// API handler would make. The actual secret values never leave
	// the DLP package — the store only sees integer deltas.
	type scan struct {
		secret  string
		blocked bool
	}
	scans := []scan{
		{"AKIA9P2QRMZNL5CVXBT4", true},                         // AWS access key (TP)
		{"ghp_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e", true},     // GitHub PAT
		{"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", true}, // OpenAI key
		{"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123", true},  // Anthropic
		{"AIzaSyD9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3D", true},    // Google API
		{"mongodb+srv://svc:Ub3rH4rdProdSecret42@cluster0.mongodb.net", true},
		{"benign string with no secrets", false},
		{"package com.example; // import statement", false},
	}
	for _, sc := range scans {
		delta := AggregateStats{DLPScansTotal: 1}
		if sc.blocked {
			delta.DLPBlocksTotal = 1
		}
		if err := s.AddStats(ctx, delta); err != nil {
			t.Fatalf("AddStats: %v", err)
		}
	}

	after, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if after.DLPScansTotal-before.DLPScansTotal != int64(len(scans)) {
		t.Errorf("dlp scans delta = %d", after.DLPScansTotal-before.DLPScansTotal)
	}
	wantBlocks := int64(0)
	for _, sc := range scans {
		if sc.blocked {
			wantBlocks++
		}
	}
	if after.DLPBlocksTotal-before.DLPBlocksTotal != wantBlocks {
		t.Errorf("dlp blocks delta = %d, want %d",
			after.DLPBlocksTotal-before.DLPBlocksTotal, wantBlocks)
	}

	// Forbidden tables that would imply scan-content storage must
	// not have been created.
	for _, name := range []string{
		"dlp_scans", "dlp_matches", "scan_log", "scan_results",
		"dlp_log", "dlp_events", "matches",
	} {
		var found string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, name).
			Scan(&found)
		if err == nil {
			t.Errorf("forbidden DLP table %q exists", name)
		} else if err != sql.ErrNoRows {
			t.Fatalf("query forbidden table %q: %v", name, err)
		}
	}

	// Exercise the block_events write path with consent OFF. Every
	// proxy block path calls InsertBlockEvent with the destination
	// host; with the gate wired correctly the host MUST NOT land on
	// disk. The sweep below would catch a regression here.
	dlpHosts := []string{
		"chat.openai.com",
		"gemini.google.com",
		"claude.ai",
		"copilot.microsoft.com",
	}
	for _, h := range dlpHosts {
		if err := s.InsertBlockEvent(ctx, "dlp", h, "AWS Access Key"); err != nil {
			t.Fatalf("InsertBlockEvent with consent off: %v", err)
		}
	}

	// Sweep every text column for any of the secrets, secret prefixes,
	// pattern names, or destination hosts. None of these should appear
	// anywhere in the database, since the agent never writes scan
	// content or matched pattern names to disk, and the consent gate
	// blocks every block_events.host write while disabled.
	forbidden := []string{
		"AKIA9P2QRMZNL5CVXBT4", "ghp_9f8a7b6c5d4e",
		"sk-proj-", "sk-ant-api03-", "AIzaSyD",
		"mongodb+srv://", "Ub3rH4rdProdSecret42",
		// pattern names that would only appear if matches were logged
		"AWS Access Key", "GitHub Personal Access Token",
		"OpenAI Project Key", "Anthropic API Key",
		"Google API Key", "MongoDB Atlas SRV Connection",
		// destination hosts that would only appear if the block_events
		// gate is broken
		"chat.openai.com", "gemini.google.com",
		"claude.ai", "copilot.microsoft.com",
	}
	scanTextColumns(t, s.DB(), forbidden)
}

// TestPrivacy_BlockEventsRespectConsentGate is the symmetric test:
// when the user has explicitly opted into the block_events history,
// the host IS persisted. This documents the carve-out — the
// privacy invariant gains a second exception (alongside the feedback allowlist's
// salted allowlist) for user-opt-in destination logs, and this test
// makes sure the gate is symmetric (off → silent, on → records).
//
// Both halves of the symmetry matter:
//   - off + InsertBlockEvent → 0 rows (privacy invariant preserved)
//   - on  + InsertBlockEvent → row recorded as-is (carve-out works)
//
// A regression in either direction is a bug: silent on-disk leaks
// in the first case, and a feature outage in the second.
func TestPrivacy_BlockEventsRespectConsentGate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "consent.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	// 1. Default: consent off. Insert is a silent no-op.
	prefs, err := s.GetAgentPreferences(ctx)
	if err != nil {
		t.Fatalf("GetAgentPreferences: %v", err)
	}
	if prefs.BlockEventsEnabled {
		t.Fatal("block_events_enabled defaults to true; want false")
	}
	if err := s.InsertBlockEvent(ctx, "dlp", "chat.openai.com", "AWS Access Key"); err != nil {
		t.Fatalf("InsertBlockEvent (off): %v", err)
	}
	got, err := s.ListBlockEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListBlockEvents: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("with consent off, got %d events; want 0", len(got))
	}

	// 2. Consent on: insert records as-is.
	if err := s.SetBlockEventsEnabled(ctx, true, 1748000000); err != nil {
		t.Fatalf("SetBlockEventsEnabled(true): %v", err)
	}
	prefs, err = s.GetAgentPreferences(ctx)
	if err != nil {
		t.Fatalf("GetAgentPreferences after enable: %v", err)
	}
	if !prefs.BlockEventsEnabled {
		t.Fatal("block_events_enabled didn't flip on")
	}
	if prefs.BlockEventsConsentedAt != 1748000000 {
		t.Fatalf("consented_at = %d; want 1748000000", prefs.BlockEventsConsentedAt)
	}
	if err := s.InsertBlockEvent(ctx, "dlp", "chat.openai.com", "AWS Access Key"); err != nil {
		t.Fatalf("InsertBlockEvent (on): %v", err)
	}
	got, err = s.ListBlockEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListBlockEvents after enable: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("with consent on, got %d events; want 1", len(got))
	}
	if got[0].Host != "chat.openai.com" || got[0].PatternName != "AWS Access Key" {
		t.Fatalf("recorded event = %+v; want host=chat.openai.com pattern=AWS Access Key", got[0])
	}

	// 3. Toggle back off: prior rows survive (consent revocation is
	//    not retroactive deletion — the user can ClearBlockEvents
	//    separately if they want that), but new inserts are silent.
	if err := s.SetBlockEventsEnabled(ctx, false, 0); err != nil {
		t.Fatalf("SetBlockEventsEnabled(false): %v", err)
	}
	if err := s.InsertBlockEvent(ctx, "dlp", "claude.ai", "Anthropic API Key"); err != nil {
		t.Fatalf("InsertBlockEvent (off again): %v", err)
	}
	got, err = s.ListBlockEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListBlockEvents after disable: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("after disable, got %d events; want 1 (the previously-recorded one)", len(got))
	}
	if got[0].Host == "claude.ai" {
		t.Fatal("post-disable event leaked to disk — gate is broken")
	}
}

func scanTextColumns(t *testing.T, db *sql.DB, forbidden []string) {
	t.Helper()
	tables, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tableNames []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatalf("scan tablename: %v", err)
		}
		tableNames = append(tableNames, n)
	}
	tables.Close()

	for _, table := range tableNames {
		cols, err := db.Query(`SELECT name, type FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatalf("pragma_table_info(%s): %v", table, err)
		}
		var textCols []string
		for cols.Next() {
			var name, typ string
			if err := cols.Scan(&name, &typ); err != nil {
				t.Fatalf("scan col: %v", err)
			}
			if strings.Contains(strings.ToUpper(typ), "TEXT") {
				textCols = append(textCols, name)
			}
		}
		cols.Close()

		for _, col := range textCols {
			rows, err := db.Query("SELECT " + col + " FROM " + table) //nolint:gosec // identifiers from pragma
			if err != nil {
				t.Fatalf("select %s.%s: %v", table, col, err)
			}
			for rows.Next() {
				var v sql.NullString
				if err := rows.Scan(&v); err != nil {
					rows.Close()
					t.Fatalf("scan: %v", err)
				}
				if !v.Valid {
					continue
				}
				lower := strings.ToLower(v.String)
				for _, f := range forbidden {
					if strings.Contains(lower, strings.ToLower(f)) {
						rows.Close()
						t.Fatalf("table=%s col=%s contains forbidden value %q (row=%q)",
							table, col, f, v.String)
					}
				}
			}
			rows.Close()
		}
	}
}
