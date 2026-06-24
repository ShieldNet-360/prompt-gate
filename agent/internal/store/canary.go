package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Canary is a single planted tripwire token. Token is the user's
// non-sensitive fake-secret value (safe to display); LastTriggered is
// a Unix timestamp (0 = never), TriggerCount the number of times the
// token has been seen by the DLP pipeline.
type Canary struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Token         string `json:"token"`
	CreatedAt     int64  `json:"created_at"`
	LastTriggered int64  `json:"last_triggered"`
	TriggerCount  int64  `json:"trigger_count"`
}

// newCanaryID returns a random 128-bit hex identifier.
func newCanaryID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("canary id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// CreateCanary inserts a canary with the given label and pre-generated
// token (the caller owns token generation so the store stays free of
// the dlp package). nowUnix is the creation timestamp. Returns the
// stored row, including its generated id.
func (s *Store) CreateCanary(ctx context.Context, label, token string, nowUnix int64) (Canary, error) {
	id, err := newCanaryID()
	if err != nil {
		return Canary{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO dlp_canaries (id, label, token, created_at, last_triggered, trigger_count)
		 VALUES (?, ?, ?, ?, 0, 0)`,
		id, label, token, nowUnix)
	if err != nil {
		return Canary{}, fmt.Errorf("insert canary: %w", err)
	}
	return Canary{ID: id, Label: label, Token: token, CreatedAt: nowUnix}, nil
}

// ListCanaries returns all canaries, newest first.
func (s *Store) ListCanaries(ctx context.Context) ([]Canary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, token, created_at, last_triggered, trigger_count
		 FROM dlp_canaries ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list canaries: %w", err)
	}
	defer rows.Close()
	var out []Canary
	for rows.Next() {
		var c Canary
		if err := rows.Scan(&c.ID, &c.Label, &c.Token, &c.CreatedAt, &c.LastTriggered, &c.TriggerCount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCanary removes a canary by id. Returns true if a row was
// deleted, false if no canary with that id existed.
func (s *Store) DeleteCanary(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dlp_canaries WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete canary: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RecordCanaryTrigger bumps trigger_count and last_triggered for the
// canary with the given label. It is best-effort: a label that matches
// no canary is a no-op (the pattern may have been deleted between the
// scan and this write). Matching is by label because the scan result
// carries only the pattern name (Canary:<label>), never the token.
func (s *Store) RecordCanaryTrigger(ctx context.Context, label string, nowUnix int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE dlp_canaries
		 SET trigger_count = trigger_count + 1, last_triggered = ?
		 WHERE label = ?`,
		nowUnix, label)
	if err != nil {
		return fmt.Errorf("record canary trigger: %w", err)
	}
	return nil
}
