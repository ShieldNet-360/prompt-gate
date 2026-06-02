// Multi-piece exfil correlator.
//
// Correlator carries a small tail (last N bytes) of each session's
// most recent paste so that secrets split across multiple consecutive
// pastes can be reassembled and detected.
//
// Example:
//   paste 1 (session=abc): "Hey debug — my key starts with AKIA1234"
//   paste 2 (session=abc, +12s): "5678ABCDEF12345678 — thanks"
//
// Without the correlator, neither paste alone contains a complete AWS access key
// pattern; with it, the second scan sees a virtual buffer of
// "...AKIA12345678ABCDEF12345678..." and the regex hits.
//
// Privacy invariant:
//   * State held only in-memory.
//   * Per-session entry expires after a short TTL (30s default).
//   * No paste content (or hash thereof) is ever persisted to disk.
//   * Session IDs are opaque tokens supplied by the caller — the
//     correlator never derives or stores user-identifiable values.

package dlp

import (
	"sync"
	"time"
)

const (
	defaultCorrelatorTTL     = 30 * time.Second
	defaultCorrelatorTailLen = 256
	defaultCorrelatorMaxSess = 4096
)

// correlatorState is the per-session tail and last-touched timestamp.
type correlatorState struct {
	tail     string
	lastSeen time.Time
}

// Correlator tracks recent paste tails per session.
type Correlator struct {
	mu       sync.Mutex
	sessions map[string]*correlatorState
	ttl      time.Duration
	tailLen  int
	maxSess  int
}

// NewCorrelator returns a Correlator with default tunables (30s TTL,
// 256-byte tail, 4096 max simultaneous sessions). Pass non-zero values
// to override; zero falls back to defaults.
func NewCorrelator(ttl time.Duration, tailLen, maxSess int) *Correlator {
	if ttl <= 0 {
		ttl = defaultCorrelatorTTL
	}
	if tailLen <= 0 {
		tailLen = defaultCorrelatorTailLen
	}
	if maxSess <= 0 {
		maxSess = defaultCorrelatorMaxSess
	}
	return &Correlator{
		sessions: make(map[string]*correlatorState),
		ttl:      ttl,
		tailLen:  tailLen,
		maxSess:  maxSess,
	}
}

// Combine updates the session state with content and returns the
// concatenated view (prior tail + current content). If this is the
// first paste in the session, returns (content, false). Otherwise
// returns (priorTail + sep + content, true).
//
// sessionID == "" disables correlation — the function returns (content, false)
// and does not touch any state. Safe to call with empty session ID.
//
// Safe for concurrent use.
func (c *Correlator) Combine(sessionID, content string) (string, bool) {
	if sessionID == "" || c == nil {
		return content, false
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeExpiredLocked(now)

	state, ok := c.sessions[sessionID]
	if !ok {
		// First paste in this session — store tail, no assembly yet.
		if len(c.sessions) >= c.maxSess {
			c.evictOldestLocked()
		}
		c.sessions[sessionID] = &correlatorState{
			tail:     tailN(content, c.tailLen),
			lastSeen: now,
		}
		return content, false
	}

	prior := state.tail
	state.tail = tailN(content, c.tailLen)
	state.lastSeen = now

	if prior == "" {
		return content, false
	}
	return prior + "\n" + content, true
}

// Forget removes the session entry. Useful when an upstream signals
// session end (e.g. browser tab closed).
func (c *Correlator) Forget(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
}

// ActiveSessions returns the current number of tracked sessions.
// Intended for tests + metrics; not safe to use as a security signal.
func (c *Correlator) ActiveSessions() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

// purgeExpiredLocked removes sessions whose lastSeen is older than ttl.
// Caller must hold mu.
func (c *Correlator) purgeExpiredLocked(now time.Time) {
	cutoff := now.Add(-c.ttl)
	for k, v := range c.sessions {
		if v.lastSeen.Before(cutoff) {
			delete(c.sessions, k)
		}
	}
}

// evictOldestLocked drops the single oldest session when the map is
// full. Linear scan acceptable at the max size (4096); callers can
// tune maxSess down for memory-constrained deployments.
func (c *Correlator) evictOldestLocked() {
	var oldestKey string
	var oldestTS time.Time
	first := true
	for k, v := range c.sessions {
		if first || v.lastSeen.Before(oldestTS) {
			oldestKey = k
			oldestTS = v.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.sessions, oldestKey)
	}
}

// tailN returns the last n bytes of s. If s is shorter than n, returns
// the entire string. n <= 0 returns "".
func tailN(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
