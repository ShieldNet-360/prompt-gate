// Per-severity threshold engine (pipeline step 5).
//
// Maps a numeric score and a pattern severity to a Block/Allow decision.
// Thresholds are loaded from the dlp_config SQLite singleton at agent
// start-up; updates via PUT /api/dlp/config call ThresholdEngine.Set.

package dlp

import (
	"strings"
	"sync"
)

// ThresholdEngine holds the current Thresholds value and protects it
// with a read-mostly mutex so /api/dlp/config writes are safe under
// concurrent /api/dlp/scan reads.
type ThresholdEngine struct {
	mu sync.RWMutex
	t  Thresholds
}

// NewThresholdEngine returns an engine seeded with t.
func NewThresholdEngine(t Thresholds) *ThresholdEngine {
	return &ThresholdEngine{t: t}
}

// Get returns a copy of the current thresholds.
func (e *ThresholdEngine) Get() Thresholds {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.t
}

// Set replaces the current thresholds atomically.
func (e *ThresholdEngine) Set(t Thresholds) {
	e.mu.Lock()
	e.t = t
	e.mu.Unlock()
}

// ShouldBlock returns true when score meets or exceeds the threshold
// for the given severity. Unknown severities fall back to the "low"
// threshold so unknown values err on the side of allowing — blocking
// only on a high score keeps surprise blocks rare.
func (e *ThresholdEngine) ShouldBlock(score int, severity string) bool {
	e.mu.RLock()
	t := e.t
	e.mu.RUnlock()
	return score >= thresholdFor(t, severity)
}

func thresholdFor(t Thresholds, severity string) int {
	switch Severity(strings.ToLower(strings.TrimSpace(severity))) {
	case SeverityCritical:
		return t.Critical
	case SeverityHigh:
		return t.High
	case SeverityMedium:
		return t.Medium
	case SeverityLow:
		return t.Low
	default:
		return t.Low
	}
}
