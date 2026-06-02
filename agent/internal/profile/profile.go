// Package profile defines the enterprise configuration profile format
// and the in-memory holder used to expose the current profile to the
// API and tamper / heartbeat subsystems.
//
// A profile is a JSON document that a managed deployment ships to the
// agent (either as a local file or a downloadable URL). It pins the
// per-category actions, DLP thresholds, and the rule-update URL the
// agent should follow. When Managed is true, the agent rejects local
// policy mutations via PUT /api/policies/:category so end users cannot
// drift the device away from the central baseline.
//
// Privacy note: the profile itself contains only configuration — it
// never carries access logs, domain history, or DLP match content.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// CategoryAction values stored in Profile.Categories. Mirrors the
// store.Action constants without forcing a profile→store import.
const (
	ActionAllow        = "allow"
	ActionAllowWithDLP = "allow_with_dlp"
	ActionDeny         = "deny"
)

// DLPThresholds mirrors store.DLPConfig so a profile can ship the full
// DLP scoring envelope. All fields are optional; zero means "leave the
// existing value untouched" when ApplyTo is called.
type DLPThresholds struct {
	ThresholdCritical int `json:"threshold_critical,omitempty"`
	ThresholdHigh     int `json:"threshold_high,omitempty"`
	ThresholdMedium   int `json:"threshold_medium,omitempty"`
	ThresholdLow      int `json:"threshold_low,omitempty"`
	HotwordBoost      int `json:"hotword_boost,omitempty"`
	EntropyBoost      int `json:"entropy_boost,omitempty"`
	EntropyPenalty    int `json:"entropy_penalty,omitempty"`
	ExclusionPenalty  int `json:"exclusion_penalty,omitempty"`
	MultiMatchBoost   int `json:"multi_match_boost,omitempty"`
}

// Profile is the JSON document a managed deployment ships to the
// agent. Name and Version are human-readable identifiers used in
// admin tooling; they have no semantic effect on the agent.
type Profile struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Managed       bool              `json:"managed"`
	Categories    map[string]string `json:"categories,omitempty"`
	DLPThresholds *DLPThresholds    `json:"dlp_thresholds,omitempty"`
	RuleUpdateURL string            `json:"rule_update_url,omitempty"`
	HeartbeatURL  string            `json:"heartbeat_url,omitempty"`
}

// ErrInvalidProfile is returned by Validate when the profile fails
// schema validation.
var ErrInvalidProfile = errors.New("invalid profile")

// Validate enforces the minimal schema invariants: Name is required,
// every category action (if any) is one of the supported values, and
// scoring thresholds (if any) are non-negative.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidProfile)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidProfile)
	}
	for cat, act := range p.Categories {
		switch act {
		case ActionAllow, ActionAllowWithDLP, ActionDeny:
		default:
			return fmt.Errorf("%w: category %q has invalid action %q",
				ErrInvalidProfile, cat, act)
		}
	}
	if t := p.DLPThresholds; t != nil {
		if t.ThresholdCritical < 0 || t.ThresholdHigh < 0 ||
			t.ThresholdMedium < 0 || t.ThresholdLow < 0 {
			return fmt.Errorf("%w: dlp thresholds must be non-negative",
				ErrInvalidProfile)
		}
	}
	return nil
}

// Parse unmarshals raw bytes into a Profile and validates it.
func Parse(raw []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Holder owns the active profile and exposes thread-safe accessors.
// The API package, the policy locker, and any future heartbeat /
// tamper observer share a single Holder instance constructed in
// cmd/agent/main.go.
type Holder struct {
	mu      sync.RWMutex
	current *Profile
}

// NewHolder returns a Holder that holds the given profile (which may
// be nil for unmanaged deployments).
func NewHolder(p *Profile) *Holder { return &Holder{current: p} }

// Get returns a defensive copy of the active profile, or nil when no
// profile has been applied. Callers must not mutate the returned
// pointer's referenced sub-objects.
func (h *Holder) Get() *Profile {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.current == nil {
		return nil
	}
	cp := *h.current
	if h.current.Categories != nil {
		cp.Categories = make(map[string]string, len(h.current.Categories))
		for k, v := range h.current.Categories {
			cp.Categories[k] = v
		}
	}
	if h.current.DLPThresholds != nil {
		t := *h.current.DLPThresholds
		cp.DLPThresholds = &t
	}
	return &cp
}

// Set replaces the active profile. p must be non-nil.
func (h *Holder) Set(p *Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	h.current = p
	h.mu.Unlock()
	return nil
}

// Locked reports whether the active profile is locked. A nil Holder or
// an unset profile is considered unlocked so a fresh install behaves
// like a Phase 1-4 deployment.
func (h *Holder) Locked() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current != nil && h.current.Managed
}
