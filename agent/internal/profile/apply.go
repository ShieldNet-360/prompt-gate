package profile

import (
	"context"
	"errors"
	"fmt"
)

// PolicyStore is the subset of store.Store the profile applier needs.
// Keeping it as an interface avoids a profile→store import cycle and
// lets apply_test.go drive the call sequence with an in-memory fake.
type PolicyStore interface {
	SetPolicy(ctx context.Context, category, action string) error
	GetDLPConfig(ctx context.Context) (DLPConfigSnapshot, error)
	SetDLPConfig(ctx context.Context, cfg DLPConfigSnapshot) error
}

// DLPConfigSnapshot mirrors store.DLPConfig field-for-field. Keeping
// the snapshot type in the profile package lets the API and main
// wire the boundary without the profile package importing store.
type DLPConfigSnapshot struct {
	ThresholdCritical int
	ThresholdHigh     int
	ThresholdMedium   int
	ThresholdLow      int
	HotwordBoost      int
	EntropyBoost      int
	EntropyPenalty    int
	ExclusionPenalty  int
	MultiMatchBoost   int
}

// PolicyReloader is the subset of policy.Engine the profile applier
// needs. May be nil — callers that don't run a policy engine (e.g.
// the Native Messaging mode) skip the reload step.
type PolicyReloader interface {
	Reload(ctx context.Context) error
}

// ApplyOptions wires the applier to its collaborators. PolicyStore
// must be non-nil; the others may be nil to opt out of that step.
type ApplyOptions struct {
	PolicyStore PolicyStore
	Reloader    PolicyReloader
	// DLPSink, when non-nil, is invoked with the merged DLP snapshot
	// after it has been written to the store. Callers use this hook
	// to push the new thresholds and weights into the live DLP
	// pipeline — without it the persisted values would only take
	// effect on the next agent restart, silently diverging from
	// what GET /api/dlp/config and GET /api/profile report.
	DLPSink func(DLPConfigSnapshot)
}

// Apply pushes the profile's category actions and DLP thresholds into
// the store and rebuilds the live policy engine. Errors short-circuit:
// applying a profile partially would leave the agent in an
// inconsistent state, so callers should treat any error as fatal at
// startup and surface as 4xx/5xx during import.
func (p *Profile) Apply(ctx context.Context, opts ApplyOptions) error {
	if p == nil {
		return errors.New("profile: apply on nil profile")
	}
	if opts.PolicyStore == nil {
		return errors.New("profile: PolicyStore is required")
	}
	for cat, act := range p.Categories {
		if err := opts.PolicyStore.SetPolicy(ctx, cat, act); err != nil {
			return fmt.Errorf("profile: set policy %q=%q: %w", cat, act, err)
		}
	}
	if t := p.DLPThresholds; t != nil {
		// Merge in the profile's overrides on top of the existing
		// row so a profile that only ships ThresholdCritical leaves
		// every other knob untouched.
		cur, err := opts.PolicyStore.GetDLPConfig(ctx)
		if err != nil {
			return fmt.Errorf("profile: read dlp_config: %w", err)
		}
		merged := mergeDLP(cur, *t)
		if err := opts.PolicyStore.SetDLPConfig(ctx, merged); err != nil {
			return fmt.Errorf("profile: write dlp_config: %w", err)
		}
		if opts.DLPSink != nil {
			opts.DLPSink(merged)
		}
	}
	if opts.Reloader != nil {
		if err := opts.Reloader.Reload(ctx); err != nil {
			return fmt.Errorf("profile: reload policy engine: %w", err)
		}
	}
	return nil
}

// mergeDLP returns cur with any non-zero field from override copied
// over. Zero is treated as "leave the existing knob alone" so
// partial profiles don't accidentally reset every threshold to 0.
func mergeDLP(cur DLPConfigSnapshot, override DLPThresholds) DLPConfigSnapshot {
	out := cur
	if override.ThresholdCritical != 0 {
		out.ThresholdCritical = override.ThresholdCritical
	}
	if override.ThresholdHigh != 0 {
		out.ThresholdHigh = override.ThresholdHigh
	}
	if override.ThresholdMedium != 0 {
		out.ThresholdMedium = override.ThresholdMedium
	}
	if override.ThresholdLow != 0 {
		out.ThresholdLow = override.ThresholdLow
	}
	if override.HotwordBoost != 0 {
		out.HotwordBoost = override.HotwordBoost
	}
	if override.EntropyBoost != 0 {
		out.EntropyBoost = override.EntropyBoost
	}
	if override.EntropyPenalty != 0 {
		out.EntropyPenalty = override.EntropyPenalty
	}
	if override.ExclusionPenalty != 0 {
		out.ExclusionPenalty = override.ExclusionPenalty
	}
	if override.MultiMatchBoost != 0 {
		out.MultiMatchBoost = override.MultiMatchBoost
	}
	return out
}
