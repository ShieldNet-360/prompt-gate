// Package policy resolves a domain to one of three actions (allow,
// allow_with_dlp, deny) by combining the rule-file lookup index with the
// per-category policy stored in SQLite. The engine is safe for concurrent
// use and supports atomic reload of both the policy map and the lookup
// index.
package policy

import (
	"context"
	"strings"
	"sync"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/rules"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

// Action is the resolved policy decision for a domain.
type Action string

const (
	// Allow forwards the query to the upstream resolver.
	Allow Action = "allow"
	// AllowWithDLP forwards the query but flags the response for DLP
	// inspection (handled in later phases).
	AllowWithDLP Action = "allow_with_dlp"
	// Deny returns NXDOMAIN.
	Deny Action = "deny"
)

// DefaultAction is the action used when a domain is not found in any
// rule file. By default, unmatched domains are allowed.
const DefaultAction = Allow

// Engine ties rule-file lookup to the per-category action map.
type Engine struct {
	store *store.Store

	mu         sync.RWMutex
	lookup     *rules.Lookup
	categories map[string]Action // category → action
	sources    []rules.RuleSource
}

// New constructs an Engine and performs an initial load.
func New(s *store.Store, sources []rules.RuleSource) (*Engine, error) {
	e := &Engine{store: s, sources: append([]rules.RuleSource(nil), sources...)}
	if err := e.Reload(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// SetSources replaces the rule sources used on the next reload.
func (e *Engine) SetSources(sources []rules.RuleSource) {
	e.mu.Lock()
	e.sources = append([]rules.RuleSource(nil), sources...)
	e.mu.Unlock()
}

// Reload rebuilds the rule-file index from disk and reloads the
// per-category policies from SQLite.
func (e *Engine) Reload(ctx context.Context) error {
	e.mu.RLock()
	sources := append([]rules.RuleSource(nil), e.sources...)
	e.mu.RUnlock()

	lookup, err := rules.Build(sources)
	if err != nil {
		return err
	}

	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return err
	}
	cats := make(map[string]Action, len(policies))
	for _, p := range policies {
		cats[p.Category] = Action(p.Action)
	}

	e.mu.Lock()
	e.lookup = lookup
	e.categories = cats
	e.mu.Unlock()
	return nil
}

// CheckDomain returns the resolved Action for the given domain.
func (e *Engine) CheckDomain(domain string) Action {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return DefaultAction
	}
	e.mu.RLock()
	lookup := e.lookup
	cats := e.categories
	e.mu.RUnlock()

	if lookup == nil {
		return DefaultAction
	}
	category, ok := lookup.Lookup(domain)
	if !ok {
		return DefaultAction
	}
	action, ok := cats[category]
	if !ok {
		// Category exists in rule files but has no policy row yet —
		// fall back to deny on the assumption that rules without
		// policies are bundled blocklists. The policy engine reload
		// after the store seed should normally cover this.
		return Deny
	}
	return action
}

// IsCategorized returns true if the domain matches any rule file,
// regardless of the current policy action. Used by the proxy to
// decide whether to MITM (so policy changes take effect on existing
// connections) or use an opaque tunnel.
func (e *Engine) IsCategorized(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	e.mu.RLock()
	lookup := e.lookup
	e.mu.RUnlock()
	if lookup == nil {
		return false
	}
	_, ok := lookup.Lookup(domain)
	return ok
}

// Categories returns a snapshot of the policy map (category → action).
func (e *Engine) Categories() map[string]Action {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]Action, len(e.categories))
	for k, v := range e.categories {
		out[k] = v
	}
	return out
}
