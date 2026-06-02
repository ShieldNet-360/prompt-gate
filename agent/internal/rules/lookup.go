package rules

import (
	"strings"
	"sync"
)

// RuleSource describes a single rule file together with the category it
// belongs to. Categories map to actions in the policy engine.
type RuleSource struct {
	Category string
	Path     string
}

// Lookup is a thread-safe domain → category index built from parsed rule
// files. Exact entries (e.g. "example.com") match only the literal domain.
// Wildcard entries (e.g. ".example.com") match the literal domain and any
// subdomain under it.
type Lookup struct {
	mu       sync.RWMutex
	exact    map[string]string // domain → category
	wildcard map[string]string // base domain (no leading dot) → category
}

// NewLookup builds an empty Lookup.
func NewLookup() *Lookup {
	return &Lookup{
		exact:    make(map[string]string),
		wildcard: make(map[string]string),
	}
}

// Build returns a Lookup loaded with the entries from the given sources.
// If multiple sources reference the same domain, the first occurrence wins.
func Build(sources []RuleSource) (*Lookup, error) {
	l := NewLookup()
	for _, src := range sources {
		entries, err := ParseFile(src.Path)
		if err != nil {
			return nil, err
		}
		l.add(src.Category, entries)
	}
	return l, nil
}

// Replace atomically swaps the index with one built from the given entries.
// This is used by the policy engine when rules are reloaded.
func (l *Lookup) Replace(sources []RuleSource) error {
	other, err := Build(sources)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.exact = other.exact
	l.wildcard = other.wildcard
	l.mu.Unlock()
	return nil
}

func (l *Lookup) add(category string, entries []string) {
	for _, raw := range entries {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, ".") {
			base := strings.TrimPrefix(entry, ".")
			if base == "" {
				continue
			}
			if _, ok := l.wildcard[base]; !ok {
				l.wildcard[base] = category
			}
			// Also include the base domain as an exact hit for queries
			// of "example.com" when the rule was ".example.com".
			if _, ok := l.exact[base]; !ok {
				l.exact[base] = category
			}
			continue
		}
		if _, ok := l.exact[entry]; !ok {
			l.exact[entry] = category
		}
	}
}

// Lookup returns the category the domain belongs to (along with true) or
// the empty string and false if there is no match. Matching is performed
// against the normalized (lower-cased, dot-stripped) domain.
func (l *Lookup) Lookup(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return "", false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if cat, ok := l.exact[domain]; ok {
		return cat, true
	}
	// Walk up the domain looking for a wildcard parent.
	for rest := domain; ; {
		idx := strings.Index(rest, ".")
		if idx < 0 {
			break
		}
		rest = rest[idx+1:]
		if rest == "" {
			break
		}
		if cat, ok := l.wildcard[rest]; ok {
			return cat, true
		}
	}
	return "", false
}

// Size returns the number of indexed entries (sum of exact + wildcard).
// Useful for diagnostics and tests.
func (l *Lookup) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.exact) + len(l.wildcard)
}
