// Aho-Corasick prefix scanner (pipeline step 2).
//
// We use github.com/cloudflare/ahocorasick (pure-Go) to do a single
// O(n) pass over the content and tell us which pattern prefixes appear.
// That library returns the matching dictionary indices but not their
// offsets, so for each matched prefix we then sweep the content with
// strings.Index to materialise candidate (offset, pattern) pairs that
// the regex step in regex.go can validate.
//
// The automaton is built once at rule-load time and held by Pipeline;
// callers must not mutate it after construction.

package dlp

import (
	"strings"

	"github.com/cloudflare/ahocorasick"
)

// Automaton wraps the underlying Aho-Corasick matcher and the slice of
// patterns it was built from. patternsByPrefixIdx[i] is the list of
// patterns that share dictionary entry i — patterns can share prefixes
// (e.g. multiple patterns with prefix "api"), in which case all sharing
// patterns are treated as candidates and validated by their own regex.
type Automaton struct {
	matcher *ahocorasick.Matcher

	// dict is the deduplicated list of lowercase prefixes fed to the
	// matcher; dictIndex[i] is the prefix string at dictionary index i.
	dict []string

	// patternsByPrefix maps dictionary index → patterns. The matcher
	// returns dictionary indices; we look up all owning patterns here.
	patternsByPrefix [][]*Pattern

	// patternsWithoutPrefix contains patterns whose Prefix is empty.
	// They are treated as candidates everywhere (offset 0) and let the
	// regex validation step do its own positional matching. This is
	// rare in practice (used for SSN, credit card, phone-number style
	// patterns where a fixed prefix is impractical).
	patternsWithoutPrefix []*Pattern
}

// BuildAutomaton constructs an Automaton from the given patterns.
// Patterns with an empty Prefix bypass the Aho-Corasick scan and are
// emitted as candidates with offset 0 for every Scan call.
//
// Matching is case-insensitive at the prefix level (we lowercase both
// the dictionary and the content). The per-pattern regex still honours
// its own flags during validation.
func BuildAutomaton(patterns []*Pattern) *Automaton {
	a := &Automaton{}
	prefixMap := make(map[string]int)
	for _, p := range patterns {
		if p == nil {
			continue
		}
		if p.Prefix == "" {
			a.patternsWithoutPrefix = append(a.patternsWithoutPrefix, p)
			continue
		}
		key := strings.ToLower(p.Prefix)
		idx, ok := prefixMap[key]
		if !ok {
			idx = len(a.dict)
			a.dict = append(a.dict, key)
			a.patternsByPrefix = append(a.patternsByPrefix, nil)
			prefixMap[key] = idx
		}
		a.patternsByPrefix[idx] = append(a.patternsByPrefix[idx], p)
	}
	if len(a.dict) > 0 {
		a.matcher = ahocorasick.NewStringMatcher(a.dict)
	}
	return a
}

// Scan performs a single Aho-Corasick pass over content and returns the
// set of (offset, pattern) candidates that the regex step should
// validate. Empty content returns nil.
func (a *Automaton) Scan(content string) []Candidate {
	if a == nil {
		return nil
	}
	if content == "" && len(a.patternsWithoutPrefix) == 0 {
		return nil
	}

	lower := strings.ToLower(content)
	var out []Candidate

	if a.matcher != nil {
		// MatchThreadSafe is required because the agent serves
		// concurrent scan requests (HTTP and Native Messaging) and
		// the pipeline now fans large payloads out across a worker
		// pool. The non-thread-safe Match mutates per-node generation
		// counters and can drop hits under racy access.
		hits := a.matcher.MatchThreadSafe([]byte(lower))
		for _, idx := range hits {
			if idx < 0 || idx >= len(a.dict) {
				continue
			}
			prefix := a.dict[idx]
			// Walk every occurrence of this prefix; emit one
			// candidate per occurrence per owning pattern.
			start := 0
			for {
				rel := strings.Index(lower[start:], prefix)
				if rel < 0 {
					break
				}
				pos := start + rel
				for _, p := range a.patternsByPrefix[idx] {
					out = append(out, Candidate{Offset: pos, Pattern: p})
				}
				start = pos + len(prefix)
				if start >= len(lower) {
					break
				}
			}
		}
	}

	for _, p := range a.patternsWithoutPrefix {
		out = append(out, Candidate{Offset: 0, Pattern: p})
	}
	return out
}

// PrefixCount returns the number of distinct lowercase prefixes that
// were fed to the underlying matcher. Useful for tests.
func (a *Automaton) PrefixCount() int {
	if a == nil {
		return 0
	}
	return len(a.dict)
}
