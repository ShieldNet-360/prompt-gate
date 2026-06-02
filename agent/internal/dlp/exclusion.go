// Exclusion rule engine (pipeline step 4c).
//
// Exclusions suppress known false positives without requiring a change
// to the core pattern set. Two types are supported:
//
//   - dictionary  — proximity match (any of Words within Window bytes)
//                   or exact match (Match.Value equals one of Words).
//   - regex       — a compiled regexp.Regexp applied to the match.
//
// Exclusions can apply to "*" (all patterns) or to a specific pattern
// by name. The first matching exclusion wins; ExclusionResult.Hit is
// what the scorer multiplies by exclusion_penalty.

package dlp

import "strings"

// ExclusionResult is the outcome of CheckExclusion.
type ExclusionResult struct {
	// Hit indicates whether at least one exclusion applies. The
	// scorer applies the exclusion_penalty when Hit is true.
	Hit bool

	// SuppressEntirely is true when an exact-match dictionary
	// exclusion fired — e.g. AKIAIOSFODNN7EXAMPLE for AWS Access
	// Key. The pipeline drops the match entirely in this case
	// instead of just penalising it.
	SuppressEntirely bool
}

// CheckExclusion evaluates every exclusion in xs against (content,
// match). Order matters only for SuppressEntirely: as soon as an exact
// dictionary hit is found the function returns immediately. Otherwise
// it accumulates Hit across all matching exclusions.
func CheckExclusion(content string, match Match, xs []Exclusion) ExclusionResult {
	if match.Pattern == nil || len(xs) == 0 {
		return ExclusionResult{}
	}
	patternName := match.Pattern.Name
	matchValueLower := strings.ToLower(match.Value)

	var result ExclusionResult
	for _, x := range xs {
		if !exclusionApplies(x.AppliesTo, patternName) {
			continue
		}
		switch x.Type {
		case ExclusionDictionary:
			res := evalDictionary(content, match, matchValueLower, x)
			if res.SuppressEntirely {
				return res
			}
			if res.Hit {
				result.Hit = true
			}
		case ExclusionRegex:
			if x.Compiled == nil {
				continue
			}
			if x.Compiled.FindStringIndex(match.Value) != nil {
				if x.Suppress {
					return ExclusionResult{Hit: true, SuppressEntirely: true}
				}
				result.Hit = true
			}
		}
	}
	return result
}

func exclusionApplies(appliesTo, patternName string) bool {
	if appliesTo == "" || appliesTo == "*" {
		return true
	}
	return strings.EqualFold(appliesTo, patternName)
}

func evalDictionary(content string, match Match, matchValueLower string, x Exclusion) ExclusionResult {
	mt := x.MatchType
	if mt == "" {
		mt = ProximityMatch
	}
	switch mt {
	case ExactMatch:
		for _, w := range x.Words {
			if strings.EqualFold(strings.TrimSpace(w), match.Value) {
				return ExclusionResult{Hit: true, SuppressEntirely: true}
			}
		}
		return ExclusionResult{}
	case ProximityMatch:
		// Look Window bytes either side of the match for any word.
		win := x.Window
		if win <= 0 {
			win = 50
		}
		start := match.Start - win
		if start < 0 {
			start = 0
		}
		end := match.End + win
		if end > len(content) {
			end = len(content)
		}
		hay := strings.ToLower(content[start:end])
		// Strip the matched secret value from the haystack so that
		// an exclusion word that lives inside the match itself
		// (e.g. "test" inside "AKIA_TEST_ABCDEFGH1234") doesn't
		// spuriously trigger the exclusion.
		if matchValueLower != "" {
			hay = strings.Replace(hay, matchValueLower, "", 1)
		}
		for _, w := range x.Words {
			w = strings.ToLower(strings.TrimSpace(w))
			if w == "" {
				continue
			}
			if strings.Contains(hay, w) {
				return ExclusionResult{Hit: true}
			}
		}
		return ExclusionResult{}
	default:
		return ExclusionResult{}
	}
}
