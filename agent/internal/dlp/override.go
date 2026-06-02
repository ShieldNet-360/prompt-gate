package dlp

import (
	"errors"
	"os"
	"path/filepath"
)

// MergePatternsFromDir loads bundled patterns from bundledPath and
// (if present) merges in patterns from
// <localDir>/dlp_patterns_override.json. Merge semantics: an entry
// in the override file with the same Name replaces the bundled
// entry; otherwise it is appended. An empty localDir or missing
// override file leaves the bundled set untouched.
func MergePatternsFromDir(bundledPath, localDir string) ([]*Pattern, error) {
	patterns, err := LoadPatterns(bundledPath)
	if err != nil {
		return nil, err
	}
	if localDir == "" {
		return patterns, nil
	}
	overridePath := filepath.Join(localDir, "dlp_patterns_override.json")
	overrides, err := LoadPatterns(overridePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return patterns, nil
		}
		return nil, err
	}
	return mergePatterns(patterns, overrides), nil
}

// MergeExclusionsFromDir does the same as MergePatternsFromDir for
// exclusions. Exclusion identity is (Type, AppliesTo, Match,
// Pattern); ties replace the bundled entry, mismatches append.
func MergeExclusionsFromDir(bundledPath, localDir string) ([]Exclusion, error) {
	exclusions, err := LoadExclusions(bundledPath)
	if err != nil {
		return nil, err
	}
	if localDir == "" {
		return exclusions, nil
	}
	overridePath := filepath.Join(localDir, "dlp_exclusions_override.json")
	overrides, err := LoadExclusions(overridePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return exclusions, nil
		}
		return nil, err
	}
	return mergeExclusions(exclusions, overrides), nil
}

func mergePatterns(base, over []*Pattern) []*Pattern {
	byName := make(map[string]int, len(base))
	for i, p := range base {
		if p != nil {
			byName[p.Name] = i
		}
	}
	out := append([]*Pattern(nil), base...)
	for _, p := range over {
		if p == nil {
			continue
		}
		if idx, ok := byName[p.Name]; ok {
			out[idx] = p
			continue
		}
		out = append(out, p)
		byName[p.Name] = len(out) - 1
	}
	return out
}

func exclusionKey(e Exclusion) string {
	// Identity is (Type, AppliesTo, Pattern) plus the joined word
	// list for dictionary exclusions. Two exclusions with the same
	// applies_to + identical content are treated as equivalent.
	words := ""
	for _, w := range e.Words {
		words += w + "\x00"
	}
	return string(e.Type) + "|" + e.AppliesTo + "|" + e.Pattern + "|" + words
}

func mergeExclusions(base, over []Exclusion) []Exclusion {
	byKey := make(map[string]int, len(base))
	for i, e := range base {
		byKey[exclusionKey(e)] = i
	}
	out := append([]Exclusion(nil), base...)
	for _, e := range over {
		k := exclusionKey(e)
		if idx, ok := byKey[k]; ok {
			out[idx] = e
			continue
		}
		out = append(out, e)
		byKey[k] = len(out) - 1
	}
	return out
}
