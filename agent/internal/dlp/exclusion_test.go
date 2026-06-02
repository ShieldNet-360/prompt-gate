package dlp

import (
	"regexp"
	"testing"
)

func TestCheckExclusion_DictionaryExact_Suppresses(t *testing.T) {
	p := mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`)
	xs := []Exclusion{
		{
			AppliesTo: "AWS Key",
			Type:      ExclusionDictionary,
			MatchType: ExactMatch,
			Words:     []string{"AKIAIOSFODNN7EXAMPLE"},
		},
	}
	m := Match{Pattern: p, Start: 0, End: 20, Value: "AKIAIOSFODNN7EXAMPLE"}
	got := CheckExclusion("AKIAIOSFODNN7EXAMPLE", m, xs)
	if !got.SuppressEntirely {
		t.Fatal("expected exact-match dictionary exclusion to suppress entirely")
	}
}

func TestCheckExclusion_DictionaryProximity_PenalisesOnly(t *testing.T) {
	p := mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`)
	xs := []Exclusion{
		{
			AppliesTo: "*",
			Type:      ExclusionDictionary,
			Words:     []string{"example", "placeholder"},
			Window:    50,
		},
	}
	content := "this is a placeholder AKIAABCDEFGHIJKLMNOP for the example doc"
	m := Match{Pattern: p, Start: 22, End: 42, Value: "AKIAABCDEFGHIJKLMNOP"}
	got := CheckExclusion(content, m, xs)
	if !got.Hit {
		t.Fatal("expected proximity dictionary exclusion to hit")
	}
	if got.SuppressEntirely {
		t.Fatal("proximity exclusion should NOT suppress entirely")
	}
}

func TestCheckExclusion_Regex(t *testing.T) {
	p := mustPattern("Email", "@", `[a-z]+@[a-z.]+`)
	xs := []Exclusion{
		{
			AppliesTo: "Email",
			Type:      ExclusionRegex,
			Pattern:   `@(example\.com|test\.com)`,
			Compiled:  regexp.MustCompile(`@(example\.com|test\.com)`),
		},
	}
	m := Match{Pattern: p, Start: 0, End: 17, Value: "user@example.com"}
	got := CheckExclusion("contact: user@example.com", m, xs)
	if !got.Hit {
		t.Fatal("expected regex exclusion to hit")
	}
}

func TestCheckExclusion_AppliesToNonMatching(t *testing.T) {
	p := mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`)
	xs := []Exclusion{
		{
			AppliesTo: "Some Other Pattern",
			Type:      ExclusionDictionary,
			Words:     []string{"example"},
			Window:    50,
		},
	}
	m := Match{Pattern: p, Start: 8, End: 28, Value: "AKIAABCDEFGHIJKLMNOP"}
	got := CheckExclusion("example AKIAABCDEFGHIJKLMNOP", m, xs)
	if got.Hit {
		t.Fatal("exclusion for a different pattern should not apply")
	}
}

func TestCheckExclusion_EmptyInputs(t *testing.T) {
	if got := CheckExclusion("x", Match{}, nil); got.Hit || got.SuppressEntirely {
		t.Fatal("empty exclusion list should not hit")
	}
}

// TestCheckExclusion_ProximityIgnoresMatchValue ensures the proximity
// haystack excludes the matched secret itself: a real AWS key whose
// body contains an exclusion word (e.g. "test") must not be wrongly
// penalised as a sample/placeholder.
func TestCheckExclusion_ProximityIgnoresMatchValue(t *testing.T) {
	p := mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9_]{16,}`)
	xs := []Exclusion{
		{
			AppliesTo: "*",
			Type:      ExclusionDictionary,
			MatchType: ProximityMatch,
			Words:     []string{"test", "example"},
			Window:    50,
		},
	}
	// "TEST" lives only inside the secret value; nothing in the
	// surrounding context should trip the exclusion.
	content := "leak: AKIA_TEST_ABCDEFGH1234 end"
	m := Match{Pattern: p, Start: 6, End: 27, Value: "AKIA_TEST_ABCDEFGH1234"}
	got := CheckExclusion(content, m, xs)
	if got.Hit {
		t.Fatal("proximity exclusion must not fire on a word that only appears inside the match value")
	}
}
