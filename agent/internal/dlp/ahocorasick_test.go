package dlp

import (
	"regexp"
	"testing"
)

func mustPattern(name, prefix, regex string) *Pattern {
	return &Pattern{
		Name:     name,
		Prefix:   prefix,
		Regex:    regex,
		Severity: SeverityCritical,
		Compiled: regexp.MustCompile(regex),
	}
}

func TestBuildAutomaton_DedupesPrefixes(t *testing.T) {
	a := BuildAutomaton([]*Pattern{
		mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`),
		mustPattern("AWS Key V2", "AKIA", `AKIA[A-Z]{16}`),
		mustPattern("GitHub Token", "ghp_", `ghp_[a-zA-Z0-9]{36}`),
		mustPattern("No prefix", "", `\d{3}-\d{2}-\d{4}`),
	})
	if got, want := a.PrefixCount(), 2; got != want {
		t.Fatalf("PrefixCount = %d, want %d", got, want)
	}
}

func TestAutomaton_Scan_FindsKnownPrefixes(t *testing.T) {
	patterns := []*Pattern{
		mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`),
		mustPattern("GitHub Token", "ghp_", `ghp_[a-zA-Z0-9]{36}`),
	}
	a := BuildAutomaton(patterns)

	content := "leak: AKIAABCDEFGHIJKLMNOP and also ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	cs := a.Scan(content)
	if len(cs) != 2 {
		t.Fatalf("Scan returned %d candidates, want 2: %#v", len(cs), cs)
	}
	gotNames := map[string]int{}
	for _, c := range cs {
		gotNames[c.Pattern.Name]++
	}
	if gotNames["AWS Key"] != 1 || gotNames["GitHub Token"] != 1 {
		t.Fatalf("missing expected hits: %#v", gotNames)
	}
}

func TestAutomaton_Scan_NoFalsePrefixes(t *testing.T) {
	patterns := []*Pattern{
		mustPattern("AWS Key", "AKIA", `AKIA[A-Z0-9]{16}`),
	}
	a := BuildAutomaton(patterns)
	if cs := a.Scan("plain text with no secrets"); len(cs) != 0 {
		t.Fatalf("Scan unexpectedly returned candidates: %#v", cs)
	}
}

func TestAutomaton_Scan_CaseInsensitivePrefix(t *testing.T) {
	patterns := []*Pattern{
		mustPattern("Generic API", "api", `(?i)api_key=\w{20,}`),
	}
	a := BuildAutomaton(patterns)
	if cs := a.Scan("API_KEY=abcdefghijklmnopqrstuvwxyz"); len(cs) == 0 {
		t.Fatal("expected case-insensitive prefix to match")
	}
}

func TestAutomaton_Scan_PatternsWithoutPrefix(t *testing.T) {
	patterns := []*Pattern{
		mustPattern("SSN", "", `\b\d{3}-\d{2}-\d{4}\b`),
	}
	a := BuildAutomaton(patterns)
	if cs := a.Scan("the number 123-45-7890 might be sensitive"); len(cs) != 1 {
		t.Fatalf("expected one candidate for prefix-less pattern, got %d", len(cs))
	}
}

func TestAutomaton_NilSafe(t *testing.T) {
	var a *Automaton
	if cs := a.Scan("anything"); cs != nil {
		t.Fatalf("nil Automaton.Scan returned %#v, want nil", cs)
	}
	if a.PrefixCount() != 0 {
		t.Fatalf("nil PrefixCount != 0")
	}
}
