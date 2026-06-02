package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLookup_ExactAndSubdomain(t *testing.T) {
	dir := t.TempDir()
	chat := writeFile(t, dir, "chat.txt", ".deepseek.com\nperplexity.ai\n")
	soc := writeFile(t, dir, "soc.txt", ".facebook.com\n")

	l, err := Build([]RuleSource{
		{Category: "AI Chat", Path: chat},
		{Category: "Social", Path: soc},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	cases := []struct {
		domain string
		want   string
		ok     bool
	}{
		{"deepseek.com", "AI Chat", true},
		{"foo.deepseek.com", "AI Chat", true},
		{"a.b.deepseek.com", "AI Chat", true},
		{"perplexity.ai", "AI Chat", true},
		{"sub.perplexity.ai", "", false}, // exact only
		{"facebook.com", "Social", true},
		{"www.facebook.com", "Social", true},
		{"example.org", "", false},
		{"", "", false},
		{"DeepSeek.COM.", "AI Chat", true},
	}
	for _, c := range cases {
		cat, ok := l.Lookup(c.domain)
		if cat != c.want || ok != c.ok {
			t.Errorf("Lookup(%q) = (%q,%v), want (%q,%v)", c.domain, cat, ok, c.want, c.ok)
		}
	}
}

func TestLookup_Replace(t *testing.T) {
	dir := t.TempDir()
	first := writeFile(t, dir, "1.txt", ".example.com\n")
	l, err := Build([]RuleSource{{Category: "Cat1", Path: first}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cat, ok := l.Lookup("foo.example.com"); !ok || cat != "Cat1" {
		t.Fatalf("Lookup before Replace: %q ok=%v", cat, ok)
	}

	second := writeFile(t, dir, "2.txt", ".other.com\n")
	if err := l.Replace([]RuleSource{{Category: "Cat2", Path: second}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, ok := l.Lookup("foo.example.com"); ok {
		t.Fatal("expected example.com to be gone after Replace")
	}
	if cat, ok := l.Lookup("a.other.com"); !ok || cat != "Cat2" {
		t.Fatalf("Lookup after Replace: %q ok=%v", cat, ok)
	}
}
