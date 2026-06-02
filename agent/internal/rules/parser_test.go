package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRules(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParseFile_BasicLinesAndComments(t *testing.T) {
	body := `# top comment

example.com
.deepseek.com
foo.bar.com  # trailing comment
   # blank-ish
`
	got, err := ParseFile(writeRules(t, "r.txt", body))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	want := []string{"example.com", ".deepseek.com", "foo.bar.com"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("entry[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestParseFile_LowercaseAndTrim(t *testing.T) {
	body := "  EXAMPLE.com  \n.MIXED.Case.Org\n"
	got, err := ParseFile(writeRules(t, "r.txt", body))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if got[0] != "example.com" || got[1] != ".mixed.case.org" {
		t.Fatalf("got %v", got)
	}
}

func TestParseFile_Missing(t *testing.T) {
	if _, err := ParseFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected error on missing file")
	}
}
