package dlp

import (
	"os"
	"path/filepath"
	"testing"
)

const bundledPatterns = `{"patterns":[
	{"name":"AWS Access Key","regex":"AKIA[A-Z0-9]{16}","prefix":"AKIA","severity":"critical"},
	{"name":"Generic Hex","regex":"[a-f0-9]{32}","prefix":"","severity":"low"}
]}`

const overridePatterns = `{"patterns":[
	{"name":"AWS Access Key","regex":"AKIA[A-Z0-9]{16}","prefix":"AKIA","severity":"high"},
	{"name":"Company Token","regex":"acme_[A-Z]{8}","prefix":"acme_","severity":"critical"}
]}`

const bundledExclusions = `{"exclusions":[
	{"applies_to":"global","type":"dictionary","words":["placeholder"]}
]}`

const overrideExclusions = `{"exclusions":[
	{"applies_to":"AWS Access Key","type":"regex","pattern":"AKIAIOSFODNN7EXAMPLE"},
	{"applies_to":"global","type":"dictionary","words":["placeholder"]}
]}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestMergePatternsFromDirReplacesAndAppends(t *testing.T) {
	bundled := filepath.Join(t.TempDir(), "dlp_patterns.json")
	localDir := t.TempDir()
	writeFile(t, bundled, bundledPatterns)
	writeFile(t, filepath.Join(localDir, "dlp_patterns_override.json"), overridePatterns)

	merged, err := MergePatternsFromDir(bundled, localDir)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(merged))
	}

	// Original index for AWS must keep its position, severity flipped.
	if merged[0].Name != "AWS Access Key" {
		t.Fatalf("ordering changed: %s", merged[0].Name)
	}
	if merged[0].Severity != "high" {
		t.Fatalf("override did not replace severity: %s", merged[0].Severity)
	}
	if merged[2].Name != "Company Token" {
		t.Fatalf("new pattern not appended: %s", merged[2].Name)
	}
}

func TestMergePatternsMissingLocalIsFine(t *testing.T) {
	bundled := filepath.Join(t.TempDir(), "dlp_patterns.json")
	writeFile(t, bundled, bundledPatterns)
	merged, err := MergePatternsFromDir(bundled, t.TempDir())
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 patterns (no override file), got %d", len(merged))
	}
}

func TestMergeExclusionsDedup(t *testing.T) {
	bundled := filepath.Join(t.TempDir(), "dlp_exclusions.json")
	localDir := t.TempDir()
	writeFile(t, bundled, bundledExclusions)
	writeFile(t, filepath.Join(localDir, "dlp_exclusions_override.json"), overrideExclusions)

	merged, err := MergeExclusionsFromDir(bundled, localDir)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 exclusions after dedup, got %d", len(merged))
	}
}

func TestMergeExclusionsEmptyDir(t *testing.T) {
	bundled := filepath.Join(t.TempDir(), "dlp_exclusions.json")
	writeFile(t, bundled, bundledExclusions)
	merged, err := MergeExclusionsFromDir(bundled, "")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("expected 1 exclusion when localDir empty, got %d", len(merged))
	}
}
