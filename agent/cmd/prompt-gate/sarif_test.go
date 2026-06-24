package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSARIF(t *testing.T) {
	findings := []fileResult{
		{File: "a.txt", Blocked: true, PatternName: "AWS Access Key", Score: 4},
		{File: "b.txt", Blocked: true, PatternName: "AWS Access Key", Score: 4},
	}
	rep := buildSARIF(findings, "1.2.3")

	// Round-trip through JSON to confirm it serialises and the required
	// SARIF fields are present.
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", back["version"])
	}
	if rep.Runs[0].Tool.Driver.Name != "Prompt Gate" {
		t.Errorf("driver name = %q", rep.Runs[0].Tool.Driver.Name)
	}
	// Two findings, one deduped rule.
	if len(rep.Runs[0].Results) != 2 {
		t.Errorf("results = %d, want 2", len(rep.Runs[0].Results))
	}
	if len(rep.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (deduped)", len(rep.Runs[0].Tool.Driver.Rules))
	}
	if rep.Runs[0].Results[0].RuleID != "AWS Access Key" || rep.Runs[0].Results[0].Level != "error" {
		t.Errorf("result0 = %+v", rep.Runs[0].Results[0])
	}
	// Privacy: the matched value must never appear anywhere in the output.
	if bytes.Contains(b, []byte("AKIA")) {
		t.Error("SARIF output leaked a matched value")
	}
}

func TestScanDir(t *testing.T) {
	patPath, excPath, err := resolveRulePaths("", "")
	if err != nil {
		t.Skipf("bundled rules not found: %v", err)
	}
	pipe, err := buildPipeline(patPath, excPath)
	if err != nil {
		t.Fatalf("build pipeline: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "clean.txt"), []byte("just normal text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.env"), []byte("aws_key = AKIA9P2QRMZNL5CVXBT4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A skipped dir must not be scanned.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("aws_key = AKIA9P2QRMZNL5CVXBT4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	stdout = &out
	t.Cleanup(func() { stdout = os.Stdout })

	// JSON mode: exactly one finding (secret.env), .git skipped.
	if code := scanDir(pipe, root, false, false); code != 1 {
		t.Fatalf("scanDir exit = %d, want 1 (out=%s)", code, out.String())
	}
	var res dirScanResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v (%s)", err, out.String())
	}
	if res.Blocked != 1 || len(res.Findings) != 1 || res.Findings[0].File != "secret.env" {
		t.Errorf("unexpected result: %+v", res)
	}

	// SARIF mode produces valid SARIF with the finding.
	out.Reset()
	if code := scanDir(pipe, root, true, false); code != 1 {
		t.Fatalf("sarif scanDir exit = %d", code)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"version": "2.1.0"`)) || !bytes.Contains(out.Bytes(), []byte("secret.env")) {
		t.Errorf("sarif output unexpected: %s", out.String())
	}
}
