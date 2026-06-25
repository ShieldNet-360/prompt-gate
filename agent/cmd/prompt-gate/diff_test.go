package main

import (
	"bytes"
	"strings"
	"testing"
)

const awsKey = "AKIA9P2QRMZNL5CVXBT4"

func TestParseUnifiedDiff(t *testing.T) {
	diff := `diff --git a/src/config.go b/src/config.go
--- a/src/config.go
+++ b/src/config.go
@@ -10,0 +11,2 @@ func load()
+key := "` + awsKey + `"
+region := "us-east-1"
@@ -40 +42,0 @@ func old()
-deleted line
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,0 +2,1 @@
+just docs
`
	chunks, err := parseUnifiedDiff(strings.NewReader(diff))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 files, got %d: %+v", len(chunks), chunks)
	}
	if chunks[0].File != "src/config.go" || chunks[0].FirstLine != 11 {
		t.Errorf("file0 = %+v, want src/config.go @ 11", chunks[0])
	}
	if len(chunks[0].Added) != 2 || !strings.Contains(chunks[0].Added[0], awsKey) {
		t.Errorf("file0 added = %v", chunks[0].Added)
	}
	if chunks[1].File != "README.md" || chunks[1].FirstLine != 2 {
		t.Errorf("file1 = %+v, want README.md @ 2", chunks[1])
	}
}

func TestScanDiff(t *testing.T) {
	patPath, excPath, err := resolveRulePaths("", "")
	if err != nil {
		t.Skipf("bundled rules not found: %v", err)
	}
	pipe, err := buildPipeline(patPath, excPath)
	if err != nil {
		t.Fatalf("build pipeline: %v", err)
	}

	var out bytes.Buffer
	stdout = &out
	t.Cleanup(func() { stdout = nil })

	// Diff that adds an AWS key → blocked, exit 1, finding for the file.
	bad := "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+secret " + awsKey + "\n"
	if code := scanDiff(pipe, strings.NewReader(bad), false); code != 1 {
		t.Fatalf("blocked diff exit = %d, want 1", code)
	}
	if !strings.Contains(out.String(), `"blocked": true`) || !strings.Contains(out.String(), `"file": "x"`) {
		t.Errorf("output missing finding: %s", out.String())
	}

	// Clean diff → exit 0.
	out.Reset()
	clean := "diff --git a/y b/y\n--- a/y\n+++ b/y\n@@ -0,0 +1 @@\n+just a normal line of code\n"
	if code := scanDiff(pipe, strings.NewReader(clean), false); code != 0 {
		t.Fatalf("clean diff exit = %d, want 0 (out=%s)", code, out.String())
	}

	// Quiet mode suppresses output.
	out.Reset()
	if code := scanDiff(pipe, strings.NewReader(bad), true); code != 1 {
		t.Fatalf("quiet blocked exit = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("quiet mode should emit nothing, got: %s", out.String())
	}
}
