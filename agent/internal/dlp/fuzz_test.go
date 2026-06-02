package dlp

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzPipelineScan feeds random byte strings through a real DLP
// pipeline configured the same way the production agent builds it.
// The goals are narrow on purpose:
//
//   - the pipeline must NOT panic on arbitrary input,
//   - the pipeline must NOT echo input bytes back as part of an
//     evidence field (the privacy invariant: nothing scanned ever
//     leaves Pipeline.Scan), and
//   - every Scan must return within a tight wall-clock budget so a
//     pathological regex backtrack can't deadlock the agent.
//
// Seed inputs cover the corner cases that classical fuzzers struggle
// with: empty strings, control characters, partial UTF-8, very long
// runs of the same character, and almost-valid token prefixes.
//
// This is the agent/internal/dlp/fuzz_test.go file from Phase 6 Task
// 25. Run with: go test -run=NONE -fuzz=FuzzPipelineScan -fuzztime=30s ./internal/dlp/
func FuzzPipelineScan(f *testing.F) {
	seeds := []string{
		"",
		" ",
		"a",
		strings.Repeat("a", 1024),
		strings.Repeat("\x00", 64),
		"\xff\xfe\xfd",
		"AKIA1234567890123456",
		"api_key = '" + strings.Repeat("x", 32) + "'",
		"-----BEGIN RSA PRIVATE KEY-----",
		"https://example.com/?token=" + strings.Repeat("a", 40),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p := testPipeline(f)
	deadline := 250 * time.Millisecond

	f.Fuzz(func(t *testing.T, input string) {
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()

		done := make(chan ScanResult, 1)
		go func() { done <- p.Scan(ctx, input) }()

		var res ScanResult
		select {
		case res = <-done:
		case <-time.After(deadline * 4):
			t.Fatalf("Scan exceeded %v on input of length %d", deadline*4, len(input))
		}

		// Privacy invariant: the wire-level ScanResult must never
		// echo the caller's input. PatternName is a static label
		// drawn from rules/dlp_patterns.json — if it ever starts
		// containing input bytes we have a privacy regression.
		if res.PatternName != "" && len(input) >= 16 && strings.Contains(res.PatternName, input) {
			t.Fatalf("PatternName leaked input bytes: %q", res.PatternName)
		}

		// Sanity: blocked results must surface a pattern name so
		// downstream consumers (the extension toast, the popup
		// history) can label the block. The pipeline contract
		// guarantees this.
		if res.Blocked && res.PatternName == "" {
			t.Fatalf("Blocked=true with empty PatternName on input %q", input)
		}
	})
}
