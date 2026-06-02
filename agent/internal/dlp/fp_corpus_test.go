package dlp

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFPCorpus runs the labeled testdata/fp_corpus/ entries through the
// full Pipeline and reports precision / recall / F1 / FP rate.
//
// Run with -v to see the breakdown:
//   go test ./internal/dlp -run TestFPCorpus -v
//
// CI-gate this test (and tighten the thresholds) once the launch-day
// pattern set is frozen. For now the failure criteria are conservative
// — they ensure the corpus is wired correctly without failing on
// known borderline patterns.
func TestFPCorpus(t *testing.T) {
	patterns := loadCorpusPatterns(t)
	if len(patterns) == 0 {
		t.Skip("rules/dlp_patterns.json not loadable from test cwd; skipping")
	}
	p := NewPipeline(DefaultScoreWeights(), nil)
	p.Rebuild(patterns, nil)

	corpus := map[string]bool{ // file -> mustBlock
		"public_examples_must_not_trigger.txt": false,
		"placeholders_must_not_trigger.txt":    false,
		"benign_must_not_trigger.txt":          false,
		"clear_secrets_must_trigger.txt":       true,
		"obfuscated_must_trigger.txt":          true,
	}

	type cell struct{ TP, FP, TN, FN int }
	totals := cell{}
	perCategory := map[string]cell{}

	for fname, mustBlock := range corpus {
		entries := readCorpusFile(t, fname)
		c := cell{}
		for _, entry := range entries {
			res := p.Scan(context.Background(), entry)
			blocked := res.Blocked
			switch {
			case mustBlock && blocked:
				c.TP++
				totals.TP++
			case mustBlock && !blocked:
				c.FN++
				totals.FN++
				if testing.Verbose() {
					t.Logf("FN [%s]: %s", fname, truncate(entry, 80))
				}
			case !mustBlock && blocked:
				c.FP++
				totals.FP++
				if testing.Verbose() {
					t.Logf("FP [%s] (pattern=%s, score=%d): %s",
						fname, res.PatternName, res.Score, truncate(entry, 80))
				}
			default:
				c.TN++
				totals.TN++
			}
		}
		perCategory[fname] = c
	}

	t.Log("=========================================================")
	t.Log("FP Corpus Benchmark — Prompt Gate DLP Pipeline")
	t.Log("=========================================================")
	for fname, c := range perCategory {
		mustBlock := corpus[fname]
		expected := "ALLOW"
		if mustBlock {
			expected = "BLOCK"
		}
		t.Logf("  %-48s expect=%s  TP=%d FP=%d TN=%d FN=%d",
			fname, expected, c.TP, c.FP, c.TN, c.FN)
	}
	t.Log("---------------------------------------------------------")
	prec := rate(totals.TP, totals.TP+totals.FP)
	rec := rate(totals.TP, totals.TP+totals.FN)
	f1 := harmonic(prec, rec)
	fpr := rate(totals.FP, totals.FP+totals.TN)
	t.Logf("  Precision : %5.1f%%  (%d / %d)", prec*100, totals.TP, totals.TP+totals.FP)
	t.Logf("  Recall    : %5.1f%%  (%d / %d)", rec*100, totals.TP, totals.TP+totals.FN)
	t.Logf("  F1        : %5.1f%%", f1*100)
	t.Logf("  FP rate   : %5.2f%%  (%d / %d)", fpr*100, totals.FP, totals.FP+totals.TN)
	t.Logf("  Totals    : TP=%d FP=%d TN=%d FN=%d", totals.TP, totals.FP, totals.TN, totals.FN)
	t.Log("=========================================================")

	// Launch-day floor. As of 2026-05-25 the pipeline reports
	// precision 100% / recall 73% / FP rate 0% on this 99-entry
	// corpus. The floors below leave headroom for new patterns that
	// might introduce small precision dips, but fail loudly if a
	// regression cuts precision below 90% or recall below 60%.
	const minPrecision = 0.90
	const minRecall = 0.60
	if prec < minPrecision {
		t.Errorf("precision %.1f%% below launch-day floor of %.0f%%", prec*100, minPrecision*100)
	}
	if rec < minRecall {
		t.Errorf("recall %.1f%% below launch-day floor of %.0f%%", rec*100, minRecall*100)
	}
	// Hard precision-first invariant for the contribution flywheel: every
	// value in the *_must_not_trigger corpus is a curated known-safe sample,
	// so a contributed pattern may NOT block any of them. Zero tolerance —
	// this is the gate that lets the community add patterns safely.
	if totals.FP > 0 {
		t.Errorf("false positives on the must-not-trigger corpus: %d (the precision-first invariant requires 0; see the FP rows logged above)", totals.FP)
	}
}

func loadCorpusPatterns(t *testing.T) []*Pattern {
	t.Helper()
	candidates := []string{
		"../../../rules/dlp_patterns.json",
		"../../rules/dlp_patterns.json",
		"../../../../rules/dlp_patterns.json",
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		patterns, err := LoadPatterns(path)
		if err != nil {
			t.Logf("load patterns from %s: %v", path, err)
			continue
		}
		return patterns
	}
	return nil
}

func readCorpusFile(t *testing.T, name string) []string {
	t.Helper()
	path := filepath.Join("testdata", "fp_corpus", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

func rate(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func harmonic(a, b float64) float64 {
	if a+b == 0 {
		return 0
	}
	return 2 * a * b / (a + b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("…(+%d)", len(s)-n)
}
