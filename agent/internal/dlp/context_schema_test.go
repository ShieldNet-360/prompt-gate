// Phase 8 Config F — schema tests (slices 1 + 2 invariants).
//
// Asserts:
//   1. SourceContext{}.IsZero() correctly identifies an empty struct;
//      any field set returns false.
//   2. Pipeline.ScanWithContext with an empty SourceContext returns
//      the same verdict as Scan / ScanSession — the backwards-compat
//      guarantee that survives slice 2's bias rules.
//   3. Pattern JSON tolerates a missing ContextBias field (existing
//      patterns continue to load).
//   4. Pattern JSON round-trips an explicit ContextBias map.
//
// Slice 2 behavioural changes (bias actually fires for non-empty
// source) are covered separately in phase8_scoring_test.go.

package dlp

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
)

func TestPhase8_SourceContext_IsZero(t *testing.T) {
	if !(SourceContext{}).IsZero() {
		t.Errorf("zero-value SourceContext must report IsZero()=true")
	}
	cases := []SourceContext{
		{DestinationKind: "ai_chat"},
		{DestinationHost: "chat.openai.com"},
		{ElementKind: "contenteditable"},
		{InCodeFence: true},
		{LanguageHint: "javascript"},
		{SurroundingHash: "a1b2c3d4e5f60718"},
		{PageURLHash: "f1e2d3c4b5a69788"},
	}
	for _, c := range cases {
		if c.IsZero() {
			t.Errorf("SourceContext %+v reports IsZero()=true, expected false", c)
		}
	}
}

func TestPhase8_Pipeline_ScanWithContext_EmptySource_MatchesScan(t *testing.T) {
	// Build a tiny pipeline with one AWS-shape pattern.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:        "AWS Access Key",
			Regex:       `AKIA[0-9A-Z]{16}`,
			Prefix:      "AKIA",
			Severity:    SeverityCritical,
			ScoreWeight: 1,
			Hotwords:    []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"
	ctx := context.Background()

	wantScan := p.Scan(ctx, content)
	wantSession := p.ScanSession(ctx, content, "")
	gotContextEmpty := p.ScanWithContext(ctx, content, "", SourceContext{})

	// Slice 1: bias rules not yet wired, so all three must agree.
	if wantScan != gotContextEmpty {
		t.Errorf("ScanWithContext(empty source) = %+v, want Scan() = %+v",
			gotContextEmpty, wantScan)
	}
	if wantSession != gotContextEmpty {
		t.Errorf("ScanWithContext(empty source) = %+v, want ScanSession() = %+v",
			gotContextEmpty, wantSession)
	}
}

func TestPhase8_Pattern_ContextBias_JSONRoundTrip(t *testing.T) {
	// Missing context_bias is tolerated (old rule files load fine).
	withoutBias := `{
		"name": "Test",
		"regex": "x",
		"prefix": "x",
		"severity": "low",
		"score_weight": 1,
		"hotwords": [],
		"hotword_window": 0,
		"hotword_boost": 0,
		"require_hotword": false,
		"entropy_min": 0
	}`
	var p1 Pattern
	if err := json.Unmarshal([]byte(withoutBias), &p1); err != nil {
		t.Fatalf("unmarshal without context_bias: %v", err)
	}
	if p1.ContextBias != nil {
		t.Errorf("missing context_bias must unmarshal to nil map, got %v", p1.ContextBias)
	}

	// Explicit context_bias round-trips byte-for-byte equivalent.
	withBias := `{
		"name": "AWS Access Key",
		"regex": "AKIA[0-9A-Z]{16}",
		"prefix": "AKIA",
		"severity": "critical",
		"score_weight": 1,
		"hotwords": ["aws"],
		"hotword_window": 200,
		"hotword_boost": 2,
		"require_hotword": false,
		"entropy_min": 3.5,
		"context_bias": {"code_host": -2, "paste_bin": 1}
	}`
	var p2 Pattern
	if err := json.Unmarshal([]byte(withBias), &p2); err != nil {
		t.Fatalf("unmarshal with context_bias: %v", err)
	}
	if p2.ContextBias == nil {
		t.Fatal("explicit context_bias must unmarshal to a non-nil map")
	}
	if p2.ContextBias["code_host"] != -2 {
		t.Errorf("code_host bias = %d, want -2", p2.ContextBias["code_host"])
	}
	if p2.ContextBias["paste_bin"] != 1 {
		t.Errorf("paste_bin bias = %d, want 1", p2.ContextBias["paste_bin"])
	}

	// Re-marshal and re-unmarshal — make sure the map survives.
	out, err := json.Marshal(p2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p3 Pattern
	if err := json.Unmarshal(out, &p3); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if p3.ContextBias["code_host"] != -2 || p3.ContextBias["paste_bin"] != 1 {
		t.Errorf("round-trip lost context_bias: got %v", p3.ContextBias)
	}
}

// mustCompilePattern compiles the regex on a Pattern literal and
// returns the same pointer with .Compiled populated. Shared by the
// Phase 8 tests that need a one-pattern Pipeline without going
// through file I/O.
func mustCompilePattern(t *testing.T, p *Pattern) *Pattern {
	t.Helper()
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		t.Fatalf("compile pattern %s: %v", p.Name, err)
	}
	p.Compiled = re
	if p.Category == "" {
		p.Category = CategoryUncategorized
	}
	return p
}
