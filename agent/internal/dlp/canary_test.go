package dlp

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateCanaryToken(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := GenerateCanaryToken("myfile")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.HasPrefix(tok, canaryTokenPrefix) {
			t.Errorf("token %q missing prefix %q", tok, canaryTokenPrefix)
		}
		// PGCRY(5) + 8 hex + 16 base32 = 29 chars.
		if len(tok) != len(canaryTokenPrefix)+8+16 {
			t.Errorf("token %q length = %d, want %d", tok, len(tok), len(canaryTokenPrefix)+8+16)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}

func TestCanaryNameRoundTrip(t *testing.T) {
	name := CanaryName("prod_db")
	if name != "Canary:prod_db" {
		t.Fatalf("CanaryName = %q", name)
	}
	label, ok := IsCanaryName(name)
	if !ok || label != "prod_db" {
		t.Fatalf("IsCanaryName(%q) = %q, %v", name, label, ok)
	}
	if _, ok := IsCanaryName("AWS Access Key"); ok {
		t.Error("non-canary name should not match")
	}
}

func TestCanaryPatternBlocks(t *testing.T) {
	tok, err := GenerateCanaryToken("secrets_export")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p := CanaryPattern(tok, "secrets_export")
	if p.Compiled == nil {
		t.Fatal("canary pattern must be pre-compiled")
	}

	pipe := NewPipeline(ScoreWeights{}, NewThresholdEngine(DefaultThresholds()))
	pipe.Rebuild(nil, nil) // no rule-file patterns
	pipe.SetCanaryPatterns([]*Pattern{p})

	// The planted token, embedded in surrounding prose, must block.
	res := pipe.Scan(context.Background(), "here is the config value "+tok+" please use it")
	if !res.Blocked {
		t.Fatalf("expected canary to block, got %+v", res)
	}
	if res.PatternName != "Canary:secrets_export" {
		t.Errorf("PatternName = %q, want Canary:secrets_export", res.PatternName)
	}

	// Content without the token must not block.
	if res := pipe.Scan(context.Background(), "ordinary text with no canary"); res.Blocked {
		t.Errorf("unexpected block on clean content: %+v", res)
	}
}

func TestSetCanaryPatternsPreservesBase(t *testing.T) {
	tok, _ := GenerateCanaryToken("c1")
	canary := CanaryPattern(tok, "c1")

	pipe := NewPipeline(ScoreWeights{}, NewThresholdEngine(DefaultThresholds()))
	pipe.SetCanaryPatterns([]*Pattern{canary})

	// A later rule-file Rebuild (no canary arg) must NOT drop the canary.
	pipe.Rebuild(nil, nil)
	if res := pipe.Scan(context.Background(), "value "+tok); !res.Blocked {
		t.Fatalf("canary dropped after Rebuild: %+v", res)
	}

	// Clearing canaries removes the tripwire.
	pipe.SetCanaryPatterns(nil)
	if res := pipe.Scan(context.Background(), "value "+tok); res.Blocked {
		t.Fatalf("canary should be cleared: %+v", res)
	}
}
