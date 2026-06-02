package dlp

import (
	"context"
	"strings"
	"testing"
)

// testPipeline builds a pipeline pre-loaded with the same default
// patterns and exclusions used in production rules/dlp_patterns.json
// and rules/dlp_exclusions.json (in miniature form). Keeping these
// inline rather than reading rules/*.json keeps the test hermetic.
func testPipeline(t testing.TB) *Pipeline {
	t.Helper()
	patternsJSON := []byte(`{
		"patterns": [
			{
				"name": "AWS Access Key",
				"regex": "AKIA[0-9A-Z]{16}",
				"prefix": "AKIA",
				"severity": "critical",
				"score_weight": 1,
				"hotwords": ["aws", "access_key", "credentials"],
				"hotword_window": 200,
				"hotword_boost": 2,
				"require_hotword": false,
				"entropy_min": 3.5
			},
			{
				"name": "GitHub Personal Access Token",
				"regex": "ghp_[A-Za-z0-9]{36}",
				"prefix": "ghp_",
				"severity": "critical",
				"score_weight": 1,
				"hotwords": ["github", "token"],
				"hotword_window": 200,
				"hotword_boost": 2,
				"require_hotword": false,
				"entropy_min": 4.0
			},
			{
				"name": "Generic API Key",
				"regex": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}",
				"prefix": "api",
				"severity": "high",
				"score_weight": 1,
				"hotwords": ["api", "key", "token"],
				"hotword_window": 50,
				"hotword_boost": 2,
				"require_hotword": true,
				"entropy_min": 3.0
			}
		]
	}`)

	exclusionsJSON := []byte(`{
		"exclusions": [
			{
				"applies_to": "AWS Access Key",
				"type": "dictionary",
				"match_type": "exact",
				"words": ["AKIAIOSFODNN7EXAMPLE"]
			},
			{
				"applies_to": "*",
				"type": "dictionary",
				"words": ["placeholder", "example", "your-key-here"],
				"window": 50
			}
		]
	}`)

	patterns, err := ParsePatterns(patternsJSON)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}
	exclusions, err := ParseExclusions(exclusionsJSON)
	if err != nil {
		t.Fatalf("ParseExclusions: %v", err)
	}

	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, exclusions)
	return p
}

func TestPipeline_BlocksTruePositive(t *testing.T) {
	p := testPipeline(t)
	content := "Here is my aws access_key for the deploy script: AKIA9F2D1JK4X8P0QRTM"
	got := p.Scan(context.Background(), content)
	if !got.Blocked {
		t.Fatalf("expected block, got %+v", got)
	}
	if got.PatternName != "AWS Access Key" {
		t.Fatalf("expected AWS Access Key, got %q", got.PatternName)
	}
}

func TestPipeline_AllowsExampleAWSKey(t *testing.T) {
	p := testPipeline(t)
	content := "AKIAIOSFODNN7EXAMPLE — see the AWS docs for this placeholder."
	got := p.Scan(context.Background(), content)
	if got.Blocked {
		t.Fatalf("AKIAIOSFODNN7EXAMPLE must be excluded, got block %+v", got)
	}
}

func TestPipeline_AllowsBenignProse(t *testing.T) {
	p := testPipeline(t)
	content := "The quick brown fox jumps over the lazy dog. " +
		"This is plain English with no secrets."
	got := p.Scan(context.Background(), content)
	if got.Blocked {
		t.Fatalf("benign prose blocked: %+v", got)
	}
}

func TestPipeline_RequireHotwordFiltersGenericMatches(t *testing.T) {
	p := testPipeline(t)
	// Generic API Key pattern requires a hotword. Without "api" /
	// "key" / "token" nearby the match must be suppressed.
	contentNoHotword := "apilookups=" + strings.Repeat("a", 30)
	got := p.Scan(context.Background(), contentNoHotword)
	if got.Blocked {
		t.Fatalf("require_hotword should drop %+v", got)
	}
}

func TestPipeline_EmptyContent(t *testing.T) {
	p := testPipeline(t)
	got := p.Scan(context.Background(), "")
	if got.Blocked {
		t.Fatalf("empty content should never block: %+v", got)
	}
}

func TestPipeline_VeryLongContent(t *testing.T) {
	p := testPipeline(t)
	// Embed a real-looking AWS key in a large blob of prose.
	long := strings.Repeat("Lorem ipsum dolor sit amet. ", 5000)
	content := "credentials: aws AKIA9F2D1JK4X8P0QRTM\n" + long
	got := p.Scan(context.Background(), content)
	if !got.Blocked {
		t.Fatalf("large content embedding a real AWS key should block, got %+v", got)
	}
}

func TestPipeline_RebuildIsAtomic(t *testing.T) {
	p := testPipeline(t)
	// Rebuild with an empty pattern set; subsequent scans should not
	// block anything.
	p.Rebuild(nil, nil)
	got := p.Scan(context.Background(), "AKIAABCDEFGHIJKLMNOP")
	if got.Blocked {
		t.Fatalf("after Rebuild(nil,nil) nothing should block; got %+v", got)
	}
}

func TestPipeline_CancelledContextReturnsEmpty(t *testing.T) {
	p := testPipeline(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := p.Scan(ctx, "AKIA9F2D1JK4X8P0QRTM aws access_key")
	if got.Blocked {
		t.Fatal("cancelled context must not block")
	}
}
