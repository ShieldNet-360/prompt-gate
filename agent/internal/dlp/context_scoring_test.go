// Phase 8 Config F — Slice 2 scoring-bias tests.
//
// Asserts:
//   1. ScoreBiasFromContext returns 0 for a zero source (Config E).
//   2. Each global bias axis fires independently with the documented
//      delta:
//        destination_kind = code_host        → -2
//        element_kind     = network_body     → +1
//        in_code_fence    AND severity≤med   → -1 (and 0 above)
//        language_hint    ∈ {test,fixture,spec, case-insens.} → -1
//   3. The four axes stack additively.
//   4. Pattern.ContextBias for the matching destination_kind REPLACES
//      the global destination delta. Entries for OTHER kinds do not
//      bleed across.
//   5. Pattern.ContextBias does not interfere with the element /
//      code-fence / language axes — those stack on top.
//   6. Pipeline-level end-to-end: same AKIA content blocks on
//      destination_kind=ai_chat and falls below threshold on
//      destination_kind=code_host (when score_weight + hotword_boost
//      net out to a score the -2 delta can push below the critical
//      threshold).
//   7. Per-pattern critical severity is NOT softened by in_code_fence
//      (regression guard — a real AWS key in a fenced demo is still
//      blocked).

package dlp

import (
	"context"
	"testing"
	"time"
)

// ── unit tests for ScoreBiasFromContext ────────────────────────────

func TestPhase8_ScoreBiasFromContext_EmptyReturnsZero(t *testing.T) {
	pat := Pattern{Severity: SeverityCritical}
	if got := ScoreBiasFromContext(pat, SourceContext{}); got != 0 {
		t.Errorf("zero source must yield bias=0, got %d", got)
	}
}

func TestPhase8_ScoreBiasFromContext_GlobalAxes(t *testing.T) {
	pat := Pattern{Severity: SeverityMedium}

	cases := []struct {
		name   string
		source SourceContext
		want   int
	}{
		{"code_host -2", SourceContext{DestinationKind: DestinationKindCodeHost}, -2},
		{"ai_chat baseline", SourceContext{DestinationKind: DestinationKindAIChat}, 0},
		{"ai_code baseline", SourceContext{DestinationKind: DestinationKindAICode}, 0},
		{"paste_bin baseline", SourceContext{DestinationKind: DestinationKindPasteBin}, 0},
		{"unknown baseline", SourceContext{DestinationKind: DestinationKindUnknown}, 0},
		{"network_body +1", SourceContext{DestinationKind: DestinationKindAIChat, ElementKind: ElementKindNetworkBody}, 1},
		{"contenteditable baseline", SourceContext{DestinationKind: DestinationKindAIChat, ElementKind: ElementKindContentEditable}, 0},
		{"code_fence + medium -1", SourceContext{DestinationKind: DestinationKindAIChat, InCodeFence: true}, -1},
		{"lang=test -1", SourceContext{DestinationKind: DestinationKindAIChat, LanguageHint: "test"}, -1},
		{"lang=Fixture -1 (case-insens)", SourceContext{DestinationKind: DestinationKindAIChat, LanguageHint: "Fixture"}, -1},
		{"lang= SPEC  -1 (whitespace + case)", SourceContext{DestinationKind: DestinationKindAIChat, LanguageHint: " SPEC "}, -1},
		{"lang=javascript baseline", SourceContext{DestinationKind: DestinationKindAIChat, LanguageHint: "javascript"}, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ScoreBiasFromContext(pat, c.source); got != c.want {
				t.Errorf("bias = %d, want %d (source=%+v)", got, c.want, c.source)
			}
		})
	}
}

func TestPhase8_ScoreBiasFromContext_FenceDoesNotSoftenCritical(t *testing.T) {
	for _, sev := range []Severity{SeverityCritical, SeverityHigh} {
		pat := Pattern{Severity: sev}
		got := ScoreBiasFromContext(pat, SourceContext{
			DestinationKind: DestinationKindAIChat,
			InCodeFence:     true,
		})
		if got != 0 {
			t.Errorf("severity=%s in code fence must NOT yield bias, got %d", sev, got)
		}
	}
}

func TestPhase8_ScoreBiasFromContext_StacksAdditively(t *testing.T) {
	// code_host (-2) + network_body (+1) + lang=test (-1) = -2
	// (code_fence -1 also stacks for medium severity → final -3)
	pat := Pattern{Severity: SeverityMedium}
	source := SourceContext{
		DestinationKind: DestinationKindCodeHost,
		ElementKind:     ElementKindNetworkBody,
		InCodeFence:     true,
		LanguageHint:    "test",
	}
	want := -2 + 1 + -1 + -1 // = -3
	if got := ScoreBiasFromContext(pat, source); got != want {
		t.Errorf("stacked bias = %d, want %d", got, want)
	}
}

func TestPhase8_ScoreBiasFromContext_PerPatternOverridesGlobalDestination(t *testing.T) {
	// Pattern declares context_bias = {"code_host": -5}; that
	// replaces the global -2 for code_host. Other destinations
	// still use the global table.
	pat := Pattern{
		Severity: SeverityCritical,
		ContextBias: map[string]int{
			DestinationKindCodeHost: -5,
		},
	}

	if got := ScoreBiasFromContext(pat, SourceContext{DestinationKind: DestinationKindCodeHost}); got != -5 {
		t.Errorf("per-pattern code_host bias = %d, want -5", got)
	}
	// Per-pattern map has no entry for ai_chat → falls back to global (0).
	if got := ScoreBiasFromContext(pat, SourceContext{DestinationKind: DestinationKindAIChat}); got != 0 {
		t.Errorf("per-pattern map without ai_chat key must fall back to global=0, got %d", got)
	}
}

func TestPhase8_ScoreBiasFromContext_PerPatternStacksWithOtherAxes(t *testing.T) {
	// Per-pattern destination delta (-3) + global element delta (+1)
	// + global lang delta (-1) = -3.
	pat := Pattern{
		Severity: SeverityCritical,
		ContextBias: map[string]int{
			DestinationKindCodeHost: -3,
		},
	}
	source := SourceContext{
		DestinationKind: DestinationKindCodeHost,
		ElementKind:     ElementKindNetworkBody,
		LanguageHint:    "test",
	}
	want := -3 + 1 + -1
	if got := ScoreBiasFromContext(pat, source); got != want {
		t.Errorf("per-pattern + axes bias = %d, want %d", got, want)
	}
}

func TestPhase8_ScoreBiasFromContext_PerPatternPositiveOverride(t *testing.T) {
	// Sanity: a per-pattern entry can also be positive (e.g. a low-
	// signal pattern that should ESCALATE on paste_bin destinations).
	pat := Pattern{
		Severity: SeverityCritical,
		ContextBias: map[string]int{
			DestinationKindPasteBin: 2,
		},
	}
	if got := ScoreBiasFromContext(pat, SourceContext{DestinationKind: DestinationKindPasteBin}); got != 2 {
		t.Errorf("per-pattern paste_bin +2 = %d, want 2", got)
	}
}

// ── end-to-end via Pipeline.ScanWithContext ────────────────────────

func TestPhase8_Pipeline_BiasFires_E2E(t *testing.T) {
	// Pattern: AWS access key, critical severity. With hotwords nearby
	// it scores score_weight(1) + hotword_boost(2) = 3.
	// Threshold for critical = 1.
	//
	//   destination=ai_chat   → bias 0  → score 3, blocks
	//   destination=code_host → bias -2 → score 1, still blocks (>= 1)
	//
	// To prove bias actually flips the verdict we need to reach below
	// the threshold. Use a per-pattern override of -3 for code_host:
	// score 3 - 3 = 0 < critical=1 → allows.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "AWS Access Key (test)",
			Regex:         `AKIA[0-9A-Z]{16}`,
			Prefix:        "AKIA",
			Severity:      SeverityCritical,
			ScoreWeight:   1,
			Hotwords:      []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
			ContextBias:   map[string]int{DestinationKindCodeHost: -3},
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"
	ctx := context.Background()

	chatResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		DestinationHost: "chat.openai.com",
		ElementKind:     ElementKindContentEditable,
	})
	if !chatResult.Blocked {
		t.Fatalf("expected ai_chat destination to BLOCK, got %+v", chatResult)
	}
	if chatResult.Score != 3 {
		t.Errorf("ai_chat score = %d, want 3 (no bias)", chatResult.Score)
	}

	codeResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		DestinationHost: "github.com",
		ElementKind:     ElementKindContentEditable,
	})
	if codeResult.Blocked {
		t.Fatalf("expected code_host destination to ALLOW (bias -3 drops score 3 → 0 < 1), got %+v", codeResult)
	}
}

func TestPhase8_Pipeline_GlobalCodeHostBias_E2E(t *testing.T) {
	// Verify the GLOBAL code_host -2 fires when no per-pattern
	// override is set. With a high-severity pattern (threshold=2)
	// and a baseline score of 3, code_host -2 drops to 1 < 2 →
	// allows.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "Generic Token",
			Regex:         `token_[A-Z0-9]{16}`,
			Prefix:        "token_",
			Severity:      SeverityHigh,
			ScoreWeight:   1,
			Hotwords:      []string{"api"},
			HotwordWindow: 200,
			HotwordBoost:  2,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	content := "api: token_ABCDEFGHIJKLMNOP"
	ctx := context.Background()

	chatResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		ElementKind:     ElementKindContentEditable,
	})
	if !chatResult.Blocked {
		t.Fatalf("expected ai_chat to BLOCK; got %+v", chatResult)
	}

	codeResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		ElementKind:     ElementKindContentEditable,
	})
	if codeResult.Blocked {
		t.Fatalf("expected code_host -2 to drop score 3 → 1 < high=2 ALLOW; got %+v", codeResult)
	}
}

// ── Phase 8 Config F2 — path_hint axis ─────────────────────────────

func TestPhase8_ScoreBiasFromContext_PathHintOnlyOnCodeHost(t *testing.T) {
	pat := Pattern{Severity: SeverityCritical}

	// path_hint applies only on code_host destinations.
	codeTest := SourceContext{
		DestinationKind: DestinationKindCodeHost,
		PathHint:        "test",
	}
	if got := ScoreBiasFromContext(pat, codeTest); got != -2-1 { // dest -2 + path -1
		t.Errorf("code_host + path=test bias = %d, want -3", got)
	}

	chatTest := SourceContext{
		DestinationKind: DestinationKindAIChat,
		PathHint:        "test",
	}
	// On ai_chat the path_hint is ignored; bias is 0 (no axes apply).
	if got := ScoreBiasFromContext(pat, chatTest); got != 0 {
		t.Errorf("ai_chat + path=test must NOT apply path bias, got %d", got)
	}

	// fixture / spec / mock all suppress on code_host; docs / "" do not.
	for _, p := range []string{"test", "fixture", "spec", "mock"} {
		src := SourceContext{DestinationKind: DestinationKindCodeHost, PathHint: p}
		if got := ScoreBiasFromContext(pat, src); got != -3 {
			t.Errorf("code_host + path=%s bias = %d, want -3", p, got)
		}
	}
	for _, p := range []string{"docs", "src", ""} {
		src := SourceContext{DestinationKind: DestinationKindCodeHost, PathHint: p}
		if got := ScoreBiasFromContext(pat, src); got != -2 {
			t.Errorf("code_host + path=%s bias = %d, want -2 (no path delta)", p, got)
		}
	}
}

func TestPhase8_Pipeline_PathHint_E2E(t *testing.T) {
	// AWS Access Key on code_host (-2) + path=test (-1) = -3 bias.
	// score_weight 1 + hotword_boost 2 = 3 base. 3 + (-3) = 0 < critical=1.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "AWS Access Key (path test)",
			Regex:         `AKIA[0-9A-Z]{16}`,
			Prefix:        "AKIA",
			Severity:      SeverityCritical,
			ScoreWeight:   1,
			Hotwords:      []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"
	ctx := context.Background()

	// code_host alone (-2): 3 - 2 = 1 ≥ critical=1 → still blocks.
	codeOnly := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		DestinationHost: "github.com",
		ElementKind:     ElementKindContentEditable,
	})
	if !codeOnly.Blocked {
		t.Fatalf("code_host alone must still block at threshold, got %+v", codeOnly)
	}

	// code_host + path=test (-3): 3 - 3 = 0 < critical=1 → allows.
	codeTest := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		DestinationHost: "github.com",
		ElementKind:     ElementKindContentEditable,
		PathHint:        "test",
	})
	if codeTest.Blocked {
		t.Fatalf("code_host + path=test must drop verdict to allow, got %+v", codeTest)
	}
}

func TestPhase8_Pipeline_CacheRespectsSource(t *testing.T) {
	// Regression: the Phase 6 scan-result cache keys only by content.
	// Without the source-aware bypass, two scans of the same content
	// with DIFFERENT source contexts would return the same cached
	// verdict — defeating Slice 2's bias entirely.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "AWS Access Key (test)",
			Regex:         `AKIA[0-9A-Z]{16}`,
			Prefix:        "AKIA",
			Severity:      SeverityCritical,
			ScoreWeight:   1,
			Hotwords:      []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
			ContextBias:   map[string]int{DestinationKindCodeHost: -3},
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)
	// Enable the cache that would otherwise short-circuit.
	p.EnableCache(NewScanCache(64, 5*time.Second))

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"
	ctx := context.Background()

	// Prime the cache with the no-source path.
	bare := p.Scan(ctx, content)
	if !bare.Blocked {
		t.Fatalf("bare Scan must block; got %+v", bare)
	}

	// Same content with code_host bias must NOT return the cached
	// no-source verdict — bias is -3, so score drops from 3 to 0
	// and the verdict flips to allow.
	codeResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		DestinationHost: "github.com",
		ElementKind:     ElementKindContentEditable,
	})
	if codeResult.Blocked {
		t.Fatalf("source must bypass content-only cache; got cached-poisoned %+v", codeResult)
	}
}

// ── Phase 8 Config H — allowlist suppresses in pipeline ───────────

func TestPhase8_Pipeline_AllowlistSuppresses_E2E(t *testing.T) {
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "AWS Access Key (H test)",
			Regex:         `AKIA[0-9A-Z]{16}`,
			Prefix:        "AKIA",
			Severity:      SeverityCritical,
			ScoreWeight:   1,
			Hotwords:      []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	// Wire a fresh allowlist on an in-memory DB.
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, err := NewAllowlist(ctx, db, testSalt(), nil)
	if err != nil {
		t.Fatalf("new allowlist: %v", err)
	}
	p.EnableAllowlist(a)

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"

	// Before adding: blocks.
	before := p.Scan(ctx, content)
	if !before.Blocked {
		t.Fatalf("baseline must block; got %+v", before)
	}

	// Add the matched value to the allowlist (scope=*).
	if _, err := a.Add(ctx, "AKIA9P2QRMZNL5CVXBT4", "", "AWS Access Key", 0); err != nil {
		t.Fatalf("add: %v", err)
	}

	// After adding: scan is allowed regardless of source (scope=*).
	after := p.Scan(ctx, content)
	if after.Blocked {
		t.Fatalf("allowlist must suppress match; got %+v", after)
	}
	afterChat := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		ElementKind:     ElementKindContentEditable,
	})
	if afterChat.Blocked {
		t.Fatalf("allowlist scope=* must suppress on ai_chat; got %+v", afterChat)
	}
}

func TestPhase8_Pipeline_AllowlistScopeIsHonoured_E2E(t *testing.T) {
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "AWS Access Key (H scope test)",
			Regex:         `AKIA[0-9A-Z]{16}`,
			Prefix:        "AKIA",
			Severity:      SeverityCritical,
			ScoreWeight:   1,
			Hotwords:      []string{"aws"},
			HotwordWindow: 200,
			HotwordBoost:  2,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)
	db := newAllowlistDB(t)
	ctx := context.Background()
	a, _ := NewAllowlist(ctx, db, testSalt(), nil)
	p.EnableAllowlist(a)

	// Allowlist this value ONLY on code_host.
	if _, err := a.Add(ctx, "AKIA9P2QRMZNL5CVXBT4", "code_host", "", 0); err != nil {
		t.Fatalf("add: %v", err)
	}

	content := "aws creds: AKIA9P2QRMZNL5CVXBT4 follow"

	// On code_host → allowed.
	codeResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindCodeHost,
		ElementKind:     ElementKindContentEditable,
	})
	if codeResult.Blocked {
		t.Fatalf("code_host scope must suppress on code_host; got %+v", codeResult)
	}

	// On ai_chat → still blocks.
	chatResult := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		ElementKind:     ElementKindContentEditable,
	})
	if !chatResult.Blocked {
		t.Fatalf("code_host scope must NOT suppress on ai_chat; got %+v", chatResult)
	}
}

func TestPhase8_Pipeline_NetworkBodyEscalates_E2E(t *testing.T) {
	// A low-confidence medium-severity pattern with a baseline score
	// of 2 sits below threshold(medium)=3, so it allows by default.
	// element_kind=network_body adds +1 → score 3 → blocks.
	patterns := []*Pattern{
		mustCompilePattern(t, &Pattern{
			Name:          "Suspicious Token Shape",
			Regex:         `tk_[a-z0-9]{20}`,
			Prefix:        "tk_",
			Severity:      SeverityMedium,
			ScoreWeight:   2,
			Hotwords:      nil,
			HotwordWindow: 0,
			HotwordBoost:  0,
		}),
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)

	content := "tk_abcdefghijklmnopqrst"
	ctx := context.Background()

	// Allowed via paste in chat (score 2 < threshold 3).
	chatPaste := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		ElementKind:     ElementKindContentEditable,
	})
	if chatPaste.Blocked {
		t.Fatalf("paste path should NOT block (score 2 < medium=3); got %+v", chatPaste)
	}

	// Same content via outbound fetch body → +1 bias → score 3 = threshold → blocks.
	chatNetwork := p.ScanWithContext(ctx, content, "", SourceContext{
		DestinationKind: DestinationKindAIChat,
		ElementKind:     ElementKindNetworkBody,
	})
	if !chatNetwork.Blocked {
		t.Fatalf("network_body should ESCALATE score 2→3 and block; got %+v", chatNetwork)
	}
}
