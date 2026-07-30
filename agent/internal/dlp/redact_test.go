package dlp

import (
	"context"
	"strings"
	"testing"
)

func TestRedact_AllowPassesThroughUntouched(t *testing.T) {
	p := testPipeline(t)
	content := "The quick brown fox. No secrets here."
	got := p.Redact(context.Background(), content, "", SourceContext{})
	if got.Action != ActionAllow {
		t.Fatalf("expected allow, got %q", got.Action)
	}
	if got.RedactedContent != content {
		t.Fatalf("allow must return original unchanged, got %q", got.RedactedContent)
	}
}

func TestRedact_RemovesSecretAndOutputIsClean(t *testing.T) {
	p := testPipeline(t)
	secret := "AKIA9F2D1JK4X8P0QRTM"
	content := "deploy with aws access_key " + secret + " then continue"

	got := p.Redact(context.Background(), content, "", SourceContext{})
	if got.Action != ActionRedact {
		t.Fatalf("expected redact, got %q (blocked=%v)", got.Action, got.Blocked)
	}
	// The secret must not survive anywhere in the returned text.
	if strings.Contains(got.RedactedContent, secret) {
		t.Fatalf("secret leaked into redacted content: %q", got.RedactedContent)
	}
	// The benign surrounding text must survive.
	if !strings.Contains(got.RedactedContent, "deploy with aws access_key") ||
		!strings.Contains(got.RedactedContent, "then continue") {
		t.Fatalf("redaction destroyed benign text: %q", got.RedactedContent)
	}
	// Re-scanning the output must be clean (mirrors the verify-pass).
	if p.Scan(context.Background(), got.RedactedContent).Blocked {
		t.Fatalf("redacted output still blocks: %q", got.RedactedContent)
	}
	// Reported offsets must point at the token inside the output.
	if len(got.Redactions) == 0 {
		t.Fatal("expected at least one reported redaction")
	}
	for _, r := range got.Redactions {
		if r.Start < 0 || r.End > len(got.RedactedContent) || r.Start >= r.End {
			t.Fatalf("redaction offsets out of range: %+v (len=%d)", r, len(got.RedactedContent))
		}
		if got.RedactedContent[r.Start:r.End] != r.Token {
			t.Fatalf("offset %+v does not point at token %q; got %q", r, r.Token, got.RedactedContent[r.Start:r.End])
		}
	}
}

func TestRedact_NeverCarriesMatchedValue(t *testing.T) {
	p := testPipeline(t)
	secret := "AKIA9F2D1JK4X8P0QRTM"
	content := "aws access_key " + secret

	got := p.Redact(context.Background(), content, "", SourceContext{})
	if got.Action != ActionRedact {
		t.Fatalf("expected redact, got %q", got.Action)
	}
	// Redaction records must never include the secret value (privacy
	// invariant — only pattern name + token + offsets are reportable).
	for _, r := range got.Redactions {
		if strings.Contains(r.Token, secret) || strings.Contains(r.PatternName, secret) {
			t.Fatalf("matched value leaked into a Redaction record: %+v", r)
		}
	}
}

func TestRedact_StableTokenForRepeatedValue(t *testing.T) {
	p := testPipeline(t)
	secret := "AKIA9F2D1JK4X8P0QRTM"
	content := "aws access_key " + secret + " and again " + secret

	got := p.Redact(context.Background(), content, "", SourceContext{})
	if got.Action != ActionRedact {
		t.Fatalf("expected redact, got %q", got.Action)
	}
	if len(got.Redactions) != 2 {
		t.Fatalf("expected 2 redactions for the repeated value, got %d", len(got.Redactions))
	}
	if got.Redactions[0].Token != got.Redactions[1].Token {
		t.Fatalf("same value must reuse the same token, got %q and %q",
			got.Redactions[0].Token, got.Redactions[1].Token)
	}
}

func TestRedact_TokenCollisionGuard(t *testing.T) {
	// If the original already contains the natural first token, the
	// allocator must hand out a different, unused one so a real secret
	// can't be aliased onto pre-existing text.
	secret := "AKIA9F2D1JK4X8P0QRTM"
	a := newTokenAllocator("noise [AWS_ACCESS_KEY_1] noise " + secret)
	pat := &Pattern{Name: "AWS Access Key", Category: "aws access key"}
	tok := a.tokenFor(pat, secret)
	if tok == "[AWS_ACCESS_KEY_1]" {
		t.Fatalf("allocator returned a token already present in source: %q", tok)
	}
	if strings.TrimSpace(tok) == "" || !strings.HasPrefix(tok, "KEY_") {
		t.Fatalf("malformed token: %q", tok)
	}
}

func TestRedact_MergeOverlappingSpansLeavesNoSliver(t *testing.T) {
	spans := []span{
		{start: 10, end: 20, token: "[A_1]", pattern: "A"},
		{start: 15, end: 25, token: "[B_1]", pattern: "B"}, // overlaps
	}
	merged := mergeSpans(spans)
	if len(merged) != 1 {
		t.Fatalf("overlapping spans must merge to one, got %d", len(merged))
	}
	if merged[0].start != 10 || merged[0].end != 25 {
		t.Fatalf("merged span should span [10,25), got [%d,%d)", merged[0].start, merged[0].end)
	}
	if merged[0].token != genericRedactToken {
		t.Fatalf("distinct tokens must collapse to %q, got %q", genericRedactToken, merged[0].token)
	}
}
