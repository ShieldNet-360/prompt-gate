package dlp

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Redaction action values for RedactionResult.Action.
const (
	ActionAllow  = "allow"
	ActionBlock  = "block"
	ActionRedact = "redact"
)

// genericRedactToken is used when merged spans cover more than one
// distinct secret type, so we never have to guess a label across a
// merged region.
const genericRedactToken = "**"

// Redaction is one applied replacement. Start/End are byte offsets into
// the RETURNED RedactedContent (not the original). The matched value is
// deliberately absent — it must never leave this process.
type Redaction struct {
	PatternName string `json:"pattern_name"`
	Token       string `json:"token"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
}

// RedactionResult is what Redact returns. It embeds the underlying
// ScanResult so callers that only care about block/allow can read
// Blocked/PatternName/Score directly.
type RedactionResult struct {
	ScanResult
	Action          string      `json:"action"`
	RedactedContent string      `json:"redacted_content,omitempty"`
	Redactions      []Redaction `json:"redactions,omitempty"`
}

// span is an internal [start,end) range in ORIGINAL coordinates plus
// the token that replaces it and the pattern that produced it.
type span struct {
	start, end int
	token      string
	pattern    string
}

// Redact runs the same pipeline as ScanWithContext and, when the
// verdict is to block, attempts to remove the offending secrets in
// place rather than rejecting the whole payload.
//
// Safety contract (see docs/redaction-design.md §7) — all enforced in
// code below, every edge fails CLOSED to block:
//
//  1. Relocate each secret verbatim in the ORIGINAL content. Match
//     offsets are in normalized space, so a secret that only exists
//     after normalization (homoglyph / base64 obfuscation) cannot be
//     located here → block, never a partial splice.
//  2. Merge overlapping / adjacent spans so no un-redacted sliver can
//     survive between two patterns covering the same secret.
//  3. Token-collision guard: the token chosen for a span is guaranteed
//     not to already occur in the original text.
//  4. Verify-pass: re-scan the redacted output; if anything still
//     trips, discard it and block. A leak now needs two independent
//     failures.
//
// Pure function: no I/O, no globals (preserves the engine-portability
// invariant). source may be the zero value.
func (p *Pipeline) Redact(ctx context.Context, content, sessionID string, source SourceContext) RedactionResult {
	base := p.ScanWithContext(ctx, content, sessionID, source)
	if !base.Blocked {
		return RedactionResult{ScanResult: base, Action: ActionAllow, RedactedContent: content}
	}

	blocked := RedactionResult{ScanResult: base, Action: ActionBlock}

	spans, ok := p.locateSecrets(content)
	if !ok || len(spans) == 0 {
		// Could not safely locate every secret in the original, or
		// nothing to redact despite a block — fail closed.
		return blocked
	}

	redacted, redactions := spliceSpans(content, spans)

	// Verify-pass: the redacted copy must itself be clean. If the
	// splice missed anything (or normalization rejoined a secret), we
	// refuse to send it.
	if p.ScanWithContext(ctx, redacted, sessionID, source).Blocked {
		return blocked
	}

	return RedactionResult{
		ScanResult:      base,
		Action:          ActionRedact,
		RedactedContent: redacted,
		Redactions:      redactions,
	}
}

// locateSecrets finds every non-benign match and maps it to a span in
// ORIGINAL coordinates. Returns ok=false (fail closed) if any secret
// cannot be located verbatim in the original. Over-redaction is safe;
// under-redaction is not, so benign-but-matched values are still
// removed (public-example/placeholder hits are skipped because
// they are provably not secrets).
func (p *Pipeline) locateSecrets(original string) ([]span, bool) {
	p.mu.RLock()
	auto := p.automaton
	largeThreshold := p.largeThreshold
	disabledCats := p.disabledCategories
	p.mu.RUnlock()
	if auto == nil {
		return nil, false
	}
	if largeThreshold <= 0 {
		largeThreshold = LargeContentThreshold
	}

	canonical := NormalizeContent(original)
	candidates := auto.Scan(canonical)
	candidates = filterCandidates(candidates, len(canonical), largeThreshold, disabledCats)
	matches := ValidateCandidates(canonical, candidates)

	// Collect distinct secret values (skip provably-benign public-example hits),
	// then redact EVERY occurrence of each in the original. Locating
	// every occurrence — not just the first — is what makes a repeated
	// secret fully removed; a single strings.Index would leave later
	// copies behind for the verify-pass to (correctly) block on.
	tokens := newTokenAllocator(original)
	seen := map[string]struct{}{}
	var spans []span
	for _, m := range matches {
		if IsPublicExample(m.Value) || IsPlaceholderShape(m.Value) {
			continue // provably not a secret — leave it in place
		}
		if m.Value == "" {
			continue
		}
		key := m.Pattern.Name + "\x00" + m.Value
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		token := tokens.tokenFor(m.Pattern, m.Value)
		from := 0
		found := false
		for {
			rel := strings.Index(original[from:], m.Value)
			if rel < 0 {
				break
			}
			start := from + rel
			spans = append(spans, span{
				start:   start,
				end:     start + len(m.Value),
				token:   token,
				pattern: m.Pattern.Name,
			})
			from = start + len(m.Value)
			found = true
		}
		if !found {
			// Secret exists only in normalized form (homoglyph / base64
			// obfuscation). We cannot prove where it sits in the bytes
			// we are about to send, so refuse to redact and let the
			// caller block.
			return nil, false
		}
	}
	if len(spans) == 0 {
		return nil, true
	}
	return mergeSpans(spans), true
}

// mergeSpans sorts by start and merges overlapping or adjacent ranges
// so no gap between two patterns can leak a fragment. When a merge
// combines distinct tokens the region collapses to genericRedactToken.
func mergeSpans(spans []span) []span {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	merged := make([]span, 0, len(spans))
	for _, s := range spans {
		if n := len(merged); n > 0 && s.start <= merged[n-1].end {
			if s.end > merged[n-1].end {
				merged[n-1].end = s.end
			}
			if s.token != merged[n-1].token {
				merged[n-1].token = genericRedactToken
				merged[n-1].pattern = ""
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// spliceSpans rebuilds the content with each span replaced by its
// token, and reports the redactions with offsets into the RETURNED
// string. spans must be sorted, non-overlapping (as mergeSpans
// guarantees).
func spliceSpans(original string, spans []span) (string, []Redaction) {
	var b strings.Builder
	redactions := make([]Redaction, 0, len(spans))
	prev := 0
	for _, s := range spans {
		b.WriteString(original[prev:s.start])
		outStart := b.Len()
		b.WriteString(s.token)
		redactions = append(redactions, Redaction{
			PatternName: s.pattern,
			Token:       s.token,
			Start:       outStart,
			End:         b.Len(),
		})
		prev = s.end
	}
	b.WriteString(original[prev:])
	return b.String(), redactions
}

// tokenAllocator hands out stable, collision-free tokens within a
// single scan. The same (pattern, value) reuses its token so
// coreference survives; distinct values increment the per-category
// counter; and a token that already appears literally in the original
// is skipped so a real secret can never be aliased onto pre-existing
// text.
type tokenAllocator struct {
	original string
	byValue  map[string]string // pattern.Name + "\x00" + value -> token
	counter  map[string]int    // category slug -> next n
}

func newTokenAllocator(original string) *tokenAllocator {
	return &tokenAllocator{
		original: original,
		byValue:  map[string]string{},
		counter:  map[string]int{},
	}
}

func (a *tokenAllocator) tokenFor(pat *Pattern, value string) string {
	key := pat.Name + "\x00" + value
	if tok, ok := a.byValue[key]; ok {
		return tok
	}
	slug := categorySlug(pat)
	for {
		a.counter[slug]++
		tok := fmt.Sprintf("[%s_%d]", slug, a.counter[slug])
		if !strings.Contains(a.original, tok) {
			a.byValue[key] = tok
			return tok
		}
	}
}

// categorySlug derives an UPPER_SNAKE token label from a pattern's
// category, falling back to its name. Non-alphanumerics fold to "_".
func categorySlug(pat *Pattern) string {
	src := pat.Category
	if src == "" || src == CategoryUncategorized {
		src = pat.Name
	}
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToUpper(src) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" {
		slug = "REDACTED"
	}
	return slug
}
