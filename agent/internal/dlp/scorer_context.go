// Source-context score-bias rules.
//
// ScoreBiasFromContext returns an additive delta applied to the
// per-pattern top score BEFORE the threshold check.
//
// Bias axes (each independent, stacks additively):
//
//   * Destination axis — destination_kind → delta.
//       code_host → -2  (dominant real-world FP class: committed
//                        test fixtures in *_test.go / fixtures/)
//       others    →  0  (baseline preserved)
//     Per-pattern Pattern.ContextBias[destination_kind] REPLACES
//     the global destination delta when present, so a pattern can
//     override e.g. "for AWS keys, code_host is -3 not -2".
//
//   * Element axis — element_kind → delta.
//       network_body → +1  (programmatic exfil intent is stronger
//                           than a manual paste)
//       others       →  0
//
//   * Code-fence axis — in_code_fence + low/medium severity → -1.
//     Dampens "here's how the AWS SDK works" style code-demo pastes
//     while leaving critical/high severity untouched.
//
//   * Language-hint axis — language_hint ∈ {test, fixture, spec}
//     (case-insensitive, whitespace-stripped) → -1.
//
// Returns 0 when source is the zero value (default scoring behaviour
// unchanged).
//
// Privacy invariant: this function is pure — string in / int out,
// no I/O, no per-event state, no logging.

package dlp

import "strings"

// Destination-kind enum values used by the global bias table and
// (typically) by the browser extension when populating
// SourceContext.DestinationKind. Strings, not iota, because they
// cross the JSON wire boundary.
const (
	DestinationKindAIChat   = "ai_chat"
	DestinationKindAICode   = "ai_code"
	DestinationKindCodeHost = "code_host"
	DestinationKindPasteBin = "paste_bin"
	DestinationKindSocial   = "social"
	DestinationKindEmail    = "email"
	DestinationKindUnknown  = "unknown"
)

// Element-kind enum values matching what each browser-extension
// interceptor populates (one per content-script type).
const (
	ElementKindInput           = "input"
	ElementKindTextarea        = "textarea"
	ElementKindContentEditable = "contenteditable"
	ElementKindFormSubmit      = "form_submit"
	ElementKindNetworkBody     = "network_body"
	ElementKindDragDrop        = "drag_drop"
	ElementKindClipboard       = "clipboard"
)

// ScoreBiasFromContext computes the score delta described in the
// file-level comment.
func ScoreBiasFromContext(pat Pattern, source SourceContext) int {
	if source.IsZero() {
		return 0
	}

	delta := 0
	delta += destinationDelta(pat, source.DestinationKind)
	delta += elementDelta(source.ElementKind)
	delta += codeFenceDelta(pat, source.InCodeFence)
	delta += languageHintDelta(source.LanguageHint)
	delta += pathHintDelta(source.DestinationKind, source.PathHint)
	return delta
}

// destinationDelta resolves the destination_kind axis. A per-pattern
// ContextBias entry replaces the global delta for that kind. An
// absent ContextBias map, or one that does not list this kind, falls
// through to the global table.
func destinationDelta(pat Pattern, kind string) int {
	if kind == "" {
		return 0
	}
	if pat.ContextBias != nil {
		if d, ok := pat.ContextBias[kind]; ok {
			return d
		}
	}
	switch kind {
	case DestinationKindCodeHost:
		return -2
	}
	return 0
}

// elementDelta resolves the element_kind axis. Programmatic
// outbound traffic (fetch / XHR / WebSocket body) signals stronger
// exfil intent than a human paste.
func elementDelta(kind string) int {
	if kind == ElementKindNetworkBody {
		return 1
	}
	return 0
}

// codeFenceDelta dampens low/medium-severity pattern hits when the
// caller signals the paste is inside a code fence (a demo / tutorial
// snippet). Critical and high severity are unaffected — a real AWS
// key in a code fence is still a real AWS key.
func codeFenceDelta(pat Pattern, inFence bool) int {
	if !inFence {
		return 0
	}
	switch pat.Severity {
	case SeverityMedium, SeverityLow:
		return -1
	}
	return 0
}

// languageHintDelta suppresses one point when the caller's
// language hint indicates the surrounding code is test / fixture /
// spec content.
func languageHintDelta(hint string) int {
	if isTestLanguageHint(hint) {
		return -1
	}
	return 0
}

// isTestLanguageHint matches the canonical hint strings the
// browser extension uses for test-suite contexts. Whitespace is
// trimmed and the match is case-insensitive so "Test" / "FIXTURE"
// also fire.
func isTestLanguageHint(hint string) bool {
	switch strings.ToLower(strings.TrimSpace(hint)) {
	case "test", "fixture", "spec":
		return true
	}
	return false
}

// Path-hint axis.
//
// pathHintDelta returns -1 only when the destination is a code host
// AND the extension classified the URL pathname as test / fixture /
// spec / mock. Restricting this to code_host avoids double-counting
// when a hint like "test" rides in language_hint already (which is
// the only path on non-code-host destinations) — language_hint's
// rule still fires on its own, but adding pathHintDelta there would
// be a -2 over-correction.
func pathHintDelta(destinationKind, pathHint string) int {
	if destinationKind != DestinationKindCodeHost {
		return 0
	}
	if isTestPathHint(pathHint) {
		return -1
	}
	return 0
}

func isTestPathHint(hint string) bool {
	switch strings.ToLower(strings.TrimSpace(hint)) {
	case "test", "fixture", "spec", "mock":
		return true
	}
	return false
}
