package dlp

import "testing"

func TestValidateCandidates_NoCompiled(t *testing.T) {
	// Pattern without Compiled is silently skipped.
	p := &Pattern{Name: "x", Prefix: "AKIA", Regex: "AKIA[A-Z0-9]{16}"}
	cs := []Candidate{{Offset: 0, Pattern: p}}
	if got := ValidateCandidates("AKIAABCDEFGHIJKLMNOP", cs); len(got) != 0 {
		t.Fatalf("ValidateCandidates returned matches for uncompiled pattern: %#v", got)
	}
}

func TestValidateCandidates_RealHit(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	content := "leak: AKIAABCDEFGHIJKLMNOP end"
	cs := []Candidate{{Offset: 6, Pattern: p}}
	got := ValidateCandidates(content, cs)
	if len(got) != 1 {
		t.Fatalf("ValidateCandidates returned %d matches, want 1: %#v", len(got), got)
	}
	if got[0].Value != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("got value %q, want %q", got[0].Value, "AKIAABCDEFGHIJKLMNOP")
	}
}

func TestValidateCandidates_NoSpuriousMatch(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	cs := []Candidate{{Offset: 0, Pattern: p}}
	if got := ValidateCandidates("AKIAxxxx", cs); len(got) != 0 {
		t.Fatalf("ValidateCandidates returned %d matches for non-matching content", len(got))
	}
}

func TestValidateCandidates_DedupesByPattern(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	content := "AKIA0000000000000000 and AKIA1111111111111111"
	cs := []Candidate{
		{Offset: 0, Pattern: p},
		{Offset: 25, Pattern: p}, // same pattern twice
	}
	got := ValidateCandidates(content, cs)
	if len(got) != 2 {
		t.Fatalf("want 2 dedup'd matches, got %d", len(got))
	}
}

func TestValidateCandidates_LongContentWindow(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	prefix := make([]byte, regexWindow*4)
	for i := range prefix {
		prefix[i] = 'x'
	}
	content := string(prefix) + "AKIAABCDEFGHIJKLMNOP"
	offset := len(prefix)
	got := ValidateCandidates(content, []Candidate{{Offset: offset, Pattern: p}})
	if len(got) != 1 {
		t.Fatalf("expected window-bound regex to find match, got %d", len(got))
	}
}

func TestValidateCandidates_EmptyInputs(t *testing.T) {
	if got := ValidateCandidates("", nil); got != nil {
		t.Fatalf("empty inputs should yield nil, got %#v", got)
	}
	if got := ValidateCandidates("x", nil); got != nil {
		t.Fatalf("nil candidates should yield nil, got %#v", got)
	}
}

// TestValidateCandidates_PrefixedMultipleOffsets guards against a DLP
// bypass where a prefixed pattern has multiple Aho-Corasick offsets in
// a large paste: the first occurrence is a benign mention of the prefix
// in prose (no full regex hit) and the real secret sits at a distant
// offset whose window does not overlap the first. An earlier
// implementation marked the pattern as "seen" after the first candidate
// failed to validate and silently skipped the rest, so the real key was
// missed.
func TestValidateCandidates_PrefixedMultipleOffsets(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	// First AKIA: benign — prefix appears in prose with no full
	// match after it. Then 4 KiB of padding to push the real key
	// well outside the first candidate's regex window.
	head := "we use AKIA-style keys, e.g. "
	pad := make([]byte, regexWindow*4)
	for i := range pad {
		pad[i] = 'x'
	}
	realKey := "key: AKIAABCDEFGHIJKLMNOP end"
	content := head + string(pad) + realKey
	realOffset := len(head) + len(pad) + len("key: ")
	if got := content[realOffset : realOffset+20]; got != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("test setup wrong; got %q", got)
	}
	// Mimic what BuildAutomaton + Scan would produce: two AC
	// candidates for the same pattern at distant offsets.
	cs := []Candidate{
		{Offset: 7, Pattern: p},          // first AKIA inside head, no real match
		{Offset: realOffset, Pattern: p}, // real key, far past the first window
	}
	got := ValidateCandidates(content, cs)
	if len(got) != 1 {
		t.Fatalf("expected 1 match at distant offset, got %d: %#v", len(got), got)
	}
	if got[0].Value != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("got value %q, want %q", got[0].Value, "AKIAABCDEFGHIJKLMNOP")
	}
}

// TestValidateCandidates_OffsetBeyondContent is a regression test for
// a panic when the Aho-Corasick offset exceeds content length, causing
// start > end in findAllInWindow.
func TestValidateCandidates_OffsetBeyondContent(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	// Content is large enough to skip the "scan full content" shortcut.
	pad := make([]byte, regexWindow*4)
	for i := range pad {
		pad[i] = 'x'
	}
	content := string(pad) + "AKIAABCDEFGHIJKLMNOP"
	// Offset well past end of content — must not panic.
	cs := []Candidate{{Offset: len(content) + 1000, Pattern: p}}
	got := ValidateCandidates(content, cs)
	// The match should still be found since the window clamps to
	// [len(content)-regexWindow, len(content)].
	if len(got) != 1 {
		t.Fatalf("expected 1 match with out-of-bounds offset, got %d", len(got))
	}
}

// TestValidateCandidates_PrefixlessLargeContent guards against a class
// of DLP bypass where a prefix-less pattern (e.g. SSN, credit card)
// gets hidden in long pastes — the Aho-Corasick offset is a sentinel
// (0) for prefix-less patterns, so the validator must scan the full
// content rather than a window starting at byte 0.
func TestValidateCandidates_PrefixlessLargeContent(t *testing.T) {
	p := mustPattern("SSN", "", `\d{3}-\d{2}-\d{4}`)
	// Build a paste that's well past the regexWindow*2 cutoff and
	// puts the secret far away from byte 0 so a windowed scan
	// starting at offset=0 would miss it.
	pad := make([]byte, regexWindow*4)
	for i := range pad {
		pad[i] = 'x'
	}
	content := string(pad) + "ssn 123-45-6789 end"
	got := ValidateCandidates(content, []Candidate{{Offset: 0, Pattern: p}})
	if len(got) != 1 {
		t.Fatalf("prefix-less pattern in large content: got %d matches, want 1", len(got))
	}
	if got[0].Value != "123-45-6789" {
		t.Fatalf("got value %q, want %q", got[0].Value, "123-45-6789")
	}
}
