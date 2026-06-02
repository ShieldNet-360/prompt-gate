// Adversary-resistant content normalization.
//
// NormalizeContent canonicalises content to defeat common obfuscation
// tricks that allow real secrets to slip past pattern-based DLP:
//
//   1. Zero-width / format-character strip
//      Removes U+200B-U+200F, U+2060, U+FEFF, U+00AD (soft hyphen),
//      U+180E (Mongolian vowel separator).
//
//   2. Homoglyph fold
//      Maps ~50 common Cyrillic and Greek lookalikes to their Latin
//      equivalents (e.g. Cyrillic U+0410 → Latin "A").
//
//   3. NFKC normalization
//      Applies Unicode compatibility decomposition + canonical
//      recomposition (handles full-width Latin, ligatures, etc.).
//
//   4. Inline base64 decode
//      Detects candidate base64-encoded blocks (length >= 16, padding-
//      aligned, base64 alphabet only) and appends decoded printable
//      plaintext to the content. Enables downstream stages to scan
//      base64-obfuscated secrets without changing the original
//      content's structure.
//
// Privacy invariant: pure string-in / string-out. No I/O, no per-event
// state, no logging.

package dlp

import (
	"encoding/base64"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeContent returns the canonical form of content for DLP
// scanning. The result may be longer than the input when base64 blocks
// were decoded and appended.
func NormalizeContent(content string) string {
	s := content
	s = stripZeroWidth(s)
	s = foldHomoglyphs(s)
	s = norm.NFKC.String(s)
	if decoded := appendDecodedBase64(s); decoded != "" {
		s = s + "\n" + decoded
	}
	return s
}

// zeroWidthRunes is the set of zero-width and invisible format
// characters that should be stripped before scanning.
var zeroWidthRunes = map[rune]struct{}{
	'​': {}, // zero-width space
	'‌': {}, // zero-width non-joiner
	'‍': {}, // zero-width joiner
	'‎': {}, // left-to-right mark
	'‏': {}, // right-to-left mark
	'⁠': {}, // word joiner
	'\uFEFF': {}, // BOM / ZWNBSP
	'­': {}, // soft hyphen
	'᠎': {}, // Mongolian vowel separator
	'؜': {}, // Arabic letter mark
}

func stripZeroWidth(s string) string {
	if !needsStrip(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if _, ok := zeroWidthRunes[r]; ok {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// needsStrip is a fast precheck — only iterate when high-bit bytes
// might be present.
func needsStrip(s string) bool {
	for _, b := range []byte(s) {
		if b > 0x7F {
			return true
		}
	}
	return false
}

// homoglyphFolds maps Cyrillic and Greek visual confusables to their
// Latin ASCII equivalents.
var homoglyphFolds = map[rune]rune{
	// Cyrillic uppercase
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'Х': 'X', 'У': 'Y', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
	'Ѵ': 'V', 'Ԛ': 'Q',

	// Cyrillic lowercase
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'х': 'x', 'у': 'y', 'ѕ': 's', 'і': 'i', 'ј': 'j',
	'ѵ': 'v', 'ԛ': 'q',

	// Greek uppercase
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
	'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',

	// Greek lowercase
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'ν': 'v',
}

func foldHomoglyphs(s string) string {
	if !needsStrip(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if fold, ok := homoglyphFolds[r]; ok {
			b.WriteRune(fold)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Tunables for the base64-decode pass.
const (
	minBase64Candidate = 16
	maxBase64Candidate = 4096
	minPrintableRatio  = 0.80
	maxDecodedAppend   = 32 * 1024
)

// appendDecodedBase64 scans s for base64-aligned candidate substrings,
// decodes those that yield mostly-printable plaintext, and returns the
// concatenation. Returns "" if no candidates qualified.
func appendDecodedBase64(s string) string {
	var out strings.Builder

	i := 0
	for i < len(s) {
		if !isBase64ByteASCII(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && isBase64ByteASCII(s[i]) {
			i++
		}
		cand := s[start:i]
		if len(cand) < minBase64Candidate || len(cand) > maxBase64Candidate {
			continue
		}
		if len(cand)%4 != 0 {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(cand)
		if err != nil {
			continue
		}
		if !isMostlyPrintable(decoded) {
			continue
		}
		if out.Len()+len(decoded) > maxDecodedAppend {
			break
		}
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.Write(decoded)
	}
	return out.String()
}

func isBase64ByteASCII(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '='
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= minPrintableRatio
}
