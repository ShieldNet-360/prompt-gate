package dlp

import (
	"strings"
	"testing"
)

func TestStripZeroWidth(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no zw chars", "hello world", "hello world"},
		{"ascii only", "ABC", "ABC"},
		{"zwsp between chars", "A​K​I​A", "AKIA"},
		{"zwnj zwj", "A‌K‍I‌A", "AKIA"},
		{"bom prefix", "\uFEFFhello", "hello"},
		{"soft hyphen", "AK­I­A", "AKIA"},
		{"word joiner", "AK⁠IA", "AKIA"},
		{"lrm rlm", "A‎K‏I", "AKI"},
		{"cyrillic pass-through (no fold)", "Кофе", "Кофе"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stripZeroWidth(c.in); got != c.want {
				t.Errorf("stripZeroWidth(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestFoldHomoglyphs(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain ascii", "AKIA1234", "AKIA1234"},
		{"cyrillic A upper", "АKIA1234", "AKIA1234"},
		{"cyrillic AKIA", "АКІА", "AKIA"},
		{"greek alpha to A", "ΑKIA1234", "AKIA1234"},
		{"greek upper mix", "ΑΚΙΑ", "AKIA"},
		{"cyrillic lowercase", "аеор", "aeop"},
		{"already latin", "passthrough", "passthrough"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := foldHomoglyphs(c.in); got != c.want {
				t.Errorf("foldHomoglyphs(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeContent_Homoglyph(t *testing.T) {
	in := "Hi, my key is АKIAQDIO5JZ8H4PB7M2N for prod."
	got := NormalizeContent(in)
	if !strings.Contains(got, "AKIAQDIO5JZ8H4PB7M2N") {
		t.Errorf("expected normalized to contain Latin 'AKIAQDIO5JZ8H4PB7M2N', got %q", got)
	}
}

func TestNormalizeContent_ZeroWidth(t *testing.T) {
	in := "key A​K​I​A​Q​D​I​O​5​J​Z​8​H​4​P​B​7​M​2​N"
	got := NormalizeContent(in)
	if !strings.Contains(got, "AKIAQDIO5JZ8H4PB7M2N") {
		t.Errorf("expected zero-width-stripped key, got %q", got)
	}
}

func TestNormalizeContent_Base64Decode(t *testing.T) {
	in := "obfuscated: QUtJQVFESU81Slo4SDRQQjdNMk4="
	got := NormalizeContent(in)
	if !strings.Contains(got, "AKIAQDIO5JZ8H4PB7M2N") {
		t.Errorf("expected decoded plaintext appended, got %q", got)
	}
}

func TestNormalizeContent_NFKC(t *testing.T) {
	in := "ＡＫＩＡＱＤＩＯ５ＪＺ８Ｈ４ＰＢ７Ｍ２Ｎ"
	got := NormalizeContent(in)
	if !strings.Contains(got, "AKIAQDIO5JZ8H4PB7M2N") {
		t.Errorf("expected fullwidth normalized to ASCII, got %q", got)
	}
}

func TestNormalizeContent_PassthroughBenign(t *testing.T) {
	in := "Hey can you help me debug this Python function?"
	got := NormalizeContent(in)
	if got != in {
		t.Errorf("benign content should pass through unchanged, got %q", got)
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"ASCII alnum", []byte("AKIAQDIO5JZ8H4PB7M2N"), true},
		{"printable punct", []byte("printable!@#$%"), true},
		{"all NUL", []byte{0x00, 0x01, 0x02, 0x03}, false},
		{"50% printable", []byte{0x00, 'a', 0x01, 'b', 0x02, 'c'}, false},
		{"nil", nil, false},
		{"empty", []byte{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isMostlyPrintable(c.in); got != c.want {
				t.Errorf("isMostlyPrintable(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func BenchmarkNormalizeContent(b *testing.B) {
	b.Run("ascii_passthrough", func(b *testing.B) {
		s := "Hey can you help me debug this Python function? It does X and Y."
		for i := 0; i < b.N; i++ {
			_ = NormalizeContent(s)
		}
	})
	b.Run("homoglyph_fold", func(b *testing.B) {
		s := "my key is АKIAQDIO5JZ8H4PB7M2N for prod"
		for i := 0; i < b.N; i++ {
			_ = NormalizeContent(s)
		}
	})
	b.Run("base64_decode", func(b *testing.B) {
		s := "obfuscated: QUtJQVFESU81Slo4SDRQQjdNMk4="
		for i := 0; i < b.N; i++ {
			_ = NormalizeContent(s)
		}
	})
}
