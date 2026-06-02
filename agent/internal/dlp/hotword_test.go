package dlp

import "testing"

func TestCheckHotwords_PresentBefore(t *testing.T) {
	p := Pattern{
		Hotwords:      []string{"aws", "access_key"},
		HotwordWindow: 50,
	}
	content := "set aws_access_key=AKIAABCDEFGHIJKLMNOP"
	m := Match{Pattern: &p, Start: 18, End: 38, Value: "AKIAABCDEFGHIJKLMNOP"}
	if !CheckHotwords(content, m, p) {
		t.Fatal("expected hotword to be detected before the match")
	}
}

func TestCheckHotwords_PresentAfter(t *testing.T) {
	p := Pattern{
		Hotwords:      []string{"token"},
		HotwordWindow: 30,
	}
	content := "ghp_abcdef123456789012345678901234567890123456 is a github token"
	m := Match{Pattern: &p, Start: 0, End: 40, Value: "ghp_abcdef12345678901234567890123456789012"}
	if !CheckHotwords(content, m, p) {
		t.Fatal("expected hotword to be detected after the match")
	}
}

func TestCheckHotwords_OutsideWindow(t *testing.T) {
	p := Pattern{
		Hotwords:      []string{"aws"},
		HotwordWindow: 5,
	}
	content := "aws ... a long string with no hotword AKIAABCDEFGHIJKLMNOP"
	m := Match{Pattern: &p, Start: 38, End: 58, Value: "AKIAABCDEFGHIJKLMNOP"}
	if CheckHotwords(content, m, p) {
		t.Fatal("hotword outside window should NOT count")
	}
}

func TestCheckHotwords_EmptyOrZeroWindow(t *testing.T) {
	tests := []struct {
		name string
		p    Pattern
	}{
		{"no hotwords", Pattern{HotwordWindow: 50}},
		{"zero window", Pattern{Hotwords: []string{"aws"}, HotwordWindow: 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := Match{Pattern: &tc.p, Start: 0, End: 4, Value: "AKIA"}
			if CheckHotwords("aws AKIA", m, tc.p) {
				t.Fatal("expected no hotword hit")
			}
		})
	}
}

func TestCheckHotwords_CaseInsensitive(t *testing.T) {
	p := Pattern{Hotwords: []string{"GitHub"}, HotwordWindow: 50}
	content := "the GitHub token here: ghp_abcdef"
	m := Match{Pattern: &p, Start: 23, End: 33, Value: "ghp_abcdef"}
	if !CheckHotwords(content, m, p) {
		t.Fatal("expected case-insensitive hotword match")
	}
}
