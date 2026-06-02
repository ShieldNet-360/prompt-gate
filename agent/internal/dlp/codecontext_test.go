package dlp

import "testing"

func TestIsPlaceholderShape(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		// Bracket templates — should match
		{"angle template uppercase", "<YOUR_API_KEY>", true},
		{"angle template lowercase", "<your_api_key>", true},
		{"angle template insert", "<INSERT_HERE>", true},
		{"angle template with spaces", "<your api key>", true},
		{"angle template with dash", "<api-key-here>", true},
		{"curly interp", "${API_KEY}", true},
		{"handlebar interp", "{{api_key}}", true},

		// Substring markers — should match
		{"your-key-here", "your-secret-here", true},
		{"YOUR_KEY", "YOUR_API_KEY", true},
		{"INSERT_VALUE", "INSERT_VALUE", true},
		{"replace before deploy", "replace-me-before-deploy", true},
		{"sample_key", "sample_aws_key", true},
		{"PLACEHOLDER", "MY_PLACEHOLDER_VALUE", true},
		{"TODO suffix", "TODO_set_key", true},
		{"fixme prefix", "fixme_replace_this", true},
		{"redacted", "[REDACTED]", true},

		// Mask characters — should match
		{"xxxxx", "xxxxxxxxxxxxxxxxxxxxx", true},
		{"XXXXX", "XXXXXXXXXXXXXXXXXXXXX", true},
		{"asterisks", "********************", true},
		{"hashes", "####################", true},
		{"bullets", "●●●●●●●●●●●●●●●●●●●●", true},

		// Real-looking secrets — must NOT match
		{"real-looking AWS key", "AKIAQDIO5JZ8H4PB7M2N", false},
		{"real-looking GH PAT", "ghp_a3f6Lm9pK2vN1bX4qH8rT5wY7eC0sJ", false},
		{"real Stripe live", "sk_live_4eC39HqLyjWDarjtT1zdp7dc", false},
		{"random UUID", "8b1f3a7c-d4e5-4f6a-9b8c-1d2e3f4a5b6c", false},
		{"realistic JWT", "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.x9HRsg", false},
		{"random hex", "8a7b6c5d4e3f2a1b9c8d7e6f5a4b3c2d", false},
		{"benign prose", "this is normal text", false},
		{"angle but not template", "<a href='link'>", false},

		// Edge cases
		{"empty", "", false},
		{"too short", "abc", false},
		{"just angle brackets", "<>", false},
		{"just brackets pair", "<a>", false},
		{"five x's not enough", "xxxxx", false},
		{"six x's enough", "xxxxxx", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsPlaceholderShape(c.value); got != c.want {
				t.Errorf("IsPlaceholderShape(%q) = %v, want %v", c.value, got, c.want)
			}
		})
	}
}

func TestIsTemplateContent(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"API_KEY", true},
		{"YOUR_TOKEN", true},
		{"insert here", true},
		{"a", true},
		{"1234", false}, // no letters
		{"", false},
		{"has@symbol", false},
		{"has/slash", false},
	}
	for _, c := range cases {
		if got := isTemplateContent(c.in); got != c.want {
			t.Errorf("isTemplateContent(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func BenchmarkIsPlaceholderShape(b *testing.B) {
	b.Run("hit_template", func(b *testing.B) {
		v := "<YOUR_API_KEY>"
		for i := 0; i < b.N; i++ {
			_ = IsPlaceholderShape(v)
		}
	})
	b.Run("hit_marker", func(b *testing.B) {
		v := "your-secret-key-here"
		for i := 0; i < b.N; i++ {
			_ = IsPlaceholderShape(v)
		}
	})
	b.Run("miss_real_secret", func(b *testing.B) {
		v := "AKIAQDIO5JZ8H4PB7M2N"
		for i := 0; i < b.N; i++ {
			_ = IsPlaceholderShape(v)
		}
	})
}
