package dlp

import "testing"

func TestIsPublicExample(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Must match — known public examples
		{"AWS docs key exact", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS docs key lowercase", "akiaiosfodnn7example", true},
		{"AWS docs key mixed case", "AkiAIosfODnn7examplE", true},
		{"AWS docs secret with /", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},
		{"Stripe test secret", "sk_test_4eC39HqLyjWDarjtT1zdp7dc", true},
		{"Stripe test secret without underscores", "sktest4eC39HqLyjWDarjtT1zdp7dc", true},
		{"Stripe test public", "pk_test_TYooMQauvdEDq54NiTphI7jx", true},
		{"Stripe restricted test", "rk_test_50tlPgJ65xQ8Hk88OF0EVx0p", true},

		// Test cards — formatting variations must collide
		{"Visa test no separators", "4111111111111111", true},
		{"Visa test with dashes", "4111-1111-1111-1111", true},
		{"Visa test with spaces", "4111 1111 1111 1111", true},
		{"Visa test mixed", "4111 1111-1111 1111", true},
		{"Stripe Visa test", "4242-4242-4242-4242", true},
		{"Mastercard test", "5555 5555 5555 4444", true},
		{"Amex test", "378282246310005", true},
		{"Amex test with dashes", "3782-822463-10005", true},
		{"Discover test", "6011111111111117", true},

		// SSN placeholders
		{"SSN 000-00-0000", "000-00-0000", true},
		{"SSN 123-45-6789", "123-45-6789", true},
		{"SSN no dashes", "123456789", true},

		// UUIDs
		{"Nil UUID", "00000000-0000-0000-0000-000000000000", true},
		{"Stripe doc UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"UUID no dashes", "550e8400e29b41d4a716446655440000", true},
		{"UUID uppercase", "550E8400-E29B-41D4-A716-446655440000", true},
		{"All-ones UUID", "11111111-1111-1111-1111-111111111111", true},
		{"All-f UUID", "ffffffff-ffff-ffff-ffff-ffffffffffff", true},

		// GitHub PAT placeholders
		{"GH PAT x-padded", "ghp_xxxxxxxxxxxxxxxxxxxx", true},
		{"GH server x-padded", "ghs_xxxxxxxxxxxxxxxxxxxx", true},

		// jwt.io canonical
		{
			"jwt.io canonical example",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			true,
		},

		// Must NOT match — real-looking but synthetic secrets
		{"synthetic AWS key", "AKIAQDIO5JZ8H4PB7M2N", false},
		{"synthetic Stripe live key", "sk_live_4eC39HqLyjWDarjtT1zdp7dc", false},
		{"synthetic GH PAT", "ghp_a3f6Lm9pK2vN1bX4qH8rT5wY7eC0sJ", false},
		{"random UUID", "8b1f3a7c-d4e5-4f6a-9b8c-1d2e3f4a5b6c", false},
		{"random CC-shape", "4532756279624064", false},
		{"random SSN-shape", "456-78-9012", false},
		{"prose with no value", "this is a sentence", false},

		// Edge cases
		{"empty string", "", false},
		{"single char", "a", false},
		{"whitespace only", "   \t\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicExample(tt.value); got != tt.want {
				t.Errorf("IsPublicExample(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNormalizeForBloom(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ABC", "abc"},
		{"4111-1111-1111-1111", "4111111111111111"},
		{"4111 1111 1111 1111", "4111111111111111"},
		{"sk_test_4eC39HqLyjWDarjtT1zdp7dc", "sktest4ec39hqlyjwdarjtt1zdp7dc"},
		{"  trim  me  ", "trimme"},
		{"\t\n\rfoo\t", "foo"},
		{"", ""},
		{"keep/slash", "keep/slash"},
		{"keep.dot", "keep.dot"},
	}
	for _, c := range cases {
		if got := normalizeForBloom(c.in); got != c.want {
			t.Errorf("normalizeForBloom(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func BenchmarkIsPublicExample(b *testing.B) {
	b.Run("hit_known_example", func(b *testing.B) {
		v := "AKIAIOSFODNN7EXAMPLE"
		for i := 0; i < b.N; i++ {
			_ = IsPublicExample(v)
		}
	})
	b.Run("miss_synthetic", func(b *testing.B) {
		v := "AKIAQDIO5JZ8H4PB7M2N"
		for i := 0; i < b.N; i++ {
			_ = IsPublicExample(v)
		}
	})
}
