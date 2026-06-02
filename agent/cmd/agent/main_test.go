package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIsNativeMessagingArgv(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, false},
		{"no extension origin", []string{"--config", "config.yaml"}, false},
		{"chrome extension origin", []string{"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"}, true},
		{"firefox extension origin", []string{"moz-extension://01234567-89ab-cdef-0123-456789abcdef/"}, true},
		{"firefox windows extra arg", []string{"moz-extension://01234567-89ab-cdef-0123-456789abcdef/", "prompt-gate@example.com"}, true},
		{"unrelated url", []string{"https://example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNativeMessagingArgv(tc.args); got != tc.want {
				t.Errorf("isNativeMessagingArgv(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestValidateRulesAlignment(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()

	t.Run("everything inside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "ai_chat_blocked.txt"), filepath.Join(dir, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"),
			filepath.Join(dir, "dlp_exclusions.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rule_paths outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(other, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "rule_paths entry") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("dlp_patterns outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir, nil,
			filepath.Join(other, "dlp_patterns.json"), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "dlp_patterns") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("dlp_exclusions outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir, nil,
			filepath.Join(dir, "dlp_patterns.json"),
			filepath.Join(other, "dlp_exclusions.json"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "dlp_exclusions") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("blank optional dlp paths are allowed", func(t *testing.T) {
		if err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "phishing.txt")}, "", ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("trailing slash on rules_dir is normalised", func(t *testing.T) {
		if err := validateRulesAlignment(dir+string(filepath.Separator),
			[]string{filepath.Join(dir, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"), ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("subdirectory of rules_dir is rejected", func(t *testing.T) {
		// rule files must be direct children: rulesDir/foo.txt, not
		// rulesDir/sub/foo.txt — the updater downloads to the former
		// only.
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "sub", "phishing.txt")}, "", "")
		if err == nil {
			t.Fatal("expected error for nested file, got nil")
		}
	})
}

func TestCategoryFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"rules/ai_chat_blocked.txt", "AI Chat Blocked"},
		{"rules/ai_code_blocked.txt", "AI Code Blocked"},
		{"rules/ai_allowed.txt", "AI Allowed"},
		{"rules/ai_chat_dlp.txt", "AI Chat DLP"},
		{"rules/phishing.txt", "Phishing"},
		{"rules/social.txt", "Social"},
		{"rules\\ai_allowed.txt", "AI Allowed"},
		{"ai-chat-dlp.txt", "AI Chat DLP"},
		{"AI_Chat_DLP.txt", "AI Chat DLP"},
		{"plain", "Plain"},
	}
	for _, tc := range cases {
		got := categoryFromPath(tc.path)
		if got != tc.want {
			t.Errorf("categoryFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
