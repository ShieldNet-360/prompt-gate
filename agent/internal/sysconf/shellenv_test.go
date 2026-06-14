//go:build !windows

package sysconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureHookCreatesFile(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	if err := ensureHook(rc, zshHook); err != nil {
		t.Fatalf("ensureHook: %v", err)
	}
	data, err := os.ReadFile(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), hookBeginMarker) {
		t.Fatal("hook begin marker not found")
	}
	if !strings.Contains(string(data), hookEndMarker) {
		t.Fatal("hook end marker not found")
	}
	if !strings.Contains(string(data), "_prompt_gate_proxy_hook") {
		t.Fatal("hook function not found")
	}
}

func TestEnsureHookIdempotent(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	_ = os.WriteFile(rc, []byte("# existing content\n"), 0o644)

	if err := ensureHook(rc, zshHook); err != nil {
		t.Fatalf("first ensureHook: %v", err)
	}
	first, _ := os.ReadFile(rc)

	if err := ensureHook(rc, zshHook); err != nil {
		t.Fatalf("second ensureHook: %v", err)
	}
	second, _ := os.ReadFile(rc)

	if string(first) != string(second) {
		t.Fatal("ensureHook is not idempotent")
	}
}

func TestEnsureHookPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".bashrc")
	existing := "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\n"
	_ = os.WriteFile(rc, []byte(existing), 0o644)

	if err := ensureHook(rc, bashHook); err != nil {
		t.Fatalf("ensureHook: %v", err)
	}
	data, _ := os.ReadFile(rc)
	if !strings.HasPrefix(string(data), existing) {
		t.Fatal("existing content was not preserved")
	}
}

func TestStripHook(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	existing := "# my config\nexport FOO=bar\n"
	_ = os.WriteFile(rc, []byte(existing), 0o644)

	_ = ensureHook(rc, zshHook)
	data, _ := os.ReadFile(rc)
	if !strings.Contains(string(data), hookBeginMarker) {
		t.Fatal("hook not added")
	}

	if err := stripHook(rc); err != nil {
		t.Fatalf("stripHook: %v", err)
	}
	data, _ = os.ReadFile(rc)
	if strings.Contains(string(data), hookBeginMarker) {
		t.Fatal("hook not removed")
	}
	if !strings.Contains(string(data), "export FOO=bar") {
		t.Fatal("existing content was lost")
	}
}

func TestStripHookMissingFile(t *testing.T) {
	if err := stripHook("/nonexistent/path/.zshrc"); err != nil {
		t.Fatalf("stripHook on missing file should not error: %v", err)
	}
}

func TestProxyFlagFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	// Override HOME so flag file goes into our temp dir.
	orig := os.Getenv("HOME")
	t.Setenv("HOME", dir)
	defer func() { _ = os.Setenv("HOME", orig) }()

	proxyURL := "http://127.0.0.1:9080"

	if err := ApplyShellProxy(proxyURL); err != nil {
		t.Fatalf("ApplyShellProxy: %v", err)
	}
	// Flag file should exist with the URL.
	flagData, err := os.ReadFile(filepath.Join(dir, proxyFlagDir, proxyFlagFile))
	if err != nil {
		t.Fatalf("read flag file: %v", err)
	}
	if got := strings.TrimSpace(string(flagData)); got != proxyURL {
		t.Fatalf("flag file = %q, want %q", got, proxyURL)
	}
	// RC files should have hooks.
	for _, rc := range []string{".zshrc", ".bashrc"} {
		data, err := os.ReadFile(filepath.Join(dir, rc))
		if err != nil {
			t.Fatalf("read %s: %v", rc, err)
		}
		if !strings.Contains(string(data), hookBeginMarker) {
			t.Fatalf("%s missing hook", rc)
		}
	}

	// Remove proxy — flag file deleted, hooks remain.
	if err := RemoveShellProxy(); err != nil {
		t.Fatalf("RemoveShellProxy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, proxyFlagDir, proxyFlagFile)); !os.IsNotExist(err) {
		t.Fatal("flag file should be deleted")
	}
	// Hooks should still be in RC files.
	for _, rc := range []string{".zshrc", ".bashrc"} {
		data, _ := os.ReadFile(filepath.Join(dir, rc))
		if !strings.Contains(string(data), hookBeginMarker) {
			t.Fatalf("%s hook was removed prematurely", rc)
		}
	}

	// Full uninstall — remove hooks too.
	if err := RemoveShellHook(); err != nil {
		t.Fatalf("RemoveShellHook: %v", err)
	}
	for _, rc := range []string{".zshrc", ".bashrc"} {
		data, _ := os.ReadFile(filepath.Join(dir, rc))
		if strings.Contains(string(data), hookBeginMarker) {
			t.Fatalf("%s hook was not removed", rc)
		}
	}
}

func TestReplaceHookUpdatesContent(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")

	oldHook := hookBeginMarker + "\n# old version\n" + hookEndMarker
	_ = os.WriteFile(rc, []byte("# config\n"+oldHook+"\n# after\n"), 0o644)

	if err := ensureHook(rc, zshHook); err != nil {
		t.Fatalf("ensureHook: %v", err)
	}
	data, _ := os.ReadFile(rc)
	content := string(data)
	if strings.Contains(content, "# old version") {
		t.Fatal("old hook body was not replaced")
	}
	if !strings.Contains(content, "_prompt_gate_proxy_hook") {
		t.Fatal("new hook body not present")
	}
	if !strings.Contains(content, "# config") {
		t.Fatal("content before hook was lost")
	}
	if !strings.Contains(content, "# after") {
		t.Fatal("content after hook was lost")
	}
}
