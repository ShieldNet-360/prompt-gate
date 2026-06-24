package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func captureHook(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	stdout = &buf
	stderr = &buf
	t.Cleanup(func() { stdout, stderr = os.Stdout, os.Stderr })
	return &buf
}

func TestGitHookInstallStatusUninstall(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "pre-commit")
	buf := captureHook(t)

	if code := cmdGitHook([]string{"install", "--hooks-dir", dir}); code != 0 {
		t.Fatalf("install exit = %d (%s)", code, buf.String())
	}
	info, err := os.Stat(hook)
	if err != nil {
		t.Fatalf("hook not written: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("hook not executable: %v", info.Mode())
	}
	body, _ := os.ReadFile(hook)
	if !bytes.Contains(body, []byte(hookSentinel)) {
		t.Error("hook missing sentinel")
	}

	buf.Reset()
	if code := cmdGitHook([]string{"status", "--hooks-dir", dir}); code != 0 || !bytes.Contains(buf.Bytes(), []byte("installed")) {
		t.Errorf("status = %d (%s)", code, buf.String())
	}

	buf.Reset()
	if code := cmdGitHook([]string{"uninstall", "--hooks-dir", dir}); code != 0 {
		t.Fatalf("uninstall exit = %d (%s)", code, buf.String())
	}
	if _, err := os.Stat(hook); !os.IsNotExist(err) {
		t.Error("hook still present after uninstall")
	}
}

func TestGitHookProtectsForeignHook(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "pre-commit")
	foreign := "#!/bin/sh\necho my own hook\n"
	if err := os.WriteFile(hook, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	buf := captureHook(t)

	// install without --force must refuse and leave the file intact.
	if code := cmdGitHook([]string{"install", "--hooks-dir", dir}); code != 1 {
		t.Fatalf("install over foreign hook exit = %d, want 1", code)
	}
	if b, _ := os.ReadFile(hook); string(b) != foreign {
		t.Error("foreign hook was modified without --force")
	}

	// uninstall must refuse to remove a foreign hook.
	buf.Reset()
	if code := cmdGitHook([]string{"uninstall", "--hooks-dir", dir}); code != 1 {
		t.Fatalf("uninstall foreign hook exit = %d, want 1", code)
	}
	if _, err := os.Stat(hook); err != nil {
		t.Error("foreign hook was removed")
	}

	// install --force overwrites it.
	buf.Reset()
	if code := cmdGitHook([]string{"install", "--hooks-dir", dir, "--force"}); code != 0 {
		t.Fatalf("install --force exit = %d (%s)", code, buf.String())
	}
	if b, _ := os.ReadFile(hook); !bytes.Contains(b, []byte(hookSentinel)) {
		t.Error("--force did not install prompt-gate hook")
	}
}
