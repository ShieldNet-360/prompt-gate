package sysconf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPatchFirefoxProfiles(t *testing.T) {
	// Create a temporary directory to act as the base directory
	tempDir := t.TempDir()

	// Override environment variables so PatchFirefoxProfiles uses tempDir
	var profileDir string
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", tempDir)
		profileDir = filepath.Join(tempDir, "Library", "Application Support", "Firefox", "Profiles", "test.default")
	case "windows":
		t.Setenv("APPDATA", tempDir)
		profileDir = filepath.Join(tempDir, "Mozilla", "Firefox", "Profiles", "test.default")
	case "linux":
		t.Setenv("HOME", tempDir)
		profileDir = filepath.Join(tempDir, ".mozilla", "firefox", "test.default")
	default:
		t.Skipf("Unsupported OS: %s", runtime.GOOS)
	}

	// Create the mock profile directory
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		t.Fatalf("failed to create mock profile dir: %v", err)
	}

	// Create a dummy prefs.js so the profile is recognized
	prefsPath := filepath.Join(profileDir, "prefs.js")
	if err := os.WriteFile(prefsPath, []byte("// fake prefs\n"), 0644); err != nil {
		t.Fatalf("failed to write prefs.js: %v", err)
	}

	// Run the patcher
	if err := PatchFirefoxProfiles(); err != nil {
		t.Fatalf("PatchFirefoxProfiles failed: %v", err)
	}

	// Verify user.js was created and contains the setting
	userJsPath := filepath.Join(profileDir, "user.js")
	content, err := os.ReadFile(userJsPath)
	if err != nil {
		t.Fatalf("failed to read user.js: %v", err)
	}

	expectedLines := []string{
		`user_pref("security.enterprise_roots.enabled", true);`,
		`user_pref("network.proxy.type", 5);`,
	}
	for _, expectedLine := range expectedLines {
		if !strings.Contains(string(content), expectedLine) {
			t.Errorf("user.js does not contain expected pref. got:\n%s", string(content))
		}
	}

	// Run patcher again to test idempotency
	if err := PatchFirefoxProfiles(); err != nil {
		t.Fatalf("PatchFirefoxProfiles failed on second run: %v", err)
	}

	// Verify the file didn't double append
	content2, err := os.ReadFile(userJsPath)
	if err != nil {
		t.Fatalf("failed to read user.js second time: %v", err)
	}

	if len(content2) != len(content) {
		t.Errorf("user.js length changed after second run! expected %d, got %d", len(content), len(content2))
	}
}
