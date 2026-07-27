package sysconf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PatchFirefoxProfiles finds all Firefox profiles on the system and injects
// the setting to trust enterprise root certificates (OS trust store). This
// ensures Firefox correctly accepts the local MITM proxy without manual setup.
func PatchFirefoxProfiles() error {
	var baseDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		baseDir = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			return fmt.Errorf("APPDATA environment variable not found")
		}
		baseDir = filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
	case "linux":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		baseDir = filepath.Join(home, ".mozilla", "firefox")
	default:
		return fmt.Errorf("unsupported OS for Firefox patching: %s", runtime.GOOS)
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Firefox is likely not installed, which is fine.
			return nil
		}
		return fmt.Errorf("failed to read Firefox profiles dir: %w", err)
	}

	patchCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profileDir := filepath.Join(baseDir, entry.Name())
		prefsPath := filepath.Join(profileDir, "prefs.js")

		// A valid profile will typically have a prefs.js file.
		if _, err := os.Stat(prefsPath); os.IsNotExist(err) {
			continue
		}

		userJsPath := filepath.Join(profileDir, "user.js")
		if err := patchUserJs(userJsPath); err != nil {
			return fmt.Errorf("failed to patch %s: %w", userJsPath, err)
		}
		patchCount++
	}

	return nil
}

func patchUserJs(userJsPath string) error {
	prefsToEnsure := map[string]string{
		`"security.enterprise_roots.enabled"`: `true`,
		`"network.proxy.type"`:                `5`,
	}

	// Read existing file to see which prefs are already set
	file, err := os.Open(userJsPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			for pref, val := range prefsToEnsure {
				if strings.Contains(line, pref) && strings.Contains(line, val) {
					delete(prefsToEnsure, pref) // Already correctly set
				}
			}
		}
		file.Close()
	} else if !os.IsNotExist(err) {
		return err // Some other read error.
	}

	if len(prefsToEnsure) == 0 {
		return nil // All required settings are already present
	}

	// Append missing settings to the user.js file
	f, err := os.OpenFile(userJsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for pref, val := range prefsToEnsure {
		prefLine := fmt.Sprintf(`user_pref(%s, %s);`, pref, val)
		if _, err := f.WriteString(fmt.Sprintf("\n%s\n", prefLine)); err != nil {
			return err
		}
	}

	return nil
}
