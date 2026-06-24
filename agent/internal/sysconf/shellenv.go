// Shell environment proxy integration for CLI/terminal tools.
//
// When the proxy is enabled, CLI tools (curl, git, npm, pip, docker,
// etc.) need http_proxy / https_proxy set in their environment. GUI
// apps use the OS system-proxy settings (networksetup on macOS,
// gsettings on Linux, registry on Windows), but terminal sessions
// only read env vars.
//
// Strategy:
//
//  1. Flag file  (~/.config/prompt-gate/proxy-env)
//     Contains the proxy URL when active; absent when inactive.
//
//  2. Shell hooks (platform-specific)
//     Unix:    precmd (zsh) / PROMPT_COMMAND (bash) hook in RC files
//              reads the flag file before every command — already-open
//              terminals pick up changes on their next prompt.
//     Windows: setx sets persistent user env vars for new CMD/PS
//              windows; a PowerShell $PROFILE prompt hook covers
//              already-open PowerShell sessions. Already-open CMD
//              windows cannot be updated (Windows limitation).
//
// ApplyShellProxy  writes the flag file + ensures hooks are present.
// RemoveShellProxy deletes the flag file (hooks auto-unset vars).
// RemoveShellHook  removes hook blocks from RC/profile files entirely.
package sysconf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	proxyFlagDir  = ".config/prompt-gate"
	proxyFlagFile = "proxy-env"
	proxyCAFile   = "proxy-ca"

	hookBeginMarker = "# >>> prompt-gate proxy hook >>>"
	hookEndMarker   = "# <<< prompt-gate proxy hook <<<"
)

// proxyFlagPath returns ~/.config/prompt-gate/proxy-env.
func proxyFlagPath() string {
	return filepath.Join(homeDir(), proxyFlagDir, proxyFlagFile)
}

// proxyCAPath returns ~/.config/prompt-gate/proxy-ca — the file
// holding the MITM CA bundle path. CLI TLS stacks that ignore the OS
// keychain (Node/claude, Python, Go, curl-openssl) need this exported
// as NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE, or they
// reach the proxy and then fail the handshake on the untrusted cert.
func proxyCAPath() string {
	return filepath.Join(homeDir(), proxyFlagDir, proxyCAFile)
}

// homeDir returns $HOME (Unix) or %USERPROFILE% (Windows).
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	return "~"
}

// ApplyShellProxy writes the proxy-URL flag file (and, when caPath is
// non-empty, the CA-bundle flag file so CLI TLS stacks trust the MITM
// cert) and configures platform-specific shell hooks. A blank caPath
// clears any stale CA flag so the hooks stop exporting the CA vars.
func ApplyShellProxy(proxyURL, caPath string) error {
	flagPath := proxyFlagPath()
	if err := os.MkdirAll(filepath.Dir(flagPath), 0o755); err != nil {
		return fmt.Errorf("sysconf: create proxy flag dir: %w", err)
	}
	if err := os.WriteFile(flagPath, []byte(proxyURL+"\n"), 0o644); err != nil {
		return fmt.Errorf("sysconf: write proxy flag: %w", err)
	}
	if caPath != "" {
		if err := os.WriteFile(proxyCAPath(), []byte(caPath+"\n"), 0o644); err != nil {
			return fmt.Errorf("sysconf: write CA flag: %w", err)
		}
	} else if err := os.Remove(proxyCAPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sysconf: clear CA flag: %w", err)
	}
	return applyShellHooks(proxyURL)
}

// RemoveShellProxy deletes the flag files and performs any
// platform-specific cleanup (e.g. unsetting persistent env vars on
// Windows). Shell hooks remain but become no-ops.
func RemoveShellProxy() error {
	if err := os.Remove(proxyFlagPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sysconf: remove proxy flag: %w", err)
	}
	if err := os.Remove(proxyCAPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sysconf: remove CA flag: %w", err)
	}
	return removeShellEnvVars()
}

// RemoveShellHook removes all hook blocks from shell RC/profile
// files and deletes the flag files. Call this on full uninstall.
func RemoveShellHook() error {
	_ = os.Remove(proxyFlagPath())
	_ = os.Remove(proxyCAPath())
	return removeAllShellHooks()
}

// rcPath returns $HOME/<name> (or %USERPROFILE%\<name> on Windows).
func rcPath(name string) string {
	return filepath.Join(homeDir(), name)
}

// ensureHook appends the hook block to path if not already present.
// Creates the file if it does not exist.
func ensureHook(path, hook string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	if strings.Contains(content, hookBeginMarker) {
		// Already present — replace in case the hook body changed.
		return replaceHook(path, content, hook)
	}
	// Append with a blank separator line.
	sep := "\n"
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		sep = "\n\n"
	} else if len(content) > 0 {
		sep = "\n"
	}
	return os.WriteFile(path, []byte(content+sep+hook+"\n"), 0o644)
}

// replaceHook replaces an existing hook block in content.
func replaceHook(path, content, hook string) error {
	start := strings.Index(content, hookBeginMarker)
	end := strings.Index(content, hookEndMarker)
	if start < 0 || end < 0 || end <= start {
		// Markers are corrupted; append fresh.
		return os.WriteFile(path, []byte(content+"\n"+hook+"\n"), 0o644)
	}
	end += len(hookEndMarker)
	// Consume the trailing newline if present.
	if end < len(content) && content[end] == '\n' {
		end++
	}
	updated := content[:start] + hook + "\n" + content[end:]
	return os.WriteFile(path, []byte(updated), 0o644)
}

// stripHook removes the hook block from path.
func stripHook(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	start := strings.Index(content, hookBeginMarker)
	end := strings.Index(content, hookEndMarker)
	if start < 0 || end < 0 {
		return nil // not present
	}
	end += len(hookEndMarker)
	if end < len(content) && content[end] == '\n' {
		end++
	}
	// Also remove one blank line before the block if present.
	if start > 0 && content[start-1] == '\n' {
		start--
	}
	updated := content[:start] + content[end:]
	return os.WriteFile(path, []byte(updated), 0o644)
}
