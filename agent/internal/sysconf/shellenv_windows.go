//go:build windows

package sysconf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// envVarNames are the proxy environment variable names managed by
// setx (persistent user env vars for CMD and new PS windows).
var envVarNames = []string{
	"http_proxy", "https_proxy",
	"HTTP_PROXY", "HTTPS_PROXY",
	"no_proxy", "NO_PROXY",
}

// psHook is injected into the PowerShell $PROFILE. It wraps the
// prompt function so the flag file is checked before every command —
// already-open PowerShell sessions pick up changes immediately.
const psHook = `# >>> prompt-gate proxy hook >>>
# Managed by Prompt Gate — do not edit this block manually.
function _PromptGateProxyCheck {
    $pf = Join-Path $env:USERPROFILE '.config\prompt-gate\proxy-env'
    if (Test-Path $pf) {
        $url = (Get-Content $pf -Raw).Trim()
        if ($url) {
            $env:http_proxy = $url
            $env:https_proxy = $url
            $env:HTTP_PROXY = $url
            $env:HTTPS_PROXY = $url
            $env:no_proxy = 'localhost,127.0.0.1,::1'
            $env:NO_PROXY = $env:no_proxy
            return
        }
    }
    Remove-Item Env:\http_proxy -ErrorAction SilentlyContinue
    Remove-Item Env:\https_proxy -ErrorAction SilentlyContinue
    Remove-Item Env:\HTTP_PROXY -ErrorAction SilentlyContinue
    Remove-Item Env:\HTTPS_PROXY -ErrorAction SilentlyContinue
    Remove-Item Env:\no_proxy -ErrorAction SilentlyContinue
    Remove-Item Env:\NO_PROXY -ErrorAction SilentlyContinue
}
# Run once on profile load.
_PromptGateProxyCheck
# Wrap the prompt function for per-command refresh.
if (-not (Get-Variable _PromptGateOrigPrompt -Scope Global -ErrorAction SilentlyContinue)) {
    $global:_PromptGateOrigPrompt = $function:prompt
    function global:prompt { _PromptGateProxyCheck; & $global:_PromptGateOrigPrompt }
}
# <<< prompt-gate proxy hook <<<`

// applyShellHooks sets persistent user env vars via setx (for new
// CMD windows) and injects a PowerShell profile hook (for already-
// open and new PowerShell sessions).
func applyShellHooks(proxyURL string) error {
	var errs []string

	// 1. setx — persistent user env vars for CMD.
	pairs := map[string]string{
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"no_proxy":    "localhost,127.0.0.1,::1",
		"NO_PROXY":    "localhost,127.0.0.1,::1",
	}
	for k, v := range pairs {
		if err := exec.Command("setx", k, v).Run(); err != nil {
			errs = append(errs, fmt.Sprintf("setx %s: %v", k, err))
		}
	}

	// 2. Broadcast WM_SETTINGCHANGE so Explorer and some terminal
	//    hosts refresh their environment snapshot.
	broadcastEnvChange()

	// 3. PowerShell profile hook — covers already-open PS sessions.
	for _, profile := range psProfilePaths() {
		if err := ensureHook(profile, psHook); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sysconf: shell hook: %s", strings.Join(errs, "; "))
	}
	return nil
}

// removeShellEnvVars deletes persistent user env vars via the
// registry and broadcasts WM_SETTINGCHANGE.
func removeShellEnvVars() error {
	var errs []string
	for _, name := range envVarNames {
		// reg delete is the only reliable way to remove (not just
		// empty) a user env var. Ignore "not found" errors.
		_ = exec.Command("reg", "delete", `HKCU\Environment`,
			"/v", name, "/f").Run()
	}
	broadcastEnvChange()
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: remove env vars: %s", strings.Join(errs, "; "))
	}
	return nil
}

// removeAllShellHooks strips hook blocks from PowerShell profiles
// and deletes persistent env vars.
func removeAllShellHooks() error {
	var errs []string
	for _, profile := range psProfilePaths() {
		if err := stripHook(profile); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := removeShellEnvVars(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: remove hook: %s", strings.Join(errs, "; "))
	}
	return nil
}

// psProfilePaths returns the PowerShell profile paths for both
// PowerShell 7+ and Windows PowerShell 5.1.
func psProfilePaths() []string {
	docs := filepath.Join(homeDir(), "Documents")
	return []string{
		// PowerShell 7+ (pwsh)
		filepath.Join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
		// Windows PowerShell 5.1 (powershell.exe)
		filepath.Join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
	}
}

// broadcastEnvChange sends WM_SETTINGCHANGE so the OS notifies
// running applications that environment variables have changed.
// This helps Explorer, Windows Terminal, and similar apps pick up
// the new values. CMD.exe does NOT respond to this message.
func broadcastEnvChange() {
	_ = exec.Command("powershell", "-NoProfile", "-Command",
		`Add-Type -TypeDefinition '`+
			`using System;using System.Runtime.InteropServices;`+
			`public class PGEnv{`+
			`[DllImport("user32.dll",CharSet=CharSet.Auto)]`+
			`public static extern IntPtr SendMessageTimeout(`+
			`IntPtr h,uint m,UIntPtr w,string l,uint f,uint t,out IntPtr r);`+
			`}';`+
			`$r=[IntPtr]::Zero;`+
			`[PGEnv]::SendMessageTimeout(`+
			`[IntPtr]0xFFFF,0x1A,[UIntPtr]::Zero,"Environment",2,5000,[ref]$r)`,
	).Run()
}

// ensurePSProfileDir creates the directory for the PowerShell
// profile if it doesn't exist. Called implicitly by ensureHook
// since os.WriteFile creates files but not directories.
func init() {
	// Pre-create PS profile directories on first import so
	// ensureHook can write the profile file without errors.
	// This is best-effort; errors are silently ignored.
	for _, p := range psProfilePaths() {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
	}
}
