//go:build darwin

package sysconf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// helperInstallMu serializes helper installation so the agent's
// install-on-first-use path and the tray's explicit InstallHelper call
// can't both fire the (single) admin prompt at once.
var helperInstallMu sync.Mutex

const (
	helperSocket      = "/var/run/prompt-gate-proxy.sock"
	helperInstallPath = "/Library/PrivilegedHelperTools/com.shieldnet360.promptgate.proxy-helper"
	helperPlistDst    = "/Library/LaunchDaemons/com.shieldnet360.promptgate.proxy-helper.plist"
	helperBinName     = "prompt-gate-proxy-helper"
)

// helperAvailable returns true when the privileged helper is running and
// responsive. Uses a short timeout so it never blocks a toggle.
func helperAvailable() bool {
	conn, err := net.DialTimeout("unix", helperSocket, 150*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
	fmt.Fprintln(conn, "PING")
	resp, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(resp) == "OK"
}

// helperCmd sends cmd to the privileged helper and returns an error when the
// response does not start with "OK". 15-second deadline covers slow pfctl.
func helperCmd(cmd string) error {
	conn, err := net.DialTimeout("unix", helperSocket, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("sysconf helper: dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintln(conn, cmd)
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("sysconf helper: read: %w", err)
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("sysconf helper: %s", strings.TrimSpace(strings.TrimPrefix(resp, "ERR")))
	}
	return nil
}

// helperInstalled reports whether the helper binary and plist are present.
func helperInstalled() bool {
	_, err1 := os.Stat(helperInstallPath)
	_, err2 := os.Stat(helperPlistDst)
	return err1 == nil && err2 == nil
}

// helperRunning delegates to helperAvailable.
func helperRunning() bool { return helperAvailable() }

// waitForHelper polls until the helper answers PING or the deadline
// passes. Used right after an install (launchctl load takes ~1s to bring
// the daemon up) so the very next privileged call goes over the socket
// instead of racing to a second password prompt.
func waitForHelper(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if helperAvailable() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ensureHelperReady guarantees the privileged helper is up before a
// privileged operation, installing it on first use. This is what makes a
// fresh install cost ONE password prompt instead of three: the first
// privileged action (CA trust or proxy enable) installs the helper (one
// prompt) and every subsequent action — CA trust, proxy, DNS — flows over
// the socket with zero prompts, regardless of the order the tray drives
// them in. Returns false (caller falls back to its own osascript path)
// only when the helper binary can't be found or install/startup fails, so
// non-helper layouts are never blocked.
func ensureHelperReady() bool {
	if helperAvailable() {
		return true
	}
	helperInstallMu.Lock()
	defer helperInstallMu.Unlock()
	// Re-check under the lock: a concurrent caller (or the tray's
	// InstallHelper) may have brought it up while we waited.
	if helperAvailable() {
		return true
	}
	if !helperInstalled() {
		bin, err := findHelperBin()
		if err != nil {
			return false // can't install — caller uses the osascript fallback
		}
		// We already hold helperInstallMu, so call the locked worker
		// directly (installHelper would re-lock and deadlock).
		if err := installHelperLocked(bin); err != nil {
			return false
		}
	}
	return waitForHelper(5 * time.Second)
}

// findHelperBin locates the proxy-helper binary next to the current
// executable (production bundle) or in common dev build paths.
func findHelperBin() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(self)
	candidates := []string{
		filepath.Join(dir, helperBinName),
		filepath.Join(dir, "..", "bin", helperBinName),
		filepath.Join(dir, "..", "..", "bin", helperBinName),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("sysconf: %s not found near %s", helperBinName, self)
}

// helperPlistXML is the LaunchDaemon plist for the privileged helper.
const helperPlistXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.shieldnet360.promptgate.proxy-helper</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Library/PrivilegedHelperTools/com.shieldnet360.promptgate.proxy-helper</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/var/log/prompt-gate-proxy-helper.log</string>
</dict>
</plist>
`

// installHelper installs the privileged helper through ONE admin prompt,
// serialized and idempotent: if the helper is already up it returns
// without prompting, and the mutex prevents the tray's explicit install
// and the agent's install-on-first-use (ensureHelperReady) from both
// firing the prompt. This is the entry point used by the public
// InstallHelper / the API; ensureHelperReady (already holding the lock)
// calls installHelperLocked directly.
func installHelper(helperBinSrc string) error {
	helperInstallMu.Lock()
	defer helperInstallMu.Unlock()
	if helperAvailable() {
		return nil // already running — don't prompt again
	}
	return installHelperLocked(helperBinSrc)
}

// installHelperLocked does the actual copy + plist + launchctl load in a
// single admin prompt. The caller MUST hold helperInstallMu. After this
// the helper starts within ~1s and future proxy/DNS/CA ops need no prompt.
func installHelperLocked(helperBinSrc string) error {
	tmp, err := os.CreateTemp("", "com.shieldnet360.promptgate.proxy-helper.*.plist")
	if err != nil {
		return fmt.Errorf("sysconf: write plist tmp: %w", err)
	}
	if _, err := tmp.WriteString(helperPlistXML); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	script := strings.Join([]string{
		"/bin/mkdir -p /Library/PrivilegedHelperTools",
		fmt.Sprintf("/bin/cp %s %s", shQuote(helperBinSrc), shQuote(helperInstallPath)),
		fmt.Sprintf("/bin/chmod 755 %s", shQuote(helperInstallPath)),
		fmt.Sprintf("/bin/cp %s %s", shQuote(tmp.Name()), shQuote(helperPlistDst)),
		fmt.Sprintf("/bin/chmod 644 %s", shQuote(helperPlistDst)),
		fmt.Sprintf("/bin/launchctl load -w %s", shQuote(helperPlistDst)),
	}, " && ")
	return runWithAdmin("set up its network helper (this is asked only once)", script)
}

// uninstallHelper stops and removes the helper daemon. Exported for future
// uninstaller / Settings UI use.
func uninstallHelper() error {
	script := strings.Join([]string{
		fmt.Sprintf("/bin/launchctl unload -w %s 2>/dev/null || true", shQuote(helperPlistDst)),
		fmt.Sprintf("/bin/rm -f %s %s", shQuote(helperInstallPath), shQuote(helperPlistDst)),
	}, " && ")
	return runWithAdmin("uninstall Prompt Gate proxy helper", script)
}
