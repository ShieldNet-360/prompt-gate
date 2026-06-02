//go:build darwin

package sysconf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

// installHelper copies the helper binary and LaunchDaemon plist, then loads
// the daemon — all in a SINGLE admin prompt. After this the helper starts
// immediately and future proxy/DNS toggles require zero prompts.
func installHelper(helperBinSrc string) error {
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
	return runWithAdmin("install Prompt Gate proxy helper", script)
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
