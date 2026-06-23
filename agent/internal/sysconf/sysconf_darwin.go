package sysconf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// listServices returns active macOS network services (skipping the
// header line and disabled services prefixed with "*").
func listServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("sysconf: networksetup -listallnetworkservices: %w", err)
	}
	var svcs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		// Skip header line "An asterisk (*) denotes..."
		if strings.Contains(line, "asterisk") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

// shQuote single-quotes a string for safe embedding in a /bin/sh
// command line. Network service names routinely contain spaces and
// slashes ("Thunderbolt Bridge", "USB 10/100/1000 LAN"); single-quoting
// is the only robust way to pass them through the batched admin script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runWithAdmin executes a /bin/sh script as root through a SINGLE macOS
// authorization prompt. AppleScript's "with administrator privileges"
// shows one password dialog covering the whole script, so callers that
// batch every privileged mutation into one script trigger exactly one
// prompt instead of one per command. This is the fix for the
// "permission prompt on every click" UX bug: previously each
// networksetup / pfctl call was its own elevation moment, so enabling
// the proxy across N network services cost N×2+ prompts.
func runWithAdmin(label, script string) error {
	// Escape for embedding inside an AppleScript double-quoted literal.
	esc := strings.ReplaceAll(script, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	apple := fmt.Sprintf(`do shell script "%s" with administrator privileges`, esc)
	if out, err := exec.Command("osascript", "-e", apple).CombinedOutput(); err != nil {
		return fmt.Errorf("sysconf: %s (admin): %s (%w)", label, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func applyProxy(host string, port int) error {
	return applyProxyWithCA(host, port, "")
}

// applyProxyWithCA enables the system proxy. When the privileged helper
// daemon is running it sends the command over the Unix socket (zero prompts).
// Otherwise it falls back to the osascript admin-batch path (one prompt).
func applyProxyWithCA(host string, port int, caPath string) error {
	if helperAvailable() {
		// Always use APPLY_PROXY (without CA). CA trust is handled
		// separately by installCA() → login keychain + user trust domain.
		return helperCmd(fmt.Sprintf("APPLY_PROXY %s %d", host, port))
	}
	// Osascript fallback: batch CA trust + proxy + QUIC block into one prompt.
	svcs, err := listServices()
	if err != nil {
		return err
	}
	var cmds []string
	// CA trust is handled separately by installCA() — do not duplicate here.
	h := shQuote(host)
	for _, svc := range svcs {
		q := shQuote(svc)
		cmds = append(cmds,
			fmt.Sprintf("/usr/sbin/networksetup -setsecurewebproxy %s %s %d", q, h, port),
			fmt.Sprintf("/usr/sbin/networksetup -setwebproxy %s %s %d", q, h, port),
		)
	}
	cmds = append(cmds,
		fmt.Sprintf("/bin/echo 'block drop quick proto udp from any to any port 443' > %s", shQuote(pfRulesFile)),
		fmt.Sprintf("/sbin/pfctl -a %s -f %s", shQuote(pfAnchor), shQuote(pfRulesFile)),
		"/sbin/pfctl -e 2>/dev/null || true",
	)
	return runWithAdmin("enable proxy", strings.Join(cmds, " && "))
}

// caTrusted reports whether our CA is present in any keychain.
// Checks login keychain first (where installCA puts it), then system.
func caTrusted(_ string) bool {
	if exec.Command("security", "find-certificate", "-c", caCommonName, loginKeychain()).Run() == nil {
		return true
	}
	return exec.Command("security", "find-certificate", "-c", caCommonName, systemKeychain).Run() == nil
}

func restoreProxy() error {
	if helperAvailable() {
		return helperCmd("REMOVE_PROXY")
	}
	svcs, err := listServices()
	if err != nil {
		return err
	}
	var cmds []string
	for _, svc := range svcs {
		q := shQuote(svc)
		cmds = append(cmds,
			fmt.Sprintf("/usr/sbin/networksetup -setsecurewebproxystate %s off", q),
			fmt.Sprintf("/usr/sbin/networksetup -setwebproxystate %s off", q),
		)
	}
	cmds = append(cmds,
		fmt.Sprintf("/sbin/pfctl -a %s -F all 2>/dev/null || true", shQuote(pfAnchor)),
		fmt.Sprintf("/bin/rm -f %s", shQuote(pfRulesFile)),
	)
	return runWithAdmin("disable proxy", strings.Join(cmds, " && "))
}

func applyDNS(dnsIP string) error {
	if helperAvailable() {
		return helperCmd("APPLY_DNS " + dnsIP)
	}
	svcs, err := listServices()
	if err != nil {
		return err
	}
	ip := shQuote(dnsIP)
	var cmds []string
	for _, svc := range svcs {
		cmds = append(cmds, fmt.Sprintf("/usr/sbin/networksetup -setdnsservers %s %s", shQuote(svc), ip))
	}
	return runWithAdmin("apply DNS", strings.Join(cmds, " && "))
}

func restoreDNS() error {
	if helperAvailable() {
		return helperCmd("REMOVE_DNS")
	}
	svcs, err := listServices()
	if err != nil {
		return err
	}
	var cmds []string
	for _, svc := range svcs {
		cmds = append(cmds, fmt.Sprintf("/usr/sbin/networksetup -setdnsservers %s Empty", shQuote(svc)))
	}
	return runWithAdmin("restore DNS", strings.Join(cmds, " && "))
}

const (
	systemKeychain = "/Library/Keychains/System.keychain"
	caCommonName   = "Prompt Gate Local CA"
	pfAnchor       = "com.prompt-gate"
	pfRulesFile    = "/tmp/prompt-gate-pf.conf"
)

// loginKeychain returns the path to the current user's login keychain.
func loginKeychain() string {
	if home := os.Getenv("HOME"); home != "" {
		return home + "/Library/Keychains/login.keychain-db"
	}
	// Last resort — shell expansion won't work, but try anyway.
	return "~/Library/Keychains/login.keychain-db"
}

func installCA(caPath string) error {
	// Prefer the privileged helper: it trusts the CA in the SYSTEM
	// keychain as root over the Unix socket — zero password prompts.
	// This is the common case once the helper is installed, and it
	// removes the login-keychain trust dialog that would otherwise be a
	// second prompt on top of the one-time helper install. Fall back to
	// the login-keychain path below only when no helper is present.
	if helperAvailable() {
		if err := helperCmd("TRUST_CA " + caPath); err == nil {
			return nil
		}
		// Helper failed (stale socket, race) — fall through to the
		// user-domain login-keychain trust so the install still works.
	}

	kc := loginKeychain()

	// 1. Clean up old duplicates from the login keychain (no prompt).
	for {
		if exec.Command("security", "find-certificate", "-c", caCommonName, kc).Run() != nil {
			break
		}
		if exec.Command("security", "delete-certificate", "-c", caCommonName, kc).Run() != nil {
			break
		}
	}
	// NOTE: we intentionally do NOT clean the system keychain here.
	// That would require runWithAdmin (one admin prompt) + the trust
	// dialog below = two prompts. User-domain trust in the login
	// keychain takes precedence over system keychain entries, so any
	// stale system cert is harmless. System keychain cleanup happens
	// in removeCA instead (single prompt there too).

	// 2. Add cert to the LOGIN keychain with user-domain trust.
	//    This shows exactly ONE macOS trust-settings dialog — the user
	//    enters their login password and that's it. No osascript admin
	//    prompt. We avoid the system keychain + admin-domain (-d)
	//    approach because `security add-trusted-cert -d` triggers
	//    SecTrustSettingsSetTrustSettings which is blocked under
	//    hardened runtime ("no user interaction was possible").
	out, err := exec.Command("security", "add-trusted-cert",
		"-r", "trustRoot", "-p", "ssl",
		"-k", kc, caPath,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysconf: install CA (login keychain): %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// 3. Verify the trust was actually applied.
	if err := exec.Command("security", "verify-cert", "-c", caPath, "-p", "ssl").Run(); err != nil {
		// Clean up the untrusted cert.
		_ = exec.Command("security", "delete-certificate", "-c", caCommonName, kc).Run()
		return fmt.Errorf("sysconf: CA installed but not trusted (verify-cert failed)")
	}
	return nil
}

func removeCA(caPath string) error {
	// Prefer the privileged helper: it removes the system-keychain trust
	// as root over the socket (zero prompts), matching the install path.
	// We still scrub the login keychain below (no admin needed) in case a
	// prior version trusted the CA there.
	if helperAvailable() {
		_ = helperCmd("REMOVE_CA " + caPath)
	}

	kc := loginKeychain()

	// Clean login keychain (no admin needed).
	for {
		if exec.Command("security", "find-certificate", "-c", caCommonName, kc).Run() != nil {
			break
		}
		if exec.Command("security", "delete-certificate", "-c", caCommonName, kc).Run() != nil {
			break
		}
	}

	// Clean system keychain — needs admin privileges.
	if exec.Command("security", "find-certificate", "-c", caCommonName, systemKeychain).Run() == nil {
		_ = runWithAdmin("remove CA", fmt.Sprintf(
			`/usr/bin/security remove-trusted-cert -d %s 2>/dev/null; `+
				`/usr/bin/security remove-trusted-cert %s 2>/dev/null; `+
				`while /usr/bin/security find-certificate -c %s %s >/dev/null 2>&1; do `+
				`/usr/bin/security delete-certificate -c %s %s || break; done`,
			shQuote(caPath),
			shQuote(caPath),
			shQuote(caCommonName), shQuote(systemKeychain),
			shQuote(caCommonName), shQuote(systemKeychain),
		))
	}

	// Verify the cert is actually gone from both keychains.
	if exec.Command("security", "find-certificate", "-c", caCommonName, systemKeychain).Run() == nil {
		return fmt.Errorf("sysconf: CA certificate still present in system keychain after removal")
	}
	if exec.Command("security", "find-certificate", "-c", caCommonName, kc).Run() == nil {
		return fmt.Errorf("sysconf: CA certificate still present in login keychain after removal")
	}
	return nil
}
