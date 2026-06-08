package sysconf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func applyProxyWithCA(host string, port int, caPath string) error {
	if caPath != "" && !caTrusted(caPath) {
		if err := installCA(caPath); err != nil {
			return err
		}
	}
	return applyProxy(host, port)
}

// caTrusted reports whether our CA has been copied into the system
// trust anchor directory by a previous installCA call.
func caTrusted(_ string) bool {
	if hasCmd("update-ca-certificates") {
		_, err := os.Stat(debDest)
		return err == nil
	}
	if hasCmd("update-ca-trust") {
		_, err := os.Stat(rhelDest)
		return err == nil
	}
	return false
}

func applyProxy(host string, port int) error {
	var errs []string
	// GNOME / GTK
	if hasCmd("gsettings") {
		for _, args := range [][]string{
			{"set", "org.gnome.system.proxy", "mode", "manual"},
			{"set", "org.gnome.system.proxy.https", "host", host},
			{"set", "org.gnome.system.proxy.https", "port", fmt.Sprintf("%d", port)},
			{"set", "org.gnome.system.proxy.http", "host", host},
			{"set", "org.gnome.system.proxy.http", "port", fmt.Sprintf("%d", port)},
		} {
			if e := exec.Command("gsettings", args...).Run(); e != nil {
				errs = append(errs, fmt.Sprintf("gsettings %v: %v", args, e))
			}
		}
	}
	// KDE
	if bin := kdeWriter(); bin != "" {
		for _, args := range [][]string{
			{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", fmt.Sprintf("http://%s:%d", host, port)},
			{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", fmt.Sprintf("http://%s:%d", host, port)},
			{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"},
		} {
			if e := exec.Command(bin, args...).Run(); e != nil {
				errs = append(errs, fmt.Sprintf("%s %v: %v", bin, args, e))
			}
		}
	}
	// /etc/profile.d
	content := fmt.Sprintf(
		"# Managed by Prompt Gate\nexport HTTP_PROXY=http://%s:%d\nexport HTTPS_PROXY=http://%s:%d\nexport http_proxy=http://%s:%d\nexport https_proxy=http://%s:%d\nexport NO_PROXY=localhost,127.0.0.1,::1\nexport no_proxy=localhost,127.0.0.1,::1\n",
		host, port, host, port, host, port, host, port,
	)
	// /etc/profile.d requires root — use pkexec. Non-fatal if it fails
	// because gsettings is the primary mechanism for GUI apps.
	if tmpf, e := os.CreateTemp("", "prompt-gate-proxy-*.sh"); e == nil {
		_, _ = tmpf.WriteString(content)
		tmpf.Close()
		if out, e2 := elevate("cp", tmpf.Name(), "/etc/profile.d/prompt-gate-proxy.sh"); e2 != nil {
			errs = append(errs, fmt.Sprintf("profile.d: %s (%v)", strings.TrimSpace(string(out)), e2))
		}
		_ = os.Remove(tmpf.Name())
	}
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: proxy apply partial failures: %s", strings.Join(errs, "; "))
	}
	return nil
}

func restoreProxy() error {
	var errs []string
	if hasCmd("gsettings") {
		if e := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run(); e != nil {
			errs = append(errs, fmt.Sprintf("gsettings: %v", e))
		}
	}
	if bin := kdeWriter(); bin != "" {
		if e := exec.Command(bin, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0").Run(); e != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", bin, e))
		}
	}
	_, _ = elevate("rm", "-f", "/etc/profile.d/prompt-gate-proxy.sh")
	if len(errs) > 0 {
		return fmt.Errorf("sysconf: proxy restore partial failures: %s", strings.Join(errs, "; "))
	}
	return nil
}

func applyDNS(dnsIP string) error {
	// systemd-resolved
	if hasCmd("resolvectl") && isServiceActive("systemd-resolved") {
		link, err := defaultLink()
		if err != nil {
			return err
		}
		if out, e := elevate("resolvectl", "dns", link, dnsIP); e != nil {
			return fmt.Errorf("sysconf: resolvectl dns: %s (%w)", strings.TrimSpace(string(out)), e)
		}
		if out, e := elevate("resolvectl", "domain", link, "~."); e != nil {
			return fmt.Errorf("sysconf: resolvectl domain: %s (%w)", strings.TrimSpace(string(out)), e)
		}
		return nil
	}
	// Fallback: rewrite /etc/resolv.conf
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		_, _ = elevate("cp", "/etc/resolv.conf", backup)
	}
	content := fmt.Sprintf("# Managed by Prompt Gate. Original backed up at %s.\nnameserver %s\noptions edns0\n", backup, dnsIP)
	tmpf, err := os.CreateTemp("", "prompt-gate-resolv-*.conf")
	if err != nil {
		return fmt.Errorf("sysconf: create temp resolv.conf: %w", err)
	}
	_, _ = tmpf.WriteString(content)
	tmpf.Close()
	defer os.Remove(tmpf.Name())
	if out, err := elevate("cp", tmpf.Name(), "/etc/resolv.conf"); err != nil {
		return fmt.Errorf("sysconf: write /etc/resolv.conf: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func restoreDNS() error {
	if hasCmd("resolvectl") && isServiceActive("systemd-resolved") {
		link, err := defaultLink()
		if err != nil {
			return err
		}
		if out, err := elevate("resolvectl", "revert", link); err != nil {
			return fmt.Errorf("sysconf: resolvectl revert: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); err == nil {
		if out, err := elevate("mv", backup, "/etc/resolv.conf"); err != nil {
			return fmt.Errorf("sysconf: restore resolv.conf: %s (%w)", strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func kdeWriter() string {
	if hasCmd("kwriteconfig6") {
		return "kwriteconfig6"
	}
	if hasCmd("kwriteconfig5") {
		return "kwriteconfig5"
	}
	return ""
}

func isServiceActive(name string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

const (
	debDest  = "/usr/local/share/ca-certificates/prompt-gate-ca.crt"
	rhelDest = "/etc/pki/ca-trust/source/anchors/prompt-gate-ca.crt"
)

// elevate runs a command via pkexec (PolicyKit) if the current process
// is not root. This shows a native password dialog on Ubuntu/Fedora so
// the user can authorise privileged operations from the GUI app.
func elevate(name string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return exec.Command(name, args...).CombinedOutput()
	}
	if !hasCmd("pkexec") {
		return nil, fmt.Errorf("sysconf: pkexec not found — run the app as root or install policykit-1")
	}
	full := append([]string{name}, args...)
	return exec.Command("pkexec", full...).CombinedOutput()
}

func installCA(caPath string) error {
	if hasCmd("update-ca-certificates") {
		// Debian / Ubuntu — copy CA to system trust dir (needs root).
		if out, err := elevate("cp", caPath, debDest); err != nil {
			return fmt.Errorf("sysconf: copy CA to %s: %s (%w)", debDest, strings.TrimSpace(string(out)), err)
		}
		if out, err := elevate("update-ca-certificates"); err != nil {
			return fmt.Errorf("sysconf: update-ca-certificates: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		// Fedora / RHEL
		if out, err := elevate("cp", caPath, rhelDest); err != nil {
			return fmt.Errorf("sysconf: copy CA to %s: %s (%w)", rhelDest, strings.TrimSpace(string(out)), err)
		}
		if out, err := elevate("update-ca-trust", "extract"); err != nil {
			return fmt.Errorf("sysconf: update-ca-trust: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	return fmt.Errorf("sysconf: no recognised ca-cert manager (need update-ca-certificates or update-ca-trust)")
}

func removeCA(_ string) error {
	if hasCmd("update-ca-certificates") {
		_, _ = elevate("rm", "-f", debDest)
		out, err := elevate("update-ca-certificates", "--fresh")
		if err != nil {
			return fmt.Errorf("sysconf: update-ca-certificates --fresh: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		_, _ = elevate("rm", "-f", rhelDest)
		out, err := elevate("update-ca-trust", "extract")
		if err != nil {
			return fmt.Errorf("sysconf: update-ca-trust: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	return fmt.Errorf("sysconf: no recognised ca-cert manager")
}

func defaultLink() (string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("sysconf: ip route: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("sysconf: no default route found")
}
