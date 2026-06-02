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
	if e := os.WriteFile("/etc/profile.d/prompt-gate-proxy.sh", []byte(content), 0644); e != nil {
		errs = append(errs, fmt.Sprintf("profile.d: %v", e))
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
	_ = os.Remove("/etc/profile.d/prompt-gate-proxy.sh")
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
		if e := exec.Command("resolvectl", "dns", link, dnsIP).Run(); e != nil {
			return fmt.Errorf("sysconf: resolvectl dns: %w", e)
		}
		if e := exec.Command("resolvectl", "domain", link, "~.").Run(); e != nil {
			return fmt.Errorf("sysconf: resolvectl domain: %w", e)
		}
		return nil
	}
	// Fallback: rewrite /etc/resolv.conf
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			_ = os.WriteFile(backup, data, 0644)
		}
	}
	content := fmt.Sprintf("# Managed by Prompt Gate. Original backed up at %s.\nnameserver %s\noptions edns0\n", backup, dnsIP)
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

func restoreDNS() error {
	if hasCmd("resolvectl") && isServiceActive("systemd-resolved") {
		link, err := defaultLink()
		if err != nil {
			return err
		}
		return exec.Command("resolvectl", "revert", link).Run()
	}
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); err == nil {
		return os.Rename(backup, "/etc/resolv.conf")
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

func installCA(caPath string) error {
	if hasCmd("update-ca-certificates") {
		// Debian / Ubuntu
		data, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("sysconf: read CA: %w", err)
		}
		if err := os.WriteFile(debDest, data, 0644); err != nil {
			return fmt.Errorf("sysconf: write %s: %w", debDest, err)
		}
		out, err := exec.Command("update-ca-certificates").CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysconf: update-ca-certificates: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		// Fedora / RHEL
		data, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("sysconf: read CA: %w", err)
		}
		if err := os.WriteFile(rhelDest, data, 0644); err != nil {
			return fmt.Errorf("sysconf: write %s: %w", rhelDest, err)
		}
		out, err := exec.Command("update-ca-trust", "extract").CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysconf: update-ca-trust: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	return fmt.Errorf("sysconf: no recognised ca-cert manager (need update-ca-certificates or update-ca-trust)")
}

func removeCA(_ string) error {
	if hasCmd("update-ca-certificates") {
		_ = os.Remove(debDest)
		out, err := exec.Command("update-ca-certificates", "--fresh").CombinedOutput()
		if err != nil {
			return fmt.Errorf("sysconf: update-ca-certificates --fresh: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		_ = os.Remove(rhelDest)
		out, err := exec.Command("update-ca-trust", "extract").CombinedOutput()
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
