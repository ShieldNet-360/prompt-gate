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
	// /etc/profile.d requires root — use runElevated. Non-fatal if it
	// fails because gsettings is the primary mechanism for GUI apps.
	if tmpf, e := os.CreateTemp("", "prompt-gate-proxy-*.sh"); e == nil {
		_, _ = tmpf.WriteString(content)
		tmpf.Close()
		script := fmt.Sprintf("cp %s /etc/profile.d/prompt-gate-proxy.sh\n", shellQuote(tmpf.Name()))
		if out, e2 := runElevated(script); e2 != nil {
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
	_, _ = runElevated("rm -f /etc/profile.d/prompt-gate-proxy.sh\n")
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
		script := fmt.Sprintf("resolvectl dns %s %s\nresolvectl domain %s '~.'\n",
			shellQuote(link), shellQuote(dnsIP), shellQuote(link))
		if out, e := runElevated(script); e != nil {
			return fmt.Errorf("sysconf: resolvectl: %s (%w)", strings.TrimSpace(string(out)), e)
		}
		return nil
	}
	// Fallback: rewrite /etc/resolv.conf
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		_, _ = runElevated(fmt.Sprintf("cp /etc/resolv.conf %s\n", shellQuote(backup)))
	}
	content := fmt.Sprintf("# Managed by Prompt Gate. Original backed up at %s.\nnameserver %s\noptions edns0\n", backup, dnsIP)
	tmpf, err := os.CreateTemp("", "prompt-gate-resolv-*.conf")
	if err != nil {
		return fmt.Errorf("sysconf: create temp resolv.conf: %w", err)
	}
	_, _ = tmpf.WriteString(content)
	tmpf.Close()
	defer os.Remove(tmpf.Name())
	script := fmt.Sprintf("cp %s /etc/resolv.conf\n", shellQuote(tmpf.Name()))
	if out, err := runElevated(script); err != nil {
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
		if out, err := runElevated(fmt.Sprintf("resolvectl revert %s\n", shellQuote(link))); err != nil {
			return fmt.Errorf("sysconf: resolvectl revert: %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	backup := "/etc/resolv.conf.prompt-gate.bak"
	if _, err := os.Stat(backup); err == nil {
		if out, err := runElevated(fmt.Sprintf("mv %s /etc/resolv.conf\n", shellQuote(backup))); err != nil {
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

// runElevated writes a shell script containing the given commands to a
// temp file and executes it via pkexec (or directly if already root).
// This avoids passing any user-controlled values as exec.Command
// arguments — only the fixed temp-file path is passed to pkexec.
func runElevated(script string) ([]byte, error) {
	f, err := os.CreateTemp("", "prompt-gate-elevate-*.sh")
	if err != nil {
		return nil, fmt.Errorf("sysconf: create temp script: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)

	if _, err := f.WriteString("#!/bin/sh\nset -e\n" + script); err != nil {
		f.Close()
		return nil, fmt.Errorf("sysconf: write temp script: %w", err)
	}
	f.Close()
	if err := os.Chmod(name, 0700); err != nil {
		return nil, fmt.Errorf("sysconf: chmod temp script: %w", err)
	}

	if os.Geteuid() == 0 {
		return exec.Command("/bin/sh", name).CombinedOutput()
	}
	if !hasCmd("pkexec") {
		return nil, fmt.Errorf("sysconf: pkexec not found — run the app as root or install policykit-1")
	}
	return exec.Command("pkexec", "/bin/sh", name).CombinedOutput()
}

// shellQuote returns a single-quoted shell literal safe for embedding
// in a script. Any embedded single quotes are escaped.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''" ) + "'"
}

func installCA(caPath string) error {
	safe := shellQuote(caPath)
	if hasCmd("update-ca-certificates") {
		script := fmt.Sprintf("cp %s %s\nupdate-ca-certificates\n", safe, shellQuote(debDest))
		if out, err := runElevated(script); err != nil {
			return fmt.Errorf("sysconf: install CA (deb): %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		script := fmt.Sprintf("cp %s %s\nupdate-ca-trust extract\n", safe, shellQuote(rhelDest))
		if out, err := runElevated(script); err != nil {
			return fmt.Errorf("sysconf: install CA (rhel): %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	return fmt.Errorf("sysconf: no recognised ca-cert manager (need update-ca-certificates or update-ca-trust)")
}

func removeCA(_ string) error {
	if hasCmd("update-ca-certificates") {
		script := fmt.Sprintf("rm -f %s\nupdate-ca-certificates --fresh\n", shellQuote(debDest))
		if out, err := runElevated(script); err != nil {
			return fmt.Errorf("sysconf: remove CA (deb): %s (%w)", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if hasCmd("update-ca-trust") {
		script := fmt.Sprintf("rm -f %s\nupdate-ca-trust extract\n", shellQuote(rhelDest))
		if out, err := runElevated(script); err != nil {
			return fmt.Errorf("sysconf: remove CA (rhel): %s (%w)", strings.TrimSpace(string(out)), err)
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
