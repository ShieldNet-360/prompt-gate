package sysconf

import (
	"fmt"
	"os/exec"
)

func applyProxyWithCA(host string, port int, caPath string) error {
	if caPath != "" && !caTrusted(caPath) {
		if err := installCA(caPath); err != nil {
			return err
		}
	}
	return applyProxy(host, port)
}

// caTrusted reports whether our CA already exists in the Root store.
// certutil -verifystore exits 0 when at least one matching cert is
// found. We match on the CA file so a missing/renamed cert re-installs.
func caTrusted(caPath string) bool {
	return exec.Command("certutil", "-verifystore", "Root", "Prompt Gate Local CA").Run() == nil
}

func applyProxy(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	// Enable proxy via registry
	cmds := [][]string{
		{"reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", addr, "/f"},
		{"reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.0.0.1;::1", "/f"},
	}
	for _, cmd := range cmds {
		if e := exec.Command(cmd[0], cmd[1:]...).Run(); e != nil {
			return fmt.Errorf("sysconf: %v: %w", cmd, e)
		}
	}
	// Notify WinInet of the change
	_ = exec.Command("powershell", "-Command",
		`Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class WinInet{[DllImport("wininet.dll")]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}'; [WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0); [WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`,
	).Run()
	return nil
}

func restoreProxy() error {
	cmds := [][]string{
		{"reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"},
	}
	for _, cmd := range cmds {
		if e := exec.Command(cmd[0], cmd[1:]...).Run(); e != nil {
			return fmt.Errorf("sysconf: %v: %w", cmd, e)
		}
	}
	_ = exec.Command("powershell", "-Command",
		`Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class WinInet{[DllImport("wininet.dll")]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}'; [WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0); [WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)`,
	).Run()
	return nil
}

func applyDNS(dnsIP string) error {
	// Use netsh to set DNS on all active interfaces
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return fmt.Errorf("sysconf: netsh interface list: %w", err)
	}
	ifaces := parseNetshInterfaces(string(out))
	for _, iface := range ifaces {
		_ = exec.Command("netsh", "interface", "ip", "set", "dns", "name="+iface, "source=static", "addr="+dnsIP).Run()
	}
	return nil
}

func restoreDNS() error {
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
	if err != nil {
		return fmt.Errorf("sysconf: netsh interface list: %w", err)
	}
	ifaces := parseNetshInterfaces(string(out))
	for _, iface := range ifaces {
		_ = exec.Command("netsh", "interface", "ip", "set", "dns", "name="+iface, "source=dhcp").Run()
	}
	return nil
}

func installCA(caPath string) error {
	out, err := exec.Command("certutil", "-addstore", "Root", caPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysconf: certutil -addstore: %s (%w)", string(out), err)
	}
	return nil
}

func removeCA(caPath string) error {
	out, err := exec.Command("certutil", "-delstore", "Root", caPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysconf: certutil -delstore: %s (%w)", string(out), err)
	}
	return nil
}

func parseNetshInterfaces(output string) []string {
	var ifaces []string
	lines := splitLines(output)
	for _, line := range lines {
		// Connected interfaces have "Connected" in the line
		if len(line) > 50 && containsCI(line, "connected") && !containsCI(line, "disconnected") {
			// Interface name is the last column (starts around position 50+)
			name := trimFields(line)
			if name != "" {
				ifaces = append(ifaces, name)
			}
		}
	}
	return ifaces
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func containsCI(s, sub string) bool {
	sl := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		sl[i] = c
	}
	subl := make([]byte, len(sub))
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		subl[i] = c
	}
	return indexOf(string(sl), string(subl)) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimFields(line string) string {
	// The interface name is typically the 4th column in netsh output
	fields := splitFields(line)
	if len(fields) >= 4 {
		return fields[len(fields)-1]
	}
	return ""
}

func splitFields(s string) []string {
	var fields []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
			i++
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '\r' {
			j++
		}
		if j > i {
			fields = append(fields, s[i:j])
		}
		i = j
	}
	return fields
}
