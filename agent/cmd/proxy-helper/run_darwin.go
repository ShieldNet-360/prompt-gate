//go:build darwin

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	socketPath     = "/var/run/prompt-gate-proxy.sock"
	systemKeychain = "/Library/Keychains/System.keychain"
	caCommonName   = "Prompt Gate Local CA"
	pfAnchor       = "com.prompt-gate"
	pfRulesFile    = "/tmp/prompt-gate-pf.conf"
)

func run() {
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy-helper: listen: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		fmt.Fprintf(os.Stderr, "proxy-helper: chmod socket: %v\n", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fmt.Fprintln(conn, dispatch(line))
	}
}

// dispatch parses a single command line and returns "OK" or "ERR reason".
// Split into at most 4 fields so a file path (last arg) may contain spaces.
func dispatch(line string) string {
	parts := strings.SplitN(line, " ", 4)
	cmd, args := parts[0], parts[1:]

	switch cmd {
	case "PING":
		return "OK"
	case "APPLY_PROXY":
		if len(args) < 2 {
			return "ERR usage: APPLY_PROXY host port"
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return "ERR invalid port"
		}
		return runApplyProxy(args[0], port, "")
	case "APPLY_PROXY_CA":
		if len(args) < 3 {
			return "ERR usage: APPLY_PROXY_CA host port caPath"
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return "ERR invalid port"
		}
		return runApplyProxy(args[0], port, args[2])
	case "REMOVE_PROXY":
		return runRemoveProxy()
	case "APPLY_DNS":
		if len(args) < 1 || args[0] == "" {
			return "ERR usage: APPLY_DNS ip"
		}
		return runApplyDNS(args[0])
	case "REMOVE_DNS":
		return runRemoveDNS()
	case "TRUST_CA":
		if len(args) < 1 || args[0] == "" {
			return "ERR usage: TRUST_CA caPath"
		}
		return runTrustCA(args[0])
	case "REMOVE_CA":
		if len(args) < 1 || args[0] == "" {
			return "ERR usage: REMOVE_CA caPath"
		}
		return runRemoveCA(args[0])
	case "CA_TRUSTED":
		if isCATrusted() {
			return "OK yes"
		}
		return "OK no"
	default:
		return "ERR unknown command"
	}
}

func listServices() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("networksetup: %w", err)
	}
	var svcs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "asterisk") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

func runApplyProxy(host string, port int, caPath string) string {
	if caPath != "" && !isCATrusted() {
		if r := runTrustCA(caPath); strings.HasPrefix(r, "ERR") {
			return r
		}
	}
	svcs, err := listServices()
	if err != nil {
		return "ERR " + err.Error()
	}
	portStr := strconv.Itoa(port)
	for _, svc := range svcs {
		if err := exec.Command("/usr/sbin/networksetup", "-setsecurewebproxy", svc, host, portStr).Run(); err != nil {
			return "ERR networksetup setsecurewebproxy " + svc + ": " + err.Error()
		}
		if err := exec.Command("/usr/sbin/networksetup", "-setwebproxy", svc, host, portStr).Run(); err != nil {
			return "ERR networksetup setwebproxy " + svc + ": " + err.Error()
		}
	}
	_ = os.WriteFile(pfRulesFile, []byte("block drop quick proto udp from any to any port 443\n"), 0o644)
	_ = exec.Command("/sbin/pfctl", "-a", pfAnchor, "-f", pfRulesFile).Run()
	_ = exec.Command("/sbin/pfctl", "-e").Run()
	return "OK"
}

func runRemoveProxy() string {
	svcs, err := listServices()
	if err != nil {
		return "ERR " + err.Error()
	}
	for _, svc := range svcs {
		_ = exec.Command("/usr/sbin/networksetup", "-setsecurewebproxystate", svc, "off").Run()
		_ = exec.Command("/usr/sbin/networksetup", "-setwebproxystate", svc, "off").Run()
	}
	_ = exec.Command("/sbin/pfctl", "-a", pfAnchor, "-F", "all").Run()
	_ = os.Remove(pfRulesFile)
	return "OK"
}

func runApplyDNS(ip string) string {
	svcs, err := listServices()
	if err != nil {
		return "ERR " + err.Error()
	}
	for _, svc := range svcs {
		if err := exec.Command("/usr/sbin/networksetup", "-setdnsservers", svc, ip).Run(); err != nil {
			return "ERR networksetup setdnsservers " + svc + ": " + err.Error()
		}
	}
	return "OK"
}

func runRemoveDNS() string {
	svcs, err := listServices()
	if err != nil {
		return "ERR " + err.Error()
	}
	for _, svc := range svcs {
		_ = exec.Command("/usr/sbin/networksetup", "-setdnsservers", svc, "Empty").Run()
	}
	return "OK"
}

func runTrustCA(caPath string) string {
	// Remove any existing cert with this CN first to avoid duplicates.
	for {
		if exec.Command("/usr/bin/security", "find-certificate", "-c", caCommonName, systemKeychain).Run() != nil {
			break
		}
		if exec.Command("/usr/bin/security", "delete-certificate", "-c", caCommonName, systemKeychain).Run() != nil {
			break
		}
	}
	out, err := exec.Command("/usr/bin/security", "add-trusted-cert",
		"-d", "-r", "trustRoot", "-k", systemKeychain, caPath,
	).CombinedOutput()
	if err != nil {
		return "ERR security add-trusted-cert: " + strings.TrimSpace(string(out))
	}
	return "OK"
}

func runRemoveCA(caPath string) string {
	_ = exec.Command("/usr/bin/security", "remove-trusted-cert", "-d", caPath).Run()
	for {
		if exec.Command("/usr/bin/security", "find-certificate", "-c", caCommonName, systemKeychain).Run() != nil {
			break
		}
		if exec.Command("/usr/bin/security", "delete-certificate", "-c", caCommonName, systemKeychain).Run() != nil {
			break
		}
	}
	return "OK"
}

func isCATrusted() bool {
	return exec.Command("/usr/bin/security", "find-certificate", "-c", caCommonName, systemKeychain).Run() == nil
}
