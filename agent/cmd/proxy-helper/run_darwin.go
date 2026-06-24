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
	"time"
)

const (
	socketPath     = "/var/run/prompt-gate-proxy.sock"
	systemKeychain = "/Library/Keychains/System.keychain"
	caCommonName   = "Prompt Gate Local CA"
	pfAnchor       = "com.prompt-gate"
	pfRulesFile    = "/tmp/prompt-gate-pf.conf"
)

const (
	// watchdogInterval is how often the fail-open watchdog checks that
	// the loopback proxy we point system traffic at is actually alive.
	watchdogInterval = 10 * time.Second
	// watchdogStrikes is how many consecutive dead checks before we
	// restore the network. ~30s of confirmed-dead at 10s spacing — long
	// enough to ride out an agent restart, short enough that the user
	// isn't stranded offline.
	watchdogStrikes = 3
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

	// Fail-open watchdog. The helper is a root LaunchDaemon with
	// KeepAlive, so it outlives a crash of the agent OR the Electron app
	// — making it the only component that can rescue the user when the
	// system proxy is left pointing at a dead 127.0.0.1:8443 (TCP 443
	// black-holed AND QUIC firewall-blocked = no internet, no recovery).
	go watchdog()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

// watchdog periodically verifies that, whenever the system secure-web
// proxy points at a loopback address (our MITM proxy), something is
// actually listening there. If the listener is gone for watchdogStrikes
// consecutive checks, it restores the network (fail-open) so the user
// regains connectivity even with the agent and tray both dead. It keys
// off live system state, so it works correctly across its own restarts.
func watchdog() {
	strikes := 0
	for {
		time.Sleep(watchdogInterval)
		// Guard each tick: a panic (e.g. a quirky networksetup output)
		// must not silently kill the watchdog — the one thing keeping the
		// user from being stranded offline.
		strikes = watchdogTick(strikes)
	}
}

// watchdogTick performs one watchdog check and returns the updated strike
// count. Recovers from any panic so the loop survives.
func watchdogTick(strikes int) (next int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "proxy-helper: watchdog tick recovered from panic: %v\n", r)
			next = 0
		}
	}()
	addr, ok := currentLoopbackProxyAddr()
	if !ok {
		return 0
	}
	if proxyListening(addr) {
		return 0
	}
	strikes++
	if strikes < watchdogStrikes {
		return strikes
	}
	fmt.Fprintf(os.Stderr,
		"proxy-helper: watchdog — system proxy %s is set but not listening; "+
			"restoring network (fail-open)\n", addr)
	if r := runRemoveProxy(); strings.HasPrefix(r, "ERR") {
		fmt.Fprintf(os.Stderr, "proxy-helper: watchdog restore failed: %s\n", r)
		// Keep the strikes maxed so we retry on the next tick.
		return strikes
	}
	return 0
}

// currentLoopbackProxyAddr returns the host:port of an ENABLED secure-web
// proxy that points at a loopback address, scanning active network
// services. The second return is false when no such proxy is set (so the
// watchdog stays idle when protection is off or a non-loopback proxy is
// configured by the user / their org).
func currentLoopbackProxyAddr() (string, bool) {
	svcs, err := listServices()
	if err != nil {
		return "", false
	}
	for _, svc := range svcs {
		out, err := exec.Command("/usr/sbin/networksetup", "-getsecurewebproxy", svc).Output()
		if err != nil {
			continue
		}
		server, port, enabled := parseSecureWebProxy(out)
		if enabled && isLoopback(server) && port != "" {
			return net.JoinHostPort(server, port), true
		}
	}
	return "", false
}

// parseSecureWebProxy extracts the Server / Port / Enabled fields from the
// output of `networksetup -getsecurewebproxy <service>`.
func parseSecureWebProxy(out []byte) (server, port string, enabled bool) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			enabled = strings.Contains(line, "Yes")
		case strings.HasPrefix(line, "Server:"):
			server = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
	return server, port, enabled
}

// isLoopback reports whether host is a loopback address — the marker that
// a proxy is ours (or another local MITM), never a remote corporate proxy.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// proxyListening reports whether a TCP listener is accepting on addr.
func proxyListening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
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
