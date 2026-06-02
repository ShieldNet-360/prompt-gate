//go:build linux || darwin || freebsd || openbsd || netbsd

package tamper

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// platformDNSCheck inspects /etc/resolv.conf on Linux/BSD and
// `networksetup -getdnsservers` output on macOS. The expected
// server is matched against any nameserver entry; the system is
// considered OK as long as the agent's loopback IP appears.
func platformDNSCheck(ctx context.Context, expectedServer string) (bool, error) {
	expectedServer = strings.TrimSpace(expectedServer)

	if runtime.GOOS == "darwin" {
		return dnsCheckDarwin(ctx, expectedServer)
	}
	return dnsCheckResolvConf(expectedServer)
}

// dnsCheckResolvConf parses /etc/resolv.conf and looks for a
// nameserver line whose IP equals expectedServer.
func dnsCheckResolvConf(expectedServer string) (bool, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == expectedServer {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// dnsCheckDarwin shells out to `networksetup -getdnsservers Wi-Fi`
// (and Ethernet) to confirm at least one active service is pointed
// at expectedServer.
func dnsCheckDarwin(ctx context.Context, expectedServer string) (bool, error) {
	services := []string{"Wi-Fi", "Ethernet"}
	for _, svc := range services {
		cmd := exec.CommandContext(ctx, "networksetup", "-getdnsservers", svc)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) == expectedServer {
				return true, nil
			}
		}
	}
	return false, nil
}
