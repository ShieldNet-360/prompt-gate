//go:build windows

package tamper

import (
	"context"
	"os/exec"
	"strings"
)

// platformDNSCheck shells out to `netsh interface ipv4 show dnsservers`
// and looks for expectedServer in the output. Any interface where it
// appears means the agent is still in path.
func platformDNSCheck(ctx context.Context, expectedServer string) (bool, error) {
	expectedServer = strings.TrimSpace(expectedServer)
	cmd := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "show", "dnsservers")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, expectedServer) {
			return true, nil
		}
	}
	return false, nil
}
