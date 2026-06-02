package sysconf

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestApplyRestoreProxy modifies real system proxy settings + pf
// firewall rules. Skipped by default — opt in with
// SYSCONF_INTEGRATION=1 and root privileges (pfctl needs /dev/pf).
func TestApplyRestoreProxy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	if os.Getenv("SYSCONF_INTEGRATION") != "1" {
		t.Skip("set SYSCONF_INTEGRATION=1 (and run as root) to exercise system-state modifications")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for pfctl /dev/pf — re-run with sudo")
	}

	// Apply
	if err := ApplyProxy("127.0.0.1", 8443); err != nil {
		t.Fatalf("ApplyProxy: %v", err)
	}

	// Verify
	out, _ := exec.Command("networksetup", "-getsecurewebproxy", "Wi-Fi").Output()
	if !strings.Contains(string(out), "Enabled: Yes") {
		t.Errorf("proxy not enabled after apply: %s", out)
	}

	// Restore
	if err := RestoreProxy(); err != nil {
		t.Fatalf("RestoreProxy: %v", err)
	}

	// Verify
	out, _ = exec.Command("networksetup", "-getsecurewebproxy", "Wi-Fi").Output()
	if !strings.Contains(string(out), "Enabled: No") {
		t.Errorf("proxy not disabled after restore: %s", out)
	}
}
