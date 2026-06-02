package api

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSysConfState_PersistLoadRoundtrip proves the on-disk state file
// (the fix for recovering from a non-graceful exit) round-trips both
// flags through ~/.prompt-gate/sysconf-state.json.
func TestSysConfState_PersistLoadRoundtrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	sysConfMu.Lock()
	sysProxyOn, sysDNSOn = true, true
	persistSysConfState()
	sysConfMu.Unlock()
	t.Cleanup(func() { sysProxyOn, sysDNSOn = false, false })

	if _, err := os.Stat(filepath.Join(home, ".prompt-gate", "sysconf-state.json")); err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	if st := loadSysConfState(); !st.Proxy || !st.DNS {
		t.Fatalf("roundtrip mismatch: got %+v, want both true", st)
	}
}

// TestReconcileSysConfOnStartup_LoadsFlagsWhenServing checks the common
// restart case: the proxy is back up (proxyServing == true), so no
// system-level restore is attempted, but the persisted flags must be
// reloaded into memory so a later graceful shutdown still restores.
func TestReconcileSysConfOnStartup_LoadsFlagsWhenServing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	sysConfMu.Lock()
	sysProxyOn, sysDNSOn = true, false
	persistSysConfState()
	sysProxyOn, sysDNSOn = false, false // simulate a fresh process
	sysConfMu.Unlock()
	t.Cleanup(func() { sysProxyOn, sysDNSOn = false, false })

	ReconcileSysConfOnStartup(true) // serving => never touches the OS

	sysConfMu.Lock()
	gotProxy, gotDNS := sysProxyOn, sysDNSOn
	sysConfMu.Unlock()
	if !gotProxy {
		t.Error("sysProxyOn not reloaded from disk")
	}
	if gotDNS {
		t.Error("sysDNSOn should have stayed false")
	}
}

// TestReconcileSysConfOnStartup_NoStateNoRestore proves a missing state
// file clears stale in-memory flags and never triggers a restore.
func TestReconcileSysConfOnStartup_NoStateNoRestore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	sysConfMu.Lock()
	sysProxyOn, sysDNSOn = true, true // stale, as if left over from another test
	sysConfMu.Unlock()
	t.Cleanup(func() { sysProxyOn, sysDNSOn = false, false })

	ReconcileSysConfOnStartup(false)

	sysConfMu.Lock()
	gotProxy, gotDNS := sysProxyOn, sysDNSOn
	sysConfMu.Unlock()
	if gotProxy || gotDNS {
		t.Errorf("flags should be false with no state file: proxy=%v dns=%v", gotProxy, gotDNS)
	}
}
