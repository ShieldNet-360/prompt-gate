// Package sysconf provides platform-specific system proxy and DNS
// configuration. All operations are performed in-process via OS
// commands (networksetup on macOS, gsettings/resolvectl on Linux,
// netsh/registry on Windows) — no external scripts required.
package sysconf

import "fmt"

// ApplyProxy configures the OS-level HTTPS/HTTP proxy to point at
// host:port. On macOS this modifies all active network services via
// networksetup; on Linux it sets GNOME/KDE proxy settings.
func ApplyProxy(host string, port int) error {
	return applyProxy(host, port)
}

// ApplyProxyWithCA trusts the CA at caPath (only when it is not already
// trusted) AND applies the system proxy. On macOS both mutations run
// under a SINGLE administrator authorization, so enabling protection
// costs at most one password prompt instead of one for the CA and a
// separate one for the proxy. Passing an empty caPath skips the CA step
// and behaves exactly like ApplyProxy.
func ApplyProxyWithCA(host string, port int, caPath string) error {
	return applyProxyWithCA(host, port, caPath)
}

// CATrusted reports whether the CA at caPath is already trusted in the
// OS trust store. Callers use this to avoid re-installing (and thus
// re-prompting for) a CA that was trusted on a previous run.
func CATrusted(caPath string) bool {
	return caTrusted(caPath)
}

// RestoreProxy removes the OS-level HTTPS/HTTP proxy settings.
func RestoreProxy() error {
	return restoreProxy()
}

// ApplyDNS sets the OS-level DNS resolver to the given IP.
func ApplyDNS(dnsIP string) error {
	return applyDNS(dnsIP)
}

// RestoreDNS resets the OS-level DNS resolver to default (DHCP).
func RestoreDNS() error {
	return restoreDNS()
}

// InstallCA trusts the given CA certificate in the OS trust store.
func InstallCA(caPath string) error {
	return installCA(caPath)
}

// RemoveCA removes the given CA certificate from the OS trust store.
func RemoveCA(caPath string) error {
	return removeCA(caPath)
}

// HelperInstalled reports whether the privileged proxy-helper daemon is
// installed on disk. On non-macOS platforms this always returns false.
func HelperInstalled() bool { return helperInstalled() }

// HelperRunning reports whether the privileged proxy-helper daemon is
// currently running and accepting commands. On non-macOS platforms this
// always returns false.
func HelperRunning() bool { return helperRunning() }

// InstallHelper installs the privileged proxy-helper daemon from the binary
// at binSrc. On macOS this requires exactly one admin prompt and the daemon
// starts immediately; on other platforms it returns errUnsupported.
func InstallHelper(binSrc string) error { return installHelper(binSrc) }

// FindHelperBin locates the proxy-helper binary relative to the current
// executable. Returns errUnsupported on non-macOS platforms.
func FindHelperBin() (string, error) { return findHelperBin() }

// errUnsupported is returned on platforms without an implementation.
var errUnsupported = fmt.Errorf("sysconf: unsupported platform")
