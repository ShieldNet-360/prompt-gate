// proxy-helper is a privileged LaunchDaemon that runs as root on macOS.
// It accepts proxy/DNS/CA commands over a Unix socket and executes them
// directly (no osascript elevation needed), so the Prompt Gate tray app
// can toggle the system proxy with zero password prompts after the helper
// is installed once.
package main

func main() {
	run()
}
