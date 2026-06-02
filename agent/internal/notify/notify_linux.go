package notify

// send is a no-op on Linux — notifications are delivered via SSE to
// the Electron UI.
func send(title, body string) {}
