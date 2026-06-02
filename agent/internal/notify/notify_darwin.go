package notify

// send is a no-op on macOS — the agent runs as root and cannot display
// desktop notifications directly. Notifications are delivered to the
// Electron UI via SSE (/api/events) and shown using Electron's
// Notification API at the desktop session level.
func send(title, body string) {}
