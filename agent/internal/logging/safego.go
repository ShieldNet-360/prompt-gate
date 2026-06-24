package logging

import "runtime/debug"

// Recover is the panic backstop for a goroutine. Deferred at the top of a
// goroutine (or a per-request handler), it turns a panic — which would
// otherwise terminate the ENTIRE process, since only net/http recovers
// its own request goroutines — into a logged error. The stack is logged
// for debugging; the panic value itself is included, so never pass
// payload bytes to panic().
func Recover(label string) {
	if r := recover(); r != nil {
		Log.WithField("goroutine", label).
			Errorf("recovered from panic: %v\n%s", r, debug.Stack())
	}
}

// Go runs fn in a new goroutine guarded by Recover(label). Use it for
// long-lived background workers (poll loops, flush timers) so a panic in
// one subsystem degrades that subsystem instead of crashing the agent and
// black-holing every user's traffic.
func Go(label string, fn func()) {
	go func() {
		defer Recover(label)
		fn()
	}()
}
