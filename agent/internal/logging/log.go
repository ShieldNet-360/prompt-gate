// Package logging exposes a global logrus logger configured at init
// time by the build-tagged files (logging_debug.go / logging_release.go).
//
// Usage:
//
//	import "github.com/ShieldNet-360/prompt-gate/agent/internal/logging"
//	logging.Log.Info("server started")
//	logging.Log.WithField("addr", addr).Debug("listening")
package logging

import log "github.com/sirupsen/logrus"

// Log is the global logger. Every package in the agent should use this
// instead of the standard log package or fmt.Fprintf(os.Stderr, ...).
// Debug-level messages are only emitted in debug builds.
var Log = log.New()
