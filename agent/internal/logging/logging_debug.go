//go:build debug

package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const maxLogSizeBytes = 200 * 1024 * 1024 // 200MB limit

func init() {
	Log.SetLevel(log.DebugLevel)
	Log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	home, err := os.UserHomeDir()
	var logPath string
	if err == nil {
		logDir := filepath.Join(home, ".prompt-gate")
		_ = os.MkdirAll(logDir, 0755)
		logPath = filepath.Join(logDir, "agent.log")
	} else {
		logPath = "agent.log"
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > maxLogSizeBytes {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}

	f, err := os.OpenFile(logPath, flags, 0644)
	if err == nil {
		Log.SetOutput(io.MultiWriter(f, os.Stderr))
		Log.Infof("=== debug build logging enabled — writing to %s (max 200MB) ===", logPath)
	} else {
		Log.SetOutput(os.Stderr)
		Log.Warnf("logging: could not open log file %s: %v — logging to stderr only", logPath, err)
	}
}
