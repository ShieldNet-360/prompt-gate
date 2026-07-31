//go:build debug

package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

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
		logPath = filepath.Join(logDir, fmt.Sprintf("agent_debug_%s.log", time.Now().Format("2006-01-02")))
	} else {
		logPath = fmt.Sprintf("agent_debug_%s.log", time.Now().Format("2006-01-02"))
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		Log.SetOutput(io.MultiWriter(f, os.Stderr))
		Log.Infof("=== debug build logging enabled — writing to %s ===", logPath)
	} else {
		Log.SetOutput(os.Stderr)
		Log.Warnf("logging: could not open log file %s: %v — logging to stderr only", logPath, err)
	}
}
