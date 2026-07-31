//go:build !debug

package logging

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const maxLogSizeBytes = 200 * 1024 * 1024 // 200MB limit

func init() {
	debugEnv := strings.ToLower(os.Getenv("PROMPT_GATE_DEBUG"))
	logFileEnv := os.Getenv("PROMPT_GATE_LOG_FILE")

	if debugEnv == "1" || debugEnv == "true" || debugEnv == "debug" || logFileEnv != "" {
		logPath := logFileEnv
		if logPath == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				logDir := filepath.Join(home, ".prompt-gate")
				_ = os.MkdirAll(logDir, 0755)
				logPath = filepath.Join(logDir, "agent.log")
			} else {
				logPath = "agent.log"
			}
		}

		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if fi, err := os.Stat(logPath); err == nil && fi.Size() > maxLogSizeBytes {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}

		f, err := os.OpenFile(logPath, flags, 0644)
		if err == nil {
			Log.SetOutput(io.MultiWriter(f, os.Stderr))
		}
		Log.SetLevel(log.DebugLevel)
		Log.SetFormatter(&log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
		Log.Infof("=== verbose debug logging enabled — writing to %s (max 200MB) ===", logPath)
	} else {
		Log.SetLevel(log.WarnLevel)
	}
}
