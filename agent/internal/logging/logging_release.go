//go:build !debug

package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

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
				logPath = filepath.Join(logDir, fmt.Sprintf("agent_%s.log", time.Now().Format("2006-01-02")))
			} else {
				logPath = fmt.Sprintf("agent_%s.log", time.Now().Format("2006-01-02"))
			}
		}

		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			Log.SetOutput(io.MultiWriter(f, os.Stderr))
		}
		Log.SetLevel(log.DebugLevel)
		Log.SetFormatter(&log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
		Log.Infof("=== verbose debug logging enabled — writing to %s ===", logPath)
	} else {
		Log.SetLevel(log.WarnLevel)
	}
}
