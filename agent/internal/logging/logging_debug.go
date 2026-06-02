//go:build debug

package logging

import (
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	name := fmt.Sprintf("edge_%s.log", time.Now().Format("2006-01-02"))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		Log.Fatalf("logging: open %s: %v", name, err)
	}

	Log.SetOutput(io.MultiWriter(f, os.Stderr))
	Log.SetLevel(log.DebugLevel)
	Log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	Log.Infof("=== debug logging enabled — writing to %s ===", name)
}
