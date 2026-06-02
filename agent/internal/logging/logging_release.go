//go:build !debug

package logging

import log "github.com/sirupsen/logrus"

func init() {
	Log.SetLevel(log.WarnLevel)
}
