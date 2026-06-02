//go:build !darwin

package sysconf

func helperAvailable() bool                   { return false }
func helperInstalled() bool                   { return false }
func helperRunning() bool                     { return false }
func installHelper(_ string) error            { return errUnsupported }
func findHelperBin() (string, error)          { return "", errUnsupported }
func uninstallHelper() error                  { return errUnsupported }
