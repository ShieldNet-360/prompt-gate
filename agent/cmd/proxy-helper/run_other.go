//go:build !darwin

package main

import (
	"fmt"
	"os"
)

func run() {
	fmt.Fprintln(os.Stderr, "proxy-helper: only supported on macOS")
	os.Exit(1)
}
