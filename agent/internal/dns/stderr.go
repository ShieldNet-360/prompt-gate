package dns

import (
	"io"
	"os"
)

// stderr is the destination for operational error messages. It is a
// package-level variable so tests can swap it out and assert on the
// output without writing to the real stderr.
var stderr io.Writer = os.Stderr
