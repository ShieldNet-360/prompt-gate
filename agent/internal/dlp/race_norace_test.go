// raceEnabled reports whether the binary was built with the Go race
// detector enabled. The integration perf budget is much tighter
// without -race so the test relaxes the bound when raceEnabled is
// true. The build-tagged twin file race_yesrace_test.go flips this
// value when the test binary is compiled with `go test -race`.

//go:build !race

package dlp

const raceEnabled = false
