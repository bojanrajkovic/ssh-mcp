// Package version carries build metadata stamped in at link time.
package version

import "fmt"

// Stamped by the linker via -X at build and release time. The defaults are
// what a plain "go build" or "go test" produces.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String renders the build stamp as one line, for --version and startup logs.
func String() string {
	return fmt.Sprintf("ssh-mcp %s (%s, built %s)", Version, Commit, Date)
}
