// Package version holds build stamps. Overridden by -ldflags at
// release; defaults below keep `go run` readable in dev.
package version

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
