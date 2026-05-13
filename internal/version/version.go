// Package version exposes build-time stamps. GoReleaser injects the
// real values via -ldflags at release; default values keep `go run`
// + `go install` workflows readable in dev.
package version

// These are overridden at build time by GoReleaser:
//
//	-X github.com/postvaleapp/postvale-cli/internal/version.Version=v0.1.0
//	-X github.com/postvaleapp/postvale-cli/internal/version.Commit=<sha>
//	-X github.com/postvaleapp/postvale-cli/internal/version.Date=<iso>
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
