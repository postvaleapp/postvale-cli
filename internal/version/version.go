// Version metadata, injected at build time via -ldflags.
package version

var (
	// Semantic version. Set by goreleaser at release time; "dev"
	// for local builds.
	Version = "dev"
	// Git commit SHA at build.
	Commit = "none"
	// RFC 3339 timestamp at build.
	Date = "unknown"
)

// String returns a one-line "wd v1.2.3 (abcdef @ 2026-05-19)" stamp.
func String() string {
	return "wd " + Version + " (" + Commit + " @ " + Date + ")"
}
