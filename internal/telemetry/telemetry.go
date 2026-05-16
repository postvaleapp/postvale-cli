// Package telemetry holds the opt-in CLI usage-metrics scaffolding.
//
// Off by default. Users opt in via `wd config set telemetry=true`
// (or the legacy WIREDEPTH_TELEMETRY=1 env var). Even when enabled,
// the events shipped are strictly anonymous:
//
//   - command + subcommand name (e.g. "scan run")
//   - flag NAMES set on the invocation (never values)
//   - exit code + wall-clock duration
//   - OS + arch + CLI version
//
// We do NOT collect: IP, domain names, keywords, API tokens, user
// identity, environment variable values, or any payload data. The
// opt-in prompt printed at `wd auth login` spells this out so users
// know what they're enabling.
//
// Transport: HTTPS POST to /api/v1/cli/telemetry. Best-effort, fire-
// and-forget; failure never breaks the foreground command. Batching
// + offline queueing land in a follow-up commit.
package telemetry

import (
	"sync/atomic"
)

// Event is the minimal record shape. JSON-marshalled and POSTed
// asynchronously when telemetry is enabled.
type Event struct {
	Command    string   `json:"cmd"`
	Subcommand string   `json:"sub,omitempty"`
	FlagNames  []string `json:"flags,omitempty"`
	ExitCode   int      `json:"exit"`
	DurationMs int64    `json:"dur_ms"`
	CLIVersion string   `json:"v"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
}

// enabled is atomic so the Track fast path needs no lock. Set once at
// startup from config + env, read on every command exit.
var enabled atomic.Bool

// SetEnabled flips the opt-in switch. Called by the config loader
// once we've resolved telemetry preference.
func SetEnabled(v bool) {
	enabled.Store(v)
}

// IsEnabled returns whether telemetry will fire. Callers use it to
// short-circuit event construction when off.
func IsEnabled() bool {
	return enabled.Load()
}

// Track is the fire-and-forget event submission entry point. When
// telemetry is off it returns immediately. When on it would POST to
// the WireDepth telemetry endpoint; the POST path is stubbed out for
// now and lands with the rest of the v2 surface.
func Track(_ Event) {
	if !enabled.Load() {
		return
	}
	// Scaffolding only - the POST + batching + offline queue land
	// with the rest of the v2 surface change. The opt-in path needs
	// the privacy explainer + the API endpoint server-side before
	// we start shipping events.
}
