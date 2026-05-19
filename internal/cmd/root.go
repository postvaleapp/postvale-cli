// Cobra root + global flag wiring for the wd CLI.
//
// Each subcommand package registers itself via init() so the root
// stays a thin orchestrator. Global flags are bound here so they're
// available to every subcommand without per-cmd re-declaration.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/version"
)

// Globally-overridable flags. Resolved against config + env in
// preRun; subcommands read the final values via the package-level
// vars.
var (
	flagAPI     string
	flagJSON    bool
	flagVerbose bool
)

var rootCmd = &cobra.Command{
	Use:   "wd",
	Short: "WireDepth CLI - external attack surface checks + monitoring",
	Long: `wd is the official WireDepth CLI.

Run public posture checks without auth, manage your monitored
domains + alerts when signed in, and verify the audit-chain
evidence pack yourself with no WireDepth dependency.

Free for the read-only checks (TLS, DMARC, DNS, etc.); sign in
for monitoring + workpapers + audit verification.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command. Called from main.
func Execute() error { return rootCmd.Execute() }

func init() {
	rootCmd.PersistentFlags().StringVar(&flagAPI, "api", "", "WireDepth API base URL (default https://wiredepth.com)")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit JSON instead of human-readable output")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output (request bodies, etc.)")

	rootCmd.SetVersionTemplate(version.String() + "\n")
	rootCmd.Version = version.Version
}
