// Package commands defines the cobra command tree for the Postvale
// CLI. Each subcommand lives in its own file so the tree is easy to
// scan + extend; root.go just wires them together + declares the
// global flags every command inherits.
package commands

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/version"
)

// Global flag values populated by cobra before any RunE fires. We
// stash them in a package-scoped struct so individual commands can
// read them without re-defining persistent flags.
type GlobalFlags struct {
	APIBase    string // --api (or POSTVALE_API env)
	Token      string // --token (or POSTVALE_TOKEN env)
	JSON       bool   // --json
	Quiet      bool   // --quiet, -q
	NoColor    bool   // --no-color
	ExitOnFail bool   // --exit-on-fail
	Timeout    int    // --timeout (seconds)
	ConfigPath string // --config
}

var globals GlobalFlags

// Globals returns a pointer to the resolved global-flag struct.
// Subcommand RunE handlers call this after cobra has parsed flags.
func Globals() *GlobalFlags {
	return &globals
}

// NewRootCommand builds the full command tree. Exposed (rather than
// initialised at package level) so tests can construct a fresh tree
// per test without state leaking between runs.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "postvale",
		Short: "Domain posture + email security checks from the terminal",
		Long: `Postvale CLI - TLS, DMARC, DNS, threat-intel, and audit
evidence for any public domain.

Free read-only checks (TLS, DMARC, DNS, Scam Check, etc.) work without
signing in. Sign in with ` + "`postvale auth login`" + ` to add domains to
continuous monitoring, pull workpapers, or run Pro features.

Designed for the terminal AND for CI. Use --json for machine output and
--exit-on-fail to gate deploys on posture grades.`,
		SilenceUsage:  true, // don't dump usage on every error
		SilenceErrors: true, // we print errors in main.go ourselves
	}

	// Persistent (global) flags. POSTVALE_API + POSTVALE_TOKEN env
	// vars are read as fallbacks in resolveGlobals().
	pf := root.PersistentFlags()
	pf.StringVar(&globals.APIBase, "api", "", "Postvale API base URL (default https://postvale.app)")
	pf.StringVar(&globals.Token, "token", "", "API token (overrides stored credential)")
	pf.BoolVar(&globals.JSON, "json", false, "Output structured JSON instead of pretty text")
	pf.BoolVarP(&globals.Quiet, "quiet", "q", false, "Suppress non-essential output")
	pf.BoolVar(&globals.NoColor, "no-color", false, "Disable ANSI colors (auto-disabled on non-TTY)")
	pf.BoolVar(&globals.ExitOnFail, "exit-on-fail", false, "Exit 1 when the result indicates a failing posture")
	pf.IntVar(&globals.Timeout, "timeout", 30, "Per-request timeout in seconds")
	pf.StringVar(&globals.ConfigPath, "config", "", "Path to config file (default ~/.config/postvale/config.yaml)")

	// PersistentPreRun resolves env-var fallbacks before any command
	// body runs. Keeping resolution here means each command's RunE
	// can just read globals.* and trust they're populated.
	root.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		resolveGlobals()
	}

	// Wire the subcommand tree. Each command lives in its own file
	// so this stays scannable as the surface grows.
	root.AddCommand(newVersionCommand())
	root.AddCommand(newCheckCommand())
	root.AddCommand(newTLSCommand())
	root.AddCommand(newDMARCCommand())
	root.AddCommand(newDNSCommand())
	root.AddCommand(newScamCommand())

	return root
}

// resolveGlobals fills empty global-flag values from environment
// variables. The order is flag > env > default.
func resolveGlobals() {
	if globals.APIBase == "" {
		if v := os.Getenv("POSTVALE_API"); v != "" {
			globals.APIBase = v
		} else {
			globals.APIBase = "https://postvale.app"
		}
	}
	if globals.Token == "" {
		if v := os.Getenv("POSTVALE_TOKEN"); v != "" {
			globals.Token = v
		}
	}
	// NO_COLOR (https://no-color.org/) is the universal opt-out.
	if !globals.NoColor && os.Getenv("NO_COLOR") != "" {
		globals.NoColor = true
	}
}

// newVersionCommand prints the build stamp + exits.
func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("postvale %s (commit %s, built %s)\n",
				version.Version, version.Commit, version.Date)
		},
	}
}
