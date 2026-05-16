// Package commands is the cobra command tree. One file per subcommand.
package commands

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/version"
)

// Persistent flag values, populated by cobra before RunE fires.
type GlobalFlags struct {
	APIBase    string
	Token      string
	JSON       bool
	Quiet      bool
	NoColor    bool
	ExitOnFail bool
	Timeout    int
	ConfigPath string
}

var globals GlobalFlags

func Globals() *GlobalFlags { return &globals }

// NewRootCommand builds a fresh command tree. Constructed (not
// package-level) so tests can spin one up per case.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "wd",
		Short: "WireDepth EASM checks + monitoring from the terminal",
		Long: `WireDepth CLI. External attack surface monitoring,
TLS / DMARC / DNS posture, threat intel, audit-chain evidence packs.

Free read-only checks need no sign-in. Sign in with ` + "`wd auth login`" + `
for monitoring, workpapers, and Pro features.

Designed for the terminal AND for CI. Use --json for machine output
and --exit-on-fail to gate deploys on posture grades.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&globals.APIBase, "api", "", "WireDepth API base URL (default https://wiredepth.com)")
	pf.StringVar(&globals.Token, "token", "", "API token (overrides stored credential)")
	pf.BoolVar(&globals.JSON, "json", false, "Output structured JSON instead of pretty text")
	pf.BoolVarP(&globals.Quiet, "quiet", "q", false, "Suppress non-essential output")
	pf.BoolVar(&globals.NoColor, "no-color", false, "Disable ANSI colors (auto-disabled on non-TTY)")
	pf.BoolVar(&globals.ExitOnFail, "exit-on-fail", false, "Exit 1 when the result indicates a failing posture")
	pf.IntVar(&globals.Timeout, "timeout", 30, "Per-request timeout in seconds")
	pf.StringVar(&globals.ConfigPath, "config", "", "Path to config file (default ~/.config/wiredepth/config.yaml)")

	root.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		resolveGlobals()
	}

	root.AddCommand(newVersionCommand())

	// v2.1 verb-group surface - the documented CLI shape going
	// forward. Commands below the verb groups (newCheckCommand
	// etc) stay live as hidden muscle-memory aliases through v2.x.
	root.AddCommand(newScanCommand())
	root.AddCommand(newAiCommand())
	root.AddCommand(newConfigCommand())
	root.AddCommand(newAuthCommand())

	// Flat-command surface from v2.0 (the original postvale shape).
	// Marked Hidden so `wd --help` no longer enumerates them, but
	// they remain directly invokable + reachable via `wd help <cmd>`.
	// Sunset planned for v3.0 once the verb groups settle.
	root.AddCommand(hidden(newCheckCommand()))
	root.AddCommand(hidden(newTLSCommand()))
	root.AddCommand(hidden(newDMARCCommand()))
	root.AddCommand(hidden(newDNSCommand()))
	root.AddCommand(hidden(newHeadersCommand()))
	root.AddCommand(hidden(newMtaStsCommand()))
	root.AddCommand(hidden(newBimiCommand()))
	root.AddCommand(hidden(newDnssecCommand()))
	root.AddCommand(hidden(newCaaCommand()))
	root.AddCommand(hidden(newSubdomainsCommand()))
	root.AddCommand(hidden(newTakeoverCommand()))
	root.AddCommand(hidden(newSpoofCommand()))
	root.AddCommand(hidden(newSpfCommand()))
	root.AddCommand(hidden(newReputationCommand()))
	root.AddCommand(hidden(newScamCommand()))

	// Surfaces that don't yet have a v2.1 verb-group home stay
	// visible. They get folded into wd watch / wd report / wd
	// findings in v2.2 alongside the server-side API endpoints
	// the verb groups need.
	root.AddCommand(newWatchCommand())
	root.AddCommand(newAlertsCommand())
	root.AddCommand(newWorkpaperCommand())
	root.AddCommand(newTuiCommand())
	root.AddCommand(newNocCommand())
	root.AddCommand(newCiCommand())
	root.AddCommand(newAuditCommand())
	root.AddCommand(newVendorsCommand())
	root.AddCommand(newEvidencePackCommand())

	// Pro+ monitoring surfaces. One-shot CLI versions of the matching
	// TUI tabs; same data, same Pro gate.
	root.AddCommand(newBrandWatchCommand())
	root.AddCommand(newLeakSitesCommand())
	root.AddCommand(newCredentialLeaksCommand())
	root.AddCommand(newVendorWatchCommand())
	root.AddCommand(newCvesCommand())
	root.AddCommand(newProbeCommand())

	return root
}

// hidden marks a command as Hidden=true so it doesn't appear in
// `wd --help` output but stays directly invokable + documented via
// `wd help <name>`. Used to retire the flat-command surface in
// favour of the verb groups while keeping muscle memory working.
func hidden(c *cobra.Command) *cobra.Command {
	c.Hidden = true
	return c
}

// Fills empty global-flag values from env vars. Flag > env > default.
// New env vars are WIREDEPTH_*; legacy POSTVALE_* read as fallback so
// existing CI pipelines continue to work through the rename window.
func resolveGlobals() {
	if globals.APIBase == "" {
		if v := os.Getenv("WIREDEPTH_API"); v != "" {
			globals.APIBase = v
		} else if v := os.Getenv("POSTVALE_API"); v != "" {
			globals.APIBase = v
		} else {
			globals.APIBase = "https://wiredepth.com"
		}
	}
	if globals.Token == "" {
		if v := os.Getenv("WIREDEPTH_TOKEN"); v != "" {
			globals.Token = v
		} else if v := os.Getenv("POSTVALE_TOKEN"); v != "" {
			globals.Token = v
		}
	}
	// https://no-color.org/
	if !globals.NoColor && os.Getenv("NO_COLOR") != "" {
		globals.NoColor = true
	}
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("wd %s (commit %s, built %s)\n",
				version.Version, version.Commit, version.Date)
		},
	}
}
