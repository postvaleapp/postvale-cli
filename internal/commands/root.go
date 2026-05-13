// Package commands is the cobra command tree. One file per subcommand.
package commands

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/version"
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
		Use:   "postvale",
		Short: "Domain posture + email security checks from the terminal",
		Long: `Postvale CLI. TLS, DMARC, DNS, threat-intel, and audit
evidence for any public domain.

Free read-only checks need no sign-in. Sign in with ` + "`postvale auth login`" + `
for monitoring, workpapers, and Pro features.

Designed for the terminal AND for CI. Use --json for machine output
and --exit-on-fail to gate deploys on posture grades.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&globals.APIBase, "api", "", "Postvale API base URL (default https://postvale.app)")
	pf.StringVar(&globals.Token, "token", "", "API token (overrides stored credential)")
	pf.BoolVar(&globals.JSON, "json", false, "Output structured JSON instead of pretty text")
	pf.BoolVarP(&globals.Quiet, "quiet", "q", false, "Suppress non-essential output")
	pf.BoolVar(&globals.NoColor, "no-color", false, "Disable ANSI colors (auto-disabled on non-TTY)")
	pf.BoolVar(&globals.ExitOnFail, "exit-on-fail", false, "Exit 1 when the result indicates a failing posture")
	pf.IntVar(&globals.Timeout, "timeout", 30, "Per-request timeout in seconds")
	pf.StringVar(&globals.ConfigPath, "config", "", "Path to config file (default ~/.config/postvale/config.yaml)")

	root.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		resolveGlobals()
	}

	root.AddCommand(newVersionCommand())
	root.AddCommand(newAuthCommand())
	root.AddCommand(newCheckCommand())
	root.AddCommand(newTLSCommand())
	root.AddCommand(newDMARCCommand())
	root.AddCommand(newDNSCommand())
	root.AddCommand(newHeadersCommand())
	root.AddCommand(newMtaStsCommand())
	root.AddCommand(newBimiCommand())
	root.AddCommand(newDnssecCommand())
	root.AddCommand(newCaaCommand())
	root.AddCommand(newSubdomainsCommand())
	root.AddCommand(newTakeoverCommand())
	root.AddCommand(newSpoofCommand())
	root.AddCommand(newSpfCommand())
	root.AddCommand(newReputationCommand())
	root.AddCommand(newScamCommand())

	return root
}

// Fills empty global-flag values from env vars. Flag > env > default.
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
			cmd.Printf("postvale %s (commit %s, built %s)\n",
				version.Version, version.Commit, version.Date)
		},
	}
}
