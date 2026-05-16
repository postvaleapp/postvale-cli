// Verb-group restructure for v2.1: `wd scan` parent + subcommands.
// Per docs/v2-migration.md, the new tree is `wd scan run | posture
// | cve | threat-intel | all`. The existing flat commands (wd tls,
// wd dmarc, wd dns, wd headers) stay live but become hidden aliases
// so muscle-memory keeps working through the rename window.
package commands

import (
	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run on-demand scans + posture grading",
		Long: `Run on-demand WireDepth scans. Subcommands target the
specific scan shape:

  wd scan run <domain>       full posture run (TLS + DMARC + DNS + headers + more)
  wd scan posture <domain>   one-pager grade card
  wd scan cve <domain>       CVE matches against detected stack
  wd scan threat-intel <X>   blocklist + IOC lookup
  wd scan all <domain>       everything, parallelised

Shorthand: ` + "`wd <domain>`" + ` is the same as ` + "`wd scan run <domain>`" + `.`,
	}
	cmd.AddCommand(newScanRunCommand())
	cmd.AddCommand(newScanPostureCommand())
	cmd.AddCommand(newScanCveCommand())
	cmd.AddCommand(newScanThreatIntelCommand())
	cmd.AddCommand(newScanAllCommand())
	return cmd
}

// `wd scan run` is the v2.1 way to call what `wd check` always did.
// We reuse the existing check command's RunE so behaviour is
// identical; the new command just gives the verb-group surface.
func newScanRunCommand() *cobra.Command {
	check := newCheckCommand()
	check.Use = "run <domain>"
	check.Short = "Run the full WireDepth posture scan on a domain"
	check.Aliases = nil
	return check
}

// `wd scan posture` reuses the existing scorecard pathway when
// shipped; placeholder until the scorecard subcommand lands.
func newScanPostureCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "posture <domain>",
		Short: "One-pager posture grade card",
		Long: `Render the at-a-glance posture grade card for a domain.

Currently mapped to the same engine as ` + "`wd scan run`" + ` with
the --format=pretty output style emphasising grades. Future v2.2
revision will fold in the standalone scorecard PDF flow.`,
		Args: cobra.ExactArgs(1),
		RunE: newCheckCommand().RunE,
	}
}

// `wd scan cve` placeholder - wired in v2.2 alongside the CVE-detail
// CLI surface. Today the same data is in `wd cves` (flat).
func newScanCveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "cve <domain>",
		Short: "CVE matches against detected tech stack (Pro+)",
		Long: `CVE matches for the technology fingerprinted on the
target domain. Pro+ feature; gated server-side.

Same data + auth as ` + "`wd cves`" + ` (flat command). The v2.1
release keeps the flat command for muscle memory.`,
		Args: cobra.ExactArgs(1),
		RunE: newCvesCommand().RunE,
	}
}

// `wd scan threat-intel` routes through the existing reputation
// command shape.
func newScanThreatIntelCommand() *cobra.Command {
	rep := newReputationCommand()
	rep.Use = "threat-intel <domain>"
	rep.Short = "Blocklist + IOC + IP-reputation lookup"
	rep.Aliases = []string{"ti", "reputation"}
	return rep
}

// `wd scan all` runs the full posture + threat-intel in parallel.
// v2.1 routes to `wd check` (which already triggers everything);
// future revisions split out the per-tool parallelism.
func newScanAllCommand() *cobra.Command {
	check := newCheckCommand()
	check.Use = "all <domain>"
	check.Short = "Run every scan + threat-intel against a domain"
	check.Aliases = nil
	return check
}
