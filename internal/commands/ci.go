package commands

import (
	"github.com/spf13/cobra"
)

// `postvale ci <subcommand>` is a thin preset: every subcommand
// here forces --quiet, --no-color, and --exit-on-fail on top of
// the underlying check. Pre-deploy hooks get short summary output
// + a meaningful exit code without remembering the flag soup.
func newCiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ci",
		Short: "CI-optimised wrappers around the check commands",
		Long: `Convenience presets for CI / pre-deploy hooks.

Every subcommand forces --quiet, --no-color, and --exit-on-fail
so the run summary stays small and the exit code drives the
pipeline.

  postvale ci check <domain>       Full posture
  postvale ci tls <domain>         TLS only
  postvale ci dmarc <domain>       DMARC only
  postvale ci dns <domain>         DNS health
  postvale ci headers <domain>     Security headers
  postvale ci dnssec <domain>      DNSSEC chain
  postvale ci spoof <domain>       Spoofability
  postvale ci takeover <sub>       Subdomain takeover`,
	}

	cmd.AddCommand(wrapForCI("check", newCheckCommand()))
	cmd.AddCommand(wrapForCI("tls", newTLSCommand()))
	cmd.AddCommand(wrapForCI("dmarc", newDMARCCommand()))
	cmd.AddCommand(wrapForCI("dns", newDNSCommand()))
	cmd.AddCommand(wrapForCI("headers", newHeadersCommand()))
	cmd.AddCommand(wrapForCI("dnssec", newDnssecCommand()))
	cmd.AddCommand(wrapForCI("spoof", newSpoofCommand()))
	cmd.AddCommand(wrapForCI("takeover", newTakeoverCommand()))
	return cmd
}

// wrapForCI returns a cobra command whose RunE flips the global
// CI flags ON before delegating to the underlying command's
// existing RunE. Avoids duplicating any check logic; the
// rendering / exit-code rules stay in one place.
func wrapForCI(name string, base *cobra.Command) *cobra.Command {
	orig := base.RunE
	base.Use = name + " <domain>"
	base.Short = "[ci] " + base.Short
	base.SilenceUsage = true
	base.RunE = func(c *cobra.Command, args []string) error {
		g := Globals()
		g.Quiet = true
		g.NoColor = true
		g.ExitOnFail = true
		if orig == nil {
			return nil
		}
		return orig(c, args)
	}
	return base
}
