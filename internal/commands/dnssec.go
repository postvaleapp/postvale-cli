package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/output"
)

func newDnssecCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dnssec <domain>",
		Short: "DNSSEC chain validator (secure / insecure / bogus)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, err := normaliseDomain(args[0])
			if err != nil {
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			result, err := client.CheckDnssec(domain)
			if err != nil {
				return fmt.Errorf("dnssec %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Status)
			} else {
				output.RenderDnssec(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && result.Status == "bogus" {
				failExit()
			}
			return nil
		},
	}
}
