package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newDNSCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dns <domain>",
		Short: "DNS health (DNSSEC, CAA, registrar, mail blocklists)",
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

			result, err := client.CheckDNS(domain)
			if err != nil {
				return fmt.Errorf("dns %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Grade)
			} else {
				output.RenderDNS(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && output.ShouldFail(string(result.Grade)) {
				failExit()
			}
			return nil
		},
	}
}
