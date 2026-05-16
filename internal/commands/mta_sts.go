package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/output"
)

func newMtaStsCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "mta-sts <domain>",
		Aliases: []string{"mtasts"},
		Short:   "MTA-STS + TLS-RPT (mail transport encryption policy)",
		Args:    cobra.ExactArgs(1),
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

			result, err := client.CheckMtaSts(domain)
			if err != nil {
				return fmt.Errorf("mta-sts %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Grade)
			} else {
				output.RenderMtaSts(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && output.ShouldFail(string(result.Grade)) {
				failExit()
			}
			return nil
		},
	}
}
