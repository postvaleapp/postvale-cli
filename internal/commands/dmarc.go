package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/output"
)

func newDMARCCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dmarc <domain>",
		Short: "DMARC + SPF posture (policy, alignment, recommendations)",
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

			result, err := client.CheckDMARC(domain)
			if err != nil {
				return fmt.Errorf("dmarc %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Grade)
			} else {
				output.RenderDMARC(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && output.ShouldFail(string(result.Grade)) {
				failExit()
			}
			return nil
		},
	}
}
