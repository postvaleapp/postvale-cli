package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/output"
)

func newCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check <domain>",
		Short: "Full posture report for a domain (TLS + DMARC + DNS + headers + more)",
		Long: `Run every available check against a domain and emit a one-shot
composite report with a single letter grade and the top
recommendations. Equivalent to https://wiredepth.com/check/<domain>.`,
		Args: cobra.ExactArgs(1),
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

			result, err := client.CheckFull(domain)
			if err != nil {
				return fmt.Errorf("check %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Grade)
			} else {
				output.RenderFullCheck(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && output.ShouldFail(string(result.Grade)) {
				failExit()
			}
			return nil
		},
	}
}
