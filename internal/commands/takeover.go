package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newTakeoverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "takeover <subdomain>",
		Short: "Subdomain takeover scan (dangling CNAME against 20+ service fingerprints)",
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

			result, err := client.CheckTakeover(domain)
			if err != nil {
				return fmt.Errorf("takeover %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Verdict)
			} else {
				output.RenderTakeover(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && (result.Verdict == "vulnerable" || result.Verdict == "suspicious") {
				failExit()
			}
			return nil
		},
	}
}
