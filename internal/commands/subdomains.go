package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/output"
)

func newSubdomainsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "subdomains <domain>",
		Short: "Subdomain inventory from public CT logs",
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

			result, err := client.CheckSubdomains(domain)
			if err != nil {
				return fmt.Errorf("subdomains %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %d\n", result.Host, result.Count)
			} else {
				output.RenderSubdomains(cmd.OutOrStdout(), result)
			}
			return nil
		},
	}
}
