package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newTLSCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tls <domain>",
		Aliases: []string{"ssl"},
		Short:   "TLS / SSL check (cert chain, protocols, HSTS)",
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

			result, err := client.CheckTLS(domain)
			if err != nil {
				return fmt.Errorf("tls %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Grade)
			} else {
				output.RenderTLS(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && output.ShouldFail(string(result.Grade)) {
				failExit()
			}
			return nil
		},
	}
}
