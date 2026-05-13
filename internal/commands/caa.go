package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newCaaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "caa <domain>",
		Short: "CAA records (which CAs may issue certs for this domain)",
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

			result, err := client.CheckCaa(domain)
			if err != nil {
				return fmt.Errorf("caa %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Verdict)
			} else {
				output.RenderCaa(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && result.Verdict == "missing" {
				failExit()
			}
			return nil
		},
	}
}
