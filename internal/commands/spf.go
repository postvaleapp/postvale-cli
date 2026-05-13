package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

// `postvale spf flatten <domain>` mirrors the web tool. We group
// SPF subcommands under a parent so room exists for spf validate /
// spf generate later.
func newSpfCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spf",
		Short: "SPF utilities (flatten)",
	}
	cmd.AddCommand(newSpfFlattenCommand())
	return cmd
}

func newSpfFlattenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "flatten <domain>",
		Short: "Resolve SPF include: chains to a 0-DNS-lookup record",
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

			result, err := client.CheckSpfFlatten(domain)
			if err != nil {
				return fmt.Errorf("spf flatten %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			output.RenderSpfFlatten(cmd.OutOrStdout(), result)
			return nil
		},
	}
}
