package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/output"
)

func newSpoofCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "spoof <domain>",
		Aliases: []string{"spoofability"},
		Short:   "Can this domain be spoofed? (yes / maybe / no)",
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

			result, err := client.CheckSpoofability(domain)
			if err != nil {
				return fmt.Errorf("spoof %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, result.Verdict)
			} else {
				output.RenderSpoofability(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && result.Verdict == "yes" {
				failExit()
			}
			return nil
		},
	}
}
