package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/output"
)

func newReputationCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "reputation <domain>",
		Aliases: []string{"threat-intel", "ti"},
		Short:   "Threat-intel reputation (malware / phishing / active IOC / domain age)",
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

			result, err := client.CheckThreatIntel(domain)
			if err != nil {
				return fmt.Errorf("reputation %s: %w", domain, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				flag := "clean"
				if result.AnyFlagged {
					flag = "flagged"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", result.Host, flag)
			} else {
				output.RenderThreatIntel(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && result.AnyFlagged {
				failExit()
			}
			return nil
		},
	}
}
