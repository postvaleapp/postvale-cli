package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/output"
)

func newAlertsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "alerts",
		Short: "List configured alert endpoints (webhooks, email)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			endpoints, err := client.ListAlerts()
			if err != nil {
				return fmt.Errorf("alerts: %w", err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), endpoints)
			}

			if len(endpoints) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
					"No alert endpoints configured. Add one at "+Globals().APIBase+"/alerts",
				))
				return nil
			}

			for _, e := range endpoints {
				state := output.StyleOK.Render("on")
				if !e.Enabled {
					state = output.StyleDim.Render("off")
				}
				target := e.URL
				if target == "" {
					target = e.EmailTo
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %s  %s  %s  %s\n",
					state,
					output.StyleStrong.Render(e.Label),
					output.StyleDim.Render(fmt.Sprintf("[%s]", e.Kind)),
					output.StyleDim.Render(target),
				)
			}
			return nil
		},
	}
}
