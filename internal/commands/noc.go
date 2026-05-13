package commands

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/auth"
	"github.com/postvaleapp/postvale-cli/internal/tui"
)

func newNocCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "noc",
		Short: "Live operations console (mirrors /dashboard/noc on the web)",
		Long: `Open the live NOC console: aggregate posture stats, action
queue, and a tail of scan events across every domain you monitor.

Polls the API in the background:
  - summary  every 30s
  - live feed every  6s

Keys:
  p   pause / resume polling
  r   refresh now
  ?   full help
  q   quit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			if _, err := auth.Load(); err != nil && Globals().Token == "" {
				if errors.Is(err, auth.ErrNotLoggedIn) {
					return fmt.Errorf("not signed in - run `postvale auth login` first")
				}
				return err
			}

			model := tui.NewNoc(client)
			prog := tea.NewProgram(model,
				tea.WithAltScreen(),
				// MouseCellMotion routes wheel events through tea so
				// the detail viewport can scroll on scroll wheel.
				tea.WithMouseCellMotion(),
			)
			if _, err := prog.Run(); err != nil {
				return fmt.Errorf("noc: %w", err)
			}
			return nil
		},
	}
}
