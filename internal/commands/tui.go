package commands

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/auth"
	"github.com/postvaleapp/postvale-cli/internal/tui"
)

func newTuiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive dashboard for your monitored domains",
		Long: `Open an interactive dashboard.

  ↑/↓ or k/j   move between domains
  ↵            details for the selected row
  r            refresh
  o            open the web dashboard for context
  ?            full keyboard help
  q            quit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			// Refuse to launch the TUI without a token - every panel
			// hits authenticated routes, so the user would just see
			// "Could not load dashboard: 401" and quit. Surface the
			// hint at the command line where they can act on it.
			if _, err := auth.Load(); err != nil && Globals().Token == "" {
				if errors.Is(err, auth.ErrNotLoggedIn) {
					return fmt.Errorf("not signed in - run `postvale auth login` first")
				}
				return err
			}

			model := tui.New(client, Globals().APIBase)
			prog := tea.NewProgram(model, tea.WithAltScreen())
			if _, err := prog.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}
			return nil
		},
	}
}
