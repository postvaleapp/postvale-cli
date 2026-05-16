package commands

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/auth"
	"github.com/WiredepthHQ/cli/internal/tui"
)

func newNocCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "noc",
		Short: "Live operations console (shortcut for `tui --page noc`)",
		Long: `Fast-launch into the NOC tab of the full TUI: aggregate posture
stats, action queue, and a tail of scan events across every monitored
domain.

  p   pause / resume polling
  r   refresh now
  ?   full help
  Tab focus the sidebar to switch tabs
  q   quit

Equivalent to: postvale tui --page noc`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			if _, err := auth.Load(); err != nil && Globals().Token == "" {
				if errors.Is(err, auth.ErrNotLoggedIn) {
					return fmt.Errorf("not signed in - run `wd auth login` first")
				}
				return err
			}

			// Validate the token round-trips before launching. Without
			// this the NOC just renders blank panels + auth errors;
			// surfacing the cause at the command line is friendlier.
			if _, err := client.Me(); err != nil {
				if api.IsAuthError(err) {
					return fmt.Errorf("the stored token was rejected by the server " +
						"(revoked, expired, or password changed). Run `wd auth login` to re-authenticate")
				}
				return fmt.Errorf("could not reach api: %w", err)
			}

			model := tui.NewShell(client, Globals().APIBase, tui.PageNoc)
			prog := tea.NewProgram(model,
				tea.WithAltScreen(),
				tea.WithMouseCellMotion(),
			)
			if _, err := prog.Run(); err != nil {
				return fmt.Errorf("noc: %w", err)
			}
			return nil
		},
	}
}
