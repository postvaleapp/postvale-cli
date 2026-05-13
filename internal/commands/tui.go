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
	var startPage string
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Full terminal client (dashboard, NOC, alerts, tools, verify, account)",
		Long: `Open the full Postvale terminal client. Sidebar nav across every
signed-in surface, no browser required.

  Tab          focus / unfocus the sidebar
  ↑/↓ or k/j   move within the sidebar
  ↵            open the highlighted page
  q            quit (from the sidebar)
  ctrl+c       quit (always)

Pages have their own key bindings; ? on a page shows the legend.

Start on a specific page with --page <name>:
  dashboard | noc | alerts | tools | verify | account`,
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

			start, err := parseShellPage(startPage)
			if err != nil {
				return err
			}
			model := tui.NewShell(client, Globals().APIBase, start)
			prog := tea.NewProgram(model,
				tea.WithAltScreen(),
				tea.WithMouseCellMotion(),
			)
			if _, err := prog.Run(); err != nil {
				return fmt.Errorf("tui: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&startPage, "page", "dashboard",
		"Page to land on: dashboard | noc | alerts | tools | verify | account")
	return cmd
}

// parseShellPage maps the --page flag to a ShellPage enum value.
func parseShellPage(s string) (tui.ShellPage, error) {
	switch s {
	case "", "dashboard":
		return tui.PageDashboard, nil
	case "noc":
		return tui.PageNoc, nil
	case "alerts":
		return tui.PageAlerts, nil
	case "tools":
		return tui.PageTools, nil
	case "verify":
		return tui.PageVerify, nil
	case "account":
		return tui.PageAccount, nil
	default:
		return tui.PageDashboard, fmt.Errorf("unknown page %q (try dashboard|noc|alerts|tools|verify|account)", s)
	}
}
