package commands

import (
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/api"
	"github.com/WiredepthHQ/wiredepth-cli/internal/auth"
	"github.com/WiredepthHQ/wiredepth-cli/internal/tui"
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
  dashboard | noc | alerts | brand | leak | creds | vendors | cves | tools | verify | account | ext`,
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

			// Validate the token is still active server-side before
			// dropping into the TUI. The local credential file can
			// stick around long after the token was revoked from
			// /account or by a security event - same way `gh` and
			// `vercel` validate. Without this the shell renders
			// "logged in" chrome while every page fetches 401.
			if _, err := client.Me(); err != nil {
				if api.IsAuthError(err) {
					return fmt.Errorf("the stored token was rejected by the server " +
						"(revoked, expired, or password changed). Run `postvale auth login` to re-authenticate. " +
						"Browser logout does NOT revoke CLI tokens by design - use /account to revoke")
				}
				return fmt.Errorf("could not reach api: %w", err)
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
		"Page to land on: dashboard | noc | alerts | brand | leak | creds | vendors | cves | tools | verify | account | ext")
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
	case "brand", "brand-watch", "brand-watchlist":
		return tui.PageBrand, nil
	case "leak", "leaks", "leak-sites":
		return tui.PageLeak, nil
	case "creds", "credentials", "credential-leaks":
		return tui.PageCreds, nil
	case "vendors", "vendor-watch", "vendor-watchlist":
		return tui.PageVendors, nil
	case "cves", "vulns", "vulnerabilities":
		return tui.PageCves, nil
	case "tools":
		return tui.PageTools, nil
	case "verify":
		return tui.PageVerify, nil
	case "account":
		return tui.PageAccount, nil
	case "ext", "extension", "extension-billing":
		return tui.PageExtension, nil
	default:
		return tui.PageDashboard, fmt.Errorf("unknown page %q (try dashboard|noc|alerts|brand|leak|tools|verify|account)", s)
	}
}
