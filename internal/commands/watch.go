package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/output"
)

func newWatchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Manage continuously-monitored domains (Pro+)",
		Long: `  postvale watch <domain>            Add a domain to monitoring
  postvale watch list                List monitored domains
  postvale watch remove <domain>     Stop monitoring a domain`,
	}
	cmd.AddCommand(newWatchAddCommand())
	cmd.AddCommand(newWatchListCommand())
	cmd.AddCommand(newWatchRemoveCommand())
	return cmd
}

func newWatchAddCommand() *cobra.Command {
	var label string
	var cadence int
	var port int
	cmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a domain to continuous monitoring",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, err := normaliseDomain(args[0])
			if err != nil {
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			req := &api.AddDomainRequest{
				Host:           host,
				Port:           port,
				Label:          label,
				CadenceMinutes: cadence,
			}
			added, err := client.AddDomain(req)
			if err != nil {
				return fmt.Errorf("watch add %s: %w", host, err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), added)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s monitoring %s\n",
				output.StyleOK.Render("✓"),
				output.StyleStrong.Render(fmt.Sprintf("%s:%d", added.Host, added.Port)),
			)
			fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
				fmt.Sprintf("  cadence: %dm | id: %s", added.CadenceMinutes, added.ID),
			))
			return nil
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "Human-friendly label")
	cmd.Flags().IntVar(&cadence, "cadence", 0, "Re-check cadence in minutes (clamped to your plan's floor)")
	cmd.Flags().IntVar(&port, "port", 443, "TLS port to probe (default 443)")
	return cmd
}

func newWatchListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List currently-monitored domains",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			domains, err := client.ListDomains()
			if err != nil {
				return fmt.Errorf("watch list: %w", err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), domains)
			}

			if len(domains) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
					"No domains monitored. Add one with `wd watch add <domain>`.",
				))
				return nil
			}

			for _, d := range domains {
				grade := d.LastWorstGrade
				if grade == "" {
					grade = "-"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %s  %s  %s\n",
					output.GradeStyle(grade).Render(padGrade(grade)),
					output.StyleStrong.Render(fmt.Sprintf("%s:%d", d.Host, d.Port)),
					output.StyleDim.Render(fmt.Sprintf("cadence %dm | id %s", d.CadenceMinutes, d.ID)),
				)
			}
			return nil
		},
	}
}

func newWatchRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <domain-or-id>",
		Aliases: []string{"rm"},
		Short:   "Stop monitoring a domain (by host or id)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			needle := strings.ToLower(strings.TrimSpace(args[0]))
			if needle == "" {
				return fmt.Errorf("domain or id required")
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			id := needle
			// If it doesn't look like a UUID, treat it as a hostname
			// and resolve to an id via list lookup.
			if !looksLikeUUID(needle) {
				domains, err := client.ListDomains()
				if err != nil {
					return fmt.Errorf("watch remove: %w", err)
				}
				match := ""
				for _, d := range domains {
					if strings.EqualFold(d.Host, needle) {
						match = d.ID
						break
					}
				}
				if match == "" {
					return fmt.Errorf("no monitored domain matches %q", needle)
				}
				id = match
			}

			if err := client.DeleteDomain(id); err != nil {
				return fmt.Errorf("watch remove: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s removed %s\n",
				output.StyleOK.Render("✓"),
				output.StyleStrong.Render(needle),
			)
			return nil
		},
	}
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, ch := range s {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}
	return true
}

func padGrade(g string) string {
	if len(g) == 1 {
		return g + " "
	}
	return g
}
