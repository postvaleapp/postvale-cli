package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/auth"
)

// `wd brand`, `wd leaks`, `wd creds`, `postvale
// vendors-monitor`, `wd cves` - one-shot CLI versions of the
// five Pro+ TUI monitoring tabs. Each wraps the matching api.Client
// method, supports --json for machine output, and human-renders a
// compact table by default. Aliases match the catalog slugs so muscle
// memory from the web sidebar carries over.

func newBrandWatchCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "brand",
		Aliases: []string{"brand-watch", "brand-watchlist"},
		Short:   "Brand watchlist findings (Pro+): keywords + lookalike matches",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := authClient()
			if err != nil {
				return err
			}
			data, err := client.BrandWatchlist()
			if err != nil {
				return wrap402(err, "brand-watchlist")
			}
			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(data)
			}
			fmt.Printf("Keywords: %d tracked\n", len(data.Watchlists))
			for _, w := range data.Watchlists {
				state := "active"
				if !w.IsActive {
					state = "paused"
				}
				label := ""
				if w.Label != nil && *w.Label != "" {
					label = " (" + *w.Label + ")"
				}
				fmt.Printf("  %-30s  %s%s\n",
					truncateStr(w.Keyword, 30), state, label)
			}
			fmt.Printf("\nMatches: %d in last %dd\n",
				len(data.Matches), data.MatchWindowDays)
			for _, m := range data.Matches {
				threat := "-"
				if m.ThreatIntelListed != nil && *m.ThreatIntelListed {
					threat = "listed"
				}
				kit := "-"
				if m.KitScore != nil && *m.KitScore != "" {
					kit = *m.KitScore
				}
				fmt.Printf("  %-32s  via %-12s  threat=%-7s  kit=%s\n",
					truncateStr(m.Candidate, 32),
					m.Source, threat, kit)
			}
			return nil
		},
	}
}

func newLeakSitesCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "leaks",
		Aliases: []string{"leak-sites"},
		Short:   "Ransomware / extortion mentions of your apex (Pro+)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := authClient()
			if err != nil {
				return err
			}
			data, err := client.LeakSites()
			if err != nil {
				return wrap402(err, "leak-sites")
			}
			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(data)
			}
			fmt.Printf("Findings: %d (limit %d)\n\n",
				data.Count, data.Limit)
			if len(data.Findings) == 0 {
				fmt.Println("  No leak-site posts match your apex or watchlist.")
				return nil
			}
			for _, f := range data.Findings {
				state := "new"
				if f.Alerted {
					state = "seen"
				}
				fmt.Printf("  [%s] %-14s  victim=%-30s  matched=%s\n",
					state,
					truncateStr(f.GroupName, 14),
					truncateStr(f.VictimTitle, 30),
					f.Match)
			}
			return nil
		},
	}
}

func newCredentialLeaksCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "creds",
		Aliases: []string{"credential-leaks", "credentials"},
		Short:   "Addresses at your apex in breach corpora (Pro+)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := authClient()
			if err != nil {
				return err
			}
			data, err := client.CredentialLeaks()
			if err != nil {
				return wrap402(err, "credential-leaks")
			}
			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(data)
			}
			fmt.Printf("Findings: %d (limit %d)\n\n",
				data.Count, data.Limit)
			if len(data.Findings) == 0 {
				fmt.Println("  No breach exposures at any monitored apex.")
				return nil
			}
			for _, f := range data.Findings {
				domain := "-"
				if f.Domain != nil {
					domain = *f.Domain
				}
				count := "?"
				if f.AccountCount != nil {
					count = fmt.Sprintf("%d", *f.AccountCount)
				}
				breach := f.BreachName
				if f.BreachTitle != nil && *f.BreachTitle != "" {
					breach = *f.BreachTitle
				}
				date := "-"
				if f.BreachDate != nil && len(*f.BreachDate) >= 10 {
					date = (*f.BreachDate)[:10]
				}
				fmt.Printf("  %-22s  %-28s  %s accounts  classes=%s  date=%s\n",
					truncateStr(domain, 22),
					truncateStr(breach, 28),
					count,
					strings.Join(f.DataClasses, ","),
					date)
			}
			return nil
		},
	}
}

func newVendorWatchCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "vendors-monitor",
		Aliases: []string{"vendor-watch", "vendor-watchlist"},
		Short:   "Continuous posture across your tracked third-party vendors (Pro+)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := authClient()
			if err != nil {
				return err
			}
			data, err := client.VendorWatchlist()
			if err != nil {
				return wrap402(err, "vendors")
			}
			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(data)
			}
			fmt.Printf("Vendors: %d watched\n\n", data.Count)
			if len(data.Vendors) == 0 {
				fmt.Println("  No vendors yet. Add at /dashboard/vendors.")
				return nil
			}
			for _, v := range data.Vendors {
				grade := "-"
				if v.LastSnapshot != nil && v.LastSnapshot.Overall != "" {
					grade = v.LastSnapshot.Overall
				}
				state := "active"
				if !v.IsActive {
					state = "paused"
				} else if v.LastError != nil && *v.LastError != "" {
					state = "error"
				}
				label := ""
				if v.Label != nil && *v.Label != "" {
					label = " (" + *v.Label + ")"
				}
				fmt.Printf("  %-28s%-18s grade=%-3s state=%s\n",
					truncateStr(v.Domain, 28),
					truncateStr(label, 18),
					grade, state)
			}
			return nil
		},
	}
}

func newCvesCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "cves",
		Aliases: []string{"vulnerabilities", "vulns"},
		Short:   "CRITICAL + HIGH CVEs against your detected tech stack (Pro+)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := authClient()
			if err != nil {
				return err
			}
			data, err := client.Vulnerabilities()
			if err != nil {
				return wrap402(err, "vulnerabilities")
			}
			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(data)
			}
			fmt.Printf("Findings: %d (limit %d)\n\n",
				data.Count, data.Limit)
			if len(data.Findings) == 0 {
				fmt.Println("  No CVEs match the detected stack.")
				return nil
			}
			for _, f := range data.Findings {
				ver := "-"
				if f.Version != nil {
					ver = *f.Version
				}
				dom := "-"
				if f.Domain != nil {
					dom = *f.Domain
				}
				cvss := "-"
				if f.CVSS != nil {
					cvss = *f.CVSS
				}
				sev := ""
				if f.Severity != nil {
					sev = *f.Severity
				}
				fmt.Printf("  %-18s  %-22s  %-12s  CVSS=%-4s [%s]  apex=%s\n",
					truncateStr(f.CveID, 18),
					truncateStr(f.Product, 22),
					truncateStr(ver, 12),
					cvss, sev,
					truncateStr(dom, 24))
			}
			return nil
		},
	}
}

// authClient wraps the standard newClient() with a not-signed-in
// short-circuit so every monitoring command surfaces the same hint
// when the user forgot to log in.
func authClient() (*api.Client, error) {
	if _, err := auth.Load(); err != nil && Globals().Token == "" {
		if errors.Is(err, auth.ErrNotLoggedIn) {
			return nil, fmt.Errorf("not signed in - run `wd auth login` first")
		}
		return nil, err
	}
	return newClient()
}

// wrap402 returns a friendlier message when the user hits a Pro+ gate.
// Keeps the same shape as the TUI page so the experience matches.
func wrap402(err error, tool string) error {
	msg := err.Error()
	if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
		return fmt.Errorf("%s requires Pro / Power / MSP. See https://wiredepth.com/pricing", tool)
	}
	return fmt.Errorf("%s: %w", tool, err)
}
