package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/wiredepth-cli/internal/api"
)

// LeakSitesPage shows ransomware leak-site / extortion-post mentions
// matched against the caller's monitored apexes + active brand
// watchlists. Pro+ feature; the page surfaces a buy-CTA hint when
// /api/v1/leak-sites returns 402.

type leakLoadedMsg struct {
	data *api.LeakSitesResp
	err  error
}

type LeakSitesPage struct {
	client *api.Client

	width  int
	height int

	loading bool
	data    *api.LeakSitesResp
	err     error
}

func newLeakSitesPage(client *api.Client) LeakSitesPage {
	return LeakSitesPage{client: client, loading: true}
}

func (m LeakSitesPage) Init() tea.Cmd {
	return m.fetch()
}

func (m LeakSitesPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.LeakSites()
		return leakLoadedMsg{data: d, err: err}
	}
}

func (m LeakSitesPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case leakLoadedMsg:
		m.loading = false
		m.data = msg.data
		m.err = msg.err
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			m.loading = true
			m.err = nil
			return m, m.fetch()
		}
	}
	return m, nil
}

func (m LeakSitesPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Leak sites",
		"ransomware + extortion mentions of your apex"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading leak-site findings..."))
		return b.String()
	}
	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
			b.WriteString("  " + StyleWarn.Render("Pro / Power / MSP required."))
			b.WriteString("\n  " + StyleDim.Render(
				"Leak-site monitoring is paywalled. Upgrade at https://wiredepth.com/pricing"))
		} else {
			b.WriteString("  " + StyleFail.Render("Could not load leak-site findings:"))
			b.WriteString("\n  " + StyleDim.Render(msg))
			b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		}
		return b.String()
	}
	if m.data == nil {
		return b.String()
	}

	b.WriteString("  " + StyleLabel.Render("FINDINGS") + "  " +
		StyleDim.Render(fmt.Sprintf("%d in window · limit %d",
			m.data.Count, m.data.Limit)) + "\n\n")
	if len(m.data.Findings) == 0 {
		b.WriteString("  " + StyleOK.Render("✓ No leak-site posts match your apex or watchlist keywords."))
		b.WriteString("\n\n  " + StyleDim.Render(
			"Workers poll public leak-site aggregators every 15 minutes."))
		b.WriteString("\n  " + StyleDim.Render(
			"r refresh  ·  Tab nav"))
		return b.String()
	}

	groupW := 14
	victimW := 32
	matchW := 18
	sourceW := 14
	seenW := 12
	header := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		padRight("GROUP", groupW),
		padRight("VICTIM", victimW),
		padRight("MATCHED", matchW),
		padRight("VIA", sourceW),
		padRight("STATE", 6),
		padRight("LAST SEEN", seenW),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, f := range m.data.Findings {
		state := StyleWarn.Render("new")
		if f.Alerted {
			state = StyleDim.Render("seen")
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
			padRight(truncate(f.GroupName, groupW), groupW),
			padRight(truncate(f.VictimTitle, victimW), victimW),
			padRight(truncate(f.Match, matchW), matchW),
			padRight(truncate(humaniseMatchSource(f.MatchSource), sourceW), sourceW),
			padRight(state, 6),
			padRight(ago(f.LastSeenAt)+" ago", seenW),
		)
		b.WriteString(row + "\n")
	}

	b.WriteString("\n  " + StyleDim.Render(
		"r refresh  ·  Tab nav  ·  full post + IR runbook at /dashboard/leak-sites on the web"))
	return b.String()
}

// humaniseMatchSource flips the snake-case enum coming from the DB
// into something readable on the TUI ("monitored_domain" -> "apex").
func humaniseMatchSource(s string) string {
	switch s {
	case "monitored_domain":
		return "apex"
	case "brand_watchlist":
		return "brand watch"
	default:
		return s
	}
}
