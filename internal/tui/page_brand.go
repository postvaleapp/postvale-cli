package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/cli/internal/api"
)

// BrandWatchPage renders the user's brand-watchlist keywords + the
// most recent lookalike matches in the last 30 days. Pro-tier
// feature; the page surfaces a buy-CTA hint when /api/v1/brand-
// watchlist returns 402.

type brandLoadedMsg struct {
	data *api.BrandWatchlistResp
	err  error
}

type BrandWatchPage struct {
	client *api.Client

	width  int
	height int

	loading bool
	data    *api.BrandWatchlistResp
	err     error
}

func newBrandWatchPage(client *api.Client) BrandWatchPage {
	return BrandWatchPage{client: client, loading: true}
}

func (m BrandWatchPage) Init() tea.Cmd {
	return m.fetch()
}

func (m BrandWatchPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.BrandWatchlist()
		return brandLoadedMsg{data: d, err: err}
	}
}

func (m BrandWatchPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case brandLoadedMsg:
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

func (m BrandWatchPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Brand watchlist",
		"typosquats + lookalike domain hits"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading brand watchlist..."))
		return b.String()
	}
	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
			b.WriteString("  " + StyleWarn.Render("Pro / Power / MSP required."))
			b.WriteString("\n  " + StyleDim.Render(
				"Brand watchlist is paywalled. Upgrade at https://wiredepth.com/pricing"))
		} else {
			b.WriteString("  " + StyleFail.Render("Could not load brand watchlist:"))
			b.WriteString("\n  " + StyleDim.Render(msg))
			b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		}
		return b.String()
	}
	if m.data == nil {
		return b.String()
	}

	// Keywords pane.
	b.WriteString("  " + StyleLabel.Render("KEYWORDS") + "  " +
		StyleDim.Render(fmt.Sprintf("%d tracked", len(m.data.Watchlists))) + "\n\n")
	if len(m.data.Watchlists) == 0 {
		b.WriteString("  " + StyleDim.Render(
			"No keywords yet. Set them up at /dashboard/brand-watchlist on the web.") + "\n\n")
	} else {
		for _, w := range m.data.Watchlists {
			state := StyleOK.Render("active")
			if !w.IsActive {
				state = StyleDim.Render("paused")
			}
			last := "-"
			if w.LastScannedAt != nil {
				last = ago(*w.LastScannedAt) + " ago"
			}
			label := w.Keyword
			if w.Label != nil && *w.Label != "" {
				label = fmt.Sprintf("%s  %s",
					w.Keyword,
					StyleDim.Render("("+*w.Label+")"),
				)
			}
			b.WriteString(fmt.Sprintf("  %s  %s  %s\n",
				padRight(label, 38),
				state,
				StyleDim.Render("scanned "+last),
			))
		}
		b.WriteString("\n")
	}

	// Matches pane.
	b.WriteString("  " + StyleLabel.Render(
		fmt.Sprintf("RECENT MATCHES (%dd window)", m.data.MatchWindowDays)) +
		"  " + StyleDim.Render(fmt.Sprintf("%d shown", len(m.data.Matches))) + "\n\n")
	if len(m.data.Matches) == 0 {
		b.WriteString("  " + StyleDim.Render("No matches in the window."))
		b.WriteString("\n\n  " + StyleDim.Render("r refresh"))
		return b.String()
	}

	candidateW := 36
	sourceW := 14
	threatW := 10
	kitW := 14
	seenW := 12
	header := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		padRight("CANDIDATE", candidateW),
		padRight("VIA", sourceW),
		padRight("RECORDS", 9),
		padRight("THREAT", threatW),
		padRight("KIT", kitW),
		padRight("FIRST SEEN", seenW),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, mm := range m.data.Matches {
		records := recordsTriplet(mm.HasA, mm.HasMx, mm.HasNs)
		threat := "-"
		if mm.ThreatIntelListed != nil && *mm.ThreatIntelListed {
			threat = StyleFail.Render("listed")
		} else if mm.ThreatIntelGrade != nil && *mm.ThreatIntelGrade != "" {
			threat = StyleWarn.Render(*mm.ThreatIntelGrade)
		} else if mm.ThreatIntelListed != nil {
			threat = StyleOK.Render("clean")
		}
		kit := "-"
		if mm.KitScore != nil && *mm.KitScore != "" {
			label := *mm.KitScore
			if mm.KitBrand != nil && *mm.KitBrand != "" {
				label = *mm.KitScore + " " + *mm.KitBrand
			}
			switch *mm.KitScore {
			case "high":
				kit = StyleFail.Render(label)
			case "medium":
				kit = StyleWarn.Render(label)
			default:
				kit = StyleDim.Render(label)
			}
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
			padRight(truncate(mm.Candidate, candidateW), candidateW),
			padRight(truncate(mm.Source, sourceW), sourceW),
			padRight(records, 9),
			padRight(threat, threatW),
			padRight(truncate(kit, kitW), kitW),
			padRight(ago(mm.FirstSeenAt)+" ago", seenW),
		)
		b.WriteString(row + "\n")
	}

	b.WriteString("\n  " + StyleDim.Render(
		"r refresh  ·  Tab nav  ·  edit + takedown packs at /dashboard/brand-watchlist on the web"))
	return b.String()
}

// recordsTriplet renders an A/MX/NS strip. "✓·· a·mx·ns" = A only.
func recordsTriplet(a, mx, ns bool) string {
	mark := func(present bool) string {
		if present {
			return StyleOK.Render("✓")
		}
		return StyleDim.Render("·")
	}
	return mark(a) + mark(mx) + mark(ns) + "  " +
		StyleDim.Render("a·mx·ns")
}
