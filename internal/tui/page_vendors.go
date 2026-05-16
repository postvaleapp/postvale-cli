package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/wiredepth-cli/internal/api"
)

// VendorWatchPage shows the caller's vendor subscriptions + the most
// recent snapshot of each vendor's posture (overall grade, per-check
// worst grade, threat-intel summary). Pro+ feature.

type vendorLoadedMsg struct {
	data *api.VendorsResp
	err  error
}

type VendorWatchPage struct {
	client *api.Client

	width  int
	height int

	loading bool
	data    *api.VendorsResp
	err     error
}

func newVendorWatchPage(client *api.Client) VendorWatchPage {
	return VendorWatchPage{client: client, loading: true}
}

func (m VendorWatchPage) Init() tea.Cmd {
	return m.fetch()
}

func (m VendorWatchPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.VendorWatchlist()
		return vendorLoadedMsg{data: d, err: err}
	}
}

func (m VendorWatchPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case vendorLoadedMsg:
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

func (m VendorWatchPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Vendor watchlist",
		"continuous posture across your third-party stack"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading vendor watchlist..."))
		return b.String()
	}
	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
			b.WriteString("  " + StyleWarn.Render("Pro / Power / MSP required."))
			b.WriteString("\n  " + StyleDim.Render(
				"Vendor watchlist is paywalled. Upgrade at https://wiredepth.com/pricing"))
		} else {
			b.WriteString("  " + StyleFail.Render("Could not load vendor watchlist:"))
			b.WriteString("\n  " + StyleDim.Render(msg))
			b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		}
		return b.String()
	}
	if m.data == nil {
		return b.String()
	}

	b.WriteString("  " + StyleLabel.Render("VENDORS") + "  " +
		StyleDim.Render(fmt.Sprintf("%d watched", m.data.Count)) + "\n\n")
	if len(m.data.Vendors) == 0 {
		b.WriteString("  " + StyleDim.Render(
			"No vendors yet. Add them at /dashboard/vendors on the web."))
		b.WriteString("\n\n  " + StyleDim.Render(
			"r refresh  ·  Tab nav"))
		return b.String()
	}

	domainW := 28
	labelW := 22
	gradeW := 7
	threatW := 18
	scannedW := 12
	header := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		padRight("DOMAIN", domainW),
		padRight("LABEL", labelW),
		padRight("GRADE", gradeW),
		padRight("THREAT", threatW),
		padRight("STATE", 8),
		padRight("LAST SCAN", scannedW),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, v := range m.data.Vendors {
		label := "-"
		if v.Label != nil && *v.Label != "" {
			label = *v.Label
		}
		grade := "-"
		threat := "-"
		if v.LastSnapshot != nil {
			if v.LastSnapshot.Overall != "" {
				grade = GradeStyle(v.LastSnapshot.Overall).Render(v.LastSnapshot.Overall)
			}
			if ti := v.LastSnapshot.ThreatIntel; ti != nil {
				if ti.Listed != nil && *ti.Listed {
					threat = StyleFail.Render("listed")
					if ti.Summary != "" {
						threat = StyleFail.Render(ti.Summary)
					}
				} else if ti.Grade != "" {
					threat = StyleWarn.Render(ti.Grade)
				} else if ti.Listed != nil {
					threat = StyleOK.Render("clean")
				}
			}
		}
		state := StyleOK.Render("active")
		if !v.IsActive {
			state = StyleDim.Render("paused")
		} else if v.LastError != nil && *v.LastError != "" {
			state = StyleFail.Render("error")
		}
		scanned := "-"
		if v.LastScannedAt != nil {
			scanned = ago(*v.LastScannedAt) + " ago"
		} else {
			scanned = StyleDim.Render("queued")
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
			padRight(truncate(v.Domain, domainW), domainW),
			padRight(truncate(label, labelW), labelW),
			padRight(grade, gradeW),
			padRight(truncate(threat, threatW), threatW),
			padRight(state, 8),
			padRight(scanned, scannedW),
		)
		b.WriteString(row + "\n")
		if v.LastError != nil && *v.LastError != "" {
			b.WriteString("    " + StyleDim.Render("error: "+truncate(*v.LastError, m.width-14)) + "\n")
		}
	}

	b.WriteString("\n  " + StyleDim.Render(
		"r refresh  ·  Tab nav  ·  add + remove + toggle at /dashboard/vendors on the web"))
	return b.String()
}
