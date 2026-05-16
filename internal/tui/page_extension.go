package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/wiredepth-cli/internal/api"
)

// ExtensionBillingPage shows the caller's Postvale Extension plan,
// seat count, current-window triage usage, top-up credits, and
// expiry. Read-only - the upgrade / top-up purchase flow lives on
// /account/extension because it needs Stripe Checkout.

type extLoadedMsg struct {
	data *api.ExtensionBudget
	err  error
}

type ExtensionBillingPage struct {
	client  *api.Client
	apiBase string

	width  int
	height int

	loading bool
	data    *api.ExtensionBudget
	err     error
}

func newExtensionBillingPage(client *api.Client, apiBase string) ExtensionBillingPage {
	return ExtensionBillingPage{client: client, apiBase: apiBase, loading: true}
}

func (m ExtensionBillingPage) Init() tea.Cmd {
	return m.fetch()
}

func (m ExtensionBillingPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.ExtensionBudget()
		return extLoadedMsg{data: d, err: err}
	}
}

func (m ExtensionBillingPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case extLoadedMsg:
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
		case "o":
			openURL(m.apiBase + "/account/extension")
			return m, nil
		}
	}
	return m, nil
}

func (m ExtensionBillingPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Extension billing",
		"Scam Check budget, seats, top-up packs"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading extension billing..."))
		return b.String()
	}
	if m.err != nil {
		b.WriteString("  " + StyleFail.Render("Could not load extension budget:"))
		b.WriteString("\n  " + StyleDim.Render(m.err.Error()))
		b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		return b.String()
	}
	if m.data == nil {
		return b.String()
	}

	rows := []struct{ k, v string }{
		{"Plan", m.data.PlanLabel + "  " + StyleDim.Render("("+m.data.Plan+")")},
		{"Seats", fmt.Sprintf("%d", m.data.Seats)},
		{"Cadence", m.data.Cadence},
	}
	for _, r := range rows {
		b.WriteString("  " + styleLabel(r.k) + "  " + r.v + "\n")
	}

	b.WriteString("\n  " + StyleLabel.Render("TRIAGE BUDGET") + "\n")
	if m.data.Unlimited {
		b.WriteString("  " + styleLabel("Used") + "  " +
			fmt.Sprintf("%d (unlimited - contract-defined)", m.data.Used) + "\n")
	} else if m.data.AggregateTriages != nil && m.data.Remaining != nil {
		total := *m.data.AggregateTriages
		remaining := *m.data.Remaining
		usedPct := 0
		if total > 0 {
			usedPct = int(float64(m.data.Used) / float64(total) * 100)
		}
		b.WriteString("  " + styleLabel("Used") + "  " +
			fmt.Sprintf("%d of %d  (%d%%)", m.data.Used, total, usedPct) + "\n")
		b.WriteString("  " + styleLabel("Remaining") + "  " +
			fmt.Sprintf("%d", remaining) + "\n")

		// Visual bar - amber until 80%, warn 80-99%, fail at 100%.
		barW := 40
		if m.width-20 < barW {
			barW = m.width - 20
		}
		if barW < 10 {
			barW = 10
		}
		filled := int(float64(m.data.Used) / float64(total) * float64(barW))
		if filled > barW {
			filled = barW
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barW-filled)
		style := StyleOK
		if usedPct >= 100 {
			style = StyleFail
		} else if usedPct >= 80 {
			style = StyleWarn
		}
		b.WriteString("  " + styleLabel("") + "  " + style.Render(bar) + "\n")
	}

	b.WriteString("\n  " + StyleLabel.Render("TOP-UP CREDITS") + "\n")
	if m.data.Topup.Credits == 0 {
		b.WriteString("  " + StyleDim.Render("None purchased.") + "\n")
	} else {
		exp := "no expiry"
		if m.data.Topup.ExpiresAt != nil {
			exp = "expires " + ago(*m.data.Topup.ExpiresAt) + " from now"
		}
		state := StyleOK.Render("active")
		if !m.data.Topup.Active {
			state = StyleDim.Render("expired")
		}
		b.WriteString("  " + styleLabel("Credits") +
			fmt.Sprintf("  %d (%s, %s)\n",
				m.data.Topup.Credits, state, exp))
	}

	b.WriteString("\n  " + StyleLabel.Render("KEYS") + "\n")
	b.WriteString("  " + StyleDim.Render(
		"o open /account/extension on the web (upgrade + top-up)  ·  r refresh"))
	return b.String()
}
