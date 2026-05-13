package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// AccountPage shows /me (email, tier, domain quota, admin flag) plus
// quotas pulled from ListDomains. Read-only; sign-out + upgrade
// link to the web.

type accountLoadedMsg struct {
	me      *api.Me
	domains []api.MonitoredDomain
	err     error
}

type AccountPage struct {
	client  *api.Client
	apiBase string

	width  int
	height int

	loading bool
	err     error
	me      *api.Me
	domains []api.MonitoredDomain
}

func newAccountPage(client *api.Client, apiBase string) AccountPage {
	return AccountPage{client: client, apiBase: apiBase, loading: true}
}

func (m AccountPage) Init() tea.Cmd {
	return m.fetch()
}

func (m AccountPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		me, err := c.Me()
		if err != nil {
			return accountLoadedMsg{err: err}
		}
		doms, _ := c.ListDomains()
		return accountLoadedMsg{me: me, domains: doms}
	}
}

func (m AccountPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case accountLoadedMsg:
		m.loading = false
		m.me = msg.me
		m.domains = msg.domains
		m.err = msg.err
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			m.loading = true
			m.err = nil
			return m, m.fetch()
		case "o":
			openURL(m.apiBase + "/account")
			return m, nil
		case "u":
			openURL(m.apiBase + "/pricing")
			return m, nil
		}
	}
	return m, nil
}

func (m AccountPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Account", "plan, quota, admin"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading account..."))
		return b.String()
	}
	if m.err != nil {
		b.WriteString("  " + StyleFail.Render("Could not load /me:"))
		b.WriteString("\n  " + StyleDim.Render(m.err.Error()))
		b.WriteString("\n\n  " + StyleDim.Render("r retry  ·  Tab nav"))
		return b.String()
	}
	if m.me == nil {
		return b.String()
	}

	u := m.me.User
	quota := u.DomainQuota
	used := len(m.domains)
	usedPct := 0
	if quota > 0 {
		usedPct = int(float64(used) / float64(quota) * 100)
	}

	tier := u.TierLabel
	if tier == "" {
		tier = u.Tier
	}
	if tier == "" {
		tier = "free"
	}

	rows := []struct{ k, v string }{
		{"Email", u.Email},
		{"Tier", tier},
		{"Plan id", u.Tier},
		{"Auth method", m.me.AuthMethod},
		{"Admin", boolLabel(u.IsAdmin)},
		{"Domain quota",
			fmt.Sprintf("%d of %d  (%d%%)", used, quota, usedPct)},
	}
	for _, r := range rows {
		b.WriteString("  " + styleLabel(r.k) + "  " + r.v + "\n")
	}

	// Visual quota bar - amber while under 80%, warn at 80%+, fail at
	// 100%. Cheap "are you close to the cap" signal.
	if quota > 0 {
		barW := 36
		if m.width-30 < barW {
			barW = m.width - 30
		}
		if barW < 10 {
			barW = 10
		}
		filled := int(float64(used) / float64(quota) * float64(barW))
		if filled > barW {
			filled = barW
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barW-filled)
		colorStyle := StyleOK
		if usedPct >= 100 {
			colorStyle = StyleFail
		} else if usedPct >= 80 {
			colorStyle = StyleWarn
		}
		b.WriteString("\n  " + styleLabel("") + "  " +
			colorStyle.Render(bar))
		b.WriteString("\n")
	}

	b.WriteString("\n  " + StyleLabel.Render("KEYS"))
	b.WriteString("\n  " + StyleDim.Render(
		"o open /account on the web  ·  u upgrade  ·  r refresh"))
	b.WriteString("\n  " + StyleDim.Render(
		"Sign-out lives on the web; we never store your password."))
	return b.String()
}

// boolLabel lives in noc.go; reuse it. Account page uses it for the
// admin flag.
