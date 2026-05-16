package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/wiredepth-cli/internal/api"
)

// CredentialLeaksPage shows breach-corpus findings scoped to addresses
// at the caller's monitored apexes. Pro+ feature. The page deliberately
// shows breach name + account count + data classes only; the webapp
// doesn't persist the leaked addresses themselves so the API never
// exposes them.

type credsLoadedMsg struct {
	data *api.CredentialLeaksResp
	err  error
}

type CredentialLeaksPage struct {
	client *api.Client

	width  int
	height int

	loading bool
	data    *api.CredentialLeaksResp
	err     error
}

func newCredentialLeaksPage(client *api.Client) CredentialLeaksPage {
	return CredentialLeaksPage{client: client, loading: true}
}

func (m CredentialLeaksPage) Init() tea.Cmd {
	return m.fetch()
}

func (m CredentialLeaksPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.CredentialLeaks()
		return credsLoadedMsg{data: d, err: err}
	}
}

func (m CredentialLeaksPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case credsLoadedMsg:
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

func (m CredentialLeaksPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Credential leaks",
		"addresses at your apex in breach corpora"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading breach findings..."))
		return b.String()
	}
	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
			b.WriteString("  " + StyleWarn.Render("Pro / Power / MSP required."))
			b.WriteString("\n  " + StyleDim.Render(
				"Breach-corpus monitoring is paywalled. Upgrade at https://wiredepth.com/pricing"))
		} else {
			b.WriteString("  " + StyleFail.Render("Could not load credential leaks:"))
			b.WriteString("\n  " + StyleDim.Render(msg))
			b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		}
		return b.String()
	}
	if m.data == nil {
		return b.String()
	}

	b.WriteString("  " + StyleLabel.Render("FINDINGS") + "  " +
		StyleDim.Render(fmt.Sprintf("%d shown · limit %d",
			m.data.Count, m.data.Limit)) + "\n\n")
	if len(m.data.Findings) == 0 {
		b.WriteString("  " + StyleOK.Render("✓ No addresses at any monitored apex appear in tracked breach corpora."))
		b.WriteString("\n\n  " + StyleDim.Render(
			"Workers poll the breach API weekly per apex."))
		b.WriteString("\n  " + StyleDim.Render(
			"r refresh  ·  Tab nav"))
		return b.String()
	}

	domainW := 22
	breachW := 24
	classesW := 30
	countW := 8
	dateW := 12
	seenW := 12
	header := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		padRight("APEX", domainW),
		padRight("BREACH", breachW),
		padRight("DATA CLASSES", classesW),
		padRight("ACCTS", countW),
		padRight("BREACH DATE", dateW),
		padRight("LAST SEEN", seenW),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, f := range m.data.Findings {
		domain := "-"
		if f.Domain != nil {
			domain = *f.Domain
		}
		breach := f.BreachName
		if f.BreachTitle != nil && *f.BreachTitle != "" {
			breach = *f.BreachTitle
		}
		classes := strings.Join(f.DataClasses, ",")
		if classes == "" {
			classes = StyleDim.Render("-")
		} else if hasPasswordClass(f.DataClasses) {
			classes = StyleFail.Render(classes)
		} else {
			classes = StyleWarn.Render(classes)
		}
		count := "-"
		if f.AccountCount != nil {
			count = fmt.Sprintf("%d", *f.AccountCount)
		}
		breachDate := "-"
		if f.BreachDate != nil {
			breachDate = (*f.BreachDate)[:10] // YYYY-MM-DD
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
			padRight(truncate(domain, domainW), domainW),
			padRight(truncate(breach, breachW), breachW),
			padRight(truncate(classes, classesW), classesW),
			padRight(count, countW),
			padRight(breachDate, dateW),
			padRight(ago(f.LastSeenAt)+" ago", seenW),
		)
		b.WriteString(row + "\n")
	}

	b.WriteString("\n  " + StyleDim.Render(
		"r refresh  ·  Tab nav  ·  reset playbook + per-account list at /dashboard/credential-leaks on the web"))
	return b.String()
}

// hasPasswordClass returns true when the breach exposed cleartext or
// hashed passwords - drives the "this one matters more" colour bump.
func hasPasswordClass(classes []string) bool {
	for _, c := range classes {
		switch strings.ToLower(c) {
		case "passwords", "password-hashes", "passwords-hashes":
			return true
		}
	}
	return false
}
