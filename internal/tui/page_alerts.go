package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/WiredepthHQ/cli/internal/api"
)

// AlertsPage is a read-only list of webhook destinations + their
// last-fired status. Edits stay on the web (`wd alerts` shipped
// later if needed) so the TUI stays trustworthy as a viewing surface.

type alertsLoadedMsg struct {
	alerts []api.AlertEndpoint
	err    error
}

type AlertsPage struct {
	client *api.Client

	width  int
	height int

	loading  bool
	alerts   []api.AlertEndpoint
	err      error
	loadedAt time.Time
}

func newAlertsPage(client *api.Client, _ string) AlertsPage {
	return AlertsPage{client: client, loading: true}
}

func (m AlertsPage) Init() tea.Cmd {
	return m.fetch()
}

func (m AlertsPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		list, err := c.ListAlerts()
		return alertsLoadedMsg{alerts: list, err: err}
	}
}

func (m AlertsPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case alertsLoadedMsg:
		m.loading = false
		m.alerts = msg.alerts
		m.err = msg.err
		m.loadedAt = time.Now()
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

func (m AlertsPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Alerts", fmt.Sprintf("read-only · %s endpoints",
		countLabel(len(m.alerts)))))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading endpoints..."))
		return b.String()
	}
	if m.err != nil {
		b.WriteString("  " + StyleFail.Render("Could not load alerts:"))
		b.WriteString("\n  " + StyleDim.Render(m.err.Error()))
		b.WriteString("\n\n  " + StyleDim.Render("r retry · Tab nav"))
		return b.String()
	}
	if len(m.alerts) == 0 {
		b.WriteString("  " + StyleDim.Render("No alert endpoints configured."))
		b.WriteString("\n  " + StyleDim.Render("Set them up at /alerts on the web."))
		return b.String()
	}

	// Column layout: kind | label | target | enabled | last-fired
	kindW := 10
	labelW := 26
	targetW := m.width - kindW - labelW - 24
	if targetW < 18 {
		targetW = 18
	}

	header := fmt.Sprintf("  %s  %s  %s  %s  %s",
		padRight("KIND", kindW),
		padRight("LABEL", labelW),
		padRight("TARGET", targetW),
		padRight("STATE", 9),
		padRight("LAST FIRED", 14),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n")
	b.WriteString("  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, a := range m.alerts {
		target := a.URL
		if a.Kind == "email" && a.EmailTo != "" {
			target = a.EmailTo
		}
		state := StyleDim.Render("paused")
		if a.Enabled {
			state = StyleOK.Render("active")
		}
		fired := "-"
		if a.LastFiredAt != nil {
			fired = ago(*a.LastFiredAt) + " ago"
		}
		if a.LastFiredStatus != nil && *a.LastFiredStatus != "" {
			if *a.LastFiredStatus != "ok" {
				fired = StyleWarn.Render(fired)
			} else {
				fired = StyleDim.Render(fired)
			}
		} else {
			fired = StyleDim.Render(fired)
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s",
			padRight(a.Kind, kindW),
			padRight(truncate(a.Label, labelW), labelW),
			padRight(truncate(target, targetW), targetW),
			padRight(state, 9),
			fired,
		)
		b.WriteString(row)
		b.WriteString("\n")
	}

	b.WriteString("\n  ")
	b.WriteString(StyleDim.Render("r refresh  ·  Tab to nav sidebar  ·  edit at /alerts on the web"))
	return b.String()
}

// ----- helpers -----

func countLabel(n int) string {
	if n == 1 {
		return "1"
	}
	return fmt.Sprintf("%d", n)
}

func ago(iso string) string {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	return formatAgo(time.Since(t))
}
