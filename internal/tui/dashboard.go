// Package tui implements the `wd tui` interactive dashboard.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/WiredepthHQ/cli/internal/api"
)

// view tracks which screen the user is currently on.
type view int

const (
	viewList view = iota
	viewDetail
	viewError
)

// keymap declares every binding once so the help component can render
// a consistent legend across all views.
type keymap struct {
	Up      key.Binding
	Down    key.Binding
	Enter   key.Binding
	Back    key.Binding
	Refresh key.Binding
	Open    key.Binding
	Help    key.Binding
	Quit    key.Binding
}

func newKeymap() keymap {
	return keymap{
		Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Enter:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("↵", "details")),
		Back:    key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Open:    key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "open in browser")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k keymap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Refresh, k.Help, k.Quit}
}

func (k keymap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter, k.Back},
		{k.Refresh, k.Open, k.Help, k.Quit},
	}
}

// Model is the bubbletea Model for the dashboard. Holds the API
// client, the currently-loaded domains + identity, and which view
// the user is on. All state changes flow through Update().
type Model struct {
	client *api.Client
	keys   keymap
	help   help.Model

	view view

	width  int
	height int

	loading bool
	spinner spinner.Model

	me       *api.Me
	domains  []api.MonitoredDomain
	tbl      table.Model
	errMsg   string
	lastSync time.Time

	apiBase string
}

// New constructs the dashboard model. The bubbletea program is
// started by the caller; we just hand it back a tea.Program-ready
// Init/Update/View triple.
func New(client *api.Client, apiBase string) Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = StyleHeader

	t := table.New(
		table.WithColumns(tableColumns()),
		table.WithFocused(true),
		table.WithHeight(16),
	)
	t.SetStyles(tableStyles())

	return Model{
		client:  client,
		keys:    newKeymap(),
		help:    help.New(),
		view:    viewList,
		loading: true,
		spinner: sp,
		tbl:     t,
		apiBase: apiBase,
	}
}

// ----- bubbletea messages -----

type dataLoadedMsg struct {
	me      *api.Me
	domains []api.MonitoredDomain
}

type loadErrMsg struct{ err error }

// fetchAll runs /me + /domains in parallel (via two goroutines feeding
// a channel) and emits a single message when both return.
func (m Model) fetchAll() tea.Cmd {
	return func() tea.Msg {
		type result struct {
			me      *api.Me
			domains []api.MonitoredDomain
			err     error
		}
		ch := make(chan result, 1)
		go func() {
			me, err := m.client.Me()
			if err != nil {
				ch <- result{err: err}
				return
			}
			doms, err := m.client.ListDomains()
			ch <- result{me: me, domains: doms, err: err}
		}()
		r := <-ch
		if r.err != nil {
			return loadErrMsg{err: r.err}
		}
		return dataLoadedMsg{me: r.me, domains: r.domains}
	}
}

// ----- Init / Update / View -----

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.fetchAll())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width
		// Reserve 4 lines for header + 3 for footer; the rest goes
		// to the table.
		h := msg.Height - 7
		if h < 5 {
			h = 5
		}
		m.tbl.SetHeight(h)
		return m, nil

	case spinner.TickMsg:
		if !m.loading {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case dataLoadedMsg:
		m.loading = false
		m.me = msg.me
		m.domains = msg.domains
		m.lastSync = time.Now()
		m.tbl.SetRows(domainRows(msg.domains))
		return m, nil

	case loadErrMsg:
		m.loading = false
		m.view = viewError
		m.errMsg = msg.err.Error()
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			return m, nil
		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			m.errMsg = ""
			return m, tea.Batch(m.spinner.Tick, m.fetchAll())
		}

		if m.view == viewError {
			if key.Matches(msg, m.keys.Back) {
				m.view = viewList
				m.errMsg = ""
				return m, nil
			}
			return m, nil
		}

		if m.view == viewDetail {
			if key.Matches(msg, m.keys.Back) {
				m.view = viewList
				return m, nil
			}
			if key.Matches(msg, m.keys.Open) {
				openURL(m.apiBase + "/dashboard")
				return m, nil
			}
			return m, nil
		}

		// viewList key handling - delegate to the table for nav.
		if key.Matches(msg, m.keys.Enter) {
			if len(m.domains) > 0 {
				m.view = viewDetail
			}
			return m, nil
		}
		if key.Matches(msg, m.keys.Open) {
			openURL(m.apiBase + "/dashboard")
			return m, nil
		}
		var cmd tea.Cmd
		m.tbl, cmd = m.tbl.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	if m.loading {
		return m.renderShell(fmt.Sprintf("\n  %s loading…\n", m.spinner.View()))
	}
	switch m.view {
	case viewError:
		return m.renderShell(m.renderError())
	case viewDetail:
		return m.renderShell(m.renderDetail())
	default:
		return m.renderShell(m.renderList())
	}
}

// renderShell wraps the per-view body with the persistent header +
// status footer, so chrome stays consistent across screens.
func (m Model) renderShell(body string) string {
	return m.renderHeader() + body + "\n" + m.renderFooter()
}

func (m Model) renderHeader() string {
	// Page label, not the brand mark. The shell's sidebar already
	// shows POSTVALE + identity; repeating either here was visible
	// redundancy.
	left := StyleHeader.Render("DASHBOARD")
	right := ""
	if !m.lastSync.IsZero() {
		right = StyleDim.Render(
			fmt.Sprintf("%d domains  ·  synced %s ago",
				len(m.domains),
				formatAgo(time.Since(m.lastSync)),
			),
		)
	}
	pad := ""
	if m.width > 0 {
		used := lipgloss.Width(left) + lipgloss.Width(right)
		if gap := m.width - used; gap > 0 {
			pad = strings.Repeat(" ", gap)
		}
	}
	return left + pad + right + "\n" +
		StyleDim.Render(strings.Repeat("─", max(0, m.width))) + "\n"
}

func (m Model) renderFooter() string {
	var status string
	if !m.lastSync.IsZero() {
		status = StyleDim.Render(fmt.Sprintf("synced %s ago", formatAgo(time.Since(m.lastSync))))
	}
	return status + "\n" + m.help.View(m.keys)
}

func (m Model) renderList() string {
	if len(m.domains) == 0 {
		return "\n  " + StyleDim.Render("No monitored domains yet. Add one with `wd watch add <domain>`.") + "\n"
	}
	return "\n" + m.tbl.View()
}

func (m Model) renderDetail() string {
	d := m.selectedDomain()
	if d == nil {
		return "\n  " + StyleDim.Render("No domain selected.")
	}
	last := "-"
	if d.LastCheckedAt != nil {
		last = formatAgo(time.Since(parseTime(*d.LastCheckedAt))) + " ago"
	}
	grade := d.LastWorstGrade
	if grade == "" {
		grade = "-"
	}
	lines := []string{
		"",
		"  " + StyleStrong.Render(fmt.Sprintf("%s:%d", d.Host, d.Port)),
		"  " + StyleDim.Render(fmt.Sprintf("id %s", d.ID)),
		"",
		"  " + StyleHeader.Render("STATUS"),
		fmt.Sprintf("  %s  %s", styleLabel("Grade"), GradeStyle(grade).Render(grade)),
		fmt.Sprintf("  %s  %s", styleLabel("Last checked"), last),
		fmt.Sprintf("  %s  %dm", styleLabel("Cadence"), d.CadenceMinutes),
		fmt.Sprintf("  %s  %v", styleLabel("Paused"), d.Paused),
	}
	if d.Label != nil && *d.Label != "" {
		lines = append(lines, fmt.Sprintf("  %s  %s", styleLabel("Label"), *d.Label))
	}
	lines = append(lines, "",
		"  "+StyleDim.Render("Press o to open this domain in the web dashboard, esc to go back."),
	)
	return strings.Join(lines, "\n") + "\n"
}

func (m Model) renderError() string {
	return "\n  " + StyleFail.Render("Could not load dashboard:") + "\n  " +
		StyleDim.Render(m.errMsg) + "\n\n  " +
		StyleDim.Render("Press r to retry, esc to dismiss, q to quit.")
}

// selectedDomain returns the row the user has highlighted in the
// table, or nil if the table is empty.
func (m Model) selectedDomain() *api.MonitoredDomain {
	idx := m.tbl.Cursor()
	if idx < 0 || idx >= len(m.domains) {
		return nil
	}
	return &m.domains[idx]
}

// ----- table wiring -----

func tableColumns() []table.Column {
	return []table.Column{
		{Title: "Host", Width: 32},
		{Title: "Port", Width: 6},
		{Title: "Grade", Width: 7},
		{Title: "Cadence", Width: 10},
		{Title: "Last checked", Width: 18},
	}
}

func domainRows(ds []api.MonitoredDomain) []table.Row {
	out := make([]table.Row, 0, len(ds))
	for _, d := range ds {
		grade := d.LastWorstGrade
		if grade == "" {
			grade = "-"
		}
		last := "-"
		if d.LastCheckedAt != nil {
			last = formatAgo(time.Since(parseTime(*d.LastCheckedAt))) + " ago"
		}
		out = append(out, table.Row{
			d.Host,
			fmt.Sprintf("%d", d.Port),
			grade,
			fmt.Sprintf("%dm", d.CadenceMinutes),
			last,
		})
	}
	return out
}

// ----- helpers -----

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

func formatAgo(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
