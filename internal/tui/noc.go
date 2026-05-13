package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// NOC console - mirrors /dashboard/noc on the webapp. Three-pane
// layout: domains on the left, action queue + live feed stacked on
// the right. Stats strip at the top.

type nocKeymap struct {
	Pause   key.Binding
	Refresh key.Binding
	Help    key.Binding
	Quit    key.Binding
}

func newNocKeymap() nocKeymap {
	return nocKeymap{
		Pause:   key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k nocKeymap) ShortHelp() []key.Binding {
	return []key.Binding{k.Pause, k.Refresh, k.Help, k.Quit}
}

func (k nocKeymap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Pause, k.Refresh, k.Help, k.Quit}}
}

// NocModel holds the live NOC state. Two independent ticker streams
// drive summary + feed polling at different cadences.
type NocModel struct {
	client *api.Client

	width  int
	height int

	keys nocKeymap
	help help.Model

	summary *api.DashboardSummary
	domains []api.MonitoredDomain
	feed    []api.RecentScan

	feedCursor string
	lastSync   time.Time
	now        time.Time

	paused bool
	loaded bool
	err    error
}

func NewNoc(client *api.Client) NocModel {
	return NocModel{
		client: client,
		keys:   newNocKeymap(),
		help:   help.New(),
		now:    time.Now(),
	}
}

// ----- messages -----

type nocSummaryMsg struct {
	summary *api.DashboardSummary
	domains []api.MonitoredDomain
	err     error
}

type nocFeedMsg struct {
	scans []api.RecentScan
	err   error
}

type nocTickSummaryMsg struct{}
type nocTickFeedMsg struct{}
type nocTickClockMsg struct{}

func (m NocModel) fetchSummary() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		summary, err := c.DashboardSummary()
		if err != nil {
			return nocSummaryMsg{err: err}
		}
		doms, err := c.ListDomains()
		return nocSummaryMsg{summary: summary, domains: doms, err: err}
	}
}

func (m NocModel) fetchFeed() tea.Cmd {
	c := m.client
	cursor := m.feedCursor
	return func() tea.Msg {
		scans, err := c.RecentScans(cursor, 50)
		return nocFeedMsg{scans: scans, err: err}
	}
}

func nocTickEvery(d time.Duration, msg tea.Msg) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return msg })
}

// ----- bubbletea wiring -----

func (m NocModel) Init() tea.Cmd {
	return tea.Batch(
		m.fetchSummary(),
		m.fetchFeed(),
		nocTickEvery(30*time.Second, nocTickSummaryMsg{}),
		nocTickEvery(6*time.Second, nocTickFeedMsg{}),
		nocTickEvery(time.Second, nocTickClockMsg{}),
	)
}

func (m NocModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width
		return m, nil

	case nocTickClockMsg:
		m.now = time.Now()
		return m, nocTickEvery(time.Second, nocTickClockMsg{})

	case nocTickSummaryMsg:
		if m.paused {
			return m, nocTickEvery(30*time.Second, nocTickSummaryMsg{})
		}
		return m, tea.Batch(m.fetchSummary(), nocTickEvery(30*time.Second, nocTickSummaryMsg{}))

	case nocTickFeedMsg:
		if m.paused {
			return m, nocTickEvery(6*time.Second, nocTickFeedMsg{})
		}
		return m, tea.Batch(m.fetchFeed(), nocTickEvery(6*time.Second, nocTickFeedMsg{}))

	case nocSummaryMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.summary = msg.summary
		if msg.domains != nil {
			m.domains = msg.domains
		}
		m.lastSync = time.Now()
		m.loaded = true
		m.err = nil
		return m, nil

	case nocFeedMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		if len(msg.scans) == 0 {
			return m, nil
		}
		seen := make(map[string]bool, len(m.feed))
		for _, s := range m.feed {
			seen[s.ID] = true
		}
		fresh := make([]api.RecentScan, 0, len(msg.scans))
		for _, s := range msg.scans {
			if !seen[s.ID] {
				fresh = append(fresh, s)
			}
		}
		// API returns newest first. Prepend to the buffer.
		combined := append(fresh, m.feed...)
		if len(combined) > 200 {
			combined = combined[:200]
		}
		m.feed = combined
		// Advance the cursor to the newest entry's ranAt so the next
		// fetch only gets strictly-newer rows.
		m.feedCursor = msg.scans[0].RanAt
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Pause):
			m.paused = !m.paused
			return m, nil
		case key.Matches(msg, m.keys.Refresh):
			return m, tea.Batch(m.fetchSummary(), m.fetchFeed())
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			return m, nil
		}
	}
	return m, nil
}

// ----- view -----

func (m NocModel) View() string {
	if !m.loaded && m.err == nil {
		return m.renderShell("\n  " + StyleDim.Render("loading…") + "\n")
	}
	body := m.renderStatsBar() + "\n\n" + m.renderPanes()
	return m.renderShell(body)
}

func (m NocModel) renderShell(body string) string {
	header := m.renderHeader()
	footer := m.renderFooter()
	return header + body + "\n" + footer
}

func (m NocModel) renderHeader() string {
	live := StyleOK.Render("● live")
	if m.paused {
		live = StyleWarn.Render("● paused")
	}
	syncedAgo := "-"
	if !m.lastSync.IsZero() {
		syncedAgo = formatAgo(m.now.Sub(m.lastSync)) + " ago"
	}
	left := StyleHeader.Render("POSTVALE · NOC")
	right := fmt.Sprintf("%s  %s",
		live,
		StyleDim.Render("synced "+syncedAgo),
	)
	pad := ""
	if m.width > 0 {
		gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
		if gap > 0 {
			pad = strings.Repeat(" ", gap)
		}
	}
	return left + pad + right + "\n" +
		StyleDim.Render(strings.Repeat("─", max(0, m.width))) + "\n"
}

func (m NocModel) renderFooter() string {
	var errLine string
	if m.err != nil {
		errLine = StyleFail.Render("! "+m.err.Error()) + "\n"
	}
	return errLine + m.help.View(m.keys)
}

func (m NocModel) renderStatsBar() string {
	if m.summary == nil {
		return "  " + StyleDim.Render("(no data)")
	}
	s := m.summary
	parts := []string{
		statVal(s.MonitoredCount) + " " + StyleDim.Render("domains"),
	}
	for _, g := range []string{"A+", "A", "B", "C", "D", "F", "-"} {
		v := s.GradeDistribution[g]
		parts = append(parts, gradeBucket(g, v))
	}
	parts = append(parts,
		statValAlert(s.BlocklistHits)+" "+StyleDim.Render("blocked"),
		statVal(s.RecentAlertCount24h)+" "+StyleDim.Render("alerts/24h"),
	)
	return "  " + strings.Join(parts, "  ")
}

func (m NocModel) renderPanes() string {
	// Two columns: domains (~60% width) | right stack (~40%).
	// Right stack is action queue on top, live feed below.
	leftW := m.width * 6 / 10
	rightW := m.width - leftW - 3
	if leftW < 30 {
		leftW = 30
	}
	if rightW < 24 {
		rightW = 24
	}

	bodyH := m.height - 8
	if bodyH < 12 {
		bodyH = 12
	}
	rightH := bodyH / 2
	feedH := bodyH - rightH - 1

	left := renderPanel("DOMAINS · "+fmt.Sprintf("%d", len(m.domains)),
		m.renderDomains(), leftW, bodyH)
	queueCount := 0
	if m.summary != nil {
		queueCount = len(m.summary.ActionQueue)
	}
	rightTop := renderPanel(fmt.Sprintf("ACTION QUEUE · %d", queueCount),
		m.renderActionQueue(), rightW, rightH)
	// 4 lines of panel chrome: top border, title, rule, bottom border.
	// Feed buffer caps at 200 but the visible window has to match the
	// panel; otherwise lipgloss expands the panel past bodyH and the
	// stats bar + left pane scroll off the top of the alt-screen.
	rightBot := renderPanel("LIVE FEED",
		m.renderLiveFeed(feedH-4), rightW, feedH)
	right := rightTop + "\n" + rightBot

	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

func (m NocModel) renderDomains() string {
	if len(m.domains) == 0 {
		return "\n  " + StyleDim.Render("No monitored domains. Add one with `postvale watch add <domain>`.") + "\n"
	}
	var b strings.Builder
	b.WriteString("  ")
	b.WriteString(colHeader("Host", 28))
	b.WriteString(colHeader("Grade", 7))
	b.WriteString(colHeader("TLS", 5))
	b.WriteString(colHeader("DMARC", 6))
	b.WriteString(colHeader("DNS", 5))
	b.WriteString(colHeader("HDR", 5))
	b.WriteString(colHeader("MTA", 5))
	b.WriteString(colHeader("Last", 8))
	b.WriteString("\n")

	for _, d := range m.domains {
		host := d.Host
		if d.Port != 443 {
			host = fmt.Sprintf("%s:%d", host, d.Port)
		}
		grade := d.LastWorstGrade
		if grade == "" {
			grade = "-"
		}
		last := "-"
		if d.LastCheckedAt != nil {
			last = formatAgo(m.now.Sub(parseTime(*d.LastCheckedAt)))
		}
		b.WriteString("  ")
		b.WriteString(truncate(host, 28))
		b.WriteString(GradeStyle(grade).Render(padRight(grade, 7)))
		b.WriteString(subGrade(d.LastGrades, "tls", 5))
		b.WriteString(subGrade(d.LastGrades, "dmarc", 6))
		b.WriteString(subGrade(d.LastGrades, "dns", 5))
		b.WriteString(subGrade(d.LastGrades, "headers", 5))
		b.WriteString(subGrade(d.LastGrades, "mtaSts", 5))
		b.WriteString(StyleDim.Render(padRight(last, 8)))
		b.WriteString("\n")
	}
	return b.String()
}

// Per-tool grade cell. Empty / missing renders as a dim dash, matching
// the webapp NOC. Letter grades use the same colour pill scheme as
// the worst-grade column.
func subGrade(grades map[string]string, key string, width int) string {
	if grades == nil {
		return StyleDim.Render(padRight("-", width))
	}
	g := grades[key]
	if g == "" && key == "mtaSts" {
		// Webapp returns either mtaSts or mta-sts depending on
		// scanner version; tolerate both.
		g = grades["mta-sts"]
	}
	if g == "" {
		return StyleDim.Render(padRight("-", width))
	}
	return GradeStyle(g).Render(padRight(g, width))
}

func (m NocModel) renderActionQueue() string {
	if m.summary == nil || len(m.summary.ActionQueue) == 0 {
		return "\n  " + StyleOK.Render("✓") + StyleDim.Render(" nothing to action") + "\n"
	}
	var b strings.Builder
	for _, it := range m.summary.ActionQueue {
		dot := severityDot(it.Severity)
		domain := truncate(it.Domain, 18)
		msg := truncate(it.Message, 40)
		age := formatAgo(m.now.Sub(parseTime(it.DetectedAt)))
		b.WriteString(fmt.Sprintf(" %s %s %s %s\n",
			dot,
			StyleStrong.Render(padRight(domain, 18)),
			StyleDim.Render(padRight(msg, 40)),
			StyleDim.Render(age),
		))
	}
	return b.String()
}

func (m NocModel) renderLiveFeed(maxLines int) string {
	if len(m.feed) == 0 {
		return "\n  " + StyleDim.Render("waiting for the next scan…") + "\n"
	}
	feed := m.feed
	if maxLines > 0 && len(feed) > maxLines {
		feed = feed[:maxLines]
	}
	var b strings.Builder
	for _, s := range feed {
		clock := formatClock(s.RanAt)
		grade := s.WorstGrade
		if grade == "" {
			grade = "-"
		}
		b.WriteString(fmt.Sprintf(" %s  %s  %s\n",
			StyleDim.Render(clock),
			truncate(s.Host, 28),
			GradeStyle(grade).Render(grade),
		))
	}
	return b.String()
}

// ----- helpers -----

func colHeader(label string, width int) string {
	return StyleHeader.Render(padRight(label, width))
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func truncate(s string, w int) string {
	if len(s) <= w {
		return padRight(s, w)
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "…"
}

func gradeBucket(g string, n int) string {
	pill := GradeStyle(g).Render(padRight(g, 2))
	return pill + " " + StyleStrong.Render(fmt.Sprintf("%d", n))
}

func statVal(n int) string {
	return StyleStrong.Render(fmt.Sprintf("%d", n))
}

func statValAlert(n int) string {
	if n > 0 {
		return StyleFail.Bold(true).Render(fmt.Sprintf("%d", n))
	}
	return statVal(n)
}

func severityDot(sev string) string {
	switch sev {
	case "high":
		return StyleFail.Render("●")
	case "med":
		return StyleWarn.Render("●")
	default:
		return StyleDim.Render("●")
	}
}

func formatClock(iso string) string {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return "--:--:--"
	}
	return t.Local().Format("15:04:05")
}

func renderPanel(title, body string, width, height int) string {
	titleLine := lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}).
		Bold(true).
		Render(title)
	border := lipgloss.RoundedBorder()
	// MaxHeight/MaxWidth clip overlong content. Without them, content
	// longer than the requested dimensions expands the panel and breaks
	// the surrounding layout.
	style := lipgloss.NewStyle().
		Border(border).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#CBD5E1", Dark: "#334155"}).
		Width(width).
		Height(height).
		MaxWidth(width + 2).
		MaxHeight(height + 2)
	header := lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#94A3B8", Dark: "#64748B"}).
		Render(strings.Repeat("─", width-2))
	// Newline between header and body forces body to start at column 0
	// of its own row. Without it lipgloss's wordwrap kicks in (the
	// rule + first body line exceed the panel width) and eats the
	// leading space of the first row, which made the severity dot
	// disappear on the top action-queue item and shifted the first
	// live-feed line left by one column.
	return style.Render(titleLine + "\n" + header + "\n" + body)
}
