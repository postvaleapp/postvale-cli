package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// NOC console - mirrors /dashboard/noc on the webapp. Three-pane
// layout (domains | action queue + live feed), polish on top: cursor
// navigation, sparkline trends, search, sort, severity tints, status
// pill, UTC clock, critical-grade flash + bell, help overlay, compact
// mode for narrow terminals.

const (
	pollSummary = 30 * time.Second
	pollFeed    = 6 * time.Second
	feedBuffer  = 200

	// Sparkline width per domain row, expressed in glyphs.
	sparkW = 8

	// How long the legend popup stays visible after `g`.
	legendDuration = 3 * time.Second

	// How long the border flashes red after a domain regresses to F.
	flashDuration = 2 * time.Second

	// Minimum splash visibility. The first poll usually returns in
	// well under this; pad to a deliberate brand moment so the
	// splash isn't a 200ms flicker.
	splashDuration = 1500 * time.Millisecond

	// Clock tick. 100ms drives animations (spinner frames, pulsing
	// indicators, flash strobe). View only re-renders when something
	// actually changes so this isn't expensive in practice.
	clockTick = 100 * time.Millisecond
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var gradeBuckets = []string{"A+", "A", "B", "C", "D", "F", "-"}

// Sort modes for the domains pane. Cycled with `s`.
const (
	sortWorstFirst = iota
	sortHostAlpha
	sortAgeNewest
	sortAgeOldest
)

func sortLabel(m int) string {
	switch m {
	case sortHostAlpha:
		return "host"
	case sortAgeNewest:
		return "newest"
	case sortAgeOldest:
		return "stale"
	default:
		return "worst"
	}
}

type nocKeymap struct {
	Pause   key.Binding
	Refresh key.Binding
	Help    key.Binding
	Quit    key.Binding
	Up      key.Binding
	Down    key.Binding
	Enter   key.Binding
	Search  key.Binding
	Sort    key.Binding
	Compact key.Binding
	Bell    key.Binding
	Legend  key.Binding
	Escape  key.Binding
}

func newNocKeymap() nocKeymap {
	return nocKeymap{
		Pause:   key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Enter:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open detail")),
		Search:  key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		Sort:    key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "cycle sort")),
		Compact: key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "compact layout")),
		Bell:    key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "bell on critical")),
		Legend:  key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "grade legend")),
		Escape:  key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	}
}

func (k nocKeymap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Search, k.Sort, k.Pause, k.Refresh, k.Help, k.Quit}
}

func (k nocKeymap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter, k.Search},
		{k.Sort, k.Compact, k.Bell, k.Legend},
		{k.Pause, k.Refresh, k.Help, k.Quit},
	}
}

// NocModel holds the live NOC state.
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

	// Polish state.
	cursor      int
	sortMode    int
	searchMode  bool
	searchInput string
	compactMode bool
	bellEnabled bool
	showHelp    bool
	legendUntil time.Time
	// prevGrades tracks the last seen worstGrade per monitored-domain
	// ID so we can detect regression -> F transitions and flash the
	// border briefly when a domain just went critical.
	prevGrades map[string]string
	flashUntil time.Time

	// Non-nil when the user has drilled into a domain. View() branches
	// on this; key handling routes to handleDetailKey while it's set.
	detailDomain *api.MonitoredDomain

	// Birth time of the model. Used to keep the splash on screen for
	// at least splashDuration so it doesn't 200ms-flash and disappear.
	bornAt time.Time
}

func NewNoc(client *api.Client) NocModel {
	now := time.Now()
	return NocModel{
		client:     client,
		keys:       newNocKeymap(),
		help:       help.New(),
		now:        now,
		bornAt:     now,
		prevGrades: make(map[string]string),
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

// bellCmd writes a single BEL byte to stderr. Wrapped in a tea.Cmd so
// rendering is not interrupted; bubbletea writes to stdout so stderr
// goes straight to the terminal.
func bellCmd() tea.Cmd {
	return func() tea.Msg {
		_, _ = os.Stderr.Write([]byte{0x07})
		return nil
	}
}

// ----- bubbletea wiring -----

func (m NocModel) Init() tea.Cmd {
	return tea.Batch(
		m.fetchSummary(),
		m.fetchFeed(),
		nocTickEvery(pollSummary, nocTickSummaryMsg{}),
		nocTickEvery(pollFeed, nocTickFeedMsg{}),
		nocTickEvery(clockTick, nocTickClockMsg{}),
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
		return m, nocTickEvery(clockTick, nocTickClockMsg{})

	case nocTickSummaryMsg:
		if m.paused {
			return m, nocTickEvery(pollSummary, nocTickSummaryMsg{})
		}
		return m, tea.Batch(m.fetchSummary(), nocTickEvery(pollSummary, nocTickSummaryMsg{}))

	case nocTickFeedMsg:
		if m.paused {
			return m, nocTickEvery(pollFeed, nocTickFeedMsg{})
		}
		return m, tea.Batch(m.fetchFeed(), nocTickEvery(pollFeed, nocTickFeedMsg{}))

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

		// Detect new D/F transitions per domain. Flash + bell once
		// per regression so an idle operator sees + hears something
		// when posture drops, without spamming on every poll.
		flash := false
		for _, d := range msg.domains {
			prev := m.prevGrades[d.ID]
			cur := d.LastWorstGrade
			if isCritical(cur) && !isCritical(prev) {
				flash = true
			}
			m.prevGrades[d.ID] = cur
		}
		if flash {
			m.flashUntil = time.Now().Add(flashDuration)
			if m.bellEnabled {
				return m, bellCmd()
			}
		}
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
		if len(combined) > feedBuffer {
			combined = combined[:feedBuffer]
		}
		m.feed = combined
		m.feedCursor = msg.scans[0].RanAt
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m NocModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Detail-view captures keys before anything else so esc / b / r
	// map to the detail-pane bindings instead of the main keymap.
	if m.detailDomain != nil {
		return m.handleDetailKey(msg)
	}

	// Search-mode swallows printable input so a `/` in a domain name
	// can be typed. Escape exits + clears, Enter exits + keeps the
	// filter, Backspace deletes a char.
	if m.searchMode {
		switch msg.String() {
		case "esc":
			m.searchMode = false
			m.searchInput = ""
		case "enter":
			m.searchMode = false
		case "backspace":
			if len(m.searchInput) > 0 {
				m.searchInput = m.searchInput[:len(m.searchInput)-1]
			}
		default:
			// Accept any single printable rune.
			r := []rune(msg.String())
			if len(r) == 1 && unicode.IsPrint(r[0]) {
				m.searchInput += string(r)
			}
		}
		return m, nil
	}

	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Escape):
		m.showHelp = false
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused
	case key.Matches(msg, m.keys.Refresh):
		return m, tea.Batch(m.fetchSummary(), m.fetchFeed())
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(msg, m.keys.Down):
		visible := len(m.visibleDomains())
		if visible > 0 && m.cursor < visible-1 {
			m.cursor++
		}
	case key.Matches(msg, m.keys.Enter):
		doms := m.visibleDomains()
		if m.cursor < len(doms) {
			d := doms[m.cursor]
			m.detailDomain = &d
		}
	case key.Matches(msg, m.keys.Search):
		m.searchMode = true
		m.searchInput = ""
	case key.Matches(msg, m.keys.Sort):
		m.sortMode = (m.sortMode + 1) % 4
		m.cursor = 0
	case key.Matches(msg, m.keys.Compact):
		m.compactMode = !m.compactMode
	case key.Matches(msg, m.keys.Bell):
		m.bellEnabled = !m.bellEnabled
		m.legendUntil = time.Now().Add(legendDuration)
	case key.Matches(msg, m.keys.Legend):
		m.legendUntil = time.Now().Add(legendDuration)
	}
	return m, nil
}

// handleDetailKey is the keymap while a domain detail view is open.
// Intentionally small: back out, escalate to browser, refresh, quit.
func (m NocModel) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.detailDomain = nil
	case "b":
		if m.detailDomain != nil {
			openURL(m.client.BaseURL() + "/dashboard/" + m.detailDomain.ID)
		}
	case "r":
		return m, tea.Batch(m.fetchSummary(), m.fetchFeed())
	case "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// ----- view -----

func (m NocModel) View() string {
	if m.inSplash() {
		return m.renderSplash()
	}
	if m.detailDomain != nil {
		return m.renderShell(m.renderDetail())
	}
	body := m.renderStatsBar() + "\n\n" + m.renderPanes()
	if m.now.Before(m.legendUntil) {
		body += "\n" + m.renderLegend()
	}
	if m.searchMode || m.searchInput != "" {
		body += "\n" + m.renderSearchBar()
	}
	out := m.renderShell(body)
	if m.showHelp {
		out = m.renderHelpOverlay(out)
	}
	return out
}

// inSplash returns true while the boot splash should stay visible.
// We hold it for at least splashDuration even after data has loaded
// so the brand moment doesn't 200ms-flash and disappear. Also stays
// if the first poll genuinely hasn't returned yet.
func (m NocModel) inSplash() bool {
	if !m.loaded && m.err == nil {
		return true
	}
	return time.Since(m.bornAt) < splashDuration
}

// renderSplash is the boot screen. Branded panel + a tagline + an
// animated braille spinner. Stays for at least splashDuration; the
// spinner advances on the 100ms clock tick so it visibly rotates
// across the visible window rather than freezing on one frame.
func (m NocModel) renderSplash() string {
	title := lipgloss.NewStyle().
		Foreground(colAmber).
		Bold(true).
		Render("POSTVALE  ·  NOC")
	tagline := StyleDim.Render("live operations console")

	spinIdx := int(m.now.UnixMilli()/100) % len(spinnerFrames)
	spinChar := lipgloss.NewStyle().Foreground(colAmber).Render(spinnerFrames[spinIdx])
	loading := spinChar + "  " + StyleDim.Italic(true).Render("preparing live feed…")

	box := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(colAmber).
		Padding(1, 6).
		Render(title + "\n\n" + tagline)

	body := box + "\n\n" + loading
	if m.width == 0 || m.height == 0 {
		return body
	}
	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center, body)
}

func (m NocModel) renderShell(body string) string {
	header := m.renderHeader()
	footer := m.renderFooter()
	return header + body + "\n" + footer
}

func (m NocModel) renderHeader() string {
	// Pulse the live indicator on 1Hz, driven by milliseconds so the
	// alternation looks even regardless of when the operator opened
	// the TUI. Paused shows a steady ● for unambiguous "we stopped".
	liveDot := "●"
	if (m.now.UnixMilli()/500)%2 == 0 {
		liveDot = "○"
	}
	live := StyleOK.Render(liveDot + " live")
	if m.paused {
		live = StyleWarn.Render("● paused")
	}
	clock := StyleDim.Render(m.now.UTC().Format("15:04:05") + " UTC")
	syncedAgo := "-"
	if !m.lastSync.IsZero() {
		syncedAgo = formatAgo(m.now.Sub(m.lastSync)) + " ago"
	}
	left := StyleHeader.Render("POSTVALE · NOC")
	right := fmt.Sprintf("%s  %s  %s",
		clock,
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
	rule := strings.Repeat("─", max(0, m.width))
	// Flash overlay: pulse the rule between bright bold heavy and a
	// dimmer thin version at 4Hz across the flashDuration window so
	// the regression visibly throbs instead of glowing steady red.
	if m.now.Before(m.flashUntil) {
		w := max(0, m.width)
		if (m.now.UnixMilli()/125)%2 == 0 {
			rule = StyleFail.Bold(true).Render(strings.Repeat("━", w))
		} else {
			rule = lipgloss.NewStyle().Foreground(colRed).Render(strings.Repeat("─", w))
		}
	} else {
		rule = StyleDim.Render(rule)
	}
	return left + pad + right + "\n" + rule + "\n"
}

func (m NocModel) renderFooter() string {
	var errLine string
	if m.err != nil {
		errLine = StyleFail.Render("! "+m.err.Error()) + "\n"
	}
	if m.detailDomain != nil {
		return errLine + StyleDim.Render(
			"b open in browser · esc back · r refresh · q quit",
		)
	}
	return errLine + m.help.View(m.keys)
}

func (m NocModel) renderStatsBar() string {
	if m.summary == nil {
		return "  " + StyleDim.Render("(no data)")
	}
	s := m.summary
	parts := []string{m.renderStatusPill(s.GradeDistribution)}
	parts = append(parts, statVal(s.MonitoredCount)+" "+StyleDim.Render("domains"))
	for _, g := range gradeBuckets {
		v := s.GradeDistribution[g]
		parts = append(parts, gradeBucket(g, v))
	}
	parts = append(parts,
		statValAlert(s.BlocklistHits)+" "+StyleDim.Render("blocked"),
		statVal(s.RecentAlertCount24h)+" "+StyleDim.Render("alerts/24h"),
	)
	if m.bellEnabled {
		parts = append(parts, StyleWarn.Render("🔔 on"))
	}
	return "  " + strings.Join(parts, "  ")
}

// renderStatusPill computes a coloured one-glance verdict from the
// grade distribution. ALL GREEN if everyone's A/A+, INCIDENT if any
// D/F, DEGRADED if any B/C without D/F.
func (m NocModel) renderStatusPill(g map[string]int) string {
	red := g["D"] + g["F"]
	amber := g["B"] + g["C"]
	if red > 0 {
		return StyleFail.Bold(true).Render(
			fmt.Sprintf("● INCIDENT: %d failing", red),
		)
	}
	if amber > 0 {
		return StyleWarn.Bold(true).Render(
			fmt.Sprintf("● DEGRADED: %d", amber),
		)
	}
	if g["A"]+g["A+"] > 0 {
		return StyleOK.Bold(true).Render("● ALL GREEN")
	}
	return StyleDim.Render("● NO DATA")
}

func (m NocModel) renderPanes() string {
	if m.compactMode {
		return m.renderCompact()
	}

	// Two columns: domains (~60% width) | right stack (~40%).
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

	left := renderPanel(m.domainsPanelTitle(),
		m.renderDomains(bodyH-4), leftW, bodyH)
	queueCount := 0
	if m.summary != nil {
		queueCount = len(m.summary.ActionQueue)
	}
	rightTop := renderPanel(fmt.Sprintf("ACTION QUEUE · %d", queueCount),
		m.renderActionQueue(rightH-4), rightW, rightH)
	rightBot := renderPanel("LIVE FEED",
		m.renderLiveFeed(feedH-4), rightW, feedH)
	right := rightTop + "\n" + rightBot

	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

// renderCompact stacks the panels vertically for narrow terminals.
// All three panels get the full width; heights are split evenly.
func (m NocModel) renderCompact() string {
	w := m.width - 4
	if w < 30 {
		w = 30
	}
	bodyH := m.height - 8
	if bodyH < 18 {
		bodyH = 18
	}
	domH := bodyH * 2 / 5
	queueH := bodyH / 5
	feedH := bodyH - domH - queueH - 2

	queueCount := 0
	if m.summary != nil {
		queueCount = len(m.summary.ActionQueue)
	}

	domains := renderPanel(m.domainsPanelTitle(),
		m.renderDomains(domH-4), w, domH)
	queue := renderPanel(fmt.Sprintf("ACTION QUEUE · %d", queueCount),
		m.renderActionQueue(queueH-4), w, queueH)
	feed := renderPanel("LIVE FEED",
		m.renderLiveFeed(feedH-4), w, feedH)
	return domains + "\n" + queue + "\n" + feed
}

func (m NocModel) domainsPanelTitle() string {
	base := fmt.Sprintf("DOMAINS · %d", len(m.visibleDomains()))
	tail := fmt.Sprintf("sort:%s", sortLabel(m.sortMode))
	if m.searchInput != "" {
		tail += " · /" + m.searchInput
	}
	return base + " · " + tail
}

// ----- domains pane -----

func (m NocModel) visibleDomains() []api.MonitoredDomain {
	doms := filterDomains(m.domains, m.searchInput)
	return sortDomains(doms, m.sortMode)
}

func filterDomains(in []api.MonitoredDomain, q string) []api.MonitoredDomain {
	if q == "" {
		return in
	}
	q = strings.ToLower(q)
	out := make([]api.MonitoredDomain, 0, len(in))
	for _, d := range in {
		if strings.Contains(strings.ToLower(d.Host), q) {
			out = append(out, d)
		}
	}
	return out
}

func sortDomains(in []api.MonitoredDomain, mode int) []api.MonitoredDomain {
	out := append([]api.MonitoredDomain{}, in...)
	switch mode {
	case sortHostAlpha:
		sort.SliceStable(out, func(i, j int) bool {
			return strings.ToLower(out[i].Host) < strings.ToLower(out[j].Host)
		})
	case sortAgeNewest:
		sort.SliceStable(out, func(i, j int) bool {
			return parseTimePtr(out[i].LastCheckedAt).After(parseTimePtr(out[j].LastCheckedAt))
		})
	case sortAgeOldest:
		sort.SliceStable(out, func(i, j int) bool {
			return parseTimePtr(out[i].LastCheckedAt).Before(parseTimePtr(out[j].LastCheckedAt))
		})
	default:
		// Worst-first (F highest rank). Secondary: host alpha so the
		// view is stable across polls.
		sort.SliceStable(out, func(i, j int) bool {
			ri, rj := gradeRank(out[i].LastWorstGrade), gradeRank(out[j].LastWorstGrade)
			if ri != rj {
				return ri > rj
			}
			return strings.ToLower(out[i].Host) < strings.ToLower(out[j].Host)
		})
	}
	return out
}

func gradeRank(g string) int {
	switch g {
	case "F":
		return 6
	case "D":
		return 5
	case "C":
		return 4
	case "B":
		return 3
	case "A":
		return 2
	case "A+":
		return 1
	default:
		return 0
	}
}

func (m NocModel) renderDomains(maxLines int) string {
	doms := m.visibleDomains()
	if len(doms) == 0 {
		if m.searchInput != "" {
			return "\n  " + StyleDim.Render("no matches for /"+m.searchInput) + "\n"
		}
		return "\n  " + StyleDim.Render("No monitored domains. Add one with `postvale watch add <domain>`.") + "\n"
	}

	cursor := m.cursor
	if cursor >= len(doms) {
		cursor = len(doms) - 1
	}
	if cursor < 0 {
		cursor = 0
	}

	var b strings.Builder
	// Header row. Two leading spaces (`  `) align with row data that
	// has a 2-char cursor / spacer prefix.
	b.WriteString("  ")
	b.WriteString(colHeader("Host", 26))
	b.WriteString(colHeader("Grade", 6))
	b.WriteString(colHeader("Trend", sparkW+1))
	b.WriteString(colHeader("TLS", 4))
	b.WriteString(colHeader("DMARC", 6))
	b.WriteString(colHeader("DNS", 4))
	b.WriteString(colHeader("HDR", 4))
	b.WriteString(colHeader("MTA", 4))
	b.WriteString(colHeader("Last", 7))
	b.WriteString("\n")

	if maxLines > 0 && len(doms) > maxLines-1 {
		doms = doms[:maxLines-1]
	}

	for i, d := range doms {
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

		prefix := "  "
		if i == cursor {
			prefix = StyleHeader.Render("❯ ")
		}
		b.WriteString(prefix)
		hostCell := truncate(host, 26)
		if i == cursor {
			hostCell = StyleStrong.Render(hostCell)
		}
		b.WriteString(hostCell)
		b.WriteString(GradeStyle(grade).Render(padRight(grade, 6)))
		b.WriteString(sparkline(m.feed, d.Host, sparkW))
		b.WriteString(" ")
		b.WriteString(subGrade(d.LastGrades, "tls", 4))
		b.WriteString(subGrade(d.LastGrades, "dmarc", 6))
		b.WriteString(subGrade(d.LastGrades, "dns", 4))
		b.WriteString(subGrade(d.LastGrades, "headers", 4))
		b.WriteString(subGrade(d.LastGrades, "mtaSts", 4))
		b.WriteString(StyleDim.Render(padRight(last, 7)))
		b.WriteString("\n")
	}
	return b.String()
}

// sparkline renders an N-cell trend strip per domain row. Bar height
// encodes grade quality (A+ tallest, F shortest) AND colour encodes
// severity (green / amber / red). Together that means a row of D/F
// scans reads as short red bars `▁▂▁▁▂` instead of a slab of full
// blocks; a row of A grades reads as tall green bars. Padding for
// hosts with not enough scan history yet uses a dim middle dot so
// "no data yet" is visually distinct from any real grade.
func sparkline(feed []api.RecentScan, host string, n int) string {
	var scans []api.RecentScan
	for _, s := range feed {
		if s.Host == host {
			scans = append(scans, s)
			if len(scans) >= n {
				break
			}
		}
	}
	// Feed comes newest-first; reverse so the right side is the most
	// recent scan, matching the eye-direction operators expect.
	for i, j := 0, len(scans)-1; i < j; i, j = i+1, j-1 {
		scans[i], scans[j] = scans[j], scans[i]
	}
	pad := n - len(scans)
	var b strings.Builder
	for i := 0; i < pad; i++ {
		b.WriteString(StyleDim.Render("·"))
	}
	for _, s := range scans {
		g := s.WorstGrade
		if g == "" {
			g = "-"
		}
		b.WriteString(GradeStyle(g).Render(gradeBlock(g)))
	}
	return b.String()
}

// bigGradeArt - 5-row ASCII letter shapes for the worst-grade hero
// pill in the detail view. Wide enough (9 cols) to read from across
// a NOC monitor.
var bigGradeArt = map[string][]string{
	"A+": {
		" █████  ╷ ",
		"██   ██╶┼╴",
		"███████ ╵ ",
		"██   ██   ",
		"██   ██   ",
	},
	"A": {
		" █████  ",
		"██   ██ ",
		"███████ ",
		"██   ██ ",
		"██   ██ ",
	},
	"B": {
		"██████  ",
		"██   ██ ",
		"██████  ",
		"██   ██ ",
		"██████  ",
	},
	"C": {
		" ██████ ",
		"██      ",
		"██      ",
		"██      ",
		" ██████ ",
	},
	"D": {
		"██████  ",
		"██   ██ ",
		"██   ██ ",
		"██   ██ ",
		"██████  ",
	},
	"F": {
		"███████ ",
		"██      ",
		"█████   ",
		"██      ",
		"██      ",
	},
	"-": {
		"        ",
		"        ",
		"███████ ",
		"        ",
		"        ",
	},
}

func bigGradeLetter(g string) string {
	art, ok := bigGradeArt[g]
	if !ok {
		art = bigGradeArt["-"]
	}
	style := GradeStyle(g).Bold(true)
	lines := make([]string, len(art))
	for i, line := range art {
		lines[i] = style.Render(line)
	}
	return strings.Join(lines, "\n")
}

// activityHistogram buckets scans per hour for the last N hours and
// renders the counts as a horizontal block-height bar strip. Empty
// hours render as a dim middle dot so the timeline reads as "we
// haven't seen activity here" rather than "this slot is empty
// data."
func activityHistogram(feed []api.RecentScan, host string, hours int, now time.Time) string {
	counts := make([]int, hours)
	for _, s := range feed {
		if s.Host != host {
			continue
		}
		t, err := time.Parse(time.RFC3339, s.RanAt)
		if err != nil {
			continue
		}
		delta := now.Sub(t)
		h := int(delta.Hours())
		if h < 0 || h >= hours {
			continue
		}
		counts[hours-1-h]++
	}
	maxC := 1
	for _, c := range counts {
		if c > maxC {
			maxC = c
		}
	}
	blocks := []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	var b strings.Builder
	for _, c := range counts {
		if c == 0 {
			b.WriteString(StyleDim.Render("·"))
			continue
		}
		idx := c * (len(blocks) - 1) / maxC
		b.WriteString(StyleOK.Render(blocks[idx]))
	}
	return b.String()
}

// heatmap renders a 7-day × 24-hour activity grid (github-style
// contribution graph). Each cell encodes scans seen in that
// (day, hour) bucket: dim · for empty, brighter blocks for busier
// hours. Bottom row is today; oldest day is at the top. Labels on
// the left name the weekday; the bottom axis labels marker hours.
func heatmap(feed []api.RecentScan, host string, now time.Time) string {
	const days = 7
	const hours = 24

	counts := make([][hours]int, days)
	for _, s := range feed {
		if s.Host != host {
			continue
		}
		t, err := time.Parse(time.RFC3339, s.RanAt)
		if err != nil {
			continue
		}
		t = t.Local()
		dayDelta := int(now.Truncate(24*time.Hour).Sub(t.Truncate(24*time.Hour)).Hours() / 24)
		if dayDelta < 0 || dayDelta >= days {
			continue
		}
		counts[days-1-dayDelta][t.Hour()]++
	}
	maxC := 1
	for _, row := range counts {
		for _, c := range row {
			if c > maxC {
				maxC = c
			}
		}
	}

	weekdays := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	todayIdx := int(now.Weekday())

	var b strings.Builder
	for i := 0; i < days; i++ {
		// Row 0 is the oldest (6 days ago); row days-1 is today.
		dayOffset := days - 1 - i
		weekdayIdx := (todayIdx - dayOffset + 7) % 7
		b.WriteString(StyleDim.Render(weekdays[weekdayIdx] + " "))
		for h := 0; h < hours; h++ {
			c := counts[i][h]
			switch {
			case c == 0:
				b.WriteString(StyleDim.Render("·"))
			case c == 1:
				b.WriteString(lipgloss.NewStyle().Foreground(colEmerald).Render("▪"))
			case c*3 < maxC*2:
				b.WriteString(lipgloss.NewStyle().Foreground(colEmerald).Bold(true).Render("▪"))
			default:
				b.WriteString(lipgloss.NewStyle().Foreground(colEmerald).Bold(true).Render("█"))
			}
		}
		b.WriteString("\n")
	}
	// Hour axis.
	b.WriteString(StyleDim.Render("    "))
	for h := 0; h < hours; h++ {
		switch h {
		case 0, 6, 12, 18:
			b.WriteString(StyleDim.Render(fmt.Sprintf("%-1d", h/10)))
		default:
			b.WriteString(StyleDim.Render(" "))
		}
	}
	b.WriteString("\n    ")
	for h := 0; h < hours; h++ {
		switch h {
		case 0, 6, 12, 18:
			b.WriteString(StyleDim.Render(fmt.Sprintf("%d", h%10)))
		default:
			b.WriteString(StyleDim.Render(" "))
		}
	}
	return b.String()
}

// gradeBlock maps a letter grade to a Unicode partial-block character
// of proportional height. Used by the sparkline + the detail view so
// the visual is consistent.
func gradeBlock(g string) string {
	switch g {
	case "A+":
		return "█"
	case "A":
		return "▇"
	case "B":
		return "▅"
	case "C":
		return "▄"
	case "D":
		return "▂"
	case "F":
		return "▁"
	default:
		return "·"
	}
}

func subGrade(grades map[string]string, key string, width int) string {
	if grades == nil {
		return StyleDim.Render(padRight("-", width))
	}
	g := grades[key]
	if g == "" && key == "mtaSts" {
		g = grades["mta-sts"]
	}
	if g == "" {
		return StyleDim.Render(padRight("-", width))
	}
	return GradeStyle(g).Render(padRight(g, width))
}

// ----- action queue -----

func (m NocModel) renderActionQueue(maxLines int) string {
	if m.summary == nil || len(m.summary.ActionQueue) == 0 {
		return "\n  " + StyleOK.Render("✓") + StyleDim.Render(" nothing to action") + "\n"
	}
	items := m.summary.ActionQueue
	if maxLines > 0 && len(items) > maxLines {
		items = items[:maxLines]
	}
	var b strings.Builder
	for _, it := range items {
		dot := severityDot(it.Severity)
		domain := truncate(it.Domain, 18)
		msg := truncate(it.Message, 38)
		age := formatAgo(m.now.Sub(parseTime(it.DetectedAt)))
		row := fmt.Sprintf(" %s %s %s %s",
			dot,
			StyleStrong.Render(padRight(domain, 18)),
			StyleDim.Render(padRight(msg, 38)),
			StyleDim.Render(padRight(age, 4)),
		)
		// Subtle severity tint - colours the row indicator more
		// strongly. Don't paint full-row backgrounds (lipgloss spans
		// past panel borders on some terminals and looks broken).
		switch it.Severity {
		case "high":
			row = StyleFail.Render("│") + row
		case "med":
			row = StyleWarn.Render("│") + row
		default:
			row = StyleDim.Render("│") + row
		}
		b.WriteString(row + "\n")
	}
	return b.String()
}

// ----- live feed -----

func (m NocModel) renderLiveFeed(maxLines int) string {
	feed := filterFeed(m.feed, m.searchInput)
	if len(feed) == 0 {
		if m.searchInput != "" {
			return "\n  " + StyleDim.Render("no matches for /"+m.searchInput) + "\n"
		}
		return "\n  " + StyleDim.Render("waiting for the next scan…") + "\n"
	}
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
			truncate(s.Host, 26),
			GradeStyle(grade).Render(grade),
		))
	}
	return b.String()
}

func filterFeed(in []api.RecentScan, q string) []api.RecentScan {
	if q == "" {
		return in
	}
	q = strings.ToLower(q)
	out := make([]api.RecentScan, 0, len(in))
	for _, s := range in {
		if strings.Contains(strings.ToLower(s.Host), q) {
			out = append(out, s)
		}
	}
	return out
}

// ----- modal / overlays -----

// renderHelpOverlay draws the full keymap centered over the current
// view. We dim the underlying chrome so the operator's attention lands
// on the key list, not the background data.
func (m NocModel) renderHelpOverlay(under string) string {
	rows := [][2]string{
		{"↑/k, ↓/j", "move cursor through domains"},
		{"enter", "open per-domain detail view"},
		{"/", "search filter (domains + feed)"},
		{"esc", "exit search / close help / leave detail"},
		{"s", "cycle sort: worst → host → newest → stale"},
		{"c", "compact layout (single column)"},
		{"b", "toggle bell on critical regression"},
		{"g", "grade legend (3s popup)"},
		{"p", "pause / resume polling"},
		{"r", "refresh now"},
		{"?", "toggle this help"},
		{"q", "quit"},
		{"", ""},
		{"in detail:", "b open in browser · esc back · r refresh"},
	}
	var b strings.Builder
	b.WriteString(StyleHeader.Render("KEY BINDINGS") + "\n")
	b.WriteString(StyleDim.Render(strings.Repeat("─", 40)) + "\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			StyleStrong.Render(padRight(r[0], 12)),
			StyleDim.Render(r[1]),
		))
	}
	b.WriteString("\n" + StyleDim.Render("? to close") + "\n")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colAmber).
		Background(lipgloss.Color("#0B1220")).
		Padding(1, 2).
		Render(b.String())
	if m.width == 0 || m.height == 0 {
		return box
	}
	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		box,
		lipgloss.WithWhitespaceChars(" "),
	)
}

// renderLegend renders a short pill strip showing the grade-colour
// mapping. Triggered by `g`; auto-hides after legendDuration. Acts as
// a colour key for new operators + a confirmation chip when `b`
// toggles bell.
func (m NocModel) renderLegend() string {
	parts := []string{
		GradeStyle("A+").Render("A+/A") + " " + StyleDim.Render("green"),
		GradeStyle("B").Render("B/C") + " " + StyleDim.Render("amber"),
		GradeStyle("F").Render("D/F") + " " + StyleDim.Render("red"),
	}
	bell := "bell: " + boolLabel(m.bellEnabled)
	return "  " + strings.Join(parts, "   ") + "   " + StyleDim.Render(bell)
}

// renderDetail draws the per-domain drill-in view. Hero strip at the
// top has a chunky ASCII grade letter on the left + key facts on the
// right. Below: sub-grade table beside an activity histogram, then
// the chronological recent-scan list and any open action items.
func (m NocModel) renderDetail() string {
	d := *m.detailDomain

	hostPort := d.Host
	if d.Port != 443 {
		hostPort = fmt.Sprintf("%s:%d", d.Host, d.Port)
	}

	grade := d.LastWorstGrade
	if grade == "" {
		grade = "-"
	}
	last := "-"
	if d.LastCheckedAt != nil {
		last = formatAgo(m.now.Sub(parseTime(*d.LastCheckedAt))) + " ago"
	}

	var out strings.Builder

	// Title strip.
	title := StyleHeader.Render("DOMAIN · " + hostPort)
	out.WriteString(title + "\n")
	out.WriteString(StyleDim.Render(strings.Repeat("─", max(40, lipgloss.Width(title)+20))) + "\n\n")

	// Hero: huge ASCII grade letter on the left, key facts stacked on
	// the right. Reads at a distance.
	bigLetter := bigGradeLetter(grade)
	cadence := fmt.Sprintf("every %dm", d.CadenceMinutes)
	status := StyleOK.Render("active")
	if d.Paused {
		status = StyleWarn.Render("paused")
	}
	facts := []string{
		StyleDim.Render("Worst grade: ") + GradeStyle(grade).Bold(true).Render(grade),
		StyleDim.Render("Last scan:   ") + StyleStrong.Render(last),
		StyleDim.Render("Cadence:     ") + StyleStrong.Render(cadence),
		StyleDim.Render("Status:      ") + status,
		"",
	}
	hero := lipgloss.JoinHorizontal(lipgloss.Top,
		bigLetter,
		"   ",
		strings.Join(facts, "\n"),
	)
	out.WriteString(hero + "\n\n")

	// Sub-grades on the left, activity histogram on the right. Two
	// columns of independent height; lipgloss aligns them at the top.
	tools := []struct {
		key, label string
	}{
		{"tls", "TLS"},
		{"dmarc", "DMARC"},
		{"dns", "DNS"},
		{"headers", "Headers"},
		{"mtaSts", "MTA-STS"},
	}
	var subgrades strings.Builder
	subgrades.WriteString(StyleHeader.Render("Sub-grades") + "\n")
	for _, t := range tools {
		g := ""
		if d.LastGrades != nil {
			g = d.LastGrades[t.key]
			if g == "" && t.key == "mtaSts" {
				g = d.LastGrades["mta-sts"]
			}
		}
		if g == "" {
			g = "-"
		}
		subgrades.WriteString(fmt.Sprintf("  %s  %s\n",
			padRight(t.label, 9),
			GradeStyle(g).Render(padRight(g, 3)),
		))
	}

	var activity strings.Builder
	activity.WriteString(StyleHeader.Render("Activity (last 12h)") + "\n")
	activity.WriteString("  " + activityHistogram(m.feed, d.Host, 12, m.now) + "\n")
	activity.WriteString("  " + StyleDim.Render("12h ago         now") + "\n\n")
	activity.WriteString(StyleHeader.Render("Recent grade trend") + "\n")
	activity.WriteString("  " + sparkline(m.feed, d.Host, 16) + "\n")
	activity.WriteString("  " + StyleDim.Render("oldest          newest") + "\n")

	twoCol := lipgloss.JoinHorizontal(lipgloss.Top,
		subgrades.String(),
		"      ",
		activity.String(),
	)
	out.WriteString(twoCol + "\n\n")

	// Weekly heatmap - 7×24 grid of scans per (day, hour) for this
	// host. Reveals cadence patterns at a glance (e.g. "this domain
	// scans hourly on weekdays, nothing weekends").
	out.WriteString(StyleHeader.Render("Scan heatmap (last 7 days)") + "\n")
	out.WriteString(heatmap(m.feed, d.Host, m.now) + "\n\n")

	// Recent scans list.
	out.WriteString(StyleHeader.Render("Recent scans") + "\n")
	var scans []api.RecentScan
	for _, s := range m.feed {
		if s.Host == d.Host {
			scans = append(scans, s)
			if len(scans) >= 10 {
				break
			}
		}
	}
	if len(scans) == 0 {
		out.WriteString("  " + StyleDim.Render("no scans observed yet in this session - they will appear here as they run") + "\n")
	} else {
		for _, s := range scans {
			g := s.WorstGrade
			if g == "" {
				g = "-"
			}
			out.WriteString(fmt.Sprintf("  %s  %s  %s\n",
				StyleDim.Render(formatClock(s.RanAt)),
				GradeStyle(g).Render(padRight(g, 3)),
				StyleDim.Render(fmt.Sprintf("%dms", s.DurationMs)),
			))
		}
	}

	// Open action items for this domain.
	if m.summary != nil {
		var items []api.ActionQueueItem
		for _, it := range m.summary.ActionQueue {
			if strings.Contains(it.Domain, d.Host) {
				items = append(items, it)
			}
		}
		if len(items) > 0 {
			out.WriteString("\n" + StyleHeader.Render("Open action items") + "\n")
			for _, it := range items {
				age := formatAgo(m.now.Sub(parseTime(it.DetectedAt)))
				out.WriteString(fmt.Sprintf("  %s  %s  %s\n",
					severityDot(it.Severity),
					StyleStrong.Render(it.Message),
					StyleDim.Render(age),
				))
			}
		}
	}

	return out.String()
}

func (m NocModel) renderSearchBar() string {
	prompt := StyleHeader.Render("/")
	input := m.searchInput
	if m.searchMode {
		input += StyleWarn.Render("_")
	}
	hint := ""
	if m.searchMode {
		hint = StyleDim.Render("   enter accept · esc clear")
	}
	return "  " + prompt + input + hint
}

// ----- helpers -----

func colHeader(label string, width int) string {
	return StyleHeader.Render(padRight(label, width))
}

func padRight(s string, w int) string {
	if lipgloss.Width(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-lipgloss.Width(s))
}

func truncate(s string, w int) string {
	if lipgloss.Width(s) <= w {
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

func parseTimePtr(iso *string) time.Time {
	if iso == nil {
		return time.Time{}
	}
	return parseTime(*iso)
}

func isCritical(g string) bool {
	return g == "D" || g == "F"
}

func boolLabel(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func renderPanel(title, body string, width, height int) string {
	titleLine := lipgloss.NewStyle().
		Foreground(colAmber).
		Bold(true).
		Render(title)
	border := lipgloss.RoundedBorder()
	style := lipgloss.NewStyle().
		Border(border).
		BorderForeground(colSlateDim).
		Width(width).
		Height(height).
		MaxWidth(width + 2).
		MaxHeight(height + 2)
	header := StyleDim.Render(strings.Repeat("─", width-2))
	return style.Render(titleLine + "\n" + header + "\n" + body)
}
