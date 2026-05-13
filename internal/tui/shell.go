package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// Shell is the top-level Model for `postvale tui`. Owns the sidebar,
// the header line, and the registry of mounted page Models. Routes
// keystrokes to the focused element (sidebar OR active page).

// ShellPage enumerates every nav destination. Order is independent of
// sidebar render order; render order lives in sidebarTree below.
type ShellPage int

const (
	PageDashboard ShellPage = iota
	PageNoc
	PageAlerts
	PageBrand
	PageLeak
	PageCreds
	PageVendors
	PageCves
	PageTools
	PageVerify
	PageAccount
)

// Sidebar width includes the right rule character. Sized so the
// longest label ("Postvale CLI") fits with room for a "▸" cursor +
// padding. Pages get width - sidebarWidth when laying out columns.
const sidebarWidth = 22

type sidebarItem struct {
	page  ShellPage
	label string
}

type sidebarSection struct {
	title string
	items []sidebarItem
}

var sidebarTree = []sidebarSection{
	{"WORKSPACE", []sidebarItem{
		{PageDashboard, "Dashboard"},
		{PageNoc, "NOC console"},
		{PageAlerts, "Alerts"},
	}},
	{"MONITORING", []sidebarItem{
		{PageBrand, "Brand watch"},
		{PageLeak, "Leak sites"},
		{PageCreds, "Credentials"},
		{PageVendors, "Vendors"},
		{PageCves, "CVEs"},
	}},
	{"TOOLS", []sidebarItem{
		{PageTools, "Free tools"},
		{PageVerify, "Verify chain"},
	}},
	{"ACCOUNT", []sidebarItem{
		{PageAccount, "Account"},
	}},
}

func flatNav() []sidebarItem {
	out := make([]sidebarItem, 0, 12)
	for _, s := range sidebarTree {
		out = append(out, s.items...)
	}
	return out
}

func navCursorFor(p ShellPage) int {
	for i, it := range flatNav() {
		if it.page == p {
			return i
		}
	}
	return 0
}

// Shell wraps the active page Model and the sidebar state.
type Shell struct {
	client  *api.Client
	apiBase string

	width  int
	height int

	cursor int       // index into flatNav()
	active ShellPage // currently-rendered page

	// Mounted page models. We cache so switching back doesn't refetch.
	// Created lazily on first nav into the page.
	pages map[ShellPage]tea.Model

	// True when arrow keys steer the sidebar. False when arrow keys go
	// to the active page (table cursor, NOC cursor, etc).
	sidebarFocused bool

	// Cached identity, fetched once and shared across pages that want
	// to render "rob@... · Pro" headers.
	me *api.Me

	// Set true when the most recent /me call returned 401 (token
	// revoked or otherwise rejected). Drives the red banner across the
	// top of every page so the operator can't miss it.
	tokenInvalid bool
}

// NewShell constructs the shell. start is the page rendered first.
// `postvale tui` opens on PageDashboard; `postvale noc` opens on
// PageNoc; future shortcuts can drop the caller anywhere.
func NewShell(client *api.Client, apiBase string, start ShellPage) Shell {
	return Shell{
		client:         client,
		apiBase:        apiBase,
		active:         start,
		cursor:         navCursorFor(start),
		pages:          make(map[ShellPage]tea.Model),
		sidebarFocused: false,
	}
}

// shellMeMsg lands when /me returns; the shell uses it to render the
// header identity strip. Sub-page Models that need /me on first paint
// (Account, for instance) fetch their own.
type shellMeMsg struct {
	me  *api.Me
	err error
}

func (s Shell) fetchMe() tea.Cmd {
	c := s.client
	return func() tea.Msg {
		me, err := c.Me()
		return shellMeMsg{me: me, err: err}
	}
}

// ----- bubbletea wiring -----

func (s Shell) Init() tea.Cmd {
	// Bootstrap: fetch /me, instantiate the starting page, run its
	// Init. The "starting page" Model is constructed inside ensurePage
	// rather than NewShell so page Init Cmds run through the program.
	ns, cmd := s.ensurePage(s.active)
	return tea.Batch(ns.fetchMe(), cmd)
}

// ensurePage instantiates the page model if not already mounted and
// returns its Init Cmd. Idempotent - second call just returns nil.
func (s Shell) ensurePage(p ShellPage) (Shell, tea.Cmd) {
	if _, ok := s.pages[p]; ok {
		return s, nil
	}
	var m tea.Model
	switch p {
	case PageDashboard:
		dash := New(s.client, s.apiBase)
		m = dash
	case PageNoc:
		noc := NewNoc(s.client)
		m = noc
	case PageAlerts:
		m = newAlertsPage(s.client, s.apiBase)
	case PageBrand:
		m = newBrandWatchPage(s.client)
	case PageLeak:
		m = newLeakSitesPage(s.client)
	case PageCreds:
		m = newCredentialLeaksPage(s.client)
	case PageVendors:
		m = newVendorWatchPage(s.client)
	case PageCves:
		m = newCvesPage(s.client)
	case PageTools:
		m = newToolsPage(s.client)
	case PageVerify:
		m = newVerifyPage()
	case PageAccount:
		m = newAccountPage(s.client, s.apiBase)
	default:
		return s, nil
	}
	cmd := m.Init()
	s.pages[p] = m
	return s, cmd
}

// Update routes messages. WindowSizeMsg, top-level keys, and the /me
// fetch are handled by the shell; everything else flows through to
// the active page.
func (s Shell) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.width = msg.Width
		s.height = msg.Height
		// Broadcast a downsized WindowSizeMsg to every mounted page so
		// columns + viewports recompute against the content area.
		sub := tea.WindowSizeMsg{
			Width:  pageContentWidth(msg.Width),
			Height: msg.Height,
		}
		var cmds []tea.Cmd
		for id, m := range s.pages {
			nm, cmd := m.Update(sub)
			s.pages[id] = nm
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return s, tea.Batch(cmds...)

	case shellMeMsg:
		if msg.err == nil {
			s.me = msg.me
			s.tokenInvalid = false
		} else if api.IsAuthError(msg.err) {
			// The stored token was revoked or rejected by the server
			// since we last checked. Flag it so View() shows the
			// banner; the operator can Tab+q to quit and re-auth.
			s.tokenInvalid = true
		}
		return s, nil

	case tea.KeyMsg:
		// Quit is global; intercept before anything else can swallow it.
		if msg.String() == "ctrl+c" {
			return s, tea.Quit
		}
		// Tab toggles sidebar focus. Sidebar-focused mode lets the user
		// drive the nav with arrows; page-focused mode forwards keys to
		// the page (so the dashboard table cursor, NOC cursor, search
		// boxes, etc. work normally).
		if msg.String() == "tab" {
			s.sidebarFocused = !s.sidebarFocused
			return s, nil
		}
		if s.sidebarFocused {
			return s.handleSidebarKey(msg)
		}
		// q quits ONLY when the page isn't in a text-input mode. We
		// can't always know that from out here, so we let the page see
		// q + handle quit itself for safety. Most pages don't bind q.
		// As a fallback, only the shell-level Ctrl+C is guaranteed.
		// Forward to active page.
		return s.forwardToActive(msg)
	}

	return s.forwardToActive(msg)
}

func (s Shell) handleSidebarKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	flat := flatNav()
	switch msg.String() {
	case "q":
		return s, tea.Quit
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
		return s, nil
	case "down", "j":
		if s.cursor < len(flat)-1 {
			s.cursor++
		}
		return s, nil
	case "enter", "right", "l":
		if s.cursor < len(flat) {
			target := flat[s.cursor].page
			s.active = target
			s.sidebarFocused = false
			ns, cmd := s.ensurePage(target)
			// Always forward the current window size after navigation.
			// Pages with no Init Cmd (Tools, Verify) won't otherwise
			// receive a WindowSizeMsg until the next terminal resize,
			// which means their viewports stay 0x0 and render nothing.
			if s.width > 0 {
				sub := tea.WindowSizeMsg{
					Width:  pageContentWidth(s.width),
					Height: s.height,
				}
				if m, ok := ns.pages[target]; ok {
					nm, _ := m.Update(sub)
					ns.pages[target] = nm
				}
			}
			return ns, cmd
		}
	}
	return s, nil
}

func (s Shell) forwardToActive(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, ok := s.pages[s.active]
	if !ok {
		return s, nil
	}
	nm, cmd := m.Update(msg)
	// If the page returned tea.Quit (e.g. dashboard.Model on q),
	// honour it.
	s.pages[s.active] = nm
	return s, cmd
}

// pageContentWidth is the per-page renderable width. The shell owns
// the leftmost `sidebarWidth` columns + a 1-char gutter; the page
// gets the rest. Floor at 40 so pages don't collapse to nothing when
// the terminal is genuinely tiny - they just clip.
func pageContentWidth(total int) int {
	w := total - sidebarWidth - 1
	if w < 40 {
		w = 40
	}
	return w
}

// View composes sidebar + page body. Sidebar renders its own
// borders; the page handles its internal layout against the
// content-area width sent via WindowSizeMsg above.
func (s Shell) View() string {
	if s.width == 0 || s.height == 0 {
		return ""
	}
	sb := s.renderSidebar()
	page := ""
	if m, ok := s.pages[s.active]; ok {
		page = m.View()
	}
	if s.tokenInvalid {
		// Prepend a screen-wide banner so it appears above whatever
		// the page is rendering. Width budget = content-area width;
		// lipgloss will pad to that with the .Width modifier.
		w := pageContentWidth(s.width)
		banner := lipgloss.NewStyle().
			Width(w).
			Padding(0, 2).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colRed).
			Bold(true).
			Render("✗ Token rejected by the server. Run `postvale auth login` to re-authenticate.  " +
				"(Browser logout does not revoke CLI tokens; manage at /account.)")
		page = banner + "\n" + page
	}
	// Place sidebar (fixed width) next to the page body. The lipgloss
	// JoinHorizontal handles uneven heights by padding the shorter
	// side with blank lines.
	return lipgloss.JoinHorizontal(lipgloss.Top, sb, page)
}

func (s Shell) renderSidebar() string {
	// Style budget: title bold-amber, item slate, active item amber +
	// "▸" prefix, focused-sidebar items underlined faint to signal "you
	// drive arrows here". Width is fixed at sidebarWidth - 1 (the
	// rightmost column is a rule).
	width := sidebarWidth - 2
	if width < 12 {
		width = 12
	}

	var lines []string
	lines = append(lines, StyleHeader.Render("POSTVALE"))
	if s.me != nil {
		ident := s.me.User.Email
		if len(ident) > width {
			ident = ident[:width]
		}
		lines = append(lines, StyleDim.Render(ident))
		tier := s.me.User.TierLabel
		if tier == "" {
			tier = s.me.User.Tier
		}
		if tier != "" {
			lines = append(lines, StyleLabel.Render(tier))
		}
	}
	lines = append(lines, "")

	idx := 0
	for _, sec := range sidebarTree {
		lines = append(lines, StyleLabel.Render(sec.title))
		for _, it := range sec.items {
			cursor := "  "
			label := it.label
			style := lipgloss.NewStyle().Foreground(colSlateStrong)
			if it.page == s.active {
				cursor = StyleHeader.Render("▸ ")
				style = StyleHeader
			} else if s.sidebarFocused && idx == s.cursor {
				cursor = StyleLabel.Render("· ")
				style = lipgloss.NewStyle().Foreground(colAmberMid).Underline(true)
			}
			lines = append(lines, cursor+style.Render(label))
			idx++
		}
		lines = append(lines, "")
	}

	// Footer hint inside the sidebar - what Tab does, what q does.
	hint := "Tab focus · q quit"
	if s.sidebarFocused {
		hint = "Tab leave · ↵ open"
	}
	lines = append(lines, "", StyleDim.Render(hint))

	body := strings.Join(lines, "\n")

	// Box: fixed width, fixed height (terminal height) so the right
	// rule extends top-to-bottom. Pad to height with spaces.
	box := lipgloss.NewStyle().
		Width(sidebarWidth-1).
		Height(s.height).
		BorderRight(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colSlateDim).
		Padding(0, 1)
	return box.Render(body)
}

// HintLine is shown by sub-pages that don't render their own footer
// help (the new pages: Alerts, Account, Verify, Tools). Kept here so
// the formatting stays consistent across pages.
func HintLine(parts ...string) string {
	return StyleDim.Render(strings.Join(parts, "  ·  "))
}

// Helpers for new pages -------------------------------------------------

// pageTitle renders a consistent H1 inside any new page that doesn't
// reuse the existing dashboard/noc header treatment.
func pageTitle(title, subtitle string) string {
	if subtitle == "" {
		return StyleHeader.Render(strings.ToUpper(title))
	}
	return StyleHeader.Render(strings.ToUpper(title)) + "  " +
		StyleDim.Render(subtitle)
}

// fmtCount renders "n thing(s)" with naive plural handling. Used in
// page subtitles ("3 endpoints", "1 domain", ...).
func fmtCount(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
