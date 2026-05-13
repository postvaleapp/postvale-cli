package tui

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/postvaleapp/postvale-cli/internal/api"
	"github.com/postvaleapp/postvale-cli/internal/output"
)

var stylePlain = lipgloss.NewStyle()

// ToolsPage is a categorised browser for the free tools. Pick a tool,
// type a domain, hit enter, see the same output as the standalone
// subcommand (`postvale tls acme.com` etc.) in a scrollable viewport.

type toolEntry struct {
	id    string
	label string
	desc  string
	run   func(c *api.Client, domain string) (string, error)
}

type toolGroup struct {
	title string
	tools []toolEntry
}

func renderTo(fn func(*bytes.Buffer) error) (string, error) {
	var b bytes.Buffer
	if err := fn(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func toolCatalog() []toolGroup {
	return []toolGroup{
		{"WEB POSTURE", []toolEntry{
			{"tls", "TLS / SSL check", "cert chain + expiry + protocols + HSTS",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckTLS(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderTLS(b, r)
						return nil
					})
				}},
			{"headers", "Security headers", "CSP, HSTS, COOP / COEP / CORP",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckHeaders(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderHeaders(b, r)
						return nil
					})
				}},
			{"subdomains", "Subdomain inventory", "CT log enumeration",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckSubdomains(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderSubdomains(b, r)
						return nil
					})
				}},
			{"takeover", "Subdomain takeover", "dangling CNAME + 20+ fingerprints",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckTakeover(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderTakeover(b, r)
						return nil
					})
				}},
		}},
		{"EMAIL AUTH", []toolEntry{
			{"dmarc", "DMARC + SPF checker", "policy, alignment, recs",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckDMARC(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderDMARC(b, r)
						return nil
					})
				}},
			{"spf-flatten", "SPF flattener", "resolve includes to 0-lookup",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckSpfFlatten(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderSpfFlatten(b, r)
						return nil
					})
				}},
			{"bimi", "BIMI checker", "verify published BIMI + VMC",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckBimi(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderBimi(b, r)
						return nil
					})
				}},
			{"mta-sts", "MTA-STS + TLS-RPT", "transport encryption policy",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckMtaSts(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderMtaSts(b, r)
						return nil
					})
				}},
			{"spoofability", "Can my domain be spoofed?", "yes / maybe / no verdict",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckSpoofability(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderSpoofability(b, r)
						return nil
					})
				}},
		}},
		{"DNS & DOMAIN", []toolEntry{
			{"dns", "DNS health", "DNSSEC, CAA, registrar, blocklists",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckDNS(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderDNS(b, r)
						return nil
					})
				}},
			{"dnssec", "DNSSEC validator", "Secure / Insecure / Bogus",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckDnssec(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderDnssec(b, r)
						return nil
					})
				}},
			{"caa", "CAA checker", "which CAs can issue your certs",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckCaa(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderCaa(b, r)
						return nil
					})
				}},
		}},
		{"THREAT INTEL", []toolEntry{
			{"threat-intel", "Reputation + threat intel", "malware, IP abuse, blocklists",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckThreatIntel(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderThreatIntel(b, r)
						return nil
					})
				}},
		}},
		{"COMPLIANCE & AUDIT", []toolEntry{
			{"full", "Full domain check", "6 tools in one shareable report",
				func(c *api.Client, d string) (string, error) {
					r, err := c.CheckFull(d)
					if err != nil {
						return "", err
					}
					return renderTo(func(b *bytes.Buffer) error {
						output.RenderFullCheck(b, r)
						return nil
					})
				}},
		}},
	}
}

// flatTools returns every tool in catalog order. Cursor indexes this.
func flatTools(cat []toolGroup) []toolEntry {
	out := []toolEntry{}
	for _, g := range cat {
		out = append(out, g.tools...)
	}
	return out
}

type toolRunDoneMsg struct {
	out string
	err error
	dur time.Duration
}

type focusMode int

const (
	focusList focusMode = iota
	focusInput
)

// viewState splits the page into two screens. modeList shows the
// catalog + domain input; modeResult takes over the whole content area
// to show the rendered check output (no list, no input) so the result
// reads like its own page rather than appended below the catalog.
type viewState int

const (
	modeList viewState = iota
	modeResult
)

type ToolsPage struct {
	client *api.Client

	width  int
	height int

	catalog []toolGroup
	cursor  int

	domain textinput.Model
	focus  focusMode

	state viewState

	running    bool
	output     string
	err        error
	took       time.Duration
	resultTool string // label of the tool whose output is in `output`

	vp viewport.Model
}

func newToolsPage(client *api.Client) ToolsPage {
	ti := textinput.New()
	ti.Placeholder = "example.com"
	ti.Prompt = "▸ "
	ti.CharLimit = 253
	ti.Width = 40
	vp := viewport.New(0, 0)
	return ToolsPage{
		client:  client,
		catalog: toolCatalog(),
		domain:  ti,
		focus:   focusList,
		vp:      vp,
	}
}

func (m ToolsPage) Init() tea.Cmd {
	return nil
}

func (m ToolsPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.vp.Width = msg.Width - 4
		// In modeResult the viewport gets the whole page area minus a
		// 4-line header + 2-line footer. In modeList we don't actually
		// use the viewport for layout so the same number is fine.
		h := msg.Height - 6
		if h < 6 {
			h = 6
		}
		m.vp.Height = h
		m.domain.Width = msg.Width - 6
		if m.output != "" {
			m.vp.SetContent(m.output)
		}
		return m, nil

	case toolRunDoneMsg:
		m.running = false
		m.err = msg.err
		m.took = msg.dur
		if msg.err == nil {
			m.output = msg.out
			m.vp.SetContent(m.output)
			m.vp.GotoTop()
			m.state = modeResult
			// Take focus off the input so 'q', 'r', 'esc' don't get
			// typed as letters in the (now-hidden) domain field.
			m.domain.Blur()
			m.focus = focusList
		}
		// On error we stay on modeList; the error renders inline so
		// the user can fix the domain + retry.
		return m, nil

	case tea.KeyMsg:
		if m.state == modeResult {
			return m.updateResult(msg)
		}
		return m.updateList(msg)
	}

	// Non-key, non-size messages: forward to whatever's active.
	if m.state == modeResult {
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}
	if m.focus == focusInput {
		var cmd tea.Cmd
		m.domain, cmd = m.domain.Update(msg)
		return m, cmd
	}
	return m, nil
}

// updateList handles keys while the catalog + domain input are
// showing. Input-focused vs list-focused gates which keys are nav vs
// typed characters.
func (m ToolsPage) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		if m.focus == focusInput {
			m.domain.Blur()
			m.focus = focusList
			return m, nil
		}
		m.err = nil
		return m, nil
	case "i":
		if m.focus != focusInput {
			m.focus = focusInput
			return m, m.domain.Focus()
		}
	case "up", "k":
		// Only steer the list cursor when the list is focused. When
		// the domain input is focused, "k" is just a letter the user
		// is typing; fall through so the textinput sees it.
		if m.focus == focusList {
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		}
	case "down", "j":
		if m.focus == focusList {
			flat := flatTools(m.catalog)
			if m.cursor < len(flat)-1 {
				m.cursor++
			}
			return m, nil
		}
	case "enter":
		flat := flatTools(m.catalog)
		if m.cursor >= len(flat) || m.running {
			return m, nil
		}
		d := strings.TrimSpace(m.domain.Value())
		if d == "" {
			m.focus = focusInput
			return m, m.domain.Focus()
		}
		m.running = true
		m.err = nil
		m.output = ""
		tool := flat[m.cursor]
		m.resultTool = tool.label
		return m, runToolCmd(m.client, tool, d)
	}

	// Anything not consumed above goes to the textinput when focused.
	if m.focus == focusInput {
		var cmd tea.Cmd
		m.domain, cmd = m.domain.Update(msg)
		return m, cmd
	}
	return m, nil
}

// updateResult handles keys while the full-screen result viewport is
// showing. Esc / Backspace / b / q all go back to the list; r re-runs
// the same tool against the same domain; up/down/k/j/PgUp/PgDn/etc
// scroll the viewport. The domain textinput is blurred while in this
// mode so plain letters can't bleed into it.
func (m ToolsPage) updateResult(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "backspace", "b", "q", "left", "h":
		// Back to the list. Keep the output buffer + tool label so a
		// repeat "r" or scroll-back still works if needed; the list
		// view ignores them.
		m.state = modeList
		return m, nil
	case "r":
		flat := flatTools(m.catalog)
		if m.cursor >= len(flat) || m.running {
			return m, nil
		}
		d := strings.TrimSpace(m.domain.Value())
		if d == "" {
			m.state = modeList
			m.focus = focusInput
			return m, m.domain.Focus()
		}
		m.running = true
		m.err = nil
		m.output = ""
		m.state = modeList // briefly show "Running..." inline before the next done msg flips us back
		tool := flat[m.cursor]
		m.resultTool = tool.label
		return m, runToolCmd(m.client, tool, d)
	}

	// Anything else: scroll the viewport (arrows, j/k, PgUp/PgDn,
	// Home/End, mouse wheel).
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func runToolCmd(c *api.Client, t toolEntry, domain string) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		out, err := t.run(c, domain)
		return toolRunDoneMsg{out: out, err: err, dur: time.Since(start)}
	}
}

func (m ToolsPage) View() string {
	if m.state == modeResult {
		return m.viewResult()
	}
	return m.viewList()
}

// viewList renders the catalog + domain input + any inline "running"
// or "error" affordance below it.
func (m ToolsPage) viewList() string {
	var b strings.Builder
	flat := flatTools(m.catalog)
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Free tools",
		fmt.Sprintf("%s · pick + paste a domain", fmtCount(len(flat), "tool", "tools"))))
	b.WriteString("\n\n")

	// Compact list: section title + each tool on one line.
	idx := 0
	for _, g := range m.catalog {
		b.WriteString("  " + StyleLabel.Render(g.title) + "\n")
		for _, t := range g.tools {
			marker := "  "
			labelStyle := stylePlain
			if idx == m.cursor {
				marker = StyleHeader.Render("▸ ")
				labelStyle = StyleHeader
			}
			line := fmt.Sprintf("  %s%-26s  %s",
				marker,
				labelStyle.Render(t.label),
				StyleDim.Render(t.desc),
			)
			b.WriteString(line + "\n")
			idx++
		}
		b.WriteString("\n")
	}

	b.WriteString("  " + StyleLabel.Render("DOMAIN") + "\n  " + m.domain.View() + "\n\n")

	if m.running {
		b.WriteString("  " + StyleWarn.Render("Running...") + "\n")
	} else if m.err != nil {
		b.WriteString("  " + StyleFail.Render("Check failed:") + "\n  " +
			StyleDim.Render(m.err.Error()) + "\n")
	} else {
		b.WriteString("  " + StyleDim.Render(
			"↑/↓ pick · i focus domain · ↵ run · Tab nav") + "\n")
	}
	return b.String()
}

// viewResult takes over the whole content area to show the rendered
// check output. Top strip = tool label + duration; viewport = the
// rendered bytes; footer = back / re-run / scroll affordances.
func (m ToolsPage) viewResult() string {
	var b strings.Builder
	subtitle := fmt.Sprintf("%s · ran in %s",
		m.resultTool,
		m.took.Round(time.Millisecond),
	)
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Result", subtitle))
	b.WriteString("\n\n")
	b.WriteString(m.vp.View())
	b.WriteString("\n  " + StyleDim.Render(
		"Esc / b back  ·  r re-run  ·  ↑↓ PgUp PgDn scroll  ·  Tab nav"))
	return b.String()
}
