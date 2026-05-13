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

type ToolsPage struct {
	client *api.Client

	width  int
	height int

	catalog []toolGroup
	cursor  int

	domain textinput.Model
	focus  focusMode

	running bool
	output  string
	err     error
	took    time.Duration

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
		m.vp.Width = msg.Width
		// Reserve room for the list + input + chrome.
		h := msg.Height - 14
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
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.focus == focusInput {
				m.domain.Blur()
				m.focus = focusList
				return m, nil
			}
			m.output = ""
			m.err = nil
			return m, nil
		case "i":
			if m.focus != focusInput {
				m.focus = focusInput
				return m, m.domain.Focus()
			}
		case "up", "k":
			// Only steer the list cursor when the list is focused. When
			// the domain input is focused, "k" is just a letter the
			// user is typing; fall through so the textinput sees it.
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
			return m, runToolCmd(m.client, tool, d)
		case "pgup", "pgdown", "home", "end":
			if m.focus != focusInput {
				var cmd tea.Cmd
				m.vp, cmd = m.vp.Update(msg)
				return m, cmd
			}
		}
	}

	// Forward to input when input is focused. Forward scroll keys to
	// viewport when output is showing + list is focused.
	if m.focus == focusInput {
		var cmd tea.Cmd
		m.domain, cmd = m.domain.Update(msg)
		return m, cmd
	}
	if m.output != "" {
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func runToolCmd(c *api.Client, t toolEntry, domain string) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		out, err := t.run(c, domain)
		return toolRunDoneMsg{out: out, err: err, dur: time.Since(start)}
	}
}

func (m ToolsPage) View() string {
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
	} else if m.output != "" {
		head := fmt.Sprintf("  %s  %s",
			StyleLabel.Render("RESULT"),
			StyleDim.Render(fmt.Sprintf("(%s)", m.took.Round(time.Millisecond))),
		)
		b.WriteString(head + "\n")
		b.WriteString(m.vp.View() + "\n")
	} else {
		b.WriteString("  " + StyleDim.Render(
			"↑/↓ pick · i focus domain · ↵ run · Esc clear · Tab nav") + "\n")
	}
	return b.String()
}
