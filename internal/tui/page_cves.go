package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// CvesPage shows CRITICAL + HIGH CVE matches against the tech stack
// publicly visible on each monitored domain. Pro+ feature. NVD-sourced;
// worker polls every 6h.

type cveLoadedMsg struct {
	data *api.VulnerabilitiesResp
	err  error
}

type CvesPage struct {
	client *api.Client

	width  int
	height int

	loading bool
	data    *api.VulnerabilitiesResp
	err     error
}

func newCvesPage(client *api.Client) CvesPage {
	return CvesPage{client: client, loading: true}
}

func (m CvesPage) Init() tea.Cmd {
	return m.fetch()
}

func (m CvesPage) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		d, err := c.Vulnerabilities()
		return cveLoadedMsg{data: d, err: err}
	}
}

func (m CvesPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case cveLoadedMsg:
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

func (m CvesPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("CVEs",
		"published vulns on your detected stack (CVSS ≥ 7)"))
	b.WriteString("\n\n")

	if m.loading {
		b.WriteString("  " + StyleDim.Render("Loading CVE findings..."))
		return b.String()
	}
	if m.err != nil {
		msg := m.err.Error()
		if strings.Contains(msg, "402") || strings.Contains(msg, "pro_required") {
			b.WriteString("  " + StyleWarn.Render("Pro / Power / MSP required."))
			b.WriteString("\n  " + StyleDim.Render(
				"CVE monitoring is paywalled. Upgrade at https://postvale.app/pricing"))
		} else {
			b.WriteString("  " + StyleFail.Render("Could not load CVE findings:"))
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
		b.WriteString("  " + StyleOK.Render("✓ No CRITICAL/HIGH CVEs match the tech detected on your monitored domains."))
		b.WriteString("\n\n  " + StyleDim.Render(
			"Workers poll NVD every 6h."))
		b.WriteString("\n  " + StyleDim.Render(
			"r refresh  ·  Tab nav"))
		return b.String()
	}

	cveW := 18
	productW := 20
	versionW := 12
	cvssW := 6
	domainW := 24
	pubW := 12
	header := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		padRight("CVE", cveW),
		padRight("PRODUCT", productW),
		padRight("VERSION", versionW),
		padRight("CVSS", cvssW),
		padRight("APEX", domainW),
		padRight("PUBLISHED", pubW),
	)
	b.WriteString(StyleLabel.Render(header))
	b.WriteString("\n  " + StyleDim.Render(strings.Repeat("─", m.width-4)))
	b.WriteString("\n")

	for _, f := range m.data.Findings {
		version := "-"
		if f.Version != nil {
			version = *f.Version
		}
		domain := "-"
		if f.Domain != nil {
			domain = *f.Domain
		}
		cvss := "-"
		if f.CVSS != nil {
			cvss = *f.CVSS
		}
		sev := ""
		if f.Severity != nil {
			sev = *f.Severity
		}
		switch sev {
		case "CRITICAL":
			cvss = StyleFail.Bold(true).Render(cvss)
		case "HIGH":
			cvss = StyleFail.Render(cvss)
		case "MEDIUM":
			cvss = StyleWarn.Render(cvss)
		default:
			cvss = StyleDim.Render(cvss)
		}
		published := "-"
		if f.PublishedAt != nil && len(*f.PublishedAt) >= 10 {
			published = (*f.PublishedAt)[:10]
		}
		row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
			padRight(truncate(f.CveID, cveW), cveW),
			padRight(truncate(f.Product, productW), productW),
			padRight(truncate(version, versionW), versionW),
			padRight(cvss, cvssW),
			padRight(truncate(domain, domainW), domainW),
			padRight(published, pubW),
		)
		b.WriteString(row + "\n")
		if f.Summary != nil && *f.Summary != "" {
			summary := truncate(*f.Summary, m.width-8)
			b.WriteString("    " + StyleDim.Render(summary) + "\n")
		}
	}

	b.WriteString("\n  " + StyleDim.Render(
		"r refresh  ·  Tab nav  ·  full advisory + patch links at /dashboard/vulnerabilities on the web"))
	return b.String()
}
