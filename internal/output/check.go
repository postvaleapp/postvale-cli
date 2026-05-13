package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/postvaleapp/postvale-cli/internal/api"
)

// RenderFullCheck prints the composite domain-check report in the
// boxed layout. Mirrors the visual shape of the web /check page.
func RenderFullCheck(w io.Writer, r *api.FullDomainCheck) {
	// Header row: "domain" + grade pill
	gradeStyle := GradeStyle(string(r.Grade))
	header := fmt.Sprintf("%s    %s",
		StyleStrong.Render(r.Host),
		gradeStyle.Render(string(r.Grade)),
	)

	// Build the subgrades table - one row per tool. Two-column
	// layout: tool name (padded) + grade pill.
	var rows []string
	for _, name := range subgradeOrder(r.Subgrades) {
		grade := r.Subgrades[name]
		rows = append(rows, fmt.Sprintf("  %s    %s",
			StyleLabel.Width(10).Render(name),
			GradeStyle(string(grade)).Render(string(grade)),
		))
	}

	// Recommendations - bulleted, max 6 so the box stays readable
	var recs []string
	if len(r.Recommendations) > 0 {
		recs = append(recs, "")
		recs = append(recs, StyleDim.Render(fmt.Sprintf("%d recommendations:", len(r.Recommendations))))
		max := 6
		if len(r.Recommendations) < max {
			max = len(r.Recommendations)
		}
		for i := 0; i < max; i++ {
			recs = append(recs, fmt.Sprintf("  %s  %s",
				StyleHeader.Render("·"),
				r.Recommendations[i],
			))
		}
		if len(r.Recommendations) > max {
			recs = append(recs, StyleDim.Render(fmt.Sprintf("  …and %d more", len(r.Recommendations)-max)))
		}
	}

	// Compose the box
	body := strings.Join(append(append([]string{header, ""}, rows...), recs...), "\n")
	fmt.Fprintln(w, StyleBox.Render(body))

	if r.ReportURL != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n",
			StyleDim.Render("→ Full report:"),
			StyleHeader.Render(r.ReportURL),
		)
	}
}

// subgradeOrder returns the keys of the subgrades map in the order
// we want to display them. We hard-code the canonical sequence so
// the report reads top-to-bottom in the same order every time.
func subgradeOrder(g map[string]api.CheckGrade) []string {
	canonical := []string{"tls", "dmarc", "spf", "dkim", "mta-sts", "dnssec", "caa", "headers", "bimi"}
	out := make([]string, 0, len(g))
	for _, k := range canonical {
		if _, ok := g[k]; ok {
			out = append(out, k)
		}
	}
	// Append any non-canonical keys we didn't anticipate
	for k := range g {
		seen := false
		for _, c := range canonical {
			if c == k {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, k)
		}
	}
	return out
}

// RenderTLS prints the TLS check result.
func RenderTLS(w io.Writer, r *api.TLSCheck) {
	if !r.Reachable {
		fmt.Fprintln(w, StyleFail.Render(fmt.Sprintf("✗ %s:%d unreachable", r.Host, r.Port)))
		if r.Error != "" {
			fmt.Fprintln(w, StyleDim.Render("  "+r.Error))
		}
		return
	}

	// Header: host:port + grade
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(fmt.Sprintf("%s:%d", r.Host, r.Port)),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)

	if r.LeafCert != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("CERTIFICATE"))
		row(w, "Subject", r.LeafCert.Subject)
		row(w, "Issuer", r.LeafCert.Issuer)
		row(w, "Valid until", fmt.Sprintf("%s (%d days)", r.LeafCert.ValidTo, r.LeafCert.DaysUntilExpiry))
		row(w, "SAN", strings.Join(r.LeafCert.SubjectAltNames, ", "))
		if r.LeafCert.SelfSigned {
			fmt.Fprintln(w, "  "+StyleFail.Render("⚠ self-signed"))
		}
	}

	// Protocols
	if len(r.Protocols) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("PROTOCOLS"))
		for _, p := range r.Protocols {
			var status string
			switch {
			case !p.Supported:
				status = StyleDim.Render("not negotiated")
			case p.Weak:
				status = StyleFail.Render("weak - deprecated")
			default:
				status = StyleOK.Render("modern")
			}
			row(w, p.Name, status)
		}
	}

	// HSTS
	if r.HSTS != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("HSTS"))
		row(w, "Present", boolLabel(r.HSTS.Present))
		if r.HSTS.Present {
			row(w, "max-age", fmt.Sprintf("%d", r.HSTS.MaxAge))
			row(w, "includeSubDomains", boolLabel(r.HSTS.IncludeSubDomains))
			row(w, "preload", boolLabel(r.HSTS.Preload))
		}
	}

	// Warnings
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("WARNINGS"))
		for _, msg := range r.Warnings {
			fmt.Fprintf(w, "  %s %s\n", StyleWarn.Render("·"), msg)
		}
	}
}

// RenderDMARC prints the DMARC + SPF check result.
func RenderDMARC(w io.Writer, r *api.DMARCCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)
	if r.InheritedFromOrgDomain {
		fmt.Fprintln(w, StyleDim.Render(fmt.Sprintf("  (inherited from %s)", r.LookupHost)))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("DMARC"))
	if !r.Found {
		fmt.Fprintln(w, "  "+StyleFail.Render("✗ no DMARC record published"))
	} else if r.Parsed != nil {
		row(w, "Policy", "p="+r.Parsed.Policy)
		if r.Parsed.SubdomainPolicy != "" {
			row(w, "Subdomain", "sp="+r.Parsed.SubdomainPolicy)
		}
		if r.Parsed.Pct > 0 {
			row(w, "Coverage", fmt.Sprintf("%d%%", r.Parsed.Pct))
		}
		if len(r.Parsed.RUA) > 0 {
			row(w, "rua", strings.Join(r.Parsed.RUA, ", "))
		}
		if len(r.Parsed.RUF) > 0 {
			row(w, "ruf", strings.Join(r.Parsed.RUF, ", "))
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("SPF"))
	if !r.SPFPresent {
		fmt.Fprintln(w, "  "+StyleFail.Render("✗ no SPF record at apex"))
	} else {
		fmt.Fprintln(w, "  "+StyleDim.Render(r.SPFRecord))
	}

	renderRecs(w, r.Recommendations)
}

// RenderDNS prints the DNS health check result.
func RenderDNS(w io.Writer, r *api.DNSCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)
	fmt.Fprintln(w, StyleDim.Render(fmt.Sprintf("  apex %s", r.Apex)))

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("DNSSEC"))
	if r.DNSSEC.Enabled {
		row(w, "Status", StyleOK.Render("enabled"))
		row(w, "DS at parent", boolLabel(r.DNSSEC.HasDS))
		row(w, "AD flag", boolLabel(r.DNSSEC.AD))
	} else {
		fmt.Fprintln(w, "  "+StyleWarn.Render("not enabled"))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("CAA"))
	if len(r.CAA.IssuersAllowed) == 0 {
		fmt.Fprintln(w, "  "+StyleWarn.Render("no records - any CA may issue"))
	} else {
		for _, ca := range r.CAA.IssuersAllowed {
			fmt.Fprintf(w, "  %s %s\n", StyleOK.Render("·"), ca)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("REGISTRATION"))
	if r.Registration.Found {
		if r.Registration.Registrar != "" {
			row(w, "Registrar", r.Registration.Registrar)
		}
		if r.Registration.ExpiresAt != "" {
			expiry := fmt.Sprintf("%s (%d days)", r.Registration.ExpiresAt, r.Registration.DaysUntilExpiry)
			var s lipgloss.Style
			switch {
			case r.Registration.DaysUntilExpiry < 14:
				s = StyleFail
			case r.Registration.DaysUntilExpiry < 60:
				s = StyleWarn
			default:
				s = StyleOK
			}
			row(w, "Expires", s.Render(expiry))
		}
	} else {
		fmt.Fprintln(w, "  "+StyleDim.Render("(no WHOIS data)"))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("MAIL BLOCKLISTS"))
	if len(r.Blacklists.Listed) == 0 {
		fmt.Fprintln(w, "  "+StyleOK.Render("✓ clean on all probed lists"))
	} else {
		for _, l := range r.Blacklists.Listed {
			fmt.Fprintf(w, "  %s %s (%s)\n", StyleFail.Render("✗"), l.Label, l.IP)
		}
	}

	renderRecs(w, r.Recommendations)
}

// RenderScamCheck prints the Scam Check verdict.
func RenderScamCheck(w io.Writer, r *api.ScamCheckResult) {
	style := VerdictStyle(r.Verdict)
	verdictLabel := strings.ReplaceAll(r.Verdict, "-", " ")
	fmt.Fprintf(w, "%s    %s\n",
		style.Render(strings.ToUpper(verdictLabel)),
		StyleDim.Render(fmt.Sprintf("(%s confidence)", r.Confidence)),
	)
	if r.Headline != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  "+r.Headline)
	}
	if len(r.Reasons) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("WHY"))
		for _, reason := range r.Reasons {
			fmt.Fprintf(w, "  %s %s\n", style.Render("·"), reason)
		}
	}
	if r.Advice != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleDim.Render("  "+r.Advice))
	}
}

// ----- small helpers -----

func row(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %s  %s\n",
		StyleLabel.Width(16).Render(label),
		value,
	)
}

func boolLabel(b bool) string {
	if b {
		return StyleOK.Render("yes")
	}
	return StyleDim.Render("no")
}

func renderRecs(w io.Writer, recs []string) {
	if len(recs) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render(fmt.Sprintf("RECOMMENDATIONS (%d)", len(recs))))
	max := 6
	if len(recs) < max {
		max = len(recs)
	}
	for i := 0; i < max; i++ {
		fmt.Fprintf(w, "  %s %s\n", StyleHeader.Render("·"), recs[i])
	}
	if len(recs) > max {
		fmt.Fprintln(w, StyleDim.Render(fmt.Sprintf("  …and %d more", len(recs)-max)))
	}
}

// ShouldFail returns true when --exit-on-fail should cause a non-zero
// exit. Centralised so each command applies the same rule.
func ShouldFail(grade string) bool {
	switch grade {
	case "A+", "A", "B":
		return false
	default:
		return true
	}
}
