package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/WiredepthHQ/cli/internal/api"
)

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

// Canonical display order; unknown keys appended at the end.
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

// Used by --exit-on-fail. Centralised so every command agrees.
func ShouldFail(grade string) bool {
	switch grade {
	case "A+", "A", "B":
		return false
	default:
		return true
	}
}

func RenderHeaders(w io.Writer, r *api.HeadersCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)
	if r.StatusCode > 0 {
		fmt.Fprintln(w, StyleDim.Render(fmt.Sprintf("  %s -> %d", r.URL, r.StatusCode)))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("HEADERS"))
	headerRow(w, "HSTS", r.HSTS != nil && r.HSTS.Present, "")
	headerRow(w, "CSP", r.CSP != nil && r.CSP.Present, evalOf(r.CSP))
	headerRow(w, "X-Frame-Options", r.XFrameOptions != nil && r.XFrameOptions.Present, "")
	headerRow(w, "X-Content-Type", r.XContentType != nil && r.XContentType.Present, "")
	headerRow(w, "Referrer-Policy", r.ReferrerPolicy != nil && r.ReferrerPolicy.Present, "")
	headerRow(w, "Permissions-Policy", r.PermissionsPol != nil && r.PermissionsPol.Present, "")
	headerRow(w, "COOP", r.COOP != nil && r.COOP.Present, "")
	headerRow(w, "COEP", r.COEP != nil && r.COEP.Present, "")
	headerRow(w, "CORP", r.CORP != nil && r.CORP.Present, "")

	if sd := r.ServerDisclose; sd != nil {
		parts := []string{}
		if sd.Server != "" {
			parts = append(parts, "Server: "+sd.Server)
		}
		if sd.XPoweredBy != "" {
			parts = append(parts, "X-Powered-By: "+sd.XPoweredBy)
		}
		if len(parts) > 0 || len(sd.Notes) > 0 {
			fmt.Fprintln(w)
			if len(parts) > 0 {
				fmt.Fprintln(w, StyleDim.Render("  Server disclosure: "+strings.Join(parts, "  ·  ")))
			}
			for _, n := range sd.Notes {
				fmt.Fprintln(w, StyleDim.Render("  - "+n))
			}
		}
	}
	renderRecs(w, r.Recommendations)
}

func headerRow(w io.Writer, name string, present bool, note string) {
	mark := StyleFail.Render("missing")
	if present {
		mark = StyleOK.Render("present")
		if note != "" && note != "good" {
			mark = StyleWarn.Render(note)
		}
	}
	fmt.Fprintf(w, "  %s  %s\n", StyleLabel.Width(20).Render(name), mark)
}

func evalOf(h *api.HeaderInfo) string {
	if h == nil {
		return ""
	}
	return h.Eval
}

func RenderMtaSts(w io.Writer, r *api.MtaStsCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("MTA-STS"))
	row(w, "DNS record", boolLabel(r.DNSRecord.Found))
	if r.PolicyFile.Fetched {
		row(w, "Mode", string(r.PolicyFile.Mode))
		if len(r.PolicyFile.MX) > 0 {
			row(w, "MX", strings.Join(r.PolicyFile.MX, ", "))
		}
		row(w, "max-age", fmt.Sprintf("%d", r.PolicyFile.MaxAge))
	} else {
		fmt.Fprintln(w, "  "+StyleWarn.Render("policy file not fetched"))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("TLS-RPT"))
	row(w, "Published", boolLabel(r.TlsRpt.Found))
	if len(r.TlsRpt.RUA) > 0 {
		row(w, "rua", strings.Join(r.TlsRpt.RUA, ", "))
	}

	renderRecs(w, r.Recommendations)
}

func RenderBimi(w io.Writer, r *api.BimiCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		GradeStyle(string(r.Grade)).Render(string(r.Grade)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("BIMI"))
	row(w, "Record", boolLabel(r.Record.Found))
	if r.Record.LogoURL != "" {
		row(w, "Logo", r.Record.LogoURL)
	}
	if r.Record.VmcURL != "" {
		row(w, "VMC", r.Record.VmcURL)
	}
	if r.Logo.Fetched {
		row(w, "Logo fetch", fmt.Sprintf("HTTP %d", r.Logo.Status))
	}
	renderRecs(w, r.Recommendations)
}

func RenderDnssec(w io.Writer, r *api.DnssecCheck) {
	tone := StyleDim
	switch r.Status {
	case "secure":
		tone = StyleOK
	case "insecure":
		tone = StyleWarn
	case "bogus":
		tone = StyleFail
	}
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		tone.Bold(true).Render(strings.ToUpper(r.Status)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+r.Headline)

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("SIGNALS"))
	row(w, "AD flag", boolLabel(r.Signals.ADFlag))
	row(w, "DNSKEY at apex", boolLabel(r.Signals.DnskeyPresent))
	row(w, "DS at parent", boolLabel(r.Signals.DSAtParent))

	renderRecs(w, r.Recommendations)
}

func RenderCaa(w io.Writer, r *api.CaaCheck) {
	tone := StyleDim
	switch r.Verdict {
	case "secure":
		tone = StyleOK
	case "partial":
		tone = StyleWarn
	case "missing":
		tone = StyleFail
	}
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		tone.Bold(true).Render(strings.ToUpper(r.Verdict)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+r.Headline)

	if len(r.AllowedIssueCAs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("ALLOWED ISSUERS"))
		for _, ca := range r.AllowedIssueCAs {
			fmt.Fprintf(w, "  %s %s\n", StyleOK.Render("·"), ca)
		}
	}
	if len(r.AllowedWildcardCAs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("ALLOWED WILDCARD"))
		for _, ca := range r.AllowedWildcardCAs {
			fmt.Fprintf(w, "  %s %s\n", StyleOK.Render("·"), ca)
		}
	}
	if len(r.IodefEndpoints) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("REPORTING"))
		for _, e := range r.IodefEndpoints {
			fmt.Fprintf(w, "  %s %s\n", StyleOK.Render("·"), e)
		}
	}
	renderRecs(w, r.Recommendations)
}

func RenderSubdomains(w io.Writer, r *api.SubdomainsCheck) {
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		StyleHeader.Render(fmt.Sprintf("%d subdomains", r.Count)),
	)
	fmt.Fprintln(w)
	max := 50
	if len(r.Subdomains) < max {
		max = len(r.Subdomains)
	}
	for i := 0; i < max; i++ {
		s := r.Subdomains[i]
		mark := StyleDim.Render("·")
		if s.Resolves {
			mark = StyleOK.Render("·")
		}
		fmt.Fprintf(w, "  %s %s\n", mark, s.Name)
	}
	if len(r.Subdomains) > max {
		fmt.Fprintln(w, StyleDim.Render(fmt.Sprintf("  ...and %d more (use --json for the full list)", len(r.Subdomains)-max)))
	}
}

func RenderTakeover(w io.Writer, r *api.TakeoverCheck) {
	tone := StyleDim
	switch r.Verdict {
	case "vulnerable":
		tone = StyleFail
	case "suspicious":
		tone = StyleWarn
	case "safe":
		tone = StyleOK
	}
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		tone.Bold(true).Render(strings.ToUpper(r.Verdict)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+r.Headline)

	if len(r.CnameChain) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render(fmt.Sprintf("CNAME CHAIN (%d hops)", len(r.CnameChain))))
		fmt.Fprintf(w, "  %s\n", r.Host)
		for i, hop := range r.CnameChain {
			fmt.Fprintf(w, "  %s %s\n", StyleDim.Render(fmt.Sprintf("%d.", i+1)), hop)
		}
		if len(r.FinalIPs) > 0 {
			fmt.Fprintln(w, StyleDim.Render("  -> "+strings.Join(r.FinalIPs, ", ")))
		} else {
			fmt.Fprintln(w, "  "+StyleWarn.Render("no final A record (chain dangles)"))
		}
	}

	if len(r.Fingerprints) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, StyleHeader.Render("MATCHES"))
		for _, fp := range r.Fingerprints {
			fmt.Fprintf(w, "  %s %s (%s confidence)\n",
				StyleFail.Render("·"),
				fp.ServiceName,
				fp.Confidence,
			)
		}
	}
	renderRecs(w, r.Recommendations)
}

func RenderSpoofability(w io.Writer, r *api.SpoofabilityCheck) {
	tone := StyleDim
	switch r.Verdict {
	case "no":
		tone = StyleOK
	case "maybe":
		tone = StyleWarn
	case "yes":
		tone = StyleFail
	}
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		tone.Bold(true).Render(strings.ToUpper(r.Verdict)),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+r.Headline)
	renderRecs(w, r.Recommendations)
}

func RenderSpfFlatten(w io.Writer, r *api.SpfFlattenCheck) {
	fmt.Fprintln(w, StyleStrong.Render(r.Host))
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("ORIGINAL"))
	if r.Original.Record != "" {
		fmt.Fprintln(w, "  "+StyleDim.Render(r.Original.Record))
		row(w, "DNS lookups", fmt.Sprintf("%d", r.Original.LookupCount))
	} else {
		fmt.Fprintln(w, "  "+StyleWarn.Render("no SPF record at apex"))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("FLATTENED"))
	if r.Flattened.Record != "" {
		fmt.Fprintln(w, "  "+r.Flattened.Record)
		row(w, "IPs", fmt.Sprintf("%d", r.Flattened.IPCount))
		row(w, "Bytes", fmt.Sprintf("%d", r.Flattened.Bytes))
	}
	renderRecs(w, r.Recommendations)
}

func RenderThreatIntel(w io.Writer, r *api.ThreatIntelCheck) {
	tone := StyleOK
	verdict := "CLEAN"
	if r.AnyFlagged {
		tone = StyleFail
		verdict = "FLAGGED"
	}
	fmt.Fprintf(w, "%s    %s\n",
		StyleStrong.Render(r.Host),
		tone.Bold(true).Render(verdict),
	)
	fmt.Fprintln(w)
	fmt.Fprintln(w, StyleHeader.Render("FEEDS"))

	if r.URLhaus != nil {
		feedRow(w, "malware (URL hosting)", r.URLhaus.Listed, "")
	}
	if r.Threatfox != nil {
		extra := r.Threatfox.MalwareFamily
		feedRow(w, "active threat IOC", r.Threatfox.Listed, extra)
	}
	if r.Phishtank != nil {
		feedRow(w, "phishing", r.Phishtank.Listed, "")
	}
	if r.DomainAge != nil {
		if r.DomainAge.NewlyRegistered {
			row(w, "Domain age", StyleFail.Render(fmt.Sprintf("%d days (newly registered)", r.DomainAge.AgeDays)))
		} else if r.DomainAge.AgeDays > 0 {
			row(w, "Domain age", StyleOK.Render(fmt.Sprintf("%d days", r.DomainAge.AgeDays)))
		}
	}
}

func feedRow(w io.Writer, label string, listed bool, extra string) {
	if listed {
		v := StyleFail.Render("listed")
		if extra != "" {
			v = StyleFail.Render(fmt.Sprintf("listed (%s)", extra))
		}
		fmt.Fprintf(w, "  %s  %s\n", StyleLabel.Width(22).Render(label), v)
	} else {
		fmt.Fprintf(w, "  %s  %s\n", StyleLabel.Width(22).Render(label), StyleOK.Render("clean"))
	}
}
