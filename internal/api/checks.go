package api

import (
	"fmt"
	"net/url"
	"strings"
)

// Phase 1 of the CLI calls a generic checks endpoint on the
// webapp side. The endpoint accepts a tool slug + a domain and
// returns the typed JSON result the matching /lib/checks/<tool>
// library produces.
//
//	GET /api/v1/check/<tool>/<domain>
//
// Webapp work to land alongside this CLI:
//   - implement /app/api/v1/check/[tool]/[domain]/route.ts
//     that dispatches on tool ∈ { tls, dmarc, dns, headers,
//     mta-sts, bimi, dnssec, caa, subdomains, takeover,
//     spoofability, spf-flatten, threat-intel, full } and
//     returns the existing check library's result struct as JSON
//   - per-IP rate-limit via freeBurstGate('cli-check')
//   - extension/CLI CORS already handled by extensionCorsHeaders
//
// Until that endpoint ships, calls will surface a 404 HTTPError -
// the CLI prints it as "this Postvale instance doesn't expose
// /api/v1/check yet" with a link to the upgrade docs.

// CheckGrade is the standard A+ → F letter grade most check
// libraries return.
type CheckGrade string

// CheckSummary is the minimal shape every check returns. Each
// specific check type embeds + extends it.
type CheckSummary struct {
	Host       string     `json:"host"`
	Grade      CheckGrade `json:"grade"`
	CheckedAt  string     `json:"checkedAt"`
	DurationMs int        `json:"durationMs"`
}

// FullDomainCheck is the composite report - what /check renders.
// Combines TLS + DMARC + DNS + headers + MTA-STS + BIMI grades
// into a single shareable summary.
type FullDomainCheck struct {
	CheckSummary
	Subgrades       map[string]CheckGrade `json:"subgrades"`
	Recommendations []string              `json:"recommendations"`
	Warnings        []string              `json:"warnings"`
	ReportURL       string                `json:"reportUrl"`
}

// TLSCheck is the response from /api/v1/check/tls/<domain>.
type TLSCheck struct {
	CheckSummary
	Port               int               `json:"port"`
	Reachable          bool              `json:"reachable"`
	Error              string            `json:"error,omitempty"`
	LeafCert           *CertInfo         `json:"leafCert,omitempty"`
	NegotiatedProtocol string            `json:"negotiatedProtocol,omitempty"`
	Protocols          []ProtocolSupport `json:"protocols"`
	HSTS               *HSTSInfo         `json:"hsts,omitempty"`
	HostnameMatch      bool              `json:"hostnameMatch,omitempty"`
	TrustedChain       bool              `json:"trustedChain,omitempty"`
	Warnings           []string          `json:"warnings"`
	Errors             []string          `json:"errors"`
}

type CertInfo struct {
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	ValidFrom       string   `json:"validFrom"`
	ValidTo         string   `json:"validTo"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	SerialNumber    string   `json:"serialNumber"`
	Fingerprint256  string   `json:"fingerprint256"`
	SubjectAltNames []string `json:"subjectAltNames"`
	SelfSigned      bool     `json:"selfSigned"`
}

type ProtocolSupport struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Weak      bool   `json:"weak"`
}

type HSTSInfo struct {
	Present           bool   `json:"present"`
	MaxAge            int    `json:"maxAge,omitempty"`
	IncludeSubDomains bool   `json:"includeSubDomains,omitempty"`
	Preload           bool   `json:"preload,omitempty"`
	Raw               string `json:"raw,omitempty"`
}

// DMARCCheck is the response from /api/v1/check/dmarc/<domain>.
type DMARCCheck struct {
	CheckSummary
	LookupHost             string       `json:"lookupHost"`
	InheritedFromOrgDomain bool         `json:"inheritedFromOrgDomain"`
	Found                  bool         `json:"found"`
	Records                []string     `json:"records"`
	Parsed                 *ParsedDMARC `json:"parsed,omitempty"`
	SPFPresent             bool         `json:"spfPresent"`
	SPFRecord              string       `json:"spfRecord,omitempty"`
	Warnings               []string     `json:"warnings"`
	Recommendations        []string     `json:"recommendations"`
}

type ParsedDMARC struct {
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomainPolicy,omitempty"`
	Pct             int      `json:"pct,omitempty"`
	RUA             []string `json:"rua,omitempty"`
	RUF             []string `json:"ruf,omitempty"`
	ADKIM           string   `json:"adkim,omitempty"`
	ASPF            string   `json:"aspf,omitempty"`
}

// DNSCheck is the response from /api/v1/check/dns/<domain>.
type DNSCheck struct {
	CheckSummary
	Apex            string           `json:"apex"`
	DNSSEC          DNSSECInfo       `json:"dnssec"`
	CAA             CAAInfo          `json:"caa"`
	NS              NSInfo           `json:"ns"`
	MX              MXInfo           `json:"mx"`
	Registration    RegistrationInfo `json:"registration"`
	Blacklists      BlacklistInfo    `json:"blacklists"`
	Warnings        []string         `json:"warnings"`
	Recommendations []string         `json:"recommendations"`
}

type DNSSECInfo struct {
	Enabled bool `json:"enabled"`
	HasDS   bool `json:"hasDS,omitempty"`
	AD      bool `json:"ad,omitempty"`
}

type CAAInfo struct {
	IssuersAllowed []string `json:"issuersAllowed"`
}

type NSInfo struct {
	Records    []string `json:"records"`
	Count      int      `json:"count"`
	Consistent bool     `json:"consistent"`
}

type MXInfo struct {
	HasMail bool `json:"hasMail"`
}

type RegistrationInfo struct {
	Found           bool     `json:"found"`
	ExpiresAt       string   `json:"expiresAt,omitempty"`
	DaysUntilExpiry int      `json:"daysUntilExpiry,omitempty"`
	Registrar       string   `json:"registrar,omitempty"`
	Status          []string `json:"status,omitempty"`
}

type BlacklistInfo struct {
	Listed []BlacklistListing `json:"listed"`
	Clean  []string           `json:"clean"`
}

type BlacklistListing struct {
	Label    string `json:"label"`
	IP       string `json:"ip"`
	Severity string `json:"severity"`
}

// ScamCheckRequest is the body POSTed to /api/v1/triage.
type ScamCheckRequest struct {
	EmailRaw string `json:"emailRaw"`
}

// ScamCheckResult mirrors what /triage's existing route handler
// returns. Trimmed to the fields the CLI renders.
type ScamCheckResult struct {
	Verdict    string   `json:"verdict"`    // 'likely-safe' | 'suspicious' | 'likely-scam'
	Confidence string   `json:"confidence"` // 'low' | 'medium' | 'high'
	Headline   string   `json:"headline"`
	Reasons    []string `json:"reasons"`
	Advice     string   `json:"advice,omitempty"`
}

// ----- Methods -----

// CheckFull runs the composite full-domain check.
func (c *Client) CheckFull(domain string) (*FullDomainCheck, error) {
	var out FullDomainCheck
	if err := c.get(checkPath("full", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckTLS runs the TLS / SSL check.
func (c *Client) CheckTLS(domain string) (*TLSCheck, error) {
	var out TLSCheck
	if err := c.get(checkPath("tls", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckDMARC runs DMARC + SPF.
func (c *Client) CheckDMARC(domain string) (*DMARCCheck, error) {
	var out DMARCCheck
	if err := c.get(checkPath("dmarc", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckDNS runs the DNS health composite.
func (c *Client) CheckDNS(domain string) (*DNSCheck, error) {
	var out DNSCheck
	if err := c.get(checkPath("dns", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScamCheck POSTs a raw email to /api/v1/triage and returns the
// verdict.
func (c *Client) ScamCheck(emailRaw string) (*ScamCheckResult, error) {
	var out ScamCheckResult
	if err := c.post("/api/v1/triage", &ScamCheckRequest{EmailRaw: emailRaw}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// checkPath constructs the path for /api/v1/check/<tool>/<domain>.
// Domains are url-escaped to handle internationalised TLDs + any
// punycode the user might paste.
func checkPath(tool, domain string) string {
	return fmt.Sprintf("/api/v1/check/%s/%s",
		url.PathEscape(strings.ToLower(tool)),
		url.PathEscape(strings.ToLower(domain)),
	)
}
