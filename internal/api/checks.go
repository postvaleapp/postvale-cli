package api

// API contract is documented in docs/api-spec.md.

import (
	"fmt"
	"net/url"
	"strings"
)

// A+ to F letter grade returned by every check.
type CheckGrade string

type CheckSummary struct {
	Host       string     `json:"host"`
	Grade      CheckGrade `json:"grade"`
	CheckedAt  string     `json:"checkedAt"`
	DurationMs int        `json:"durationMs"`
}

// Composite report covering TLS, DMARC, DNS, headers, MTA-STS, BIMI.
type FullDomainCheck struct {
	CheckSummary
	Subgrades       map[string]CheckGrade `json:"subgrades"`
	Recommendations []string              `json:"recommendations"`
	Warnings        []string              `json:"warnings"`
	ReportURL       string                `json:"reportUrl"`
}

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

type ScamCheckRequest struct {
	EmailRaw string `json:"emailRaw"`
}

// Trimmed to the fields the CLI renders.
type ScamCheckResult struct {
	Verdict    string   `json:"verdict"`    // 'likely-safe' | 'suspicious' | 'likely-scam'
	Confidence string   `json:"confidence"` // 'low' | 'medium' | 'high'
	Headline   string   `json:"headline"`
	Reasons    []string `json:"reasons"`
	Advice     string   `json:"advice,omitempty"`
}

// ----- Methods -----

func (c *Client) CheckFull(domain string) (*FullDomainCheck, error) {
	var out FullDomainCheck
	if err := c.get(checkPath("full", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckTLS(domain string) (*TLSCheck, error) {
	var out TLSCheck
	if err := c.get(checkPath("tls", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckDMARC(domain string) (*DMARCCheck, error) {
	var out DMARCCheck
	if err := c.get(checkPath("dmarc", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckDNS(domain string) (*DNSCheck, error) {
	var out DNSCheck
	if err := c.get(checkPath("dns", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ScamCheck(emailRaw string) (*ScamCheckResult, error) {
	var out ScamCheckResult
	if err := c.post("/api/v1/triage", &ScamCheckRequest{EmailRaw: emailRaw}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func checkPath(tool, domain string) string {
	return fmt.Sprintf("/api/v1/check/%s/%s",
		url.PathEscape(strings.ToLower(tool)),
		url.PathEscape(strings.ToLower(domain)),
	)
}
