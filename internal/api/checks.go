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

type HeadersCheck struct {
	CheckSummary
	URL             string            `json:"url,omitempty"`
	StatusCode      int               `json:"statusCode,omitempty"`
	HSTS            *HSTSInfo         `json:"hsts,omitempty"`
	CSP             *HeaderInfo       `json:"csp,omitempty"`
	XFrameOptions   *HeaderInfo       `json:"xFrameOptions,omitempty"`
	XContentType    *HeaderInfo       `json:"xContentType,omitempty"`
	ReferrerPolicy  *HeaderInfo       `json:"referrerPolicy,omitempty"`
	PermissionsPol  *HeaderInfo       `json:"permissionsPolicy,omitempty"`
	COOP            *HeaderInfo       `json:"coop,omitempty"`
	COEP            *HeaderInfo       `json:"coep,omitempty"`
	CORP            *HeaderInfo       `json:"corp,omitempty"`
	ServerDisclose  *ServerDisclosure `json:"serverDisclosure,omitempty"`
	Warnings        []string          `json:"warnings"`
	Recommendations []string          `json:"recommendations"`
}

type ServerDisclosure struct {
	Server     string   `json:"server,omitempty"`
	XPoweredBy string   `json:"xPoweredBy,omitempty"`
	Notes      []string `json:"notes"`
}

type HeaderInfo struct {
	Present bool   `json:"present"`
	Raw     string `json:"raw,omitempty"`
	Eval    string `json:"eval,omitempty"`
}

type MtaStsCheck struct {
	CheckSummary
	Apex      string `json:"apex"`
	DNSRecord struct {
		Found   bool   `json:"found"`
		Version string `json:"version,omitempty"`
		ID      string `json:"id,omitempty"`
	} `json:"dnsRecord"`
	PolicyFile struct {
		Fetched bool     `json:"fetched"`
		Mode    string   `json:"mode,omitempty"`
		MX      []string `json:"mx"`
		MaxAge  int      `json:"maxAge,omitempty"`
	} `json:"policyFile"`
	TlsRpt struct {
		Found bool     `json:"found"`
		RUA   []string `json:"rua"`
	} `json:"tlsRpt"`
	Warnings        []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
}

type BimiCheck struct {
	CheckSummary
	Apex   string `json:"apex"`
	Record struct {
		Found   bool   `json:"found"`
		LogoURL string `json:"logoUrl,omitempty"`
		VmcURL  string `json:"vmcUrl,omitempty"`
	} `json:"record"`
	Logo struct {
		Fetched bool `json:"fetched"`
		Status  int  `json:"status,omitempty"`
	} `json:"logo"`
	VMC struct {
		Fetched bool `json:"fetched"`
		Status  int  `json:"status,omitempty"`
	} `json:"vmc"`
	Warnings        []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
}

// Verdicts: secure | insecure | bogus | indeterminate
type DnssecCheck struct {
	Host     string `json:"host"`
	Status   string `json:"status"`
	Headline string `json:"headline"`
	Signals  struct {
		ADFlag        bool `json:"adFlag"`
		DnskeyPresent bool `json:"dnskeyPresent"`
		DnskeyCount   int  `json:"dnskeyCount"`
		DSAtParent    bool `json:"dsAtParent"`
		DSCount       int  `json:"dsCount"`
	} `json:"signals"`
	Recommendations []string `json:"recommendations"`
	CheckedAt       string   `json:"checkedAt"`
	DurationMs      int      `json:"durationMs"`
}

// Verdict: secure | partial | missing
type CaaCheck struct {
	Host               string         `json:"host"`
	Verdict            string         `json:"verdict"`
	Headline           string         `json:"headline"`
	Records            []CaaRecordRow `json:"records"`
	AllowedIssueCAs    []string       `json:"allowedIssueCAs"`
	AllowedWildcardCAs []string       `json:"allowedWildcardCAs"`
	IodefEndpoints     []string       `json:"iodefEndpoints"`
	Recommendations    []string       `json:"recommendations"`
	CheckedAt          string         `json:"checkedAt"`
	DurationMs         int            `json:"durationMs"`
}

type CaaRecordRow struct {
	Critical int    `json:"critical"`
	Tag      string `json:"tag"`
	Value    string `json:"value"`
}

type SubdomainsCheck struct {
	Host       string           `json:"host"`
	Count      int              `json:"count"`
	Subdomains []SubdomainEntry `json:"subdomains"`
	CheckedAt  string           `json:"checkedAt"`
	DurationMs int              `json:"durationMs"`
}

type SubdomainEntry struct {
	Name      string `json:"name"`
	FirstSeen string `json:"firstSeen,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	Resolves  bool   `json:"resolves,omitempty"`
}

// Verdict: vulnerable | suspicious | safe | no-cname | error
type TakeoverCheck struct {
	Host            string                `json:"host"`
	Verdict         string                `json:"verdict"`
	Headline        string                `json:"headline"`
	CnameChain      []string              `json:"cnameChain"`
	FinalIPs        []string              `json:"finalIPs"`
	Fingerprints    []TakeoverFingerprint `json:"fingerprints"`
	Recommendations []string              `json:"recommendations"`
	CheckedAt       string                `json:"checkedAt"`
	DurationMs      int                   `json:"durationMs"`
}

type TakeoverFingerprint struct {
	Service     string `json:"service"`
	ServiceName string `json:"serviceName"`
	CnameTarget string `json:"cnameTarget"`
	Confidence  string `json:"confidence"`
}

// Verdict: yes | maybe | no
type SpoofabilityCheck struct {
	Host            string   `json:"host"`
	Verdict         string   `json:"verdict"`
	Headline        string   `json:"headline"`
	Recommendations []string `json:"recommendations"`
	CheckedAt       string   `json:"checkedAt"`
	DurationMs      int      `json:"durationMs"`
}

type SpfFlattenCheck struct {
	Host     string `json:"host"`
	Original struct {
		Record      string `json:"record"`
		LookupCount int    `json:"lookupCount"`
	} `json:"original"`
	Flattened struct {
		Record   string   `json:"record"`
		Includes []string `json:"resolvedIncludes"`
		IPCount  int      `json:"ipCount"`
		Bytes    int      `json:"bytes"`
	} `json:"flattened"`
	Warnings        []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
	CheckedAt       string   `json:"checkedAt"`
	DurationMs      int      `json:"durationMs"`
}

type ThreatIntelCheck struct {
	Host       string `json:"host"`
	AnyFlagged bool   `json:"anyFlagged"`
	URLhaus    *struct {
		Listed   bool `json:"listed"`
		URLCount int  `json:"urlCount,omitempty"`
	} `json:"urlhaus,omitempty"`
	Threatfox *struct {
		Listed        bool   `json:"listed"`
		MalwareFamily string `json:"malwareFamily,omitempty"`
	} `json:"threatfox,omitempty"`
	Phishtank *struct {
		Listed bool `json:"listed"`
	} `json:"phishtank,omitempty"`
	DomainAge *struct {
		AgeDays         int    `json:"ageDays,omitempty"`
		NewlyRegistered bool   `json:"newlyRegistered"`
		RegisteredAt    string `json:"registeredAt,omitempty"`
	} `json:"domainAge,omitempty"`
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

func (c *Client) CheckHeaders(domain string) (*HeadersCheck, error) {
	var out HeadersCheck
	if err := c.get(checkPath("headers", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckMtaSts(domain string) (*MtaStsCheck, error) {
	var out MtaStsCheck
	if err := c.get(checkPath("mta-sts", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckBimi(domain string) (*BimiCheck, error) {
	var out BimiCheck
	if err := c.get(checkPath("bimi", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckDnssec(domain string) (*DnssecCheck, error) {
	var out DnssecCheck
	if err := c.get(checkPath("dnssec", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckCaa(domain string) (*CaaCheck, error) {
	var out CaaCheck
	if err := c.get(checkPath("caa", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckSubdomains(domain string) (*SubdomainsCheck, error) {
	var out SubdomainsCheck
	if err := c.get(checkPath("subdomains", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckTakeover(domain string) (*TakeoverCheck, error) {
	var out TakeoverCheck
	if err := c.get(checkPath("takeover", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckSpoofability(domain string) (*SpoofabilityCheck, error) {
	var out SpoofabilityCheck
	if err := c.get(checkPath("spoofability", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckSpfFlatten(domain string) (*SpfFlattenCheck, error) {
	var out SpfFlattenCheck
	if err := c.get(checkPath("spf-flatten", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CheckThreatIntel(domain string) (*ThreatIntelCheck, error) {
	var out ThreatIntelCheck
	if err := c.get(checkPath("threat-intel", domain), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckGeneric runs an arbitrary tool from /api/v1/check/<tool>/<domain>
// and decodes the JSON into the supplied destination. Useful when the
// caller wants a tool that doesn't have a typed shape yet.
func (c *Client) CheckGeneric(tool, domain string, out any) error {
	return c.get(checkPath(tool, domain), out)
}

// Me is the response from GET /api/v1/me. Trimmed to what `auth
// whoami` renders; key + authMethod fields available but we don't
// surface them today.
type Me struct {
	User struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		Tier        string `json:"tier"`
		TierLabel   string `json:"tierLabel"`
		DomainQuota int    `json:"domainQuota"`
		IsAdmin     bool   `json:"isAdmin"`
	} `json:"user"`
	AuthMethod string `json:"authMethod"`
}

func (c *Client) Me() (*Me, error) {
	var out Me
	if err := c.get("/api/v1/me", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- watch (monitored domains) ----

type MonitoredDomain struct {
	ID             string            `json:"id"`
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	Label          *string           `json:"label,omitempty"`
	CadenceMinutes int               `json:"cadenceMinutes"`
	Paused         bool              `json:"paused"`
	LastCheckedAt  *string           `json:"lastCheckedAt,omitempty"`
	LastWorstGrade string            `json:"lastWorstGrade,omitempty"`
	LastGrades     map[string]string `json:"lastGrades,omitempty"`
	CreatedAt      string            `json:"createdAt"`
}

type domainsListResp struct {
	Data  []MonitoredDomain `json:"data"`
	Count int               `json:"count"`
}

func (c *Client) ListDomains() ([]MonitoredDomain, error) {
	var out domainsListResp
	if err := c.get("/api/v1/domains", &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

type AddDomainRequest struct {
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Label          string `json:"label,omitempty"`
	CadenceMinutes int    `json:"cadenceMinutes,omitempty"`
}

type addDomainResp struct {
	Domain MonitoredDomain `json:"domain"`
}

func (c *Client) AddDomain(req *AddDomainRequest) (*MonitoredDomain, error) {
	var out addDomainResp
	if err := c.post("/api/v1/domains", req, &out); err != nil {
		return nil, err
	}
	return &out.Domain, nil
}

func (c *Client) DeleteDomain(id string) error {
	return c.do("DELETE", "/api/v1/domains/"+url.PathEscape(id), nil, nil)
}

// ---- alerts ----

type AlertEndpoint struct {
	ID              string  `json:"id"`
	Kind            string  `json:"kind"`
	Label           string  `json:"label"`
	URL             string  `json:"url,omitempty"`
	EmailTo         string  `json:"emailTo,omitempty"`
	Enabled         bool    `json:"enabled"`
	LastFiredAt     *string `json:"lastFiredAt,omitempty"`
	LastFiredStatus *string `json:"lastFiredStatus,omitempty"`
	CreatedAt       string  `json:"createdAt"`
}

type alertsResp struct {
	Data  []AlertEndpoint `json:"data"`
	Count int             `json:"count"`
}

func (c *Client) ListAlerts() ([]AlertEndpoint, error) {
	var out alertsResp
	if err := c.get("/api/v1/alerts", &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// ---- NOC dashboard ----

type DashboardSummary struct {
	MonitoredCount      int               `json:"monitoredCount"`
	GradeDistribution   map[string]int    `json:"gradeDistribution"`
	BlocklistHits       int               `json:"blocklistHits"`
	RecentAlertCount24h int               `json:"recentAlertCount24h"`
	ActionQueue         []ActionQueueItem `json:"actionQueue"`
	GeneratedAt         string            `json:"generatedAt"`
}

type ActionQueueItem struct {
	Severity   string `json:"severity"`
	Kind       string `json:"kind"`
	Domain     string `json:"domain"`
	Message    string `json:"message"`
	DetectedAt string `json:"detectedAt"`
}

func (c *Client) DashboardSummary() (*DashboardSummary, error) {
	var out DashboardSummary
	if err := c.get("/api/v1/dashboard/summary", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type RecentScan struct {
	ID                string            `json:"id"`
	MonitoredDomainID string            `json:"monitoredDomainId"`
	Host              string            `json:"host"`
	Port              int               `json:"port"`
	WorstGrade        string            `json:"worstGrade"`
	Grades            map[string]string `json:"grades"`
	RanAt             string            `json:"ranAt"`
	DurationMs        int               `json:"durationMs"`
}

type recentScansResp struct {
	Scans  []RecentScan `json:"scans"`
	Cursor *string      `json:"cursor"`
}

// LiveAnchorHead returns the current chain head hash from
// /api/v1/audit/anchors (public, no auth). Empty string + error if the
// chain is empty or the endpoint is unreachable.
func (c *Client) LiveAnchorHead() (string, error) {
	var out struct {
		Current struct {
			HeadHash *string `json:"headHash"`
		} `json:"current"`
	}
	if err := c.get("/api/v1/audit/anchors", &out); err != nil {
		return "", err
	}
	if out.Current.HeadHash == nil {
		return "", fmt.Errorf("no live anchor head (chain may be empty)")
	}
	return *out.Current.HeadHash, nil
}

// RecentScans returns the latest scans across the caller's domain set.
// since is an ISO timestamp; when non-empty, only scans with ranAt
// strictly after it are returned (cursor-based tail).
func (c *Client) RecentScans(since string, limit int) ([]RecentScan, error) {
	path := "/api/v1/scans/recent"
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if since != "" {
		q.Set("since", since)
	}
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out recentScansResp
	if err := c.get(path, &out); err != nil {
		return nil, err
	}
	return out.Scans, nil
}

func checkPath(tool, domain string) string {
	return fmt.Sprintf("/api/v1/check/%s/%s",
		url.PathEscape(strings.ToLower(tool)),
		url.PathEscape(strings.ToLower(domain)),
	)
}

// ---- brand watchlist (Pro+) ----

type BrandWatchlist struct {
	ID            string  `json:"id"`
	Keyword       string  `json:"keyword"`
	Label         *string `json:"label,omitempty"`
	IsActive      bool    `json:"isActive"`
	LastScannedAt *string `json:"lastScannedAt,omitempty"`
	CreatedAt     string  `json:"createdAt"`
}

type BrandWatchlistMatch struct {
	ID                 string  `json:"id"`
	WatchlistID        string  `json:"watchlistId"`
	Keyword            string  `json:"keyword"`
	Candidate          string  `json:"candidate"`
	Source             string  `json:"source"`
	HasA               bool    `json:"hasA"`
	HasMx              bool    `json:"hasMx"`
	HasNs              bool    `json:"hasNs"`
	ThreatIntelListed  *bool   `json:"threatIntelListed,omitempty"`
	ThreatIntelGrade   *string `json:"threatIntelGrade,omitempty"`
	ThreatIntelSummary *string `json:"threatIntelSummary,omitempty"`
	KitBrand           *string `json:"kitBrand,omitempty"`
	KitScore           *string `json:"kitScore,omitempty"`
	KitHomepageURL     *string `json:"kitHomepageUrl,omitempty"`
	FirstSeenAt        string  `json:"firstSeenAt"`
	LastSeenAt         string  `json:"lastSeenAt"`
}

type BrandWatchlistResp struct {
	Watchlists      []BrandWatchlist      `json:"watchlists"`
	Matches         []BrandWatchlistMatch `json:"matches"`
	MatchWindowDays int                   `json:"matchWindowDays"`
	MatchLimit      int                   `json:"matchLimit"`
}

func (c *Client) BrandWatchlist() (*BrandWatchlistResp, error) {
	var out BrandWatchlistResp
	if err := c.get("/api/v1/brand-watchlist", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- leak sites (Pro+) ----

type LeakSiteFinding struct {
	ID                string  `json:"id"`
	GroupName         string  `json:"groupName"`
	VictimTitle       string  `json:"victimTitle"`
	Match             string  `json:"match"`
	MatchSource       string  `json:"matchSource"`
	MonitoredDomainID *string `json:"monitoredDomainId,omitempty"`
	WatchlistID       *string `json:"watchlistId,omitempty"`
	PostURL           *string `json:"postUrl,omitempty"`
	PublishedAt       *string `json:"publishedAt,omitempty"`
	FirstSeenAt       string  `json:"firstSeenAt"`
	LastSeenAt        string  `json:"lastSeenAt"`
	Alerted           bool    `json:"alerted"`
}

type LeakSitesResp struct {
	Findings []LeakSiteFinding `json:"findings"`
	Count    int               `json:"count"`
	Limit    int               `json:"limit"`
}

func (c *Client) LeakSites() (*LeakSitesResp, error) {
	var out LeakSitesResp
	if err := c.get("/api/v1/leak-sites", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- credential leaks (Pro+) ----

type CredentialLeakFinding struct {
	ID                string   `json:"id"`
	MonitoredDomainID string   `json:"monitoredDomainId"`
	Domain            *string  `json:"domain,omitempty"`
	BreachName        string   `json:"breachName"`
	BreachTitle       *string  `json:"breachTitle,omitempty"`
	BreachedDomain    *string  `json:"breachedDomain,omitempty"`
	AccountCount      *int     `json:"accountCount,omitempty"`
	DataClasses       []string `json:"dataClasses"`
	BreachDate        *string  `json:"breachDate,omitempty"`
	AddedAt           *string  `json:"addedAt,omitempty"`
	FirstSeenAt       string   `json:"firstSeenAt"`
	LastSeenAt        string   `json:"lastSeenAt"`
	Alerted           bool     `json:"alerted"`
}

type CredentialLeaksResp struct {
	Findings []CredentialLeakFinding `json:"findings"`
	Count    int                     `json:"count"`
	Limit    int                     `json:"limit"`
}

func (c *Client) CredentialLeaks() (*CredentialLeaksResp, error) {
	var out CredentialLeaksResp
	if err := c.get("/api/v1/credential-leaks", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- vendor watchlist (Pro+) ----

// VendorSnapshot is the loose JSON the worker writes after each scan.
// Fields are optional so the API surface stays stable as the worker
// evolves. Today's keys: capturedAt, overall, worst, threatIntel.
type VendorSnapshot struct {
	CapturedAt  string               `json:"capturedAt,omitempty"`
	Overall     string               `json:"overall,omitempty"`
	Worst       map[string]string    `json:"worst,omitempty"`
	ThreatIntel *VendorThreatSummary `json:"threatIntel,omitempty"`
}

type VendorThreatSummary struct {
	Listed  *bool  `json:"listed,omitempty"`
	Summary string `json:"summary,omitempty"`
	Grade   string `json:"grade,omitempty"`
}

type VendorSubscription struct {
	ID            string          `json:"id"`
	Domain        string          `json:"domain"`
	Label         *string         `json:"label,omitempty"`
	Notes         *string         `json:"notes,omitempty"`
	IsActive      bool            `json:"isActive"`
	LastSnapshot  *VendorSnapshot `json:"lastSnapshot,omitempty"`
	LastScannedAt *string         `json:"lastScannedAt,omitempty"`
	LastError     *string         `json:"lastError,omitempty"`
	CreatedAt     string          `json:"createdAt"`
}

type VendorsResp struct {
	Vendors []VendorSubscription `json:"vendors"`
	Count   int                  `json:"count"`
}

func (c *Client) VendorWatchlist() (*VendorsResp, error) {
	var out VendorsResp
	if err := c.get("/api/v1/vendors", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- CVEs (Pro+) ----

type CveFinding struct {
	ID                string  `json:"id"`
	MonitoredDomainID string  `json:"monitoredDomainId"`
	Domain            *string `json:"domain,omitempty"`
	CveID             string  `json:"cveId"`
	Product           string  `json:"product"`
	Version           *string `json:"version,omitempty"`
	CVSS              *string `json:"cvss,omitempty"`
	Severity          *string `json:"severity,omitempty"`
	Summary           *string `json:"summary,omitempty"`
	PublishedAt       *string `json:"publishedAt,omitempty"`
	FirstSeenAt       string  `json:"firstSeenAt"`
	LastSeenAt        string  `json:"lastSeenAt"`
	Alerted           bool    `json:"alerted"`
}

type VulnerabilitiesResp struct {
	Findings []CveFinding `json:"findings"`
	Count    int          `json:"count"`
	Limit    int          `json:"limit"`
}

func (c *Client) Vulnerabilities() (*VulnerabilitiesResp, error) {
	var out VulnerabilitiesResp
	if err := c.get("/api/v1/vulnerabilities", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- CLI self-revoke ----

type CliRevokeResp struct {
	OK        bool   `json:"ok"`
	RevokedAt string `json:"revokedAt"`
}

// CliRevoke flips revokedAt on the API key carrying the current
// request. Used by `wd auth logout --remote`.
func (c *Client) CliRevoke() (*CliRevokeResp, error) {
	var out CliRevokeResp
	if err := c.post("/api/v1/cli/revoke", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- extension billing ----

type ExtensionTopup struct {
	Credits   int     `json:"credits"`
	ExpiresAt *string `json:"expiresAt,omitempty"`
	Active    bool    `json:"active"`
}

type ExtensionBudget struct {
	Plan             string         `json:"plan"`
	PlanLabel        string         `json:"planLabel"`
	Seats            int            `json:"seats"`
	Cadence          string         `json:"cadence"`
	WindowDays       int            `json:"windowDays"`
	AggregateTriages *int           `json:"aggregateTriages,omitempty"`
	Used             int            `json:"used"`
	Remaining        *int           `json:"remaining,omitempty"`
	Unlimited        bool           `json:"unlimited"`
	Topup            ExtensionTopup `json:"topup"`
	ManageURL        string         `json:"manageUrl"`
}

func (c *Client) ExtensionBudget() (*ExtensionBudget, error) {
	var out ExtensionBudget
	if err := c.get("/api/v1/extension/budget", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
