// Package api is the HTTP client for wiredepth.com. All command code
// goes through this package so auth, retries, and UA stamping live
// in one place.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WiredepthHQ/cli/internal/version"
)

// 8 MiB ceiling on any single response body. Bounds memory if the
// server (or a malicious one via --api) returns a huge payload.
const maxResponseBytes = 8 << 20

type Client struct {
	base       *url.URL
	token      string
	httpClient *http.Client
}

func New(baseURL, token string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid api url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("api url must be http or https: %q", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("api url missing host: %q", baseURL)
	}
	return &Client{
		base:       u,
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

func userAgent() string {
	return fmt.Sprintf("wd-cli/%s (+https://github.com/WiredepthHQ/cli)", version.Version)
}

// BaseURL returns the configured API base as a string, e.g.
// "https://wiredepth.com". Useful for callers that need to build
// dashboard URLs to hand to the user's browser.
func (c *Client) BaseURL() string {
	return c.base.String()
}

// HTTPError is returned for non-2xx responses.
type HTTPError struct {
	StatusCode int
	Status     string
	URL        string
	Body       []byte
}

// IsAuthError returns true when err is an HTTPError whose status code
// indicates the caller's token was rejected by the server (401). Used
// by command pre-flight checks + the TUI shell to distinguish a token
// problem from a transient network or server issue.
func IsAuthError(err error) bool {
	he := asHTTPError(err)
	return he != nil && he.StatusCode == 401
}

// IsCloudflareChallenge returns true when err is an HTTPError whose
// body looks like Cloudflare's bot-challenge interstitial. Datacenter
// IPs (CI runners, build VMs, ephemeral cloud workstations) routinely
// get challenged on first hit. The presence of these markers tells us
// "this isn't a Postvale-server error - the request never reached
// Postvale". Callers can present a helpful hint instead of a wall of
// HTML preview.
//
// Detection looks at well-known Cloudflare HTML titles. We avoid
// keying on headers like cf-ray (it appears even on legitimate cached
// responses) so we don't get false positives.
func IsCloudflareChallenge(err error) bool {
	he := asHTTPError(err)
	if he == nil || he.StatusCode != 403 {
		return false
	}
	body := string(he.Body)
	if len(body) > 4096 {
		body = body[:4096]
	}
	if strings.Contains(body, "<title>Just a moment...</title>") {
		return true
	}
	if strings.Contains(body, "Attention Required! | Cloudflare") {
		return true
	}
	if strings.Contains(body, "cf-mitigated") {
		return true
	}
	if strings.Contains(body, "challenge-platform") {
		return true
	}
	return false
}

// asHTTPError walks the wrapped-error chain to find an *HTTPError.
// Shared by IsAuthError and IsCloudflareChallenge so callers don't
// repeat the unwrap loop.
func asHTTPError(err error) *HTTPError {
	if err == nil {
		return nil
	}
	for cur := err; cur != nil; {
		if h, ok := cur.(*HTTPError); ok {
			return h
		}
		// Unwrap manually since this package can't depend on errors.As
		// reaching custom error types through fmt.Errorf wrapping in
		// every call site - the get/do helpers return the *HTTPError
		// directly, so a simple type assertion is enough.
		if u, ok := cur.(interface{ Unwrap() error }); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return nil
}

func (e *HTTPError) Error() string {
	// Cloudflare bot-challenge interstitial: the request never reached
	// Postvale. Surface a one-line hint instead of 200 chars of HTML
	// preview so the operator knows where to look.
	if IsCloudflareChallenge(e) {
		return fmt.Sprintf(
			"api: %s for %s: blocked by Cloudflare bot-challenge "+
				"(your IP is on a list of datacenter / CI / VPN ranges Cloudflare auto-challenges). "+
				"This is a network policy on wiredepth.com, not a Postvale-server error. "+
				"If you're hitting this from CI or a cloud VM, see "+
				"https://wiredepth.com/docs/cloudflare-bypass for the operator-side fix.",
			e.Status, e.URL,
		)
	}
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(e.Body, &parsed); err == nil {
		if parsed.Message != "" {
			return fmt.Sprintf("api: %s (%s)", parsed.Message, e.Status)
		}
		if parsed.Error != "" {
			return fmt.Sprintf("api: %s (%s)", parsed.Error, e.Status)
		}
	}
	preview := string(e.Body)
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	if preview == "" {
		return fmt.Sprintf("api: %s for %s", e.Status, e.URL)
	}
	return fmt.Sprintf("api: %s for %s: %s", e.Status, e.URL, preview)
}

func (c *Client) get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

// resolve splits path into Path + RawQuery against the client's base
// URL. Required because setting url.URL.Path on a string that contains
// "?foo=bar" would URL-escape the "?" and turn the query into a path
// segment server-side.
func (c *Client) resolve(path string) (*url.URL, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid request path %q: %w", path, err)
	}
	return c.base.ResolveReference(ref), nil
}

// GetStream issues an authenticated GET and streams the response
// body to w. Used for binary downloads (PDFs etc.) where we don't
// want to buffer the whole payload in memory. Cap is still enforced.
func (c *Client) GetStream(path string, w io.Writer) error {
	u, err := c.resolve(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent())
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request GET %s: %w", u.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        u.String(),
			Body:       buf,
		}
	}

	// Stream with a hard ceiling. Workpaper PDFs are well under 8 MiB
	// in practice; we use the same maxResponseBytes cap as JSON.
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("stream body: %w", err)
	}
	if n > maxResponseBytes {
		return fmt.Errorf("response exceeded %d bytes", maxResponseBytes)
	}
	return nil
}

func (c *Client) post(path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	return c.do(http.MethodPost, path, rdr, out)
}

func (c *Client) do(method, path string, body io.Reader, out any) error {
	u, err := c.resolve(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, u.String(), err)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(buf)) > maxResponseBytes {
		return fmt.Errorf("response exceeded %d bytes", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        u.String(),
			Body:       buf,
		}
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(buf, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
