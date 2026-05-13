// Package api is the HTTP client for postvale.app. All commands go
// through this package - never directly through net/http - so we can
// add auth, retries, rate-limit awareness, and user-agent stamping
// in one place.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/postvaleapp/postvale-cli/internal/version"
)

// Client wraps an HTTP client + base URL + optional auth token.
// Construct with New; never construct the zero value.
type Client struct {
	base       *url.URL
	token      string
	httpClient *http.Client
}

// New constructs a client for the given base URL (e.g.
// https://postvale.app). Returns an error if the URL is malformed.
//
// timeout controls the per-request deadline. Set to 0 for no
// timeout (not recommended in production - prefer 30s+).
func New(baseURL, token string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid api url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("api url missing scheme or host: %q", baseURL)
	}
	return &Client{
		base:  u,
		token: token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// userAgent returns the User-Agent string the CLI sends with every
// request. Includes the CLI version so the API can attribute traffic
// + roll out version-gated features.
func userAgent() string {
	return fmt.Sprintf("postvale-cli/%s (+https://github.com/postvaleapp/postvale-cli)", version.Version)
}

// HTTPError is returned when the server responds with a non-2xx
// status. Wraps the response code + body so callers can render a
// useful error to the user.
type HTTPError struct {
	StatusCode int
	Status     string
	URL        string
	Body       []byte
}

func (e *HTTPError) Error() string {
	// Try to extract { "error": "...", "message": "..." } shape if
	// the server returned JSON. Falls back to plain text otherwise.
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(e.Body, &parsed); err == nil && (parsed.Error != "" || parsed.Message != "") {
		if parsed.Message != "" {
			return fmt.Sprintf("api: %s (%s)", parsed.Message, e.Status)
		}
		return fmt.Sprintf("api: %s (%s)", parsed.Error, e.Status)
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

// get issues an authenticated GET to path (relative to the base URL).
// Body is decoded into out (a pointer to the response struct).
func (c *Client) get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

// post issues an authenticated POST with a JSON body.
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
	u := *c.base // copy
	u.Path = path

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

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
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
