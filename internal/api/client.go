// Package api is the HTTP client for postvale.app. All command code
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
	"time"

	"github.com/postvaleapp/postvale-cli/internal/version"
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
	return fmt.Sprintf("postvale-cli/%s (+https://github.com/postvaleapp/postvale-cli)", version.Version)
}

// HTTPError is returned for non-2xx responses.
type HTTPError struct {
	StatusCode int
	Status     string
	URL        string
	Body       []byte
}

func (e *HTTPError) Error() string {
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
	u := *c.base
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
