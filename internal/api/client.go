// HTTP client to the WireDepth API.
//
// One client per Cmd lifetime. Sets the right User-Agent so the
// webapp can log CLI traffic separately from browser traffic, and
// attaches the bearer token when present. Timeouts are intentional
// short defaults (15s); a check that takes longer is a check that
// would hang a CI pipeline.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WiredepthHQ/cli/internal/version"
)

// Client is the lazily-initialised HTTP client. Zero value is
// usable; SetBase + SetToken are setters that should be called
// before any request method.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a Client with default 15s timeout pointed at base.
func New(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// SetToken attaches a bearer token to every subsequent request.
func (c *Client) SetToken(t string) { c.token = t }

// Get performs a GET against the API and decodes the JSON response
// into out. Returns a typed *APIError on non-2xx so callers can
// distinguish auth failures from validation errors.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// CheckResult is the wire shape returned by /api/v1/check/<tool>/<domain>.
// The webapp returns raw check structs; we keep this loose so each
// caller can decode into a tool-specific struct.
type CheckResult struct {
	Domain string          `json:"domain"`
	Tool   string          `json:"tool"`
	Result json.RawMessage `json:"result"`
}

// Check calls /api/v1/check/<tool>/<domain> and decodes the result
// into out. Pass `nil` for out if the caller just wants raw bytes
// from CheckResult.Result.
func (c *Client) Check(ctx context.Context, tool, domain string, out *CheckResult) error {
	t := url.PathEscape(strings.ToLower(strings.TrimSpace(tool)))
	d := url.PathEscape(strings.ToLower(strings.TrimSpace(domain)))
	if t == "" || d == "" {
		return errors.New("tool and domain are required")
	}
	return c.Get(ctx, "/api/v1/check/"+t+"/"+d, out)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wd/"+version.Version+" (https://wiredepth.com)")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Read up to 8KB of error body for the message; truncate
		// beyond that to keep stderr readable.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return &APIError{
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(b)),
		}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// APIError is returned when the API responds with a non-2xx status.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("api: %d %s", e.Status, e.Body)
	}
	return fmt.Sprintf("api: HTTP %d", e.Status)
}
