package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://wiredepth.com"
	pollEndpoint   = "/api/v1/probes/poll"
	findingsEnd    = "/api/v1/probes/findings"
	bodyLimit      = 1 << 20 // 1MB response cap
)

// Client wraps the probe-side HTTP calls. Bearer auth, JSON.
type Client struct {
	APIBase    string
	Token      string
	HTTPClient *http.Client
	Version    string
}

// New builds a client with sensible defaults. Empty APIBase falls back
// to https://wiredepth.com.
func New(apiBase, token, version string) *Client {
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	return &Client{
		APIBase: strings.TrimRight(apiBase, "/"),
		Token:   token,
		Version: version,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// WorkItem is one row from /api/v1/probes/poll.
type WorkItem struct {
	ID      string                 `json:"id"`
	Kind    string                 `json:"kind"`
	Target  string                 `json:"target"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type PollResponse struct {
	Work                []WorkItem `json:"work"`
	PollIntervalSeconds int        `json:"pollIntervalSeconds"`
}

// Poll requests pending work. probePlatform is "linux/amd64" etc.
func (c *Client) Poll(ctx context.Context) (*PollResponse, error) {
	body := map[string]interface{}{
		"probeVersion":  c.Version,
		"probePlatform": runtime.GOOS + "/" + runtime.GOARCH,
		"maxItems":      5,
	}
	resp, err := c.postJSON(ctx, pollEndpoint, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	var out PollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, bodyLimit)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode poll: %w", err)
	}
	return &out, nil
}

// Finding is one row submitted to /api/v1/probes/findings.
type Finding struct {
	Target               string                 `json:"target"`
	Kind                 string                 `json:"kind"`
	Severity             string                 `json:"severity"`
	Title                string                 `json:"title"`
	Detail               map[string]interface{} `json:"detail"`
	DistinguishingDetail string                 `json:"distinguishingDetail"`
}

type SubmitRequest struct {
	WorkID   string    `json:"workId,omitempty"`
	Findings []Finding `json:"findings"`
}

type SubmitResponse struct {
	Accepted   int                      `json:"accepted"`
	Rejections []map[string]interface{} `json:"rejections,omitempty"`
}

// Submit POSTs findings produced by a work item.
func (c *Client) Submit(ctx context.Context, req SubmitRequest) (*SubmitResponse, error) {
	resp, err := c.postJSON(ctx, findingsEnd, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, statusError(resp)
	}
	var out SubmitResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, bodyLimit)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode submit: %w", err)
	}
	return &out, nil
}

func (c *Client) postJSON(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	url := c.APIBase + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "wiredepth-probe/"+c.Version)
	return c.HTTPClient.Do(req)
}

func statusError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("probe token rejected (401); revoked or invalid")
	}
	if resp.StatusCode == http.StatusLocked {
		return errors.New("probe paused by operator (423); resume in the dashboard")
	}
	return fmt.Errorf("http %d: %s", resp.StatusCode, msg)
}
