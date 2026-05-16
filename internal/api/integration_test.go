package api_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/output"
)

// Integration test for every check tool exposed by the CLI. Hits the
// live API at $WIREDEPTH_TEST_API (default https://wiredepth.com) and
// asserts that the response decodes into the Go struct + the matching
// output renderer produces non-empty bytes.
//
// Gated by env var POSTVALE_LIVE_TESTS=1 because it requires network.
// Run with:
//   POSTVALE_LIVE_TESTS=1 go test ./internal/api -run Integration -v
//
// Adding a new check? Add an entry to the table below. The whole point
// of this test is to catch type-mismatches the moment a webapp PR
// changes a response shape - the way HeadersCheck.serverDisclosure
// silently drifted from a string to an object did before this test
// existed.

func TestIntegration_CheckTools(t *testing.T) {
	if os.Getenv("POSTVALE_LIVE_TESTS") != "1" {
		t.Skip("set POSTVALE_LIVE_TESTS=1 to run live API tests")
	}

	apiBase := os.Getenv("WIREDEPTH_TEST_API")
	if apiBase == "" {
		apiBase = "https://wiredepth.com"
	}
	domain := os.Getenv("WIREDEPTH_TEST_DOMAIN")
	if domain == "" {
		domain = "wiredepth.com"
	}
	token := os.Getenv("POSTVALE_TEST_TOKEN") // optional, only needed for authed routes

	client, err := api.New(apiBase, token, 60*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	type checkCase struct {
		name string
		// run hits the API + renders. Returning a non-empty buffer +
		// nil err is success; returning an err fails the subtest.
		run func() ([]byte, error)
	}

	cases := []checkCase{
		{"full", func() ([]byte, error) {
			r, err := client.CheckFull(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderFullCheck(&b, r)
			return b.Bytes(), nil
		}},
		{"tls", func() ([]byte, error) {
			r, err := client.CheckTLS(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderTLS(&b, r)
			return b.Bytes(), nil
		}},
		{"dmarc", func() ([]byte, error) {
			r, err := client.CheckDMARC(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderDMARC(&b, r)
			return b.Bytes(), nil
		}},
		{"dns", func() ([]byte, error) {
			r, err := client.CheckDNS(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderDNS(&b, r)
			return b.Bytes(), nil
		}},
		{"headers", func() ([]byte, error) {
			r, err := client.CheckHeaders(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderHeaders(&b, r)
			return b.Bytes(), nil
		}},
		{"mta-sts", func() ([]byte, error) {
			r, err := client.CheckMtaSts(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderMtaSts(&b, r)
			return b.Bytes(), nil
		}},
		{"bimi", func() ([]byte, error) {
			r, err := client.CheckBimi(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderBimi(&b, r)
			return b.Bytes(), nil
		}},
		{"dnssec", func() ([]byte, error) {
			r, err := client.CheckDnssec(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderDnssec(&b, r)
			return b.Bytes(), nil
		}},
		{"caa", func() ([]byte, error) {
			r, err := client.CheckCaa(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderCaa(&b, r)
			return b.Bytes(), nil
		}},
		{"subdomains", func() ([]byte, error) {
			r, err := client.CheckSubdomains(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderSubdomains(&b, r)
			return b.Bytes(), nil
		}},
		{"takeover", func() ([]byte, error) {
			r, err := client.CheckTakeover(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderTakeover(&b, r)
			return b.Bytes(), nil
		}},
		{"spoofability", func() ([]byte, error) {
			r, err := client.CheckSpoofability(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderSpoofability(&b, r)
			return b.Bytes(), nil
		}},
		{"spf-flatten", func() ([]byte, error) {
			r, err := client.CheckSpfFlatten(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderSpfFlatten(&b, r)
			return b.Bytes(), nil
		}},
		{"threat-intel", func() ([]byte, error) {
			r, err := client.CheckThreatIntel(domain)
			if err != nil {
				return nil, err
			}
			var b bytes.Buffer
			output.RenderThreatIntel(&b, r)
			return b.Bytes(), nil
		}},
		{"vendor-consolidation", func() ([]byte, error) {
			var raw map[string]any
			if err := client.CheckGeneric("vendor-consolidation", domain, &raw); err != nil {
				return nil, err
			}
			// Generic doesn't have a renderer; existence + decode is enough.
			if len(raw) == 0 {
				return nil, errAssert("vendor-consolidation returned an empty object")
			}
			return []byte("ok"), nil
		}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out, err := c.run()
			if err != nil {
				// Cloudflare's bot-challenge interstitial means the
				// runner IP got 403-d at the edge - the request never
				// reached Postvale, so we can't assert anything about
				// the response shape. Skip with a clear message rather
				// than fail CI; the same code path passes from a
				// non-datacenter IP (the operator's laptop). Real fix
				// is the Cloudflare config documented at
				// docs/cloudflare-bypass.md.
				if api.IsCloudflareChallenge(err) {
					t.Skipf("%s: blocked by Cloudflare bot-challenge "+
						"(see docs/cloudflare-bypass.md); request never reached the API", c.name)
				}
				t.Fatalf("%s against %s: %v", c.name, domain, err)
			}
			if len(out) == 0 {
				t.Fatalf("%s rendered an empty result", c.name)
			}
		})
	}
}

// TestIntegration_MonitoringEndpoints exercises the Pro+ monitoring
// endpoints (brand watchlist, leak sites, credential leaks, vendor
// watchlist, CVEs). Requires a token from a Pro+ account in
// POSTVALE_TEST_TOKEN. Same opt-in env var. We assert each endpoint
// either returns 200 with a parseable body, OR 402 (which is the
// correct response for free / Starter tokens).

func TestIntegration_MonitoringEndpoints(t *testing.T) {
	if os.Getenv("POSTVALE_LIVE_TESTS") != "1" {
		t.Skip("set POSTVALE_LIVE_TESTS=1 to run live API tests")
	}
	token := os.Getenv("POSTVALE_TEST_TOKEN")
	if token == "" {
		t.Skip("set POSTVALE_TEST_TOKEN to run authenticated tests")
	}
	apiBase := os.Getenv("WIREDEPTH_TEST_API")
	if apiBase == "" {
		apiBase = "https://wiredepth.com"
	}

	client, err := api.New(apiBase, token, 60*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	type monCase struct {
		name string
		run  func() error
	}

	// Each case ignores 402 as "user isn't on a Pro+ tier" - the
	// shape contract is what we're testing, not the entitlement. Any
	// other error fails the subtest.
	allow402 := func(err error) bool {
		if err == nil {
			return false
		}
		// HTTPError stringifies as "api: ... (402 ...)" so a contains
		// check is enough without re-exporting the type.
		return contains(err.Error(), "402") || contains(err.Error(), "pro_required")
	}

	cases := []monCase{
		{"brand-watchlist", func() error {
			r, err := client.BrandWatchlist()
			if allow402(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if r == nil {
				return errAssert("brand-watchlist returned nil")
			}
			return nil
		}},
		{"leak-sites", func() error {
			r, err := client.LeakSites()
			if allow402(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if r == nil {
				return errAssert("leak-sites returned nil")
			}
			return nil
		}},
		{"credential-leaks", func() error {
			r, err := client.CredentialLeaks()
			if allow402(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if r == nil {
				return errAssert("credential-leaks returned nil")
			}
			return nil
		}},
		{"vendors", func() error {
			r, err := client.VendorWatchlist()
			if allow402(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if r == nil {
				return errAssert("vendors returned nil")
			}
			return nil
		}},
		{"vulnerabilities", func() error {
			r, err := client.Vulnerabilities()
			if allow402(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if r == nil {
				return errAssert("vulnerabilities returned nil")
			}
			return nil
		}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := c.run(); err != nil {
				if api.IsCloudflareChallenge(err) {
					t.Skipf("%s: blocked by Cloudflare bot-challenge "+
						"(see docs/cloudflare-bypass.md); request never reached the API", c.name)
				}
				t.Fatalf("%s: %v", c.name, err)
			}
		})
	}
}

// errAssert is a tiny helper so the table can fail without pulling in
// testify just for a single sentinel.
type errAssert string

func (e errAssert) Error() string { return string(e) }

// contains is a tiny strings.Contains that avoids pulling in the
// strings package just for one call site (keeps the test file's
// imports minimal).
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
