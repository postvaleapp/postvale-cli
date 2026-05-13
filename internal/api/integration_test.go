package api_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/postvaleapp/postvale-cli/internal/api"
	"github.com/postvaleapp/postvale-cli/internal/output"
)

// Integration test for every check tool exposed by the CLI. Hits the
// live API at $POSTVALE_TEST_API (default https://postvale.app) and
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

	apiBase := os.Getenv("POSTVALE_TEST_API")
	if apiBase == "" {
		apiBase = "https://postvale.app"
	}
	domain := os.Getenv("POSTVALE_TEST_DOMAIN")
	if domain == "" {
		domain = "postvale.app"
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
				t.Fatalf("%s against %s: %v", c.name, domain, err)
			}
			if len(out) == 0 {
				t.Fatalf("%s rendered an empty result", c.name)
			}
		})
	}
}

// errAssert is a tiny helper so the table can fail without pulling in
// testify just for a single sentinel.
type errAssert string

func (e errAssert) Error() string { return string(e) }
