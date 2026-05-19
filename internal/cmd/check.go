// Public-tool check commands.
//
// One subcommand per tool, all routed through the same API call
// against /api/v1/check/<tool>/<domain>. The webapp does the work;
// we marshal the JSON response back to stdout. Output mode is
// human-readable text by default, JSON when --json is set.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/config"
	"github.com/WiredepthHQ/cli/internal/output"
)

// toolCmd builds a cobra subcommand for the given tool. Keeps each
// command's plumbing identical; only the tool slug + short
// description differ.
func toolCmd(tool, short, long string) *cobra.Command {
	return &cobra.Command{
		Use:   tool + " <domain>",
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd.Context(), tool, args[0])
		},
	}
}

func runCheck(ctx context.Context, tool, domain string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if flagAPI != "" {
		cfg.API = flagAPI
	}

	client := api.New(cfg.API)
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	// Generous 30s timeout per check - the headers / subdomain /
	// full-scan paths can chew through several DNS + TLS handshakes
	// against the target.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var result api.CheckResult
	if err := client.Check(ctx, tool, domain, &result); err != nil {
		return fmt.Errorf("%s check failed: %w", tool, err)
	}

	if flagJSON {
		return json.NewEncoder(os.Stdout).Encode(result.Result)
	}
	return output.RenderCheckResult(os.Stdout, tool, domain, result.Result)
}

func init() {
	checks := []struct {
		tool, short, long string
	}{
		{"check", "Run the full posture check (TLS / DMARC / DNS / headers / MTA-STS)",
			"Run every core posture check against the target in one shot. Returns a grade per tool plus an overall grade. Use the tool-specific commands (tls, dmarc, dns, ...) for narrower scope."},
		{"tls", "TLS / cert chain inspection",
			"Inspects the certificate chain, protocol suite, HSTS configuration, and OCSP revocation status of the target."},
		{"dmarc", "DMARC + SPF + DKIM posture",
			"Resolves DMARC, SPF, and DKIM records and reports policy strength, alignment, and common misconfigurations."},
		{"dns", "DNS posture (DNSSEC + CAA + RBLs + registrar)",
			"Walks DNSSEC chain via DoH, checks CAA, queries six mail blocklists, and surfaces registrar / EPP status."},
		{"dnssec", "DNSSEC chain validation",
			"Validates the DNSSEC chain via two independent DoH resolvers (Cloudflare + Google) for cross-source confirmation."},
		{"caa", "CAA record check",
			"Resolves CAA records and reports issuance scope + wildcard exposure."},
		{"headers", "HTTP security header audit",
			"Audits CSP, HSTS, X-Frame-Options, COOP, COEP, and other response headers against current best-practice defaults."},
		{"mta-sts", "MTA-STS policy check",
			"Resolves the MTA-STS policy + TLS-RPT record and reports enforcement mode."},
		{"subdomains", "CT-log subdomain enumeration",
			"Enumerates subdomains from public CT log aggregators. Free tier returns the top 10; paid tier returns the full inventory."},
		{"takeover", "Subdomain takeover check (CNAME + body probe)",
			"Walks the CNAME chain, matches against 68 known-takeover-service fingerprints, and probes the HTTPS body for documented unclaimed signatures."},
		{"spoofability", "Single-verdict spoofability (yes / maybe / no)",
			"Synthesises DMARC + SPF + DKIM + MTA-STS into one answer to 'can a third party send mail as this domain?'"},
		{"threat-intel", "Threat-intel reputation (malware / phishing / blocklists)",
			"Checks the target against the threat-intel feeds we ingest."},
	}
	for _, c := range checks {
		rootCmd.AddCommand(toolCmd(c.tool, c.short, c.long))
	}
}
