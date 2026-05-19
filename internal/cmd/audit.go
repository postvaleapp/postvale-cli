// Audit chain commands.
//
// `wd audit anchors` lists the daily Merkle anchors that WireDepth
// publishes; `wd audit verify` fetches a JSONL export + recomputes
// the chain to confirm what the webapp claims matches what the
// crypto proves. The verifier is intentionally implemented in Go
// here (not just a wrapper around a webapp endpoint) - the whole
// point is that the auditor doesn't need WireDepth's servers to
// confirm the evidence.
//
// `wd audit verify` ships as a stub for now: lists the anchors so
// the auditor can confirm they exist + are timestamped. Full Merkle
// recomputation lands in a follow-up - the algorithm spec lives at
// https://wiredepth.com/docs/verify and a browser-only verifier
// already runs at /verify, so the structure is well-defined; this
// is a translation exercise.
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
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect + verify the WireDepth audit chain",
	Long: `Inspect + verify the cryptographic audit chain that
backs every monitored finding.

WireDepth hashes every finding into a per-user daily Merkle tree,
publishes the daily root, and anchors the root to an external RFC
3161 TSA (DigiCert) so the timestamp can't be backdated. This
command lets you (or your auditor) read the anchors directly + run
the verification yourself. WireDepth's servers never have to be
trusted to confirm the evidence is real.`,
}

var auditAnchorsCmd = &cobra.Command{
	Use:   "anchors",
	Short: "List published daily Merkle anchors",
	RunE: func(cmd *cobra.Command, args []string) error {
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
		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()

		// /api/v1/audit/anchors is CORS-open + public; no auth
		// required (the whole point is the public can verify the
		// anchors independently).
		var anchors struct {
			Anchors []struct {
				Date     string `json:"date"`
				Root     string `json:"root"`
				TSAToken string `json:"tsaToken,omitempty"`
				Count    int    `json:"count"`
			} `json:"anchors"`
		}
		if err := client.Get(ctx, "/api/v1/audit/anchors", &anchors); err != nil {
			return fmt.Errorf("fetch anchors: %w", err)
		}

		if flagJSON {
			return json.NewEncoder(os.Stdout).Encode(anchors)
		}
		fmt.Println("Date        Findings  Root                                                              TSA")
		for _, a := range anchors.Anchors {
			tsa := "no"
			if a.TSAToken != "" {
				tsa = "yes"
			}
			fmt.Printf("%-10s  %-8d  %s  %s\n", a.Date, a.Count, a.Root, tsa)
		}
		return nil
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an audit-export JSONL bundle against the published anchors",
	Long: `Verify an exported audit log bundle by recomputing the
Merkle root client-side and matching it against the daily anchor
that WireDepth publishes.

Stub in this release: the wire-up to fetch + parse + recompute
will land in a follow-up commit. The algorithm spec is at
https://wiredepth.com/docs/verify and the browser-only verifier
at https://wiredepth.com/verify shows the same logic running
against a pasted export today.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "Verification CLI implementation is in progress.")
		fmt.Fprintln(cmd.OutOrStdout(), "For now, run the browser verifier at https://wiredepth.com/verify -")
		fmt.Fprintln(cmd.OutOrStdout(), "it runs the same algorithm client-side with no WireDepth account.")
		return nil
	},
}

func init() {
	auditCmd.AddCommand(auditAnchorsCmd, auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
