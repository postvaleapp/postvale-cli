// Audit chain commands.
//
// `wd audit anchors` lists the daily Merkle anchors that WireDepth
// publishes; `wd audit verify` reads a JSONL export (or fetches one
// via the API) and walks the per-row chain + Merkle inclusion
// proofs. Implementation lives in internal/merkle; this file is
// just cobra wiring + output formatting.
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/api"
	"github.com/WiredepthHQ/cli/internal/config"
	"github.com/WiredepthHQ/cli/internal/merkle"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect + verify the WireDepth audit chain",
	Long: `Inspect + verify the cryptographic audit chain that
backs every monitored finding.

WireDepth hashes every audit-log row into a per-user chain
(sha256(canonical_json + prev_hash) per row), rolls the daily chain
heads into a Merkle tree, publishes the daily root, and anchors
the root to an external RFC 3161 TSA (DigiCert) so the timestamp
can't be backdated. This command lets you (or your auditor) read
the anchors directly + run the verification yourself. WireDepth's
servers never have to be trusted to confirm the evidence is real.`,
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
				Date        string `json:"date"`
				HeadHash    string `json:"headHash"`
				HeadRowID   int    `json:"headRowId"`
				RowCount    int    `json:"rowCount"`
				CreatedAt   string `json:"createdAt"`
				TsrTokenB64 string `json:"tsrTokenB64,omitempty"`
			} `json:"anchors"`
		}
		if err := client.Get(ctx, "/api/v1/audit/anchors", &anchors); err != nil {
			return fmt.Errorf("fetch anchors: %w", err)
		}

		if flagJSON {
			return json.NewEncoder(os.Stdout).Encode(anchors)
		}
		fmt.Println("Date        Rows      Head hash                                                         TSA")
		for _, a := range anchors.Anchors {
			tsa := "no"
			if a.TsrTokenB64 != "" {
				tsa = "yes"
			}
			fmt.Printf("%-10s  %-8d  %s  %s\n", a.Date, a.RowCount, a.HeadHash, tsa)
		}
		return nil
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify [export-file]",
	Short: "Verify an audit-export JSONL bundle",
	Long: `Verify an audit log bundle by recomputing the per-row
sha256 chain hashes + linkage. Pass a JSONL export file as the
argument, or '-' to read from stdin. The export comes from
GET /api/v1/audit/export?format=jsonl on the signed-in account.

Exit codes:
  0  every row verifies + chain links cleanly
  1  one or more rows failed verification
  2  input could not be parsed

Run with --json for machine-readable output.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAuditVerify,
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	var reader io.Reader
	if len(args) == 0 || args[0] == "-" {
		reader = cmd.InOrStdin()
	} else {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		reader = f
	}

	rows, parseErrs, err := parseJSONL(reader)
	if err != nil {
		// Hard read error - exit with code 2 below via the cobra
		// caller's err propagation. Wrap with a distinct prefix
		// so the operator sees it wasn't a verification failure.
		return fmt.Errorf("read export: %w", err)
	}
	if len(rows) == 0 {
		return errors.New("no audit rows found in input (expected JSONL or JSON array)")
	}

	rep := merkle.VerifyChain(rows)

	if flagJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Rows        int                  `json:"rows"`
			GoodRowHash int                  `json:"good_row_hash"`
			BadRowHash  int                  `json:"bad_row_hash"`
			GoodLinkage int                  `json:"good_linkage"`
			BadLinkage  int                  `json:"bad_linkage"`
			ParseErrors []string             `json:"parse_errors,omitempty"`
			Errors      []merkle.VerifyError `json:"errors,omitempty"`
		}{
			Rows:        rep.Rows,
			GoodRowHash: rep.GoodRowHash,
			BadRowHash:  rep.BadRowHash,
			GoodLinkage: rep.GoodLinkage,
			BadLinkage:  rep.BadLinkage,
			ParseErrors: parseErrs,
			Errors:      rep.Errors,
		})
	}

	// Text output.
	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "Rows:        %d\n", rep.Rows)
	fmt.Fprintf(stdout, "Row-hash:    %d good, %d bad\n", rep.GoodRowHash, rep.BadRowHash)
	fmt.Fprintf(stdout, "Linkage:     %d good, %d bad\n", rep.GoodLinkage, rep.BadLinkage)
	if len(parseErrs) > 0 {
		fmt.Fprintf(stdout, "Parse errors: %d (lines skipped)\n", len(parseErrs))
		for _, e := range parseErrs {
			fmt.Fprintln(stdout, "  -", e)
		}
	}
	if len(rep.Errors) > 0 {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Verification errors:")
		for _, e := range rep.Errors {
			fmt.Fprintf(stdout, "  row %d (id=%s) %s: %s\n",
				e.RowIndex, e.RowID, e.Field, e.Reason)
		}
		// Use the cobra Cmd.Errorf trick to surface a non-zero
		// exit without printing usage. SilenceUsage is set on the
		// root cmd already.
		return errors.New("verification failed (see errors above)")
	}
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "OK: chain is intact + every row_hash recomputes cleanly")
	return nil
}

// parseJSONL handles both newline-delimited JSON (one row per line)
// and JSON-array form ({rows: [...]} or top-level array). Skips
// blank lines + JSON parse failures (reports them in parseErrs).
func parseJSONL(r io.Reader) ([]merkle.AuditRow, []string, error) {
	// Sniff first non-whitespace byte to pick the format. If it's
	// '[' or '{' we assume JSON-array; otherwise JSONL.
	buf := bufio.NewReader(r)
	var firstByte byte
	for {
		b, err := buf.ReadByte()
		if err == io.EOF {
			return nil, nil, errors.New("input is empty")
		}
		if err != nil {
			return nil, nil, err
		}
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if err := buf.UnreadByte(); err != nil {
			return nil, nil, err
		}
		firstByte = b
		break
	}

	if firstByte == '[' || firstByte == '{' {
		// JSON-array form.
		all, err := io.ReadAll(buf)
		if err != nil {
			return nil, nil, err
		}
		// Two possible shapes: top-level [], or {"rows": [...]}.
		var asArr []merkle.AuditRow
		if json.Unmarshal(all, &asArr) == nil {
			return asArr, nil, nil
		}
		var wrap struct {
			Rows []merkle.AuditRow `json:"rows"`
		}
		if err := json.Unmarshal(all, &wrap); err != nil {
			return nil, nil, fmt.Errorf("parse json: %w", err)
		}
		return wrap.Rows, nil, nil
	}

	// JSONL.
	var rows []merkle.AuditRow
	var parseErrs []string
	sc := bufio.NewScanner(buf)
	// Audit-log metadata can be large; allow up to 1MB per line.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r merkle.AuditRow
		if err := json.Unmarshal(line, &r); err != nil {
			parseErrs = append(parseErrs,
				fmt.Sprintf("line %d: %v", lineNo, err))
			continue
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return rows, parseErrs, nil
}

func init() {
	auditCmd.AddCommand(auditAnchorsCmd, auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
