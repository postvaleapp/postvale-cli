package commands

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/auth"
)

// `postvale audit` is the local-verification toolkit for the audit-log
// Merkle chain documented at https://postvale.app/docs/verify. Two
// subcommands today: `export` pulls the caller's chain segment, and
// `verify` re-hashes a JSONL file (no Postvale account required to
// run verify; the algorithm is public).

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Export + verify the audit-log Merkle chain",
	}
	cmd.AddCommand(newAuditExportCommand())
	cmd.AddCommand(newAuditVerifyCommand())
	return cmd
}

func newAuditExportCommand() *cobra.Command {
	var (
		outPath string
		scope   string
		since   string
		format  string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Download your audit chain segment (JSONL)",
		Long: `Fetches /api/v1/audit/export and writes the response to stdout
or to a file.

  --scope:   'mine' (default) or 'all' (admin-only).
  --since:   ISO-8601 timestamp; only rows on or after this.
  --format:  'jsonl' (default) or 'json' (envelope with metadata).
  --out:     File path to write to. Defaults to stdout.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := auth.Load(); err != nil && Globals().Token == "" {
				if errors.Is(err, auth.ErrNotLoggedIn) {
					return fmt.Errorf("not signed in - run `postvale auth login` first")
				}
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}

			path := "/api/v1/audit/export"
			q := url.Values{}
			if scope != "" {
				q.Set("scope", scope)
			}
			if since != "" {
				q.Set("since", since)
			}
			if format != "" {
				q.Set("format", format)
			}
			if enc := q.Encode(); enc != "" {
				path += "?" + enc
			}

			var w io.Writer = os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("open %s: %w", outPath, err)
				}
				defer f.Close()
				w = f
			}
			if err := client.GetStream(path, w); err != nil {
				return fmt.Errorf("audit export: %w", err)
			}
			if outPath != "" && !Globals().Quiet {
				fmt.Fprintf(os.Stderr, "Wrote %s\n", outPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "File to write to (default stdout)")
	cmd.Flags().StringVar(&scope, "scope", "mine", "mine | all")
	cmd.Flags().StringVar(&since, "since", "", "ISO-8601 lower bound")
	cmd.Flags().StringVar(&format, "format", "jsonl", "jsonl | json")
	return cmd
}

func newAuditVerifyCommand() *cobra.Command {
	var (
		anchorHead string
		merkleRoot string
		proofPath  string
		fetchLive  bool
	)
	cmd := &cobra.Command{
		Use:   "verify <file.jsonl>",
		Short: "Re-compute the Merkle chain on a local export",
		Long: `Verifies a local audit-chain export against the published spec
at https://postvale.app/docs/verify. No Postvale account required.

  postvale audit verify chain.jsonl
  postvale audit verify chain.jsonl --anchor <hex>
  postvale audit verify chain.jsonl --fetch-anchor
  postvale audit verify chain.jsonl --merkle-root <hex> --inclusion-proof proof.json

The verifier:
  1. Parses the file as JSONL (or a JSON array).
  2. Re-computes each row's global + per-user sha256 chain and
     compares to the stored row_hash / user_row_hash.
  3. Asserts prev_hash linkage on both chains.
  4. Optionally compares the global head to a known anchor head
     (--anchor) or the live head (--fetch-anchor).
  5. Optionally walks a v3 Merkle inclusion proof and confirms it
     reconstructs to the supplied --merkle-root.

Exit code 0 on PASS, 1 on FAIL. Use --json to get machine output.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rows, err := loadAuditRows(args[0])
			if err != nil {
				return err
			}

			var anchor string
			if fetchLive {
				client, err := newClient()
				if err != nil {
					return err
				}
				live, err := client.LiveAnchorHead()
				if err != nil {
					return fmt.Errorf("fetch live anchor: %w", err)
				}
				anchor = live
			} else if anchorHead != "" {
				anchor = strings.TrimSpace(anchorHead)
			}

			var merkleProof *merkleInclusionProof
			if proofPath != "" {
				p, err := loadInclusionProof(proofPath)
				if err != nil {
					return fmt.Errorf("inclusion proof: %w", err)
				}
				merkleProof = p
			}

			res := verifyChain(rows, anchor)
			if merkleProof != nil && merkleRoot != "" {
				ok, computed := verifyMerkleInclusion(*merkleProof, strings.TrimSpace(merkleRoot))
				res.MerkleInclusion = &merkleInclusionResult{
					OK:           ok,
					ComputedRoot: computed,
					ExpectedRoot: strings.TrimSpace(merkleRoot),
				}
				if !ok {
					res.OK = false
				}
			}

			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(res)
			}
			printVerifyResult(res)
			if !res.OK {
				return errors.New("verification failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&anchorHead, "anchor", "", "Expected anchor head hash")
	cmd.Flags().BoolVar(&fetchLive, "fetch-anchor", false, "Fetch live head from /api/v1/audit/anchors")
	cmd.Flags().StringVar(&merkleRoot, "merkle-root", "", "Expected v3 Merkle root (hex)")
	cmd.Flags().StringVar(&proofPath, "inclusion-proof", "", "Path to JSON inclusion proof for the per-user head")
	return cmd
}

type merkleInclusionProof struct {
	Leaf string `json:"leaf"`
	Path []struct {
		Hash string `json:"hash"`
		Side string `json:"side"`
	} `json:"path"`
}

type merkleInclusionResult struct {
	OK           bool   `json:"ok"`
	ComputedRoot string `json:"computedRoot"`
	ExpectedRoot string `json:"expectedRoot"`
}

func loadInclusionProof(path string) (*merkleInclusionProof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p merkleInclusionProof
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse proof JSON: %w", err)
	}
	return &p, nil
}

func verifyMerkleInclusion(p merkleInclusionProof, expectedRoot string) (bool, string) {
	acc, err := hex.DecodeString(p.Leaf)
	if err != nil {
		return false, ""
	}
	for _, step := range p.Path {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false, ""
		}
		var concat []byte
		if step.Side == "L" {
			concat = append(append([]byte{}, sib...), acc...)
		} else {
			concat = append(append([]byte{}, acc...), sib...)
		}
		sum := sha256.Sum256(concat)
		acc = sum[:]
	}
	computed := hex.EncodeToString(acc)
	return computed == expectedRoot, computed
}

// ----- chain math (mirrors src/lib/audit-chain.ts in the webapp) -----

type exportedRow struct {
	ID           int64                  `json:"id"`
	UserID       *string                `json:"user_id"`
	Action       string                 `json:"action"`
	Resource     *string                `json:"resource"`
	Metadata     map[string]interface{} `json:"metadata"`
	IP           *string                `json:"ip"`
	UserAgent    *string                `json:"user_agent"`
	CreatedAt    string                 `json:"created_at"`
	PrevHash     *string                `json:"prev_hash"`
	RowHash      string                 `json:"row_hash"`
	UserPrevHash *string                `json:"user_prev_hash,omitempty"`
	UserRowHash  *string                `json:"user_row_hash,omitempty"`
}

// canonicalJSON emits a deterministic JSON encoding: object keys sorted
// alphabetically, no whitespace, JSON strings escaped per encoding/json.
// Identical algorithm to the TypeScript reference at /docs/verify so
// this verifier matches the webapp + CLI implementations bit-for-bit.
func canonicalJSON(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case string:
		return mustJSON(val)
	case bool, float64, int, int64:
		return mustJSON(val)
	case []interface{}:
		parts := make([]string, len(val))
		for i, e := range val {
			parts[i] = canonicalJSON(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = mustJSON(k) + ":" + canonicalJSON(val[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		return mustJSON(val)
	}
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func ptrOrNil(p *string) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

func computeRowHash(row exportedRow, prevHash *string) string {
	var prev interface{}
	if prevHash != nil {
		prev = *prevHash
	}
	payload := canonicalJSON(map[string]interface{}{
		"action":     row.Action,
		"created_at": row.CreatedAt,
		"ip":         ptrOrNil(row.IP),
		"metadata":   asInterface(row.Metadata),
		"prev_hash":  prev,
		"resource":   ptrOrNil(row.Resource),
		"user_agent": ptrOrNil(row.UserAgent),
		"user_id":    ptrOrNil(row.UserID),
	})
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func asInterface(m map[string]interface{}) interface{} {
	if m == nil {
		return nil
	}
	return map[string]interface{}(m)
}

// ----- file loading -----

func loadAuditRows(path string) ([]exportedRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Peek the first byte to decide JSON vs JSONL.
	br := bufio.NewReader(f)
	first, err := br.Peek(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(first) > 0 && (first[0] == '[' || first[0] == '{') {
		all, err := io.ReadAll(br)
		if err != nil {
			return nil, err
		}
		// Try array first, then { rows: [...] } envelope.
		var arr []exportedRow
		if json.Unmarshal(all, &arr) == nil && len(arr) > 0 {
			return arr, nil
		}
		var env struct {
			Rows []exportedRow `json:"rows"`
		}
		if json.Unmarshal(all, &env) == nil {
			return env.Rows, nil
		}
		return nil, errors.New("could not parse file as JSONL, JSON array, or {rows: []} envelope")
	}

	// JSONL.
	var out []exportedRow
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r exportedRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ----- verification -----

type verifyResult struct {
	OK            bool   `json:"ok"`
	RowsChecked   int    `json:"rowsChecked"`
	TotalRows     int    `json:"totalRows"`
	ChainHead     string `json:"chainHead"`
	AnchorMatch   string `json:"anchorMatch,omitempty"`
	FirstMismatch *struct {
		RowID    int64  `json:"rowId"`
		Field    string `json:"field,omitempty"`
		Declared string `json:"declared"`
		Computed string `json:"computed"`
	} `json:"firstMismatch,omitempty"`
	PerUser         []perUserChainResult   `json:"perUser,omitempty"`
	MerkleInclusion *merkleInclusionResult `json:"merkleInclusion,omitempty"`
	DurationMs      int64                  `json:"durationMs"`
}

type perUserChainResult struct {
	UserID             string `json:"userId"`
	RowsChecked        int    `json:"rowsChecked"`
	OK                 bool   `json:"ok"`
	Head               string `json:"head,omitempty"`
	FirstMismatchRowID int64  `json:"firstMismatchRowId,omitempty"`
}

func verifyChain(rows []exportedRow, anchorHead string) verifyResult {
	start := time.Now()
	res := verifyResult{TotalRows: len(rows)}
	if len(rows) == 0 {
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	var lastHash string
	for i, r := range rows {
		if i > 0 && r.PrevHash != nil && *r.PrevHash != lastHash {
			res.FirstMismatch = &struct {
				RowID    int64  `json:"rowId"`
				Field    string `json:"field,omitempty"`
				Declared string `json:"declared"`
				Computed string `json:"computed"`
			}{
				RowID:    r.ID,
				Field:    "prev_hash linkage",
				Declared: *r.PrevHash,
				Computed: lastHash,
			}
			break
		}
		computed := computeRowHash(r, r.PrevHash)
		if computed != r.RowHash {
			res.FirstMismatch = &struct {
				RowID    int64  `json:"rowId"`
				Field    string `json:"field,omitempty"`
				Declared string `json:"declared"`
				Computed string `json:"computed"`
			}{
				RowID:    r.ID,
				Declared: r.RowHash,
				Computed: computed,
			}
			break
		}
		lastHash = r.RowHash
		res.RowsChecked++
	}
	res.ChainHead = lastHash

	if anchorHead != "" {
		if lastHash == anchorHead {
			res.AnchorMatch = "match"
		} else {
			res.AnchorMatch = "mismatch"
		}
	}

	// v2 per-user chain check. One entry per user_id appearing in the
	// export. Rows without user_row_hash are skipped (anonymous or
	// pre-v2 events).
	perUser := map[string]*perUserChainResult{}
	for _, r := range rows {
		if r.UserID == nil || r.UserRowHash == nil {
			continue
		}
		uid := *r.UserID
		st := perUser[uid]
		if st == nil {
			st = &perUserChainResult{UserID: uid, OK: true}
			perUser[uid] = st
		}
		if !st.OK {
			continue
		}
		var prevHashStr string
		if r.UserPrevHash != nil {
			prevHashStr = *r.UserPrevHash
		}
		if st.Head != "" && prevHashStr != st.Head {
			st.OK = false
			st.FirstMismatchRowID = r.ID
			continue
		}
		computed := computeRowHash(r, r.UserPrevHash)
		if computed != *r.UserRowHash {
			st.OK = false
			st.FirstMismatchRowID = r.ID
			continue
		}
		st.Head = *r.UserRowHash
		st.RowsChecked++
	}
	perUserOK := true
	for _, st := range perUser {
		res.PerUser = append(res.PerUser, *st)
		if !st.OK {
			perUserOK = false
		}
	}

	res.OK = res.FirstMismatch == nil &&
		(anchorHead == "" || res.AnchorMatch == "match") &&
		perUserOK
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func printVerifyResult(r verifyResult) {
	if r.OK {
		fmt.Println("\n  \033[32m✓ PASS\033[0m")
	} else {
		fmt.Println("\n  \033[31m✗ FAIL\033[0m")
	}
	fmt.Printf("  %d of %d rows checked in %dms\n", r.RowsChecked, r.TotalRows, r.DurationMs)
	if r.ChainHead != "" {
		fmt.Printf("  computed head:  %s\n", r.ChainHead)
	}
	if r.AnchorMatch != "" {
		if r.AnchorMatch == "match" {
			fmt.Println("  anchor match:   \033[32m✓ matches supplied anchor\033[0m")
		} else {
			fmt.Println("  anchor match:   \033[31m✗ differs from supplied anchor\033[0m")
		}
	}
	if r.FirstMismatch != nil {
		fmt.Printf("\n  first mismatch on row %d", r.FirstMismatch.RowID)
		if r.FirstMismatch.Field != "" {
			fmt.Printf(" (%s)", r.FirstMismatch.Field)
		}
		fmt.Println()
		fmt.Printf("    declared: %s\n", r.FirstMismatch.Declared)
		fmt.Printf("    computed: %s\n", r.FirstMismatch.Computed)
	}
	if len(r.PerUser) > 0 {
		fmt.Println("\n  per-user chains:")
		for _, u := range r.PerUser {
			status := "\033[32m✓\033[0m"
			if !u.OK {
				status = "\033[31m✗\033[0m"
			}
			uid := u.UserID
			if len(uid) > 8 {
				uid = uid[:8] + "…"
			}
			fmt.Printf("    %s  user %-12s  %d rows", status, uid, u.RowsChecked)
			if u.FirstMismatchRowID > 0 {
				fmt.Printf("  (mismatch at row %d)", u.FirstMismatchRowID)
			}
			fmt.Println()
		}
	}
	if r.MerkleInclusion != nil {
		fmt.Println()
		if r.MerkleInclusion.OK {
			fmt.Println("  \033[32m✓\033[0m Merkle inclusion proof reconstructs to the expected root")
		} else {
			fmt.Println("  \033[31m✗\033[0m Merkle inclusion proof did NOT match the expected root")
			fmt.Printf("    computed: %s\n", r.MerkleInclusion.ComputedRoot)
			fmt.Printf("    expected: %s\n", r.MerkleInclusion.ExpectedRoot)
		}
	}
	fmt.Println()
}
