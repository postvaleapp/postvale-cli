// Audit-log chain + Merkle inclusion verification.
//
// Mirrors the canonical-JSON + sha256 + Merkle algorithm at
// wiredepth.com/docs/verify - ported from the browser verifier at
// src/app/verify/verify-client.tsx (TypeScript Web Crypto) to Go's
// crypto/sha256.
//
// The verification produces a structured report (errors per row +
// per inclusion-proof step) so callers can decide whether a single
// bad row aborts or just gets flagged.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// AuditRow is the JSONL shape exported by /api/v1/audit/export.
type AuditRow struct {
	ID           string          `json:"id"`
	UserID       string          `json:"user_id"`
	Action       string          `json:"action"`
	Resource     string          `json:"resource"`
	Metadata     json.RawMessage `json:"metadata"`
	IP           string          `json:"ip"`
	UserAgent    string          `json:"user_agent"`
	CreatedAt    string          `json:"created_at"`
	PrevHash     *string         `json:"prev_hash"`
	RowHash      string          `json:"row_hash"`
	UserPrevHash *string         `json:"user_prev_hash,omitempty"`
	UserRowHash  *string         `json:"user_row_hash,omitempty"`
}

// VerifyReport is the structured verifier output. Errors list is
// the source of truth - empty means every row chained cleanly + the
// linkage held end-to-end.
type VerifyReport struct {
	Rows        int
	GoodRowHash int
	BadRowHash  int
	GoodLinkage int
	BadLinkage  int
	Errors      []VerifyError
}

// VerifyError records a per-row verification failure.
type VerifyError struct {
	RowIndex int
	RowID    string
	Field    string
	Reason   string
}

// VerifyChain walks the audit-log rows in order; each row must (a)
// link to the previous row's row_hash via prev_hash, and (b)
// re-canonicalise + sha256 to the declared row_hash.
//
// We don't abort on the first error - verifier UX is better when
// you can see EVERY problem in one pass instead of fix-and-retry.
func VerifyChain(rows []AuditRow) VerifyReport {
	rep := VerifyReport{Rows: len(rows)}
	var lastRowHash string
	for i, r := range rows {
		// Linkage check skipped for the first row (no previous
		// hash to compare against) + when prev_hash is null (which
		// is the v1-chain header row).
		if i > 0 && lastRowHash != "" {
			declared := ""
			if r.PrevHash != nil {
				declared = *r.PrevHash
			}
			if declared != lastRowHash {
				rep.BadLinkage++
				rep.Errors = append(rep.Errors, VerifyError{
					RowIndex: i,
					RowID:    r.ID,
					Field:    "prev_hash linkage",
					Reason: fmt.Sprintf(
						"declared %q, expected previous row_hash %q",
						declared, lastRowHash,
					),
				})
			} else {
				rep.GoodLinkage++
			}
		}

		computed, err := computeRowHash(r)
		if err != nil {
			rep.BadRowHash++
			rep.Errors = append(rep.Errors, VerifyError{
				RowIndex: i,
				RowID:    r.ID,
				Field:    "row_hash",
				Reason:   "canonicalisation failed: " + err.Error(),
			})
		} else if computed != r.RowHash {
			rep.BadRowHash++
			rep.Errors = append(rep.Errors, VerifyError{
				RowIndex: i,
				RowID:    r.ID,
				Field:    "row_hash",
				Reason: fmt.Sprintf(
					"declared %q, recomputed %q", r.RowHash, computed,
				),
			})
		} else {
			rep.GoodRowHash++
		}

		lastRowHash = r.RowHash
	}
	return rep
}

func computeRowHash(r AuditRow) (string, error) {
	// Canonicalisation rule: object with keys sorted lex
	// ascending - {action, created_at, ip, metadata, prev_hash,
	// resource, user_agent, user_id}. Metadata stays as the raw
	// JSON value (we parse it back into any to canonicalise).
	var meta any
	if len(r.Metadata) > 0 {
		if err := json.Unmarshal(r.Metadata, &meta); err != nil {
			return "", err
		}
	}
	prevHash := any(nil)
	if r.PrevHash != nil {
		prevHash = *r.PrevHash
	}
	payload := map[string]any{
		"action":     r.Action,
		"created_at": r.CreatedAt,
		"ip":         r.IP,
		"metadata":   meta,
		"prev_hash":  prevHash,
		"resource":   r.Resource,
		"user_agent": r.UserAgent,
		"user_id":    r.UserID,
	}
	canon, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

// -----------------------------------------------------------------------------
// Merkle inclusion-proof verification
// -----------------------------------------------------------------------------

// InclusionProof is the per-leaf proof payload emitted by the
// webapp's audit-merkle module.
type InclusionProof struct {
	Leaf string          `json:"leaf"`
	Path []InclusionStep `json:"path"`
}

// InclusionStep is one (sibling_hash, side) pair in an inclusion
// proof. Side 'L' means the sibling sits on the LEFT of the
// accumulator; 'R' means it sits on the RIGHT.
type InclusionStep struct {
	Hash string `json:"hash"`
	Side string `json:"side"`
}

// VerifyInclusion walks the inclusion proof + returns the computed
// root hex. Compare against the published anchor to confirm.
func VerifyInclusion(proof InclusionProof) (string, error) {
	acc, err := hex.DecodeString(proof.Leaf)
	if err != nil {
		return "", fmt.Errorf("invalid leaf hex: %w", err)
	}
	if len(acc) != 32 {
		return "", errors.New("leaf must be 32 bytes (sha256)")
	}
	for i, step := range proof.Path {
		sib, err := hex.DecodeString(step.Hash)
		if err != nil {
			return "", fmt.Errorf("step %d: invalid sibling hex: %w", i, err)
		}
		if len(sib) != 32 {
			return "", fmt.Errorf("step %d: sibling must be 32 bytes", i)
		}
		var concat [64]byte
		switch step.Side {
		case "L":
			copy(concat[:32], sib)
			copy(concat[32:], acc)
		case "R":
			copy(concat[:32], acc)
			copy(concat[32:], sib)
		default:
			return "", fmt.Errorf("step %d: invalid side %q (want L or R)", i, step.Side)
		}
		sum := sha256.Sum256(concat[:])
		acc = sum[:]
	}
	return hex.EncodeToString(acc), nil
}
