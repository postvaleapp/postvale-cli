package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// computeRowHash parity test. Uses a hand-crafted audit row + the
// canonical-form payload + sha256 to derive the expected hash, then
// confirms VerifyChain accepts it.
func TestVerifyChain_SingleValidRow(t *testing.T) {
	// Compute expected row_hash manually so the test is self-
	// contained (no fixture file needed).
	canonical := `{"action":"x","created_at":"2026-01-01T00:00:00Z","ip":"","metadata":null,"prev_hash":null,"resource":"","user_agent":"","user_id":"u1"}`
	sum := sha256.Sum256([]byte(canonical))
	expectedHash := hex.EncodeToString(sum[:])

	row := AuditRow{
		ID:        "row-1",
		UserID:    "u1",
		Action:    "x",
		CreatedAt: "2026-01-01T00:00:00Z",
		PrevHash:  nil,
		RowHash:   expectedHash,
	}

	rep := VerifyChain([]AuditRow{row})
	if rep.BadRowHash != 0 {
		t.Errorf("expected 0 bad row hashes, got %d (errors: %+v)",
			rep.BadRowHash, rep.Errors)
	}
	if rep.GoodRowHash != 1 {
		t.Errorf("expected 1 good row hash, got %d", rep.GoodRowHash)
	}
}

// Detects a tampered row_hash. If we flip one bit of the declared
// row_hash, VerifyChain must catch it.
func TestVerifyChain_BadRowHashDetected(t *testing.T) {
	row := AuditRow{
		ID:        "row-1",
		UserID:    "u1",
		Action:    "x",
		CreatedAt: "2026-01-01T00:00:00Z",
		RowHash:   "deadbeef",
	}
	rep := VerifyChain([]AuditRow{row})
	if rep.BadRowHash != 1 {
		t.Errorf("expected 1 bad row hash, got %d", rep.BadRowHash)
	}
}

// Linkage check: row N's prev_hash must equal row N-1's row_hash.
// If we break that link, VerifyChain must flag it.
func TestVerifyChain_BadLinkageDetected(t *testing.T) {
	// Two rows where row 2's prev_hash doesn't match row 1's
	// row_hash. We compute valid row_hashes for both (so the only
	// failure mode is linkage).
	r1Canonical := `{"action":"a","created_at":"t1","ip":"","metadata":null,"prev_hash":null,"resource":"","user_agent":"","user_id":"u1"}`
	r1Sum := sha256.Sum256([]byte(r1Canonical))
	r1Hash := hex.EncodeToString(r1Sum[:])

	wrongPrev := "wrong-prev-hash"
	r2Canonical := `{"action":"b","created_at":"t2","ip":"","metadata":null,"prev_hash":"` + wrongPrev + `","resource":"","user_agent":"","user_id":"u1"}`
	r2Sum := sha256.Sum256([]byte(r2Canonical))
	r2Hash := hex.EncodeToString(r2Sum[:])

	rows := []AuditRow{
		{
			ID: "r1", UserID: "u1", Action: "a", CreatedAt: "t1",
			RowHash: r1Hash,
		},
		{
			ID: "r2", UserID: "u1", Action: "b", CreatedAt: "t2",
			PrevHash: &wrongPrev, RowHash: r2Hash,
		},
	}
	rep := VerifyChain(rows)
	// row_hash for both rows recomputes cleanly (we made sure).
	// Only the linkage should fail.
	if rep.BadLinkage != 1 {
		t.Errorf("expected 1 bad linkage, got %d (errors: %+v)",
			rep.BadLinkage, rep.Errors)
	}
	if rep.BadRowHash != 0 {
		t.Errorf("expected 0 bad row hashes, got %d", rep.BadRowHash)
	}
}

// VerifyInclusion parity test. Build a tiny tree by hand + walk one
// leaf's inclusion proof; result should match the manually-computed
// root.
func TestVerifyInclusion_TwoLeaf(t *testing.T) {
	// Two leaves; tree height = 1; root = sha256(leftLeaf || rightLeaf).
	leftLeaf := hashHex("leaf-left")
	rightLeaf := hashHex("leaf-right")

	concat := make([]byte, 64)
	copy(concat[0:32], mustHex(leftLeaf))
	copy(concat[32:64], mustHex(rightLeaf))
	rootSum := sha256.Sum256(concat)
	expectedRoot := hex.EncodeToString(rootSum[:])

	// Inclusion proof for the LEFT leaf: sibling is rightLeaf on
	// the right side of the accumulator.
	proof := InclusionProof{
		Leaf: leftLeaf,
		Path: []InclusionStep{
			{Hash: rightLeaf, Side: "R"},
		},
	}
	got, err := VerifyInclusion(proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expectedRoot {
		t.Errorf("verify mismatch:\n  got  %s\n  want %s", got, expectedRoot)
	}

	// And the RIGHT leaf's proof: sibling is leftLeaf on the LEFT.
	proofR := InclusionProof{
		Leaf: rightLeaf,
		Path: []InclusionStep{
			{Hash: leftLeaf, Side: "L"},
		},
	}
	gotR, err := VerifyInclusion(proofR)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotR != expectedRoot {
		t.Errorf("right-leaf verify mismatch:\n  got  %s\n  want %s",
			gotR, expectedRoot)
	}
}

// Tampered proof step: if we flip a bit on the sibling hash, the
// computed root MUST diverge from the published root.
func TestVerifyInclusion_TamperedSiblingDetected(t *testing.T) {
	leftLeaf := hashHex("leaf-left")
	rightLeaf := hashHex("leaf-right")
	tamperedSibling := hashHex("DIFFERENT-tampered")

	concat := make([]byte, 64)
	copy(concat[0:32], mustHex(leftLeaf))
	copy(concat[32:64], mustHex(rightLeaf))
	realRootSum := sha256.Sum256(concat)
	realRoot := hex.EncodeToString(realRootSum[:])

	proof := InclusionProof{
		Leaf: leftLeaf,
		Path: []InclusionStep{
			{Hash: tamperedSibling, Side: "R"},
		},
	}
	got, err := VerifyInclusion(proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == realRoot {
		t.Errorf("tampered sibling unexpectedly produced the real root - the test setup is broken")
	}
}

// Bad-format inputs should error cleanly rather than panic.
func TestVerifyInclusion_BadInputs(t *testing.T) {
	tests := []struct {
		name  string
		proof InclusionProof
	}{
		{"non-hex-leaf", InclusionProof{Leaf: "not-hex", Path: nil}},
		{
			"short-leaf",
			InclusionProof{Leaf: "abcd", Path: nil},
		},
		{
			"bad-side",
			InclusionProof{
				Leaf: hashHex("x"),
				Path: []InclusionStep{{Hash: hashHex("y"), Side: "Z"}},
			},
		},
		{
			"non-hex-sibling",
			InclusionProof{
				Leaf: hashHex("x"),
				Path: []InclusionStep{{Hash: "not-hex", Side: "L"}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyInclusion(tc.proof)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// Helpers.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
