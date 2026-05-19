// Canonical JSON encoder matching the WireDepth audit-chain spec at
// wiredepth.com/docs/verify.
//
// Rules (frozen - changing breaks every existing chain row):
//
//  1. Object keys sorted ascending by codepoint (UTF-16, matching
//     JavaScript's default Array.prototype.sort) - which for
//     ASCII keys is identical to byte-ascending order.
//  2. Strings JSON-escape standard but with no extra spaces.
//  3. Numbers: JSON number form (no trailing .0 for integers in
//     JS; we never store floats in audit_log values).
//  4. null is the literal "null".
//  5. Arrays preserve element order.
//  6. No top-level whitespace; comma + colon separators only.
//
// This is what's hashed to produce row_hash on every audit_log row.
// A verifier that disagrees on canonicalisation cannot reproduce
// the chain at all.
package merkle

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// CanonicalJSON encodes v according to the WireDepth canonical JSON
// rules. Returns ErrCanonical when v contains a type that JSON can't
// represent (channels, funcs, etc.).
func CanonicalJSON(v any) (string, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ErrCanonical is returned when canonicalisation fails (unsupported
// value type in input).
var ErrCanonical = errors.New("value not representable in canonical JSON")

func writeCanonical(sb *strings.Builder, v any) error {
	if v == nil {
		sb.WriteString("null")
		return nil
	}
	switch x := v.(type) {
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
		return nil
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		sb.Write(b)
		return nil
	case float64:
		// Numbers come from json.Unmarshal as float64; emit using
		// json.Marshal so the formatting matches JS's default
		// Number.toString (no trailing .0 on integers; scientific
		// notation only when JS would use it).
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		sb.Write(b)
		return nil
	case json.Number:
		sb.WriteString(string(x))
		return nil
	case []any:
		sb.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Lexicographic sort on the key strings. UTF-16 ordering
		// equals byte-ascending for ASCII; mixed-script keys would
		// diverge in theory but WireDepth's audit-log keys are all
		// ASCII identifiers.
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			sb.Write(kb)
			sb.WriteByte(':')
			if err := writeCanonical(sb, x[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
		return nil
	}
	return ErrCanonical
}
