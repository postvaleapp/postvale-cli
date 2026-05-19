package merkle

import (
	"encoding/json"
	"testing"
)

// Canonical-JSON encoder parity tests. Every test case mirrors the
// behaviour of the browser verifier at src/app/verify/verify-client.tsx
// in the webapp repo - if the Go encoder diverges from the JS encoder
// on ANY input, the row-hash recomputation will fail + customers
// won't be able to verify their export. These tests are the safety
// net for that contract.
func TestCanonicalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"null", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"empty-string", "", `""`},
		{"basic-string", "hello", `"hello"`},
		{"string-with-quote", "he said \"hi\"", `"he said \"hi\""`},
		{"string-with-backslash", "a\\b", `"a\\b"`},
		{"string-with-newline", "line1\nline2", `"line1\nline2"`},
		{"integer", float64(42), `42`},
		{"negative-integer", float64(-17), `-17`},
		{"empty-array", []any{}, `[]`},
		{"single-array", []any{float64(1)}, `[1]`},
		{"mixed-array", []any{float64(1), "two", true, nil}, `[1,"two",true,null]`},
		{"empty-object", map[string]any{}, `{}`},
		{
			name: "single-object",
			input: map[string]any{
				"k": "v",
			},
			want: `{"k":"v"}`,
		},
		{
			// Keys MUST be sorted ascending - this is the
			// load-bearing contract for row-hash parity with the
			// browser verifier. If this test fails, every audit-log
			// export will fail to verify regardless of correctness.
			name: "object-keys-sorted-ascending",
			input: map[string]any{
				"zebra": float64(1),
				"alpha": float64(2),
				"mike":  float64(3),
			},
			want: `{"alpha":2,"mike":3,"zebra":1}`,
		},
		{
			name: "nested-object",
			input: map[string]any{
				"outer": map[string]any{
					"b": float64(2),
					"a": float64(1),
				},
				"flag": true,
			},
			want: `{"flag":true,"outer":{"a":1,"b":2}}`,
		},
		{
			// The audit-row canonical-form. Mirrors the exact payload
			// shape that computeRowHash in verify-client.tsx produces.
			name: "audit-row-payload-shape",
			input: map[string]any{
				"action":     "finding.acknowledge",
				"created_at": "2026-05-19T12:00:00.000Z",
				"ip":         "203.0.113.5",
				"metadata":   nil,
				"prev_hash":  "abc123",
				"resource":   "finding=xyz",
				"user_agent": "Mozilla/5.0",
				"user_id":    "uuid-here",
			},
			want: `{"action":"finding.acknowledge","created_at":"2026-05-19T12:00:00.000Z","ip":"203.0.113.5","metadata":null,"prev_hash":"abc123","resource":"finding=xyz","user_agent":"Mozilla/5.0","user_id":"uuid-here"}`,
		},
		{
			// Numeric metadata - the browser encodes float64 from JSON.parse;
			// our encoder must match.
			name: "metadata-with-numbers",
			input: map[string]any{
				"count":   float64(42),
				"enabled": true,
			},
			want: `{"count":42,"enabled":true}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalJSON(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("canonical:\n  got  %s\n  want %s", got, tc.want)
			}
		})
	}
}

// Round-trip via json.Unmarshal -> CanonicalJSON. Catches drift in
// how json.Unmarshal types intermediate values (it picks float64 for
// numbers + map[string]any for objects) - our encoder has to handle
// those concrete types.
func TestCanonicalJSON_RoundTrip(t *testing.T) {
	rows := []string{
		`{"action":"login","ip":"1.2.3.4","metadata":{"foo":1,"bar":[1,2,3]}}`,
		`{"action":"x","metadata":null,"user_id":"u1"}`,
		`{"nested":{"deep":{"deeper":{"deepest":true}}}}`,
		`[1,2,3,4]`,
	}
	for i, row := range rows {
		t.Run("row-"+string(rune('a'+i)), func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(row), &v); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			_, err := CanonicalJSON(v)
			if err != nil {
				t.Errorf("canonical failed: %v", err)
			}
		})
	}
}
