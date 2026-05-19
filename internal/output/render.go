// Human-readable rendering of check results.
//
// The webapp returns raw check-library structs (one shape per tool)
// so the renderer has to handle each tool's shape. Anything we
// don't have a custom renderer for falls back to pretty-printed
// JSON - operator can still read it, just less neatly.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderCheckResult renders the result of /api/v1/check/<tool>/<domain>
// to w in a human-readable form. Falls back to pretty-printed JSON
// when the tool doesn't have a custom renderer yet.
func RenderCheckResult(w io.Writer, tool, domain string, raw json.RawMessage) error {
	// Header.
	fmt.Fprintln(w, bold("> "+strings.ToLower(tool)+" check"))
	fmt.Fprintln(w, "  "+domain)
	fmt.Fprintln(w)

	switch strings.ToLower(tool) {
	case "check":
		return renderFull(w, raw)
	default:
		return renderPrettyJSON(w, raw)
	}
}

// renderFull handles the composite /check response with overall +
// per-tool grades. Shape:
//
//	{
//	  "overallGrade": "B+",
//	  "tools": [{ "tool": "tls", "grade": "A", "summary": "..." }, ...]
//	}
func renderFull(w io.Writer, raw json.RawMessage) error {
	var v struct {
		OverallGrade string `json:"overallGrade"`
		Tools        []struct {
			Tool    string `json:"tool"`
			Grade   string `json:"grade"`
			Summary string `json:"summary"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		// Shape didn't match; fall back to pretty JSON.
		return renderPrettyJSON(w, raw)
	}
	fmt.Fprintf(w, "  Overall: %s\n\n", v.OverallGrade)
	for _, t := range v.Tools {
		fmt.Fprintf(w, "    %-10s  %-3s  %s\n", t.Tool, t.Grade, t.Summary)
	}
	return nil
}

// renderPrettyJSON marshals to indented JSON. Used as the fallback
// for shapes we don't have a custom renderer for.
func renderPrettyJSON(w io.Writer, raw json.RawMessage) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Just dump bytes if we can't even parse.
		_, err = w.Write(raw)
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("  ", "  ")
	return enc.Encode(v)
}

// bold returns the string wrapped in ANSI bold escapes when stdout
// is a TTY. Best-effort - we don't try to be clever about detecting
// non-TTY pipes here; the duplicate escape chars in a pipe are
// readable enough.
func bold(s string) string {
	return "\033[1m" + s + "\033[0m"
}
