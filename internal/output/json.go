package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// EmitJSON writes v as pretty-printed JSON to w. Used by every
// command when --json is set.
func EmitJSON(w io.Writer, v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	_, err = fmt.Fprintln(w, string(buf))
	return err
}
