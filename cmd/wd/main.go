// wd - the WireDepth CLI.
//
// Entry point. Wires the cobra root, hands off to subcommand
// packages. Build-time version metadata is injected via -ldflags
// in goreleaser.yaml.
package main

import (
	"fmt"
	"os"

	"github.com/WiredepthHQ/cli/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
