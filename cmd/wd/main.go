// wd - WireDepth CLI entry point. Command logic lives in
// internal/commands.
package main

import (
	"fmt"
	"os"

	"github.com/WiredepthHQ/wiredepth-cli/internal/commands"
)

func main() {
	if err := commands.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
