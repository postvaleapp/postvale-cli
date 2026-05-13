// Package main is the entry point for the Postvale CLI.
//
// All command logic lives in internal/commands; this file just wires
// the cobra root + handles os.Exit. Keeping main.go tiny makes it
// trivial to add alternative entry points later (postvale-server,
// postvale-mcp, etc.) without duplicating the command tree.
package main

import (
	"fmt"
	"os"

	"github.com/postvaleapp/postvale-cli/internal/commands"
)

func main() {
	if err := commands.NewRootCommand().Execute(); err != nil {
		// cobra already prints user-facing errors via its own
		// error-handling pipeline; we only land here for genuine
		// programmer errors / unhandled exits. Print to stderr +
		// exit 1 so CI pipelines see a failure.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
