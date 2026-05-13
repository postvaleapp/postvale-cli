// Postvale CLI entry point. All command logic lives in
// internal/commands.
package main

import (
	"fmt"
	"os"

	"github.com/postvaleapp/postvale-cli/internal/commands"
)

func main() {
	if err := commands.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
