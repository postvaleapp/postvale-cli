// `wd config` verb group - local CLI configuration. v2.1 ships
// the read-only shape (config show); full mutations land in v2.2
// alongside the proper config-file persistence.
package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/auth"
	"github.com/WiredepthHQ/cli/internal/output"
)

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Local CLI configuration",
		Long: `Show the active configuration (API base, default
output format, stored credential location, environment-variable
overrides). v2.2 will add the writable shape: wd config set
<key> <value>.`,
	}
	cmd.AddCommand(newConfigShowCommand())
	cmd.AddCommand(newConfigPathCommand())
	return cmd
}

func newConfigShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the resolved configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			g := Globals()
			configureOutput(cmd.OutOrStdout())
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s WD CLI CONFIG\n\n", output.StyleDim.Render(">_"))

			rows := []struct {
				key, val string
			}{
				{"api-base", g.APIBase},
				{"json-output", boolStr(g.JSON)},
				{"quiet", boolStr(g.Quiet)},
				{"no-color", boolStr(g.NoColor)},
				{"timeout-sec", fmt.Sprintf("%d", g.Timeout)},
				{"credential", auth.StorageLocation()},
				{"env override", envOverrideSnapshot()},
				{"config dir", configDirPath()},
			}
			for _, r := range rows {
				fmt.Fprintf(w, "  %s %s\n",
					output.StyleDim.Render(padRight(r.key, 14)),
					r.val,
				)
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, output.StyleDim.Render(
				"v2.2 adds: wd config set <key>=<value> for persistent mutations.",
			))
			return nil
		},
	}
}

func newConfigPathCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the config-dir path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), configDirPath())
			return nil
		},
	}
}

func envOverrideSnapshot() string {
	parts := []string{}
	for _, name := range []string{
		"WIREDEPTH_API",
		"WIREDEPTH_TOKEN",
		"POSTVALE_API",
		"POSTVALE_TOKEN",
		"NO_COLOR",
	} {
		if v := os.Getenv(name); v != "" {
			marker := name
			if name == "POSTVALE_API" || name == "POSTVALE_TOKEN" {
				marker += " (legacy)"
			}
			parts = append(parts, marker)
		}
	}
	if len(parts) == 0 {
		return "(none set)"
	}
	return strings.Join(parts, ", ")
}

func configDirPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return "(unavailable)"
	}
	return filepath.Join(base, "wiredepth")
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
