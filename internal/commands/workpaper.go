package commands

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

// Allowed workpaper types. Mirrors the webapp's WORKPAPER_REFS map
// so a typo returns a clean error rather than a 400 from the server.
var workpaperTypes = map[string]bool{
	"email-auth": true,
	"tls":        true,
	"vendor":     true,
	"dns":        true,
	"incident":   true,
}

func newWorkpaperCommand() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "workpaper <type> <domain>",
		Short: "Download an audit workpaper PDF",
		Long: `Download a workpaper PDF for the given control area + domain.

  type:   email-auth | tls | vendor | dns | incident
  domain: any public domain

By default the PDF streams to stdout. Pass --out to write to a
file instead (recommended unless piping into a viewer).

  postvale workpaper email-auth acme.com --out wp-email-auth.pdf
  postvale workpaper tls acme.com > wp-tls.pdf`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tool := strings.ToLower(strings.TrimSpace(args[0]))
			if !workpaperTypes[tool] {
				return fmt.Errorf("unknown workpaper type %q (allowed: email-auth, tls, vendor, dns, incident)", args[0])
			}
			domain, err := normaliseDomain(args[1])
			if err != nil {
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			path := fmt.Sprintf("/api/workpapers/%s/%s?dl=1",
				url.PathEscape(tool),
				url.PathEscape(domain),
			)

			var w *os.File = os.Stdout
			if outPath != "" {
				f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
				if err != nil {
					return fmt.Errorf("open %s: %w", outPath, err)
				}
				defer f.Close()
				w = f
			}

			if err := client.GetStream(path, w); err != nil {
				return fmt.Errorf("workpaper: %w", err)
			}

			if outPath != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s wrote %s\n",
					output.StyleOK.Render("✓"),
					output.StyleStrong.Render(outPath),
				)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Write PDF to this path (default: stdout)")
	return cmd
}
