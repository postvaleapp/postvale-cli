package commands

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/wiredepth-cli/internal/auth"
)

// `postvale evidence-pack <framework> <domain>` - Prove-tier feature.
// Downloads /api/v1/evidence-pack/<framework>/<domain> as a ZIP of all
// five workpapers + a README. Server runs the checks live + renders
// the PDFs; no persistence.

func newEvidencePackCommand() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "evidence-pack <framework> <domain>",
		Short: "Download a Prove-tier evidence pack (all 5 workpapers + README, zipped)",
		Long: `Generates a single ZIP containing every workpaper PDF (email
auth, TLS, vendor inventory, DNS governance, incident readiness)
plus a README tagged to the supplied framework. Requires a
Postvale Prove subscription on the signed-in account (or
Enterprise, which bundles Prove).

  postvale evidence-pack osfi-b-13 acme.com -o pack.zip

Frameworks: any slug listed at https://wiredepth.com/compliance,
e.g. osfi-b-13, soc-2, pci-dss, hipaa-security-rule, iso-27001,
fedramp, irap, nis2, dora, sec-cybersecurity-disclosure,
nydfs-part-500, pipeda, quebec-law-25, ni-52-109, glba, stateramp,
cmmc, au-privacy-act, osfi-e-21, apra-cps-234, apra-cps-230.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			framework := args[0]
			domain, err := normaliseDomain(args[1])
			if err != nil {
				return err
			}
			if _, err := auth.Load(); err != nil && Globals().Token == "" {
				if errors.Is(err, auth.ErrNotLoggedIn) {
					return fmt.Errorf("not signed in - run `postvale auth login` first")
				}
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}

			path := "/api/v1/evidence-pack/" + url.PathEscape(framework) + "/" + url.PathEscape(domain)
			var w io.Writer = os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("open %s: %w", outPath, err)
				}
				defer f.Close()
				w = f
			}
			if err := client.GetStream(path, w); err != nil {
				return fmt.Errorf("evidence-pack: %w", err)
			}
			if outPath != "" && !Globals().Quiet {
				fmt.Fprintf(os.Stderr, "Wrote %s\n", outPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Path to write the ZIP (default stdout)")
	return cmd
}
