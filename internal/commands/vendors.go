package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// `wd vendors <domain>` - third-party email-sender inventory
// derived from SPF includes + DKIM selectors + MX + DMARC ruf
// addresses. Same data the vendor workpaper renders against.

func newVendorsCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "vendors <domain>",
		Aliases: []string{"vendor", "vendor-consolidation"},
		Short:   "Third-party email sender inventory for a domain",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, err := normaliseDomain(args[0])
			if err != nil {
				return err
			}
			client, err := newClient()
			if err != nil {
				return err
			}

			var result map[string]interface{}
			if err := client.CheckGeneric("vendor-consolidation", domain, &result); err != nil {
				return fmt.Errorf("vendors %s: %w", domain, err)
			}

			if Globals().JSON {
				return json.NewEncoder(os.Stdout).Encode(result)
			}
			// Pretty output: count, then per-vendor lines.
			vendors, _ := result["vendors"].([]interface{})
			fmt.Printf("Vendors authorised to send mail as %s: %d\n\n", domain, len(vendors))
			for _, v := range vendors {
				m, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				name, _ := m["vendor"].(string)
				channel, _ := m["channel"].(string)
				canSend, _ := m["canSendAs"].(bool)
				flag := "·"
				if canSend {
					flag = "✓"
				}
				fmt.Printf("  %s  %-30s  %s\n", flag, truncateStr(name, 30), channel)
			}
			return nil
		},
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
