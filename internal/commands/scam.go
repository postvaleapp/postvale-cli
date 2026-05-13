package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newScamCommand() *cobra.Command {
	var filePath string
	cmd := &cobra.Command{
		Use:   "scam",
		Short: "Scam Check - verdict + reasons for a suspicious email",
		Long: `Run the Scam Check verdict against a raw email. Pipe the .eml
content via stdin, or pass --file:

  postvale scam < suspicious.eml
  postvale scam --file suspicious.eml

The verdict is one of: likely-safe, suspicious, likely-scam. With
--exit-on-fail the CLI exits 1 for anything other than likely-safe.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readEmailInput(cmd.InOrStdin(), filePath)
			if err != nil {
				return err
			}
			if len(raw) == 0 {
				return fmt.Errorf("no email content provided (pipe via stdin or --file)")
			}

			client, err := newClient()
			if err != nil {
				return err
			}
			configureOutput(cmd.OutOrStdout())

			result, err := client.ScamCheck(string(raw))
			if err != nil {
				return fmt.Errorf("scam check: %w", err)
			}

			g := Globals()
			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), result)
			}
			if g.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n", result.Verdict, result.Confidence)
			} else {
				output.RenderScamCheck(cmd.OutOrStdout(), result)
			}

			if g.ExitOnFail && result.Verdict != "likely-safe" {
				failExit()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "Read email from this file (default: stdin)")
	return cmd
}

func readEmailInput(stdin io.Reader, filePath string) ([]byte, error) {
	if filePath != "" {
		return os.ReadFile(filePath)
	}
	return io.ReadAll(stdin)
}
