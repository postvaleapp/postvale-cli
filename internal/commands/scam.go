package commands

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/output"
)

// 10 MiB ceiling on the email blob sent to the API.
const maxEmailBytes = 10 << 20

func newScamCommand() *cobra.Command {
	var filePath string
	cmd := &cobra.Command{
		Use:   "scam",
		Short: "Scam Check - verdict + reasons for a suspicious email",
		Long: `Run Scam Check against a raw email. Pipe the .eml via stdin
or pass --file:

  postvale scam < suspicious.eml
  postvale scam --file suspicious.eml

Verdict is one of: likely-safe, suspicious, likely-scam. With
--exit-on-fail the CLI exits 1 for anything other than likely-safe.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readEmailInput(cmd.InOrStdin(), filePath)
			if err != nil {
				return err
			}
			if len(raw) == 0 {
				return errors.New("no email content provided (pipe via stdin or --file)")
			}
			if len(raw) > maxEmailBytes {
				return fmt.Errorf("email exceeds %d-byte limit", maxEmailBytes)
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
		info, err := os.Stat(filePath)
		if err != nil {
			return nil, err
		}
		if info.Size() > maxEmailBytes {
			return nil, fmt.Errorf("file exceeds %d-byte limit", maxEmailBytes)
		}
		return os.ReadFile(filePath)
	}
	return io.ReadAll(io.LimitReader(stdin, maxEmailBytes+1))
}
