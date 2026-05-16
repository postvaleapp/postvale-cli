package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/output"
	"github.com/WiredepthHQ/cli/internal/probe"
	"github.com/WiredepthHQ/cli/internal/probe/checks"
	"github.com/WiredepthHQ/cli/internal/version"
)

func newProbeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Run a WireDepth on-prem scanning probe",
		Long: `Manage and run the WireDepth on-prem scanning probe. Drop the
binary inside your VPC, DMZ, or on-prem segment to extend the
outside-in coverage to assets the public internet can't see.

  postvale probe enroll    Save the install token issued by the dashboard
  postvale probe run       Foreground daemon: poll, scan, submit findings
  postvale probe status    Show the configured probe state
  postvale probe revoke    Forget the locally-stored token (local-only)

Posture / surface / misconfig only. No credentialed scans, no
exploit attempts, no endpoint agent. Use the dashboard at
` + "`/account/probes`" + ` to enrol + revoke from the server side.`,
	}
	cmd.AddCommand(newProbeEnrollCommand())
	cmd.AddCommand(newProbeRunCommand())
	cmd.AddCommand(newProbeStatusCommand())
	cmd.AddCommand(newProbeRevokeCommand())
	return cmd
}

func newProbeEnrollCommand() *cobra.Command {
	var fromStdin bool
	cmd := &cobra.Command{
		Use:   "enroll [token]",
		Short: "Save a probe install token issued by the dashboard",
		Long: `Save a probe install token issued by the dashboard.

Get a token from /account/probes on the WireDepth dashboard. The
token is shown exactly once; save it then. This command stores it
locally so ` + "`wd probe run`" + ` can pick it up.

Examples:
  postvale probe enroll wdp_abc_xxxxxxxx
  cat /secrets/probe.token | postvale probe enroll --stdin`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configureOutput(cmd.OutOrStdout())
			var token string
			switch {
			case fromStdin:
				data, err := readAllStdin(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
				token = strings.TrimSpace(data)
			case len(args) == 1:
				token = strings.TrimSpace(args[0])
			default:
				return errors.New("pass the token as an argument or via --stdin")
			}
			if token == "" {
				return errors.New("token is empty")
			}
			if !strings.HasPrefix(token, "wdp_") {
				return errors.New("token must start with `wdp_`")
			}
			if err := probe.SaveToken(token); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, output.StyleOK.Render("Probe token saved to "+probe.StorageLocation()))
			fmt.Fprintln(w, output.StyleDim.Render("Start the daemon with: postvale probe run"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "Read the token from stdin")
	return cmd
}

func newProbeRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the probe daemon in the foreground",
		Long: `Run the probe daemon in the foreground. Poll the WireDepth API
for pending work, run the allowed check kinds, and submit findings.

Long-lived process. Wrap in systemd / launchd / Windows Service for
production use. Reads the token from $WIREDEPTH_PROBE_TOKEN or the
config file written by ` + "`wd probe enroll`" + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g := Globals()
			token, err := probe.LoadToken()
			if err != nil {
				return err
			}
			client := probe.New(g.APIBase, token, version.Version)

			ctx, cancel := signal.NotifyContext(
				cmd.Context(),
				os.Interrupt, syscall.SIGTERM,
			)
			defer cancel()

			runners := map[string]probe.CheckFunc{
				"tls": func(ctx context.Context, target string, options map[string]interface{}) ([]probe.Finding, error) {
					return checks.TLS(ctx, target, probe.PortFromOptions(options))
				},
				// headers / port-scan / webapp-fingerprint land in
				// follow-up commits. The protocol + storage + cobra
				// shape are stable now; adding a check kind is one
				// implementation file + one map entry here.
			}

			return probe.Run(ctx, probe.RunnerOptions{
				Client:       client,
				Logger:       os.Stderr,
				CheckRunners: runners,
			})
		},
	}
	return cmd
}

func newProbeStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the probe's configured state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configureOutput(cmd.OutOrStdout())
			g := Globals()
			tok, loadErr := probe.LoadToken()
			location := probe.StorageLocation()
			w := cmd.OutOrStdout()

			if loadErr != nil {
				if g.JSON {
					return output.EmitJSON(w, map[string]interface{}{
						"configured": false,
						"location":   location,
					})
				}
				fmt.Fprintln(w, output.StyleDim.Render(
					"No probe token configured. Run: postvale probe enroll <token>",
				))
				return nil
			}
			masked := maskToken(tok)
			if g.JSON {
				prefix := tok
				if len(prefix) > 12 {
					prefix = prefix[:12]
				}
				return output.EmitJSON(w, map[string]interface{}{
					"configured":  true,
					"location":    location,
					"tokenPrefix": prefix,
					"tokenMasked": masked,
					"apiBase":     apiBaseOrDefault(g.APIBase),
				})
			}
			fmt.Fprintf(w, "token    %s\n", masked)
			fmt.Fprintf(w, "location %s\n", location)
			fmt.Fprintf(w, "api      %s\n", apiBaseOrDefault(g.APIBase))
			return nil
		},
	}
	return cmd
}

func newProbeRevokeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Forget the locally-stored probe token (local-only)",
		Long: `Forget the locally-stored probe token. The server-side token
stays live until you revoke it in the dashboard at /account/probes;
this command only clears local state.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configureOutput(cmd.OutOrStdout())
			if err := probe.DeleteToken(); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, output.StyleOK.Render("Local probe token cleared"))
			fmt.Fprintln(w, output.StyleDim.Render(
				"Server-side: revoke at https://wiredepth.com/account/probes",
			))
			return nil
		},
	}
	return cmd
}

// ---- helpers ----

func readAllStdin(r *os.File) (string, error) {
	var sb strings.Builder
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1<<16)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteString("\n")
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func maskToken(t string) string {
	if len(t) <= 8 {
		return strings.Repeat("*", len(t))
	}
	return t[:4] + strings.Repeat("*", len(t)-8) + t[len(t)-4:]
}

func apiBaseOrDefault(b string) string {
	if b == "" {
		return "https://wiredepth.com"
	}
	return b
}
