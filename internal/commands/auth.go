package commands

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/postvaleapp/postvale-cli/internal/api"
	"github.com/postvaleapp/postvale-cli/internal/auth"
	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage CLI authentication",
		Long: `Manage the Bearer token the CLI uses for Pro features:
  postvale auth login    Open browser, mint a token, store it
  postvale auth logout   Forget the stored token (local only)
  postvale auth whoami   Show who's signed in + plan`,
	}
	cmd.AddCommand(newAuthLoginCommand())
	cmd.AddCommand(newAuthLogoutCommand())
	cmd.AddCommand(newAuthWhoamiCommand())
	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	var browserTimeout int
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Open browser, approve a CLI token, store it locally",
		Long: `Open postvale.app/cli-auth in your browser. After you sign in
and click Allow, postvale.app mints a Bearer token and sends it
back to a one-shot listener on 127.0.0.1. The CLI stores the token
in your OS keyring (or ~/.config/postvale/token on systems with no
keyring) and uses it for every subsequent call.

Revoke from the Account page if you ever need to.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			g := Globals()
			configureOutput(cmd.OutOrStdout())

			label := defaultTokenLabel()

			fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
				fmt.Sprintf("Opening %s/cli-auth in your browser...", g.APIBase),
			))

			result, err := auth.LoginViaBrowser(
				g.APIBase,
				label,
				time.Duration(browserTimeout)*time.Second,
			)
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}

			if err := auth.Save(result.Token); err != nil {
				return fmt.Errorf("store token: %w", err)
			}

			// Verify the token round-trips so we can print the user's
			// email immediately, not just "ok".
			client, err := api.New(g.APIBase, result.Token, 15*time.Second)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			me, err := client.Me()
			if err != nil {
				// Token saved but verify failed - surface the error,
				// don't roll back. User can re-run if they need to.
				fmt.Fprintln(cmd.OutOrStdout(), output.StyleWarn.Render(
					"Token saved but /api/v1/me round-trip failed: "+err.Error(),
				))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n",
				output.StyleOK.Render("Logged in as"),
				output.StyleStrong.Render(me.User.Email),
			)
			fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
				fmt.Sprintf("  plan: %s | token stored in: %s | label: %s",
					me.User.TierLabel, auth.StorageLocation(), label,
				),
			))
			return nil
		},
	}
	cmd.Flags().IntVar(&browserTimeout, "browser-timeout", 180,
		"Seconds to wait for the browser approval (default 180)")
	return cmd
}

func newAuthLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget the locally-stored token (does not revoke on server)",
		Long: `Delete the local credential. Does NOT revoke the token on
postvale.app - the server still considers it valid until you revoke
it explicitly from the Account page.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auth.Delete(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), output.StyleOK.Render("Logged out locally."))
			fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
				"To fully revoke, visit "+Globals().APIBase+"/account",
			))
			return nil
		},
	}
}

func newAuthWhoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show who you're signed in as (and plan)",
		RunE: func(cmd *cobra.Command, args []string) error {
			g := Globals()
			configureOutput(cmd.OutOrStdout())

			token := g.Token
			if token == "" {
				t, err := auth.Load()
				if err != nil {
					if errors.Is(err, auth.ErrNotLoggedIn) {
						fmt.Fprintln(cmd.ErrOrStderr(), output.StyleDim.Render(
							"Not signed in. Run `postvale auth login`.",
						))
						os.Exit(1)
					}
					return err
				}
				token = t
			}

			client, err := api.New(g.APIBase, token, 15*time.Second)
			if err != nil {
				return err
			}
			me, err := client.Me()
			if err != nil {
				return fmt.Errorf("whoami: %w", err)
			}

			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), me)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", output.StyleStrong.Render(me.User.Email))
			fmt.Fprintln(cmd.OutOrStdout(), output.StyleDim.Render(
				fmt.Sprintf("  plan: %s | stored: %s", me.User.TierLabel, auth.StorageLocation()),
			))
			return nil
		},
	}
}

// Token label sent to the webapp. Surfaces in the Account API-keys
// page so the user can spot + revoke this specific token later.
func defaultTokenLabel() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("postvale-cli on %s (%s/%s)", host, runtime.GOOS, runtime.GOARCH)
}
