// Auth subcommands: login / logout / whoami.
//
// Login is a browser-based device-code-style flow:
//  1. CLI POSTs to /api/v1/cli/start, gets a one-time URL + poll
//     token
//  2. CLI opens the URL in the user's browser (or prints it if we
//     can't); the user signs in + approves the CLI
//  3. CLI polls /api/v1/cli/exchange with the poll token until the
//     webapp returns the API token
//  4. Token lands in the OS keyring; not on the filesystem
//
// Implementation stub: this commit ships the cobra command shell +
// keyring plumbing. The browser-flow wire calls land in a follow-up
// once the webapp's /api/v1/cli/* endpoints are confirmed.
package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/auth"
	"github.com/WiredepthHQ/cli/internal/config"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Sign in / out + check identity",
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Browser-based sign-in (stores token in OS keyring)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: wire to /api/v1/cli/start + /api/v1/cli/exchange.
		// For now, support the manual paste-in token path so
		// scripted setup (CI, container images) works without
		// browser interaction.
		fmt.Fprintln(cmd.OutOrStdout(), "Paste a token from https://wiredepth.com/account/api-keys")
		fmt.Fprint(cmd.OutOrStdout(), "Token: ")
		var token string
		_, err := fmt.Fscanln(cmd.InOrStdin(), &token)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return errors.New("no token provided")
		}
		if err := auth.SaveToken(token); err != nil {
			return fmt.Errorf("save token: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Token saved to keyring.")
		return nil
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove the stored API token",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.ClearToken(); err != nil {
			return fmt.Errorf("clear token: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Token cleared.")
		return nil
	},
}

var authWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current authenticated identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: GET /api/v1/me, render the email + plan tier
		// inline. Stub for now - returns "authenticated" if a
		// token is present, else points to the login command.
		_, err := auth.LoadToken()
		if errors.Is(err, auth.ErrNotFound) {
			cfg, _ := config.Load()
			if cfg != nil && cfg.Token != "" {
				fmt.Fprintln(cmd.OutOrStdout(), "Token from env (WIREDEPTH_TOKEN).")
				return nil
			}
			return errors.New("not signed in (run `wd auth login`)")
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Token present in keyring.")
		return nil
	},
}

func init() {
	authCmd.AddCommand(authLoginCmd, authLogoutCmd, authWhoamiCmd)
	rootCmd.AddCommand(authCmd)
}
