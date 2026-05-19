// Auth subcommands: login / logout / whoami.
//
// Default login is browser-based loopback flow (mirrors GitHub CLI,
// Vercel CLI):
//  1. CLI spins up an HTTP listener on 127.0.0.1:<random-port>.
//  2. CLI opens browser to /cli-auth on the webapp with cb=<loop-
//     back URL>, state=<random>, label=<host hint>.
//  3. User signs in (if needed) + clicks Allow on the consent page.
//  4. Consent form POSTs /api/v1/cli/exchange; server mints a token
//     + returns the redirect URL with token + state baked in.
//  5. Browser navigates to the cb URL; CLI listener captures the
//     token, verifies state matches, stores in OS keyring.
//  6. Listener writes a "you can close this tab" HTML page; the CLI
//     prints "Logged in" and exits.
//
// For headless / CI use, --token=PASTED or `wd auth login < token-file`
// skips the browser flow entirely.
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

var (
	authLoginFlagToken     string
	authLoginFlagLabel     string
	authLoginFlagNoBrowser bool
)

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Browser-based sign-in (stores token in OS keyring)",
	Long: `Open the user's default browser to the WireDepth consent
page; capture the minted API token via a loopback HTTP listener
on 127.0.0.1:<random-port>; store the token in the OS keyring
(Keychain on macOS, Credential Manager on Windows, libsecret on
Linux).

For non-interactive use (CI, headless boxes), pass --token to skip
the browser flow:

  wd auth login --token "$(cat /run/secrets/wd-token)"

Or set WIREDEPTH_TOKEN in the environment - higher priority than
the keyring; no need to call login at all.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if flagAPI != "" {
			cfg.API = flagAPI
		}

		// Token-paste path: no browser, just save the provided
		// value. Useful for CI / containers / "I generated a
		// token in the webapp + want to install it locally".
		if authLoginFlagToken != "" {
			token := strings.TrimSpace(authLoginFlagToken)
			if token == "" {
				return errors.New("--token is empty")
			}
			if err := auth.SaveToken(token); err != nil {
				return fmt.Errorf("save token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Token saved to keyring.")
			return nil
		}

		// --no-browser falls back to the original paste-in
		// path, for environments where loopback listeners are
		// firewalled.
		if authLoginFlagNoBrowser {
			fmt.Fprintln(cmd.OutOrStdout(),
				"Generate an API key at",
				strings.TrimRight(cfg.API, "/")+"/account/api-keys")
			fmt.Fprint(cmd.OutOrStdout(), "Paste token: ")
			var token string
			if _, err := fmt.Fscanln(cmd.InOrStdin(), &token); err != nil {
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
		}

		// Browser flow.
		res, err := auth.RunBrowserLogin(cfg.API, authLoginFlagLabel)
		if err != nil {
			return fmt.Errorf("browser login: %w", err)
		}
		if err := auth.SaveToken(res.Token); err != nil {
			return fmt.Errorf("save token: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Logged in. Token saved to keyring.")
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
	authLoginCmd.Flags().StringVar(&authLoginFlagToken, "token", "",
		"API token to store (skips browser flow; for CI / non-interactive use)")
	authLoginCmd.Flags().StringVar(&authLoginFlagLabel, "label", "",
		"label for the new token (defaults to 'wd CLI on <hostname>')")
	authLoginCmd.Flags().BoolVar(&authLoginFlagNoBrowser, "no-browser", false,
		"skip the browser flow + paste a token by hand instead")
	authCmd.AddCommand(authLoginCmd, authLogoutCmd, authWhoamiCmd)
	rootCmd.AddCommand(authCmd)
}
