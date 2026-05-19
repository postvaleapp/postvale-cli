// Browser-flow login - mirror of the GitHub CLI / Vercel CLI
// pattern.
//
// Spins up a loopback HTTP listener on 127.0.0.1:<random-port>,
// opens the user's browser to /cli-auth on the WireDepth webapp
// with cb / state / label query params, blocks until the listener
// captures the token via the redirect from /api/v1/cli/exchange.
//
// State token is cryptographically random; webapp echoes it back
// in the redirect and we reject any mismatch (CSRF / response-
// injection defence).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// BrowserLoginResult is what RunBrowserLogin returns when the user
// successfully completes the consent flow. The token is the raw
// API-key value the webapp minted; caller stores it via auth.SaveToken.
type BrowserLoginResult struct {
	Token string
	State string
}

// RunBrowserLogin opens the user's browser to the WireDepth consent
// page + waits for the loopback callback. Times out after 5 minutes
// of inactivity (covers slow sign-in flows but doesn't block
// indefinitely on a forgotten terminal).
//
// apiBase is the API root (eg https://wiredepth.com); label is a
// human-readable hint for the audit log + token list ("wd CLI on
// laptop.local", "wd CLI in ci pipeline"). hostHint is just used
// to produce the label default when the caller doesn't provide one.
func RunBrowserLogin(
	apiBase string,
	label string,
) (*BrowserLoginResult, error) {
	if apiBase == "" {
		return nil, errors.New("api base URL is empty")
	}
	if label == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		label = fmt.Sprintf("wd CLI on %s", host)
	}

	state, err := randomState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// Bind to 127.0.0.1 on an OS-picked port. Listener stays open
	// only for the duration of this function.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback listener: %w", err)
	}
	defer lis.Close()

	port := lis.Addr().(*net.TCPAddr).Port
	cb := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	consentURL := fmt.Sprintf(
		"%s/cli-auth?cb=%s&state=%s&label=%s",
		strings.TrimRight(apiBase, "/"),
		url.QueryEscape(cb),
		url.QueryEscape(state),
		url.QueryEscape(label),
	)

	// Channel for the listener handler to deliver the captured
	// result (or an error if state mismatches / token missing).
	type captured struct {
		token string
		state string
		err   error
	}
	results := make(chan captured, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Single callback path; anything else gets a 404 + we
			// don't fire results (might be browser pre-fetching
			// favicon or similar).
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			gotToken := q.Get("token")
			gotState := q.Get("state")
			if gotToken == "" {
				results <- captured{err: errors.New("callback missing token")}
				writeBrowserClose(w, "wd: missing token", "Login failed - the redirect URL had no token. Check the terminal.", true)
				return
			}
			if gotState != state {
				results <- captured{err: errors.New("state mismatch (possible CSRF)")}
				writeBrowserClose(w, "wd: state mismatch", "Login failed - state token did not match. Possible CSRF; try again.", true)
				return
			}
			results <- captured{token: gotToken, state: gotState}
			writeBrowserClose(w, "wd: logged in", "You can close this tab and return to the terminal.", false)
		}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Run the server in a goroutine; the main goroutine blocks on
	// the results channel.
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	fmt.Println("Opening browser to:")
	fmt.Println("  " + consentURL)
	fmt.Println()
	fmt.Println("If the browser does not open automatically, paste the URL above.")
	if err := openBrowser(consentURL); err != nil {
		// Browser-open failures are common (headless boxes, SSH);
		// we already printed the URL so the user can paste it.
		// Don't fatal here - keep waiting for the callback.
		fmt.Fprintln(os.Stderr, "warning: could not open browser automatically:", err)
	}

	// Wait up to 5 minutes for the callback. Generous on purpose -
	// browser-flow sign-in can involve 2FA, password manager, etc.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	select {
	case res := <-results:
		// Shut down the listener cleanly so the OS releases the port.
		shutdownCtx, c2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer c2()
		_ = server.Shutdown(shutdownCtx)
		if res.err != nil {
			return nil, res.err
		}
		return &BrowserLoginResult{Token: res.token, State: res.state}, nil
	case err := <-serverErr:
		return nil, fmt.Errorf("loopback listener died: %w", err)
	case <-ctx.Done():
		_ = server.Close()
		return nil, errors.New("login timed out after 5 minutes")
	}
}

func randomState() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// openBrowser opens url in the user's default browser. Best-effort:
// returns an error if the OS-specific command fails, but the
// caller continues waiting for the callback (the user can paste
// the URL by hand if auto-open didn't work).
func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		// rundll32 url.dll,FileProtocolHandler accepts a URL.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		// xdg-open covers most Linux desktops; falls back via
		// the desktop's xdg-utils. On headless systems this
		// fails fast (we already printed the URL).
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

// writeBrowserClose writes a minimal HTML page to the loopback
// listener's response so the user gets confirmation in their
// browser tab. Status 200 always; the success/failure flag just
// drives the headline + colour.
func writeBrowserClose(
	w http.ResponseWriter,
	title string,
	message string,
	failure bool,
) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	colour := "#22c55e"
	if failure {
		colour = "#ef4444"
	}
	body := fmt.Sprintf(`<!doctype html>
<html><head><title>%s</title><meta charset="utf-8">
<style>
  body { font-family: system-ui, sans-serif; max-width: 520px; margin: 64px auto; padding: 24px; color: #0f172a; }
  .card { border-left: 4px solid %s; background: #f8fafc; padding: 20px; border-radius: 6px; }
  h1 { margin: 0 0 8px; font-size: 18px; }
  p { margin: 0; color: #475569; font-size: 14px; line-height: 1.5; }
</style>
</head><body>
  <div class="card">
    <h1>%s</h1>
    <p>%s</p>
  </div>
</body></html>`,
		htmlEscape(title), colour, htmlEscape(title), htmlEscape(message),
	)
	_, _ = w.Write([]byte(body))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
