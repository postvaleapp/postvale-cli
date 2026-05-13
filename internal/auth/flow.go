package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

// LoopbackResult is what we hand back to the caller after the user
// approves on /cli-auth. Contains the token the webapp minted and
// the state we sent (already verified to match).
type LoopbackResult struct {
	Token string
	State string
}

// LoginViaBrowser implements the loopback-OAuth-style flow used by
// `gh`, `vercel`, `supabase` CLIs. Steps:
//
//  1. Bind a listener on 127.0.0.1:<random port>.
//  2. Generate a random `state` value.
//  3. Open the browser to /cli-auth?cb=...&state=...&label=...
//  4. The consent page POSTs to /api/v1/cli/exchange which redirects
//     the browser back to the loopback URL with token+state.
//  5. We capture the token, verify state, return.
//
// timeout is the upper bound on how long we'll wait for the user to
// complete the consent. 3 minutes is roomy without leaving a dead
// listener if they abandon the tab.
func LoginViaBrowser(apiBase, label string, timeout time.Duration) (*LoopbackResult, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("loopback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	state, err := randomState()
	if err != nil {
		ln.Close()
		return nil, err
	}

	cb := fmt.Sprintf("http://127.0.0.1:%d/cli-callback", port)
	consentURL, err := buildConsentURL(apiBase, cb, state, label)
	if err != nil {
		ln.Close()
		return nil, err
	}

	resultCh := make(chan *LoopbackResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/cli-callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		gotState := r.URL.Query().Get("state")
		if token == "" || gotState == "" {
			writeBrowserPage(w, false, "Missing token or state in callback URL.")
			errCh <- errors.New("callback missing token or state")
			return
		}
		if !safeEq(gotState, state) {
			writeBrowserPage(w, false, "State mismatch. The CLI rejected the response. Re-run `postvale auth login`.")
			errCh <- errors.New("state mismatch")
			return
		}
		writeBrowserPage(w, true, "")
		resultCh <- &LoopbackResult{Token: token, State: gotState}
	})

	srv := &http.Server{
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := openBrowser(consentURL); err != nil {
		// Browser open failure isn't fatal; print the URL and let the
		// user paste it manually.
		fmt.Printf("Could not open browser automatically. Visit:\n\n  %s\n\n", consentURL)
	}

	select {
	case r := <-resultCh:
		return r, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for browser approval")
	}
}

func buildConsentURL(apiBase, cb, state, label string) (string, error) {
	u, err := url.Parse(apiBase)
	if err != nil {
		return "", fmt.Errorf("api base: %w", err)
	}
	u.Path = "/cli-auth"
	q := u.Query()
	q.Set("cb", cb)
	q.Set("state", state)
	q.Set("label", label)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Constant-time string compare. Length-different strings short-circuit.
func safeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := 0; i < len(a); i++ {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

// openBrowser shells out to the platform-native opener. We never
// pass the URL through a shell - exec.Command's argv form avoids
// any quoting / metacharacter risk.
func openBrowser(rawURL string) error {
	// Defensive parse: refuse to open anything that isn't an http(s)
	// URL the CLI itself just constructed. Cheap last-line check.
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("bad url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsafe scheme %q", u.Scheme)
	}

	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}

// writeBrowserPage renders the tab the user sees after the callback
// fires. Success page tells them they can close it; failure page
// explains what to do.
func writeBrowserPage(w http.ResponseWriter, ok bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	title := "Signed in"
	body := "You're signed in to the Postvale CLI. You can close this tab."
	if !ok {
		title = "Sign-in failed"
		body = "Something went wrong: " + html.EscapeString(message) + ". Re-run `postvale auth login` from your terminal."
	}
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s - Postvale CLI</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 0 1.5rem; color: #0f172a; }
  @media (prefers-color-scheme: dark) { body { color: #f1f5f9; background: #020617; } }
  h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 0.75rem; }
  p { color: #64748b; line-height: 1.5; }
  code { background: rgba(148,163,184,0.2); padding: 0.1rem 0.3rem; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.9em; }
</style>
</head>
<body>
<h1>%s</h1>
<p>%s</p>
</body>
</html>
`, html.EscapeString(title), html.EscapeString(title), body)
}
