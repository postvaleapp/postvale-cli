package commands

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/postvaleapp/postvale-cli/internal/api"
	"github.com/postvaleapp/postvale-cli/internal/auth"
	"github.com/postvaleapp/postvale-cli/internal/output"
)

func newClient() (*api.Client, error) {
	g := Globals()
	timeout := time.Duration(g.Timeout) * time.Second
	if g.Timeout <= 0 {
		timeout = 30 * time.Second
	}
	token := g.Token
	if token == "" {
		// Try the stored credential as a fallback so most commands
		// can just be run without --token. Anonymous routes don't
		// care if this returns ErrNotLoggedIn.
		if t, err := auth.Load(); err == nil {
			token = t
		}
	}
	return api.New(g.APIBase, token, timeout)
}

// Honour --no-color and auto-disable ANSI when piped.
func configureOutput(out io.Writer) {
	g := Globals()
	if g.NoColor {
		output.Disable()
		return
	}
	if f, ok := out.(*os.File); ok {
		if !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
			output.Disable()
		}
	}
}

// Rejects IPs, ports, schemes; the user has other tools for those.
var domainRE = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func normaliseDomain(raw string) (string, error) {
	d := strings.TrimSpace(strings.ToLower(raw))
	if d == "" {
		return "", errors.New("domain is required")
	}
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.Index(d, "/"); i >= 0 {
		d = d[:i]
	}
	if i := strings.Index(d, ":"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	if !domainRE.MatchString(d) {
		return "", fmt.Errorf("not a valid domain: %q", raw)
	}
	return d, nil
}

// Forces a non-zero exit. Call after all output has flushed.
func failExit() { os.Exit(1) }
