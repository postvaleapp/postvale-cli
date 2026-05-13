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
	"github.com/postvaleapp/postvale-cli/internal/output"
)

// newClient builds an API client using the resolved global flags.
// Centralised so every command builds its client the same way.
func newClient() (*api.Client, error) {
	g := Globals()
	timeout := time.Duration(g.Timeout) * time.Second
	if g.Timeout <= 0 {
		timeout = 30 * time.Second
	}
	return api.New(g.APIBase, g.Token, timeout)
}

// configureOutput honours --no-color + auto-disables ANSI when
// stdout isn't a TTY (so piped output stays clean).
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

// domainRE matches valid-looking domains. Reject IPs, ports, schemes;
// the user has plenty of other CLI tools for those edge cases.
var domainRE = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// normaliseDomain strips a leading scheme, path, port + lower-cases.
// Returns ("", error) for inputs that don't look like a domain.
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

// failExit returns the right exit code for --exit-on-fail.
// Returning an error from RunE doesn't let us control the exit code
// granularly, so we os.Exit directly. Callers should call this
// AFTER all output has flushed.
func failExit() {
	os.Exit(1)
}
