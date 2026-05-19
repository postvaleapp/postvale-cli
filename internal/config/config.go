// Config loading + persistence for wd.
//
// Reads from env vars first, then ~/.config/wiredepth/config (one
// line per KEY=value), then falls back to defaults. The API base
// URL can also be set via the global --api flag - flags override
// everything else.
package config

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvAPI overrides the API base URL. Useful for staging or
	// self-hosted WireDepth deployments.
	EnvAPI = "WIREDEPTH_API"
	// EnvToken overrides the API token. Higher priority than the
	// system keyring so CI can set this without touching the OS
	// credential store.
	EnvToken = "WIREDEPTH_TOKEN"

	// DefaultAPI is the production WireDepth API base URL.
	DefaultAPI = "https://wiredepth.com"
)

// Config is the resolved runtime configuration. Build it via Load();
// individual fields can be overridden by flag values after Load
// returns.
type Config struct {
	API   string
	Token string
}

// Load resolves config from env, then file, then defaults. Returns
// a Config with API set; Token is left empty when no env value is
// set (the auth package handles keyring fallback at request time).
func Load() (*Config, error) {
	c := &Config{API: DefaultAPI}

	// File first, env overrides file. Skip missing file silently;
	// it's optional.
	if path, err := configPath(); err == nil {
		if kv, err := readKV(path); err == nil {
			if v := kv["API"]; v != "" {
				c.API = v
			}
		}
	}

	if v := os.Getenv(EnvAPI); v != "" {
		c.API = v
	}
	if v := os.Getenv(EnvToken); v != "" {
		c.Token = v
	}

	return c, nil
}

// configPath returns ~/.config/wiredepth/config. Caller handles
// missing-file errors silently when the file is optional.
func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wiredepth", "config"), nil
}

// readKV parses a KEY=value text file. Blank lines + lines starting
// with # are ignored. No quoting support; values are trimmed.
func readKV(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ErrNoToken is returned when an authenticated command runs without
// a configured token (no env, no keyring).
var ErrNoToken = errors.New("no API token configured (run `wd auth login` or set WIREDEPTH_TOKEN)")
