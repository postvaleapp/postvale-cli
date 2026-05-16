// Package probe implements the on-prem scanning probe.
package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	envOverride = "WIREDEPTH_PROBE_TOKEN"
	tokenFile   = "probe.token"
)

var ErrNoToken = errors.New("no probe token configured (run `postvale probe enroll`)")

// LoadToken returns the probe token. Env wins, then file.
func LoadToken() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return v, nil
	}
	path, err := tokenPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoToken
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", ErrNoToken
	}
	return v, nil
}

// SaveToken writes the token to the user config dir, 0600 perms.
func SaveToken(token string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, tokenFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// DeleteToken removes the stored token. Idempotent.
func DeleteToken() error {
	path, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// StorageLocation describes where the token currently lives.
func StorageLocation() string {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return "env (" + envOverride + ")"
	}
	path, err := tokenPath()
	if err != nil {
		return "(not stored)"
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return "(not stored)"
}

func tokenPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tokenFile), nil
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}
	// Shares the postvale config dir with the user auth token, but a
	// different filename so the two don't collide. Renaming the dir
	// to 'wiredepth' is a separate migration (loud, touches every
	// install).
	return filepath.Join(base, "postvale"), nil
}
