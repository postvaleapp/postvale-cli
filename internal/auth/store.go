// Package auth handles CLI credential storage.
package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "postvale-cli"
	keyringUser    = "default"
	envOverride    = "POSTVALE_TOKEN"
)

// Errors callers can match against.
var (
	ErrNotLoggedIn = errors.New("not logged in (run `postvale auth login`)")
)

// Save writes the token to the OS keyring. Falls back to a 0600 file
// in ~/.config/postvale/ when the keyring isn't available (CI hosts,
// stripped Linux images, headless boxes).
func Save(token string) error {
	if err := keyring.Set(keyringService, keyringUser, token); err == nil {
		return nil
	}
	return fileSave(token)
}

// Load returns the stored token. Checks the env var first so CI use
// (POSTVALE_TOKEN=abc postvale check ...) doesn't need a stored
// credential at all.
func Load() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return v, nil
	}
	if v, err := keyring.Get(keyringService, keyringUser); err == nil && v != "" {
		return v, nil
	}
	v, err := fileLoad()
	if err != nil {
		return "", ErrNotLoggedIn
	}
	if v == "" {
		return "", ErrNotLoggedIn
	}
	return v, nil
}

// Delete removes any stored token. Idempotent.
func Delete() error {
	// Try keyring first; ignore "not found" style errors.
	_ = keyring.Delete(keyringService, keyringUser)
	// Always try the file path too in case both happen to exist.
	if path, err := tokenFilePath(); err == nil {
		_ = os.Remove(path)
	}
	return nil
}

// StorageLocation describes where the token currently lives. Useful
// for `postvale auth whoami` to surface "keyring" vs "file fallback".
func StorageLocation() string {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return "env (" + envOverride + ")"
	}
	if _, err := keyring.Get(keyringService, keyringUser); err == nil {
		switch runtime.GOOS {
		case "darwin":
			return "macOS Keychain"
		case "windows":
			return "Windows Credential Manager"
		default:
			return "libsecret / DBus keyring"
		}
	}
	if path, err := tokenFilePath(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "(not stored)"
}

// ---- file fallback ----

func tokenFilePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "token"), nil
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}
	return filepath.Join(base, "postvale"), nil
}

func fileSave(token string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "token")
	// O_TRUNC because we want a clean overwrite; 0600 perms because
	// the file holds a long-lived bearer token.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(token); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func fileLoad() (string, error) {
	path, err := tokenFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
