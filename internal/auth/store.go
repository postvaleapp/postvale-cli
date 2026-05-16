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
	keyringService    = "wiredepth-cli"
	keyringServiceOld = "postvale-cli"
	keyringUser       = "default"
	envOverride       = "WIREDEPTH_TOKEN"
	envOverrideOld    = "POSTVALE_TOKEN"
)

// Errors callers can match against.
var (
	ErrNotLoggedIn = errors.New("not logged in (run `wd auth login`)")
)

// Save writes the token to the OS keyring. Falls back to a 0600 file
// in ~/.config/wiredepth/ when the keyring isn't available (CI hosts,
// stripped Linux images, headless boxes).
func Save(token string) error {
	if err := keyring.Set(keyringService, keyringUser, token); err == nil {
		return nil
	}
	return fileSave(token)
}

// Load returns the stored token. Checks the env var first so CI use
// (WIREDEPTH_TOKEN=abc wd check ...) doesn't need a stored credential
// at all. Legacy keyring service + env var are read as fallback so
// users mid-rename don't get logged out.
func Load() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv(envOverrideOld)); v != "" {
		return v, nil
	}
	if v, err := keyring.Get(keyringService, keyringUser); err == nil && v != "" {
		return v, nil
	}
	if v, err := keyring.Get(keyringServiceOld, keyringUser); err == nil && v != "" {
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

// Delete removes any stored token. Idempotent. Wipes the legacy
// keyring entry too so a user mid-rename doesn't leave a dangling
// credential behind.
func Delete() error {
	_ = keyring.Delete(keyringService, keyringUser)
	_ = keyring.Delete(keyringServiceOld, keyringUser)
	if path, err := tokenFilePath(); err == nil {
		_ = os.Remove(path)
	}
	if path, err := legacyTokenFilePath(); err == nil {
		_ = os.Remove(path)
	}
	return nil
}

// StorageLocation describes where the token currently lives. Useful
// for `wd auth whoami` to surface "keyring" vs "file fallback".
func StorageLocation() string {
	if v := strings.TrimSpace(os.Getenv(envOverride)); v != "" {
		return "env (" + envOverride + ")"
	}
	if v := strings.TrimSpace(os.Getenv(envOverrideOld)); v != "" {
		return "env (" + envOverrideOld + ", legacy)"
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
	if _, err := keyring.Get(keyringServiceOld, keyringUser); err == nil {
		return "(legacy keyring entry, run `wd auth login` to migrate)"
	}
	if path, err := tokenFilePath(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if path, err := legacyTokenFilePath(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return path + " (legacy)"
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
	return filepath.Join(base, "wiredepth"), nil
}

// legacyTokenFilePath points at the pre-rename ~/.config/postvale/
// token location. Read-only fallback so users keep working through
// the rename window without re-authing.
func legacyTokenFilePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}
	return filepath.Join(base, "postvale", "token"), nil
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
	if path, err := tokenFilePath(); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}
	// Legacy ~/.config/postvale/token fallback for the rename window.
	if path, err := legacyTokenFilePath(); err == nil {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}
	return "", os.ErrNotExist
}
