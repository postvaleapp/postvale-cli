// API token storage backed by the OS keyring (Keychain on macOS,
// Credential Manager on Windows, libsecret on Linux). Falls back to
// reading WIREDEPTH_TOKEN from the env at request time when no
// keyring entry is present.
//
// No filesystem fallback by design - a stale token on disk is a
// recurring incident-response footgun. CI should set the env var;
// interactive users use the keyring via `wd auth login`.
package auth

import (
	"errors"

	"github.com/zalando/go-keyring"
)

const (
	service = "wiredepth"
	user    = "api-token"
)

// SaveToken stores the API token in the OS keyring. Overwrites any
// existing value silently - `wd auth login` is idempotent.
func SaveToken(token string) error {
	if token == "" {
		return errors.New("refusing to store empty token")
	}
	return keyring.Set(service, user, token)
}

// LoadToken returns the stored API token, or ErrNotFound when the
// keyring has no entry. Callers handle the env-var fallback at the
// config layer.
func LoadToken() (string, error) {
	t, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return t, err
}

// ClearToken removes the stored token. Used by `wd auth logout`.
// Treats a missing entry as success - logging out twice is fine.
func ClearToken() error {
	err := keyring.Delete(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// ErrNotFound is returned by LoadToken when there is no keyring
// entry yet. Distinguish from other keyring errors (locked, denied)
// so callers can fall back to env vars vs surfacing the failure.
var ErrNotFound = errors.New("no API token in keyring")
