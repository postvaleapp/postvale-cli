#!/bin/sh
# Postvale CLI installer.
#
# Use:
#   curl -fsSL https://wiredepth.com/install.sh | sh
#
# Picks the latest GitHub Release binary for the host's OS/arch,
# verifies the checksum, drops the binary in /usr/local/bin (or
# $POSTVALE_BIN_DIR if you'd rather put it elsewhere).
#
# Env vars:
#   POSTVALE_BIN_DIR   target directory (default /usr/local/bin)
#   POSTVALE_VERSION   pin to a specific version (default latest)
#
# Source: https://github.com/WiredepthHQ/cli

set -eu

REPO="WiredepthHQ/wiredepth-cli"
BIN="postvale"
BIN_DIR="${POSTVALE_BIN_DIR:-/usr/local/bin}"

# ---- OS / arch detection ----

uname_s=$(uname -s 2>/dev/null || echo Unknown)
uname_m=$(uname -m 2>/dev/null || echo Unknown)

case "$uname_s" in
  Linux)  os="Linux"  ;;
  Darwin) os="Darwin" ;;
  *) echo "unsupported OS: $uname_s (use Homebrew, Scoop, or download manually from https://github.com/$REPO/releases)" >&2; exit 1 ;;
esac

case "$uname_m" in
  x86_64|amd64)  arch="x86_64" ;;
  arm64|aarch64) arch="arm64"  ;;
  *) echo "unsupported architecture: $uname_m" >&2; exit 1 ;;
esac

# ---- Pick version ----

if [ -z "${POSTVALE_VERSION:-}" ]; then
  # Resolve "latest" via the GH API redirect
  version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" \
              | sed -E 's|.*/tag/(v[^/]+)$|\1|')
  if [ -z "$version" ]; then
    echo "could not resolve latest version" >&2
    exit 1
  fi
else
  version="$POSTVALE_VERSION"
fi

# Reject anything that doesn't look like a semver tag. Stops attempts
# to smuggle arbitrary path components through POSTVALE_VERSION.
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) : ;;
  *)
    echo "invalid version $version (expected vX.Y.Z)" >&2
    exit 1
    ;;
esac

# Strip leading v for the archive name
ver_num="${version#v}"
archive="postvale_${ver_num}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$version/$archive"
checksum_url="https://github.com/$REPO/releases/download/$version/checksums.txt"

# ---- Download + verify ----

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $archive ..."
curl -fsSL "$url" -o "$tmp/$archive"

echo "Verifying checksum ..."
curl -fsSL "$checksum_url" -o "$tmp/checksums.txt"
expected=$(grep "$archive" "$tmp/checksums.txt" | awk '{print $1}')
if [ -z "$expected" ]; then
  echo "no checksum entry for $archive" >&2
  exit 1
fi
actual=$( (sha256sum "$tmp/$archive" 2>/dev/null || shasum -a 256 "$tmp/$archive") | awk '{print $1}')
if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi

# ---- Install ----

tar -xzf "$tmp/$archive" -C "$tmp"

if [ ! -w "$BIN_DIR" ]; then
  echo "$BIN_DIR is not writable; falling back to sudo install"
  sudo install -m 0755 "$tmp/$BIN" "$BIN_DIR/$BIN"
else
  install -m 0755 "$tmp/$BIN" "$BIN_DIR/$BIN"
fi

echo "Installed $($BIN_DIR/$BIN version)"
echo "Run \`postvale help\` to get started."
