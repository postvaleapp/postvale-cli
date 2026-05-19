#!/bin/sh
# wd CLI installer.
#
# Detects OS + arch, downloads the matching release binary from
# GitHub, drops it in ~/.local/bin (or /usr/local/bin via sudo if
# that's not on PATH). Idempotent - re-run to upgrade.
#
# Usage:
#   curl -fsSL https://wiredepth.com/cli/install.sh | sh
#
# Environment overrides:
#   WD_VERSION    pin a specific version (default: latest)
#   WD_PREFIX     install dir (default: ~/.local/bin)

set -eu

VERSION="${WD_VERSION:-latest}"
PREFIX="${WD_PREFIX:-$HOME/.local/bin}"

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_m=$(uname -m)

case "${uname_s}" in
  darwin)  os=darwin ;;
  linux)   os=linux ;;
  msys*|mingw*|cygwin*) os=windows ;;
  *) echo "unsupported OS: ${uname_s}" >&2; exit 1 ;;
esac

case "${uname_m}" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: ${uname_m}" >&2; exit 1 ;;
esac

if [ "${VERSION}" = "latest" ]; then
  # Resolve "latest" via GitHub's HTML redirect; avoids needing
  # the API (which rate-limits unauthenticated callers).
  VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/WiredepthHQ/cli/releases/latest \
    | sed 's|.*/tag/||')
  if [ -z "${VERSION}" ]; then
    echo "could not resolve latest version" >&2
    exit 1
  fi
fi

ext=tar.gz
if [ "${os}" = "windows" ]; then
  ext=zip
fi

asset="wd_${VERSION#v}_${os}_${arch}.${ext}"
url="https://github.com/WiredepthHQ/cli/releases/download/${VERSION}/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

echo "Downloading ${asset}..."
curl -fsSL "${url}" -o "${tmp}/${asset}"

cd "${tmp}"
if [ "${ext}" = "zip" ]; then
  unzip -q "${asset}"
else
  tar -xzf "${asset}"
fi

mkdir -p "${PREFIX}"
binary=wd
[ "${os}" = "windows" ] && binary=wd.exe
mv "${binary}" "${PREFIX}/${binary}"
chmod +x "${PREFIX}/${binary}"

echo "Installed wd ${VERSION} to ${PREFIX}/${binary}"

# PATH hint if the install dir isn't on PATH.
case ":${PATH}:" in
  *:${PREFIX}:*) ;;
  *) echo "Hint: ${PREFIX} is not on \$PATH. Add it to your shell's rc file." ;;
esac
