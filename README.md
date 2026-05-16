# wd - WireDepth CLI

The official CLI for [WireDepth](https://wiredepth.com) - external
attack surface monitoring with TLS / DMARC / DNS / threat-intel /
audit-chain evidence for any public domain. Free, no signup for the
read-only checks; sign in for monitoring + workpapers.

> **Renamed from `postvale`.** Legacy env vars (`POSTVALE_API`,
> `POSTVALE_TOKEN`) + the old keyring service + the old
> `~/.config/postvale/` config dir are still read as fallback so
> existing installs keep working through the rename window. See
> [docs/v2-migration.md](./docs/v2-migration.md) for the full
> migration plan.

```
$ wd check example.com

  ┌─ example.com ─────────────────────────── A- ─┐
  │                                              │
  │  TLS         A    Cert valid · TLS 1.3 · HSTS│
  │  DMARC       A    p=reject · alignment strict│
  │  SPF         B    Soft fail (~all)           │
  │  DKIM        A    1 selector active          │
  │  MTA-STS     A    Enforced                   │
  │  DNSSEC      A    Validated                  │
  │  CAA         B    Only issue, no issuewild   │
  │  Headers     C    Missing CSP, COOP, COEP    │
  │                                              │
  └──────────────────────────────────────────────┘

  → Full report: https://wiredepth.com/check/example.com
```

## Install

### Homebrew (macOS, Linux)
```sh
brew install WiredepthHQ/tap/wd
```

### Scoop (Windows)
```sh
scoop bucket add wiredepth https://github.com/WiredepthHQ/scoop-bucket
scoop install wd
```

### Shell installer
```sh
curl -fsSL https://wiredepth.com/install.sh | sh
```

### Go
```sh
go install github.com/WiredepthHQ/cli/cmd/wd@latest
```

### Direct download
Pre-built binaries for `linux`, `darwin`, `windows` × `amd64` / `arm64`
are on the [releases page](https://github.com/WiredepthHQ/cli/releases).

## Quick start

No signup needed for read-only checks:

```sh
wd check example.com               # full posture
wd tls api.example.com             # TLS / SSL only
wd dmarc example.com               # DMARC + SPF
wd dns example.com                 # DNS health
wd scam < suspicious-email.eml     # Scam Check from stdin
wd spf flatten example.com         # SPF include flattener
```

Sign in to add domains to continuous monitoring or pull audit
workpapers:

```sh
wd auth login                      # opens browser
wd watch example.com               # add to Pro+ monitoring
wd alerts --since 24h              # recent alerts on your monitored set
wd workpaper email-auth example.com > wp-email-auth.pdf
```

## CI integration

The CLI is designed to drop into CI/CD pipelines:

```yaml
# .github/workflows/posture.yml
- name: Check TLS posture
  run: |
    curl -fsSL https://wiredepth.com/install.sh | sh
    wd tls --quiet --exit-on-fail $DOMAIN
```

`--exit-on-fail` exits non-zero if the check returns a grade below `B`
or a failing verdict. Combine with `--json` for machine-readable
output you can store as a build artifact.

## Output formats

- Default: pretty terminal output with colour + box drawing
- `--json`: structured JSON (every command supports it)
- `--quiet`: minimal output (one-line summary or nothing on success)
- `--no-color`: disable ANSI (auto-disabled on non-TTY)

## Commands

Run `wd help` for the full command list, or `wd help <command>`
for per-command flags. See [`docs/commands.md`](docs/commands.md) for the
full reference.

## TUI dashboard

```sh
wd tui
```

Opens an interactive [Bubbletea](https://github.com/charmbracelet/bubbletea)
dashboard for your monitored domains, recent alerts, and one-shot
checks. Press `?` for keyboard shortcuts. Pro+ feature - free tier
opens in read-only "demo data" mode.

## Privacy

The CLI doesn't ship telemetry. The only network calls it makes are
to `wiredepth.com`. No phone-home, no anonymous analytics, no crash
reporting unless you opt in via `wd auth login --share-crashes`.

Tokens are stored in your OS keychain (macOS Keychain, Windows
Credential Manager, libsecret on Linux). On systems without a
keychain we fall back to `~/.config/wiredepth/token` with `0600`
permissions.

## Contributing

Bug reports + PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
