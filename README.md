# postvale

The official CLI for [Postvale](https://postvale.app) - TLS, DMARC, DNS,
threat-intel, and compliance evidence for any public domain. Free, no
signup for the read-only checks; sign in for monitoring + workpapers.

```
$ postvale check example.com

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

  → Full report: https://postvale.app/check/example.com
```

## Install

### Homebrew (macOS, Linux)
```sh
brew install postvaleapp/tap/postvale
```

### Scoop (Windows)
```sh
scoop bucket add postvale https://github.com/postvaleapp/scoop-bucket
scoop install postvale
```

### Shell installer
```sh
curl -fsSL https://postvale.app/install.sh | sh
```

### Go
```sh
go install github.com/postvaleapp/postvale-cli/cmd/postvale@latest
```

### Direct download
Pre-built binaries for `linux`, `darwin`, `windows` × `amd64` / `arm64`
are on the [releases page](https://github.com/postvaleapp/postvale-cli/releases).

## Quick start

No signup needed for read-only checks:

```sh
postvale check example.com               # full posture
postvale tls api.example.com             # TLS / SSL only
postvale dmarc example.com               # DMARC + SPF
postvale dns example.com                 # DNS health
postvale scam < suspicious-email.eml     # Scam Check from stdin
postvale spf flatten example.com         # SPF include flattener
```

Sign in to add domains to continuous monitoring or pull audit
workpapers:

```sh
postvale auth login                      # opens browser
postvale watch example.com               # add to Pro+ monitoring
postvale alerts --since 24h              # recent alerts on your monitored set
postvale workpaper email-auth example.com > wp-email-auth.pdf
```

## CI integration

The CLI is designed to drop into CI/CD pipelines:

```yaml
# .github/workflows/posture.yml
- name: Check TLS posture
  run: |
    curl -fsSL https://postvale.app/install.sh | sh
    postvale tls --quiet --exit-on-fail $DOMAIN
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

Run `postvale help` for the full command list, or `postvale help <command>`
for per-command flags. See [`docs/commands.md`](docs/commands.md) for the
full reference.

## TUI dashboard

```sh
postvale tui
```

Opens an interactive [Bubbletea](https://github.com/charmbracelet/bubbletea)
dashboard for your monitored domains, recent alerts, and one-shot
checks. Press `?` for keyboard shortcuts. Pro+ feature - free tier
opens in read-only "demo data" mode.

## Self-hosted

If you run a private Postvale instance:

```sh
postvale --api https://postvale.acme.internal check example.com
```

Set `POSTVALE_API` in your environment to make it permanent.

## Privacy

The CLI doesn't ship telemetry. The only network calls it makes are
to the API endpoint (`postvale.app` by default, or `--api`). No
phone-home, no anonymous analytics, no crash reporting unless you
opt in via `postvale auth login --share-crashes`.

Tokens are stored in your OS keychain (macOS Keychain, Windows
Credential Manager, libsecret on Linux). On systems without a
keychain we fall back to `~/.config/postvale/token` with `0600`
permissions.

## Contributing

Bug reports + PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
