# Changelog

All notable changes to the Postvale CLI are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Initial scaffold: cobra command tree, Lipgloss output, base API client
- Phase 1 commands: `check`, `tls`, `dmarc`, `dns`, `headers`,
  `mta-sts`, `bimi`, `dnssec`, `caa`, `subdomains`, `takeover`,
  `spoof`, `spf flatten`, `reputation`, `scam`, `version`
- Phase 2 (auth + monitoring + workpapers):
  - `auth login` / `auth logout` / `auth whoami` (loopback OAuth,
    OS keyring with file fallback)
  - `watch <domain>` / `watch list` / `watch remove <domain-or-id>`
  - `alerts` (lists configured webhook + email endpoints)
  - `workpaper <type> <domain> [--out path]` (streams PDF)
- Phase 3 (TUI + CI):
  - `tui`: Bubbletea dashboard with a domains table, refresh,
    detail view, in-browser deep-link, help overlay
  - `ci` subcommands (`ci check`, `ci tls`, `ci dmarc`, `ci dns`,
    `ci headers`, `ci dnssec`, `ci spoof`, `ci takeover`) which
    force --quiet, --no-color, --exit-on-fail by default
- Global flags: `--json`, `--quiet`, `--no-color`, `--exit-on-fail`,
  `--timeout`, `--api`, `--token`, `--config`
- `POSTVALE_API` + `POSTVALE_TOKEN` env-var fallbacks
- `NO_COLOR` env-var support per https://no-color.org/
- MIT licence
