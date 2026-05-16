# Changelog

All notable changes to the WireDepth CLI are documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased] - v2.0 surface rename

### Changed
- **Binary renamed**: entry point is now `wd` (was `postvale`). The
  Go module is `github.com/WiredepthHQ/cli`; the binary
  lives at `cmd/wd/`.
- **Env vars renamed**: `WIREDEPTH_API` + `WIREDEPTH_TOKEN` are the
  new names. Legacy `POSTVALE_API` + `POSTVALE_TOKEN` are still
  read as fallback through v2.2; dropped in v2.3.
- **Keyring service renamed**: new tokens write under `wiredepth-cli`.
  Legacy `postvale-cli` keyring entries are read as fallback so
  existing logins don't break.
- **Config dir renamed**: `~/.config/wiredepth/` (was
  `~/.config/postvale/`). Legacy path read as fallback.
- **API base default**: `https://wiredepth.com` (was `https://postvale.app`).
- **User-Agent**: `wd-cli/<version>` (was `postvale-cli/<version>`).

### Added
- `internal/telemetry/`: scaffolding for opt-in CLI usage metrics.
  Off by default; the API endpoint + privacy-explainer landing
  ship in v2.0.x. See `docs/v2-migration.md` for the data model.
- `docs/v2-migration.md`: the full v2 migration plan (this rename
  is Phase 1; verb-group restructure is v2.1; AI surface v2.2;
  TUI mode + legacy fallback removal v2.3).

## [Pre-rename releases]

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
- `noc`: live operations console. 3-pane layout (domains table,
  action queue, scan tail) + top stats strip. Polls /api/v1/
  dashboard/summary every 30s and /api/v1/scans/recent every 6s
  with cursor-based incremental fetch. Pause/resume + refresh.
- Global flags: `--json`, `--quiet`, `--no-color`, `--exit-on-fail`,
  `--timeout`, `--api`, `--token`, `--config`
- `POSTVALE_API` + `POSTVALE_TOKEN` env-var fallbacks
- `NO_COLOR` env-var support per https://no-color.org/
- MIT licence
