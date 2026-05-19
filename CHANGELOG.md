# Changelog

## [Unreleased] - v3.0 clean rewrite

Full rewrite. Drops the TUI / probe / extension-billing / NOC
surface, drops legacy postvale fallback paths, and rebuilds the
command tree around scriptable-CLI essentials.

- Phase 1 (this release): public posture checks for any domain
  without auth - `check`, `tls`, `dmarc`, `dns`, `dnssec`, `caa`,
  `headers`, `mta-sts`, `subdomains`, `takeover`, `spoofability`,
  `threat-intel`. All route through `/api/v1/check/<tool>/<domain>`
  on the WireDepth webapp.
- Auth scaffolding: `wd auth login` / `logout` / `whoami`. Tokens
  live in the OS keyring (Keychain / Credential Manager /
  libsecret); CI uses `WIREDEPTH_TOKEN` env var.
- Audit chain: `wd audit anchors` lists the published daily
  Merkle roots; `wd audit verify` is a stub for the JSONL-export
  verification (algorithm spec at wiredepth.com/docs/verify).
- Output: human-readable text by default, `--json` for scripting.

### Breaking changes from v2.x

- Binary name remains `wd` (no change)
- Module path remains `github.com/WiredepthHQ/cli` (no change)
- All `postvale` / `POSTVALE_*` legacy fallback removed - the
  rename has been live for weeks; CI / install scripts that still
  reference the old name should update
- TUI removed (`wd tui` / `wd noc` / `wd dashboard` no longer
  exist) - use the web app for the GUI experience
- On-prem `probe` subcommand removed - WireDepth ships multi-
  region probes from AWS instead
- Extension billing CLI removed - manage via the web app
- AI commands removed from the CLI - the AI playbook lives on
  per-finding pages in the web app

### Why a clean rewrite

The codebase had grown to 64 files + 12k LOC, half of which was
the Bubble Tea TUI subsystem. A CLI that opens a full-screen
interactive surface is a different product category from a
scriptable + composable Unix-style CLI. The rewrite picks the
latter posture deliberately.

## Previous versions

See git history before this rewrite. v2.x line was the
postvale-rename intermediate state; v1.x was the original
postvale-branded CLI.
