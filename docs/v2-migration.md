# CLI v2 migration plan

The CLI rebrand from `postvale` to `wd` ships in phases. This doc is
the current shape of the work + what users see at each step.

## What landed in v2.0 (this release)

- **Binary rename**: the entry point is now `wd`. The Go module is
  `github.com/WiredepthHQ/wiredepth-cli`; the binary lives at
  `cmd/wd/`.
- **Env var rename**: read `WIREDEPTH_API` and `WIREDEPTH_TOKEN`
  first, then fall back to the legacy `POSTVALE_API` /
  `POSTVALE_TOKEN`. Existing CI pipelines keep working through the
  rename window; we'll drop the legacy reads in v2.3.
- **Keyring service rename**: new tokens land under the
  `wiredepth-cli` keyring service. Legacy `postvale-cli` entries
  are still read as fallback so users who logged in before don't
  have to re-auth. Next `wd auth login` writes to the new service.
- **Config dir rename**: file-fallback tokens land at
  `~/.config/wiredepth/token` instead of `~/.config/postvale/`.
  The pre-rename location is still read as fallback.
- **User-Agent rename**: HTTP requests identify as `wd-cli/<version>`
  instead of `postvale-cli/<version>`.
- **API base default**: now `https://wiredepth.com` everywhere it
  was `https://postvale.app`.
- **Help text**: every `Long:` description reflects the EASM
  positioning instead of the original posture-checker framing.
- **Telemetry scaffolding**: opt-in CLI usage metrics live behind
  `wd config set telemetry=true`. Off by default; the wire-up to
  the API endpoint + privacy explainer is staged for v2.0.x.

## What ships next (v2.1)

The big surface change from the original proposal: command tree
reorganised from flat per-check commands (`wd tls`, `wd dmarc`,
etc) into EASM workflow verb groups (`wd scan`, `wd assets`, `wd
findings`, `wd watch`, `wd report`, `wd auth`, `wd config`).

The current flat commands stay as hidden aliases so muscle-memory
doesn't break, e.g. `wd tls example.com` still works (silently
runs as `wd scan run example.com --checks=tls`). README points
visitors at the new verbs; the legacy aliases are documented
under "Migration from postvale CLI".

## What ships in v2.2 (AI surface)

`wd ai brief` / `wd ai runbook <finding-id>` / `wd ai explain
<finding-id>` / `wd ai chat`. Routes to the existing
`/api/v1/dashboard/daily-brief` + `/api/v1/ir-runbook/*` endpoints;
the chat REPL adds a new server-side tool-use loop that lets the
LLM call our other API endpoints on the user's behalf.

## What ships in v2.3 (TUI mode + legacy cleanup)

- `wd live` (alias for `wd watch live`) - full-screen Bubble Tea
  TUI mirroring the dashboard Live Console.
- Drop the legacy `postvale` brand fallbacks: env vars, keyring
  service, config dir. Users have had two minor versions to migrate.

## CI / runner authentication

Browser-based OAuth-style PAT exchange (`wd auth login`) is the
default. Two-week deprecation window applies to its current shape
- no breaking changes through v2.x. CI runners that can't pop a
browser today use `WIREDEPTH_TOKEN=...` directly; a device-flow
companion is on the roadmap but not in scope for v2.0.

## Telemetry posture

- **Off by default.** Users opt in via `wd config set
  telemetry=true`.
- **No PII.** Events ship: command + subcommand name, flag names
  (NEVER values), exit code, wall-clock duration, OS, arch, CLI
  version.
- **No content.** Domain names, keywords, API tokens, file paths,
  and environment variable values are never collected.
- **No identity.** No IP, no email, no account id. Events are
  account-anonymous; the server side aggregates them across all
  users.
- **Endpoint.** HTTPS POST to `/api/v1/cli/telemetry`. Best-effort
  fire-and-forget; failure never blocks or surfaces in the
  foreground command. Batching + offline queueing TBD.
