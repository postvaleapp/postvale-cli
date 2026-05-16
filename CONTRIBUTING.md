# Contributing

Thanks for the interest! A few things to know before opening a PR.

## Local dev

```sh
git clone https://github.com/WiredepthHQ/cli.git
cd postvale-cli
go build ./...
go test ./...
go run ./cmd/postvale --help
```

Go 1.24+ required.

## Project layout

```
cmd/postvale/        Entry point - main.go only
internal/api/        HTTP client to wiredepth.com + typed response shapes
internal/commands/   Cobra command tree (one file per subcommand)
internal/output/     Lipgloss styles + per-check renderers + JSON
internal/version/    Build stamps (overridden via -ldflags at release)
```

API contract is documented in [`docs/api-spec.md`](docs/api-spec.md).

## Code style

- `gofmt -s` clean (CI checks this).
- `go vet` clean.
- Tab indent (Go default).
- Prefer stdlib over deps. Small focused deps are fine.
- One package per concern; keep `internal/` flat.
- No `panic()` in command code - return errors, let cobra handle them.
- Output renderers never call `os.Exit`; that's the command's job.

## Comments

Short. One line preferred, two max. Explain WHY, never WHAT.

- The code shows what; don't restate it.
- Skip the comment entirely if the code is self-explanatory.
- Package-level docstrings: one sentence.
- Don't list alternatives considered. That goes in a design doc.

## Prose style

No em-dashes (use ` - `, `. `, `; `, `: `, or parentheses).
Applies to comments, doc strings, READMEs, and commit messages.

## Security review

Read the diff line by line before pushing. Watch for:

- Hardcoded secrets, tokens, customer data, internal URLs
- Unbounded reads (`io.ReadAll` on untrusted bodies; use
  `io.LimitReader`)
- Unvalidated user input reaching HTTP, filesystem, or exec paths
- New dependencies that haven't been vetted (license, last
  maintenance, transitive deps)
- Debug `fmt.Println` / `log.Printf` or commented-out code
- TLS skip-verify or insecure defaults

CLI-specific:

- File path arguments must not allow reads outside what the user
  asked for (no glob expansion on untrusted input, no symlink-
  following without intent).
- `--token` on a shell command line is visible in `ps aux`.
  Docs must point users at env vars or stored credentials.
- The API base URL is user-supplied via `--api`; always re-parse
  via `url.Parse` and check scheme/host before use.
- Response parsing must tolerate malformed/missing fields without
  crashing.

## Dependencies

Run `go mod tidy` before every commit. New dep checklist:

- License compatible with MIT (MIT, BSD-2/3, Apache-2.0, ISC, MPL-2.0)
- Active maintenance (commits in last 12 months)
- Reasonable transitive footprint
- No known CVEs (`govulncheck ./...` before push)

## Adding a new check command

1. Add the API method in `internal/api/checks.go` with its response type
2. Add the renderer in `internal/output/check.go`
3. Add the command in `internal/commands/<name>.go` (copy `tls.go` as a template)
4. Wire it into `NewRootCommand()` in `internal/commands/root.go`
5. Add the entry to `README.md` and `CHANGELOG.md`

## Tests

- New exported function: add a test
- Parsers / formatters: table-driven
- Integration tests against a real Postvale instance go in
  `tests/e2e/` and are gated by `POSTVALE_E2E=1`

## Commits

[Conventional Commits](https://www.conventionalcommits.org/). Lower
case. Imperative mood.

```
feat(commands): add postvale watch
fix(api): handle 429 rate-limit response
chore: bump cobra to v1.10.2
docs: clarify CI integration example
```

First line under 72 chars. Empty line + body if more context is
needed.

## Releases

- SemVer; `v0.x.y` while pre-1.0, breaking changes allowed in
  minor bumps.
- Tagging `vX.Y.Z` triggers GoReleaser via
  `.github/workflows/release.yml`.
- Update `CHANGELOG.md` in the same commit as the tag.

## License

By contributing you agree your work is licensed under MIT.
