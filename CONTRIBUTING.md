# Contributing

Thanks for the interest! A few things to know before opening a PR.

## Local dev

```sh
git clone https://github.com/postvaleapp/postvale-cli.git
cd postvale-cli
go build ./...
go test ./...
go run ./cmd/postvale --help
```

Go 1.23+ required.

## Project layout

```
cmd/postvale/        Entry point - main.go only
internal/api/        HTTP client to postvale.app + typed response shapes
internal/auth/       Token storage (OS keyring with file fallback)
internal/commands/   Cobra command tree (one file per subcommand)
internal/output/     Lipgloss styles + per-check renderers + JSON
internal/tui/        Bubbletea models for `postvale tui`
internal/version/    Build stamps (overridden via -ldflags at release)
```

## Style

- `gofmt -s` clean (CI checks this)
- `go vet` clean
- Comments on exported functions explain WHY, not just what
- No `panic()` in command code - return errors and let cobra handle them
- Output renderers never call `os.Exit` directly - that's the command's job
- New commands go in `internal/commands/<name>.go` + wire into `root.go`

## Adding a new check command

1. Add the API method in `internal/api/checks.go` with its response type
2. Add the renderer in `internal/output/check.go`
3. Add the command in `internal/commands/<name>.go` (copy `tls.go` as a template)
4. Wire it into `NewRootCommand()` in `internal/commands/root.go`
5. Add the entry to `README.md` and `CHANGELOG.md`

## Tests

```sh
go test ./...                # full suite
go test -run TestName ./...  # one test
go test -race ./...          # race detector
```

## License

By contributing you agree your work is licensed under MIT.
