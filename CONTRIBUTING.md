# Contributing to wd

## Style

- `gofmt -s` clean, `go vet ./...` clean, `go test ./...` clean
  before push. Pre-commit hook in `.githooks/pre-commit` (run
  `git config core.hooksPath .githooks` once)
- Short comments, WHY only. One line preferred, two lines max.
  Skip the comment entirely if the code is self-explanatory
- No marketing prose anywhere (commits, comments, README, docs)
- No em-dashes anywhere. Use ` - `, `. `, `; `, `: `, or
  parentheses
- No commented-out code; remove it or extract behind a flag

Bad:
```go
// GlobalFlags holds the values for the global flags. We use a
// package-scoped struct so individual commands can read them
// without having to re-define persistent flags everywhere.
type GlobalFlags struct {
```

Good:
```go
// Persistent flag values, populated by cobra before RunE fires.
type GlobalFlags struct {
```

## Project layout

```
cmd/wd/             main entry
internal/
  api/              HTTP client to wiredepth.com
  auth/             OS keyring token storage
  cmd/              cobra subcommand tree
  config/           config file + env var resolution
  output/           human-readable + JSON renderers
  version/          build stamps (set by ldflags)
docs/               docs published on wiredepth.com/docs
```

## Adding a check command

The webapp's `/api/v1/check/<tool>/<domain>` endpoint dispatches
to the right check library. To add a new `wd <tool>` subcommand:

1. Add an entry to the `checks` slice in `internal/cmd/check.go`
2. Add a tool-specific renderer to `internal/output/render.go`
   if the default JSON fallback isn't readable enough
3. No webapp changes needed if the tool is already in the
   webapp's `ALLOWED_TOOLS` set

## Pre-push checklist

1. `gofmt -s -l .` returns empty
2. `go vet ./...` clean
3. `go build ./...` clean
4. `go test ./...` clean
5. Em-dash grep returns empty:
   ```sh
   LC_ALL=en_US.UTF-8 grep -rnP "[—–]" --include='*.go' \
     --include='*.md' --include='*.sh' --include='*.yaml' .
   ```
6. No hardcoded secrets, tokens, customer domains, or internal
   URLs in the diff
7. No `io.ReadAll` on untrusted bodies without `io.LimitReader`
8. No debug `fmt.Println` left over
9. Commit message in Conventional Commits

## Release process

Tags drive releases via goreleaser. To cut `v3.1.0`:

```sh
git tag v3.1.0
git push origin v3.1.0
```

GitHub Actions builds binaries for darwin/linux/windows on amd64
+ arm64 and publishes them to the
[releases page](https://github.com/WiredepthHQ/cli/releases).
The install.sh + the wiredepth.com/cli page both point at the
latest release.

## License

MIT. By contributing you agree your work is licensed under MIT.
