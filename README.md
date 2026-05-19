# wd - WireDepth CLI

The official CLI for [WireDepth](https://wiredepth.com) - external
attack-surface monitoring with TLS / DMARC / DNS / threat-intel /
audit-chain evidence for any public domain.

Free + no signup for the read-only posture checks. Sign in for the
monitoring stack (findings, alerts, evidence packs, audit-chain
verification).

```
$ wd check example.com
> check check
  example.com

  Overall: B+

    tls         A    Cert valid · TLS 1.3 · HSTS preload
    dmarc       A    p=reject · alignment strict
    dns         B    DNSSEC ok · CAA missing
    headers     C    Missing CSP, COOP, COEP
    mta-sts     A    Enforced
```

## Install

```sh
curl -fsSL https://wiredepth.com/cli/install.sh | sh
```

Or grab a binary from the
[releases page](https://github.com/WiredepthHQ/cli/releases).

The install script auto-detects OS + arch, drops the `wd` binary
into `$HOME/.local/bin`, and prints a PATH-tweak hint if needed.

## Usage

### Public posture checks (no auth)

```sh
wd check example.com          # full report - TLS / DMARC / DNS / headers / MTA-STS
wd tls example.com            # just the TLS chain inspection
wd dmarc example.com          # DMARC + SPF + DKIM
wd dns example.com            # DNSSEC + CAA + MX + RBLs + registrar
wd headers example.com        # HTTP security headers
wd subdomains example.com     # CT-log subdomain enum (free tier returns top 10)
wd takeover sub.example.com   # CNAME + body-probe takeover check
wd spoofability example.com   # yes / maybe / no verdict
wd threat-intel example.com   # reputation feeds
```

Every check supports `--json` for scripting:

```sh
wd tls example.com --json | jq '.protocols'
```

### Sign in for monitoring + audit

```sh
wd auth login                 # browser-flow, token lands in OS keyring
wd auth whoami                # confirm identity
wd auth logout                # clear stored token
```

CI users skip the browser and set `WIREDEPTH_TOKEN` in the env
instead - higher priority than the keyring.

### Audit chain verification

```sh
wd audit anchors              # list daily Merkle roots WireDepth publishes
wd audit verify <export.jsonl> # verify the export against the anchors
```

The audit chain is hashed into a per-user daily Merkle tree, the
root is published at `/api/v1/audit/anchors`, and the root is
anchored to an external RFC 3161 TSA (DigiCert) so the timestamp
can't be backdated. The `verify` subcommand recomputes the chain
client-side. The same algorithm runs in your browser at
[wiredepth.com/verify](https://wiredepth.com/verify) with no
WireDepth account.

## Configuration

Precedence: CLI flag > env var > config file > default.

| Setting | Flag | Env | Config file key |
|---|---|---|---|
| API base URL | `--api` | `WIREDEPTH_API` | `API` |
| API token | (none) | `WIREDEPTH_TOKEN` | (use keyring) |
| Output mode | `--json` | - | - |

Config file: `~/.config/wiredepth/config` (or the platform
equivalent). One `KEY=value` per line, `#` comments allowed.

## License

MIT - see [LICENSE](./LICENSE).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Short version: `go fmt`
+ `go vet` + `go test` clean, no marketing prose in code comments,
no em-dashes.
