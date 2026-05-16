# Cloudflare bot-challenge bypass

Postvale's API sits behind Cloudflare. Cloudflare auto-challenges
requests from IP ranges with a high bot score - GitHub Actions
runners, AWS Lambda IPs, the Vercel build pool, Tor exits, public
VPNs, and most cloud datacenter ranges. When that happens the API
returns:

```
403 Forbidden
<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
```

The CLI catches this and prints a one-liner pointing back at this
file. Real options below, ordered by who has to act.

## Operator side (you, the wiredepth.com admin)

This is the only fix that makes the CLI work for all your customers
from cloud / CI environments. Two paths:

### Option A - allowlist /api/v1/* (recommended)

Tell Cloudflare not to bot-challenge any path under `/api/v1/`. The
public check endpoints are explicitly designed to be hit by scripts;
they have their own per-IP `freeBurstGate('cli-check')` rate limit,
so dropping the bot challenge doesn't open the door to abuse.

In the Cloudflare dashboard for wiredepth.com:

1. **Security -> WAF -> Custom rules -> Create rule**
2. Name: "Skip bot challenge for /api/v1"
3. Field: URI Path. Operator: starts with. Value: `/api/v1/`
4. Action: **Skip** -> "All managed rules" + "Super Bot Fight Mode"
5. Deploy

Test from a known-flagged IP (a GitHub Actions runner, or `curl`
from a Hetzner box). 200 response = working.

### Option B - require a CI bypass header

If you'd rather keep the challenge on by default and bypass it only
for trusted callers, set up a header-gated skip:

1. Generate a 32-byte secret. Store as `CF_CI_BYPASS_SECRET` in
   your CI / build env.
2. Cloudflare WAF -> Create rule
3. Field: HTTP Request Header. Header: `X-Postvale-CI`. Value:
   equals `<secret>`
4. Action: Skip "All managed rules" + "Super Bot Fight Mode"
5. Patch the CLI to send the header when `POSTVALE_CI_BYPASS` env
   var is set:
   ```go
   if v := os.Getenv("POSTVALE_CI_BYPASS"); v != "" {
       req.Header.Set("X-Postvale-CI", v)
   }
   ```
6. In your CI:
   ```yaml
   env:
     POSTVALE_CI_BYPASS: ${{ secrets.CF_CI_BYPASS_SECRET }}
   ```

This is more complex than Option A and protects nothing the per-IP
rate limit doesn't already protect, but it's there if you want it.

### Option C - allowlist specific IP ranges

Cloudflare publishes GitHub Actions runner IP ranges; AWS publishes
the same for Lambda + EC2; Vercel for their build pool. You can
allowlist these in Cloudflare's IP Access Rules. Maintenance
burden is real - lists change quarterly. Skip unless you have a
specific compliance reason to keep the bot challenge on for
`/api/v1/`.

## CLI / customer side

If you're a customer hitting this from your CI or a cloud VM and
you don't control the Cloudflare config:

- **Retry locally** to confirm: same `postvale check ...` command
  from a laptop on residential broadband should succeed. That
  isolates Cloudflare as the cause.
- **Run the CLI from a non-datacenter IP**. Most office /
  home / mobile networks have a low-enough bot score to pass.
- **Open a support ticket** with the API operator (the org running
  Postvale) and ask for Option B above. Solo-founder Postvale
  customers shouldn't have to do this - we'll either pre-allowlist
  major CI ranges or expose Option B by default. Open until that
  ships.

## Why not just send a fake User-Agent

We already send `postvale-cli/<version> (+https://github.com/...)`.
Cloudflare's bot fight mode evaluates UA, IP reputation, request
patterns, and TLS fingerprint together. Setting a "browsery" UA
is detected as a bot-bypass attempt and the score gets worse, not
better.

## Integration tests in CI

The opt-in integration test (`POSTVALE_LIVE_TESTS=1`) detects the
Cloudflare challenge response (`api.IsCloudflareChallenge(err)`)
and `t.Skip`s the affected subtests rather than failing the build.
Locally, the same tests pass against a non-flagged IP. The check is
loud (`Skip:` shows up clearly in the test output) so a regression
in shape coverage still surfaces as fast as the network policy
allows.
