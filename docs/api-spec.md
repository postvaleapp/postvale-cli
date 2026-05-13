# CLI ↔ API contract

The CLI calls a generic check endpoint on the Postvale API:

```
GET /api/v1/check/<tool>/<domain>
```

Where `<tool>` is one of:

```
tls dmarc dns headers mta-sts bimi dnssec caa
subdomains takeover spoofability spf-flatten threat-intel full
```

Each tool returns the JSON-serialised result of the matching
`/lib/checks/<tool>` library. Response shapes are pinned in
`internal/api/checks.go`.

## Webapp-side requirements

To keep the CLI a thin wrapper, the API endpoint must:

- Validate the tool slug against an allowlist
- Validate the domain via the shared domain schema
- Apply the per-IP rate-limit via `freeBurstGate('cli-check')`
- Return CORS headers via `extensionCorsHeaders`
- Return the existing check library's result struct as-is
- Wrap errors as `{ error: 'code', message: 'human text' }` with
  the appropriate HTTP status

## Non-check routes

| CLI command | Method | Path | Notes |
|---|---|---|---|
| `postvale scam` | POST | `/api/v1/triage` | Already exists |
| `postvale auth login` | POST | `/api/v1/cli/exchange` | Phase 2 |
| `postvale watch ...` | POST | `/api/v1/domains` | Phase 2 |
| `postvale alerts` | GET | `/api/v1/alerts` | Already exists |
| `postvale workpaper` | GET | `/api/v1/workpapers/<type>/<domain>` | Phase 2 |

## Backward compatibility

The CLI pins to `v1`. Breaking changes to a check shape go in
`v2` paths. Adding fields to existing shapes is non-breaking
(the CLI ignores fields it doesn't know about).
