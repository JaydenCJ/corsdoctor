# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Request-side classification implementing Fetch's CORS safelists:
  method normalization (the six normalizable methods; the PATCH byte-case
  trap), per-header value rules (`content-type` essences, language byte
  sets, single-range `Range`), the 128-byte value and 1024-byte aggregate
  limits, and the forbidden (browser-owned) header list so wire captures
  never produce false preflight triggers.
- Full "CORS check" evaluation against preflight and actual responses:
  presence, wildcard-vs-credentials, byte-exact origin comparison with
  structural mismatch diagnosis (multiple values, trailing slash/path,
  scheme, port with default-port elision, host case, subdomains), and the
  byte-case-sensitive `Access-Control-Allow-Credentials: true` rule.
- "CORS-preflight fetch" evaluation: ok-status with a dedicated redirect
  failure and status-class fixes (401/403 auth middleware, 404/405 missing
  OPTIONS route), byte-exact `Access-Control-Allow-Methods` coverage,
  case-insensitive `Access-Control-Allow-Headers` coverage, and the
  wildcard rules including the `Authorization` non-wildcard exception.
- Verdicts that pinpoint the failing step (`blocked at
  preflight.allow-headers`), reconstruct the Chrome-style console message,
  and propose concrete fixes, including the cross-phase "your middleware
  only decorates OPTIONS" hint.
- Input formats: a strict hand-writable capture JSON
  (docs/capture-format.md) and HAR ingestion with entry selection
  (`--url`), automatic preflight pairing, credential inference from
  Cookie/Authorization, and reconstruction of the intended request from a
  failed preflight's `Access-Control-Request-*` headers.
- `check` (file or stdin) and `simulate` (pure what-if with server
  requirements) subcommands; human text reports and a stable JSON envelope
  (`schema_version: 1`); exit codes 0 allowed / 1 blocked / 2 usage /
  3 incomplete capture.
- Warnings and notes: `Vary: Origin` cache hazard, `null`-origin allowance,
  `Access-Control-Max-Age` stale-preflight caching, exposed-header listing
  with the wildcard-vs-credentials rule.
- Runnable example captures (`examples/`), format and algorithm references
  (`docs/capture-format.md`, `docs/checks.md`).
- 89 deterministic offline tests (unit + in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/corsdoctor/releases/tag/v0.1.0
