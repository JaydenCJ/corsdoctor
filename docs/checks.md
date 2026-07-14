# The checks, in browser order

corsdoctor is an implementation of the CORS algorithm from the WHATWG
Fetch standard, run over a capture instead of a live request. This page
lists every step it evaluates, in the order a browser runs them, with the
stable failure `code` emitted in JSON output. Section numbers drift in the
living standard, so steps are cited by algorithm name.

## Phase 0 — request classification (request side)

Decides whether the browser sends a preflight at all. Not a pass/fail
check — its output is the *contract* the server must meet.

| Rule | Detail |
|---|---|
| method safelist | only byte-exact `GET`, `HEAD`, `POST` skip the preflight; the six normalizable methods are uppercased first (PATCH is not one of them) |
| forbidden headers | browser-owned headers (`Cookie`, `User-Agent`, `Origin`, `Sec-*`, `Proxy-*`, …) never trigger a preflight |
| header safelist | only `accept`, `accept-language`, `content-language`, `content-type`, `range` can skip it, and only with conforming values |
| value rules | `content-type` essence must be one of the three form types; languages have a tight byte set; `range` must be a single explicit-start bytes range |
| size rules | any value > 128 bytes, or > 1024 bytes of safelisted values combined, forces the preflight |

The resulting unsafe-name list (lowercased, sorted) is exactly what the
browser sends as `Access-Control-Request-Headers`.

## Phase 1 — CORS-preflight fetch (against the OPTIONS response)

| Step ID | Failure code(s) | What must hold |
|---|---|---|
| `preflight.allow-origin` | `missing-allow-origin` | `Access-Control-Allow-Origin` is present |
| `preflight.origin-match` | `origin-mismatch`, `multiple-allow-origin-values`, `wildcard-with-credentials` | value is `*` (credentials omitted) or byte-equals the serialized origin |
| `preflight.allow-credentials` | `credentials-flag` | with credentials: value is exactly `true` |
| `preflight.status` | `preflight-status`, `preflight-redirect` | 2xx; a redirect is a dedicated failure |
| `preflight.allow-methods` | `method-not-allowed` | method listed byte-exactly, or CORS-safelisted, or `*` without credentials |
| `preflight.allow-headers` | `header-not-allowed` | every unsafe name covered case-insensitively; `*` is literal with credentials and never covers `authorization` |

## Phase 2 — CORS check (against the actual response)

| Step ID | Failure code(s) | What must hold |
|---|---|---|
| `response.allow-origin` | `missing-allow-origin` | header present |
| `response.origin-match` | `origin-mismatch`, `multiple-allow-origin-values`, `wildcard-with-credentials` | same rules as the preflight |
| `response.allow-credentials` | `credentials-flag` | with credentials: exactly `true` |

When the preflight fails, phase 2 is reported as skipped — the browser
never sends the request — but every phase-1 step is still evaluated so one
run surfaces *all* the problems, not just the first.

## Beyond pass/fail

- **Origin-mismatch diagnosis** names the structural cause: multiple
  values, trailing slash/path, scheme, port (with default-port elision),
  case, or a related-subdomain trap.
- **Warnings** flag hazards that do not block: origin echoed without
  `Vary: Origin`, `Access-Control-Allow-Origin: null`, a captured
  preflight that would fail if the browser ever needed one.
- **Notes** surface context: method normalization, `Access-Control-Max-Age`
  caching (a stale cached preflight keeps failing after a server fix),
  HAR credential inference.
- **Exposed headers** lists what page JavaScript can actually read on an
  allowed response: the safelisted response headers plus
  `Access-Control-Expose-Headers` grants, with the wildcard-vs-credentials
  rule applied.
