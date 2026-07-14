# Capture formats

corsdoctor reads two input formats and auto-detects which one it got: its
own **capture JSON** and browser **HAR** exports. A top-level `"log"` key
means HAR; anything else is parsed as capture JSON.

## Capture JSON

The smallest hand-writable description of a CORS exchange. Unknown fields
are rejected so a typo like `"reponse"` cannot silently drop half the
capture.

```json
{
  "request": {
    "method": "PUT",
    "url": "https://api.example.test/v1/items/42",
    "origin": "https://app.example.test",
    "headers": { "Content-Type": "application/json" },
    "credentials": true
  },
  "preflight": { "status": 204, "headers": { "Access-Control-Allow-Origin": "*" } },
  "response":  { "status": 200, "headers": { "Access-Control-Allow-Origin": "*" } }
}
```

| Field | Required | Notes |
|---|---|---|
| `request.url` | yes | absolute URL of the request |
| `request.origin` | yes* | serialized origin of the page; *falls back to an `Origin` header |
| `request.method` | no | defaults to `GET`; normalized the way browsers do |
| `request.headers` | no | object; values may be a string or an array of strings |
| `request.credentials` | no | `true`/`false` or fetch's `"include"`/`"same-origin"`/`"omit"` |
| `preflight` | no | the OPTIONS response: `status` (required) + `headers` |
| `response` | no | the actual response: `status` (required) + `headers` |

Array header values become separate fields — that is how you reproduce a
*duplicated* `Access-Control-Allow-Origin`, which browsers join with `", "`
and then reject.

What corsdoctor does with missing pieces:

- **No `preflight`, request needs one** → verdict `incomplete` (exit 3),
  with the exact preflight contract the server must meet.
- **No `response`** → the preflight is judged alone; verdict `incomplete`.
- **Neither** → verdict `advisory` (exit 0): a pure what-if listing every
  header the server will have to send.

## HAR

Save from any browser's network panel ("Save all as HAR"). corsdoctor
reads the subset it needs (`request.method/url/headers`,
`response.status/headers`) and does three non-obvious things:

1. **Entry selection** — `--url <substring>` picks the request to diagnose;
   the first non-preflight match wins and ambiguity is reported.
2. **Preflight pairing** — an `OPTIONS` entry with the same URL whose
   `Access-Control-Request-Method` matches the main method is attached as
   the preflight automatically.
3. **Reconstruction** — if the HAR contains *only* the preflight (the
   browser never sent the real request because the preflight failed), the
   intended request is rebuilt from `Access-Control-Request-Method` and
   `Access-Control-Request-Headers`, so the diagnosis still runs end to end.

### Known HAR limitations

- HAR does not record fetch's *credentials mode*. corsdoctor infers
  `include` when the request carried `Cookie` or `Authorization`, says so
  in the report, and lets `--credentials` / `--no-credentials` override.
- HAR cannot distinguish author-set headers from browser-added ones. The
  well-known browser-owned names (`User-Agent`, `Cookie`, `Sec-*`, …) are
  ignored for the preflight decision, but a `Cache-Control` added by a
  hard reload is indistinguishable from one your code set.
- HTTP/2 pseudo-headers (`:method`, `:path`, …) are dropped.
