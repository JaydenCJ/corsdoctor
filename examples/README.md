# corsdoctor examples

Each file is a self-contained capture you can feed straight to the CLI.
Run them from the repository root after `go build -o corsdoctor ./cmd/corsdoctor`.

| File | Scenario | Verdict (exit code) |
|---|---|---|
| `allowed-simple.json` | public API with `*` and `Expose-Headers` | allowed (0) |
| `blocked-missing-allow-origin.json` | server sends no CORS headers at all | blocked (1) |
| `blocked-wildcard-credentials.json` | `*` combined with cookies | blocked (1) |
| `blocked-preflight-header.json` | `x-api-key` missing from `Access-Control-Allow-Headers` | blocked (1) |
| `failed-preflight.har` | HAR with only the failed OPTIONS — the real request is reconstructed from `Access-Control-Request-*` | blocked (1) |

```bash
./corsdoctor check examples/blocked-preflight-header.json
./corsdoctor check examples/failed-preflight.har
./corsdoctor check --json examples/allowed-simple.json | head -20
```

No file? Ask a what-if question directly:

```bash
./corsdoctor simulate --origin https://app.example.test \
  --url https://api.example.test/v1/items \
  --method DELETE -H 'X-Api-Key: k1' --credentials
```
