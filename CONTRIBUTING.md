# Contributing to corsdoctor

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else.

```bash
git clone https://github.com/JaydenCJ/corsdoctor && cd corsdoctor
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives it end to end over the
bundled example captures — JSON, HAR, stdin, simulate, exit codes — and
must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (89 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the `cors` engine never touches I/O — only `cli` reads files).

## Ground rules

- Keep dependencies at zero — corsdoctor is standard library only, and a
  diagnosis tool people paste captures into must stay auditable.
- No network calls, ever. Captures are read from disk or stdin; nothing is
  fetched, nothing is sent. No telemetry.
- Spec-faithfulness first: every check cites the Fetch-standard algorithm
  it implements, and a behavior change needs a matching citation in
  `docs/checks.md`.
- Diagnoses must be honest: if corsdoctor cannot prove a failure from the
  capture, the verdict is `incomplete` or `advisory` — never a guess.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `corsdoctor version`, the full command you ran, and
the capture file (redact hostnames and header values if needed — the
header *names*, status codes, and the `Access-Control-*` values are what
the algorithm sees). If a real browser disagrees with corsdoctor's
verdict, paste the browser's console message too: that comparison is
exactly what makes the report actionable.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
