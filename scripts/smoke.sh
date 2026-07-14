#!/usr/bin/env bash
# End-to-end smoke test for corsdoctor: builds the binary, runs it over the
# bundled example captures (JSON and HAR), the simulate subcommand, and
# stdin input, asserting on real CLI output and exit codes. No network,
# idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/corsdoctor"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/corsdoctor) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "corsdoctor 0.1.0" || fail "--version mismatch"

echo "3. allowed capture exits 0 and lists exposed headers"
OUT="$("$BIN" check "$ROOT/examples/allowed-simple.json")" || fail "allowed capture should exit 0"
echo "$OUT" | grep -q "verdict  ALLOWED" || fail "missing ALLOWED verdict"
echo "$OUT" | grep -q "x-request-id" || fail "exposed headers missing"

echo "4. missing Access-Control-Allow-Origin is blocked with the browser message"
set +e
OUT="$("$BIN" check "$ROOT/examples/blocked-missing-allow-origin.json")"
[ $? -eq 1 ] || fail "blocked capture should exit 1"
set -e
echo "$OUT" | grep -q "BLOCKED at response.allow-origin" || fail "failing step not named"
echo "$OUT" | grep -q "No 'Access-Control-Allow-Origin' header is present" || fail "browser message missing"

echo "5. wildcard + credentials is pinpointed at origin-match"
set +e
OUT="$("$BIN" check "$ROOT/examples/blocked-wildcard-credentials.json")"
[ $? -eq 1 ] || fail "wildcard+credentials should exit 1"
set -e
echo "$OUT" | grep -q "BLOCKED at response.origin-match" || fail "wrong failing step"
echo "$OUT" | grep -q "must not be the wildcard" || fail "wildcard message missing"

echo "6. preflight header coverage failure names the header and the fix"
set +e
OUT="$("$BIN" check "$ROOT/examples/blocked-preflight-header.json")"
[ $? -eq 1 ] || fail "preflight capture should exit 1"
set -e
echo "$OUT" | grep -q "BLOCKED at preflight.allow-headers" || fail "wrong failing step"
echo "$OUT" | grep -q "add x-api-key to Access-Control-Allow-Headers" || fail "fix missing"

echo "7. HAR with only a failed preflight is reconstructed and diagnosed"
set +e
OUT="$("$BIN" check "$ROOT/examples/failed-preflight.har")"
[ $? -eq 1 ] || fail "HAR diagnosis should exit 1"
set -e
echo "$OUT" | grep -q "reconstructed from Access-Control-Request-Method" || fail "reconstruction note missing"
echo "$OUT" | grep -q "Request header field authorization is not allowed" || fail "authorization diagnosis missing"

echo "8. JSON report is machine-readable and stable"
"$BIN" check --json "$ROOT/examples/allowed-simple.json" > "$WORKDIR/report.json" \
  || fail "json report should exit 0"
grep -q '"schema_version": 1' "$WORKDIR/report.json" || fail "json envelope missing"
grep -q '"outcome": "allowed"' "$WORKDIR/report.json" || fail "json outcome missing"

echo "9. stdin capture works"
"$BIN" check - < "$ROOT/examples/allowed-simple.json" | grep -q "ALLOWED" \
  || fail "stdin capture failed"

echo "10. simulate answers a what-if with server requirements"
OUT="$("$BIN" simulate --origin https://app.example.test \
  --url https://api.example.test/v1/items \
  --method DELETE -H 'X-Api-Key: k1' --credentials)" || fail "simulate should exit 0"
echo "$OUT" | grep -q "server requirements" || fail "requirements section missing"
echo "$OUT" | grep -q "Access-Control-Allow-Methods: DELETE" || fail "method requirement missing"

echo "11. --credentials flag flips the wildcard verdict"
set +e
"$BIN" check --credentials "$ROOT/examples/allowed-simple.json" >/dev/null
[ $? -eq 1 ] || fail "wildcard must fail once credentials are forced"
set -e

echo "12. usage errors exit 2"
set +e
"$BIN" check "$WORKDIR/does-not-exist.json" >/dev/null 2>&1
[ $? -eq 2 ] || fail "missing file should exit 2"
set -e

echo "SMOKE OK"
