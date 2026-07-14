// In-process CLI integration tests: Run(argv, stdin, stdout, stderr) is the
// whole binary surface, so these cover argument parsing, exit codes, file
// and stdin input, and both output formats without building anything.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run invokes the CLI and returns (exitCode, stdout, stderr).
func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// writeCapture drops a capture JSON into a temp dir and returns its path.
func writeCapture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const blockedCapture = `{
	"request": {"method": "GET", "url": "https://api.example.test/data", "origin": "https://app.example.test"},
	"response": {"status": 200, "headers": {"Content-Type": "application/json"}}
}`

const allowedCapture = `{
	"request": {"method": "GET", "url": "https://api.example.test/data", "origin": "https://app.example.test"},
	"response": {"status": 200, "headers": {"Access-Control-Allow-Origin": "*"}}
}`

func TestCLI_VersionAndHelp(t *testing.T) {
	code, out, _ := run(t, "", "version")
	if code != 0 || out != "corsdoctor 0.1.0\n" {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, "", "--help")
	if code != 0 || !strings.Contains(out, "exit codes: 0 allowed") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}
}

func TestCLI_CheckBlockedExitsOne(t *testing.T) {
	code, out, _ := run(t, "", "check", writeCapture(t, blockedCapture))
	if code != ExitBlocked {
		t.Fatalf("blocked capture must exit 1, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "verdict  BLOCKED at response.allow-origin") {
		t.Fatalf("report must name the failing step:\n%s", out)
	}
}

func TestCLI_CheckAllowedExitsZero_AlsoAsBarePath(t *testing.T) {
	path := writeCapture(t, allowedCapture)
	code, out, _ := run(t, "", "check", path)
	if code != ExitAllowed || !strings.Contains(out, "verdict  ALLOWED") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	// A bare path (no subcommand) must behave exactly like check.
	code, out, _ = run(t, "", path)
	if code != ExitAllowed || !strings.Contains(out, "verdict  ALLOWED") {
		t.Fatalf("bare path must behave like check: code=%d\n%s", code, out)
	}
}

func TestCLI_JSONOutputParsesAndCarriesExitCode(t *testing.T) {
	code, out, _ := run(t, "", "check", "--json", writeCapture(t, blockedCapture))
	if code != ExitBlocked {
		t.Fatalf("code=%d", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["exit_code"] != float64(1) || got["outcome"] != "blocked" {
		t.Fatalf("envelope wrong: %v", got)
	}
}

func TestCLI_ReadsCaptureFromStdin(t *testing.T) {
	code, out, _ := run(t, allowedCapture, "check", "-")
	if code != ExitAllowed || !strings.Contains(out, "ALLOWED") {
		t.Fatalf("stdin capture failed: code=%d\n%s", code, out)
	}
}

func TestCLI_UsageErrorsExitTwo(t *testing.T) {
	if code, _, errOut := run(t, ""); code != ExitUsage || !strings.Contains(errOut, "usage") {
		t.Fatalf("no args: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := run(t, "", "check", "/does/not/exist.json"); code != ExitUsage || !strings.Contains(errOut, "reading capture") {
		t.Fatalf("missing file: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := run(t, "", "check", "--credentials", "--no-credentials", writeCapture(t, allowedCapture)); code != ExitUsage || !strings.Contains(errOut, "conflict") {
		t.Fatalf("conflicting flags: code=%d err=%q", code, errOut)
	}
	if code, _, errOut := run(t, "", "--bogus"); code != ExitUsage || !strings.Contains(errOut, "--bogus") {
		t.Fatalf("unknown flag: code=%d err=%q", code, errOut)
	}
}

func TestCLI_CredentialsFlagFlipsTheVerdict(t *testing.T) {
	// The wildcard passes without credentials and fails with them; the
	// override flag must be able to demonstrate both from one capture.
	path := writeCapture(t, allowedCapture)
	if code, _, _ := run(t, "", "check", path); code != ExitAllowed {
		t.Fatal("baseline must be allowed")
	}
	code, out, _ := run(t, "", "check", "--credentials", path)
	if code != ExitBlocked || !strings.Contains(out, "wildcard") {
		t.Fatalf("with credentials the wildcard must fail: code=%d\n%s", code, out)
	}
}

func TestCLI_IncompleteCaptureExitsThree(t *testing.T) {
	capture := `{
		"request": {"method": "PUT", "url": "https://api.example.test/x", "origin": "https://app.example.test"},
		"response": {"status": 200, "headers": {"Access-Control-Allow-Origin": "*"}}
	}`
	code, out, _ := run(t, "", "check", writeCapture(t, capture))
	if code != ExitIncomplete || !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("preflight-required-but-uncaptured must exit 3: code=%d\n%s", code, out)
	}
}

func TestCLI_SimulateAdvisoryMode(t *testing.T) {
	code, out, _ := run(t, "", "simulate",
		"--origin", "https://app.example.test",
		"--url", "https://api.example.test/items",
		"--method", "DELETE",
		"-H", "X-Api-Key: k1",
		"--credentials")
	if code != ExitAllowed {
		t.Fatalf("advisory exits 0, got %d\n%s", code, out)
	}
	for _, want := range []string{"server requirements", "Access-Control-Allow-Methods: DELETE", "x-api-key"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestCLI_SimulateFullExchange(t *testing.T) {
	code, out, _ := run(t, "", "simulate",
		"--origin", "https://app.example.test",
		"--url", "https://api.example.test/items",
		"--method", "PUT",
		"--preflight-status", "204",
		"--preflight-header", "Access-Control-Allow-Origin: *",
		"--preflight-header", "Access-Control-Allow-Methods: PUT",
		"--status", "200",
		"--response-header", "Access-Control-Allow-Origin: *")
	if code != ExitAllowed || !strings.Contains(out, "verdict  ALLOWED") {
		t.Fatalf("code=%d\n%s", code, out)
	}
}

func TestCLI_SimulateUsageErrors(t *testing.T) {
	// --origin and --url are required.
	if code, _, errOut := run(t, "", "simulate", "--url", "https://a.test/"); code != ExitUsage || !strings.Contains(errOut, "--origin") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	// A malformed -H value must be rejected, not silently dropped.
	if code, _, _ := run(t, "", "simulate", "--origin", "https://a.test", "--url", "https://b.test/", "-H", "no-colon"); code != ExitUsage {
		t.Fatal("malformed header flag must be a usage error")
	}
	// Preflight headers without a status make no sense.
	if code, _, errOut := run(t, "", "simulate", "--origin", "https://a.test", "--url", "https://b.test/",
		"--preflight-header", "X: y"); code != ExitUsage || !strings.Contains(errOut, "--preflight-status") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}
