// Package cli implements the corsdoctor command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JaydenCJ/corsdoctor/internal/capture"
	"github.com/JaydenCJ/corsdoctor/internal/cors"
	"github.com/JaydenCJ/corsdoctor/internal/report"
	"github.com/JaydenCJ/corsdoctor/internal/version"
)

// Exit codes. Documented in the README; scripts can gate on them.
const (
	ExitAllowed    = 0 // allowed / not-cors / advisory
	ExitBlocked    = 1 // a CORS check failed
	ExitUsage      = 2 // bad flags or unusable input
	ExitIncomplete = 3 // nothing failed, but the capture is missing a message
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdin, stdout, stderr)
	case "simulate":
		return runSimulate(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "corsdoctor %s\n", version.Version)
		return ExitAllowed
	case "help", "--help", "-h":
		usage(stdout)
		return ExitAllowed
	default:
		if strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(stderr, "corsdoctor: unknown flag %q before a subcommand\n\n", args[0])
			usage(stderr)
			return ExitUsage
		}
		// Bare path: treat as `check <path>`.
		return runCheck(args, stdin, stdout, stderr)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `corsdoctor — explains exactly why a CORS request fails

usage:
  corsdoctor check <capture.json|capture.har|-> [flags]
  corsdoctor simulate --origin <origin> --url <url> [flags]
  corsdoctor version

check flags:
  --json               machine-readable report instead of text
  --url <substring>    pick the HAR entry to diagnose (substring match)
  --credentials        force credentials mode "include"
  --no-credentials     force credentials mode "omit"

simulate flags:
  --origin <origin>              the requesting page's origin (required)
  --url <url>                    the request URL (required)
  --method <m>                   request method (default GET)
  -H, --header 'Name: value'     request header (repeatable)
  --credentials                  send with credentials
  --preflight-status <n>         status of the OPTIONS response
  --preflight-header 'N: v'      preflight response header (repeatable)
  --status <n>                   status of the actual response
  --response-header 'N: v'       actual response header (repeatable)
  --json                         machine-readable report

exit codes: 0 allowed/advisory, 1 blocked, 2 usage error, 3 incomplete capture
`)
}

// headerFlag is a repeatable "Name: value" flag.
type headerFlag struct{ headers cors.Headers }

func (h *headerFlag) String() string { return fmt.Sprintf("%d headers", len(h.headers)) }
func (h *headerFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("want 'Name: value', got %q", v)
	}
	h.headers = append(h.headers, cors.Header{
		Name:  strings.TrimSpace(name),
		Value: strings.TrimSpace(value),
	})
	return nil
}

func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable report")
	urlFilter := fs.String("url", "", "pick the HAR entry to diagnose (substring match)")
	withCreds := fs.Bool("credentials", false, `force credentials mode "include"`)
	withoutCreds := fs.Bool("no-credentials", false, `force credentials mode "omit"`)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "corsdoctor check: exactly one capture file (or -) is required")
		return ExitUsage
	}
	if *withCreds && *withoutCreds {
		fmt.Fprintln(stderr, "corsdoctor check: --credentials and --no-credentials conflict")
		return ExitUsage
	}

	path := fs.Arg(0)
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "corsdoctor: reading capture: %v\n", err)
		return ExitUsage
	}

	opts := capture.Options{URLFilter: *urlFilter}
	if *withCreds {
		t := true
		opts.Credentials = &t
	}
	if *withoutCreds {
		f := false
		opts.Credentials = &f
	}
	c, err := capture.Parse(data, opts)
	if err != nil {
		fmt.Fprintf(stderr, "corsdoctor: %v\n", err)
		return ExitUsage
	}
	return diagnose(c, *asJSON, stdout, stderr)
}

func runSimulate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable report")
	origin := fs.String("origin", "", "the requesting page's origin")
	reqURL := fs.String("url", "", "the request URL")
	method := fs.String("method", "GET", "request method")
	credentials := fs.Bool("credentials", false, "send with credentials")
	preflightStatus := fs.Int("preflight-status", 0, "status of the OPTIONS response")
	status := fs.Int("status", 0, "status of the actual response")
	var reqHeaders, preflightHeaders, respHeaders headerFlag
	fs.Var(&reqHeaders, "H", "request header 'Name: value' (repeatable)")
	fs.Var(&reqHeaders, "header", "request header 'Name: value' (repeatable)")
	fs.Var(&preflightHeaders, "preflight-header", "preflight response header (repeatable)")
	fs.Var(&respHeaders, "response-header", "actual response header (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "corsdoctor simulate: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	if *origin == "" || *reqURL == "" {
		fmt.Fprintln(stderr, "corsdoctor simulate: --origin and --url are both required")
		return ExitUsage
	}

	c := cors.Capture{
		Request: cors.Request{
			Method:      *method,
			URL:         *reqURL,
			Origin:      *origin,
			Headers:     reqHeaders.headers,
			Credentials: *credentials,
		},
	}
	if *preflightStatus != 0 || len(preflightHeaders.headers) > 0 {
		if *preflightStatus == 0 {
			fmt.Fprintln(stderr, "corsdoctor simulate: --preflight-header given without --preflight-status")
			return ExitUsage
		}
		c.Preflight = &cors.Response{Status: *preflightStatus, Headers: preflightHeaders.headers}
	}
	if *status != 0 || len(respHeaders.headers) > 0 {
		if *status == 0 {
			fmt.Fprintln(stderr, "corsdoctor simulate: --response-header given without --status")
			return ExitUsage
		}
		c.Response = &cors.Response{Status: *status, Headers: respHeaders.headers}
	}
	return diagnose(c, *asJSON, stdout, stderr)
}

// diagnose evaluates the capture and renders the report.
func diagnose(c cors.Capture, asJSON bool, stdout, stderr io.Writer) int {
	v, err := cors.Evaluate(c)
	if err != nil {
		fmt.Fprintf(stderr, "corsdoctor: %v\n", err)
		return ExitUsage
	}
	code := exitCode(v.Outcome)
	if asJSON {
		if err := report.JSON(stdout, v, code); err != nil {
			fmt.Fprintf(stderr, "corsdoctor: %v\n", err)
			return ExitUsage
		}
		return code
	}
	report.Text(stdout, v)
	return code
}

func exitCode(o cors.Outcome) int {
	switch o {
	case cors.OutcomeBlocked:
		return ExitBlocked
	case cors.OutcomeIncomplete:
		return ExitIncomplete
	default:
		return ExitAllowed
	}
}
