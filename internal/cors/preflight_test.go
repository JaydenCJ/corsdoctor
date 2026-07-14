// Tests for the response side of "CORS-preflight fetch": the ok-status
// requirement and the methods/headers coverage checks, including the
// wildcard and byte-case traps.
package cors

import (
	"strings"
	"testing"
)

// pf runs a preflight evaluation with a passing CORS check baked in, so
// each test exercises exactly one downstream step.
func pf(t *testing.T, credentials bool, method string, unsafeNames []string, status int, extra ...string) []Step {
	t.Helper()
	headers := append([]string{"Access-Control-Allow-Origin: https://app.example.test"}, extra...)
	if credentials {
		headers = append(headers, "Access-Control-Allow-Credentials: true")
	}
	return evaluatePreflight(appOrigin, credentials, method, unsafeNames, resp(status, headers...))
}

func TestPreflight_RedirectFailsWithItsOwnCode(t *testing.T) {
	// Browsers report redirected preflights with a dedicated error; so do we.
	steps := pf(t, false, "PUT", nil, 308, "Access-Control-Allow-Methods: PUT")
	s := stepByID(t, steps, "preflight.status")
	if s.Status != StatusFail || s.Code != CodePreflightRedirect {
		t.Fatalf("308 must fail as a redirect, got %+v", s)
	}
	if !strings.Contains(s.Fix, "redirect") {
		t.Fatalf("the fix must mention redirects, got %q", s.Fix)
	}
}

func TestPreflight_StatusFixBlamesTheUsualCulprit(t *testing.T) {
	// 2xx passes; each failing class points at its real-world cause.
	steps := pf(t, false, "PUT", nil, 204, "Access-Control-Allow-Methods: PUT")
	if s := stepByID(t, steps, "preflight.status"); s.Status != StatusPass {
		t.Fatalf("204 is an ok status, got %+v", s)
	}
	steps = pf(t, false, "PUT", nil, 401, "Access-Control-Allow-Methods: PUT")
	s := stepByID(t, steps, "preflight.status")
	if s.Status != StatusFail || s.Code != CodePreflightStatus || !strings.Contains(s.Fix, "auth") {
		t.Fatalf("401 should fail and point at auth middleware, got %+v", s)
	}
	steps = pf(t, false, "PUT", nil, 405, "Access-Control-Allow-Methods: PUT")
	if s := stepByID(t, steps, "preflight.status"); !strings.Contains(s.Fix, "OPTIONS handler") {
		t.Fatalf("405 should point at the missing OPTIONS route, got %q", s.Fix)
	}
}

func TestPreflight_MethodListedOrSafelistedPasses(t *testing.T) {
	steps := pf(t, true, "DELETE", nil, 204, "Access-Control-Allow-Methods: PUT, DELETE")
	if s := stepByID(t, steps, "preflight.allow-methods"); s.Status != StatusPass {
		t.Fatalf("listed method must pass, got %+v", s)
	}
	// A POST that preflights because of its headers is allowed even when
	// Access-Control-Allow-Methods is entirely absent.
	steps = pf(t, false, "POST", []string{"x-api-key"}, 204, "Access-Control-Allow-Headers: x-api-key")
	s := stepByID(t, steps, "preflight.allow-methods")
	if s.Status != StatusPass || !strings.Contains(s.Detail, "CORS-safelisted") {
		t.Fatalf("safelisted POST must pass without listing, got %+v", s)
	}
}

func TestPreflight_MissingAllowMethodsFailsUnsafeMethod(t *testing.T) {
	steps := pf(t, false, "PUT", nil, 204)
	s := stepByID(t, steps, "preflight.allow-methods")
	if s.Status != StatusFail || s.Code != CodeMethodNotAllowed {
		t.Fatalf("PUT with no ACAM must fail, got %+v", s)
	}
	if !strings.Contains(s.Detail, "no Access-Control-Allow-Methods") {
		t.Fatalf("the detail must say the header is absent, got %q", s.Detail)
	}
}

func TestPreflight_WildcardMethodsDependOnCredentialsMode(t *testing.T) {
	steps := pf(t, false, "PATCH", nil, 204, "Access-Control-Allow-Methods: *")
	if s := stepByID(t, steps, "preflight.allow-methods"); s.Status != StatusPass {
		t.Fatalf("* must cover PATCH without credentials, got %+v", s)
	}
	steps = pf(t, true, "PATCH", nil, 204, "Access-Control-Allow-Methods: *")
	s := stepByID(t, steps, "preflight.allow-methods")
	if s.Status != StatusFail || !strings.Contains(s.Detail, "literal") {
		t.Fatalf("* with credentials must fail and explain literalness, got %+v", s)
	}
}

func TestPreflight_MethodCaseMismatchExplainsThePatchTrap(t *testing.T) {
	// fetch(url, {method: "patch"}) sends "patch"; a server allowing
	// "PATCH" fails the byte comparison. The detail must teach this.
	steps := pf(t, false, "patch", nil, 204, "Access-Control-Allow-Methods: PATCH")
	s := stepByID(t, steps, "preflight.allow-methods")
	if s.Status != StatusFail {
		t.Fatalf("byte-case mismatch must fail, got %+v", s)
	}
	if !strings.Contains(s.Detail, "byte case") || !strings.Contains(s.Detail, "DELETE/GET/HEAD/OPTIONS/POST/PUT") {
		t.Fatalf("the detail must explain the normalization trap, got %q", s.Detail)
	}
}

func TestPreflight_HeadersCoveredCaseInsensitively(t *testing.T) {
	steps := pf(t, true, "PUT", []string{"content-type", "x-api-key"}, 204,
		"Access-Control-Allow-Methods: PUT",
		"Access-Control-Allow-Headers: Content-Type, X-API-Key")
	if s := stepByID(t, steps, "preflight.allow-headers"); s.Status != StatusPass {
		t.Fatalf("header names compare case-insensitively, got %+v", s)
	}
}

func TestPreflight_MissingHeadersListedInFailure(t *testing.T) {
	steps := pf(t, false, "PUT", []string{"x-a", "x-b"}, 204,
		"Access-Control-Allow-Methods: PUT",
		"Access-Control-Allow-Headers: x-a")
	s := stepByID(t, steps, "preflight.allow-headers")
	if s.Status != StatusFail || s.Code != CodeHeaderNotAllowed {
		t.Fatalf("uncovered header must fail, got %+v", s)
	}
	if !strings.Contains(s.Detail, "x-b") || strings.Contains(s.Fix, "x-a,") {
		t.Fatalf("only the missing name belongs in detail/fix: %q / %q", s.Detail, s.Fix)
	}
	if s.Subject != "x-b" {
		t.Fatalf("Subject drives the browser message and must be the first missing name, got %q", s.Subject)
	}
}

func TestPreflight_WildcardHeadersDependOnCredentialsMode(t *testing.T) {
	steps := pf(t, false, "PUT", []string{"x-api-key"}, 204,
		"Access-Control-Allow-Methods: PUT",
		"Access-Control-Allow-Headers: *")
	if s := stepByID(t, steps, "preflight.allow-headers"); s.Status != StatusPass {
		t.Fatalf("* must cover x-api-key without credentials, got %+v", s)
	}
	steps = pf(t, true, "PUT", []string{"x-api-key"}, 204,
		"Access-Control-Allow-Methods: PUT",
		"Access-Control-Allow-Headers: *")
	s := stepByID(t, steps, "preflight.allow-headers")
	if s.Status != StatusFail || !strings.Contains(s.Detail, "literal") {
		t.Fatalf("* with credentials must fail and explain literalness, got %+v", s)
	}
}

func TestPreflight_WildcardNeverCoversAuthorization(t *testing.T) {
	// Even without credentials, "*" does not cover Authorization — it is
	// Fetch's one "CORS non-wildcard request-header name".
	steps := pf(t, false, "PUT", []string{"authorization"}, 204,
		"Access-Control-Allow-Methods: PUT",
		"Access-Control-Allow-Headers: *")
	s := stepByID(t, steps, "preflight.allow-headers")
	if s.Status != StatusFail {
		t.Fatalf("* must not cover authorization, got %+v", s)
	}
	if !strings.Contains(s.Detail, "authorization") {
		t.Fatalf("the detail must name authorization, got %q", s.Detail)
	}
}

func TestPreflight_NoUnsafeHeadersPassesTrivially(t *testing.T) {
	steps := pf(t, false, "DELETE", nil, 204, "Access-Control-Allow-Methods: DELETE")
	s := stepByID(t, steps, "preflight.allow-headers")
	if s.Status != StatusPass || !strings.Contains(s.Detail, "method alone") {
		t.Fatalf("no unsafe headers means a trivial pass, got %+v", s)
	}
}
