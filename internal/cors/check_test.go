// Tests for Fetch's "CORS check" — the algorithm run against both the
// preflight and the actual response. Each case pins one spec step.
package cors

import (
	"strings"
	"testing"
)

// resp builds a Response from status and "Name: value" strings.
func resp(status int, headers ...string) *Response {
	r := &Response{Status: status}
	for _, h := range headers {
		name, value, _ := strings.Cut(h, ":")
		r.Headers = append(r.Headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return r
}

// stepByID finds a step in a slice; fails the test when absent.
func stepByID(t *testing.T, steps []Step, id string) Step {
	t.Helper()
	for _, s := range steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step %q in %v", id, steps)
	return Step{}
}

var appOrigin = Origin{Scheme: "https", Host: "app.example.test"}

func TestCORSCheck_MissingAllowOriginFails(t *testing.T) {
	steps := corsCheck("response", appOrigin, false, resp(200, "Content-Type: application/json"))
	s := stepByID(t, steps, "response.allow-origin")
	if s.Status != StatusFail || s.Code != CodeMissingAllowOrigin {
		t.Fatalf("want missing-allow-origin failure, got %+v", s)
	}
	// The later steps are unreachable and must say so, not silently pass.
	if stepByID(t, steps, "response.origin-match").Status != StatusSkip {
		t.Fatal("origin-match must be skipped when the header is absent")
	}
}

func TestCORSCheck_WildcardDependsOnCredentialsMode(t *testing.T) {
	steps := corsCheck("response", appOrigin, false, resp(200, "Access-Control-Allow-Origin: *"))
	if s := stepByID(t, steps, "response.origin-match"); s.Status != StatusPass {
		t.Fatalf("wildcard without credentials must pass, got %+v", s)
	}
	steps = corsCheck("response", appOrigin, true, resp(200,
		"Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"))
	s := stepByID(t, steps, "response.origin-match")
	if s.Status != StatusFail || s.Code != CodeWildcardCredentials {
		t.Fatalf("wildcard with credentials must fail with its own code, got %+v", s)
	}
	if !strings.Contains(s.Fix, "https://app.example.test") {
		t.Fatalf("the fix must tell the server to echo the origin, got %q", s.Fix)
	}
}

func TestCORSCheck_ByteExactMatchPasses(t *testing.T) {
	steps := corsCheck("response", appOrigin, false, resp(200,
		"Access-Control-Allow-Origin: https://app.example.test"))
	if s := stepByID(t, steps, "response.origin-match"); s.Status != StatusPass {
		t.Fatalf("exact match must pass, got %+v", s)
	}
	// "null" byte-matches the opaque origin the same way.
	steps = corsCheck("response", Origin{Opaque: true}, false, resp(200,
		"Access-Control-Allow-Origin: null"))
	if s := stepByID(t, steps, "response.origin-match"); s.Status != StatusPass {
		t.Fatalf(`"null" must byte-match the opaque origin, got %+v`, s)
	}
}

func TestCORSCheck_MismatchCarriesDiagnosis(t *testing.T) {
	steps := corsCheck("response", appOrigin, false, resp(200,
		"Access-Control-Allow-Origin: http://app.example.test"))
	s := stepByID(t, steps, "response.origin-match")
	if s.Status != StatusFail || s.Code != CodeOriginMismatch {
		t.Fatalf("want origin-mismatch, got %+v", s)
	}
	if !strings.Contains(s.Detail, "scheme mismatch") {
		t.Fatalf("the detail must diagnose the scheme, got %q", s.Detail)
	}
}

func TestCORSCheck_DuplicateFieldsFailAsMultipleValues(t *testing.T) {
	// Two layers each adding ACAO is a real-world classic: the browser
	// joins the fields with ", " and nothing can match the origin anymore.
	steps := corsCheck("response", appOrigin, false, resp(200,
		"Access-Control-Allow-Origin: https://app.example.test",
		"Access-Control-Allow-Origin: https://app.example.test"))
	s := stepByID(t, steps, "response.origin-match")
	if s.Status != StatusFail || s.Code != CodeMultipleValues {
		t.Fatalf("duplicate ACAO must fail as multiple values, got %+v", s)
	}
}

func TestCORSCheck_CredentialsStepSkippedWithoutCredentials(t *testing.T) {
	steps := corsCheck("response", appOrigin, false, resp(200, "Access-Control-Allow-Origin: *"))
	if s := stepByID(t, steps, "response.allow-credentials"); s.Status != StatusSkip {
		t.Fatalf("the credentials check must not run without credentials, got %+v", s)
	}
}

func TestCORSCheck_AllowCredentialsMustBeExactlyTrue(t *testing.T) {
	// A missing header fails outright…
	steps := corsCheck("response", appOrigin, true, resp(200,
		"Access-Control-Allow-Origin: https://app.example.test"))
	s := stepByID(t, steps, "response.allow-credentials")
	if s.Status != StatusFail || s.Code != CodeCredentialsFlag {
		t.Fatalf("missing ACAC with credentials must fail, got %+v", s)
	}
	// …and so do "True", "TRUE", "*", "1" — real values seen in the wild;
	// only the exact byte string "true" passes.
	for _, v := range []string{"True", "TRUE", "*", "1"} {
		steps := corsCheck("response", appOrigin, true, resp(200,
			"Access-Control-Allow-Origin: https://app.example.test",
			"Access-Control-Allow-Credentials: "+v))
		s := stepByID(t, steps, "response.allow-credentials")
		if s.Status != StatusFail {
			t.Fatalf("ACAC %q must fail, got %+v", v, s)
		}
	}
	steps = corsCheck("response", appOrigin, true, resp(200,
		"Access-Control-Allow-Origin: https://app.example.test",
		"Access-Control-Allow-Credentials: true"))
	if s := stepByID(t, steps, "response.allow-credentials"); s.Status != StatusPass {
		t.Fatalf(`exact "true" must pass, got %+v`, s)
	}
}
