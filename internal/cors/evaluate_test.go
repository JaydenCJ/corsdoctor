// End-to-end tests for Evaluate: outcome computation, phase orchestration,
// cross-phase hints, warnings, and exposed headers.
package cors

import (
	"strings"
	"testing"
)

// simpleGet is a credential-less cross-origin GET with no unsafe headers.
func simpleGet() Request {
	return Request{
		Method: "GET",
		URL:    "https://api.example.test/data",
		Origin: "https://app.example.test",
	}
}

func mustEvaluate(t *testing.T, c Capture) *Verdict {
	t.Helper()
	v, err := Evaluate(c)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return v
}

func TestEvaluate_SimpleGetAllowedByWildcard(t *testing.T) {
	v := mustEvaluate(t, Capture{
		Request:  simpleGet(),
		Response: resp(200, "Access-Control-Allow-Origin: *", "Content-Type: application/json"),
	})
	if v.Outcome != OutcomeAllowed || v.Failed != nil {
		t.Fatalf("want allowed, got %s (failed: %+v)", v.Outcome, v.Failed)
	}
	if v.Classification.PreflightRequired {
		t.Fatal("a simple GET must not require a preflight")
	}
}

func TestEvaluate_SameOriginIsNotCORS(t *testing.T) {
	v := mustEvaluate(t, Capture{Request: Request{
		Method: "PUT", // even an unsafe method: same-origin means no CORS at all
		URL:    "https://app.example.test:443/api/data",
		Origin: "https://app.example.test",
	}})
	if v.Outcome != OutcomeNotCORS {
		t.Fatalf("https://x and https://x:443 are the same origin, got %s", v.Outcome)
	}
	if len(v.Steps) != 0 {
		t.Fatalf("no CORS steps must run on a same-origin request, got %d", len(v.Steps))
	}
}

func TestEvaluate_BlockedAtResponseMissingACAO(t *testing.T) {
	v := mustEvaluate(t, Capture{
		Request:  simpleGet(),
		Response: resp(200, "Content-Type: application/json"),
	})
	if v.Outcome != OutcomeBlocked || v.Failed == nil || v.Failed.ID != "response.allow-origin" {
		t.Fatalf("want blocked at response.allow-origin, got %s / %+v", v.Outcome, v.Failed)
	}
	if !strings.Contains(v.BrowserMessage, "No 'Access-Control-Allow-Origin' header is present") {
		t.Fatalf("browser message wrong: %q", v.BrowserMessage)
	}
}

func TestEvaluate_PreflightRequiredButNotCaptured_Incomplete(t *testing.T) {
	req := simpleGet()
	req.Method = "PUT"
	v := mustEvaluate(t, Capture{
		Request:  req,
		Response: resp(200, "Access-Control-Allow-Origin: *"),
	})
	if v.Outcome != OutcomeIncomplete {
		t.Fatalf("the main response passes but the preflight is uncaptured: want incomplete, got %s", v.Outcome)
	}
	if len(v.Requirements) == 0 || !strings.Contains(v.Requirements[0], "OPTIONS") {
		t.Fatalf("incomplete verdict must state the preflight contract, got %v", v.Requirements)
	}
	// The mirror image — preflight captured and passing, response missing —
	// is also incomplete, crediting the preflight.
	v = mustEvaluate(t, Capture{
		Request:   req,
		Preflight: resp(204, "Access-Control-Allow-Origin: *", "Access-Control-Allow-Methods: PUT"),
	})
	if v.Outcome != OutcomeIncomplete || !strings.Contains(v.Summary, "preflight passes") {
		t.Fatalf("want incomplete crediting the preflight, got %s / %q", v.Outcome, v.Summary)
	}
}

func TestEvaluate_NoResponsesGivesAdvisoryRequirements(t *testing.T) {
	req := simpleGet()
	req.Method = "DELETE"
	req.Credentials = true
	req.Headers = Headers{{Name: "X-Api-Key", Value: "k"}}
	v := mustEvaluate(t, Capture{Request: req})
	if v.Outcome != OutcomeAdvisory {
		t.Fatalf("want advisory, got %s", v.Outcome)
	}
	joined := strings.Join(v.Requirements, "\n")
	for _, want := range []string{
		"Access-Control-Allow-Methods: DELETE",
		"Access-Control-Allow-Headers: x-api-key",
		"Access-Control-Allow-Credentials: true",
		"the actual DELETE response",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("requirements missing %q:\n%s", want, joined)
		}
	}
}

func TestEvaluate_FullCredentialedRoundTripAllowed(t *testing.T) {
	req := simpleGet()
	req.Method = "PUT"
	req.Credentials = true
	req.Headers = Headers{{Name: "Content-Type", Value: "application/json"}}
	corsHeaders := []string{
		"Access-Control-Allow-Origin: https://app.example.test",
		"Access-Control-Allow-Credentials: true",
		"Vary: Origin",
	}
	v := mustEvaluate(t, Capture{
		Request: req,
		Preflight: resp(204, append(corsHeaders,
			"Access-Control-Allow-Methods: PUT",
			"Access-Control-Allow-Headers: content-type")...),
		Response: resp(200, corsHeaders...),
	})
	if v.Outcome != OutcomeAllowed {
		t.Fatalf("want allowed, got %s (failed: %+v)", v.Outcome, v.Failed)
	}
	if len(v.Warnings) != 0 {
		t.Fatalf("Vary: Origin is set; no warnings expected, got %v", v.Warnings)
	}
}

func TestEvaluate_ResponseSkippedWhenPreflightFails(t *testing.T) {
	req := simpleGet()
	req.Method = "PUT"
	v := mustEvaluate(t, Capture{
		Request:   req,
		Preflight: resp(204, "Access-Control-Allow-Origin: *"), // no ACAM → method fails
		Response:  resp(200, "Access-Control-Allow-Origin: *"),
	})
	if v.Outcome != OutcomeBlocked || v.Failed.ID != "preflight.allow-methods" {
		t.Fatalf("want blocked at preflight.allow-methods, got %+v", v.Failed)
	}
	last := v.Steps[len(v.Steps)-1]
	if last.ID != "response.cors-check" || last.Status != StatusSkip {
		t.Fatalf("the response phase must be skipped after a failed preflight, got %+v", last)
	}
}

func TestEvaluate_UncalledForPreflightNeverBlocks(t *testing.T) {
	// A captured OPTIONS response that *would* fail must not block a
	// request that never triggers a preflight — it becomes a warning.
	v := mustEvaluate(t, Capture{
		Request:   simpleGet(),
		Preflight: resp(500),
		Response:  resp(200, "Access-Control-Allow-Origin: *"),
	})
	if v.Outcome != OutcomeAllowed {
		t.Fatalf("simple GET with passing response must be allowed, got %s", v.Outcome)
	}
	if len(v.Warnings) == 0 || !strings.Contains(strings.Join(v.Warnings, " "), "would fail") {
		t.Fatalf("the failing-but-unrequired preflight deserves a warning, got %v", v.Warnings)
	}
}

func TestEvaluate_CrossPhaseHintWhenOnlyOptionsDecorated(t *testing.T) {
	// The classic middleware bug: OPTIONS carries CORS headers, the actual
	// response does not. The fix list must call it out.
	req := simpleGet()
	req.Method = "PUT"
	v := mustEvaluate(t, Capture{
		Request: req,
		Preflight: resp(204,
			"Access-Control-Allow-Origin: https://app.example.test",
			"Access-Control-Allow-Methods: PUT", "Vary: Origin"),
		Response: resp(200, "Content-Type: application/json"),
	})
	if v.Outcome != OutcomeBlocked || v.Failed.ID != "response.allow-origin" {
		t.Fatalf("want blocked at response.allow-origin, got %+v", v.Failed)
	}
	if !strings.Contains(strings.Join(v.Fixes, " "), "only decorates OPTIONS") {
		t.Fatalf("the cross-phase hint is missing: %v", v.Fixes)
	}
}

func TestEvaluate_VaryOriginWarning(t *testing.T) {
	v := mustEvaluate(t, Capture{
		Request:  simpleGet(),
		Response: resp(200, "Access-Control-Allow-Origin: https://app.example.test"),
	})
	if !strings.Contains(strings.Join(v.Warnings, " "), "Vary: Origin") {
		t.Fatalf("echoing an origin without Vary: Origin must warn, got %v", v.Warnings)
	}
}

func TestEvaluate_ExposedHeaders(t *testing.T) {
	v := mustEvaluate(t, Capture{
		Request: simpleGet(),
		Response: resp(200,
			"Access-Control-Allow-Origin: *",
			"Content-Type: application/json",
			"X-Request-Id: r-1",
			"Access-Control-Expose-Headers: X-Request-Id"),
	})
	got := strings.Join(v.ExposedHeaders, ",")
	if !strings.Contains(got, "content-type") || !strings.Contains(got, "x-request-id") {
		t.Fatalf("exposed headers must include safelisted + granted names, got %v", v.ExposedHeaders)
	}

	// With credentials, an Expose-Headers wildcard is literal and must not
	// spill every header into the readable set.
	req := simpleGet()
	req.Credentials = true
	v = mustEvaluate(t, Capture{
		Request: req,
		Response: resp(200,
			"Access-Control-Allow-Origin: https://app.example.test",
			"Access-Control-Allow-Credentials: true",
			"X-Secret: s",
			"Access-Control-Expose-Headers: *"),
	})
	for _, n := range v.ExposedHeaders {
		if n == "x-secret" {
			t.Fatalf("with credentials, * must not expose everything: %v", v.ExposedHeaders)
		}
	}
}

func TestEvaluate_ExposeWildcardWithoutCredentialsExposesAll(t *testing.T) {
	v := mustEvaluate(t, Capture{
		Request: simpleGet(),
		Response: resp(200,
			"Access-Control-Allow-Origin: *",
			"X-Request-Id: r-1",
			"Set-Cookie: sid=1",
			"Access-Control-Expose-Headers: *"),
	})
	got := strings.Join(v.ExposedHeaders, ",")
	if !strings.Contains(got, "x-request-id") {
		t.Fatalf("a valid wildcard exposes custom headers, got %v", v.ExposedHeaders)
	}
	if strings.Contains(got, "set-cookie") {
		t.Fatalf("Set-Cookie is never exposed, got %v", v.ExposedHeaders)
	}
}

func TestEvaluate_DiagnosticNotes(t *testing.T) {
	// Method normalization is applied and disclosed…
	req := simpleGet()
	req.Method = "put"
	v := mustEvaluate(t, Capture{Request: req, Response: resp(200, "Access-Control-Allow-Origin: *")})
	if v.Request.Method != "PUT" || !strings.Contains(strings.Join(v.Notes, " "), "normalized") {
		t.Fatalf("put must normalize to PUT with a note, got %q / %v", v.Request.Method, v.Notes)
	}

	// …Access-Control-Max-Age is surfaced (stale cached preflights keep
	// failing after a server fix, which confuses everyone)…
	req = simpleGet()
	req.Method = "PUT"
	v = mustEvaluate(t, Capture{
		Request: req,
		Preflight: resp(204, "Access-Control-Allow-Origin: *",
			"Access-Control-Allow-Methods: PUT", "Access-Control-Max-Age: 600"),
		Response: resp(200, "Access-Control-Allow-Origin: *"),
	})
	if !strings.Contains(strings.Join(v.Notes, " "), "600s") {
		t.Fatalf("Max-Age must be surfaced, got %v", v.Notes)
	}

	// …and the opaque "null" origin gets an explanation.
	req = simpleGet()
	req.Origin = "null"
	v = mustEvaluate(t, Capture{Request: req, Response: resp(200, "Access-Control-Allow-Origin: *")})
	if !strings.Contains(strings.Join(v.Notes, " "), "sandboxed iframe") {
		t.Fatalf("the null origin deserves an explanation, got %v", v.Notes)
	}
}

func TestEvaluate_OriginResolutionAndInputErrors(t *testing.T) {
	// The origin falls back to the captured Origin request header.
	v := mustEvaluate(t, Capture{
		Request: Request{
			Method:  "GET",
			URL:     "https://api.example.test/data",
			Headers: Headers{{Name: "Origin", Value: "https://app.example.test"}},
		},
		Response: resp(200, "Access-Control-Allow-Origin: *"),
	})
	if v.Origin != "https://app.example.test" {
		t.Fatalf("origin must come from the Origin header, got %q", v.Origin)
	}
	// Unusable input is an error, not a verdict.
	cases := []Capture{
		{Request: Request{URL: "/relative", Origin: "https://a.test"}},
		{Request: Request{URL: "https://api.example.test/x"}}, // no origin anywhere
		{Request: Request{URL: "https://api.example.test/x", Origin: "not an origin"}},
	}
	for i, c := range cases {
		if _, err := Evaluate(c); err == nil {
			t.Fatalf("case %d must return an input error", i)
		}
	}
}
