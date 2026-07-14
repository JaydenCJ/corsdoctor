// Tests for the Chrome-style console message reconstruction. Developers
// google these exact strings; reproducing them proves the diagnosis found
// the same failure the browser reported.
package cors

import (
	"strings"
	"testing"
)

const msgURL = "https://api.example.test/data"
const msgOrigin = "https://app.example.test"

func TestBrowserMessage_WildcardWithCredentials(t *testing.T) {
	got := browserMessage(&Step{Phase: "response", Code: CodeWildcardCredentials}, msgURL, msgOrigin)
	want := "must not be the wildcard '*' when the request's credentials mode is 'include'"
	if !strings.Contains(got, want) || !strings.HasPrefix(got, "Access to fetch at 'https://api.example.test/data' from origin 'https://app.example.test' has been blocked by CORS policy: ") {
		t.Fatalf("got %q", got)
	}
}

func TestBrowserMessage_PreflightPhaseGetsThePreflightPrefix(t *testing.T) {
	got := browserMessage(&Step{Phase: "preflight", Code: CodeMissingAllowOrigin}, msgURL, msgOrigin)
	if !strings.Contains(got, "Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present") {
		t.Fatalf("got %q", got)
	}
	// The same failure on the actual response must NOT carry the prefix.
	got = browserMessage(&Step{Phase: "response", Code: CodeMissingAllowOrigin}, msgURL, msgOrigin)
	if strings.Contains(got, "preflight") {
		t.Fatalf("response-phase message must not mention the preflight: %q", got)
	}
}

func TestBrowserMessage_QuotesTheFailingSubject(t *testing.T) {
	got := browserMessage(&Step{Phase: "preflight", Code: CodeMethodNotAllowed, Subject: "PUT"}, msgURL, msgOrigin)
	if !strings.Contains(got, "Method PUT is not allowed by Access-Control-Allow-Methods in preflight response.") {
		t.Fatalf("got %q", got)
	}
	got = browserMessage(&Step{Phase: "preflight", Code: CodeHeaderNotAllowed, Subject: "x-api-key"}, msgURL, msgOrigin)
	if !strings.Contains(got, "Request header field x-api-key is not allowed by Access-Control-Allow-Headers in preflight response.") {
		t.Fatalf("got %q", got)
	}
	got = browserMessage(&Step{Phase: "response", Code: CodeOriginMismatch, Subject: "https://other.test"}, msgURL, msgOrigin)
	if !strings.Contains(got, "has a value 'https://other.test' that is not equal to the supplied origin") {
		t.Fatalf("got %q", got)
	}
}
