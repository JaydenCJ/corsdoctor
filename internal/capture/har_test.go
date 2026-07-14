// Tests for HAR ingestion: entry selection, preflight pairing, credentials
// inference, and the reconstruct-from-failed-preflight path.
package capture

import (
	"fmt"
	"strings"
	"testing"
)

// harDoc assembles a minimal HAR file from entry JSON fragments.
func harDoc(entries ...string) []byte {
	return []byte(fmt.Sprintf(`{"log": {"version": "1.2", "entries": [%s]}}`, strings.Join(entries, ",")))
}

func harEntryJSON(method, url string, reqHeaders string, status int, respHeaders string) string {
	return fmt.Sprintf(`{
		"request": {"method": %q, "url": %q, "headers": [%s]},
		"response": {"status": %d, "headers": [%s]}
	}`, method, url, reqHeaders, status, respHeaders)
}

func h(name, value string) string {
	return fmt.Sprintf(`{"name": %q, "value": %q}`, name, value)
}

const apiURL = "https://api.example.test/v1/items"

func TestHAR_PairsMainEntryWithItsPreflight(t *testing.T) {
	doc := harDoc(
		harEntryJSON("OPTIONS", apiURL,
			h("Origin", "https://app.example.test")+","+h("Access-Control-Request-Method", "PUT"),
			204, h("Access-Control-Allow-Origin", "*")),
		harEntryJSON("PUT", apiURL,
			h("Origin", "https://app.example.test")+","+h("Content-Type", "application/json"),
			200, h("Access-Control-Allow-Origin", "*")),
	)
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.Method != "PUT" {
		t.Fatalf("the main entry is the PUT, got %q", cap.Request.Method)
	}
	if cap.Preflight == nil || cap.Preflight.Status != 204 {
		t.Fatalf("the OPTIONS entry must be paired as the preflight, got %+v", cap.Preflight)
	}
	if cap.Response == nil || cap.Response.Status != 200 {
		t.Fatalf("response wrong: %+v", cap.Response)
	}
}

func TestHAR_URLFilterSelectsAmongEntries(t *testing.T) {
	doc := harDoc(
		harEntryJSON("GET", "https://cdn.example.test/app.js", h("Origin", "https://app.example.test"), 200, ""),
		harEntryJSON("GET", apiURL, h("Origin", "https://app.example.test"), 200, ""),
	)
	cap, err := Parse(doc, Options{URLFilter: "/v1/items"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.URL != apiURL {
		t.Fatalf("filter must pick the API entry, got %q", cap.Request.URL)
	}
}

func TestHAR_NoMatchingEntryErrors(t *testing.T) {
	doc := harDoc(harEntryJSON("GET", apiURL, "", 200, ""))
	if _, err := Parse(doc, Options{URLFilter: "/nope"}); err == nil || !strings.Contains(err.Error(), "--url") {
		t.Fatalf("a filter with no matches must error and mention --url, got %v", err)
	}
	if _, err := Parse(harDoc(), Options{}); err == nil {
		t.Fatal("an empty HAR must error")
	}
}

func TestHAR_InfersCredentialsFromCookie(t *testing.T) {
	doc := harDoc(harEntryJSON("GET", apiURL,
		h("Origin", "https://app.example.test")+","+h("Cookie", "sid=1"), 200, ""))
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cap.Request.Credentials {
		t.Fatal("a Cookie on the wire means credentials were included")
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "inferred") {
		t.Fatalf("the inference must be disclosed, got %v", cap.Notes)
	}
	// The explicit flag beats the inference.
	f := false
	cap, err = Parse(doc, Options{Credentials: &f})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.Credentials {
		t.Fatal("--no-credentials must beat the Cookie inference")
	}
}

func TestHAR_FailedPreflightReconstructsTheIntendedRequest(t *testing.T) {
	// When the preflight fails, the browser never sends the real request —
	// the HAR contains only OPTIONS. The intended request is rebuilt from
	// Access-Control-Request-* so the diagnosis still runs end to end.
	doc := harDoc(harEntryJSON("OPTIONS", apiURL,
		h("Origin", "https://app.example.test")+","+
			h("Access-Control-Request-Method", "DELETE")+","+
			h("Access-Control-Request-Headers", "content-type,x-api-key"),
		403, ""))
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.Method != "DELETE" || cap.Request.Origin != "https://app.example.test" {
		t.Fatalf("request not reconstructed: %+v", cap.Request)
	}
	if !cap.Request.Headers.Has("content-type") || !cap.Request.Headers.Has("x-api-key") {
		t.Fatalf("unsafe headers must be reconstructed, got %+v", cap.Request.Headers)
	}
	if cap.Preflight == nil || cap.Preflight.Status != 403 {
		t.Fatalf("the failing OPTIONS is the preflight, got %+v", cap.Preflight)
	}
	if cap.Response != nil {
		t.Fatal("no actual response exists in this scenario")
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "reconstructed") {
		t.Fatalf("the reconstruction must be disclosed, got %v", cap.Notes)
	}
}

func TestHAR_DropsHTTP2PseudoHeaders(t *testing.T) {
	doc := harDoc(harEntryJSON("GET", apiURL,
		h(":method", "GET")+","+h(":path", "/v1/items")+","+h("Origin", "https://app.example.test"),
		200, h(":status", "200")+","+h("Access-Control-Allow-Origin", "*")))
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, hd := range cap.Request.Headers {
		if strings.HasPrefix(hd.Name, ":") {
			t.Fatalf("pseudo-header leaked: %q", hd.Name)
		}
	}
	if !cap.Response.Headers.Has("Access-Control-Allow-Origin") {
		t.Fatal("real headers must survive the pseudo-header filter")
	}
}

func TestHAR_MultipleMainMatchesAreNoted(t *testing.T) {
	doc := harDoc(
		harEntryJSON("GET", apiURL+"/1", h("Origin", "https://app.example.test"), 200, ""),
		harEntryJSON("GET", apiURL+"/2", h("Origin", "https://app.example.test"), 200, ""),
	)
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.URL != apiURL+"/1" {
		t.Fatalf("the first match wins, got %q", cap.Request.URL)
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "--url") {
		t.Fatalf("ambiguity must be disclosed with the --url hint, got %v", cap.Notes)
	}
}

func TestHAR_PreflightPairingChecksMethodAndURL(t *testing.T) {
	// An OPTIONS for a DIFFERENT method or URL must not be paired.
	doc := harDoc(
		harEntryJSON("OPTIONS", apiURL,
			h("Access-Control-Request-Method", "DELETE"), 204, ""),
		harEntryJSON("PUT", apiURL, h("Origin", "https://app.example.test"), 200, ""),
	)
	cap, err := Parse(doc, Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Preflight != nil {
		t.Fatalf("a DELETE preflight must not pair with a PUT request, got %+v", cap.Preflight)
	}
}
