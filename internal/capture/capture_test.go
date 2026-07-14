// Tests for the corsdoctor JSON capture format: value-shape tolerance
// (string-or-array headers, bool-or-string credentials), strictness about
// unknown fields, and the credentials override.
package capture

import (
	"strings"
	"testing"
)

func TestParse_CaptureJSONBasics(t *testing.T) {
	cap, err := Parse([]byte(`{
		"request": {
			"method": "PUT",
			"url": "https://api.example.test/v1",
			"origin": "https://app.example.test",
			"headers": {"Content-Type": "application/json"},
			"credentials": true
		},
		"preflight": {"status": 204, "headers": {"Access-Control-Allow-Origin": "*"}},
		"response": {"status": 200, "headers": {"Access-Control-Allow-Origin": "*"}}
	}`), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.Method != "PUT" || !cap.Request.Credentials {
		t.Fatalf("request wrong: %+v", cap.Request)
	}
	if cap.Preflight == nil || cap.Preflight.Status != 204 || cap.Response == nil {
		t.Fatal("both responses must be parsed")
	}
	if v, ok := cap.Request.Headers.Get("content-type"); !ok || v != "application/json" {
		t.Fatalf("headers wrong: %+v", cap.Request.Headers)
	}
}

func TestParse_HeaderValuesAcceptStringOrArray(t *testing.T) {
	cap, err := Parse([]byte(`{
		"request": {"url": "https://api.example.test/", "origin": "https://app.example.test"},
		"response": {"status": 200, "headers": {
			"Access-Control-Allow-Origin": ["https://a.test", "https://b.test"]
		}}
	}`), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Array values become separate fields — exactly the duplicated-header
	// situation the CORS check needs to see to diagnose "multiple values".
	if n := cap.Response.Headers.Count("Access-Control-Allow-Origin"); n != 2 {
		t.Fatalf("want 2 fields, got %d", n)
	}
}

func TestParse_CredentialsAcceptsFetchModeStrings(t *testing.T) {
	for mode, want := range map[string]bool{`"include"`: true, `"omit"`: false, `"same-origin"`: false, "true": true} {
		cap, err := Parse([]byte(`{"request": {"url": "https://a.test/", "origin": "https://b.test", "credentials": `+mode+`}}`), Options{})
		if err != nil {
			t.Fatalf("credentials %s: %v", mode, err)
		}
		if cap.Request.Credentials != want {
			t.Fatalf("credentials %s: want %v", mode, want)
		}
	}
	_, err := Parse([]byte(`{"request": {"url": "https://a.test/", "origin": "https://b.test", "credentials": "yes"}}`), Options{})
	if err == nil || !strings.Contains(err.Error(), "include") {
		t.Fatalf("bad credentials string must error helpfully, got %v", err)
	}
	// The --credentials/--no-credentials flags override the capture value.
	f := false
	cap, err := Parse([]byte(`{"request": {"url": "https://a.test/", "origin": "https://b.test", "credentials": true}}`), Options{Credentials: &f})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cap.Request.Credentials {
		t.Fatal("--no-credentials must override the capture")
	}
	if !strings.Contains(strings.Join(cap.Notes, " "), "forced") {
		t.Fatalf("the override must be noted, got %v", cap.Notes)
	}
}

func TestParse_UnknownFieldsRejected(t *testing.T) {
	// Typos like "reponse" would otherwise silently drop half the capture.
	_, err := Parse([]byte(`{"request": {"url": "https://a.test/"}, "reponse": {"status": 200}}`), Options{})
	if err == nil || !strings.Contains(err.Error(), "reponse") {
		t.Fatalf("unknown top-level field must be rejected by name, got %v", err)
	}
}

func TestParse_InvalidInputsErrorByName(t *testing.T) {
	cases := []struct {
		src  string
		want string // substring the error must contain
	}{
		{`{}`, `"request"`},
		{`{"request": {"origin": "https://a.test"}}`, "request.url"},
		{`{"request": {"url": "https://a.test/"}, "preflight": {"headers": {}}}`, "preflight.status"},
		{"PUT /v1 HTTP/1.1\r\n", "not valid JSON"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.src), Options{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("Parse(%q) error = %v; want it to mention %q", c.src, err, c.want)
		}
	}
}

func TestParse_SortsHeaderKeysDeterministically(t *testing.T) {
	// JSON objects are unordered; the parse must impose an order so two
	// runs over the same file render byte-identical reports.
	cap, err := Parse([]byte(`{"request": {"url": "https://a.test/", "origin": "https://b.test",
		"headers": {"Z-Last": "1", "A-First": "2", "M-Mid": "3"}}}`), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var names []string
	for _, h := range cap.Request.Headers {
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "A-First,M-Mid,Z-Last" {
		t.Fatalf("headers must be sorted, got %v", names)
	}
}
