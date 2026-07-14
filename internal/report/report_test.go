// Tests for the human (text) and machine (JSON) renderers. The text report
// is the product; these tests pin its load-bearing lines without freezing
// every byte of prose.
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JaydenCJ/corsdoctor/internal/cors"
)

func blockedVerdict(t *testing.T) *cors.Verdict {
	t.Helper()
	v, err := cors.Evaluate(cors.Capture{
		Request: cors.Request{
			Method: "GET",
			URL:    "https://api.example.test/data",
			Origin: "https://app.example.test",
		},
		Response: &cors.Response{Status: 200},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return v
}

func TestText_BlockedReportNamesStepAndBrowserMessage(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, blockedVerdict(t))
	out := buf.String()
	for _, want := range []string{
		"verdict  BLOCKED at response.allow-origin",
		"browser console (Chrome-style)",
		"has been blocked by CORS policy",
		"fix\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestText_AllowedReportListsExposedHeaders(t *testing.T) {
	v, err := cors.Evaluate(cors.Capture{
		Request: cors.Request{Method: "GET", URL: "https://api.example.test/data", Origin: "https://app.example.test"},
		Response: &cors.Response{Status: 200, Headers: cors.Headers{
			{Name: "Access-Control-Allow-Origin", Value: "*"},
			{Name: "Content-Type", Value: "application/json"},
		}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var buf bytes.Buffer
	Text(&buf, v)
	out := buf.String()
	if !strings.Contains(out, "verdict  ALLOWED") || !strings.Contains(out, "content-type") {
		t.Fatalf("allowed report wrong:\n%s", out)
	}
}

func TestText_NotCORSReportIsShort(t *testing.T) {
	v, err := cors.Evaluate(cors.Capture{Request: cors.Request{
		Method: "GET", URL: "https://app.example.test/api", Origin: "https://app.example.test",
	}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var buf bytes.Buffer
	Text(&buf, v)
	out := buf.String()
	if !strings.Contains(out, "NOT A CORS REQUEST") {
		t.Fatalf("want the not-cors verdict:\n%s", out)
	}
	if strings.Contains(out, "request classification") {
		t.Fatalf("same-origin requests need no classification section:\n%s", out)
	}
}

func TestText_AdvisoryListsServerRequirements(t *testing.T) {
	v, err := cors.Evaluate(cors.Capture{Request: cors.Request{
		Method: "DELETE", URL: "https://api.example.test/x", Origin: "https://app.example.test",
	}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var buf bytes.Buffer
	Text(&buf, v)
	if !strings.Contains(buf.String(), "server requirements") {
		t.Fatalf("advisory report must list requirements:\n%s", buf.String())
	}
}

func TestJSON_EnvelopeIsStableAndParses(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, blockedVerdict(t), 1); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got["schema_version"] != float64(1) || got["tool"] != "corsdoctor" || got["exit_code"] != float64(1) {
		t.Fatalf("envelope wrong: %v", got)
	}
	if got["outcome"] != "blocked" || got["failed_step"] == nil {
		t.Fatalf("verdict fields missing: %v", got)
	}
}

func TestJSON_DoesNotEscapeHTML(t *testing.T) {
	// URLs with & and origins inside <> must survive verbatim for humans
	// piping to jq.
	v, err := cors.Evaluate(cors.Capture{
		Request:  cors.Request{Method: "GET", URL: "https://api.example.test/q?a=1&b=2", Origin: "https://app.example.test"},
		Response: &cors.Response{Status: 200, Headers: cors.Headers{{Name: "Access-Control-Allow-Origin", Value: "*"}}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var buf bytes.Buffer
	if err := JSON(&buf, v, 0); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(buf.String(), `\u0026`) {
		t.Fatalf("HTML escaping must be off:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "a=1&b=2") {
		t.Fatalf("the URL must survive verbatim:\n%s", buf.String())
	}
}
