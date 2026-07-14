// Tests for origin parsing, serialization, and the mismatch diagnosis.
// CORS compares *serialized* origins byte-for-byte, so canonicalization
// (lowercasing, default-port elision, no trailing slash) is load-bearing.
package cors

import (
	"strings"
	"testing"
)

func mustOrigin(t *testing.T, s string) Origin {
	t.Helper()
	o, err := ParseOrigin(s)
	if err != nil {
		t.Fatalf("ParseOrigin(%q): %v", s, err)
	}
	return o
}

func TestParseOrigin_BasicAndNull(t *testing.T) {
	o := mustOrigin(t, "https://app.example.test")
	if o.Scheme != "https" || o.Host != "app.example.test" || o.Port != "" || o.Opaque {
		t.Fatalf("unexpected origin: %+v", o)
	}
	if !mustOrigin(t, "null").Opaque {
		t.Fatal(`"null" must parse as the opaque origin`)
	}
}

func TestParseOrigin_CanonicalSerialization(t *testing.T) {
	// https://x:443 and https://x are the SAME origin; the serialization
	// drops the default port, which is what the byte comparison sees.
	if got := mustOrigin(t, "https://api.example.test:443").Serialize(); got != "https://api.example.test" {
		t.Fatalf("got %q", got)
	}
	if got := mustOrigin(t, "http://api.example.test:8080").Serialize(); got != "http://api.example.test:8080" {
		t.Fatalf("non-default port must survive, got %q", got)
	}
	// Scheme and host are lowercased, as browsers serialize them.
	if got := mustOrigin(t, "HTTPS://API.Example.TEST").Serialize(); got != "https://api.example.test" {
		t.Fatalf("got %q", got)
	}
}

func TestParseOrigin_ToleratesOneTrailingSlash(t *testing.T) {
	// Humans paste "https://app.example.test/" from the address bar.
	if got := mustOrigin(t, "https://app.example.test/").Serialize(); got != "https://app.example.test" {
		t.Fatalf("got %q", got)
	}
}

func TestParseOrigin_RejectsPathsQueriesAndBareHosts(t *testing.T) {
	for _, s := range []string{
		"https://app.example.test/login",
		"https://app.example.test?x=1",
		"https://user:pw@app.example.test",
		"app.example.test",
	} {
		if _, err := ParseOrigin(s); err == nil {
			t.Fatalf("%q must be rejected as a serialized origin", s)
		}
	}
}

func TestSameOrigin_PortAndSchemeMatter(t *testing.T) {
	a := mustOrigin(t, "http://127.0.0.1:5173")
	if !SameOrigin(a, mustOrigin(t, "http://127.0.0.1:5173")) {
		t.Fatal("identical origins must be same-origin")
	}
	if SameOrigin(a, mustOrigin(t, "http://127.0.0.1:3000")) {
		t.Fatal("different ports are different origins")
	}
	if SameOrigin(mustOrigin(t, "https://x.test"), mustOrigin(t, "http://x.test")) {
		t.Fatal("different schemes are different origins")
	}
	// The opaque origin is not same-origin even with itself.
	n := mustOrigin(t, "null")
	if SameOrigin(n, n) {
		t.Fatal("the opaque origin is not same-origin even with itself")
	}
}

func TestDiagnoseOriginMismatch_NamesTheStructuralCause(t *testing.T) {
	origin := mustOrigin(t, "https://app.example.test")
	cases := []struct {
		allow string
		want  string // substring the diagnosis must contain
	}{
		{"https://app.example.test, https://app.example.test", "multiple values"},
		{"https://app.example.test/", "trailing slash"},
		{"http://app.example.test", "scheme mismatch"},
		// ParseOrigin lowercases, so case must be diagnosed on the raw value.
		{"https://APP.example.test", "letter case"},
		{"https://app.example.test:8443", "port mismatch"},
		{"https://example.test", "subdomain"},
		{"null", `literal "null"`},
		{"https://other.test", "byte-for-byte different"},
	}
	for _, c := range cases {
		got := diagnoseOriginMismatch(c.allow, origin)
		if !strings.Contains(got, c.want) {
			t.Fatalf("diagnose(%q) = %q; want it to mention %q", c.allow, got, c.want)
		}
	}
}

func TestDiagnoseOriginMismatch_OpaqueRequestOrigin(t *testing.T) {
	got := diagnoseOriginMismatch("https://app.example.test", mustOrigin(t, "null"))
	if !strings.Contains(got, "opaque") {
		t.Fatalf("diagnosis must explain the null origin, got %q", got)
	}
}
