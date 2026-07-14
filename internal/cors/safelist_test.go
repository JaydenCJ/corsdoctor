// Tests for the request-side safelists: method normalization, the
// per-header value rules, forbidden headers, and full classification.
// These rules decide whether a preflight happens at all, so each case
// pins a behavior developers routinely get wrong.
package cors

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeMethod_UppercasesOnlyTheSixKnownMethods(t *testing.T) {
	for _, in := range []string{"get", "Post", "pUt", "delete", "head", "options"} {
		out, changed := NormalizeMethod(in)
		if out != strings.ToUpper(in) || !changed {
			t.Fatalf("NormalizeMethod(%q) = %q, changed=%v", in, out, changed)
		}
	}
	// PATCH is deliberately not in Fetch's normalize set: "patch" goes out
	// as "patch" and must match Access-Control-Allow-Methods byte-for-byte.
	for _, in := range []string{"patch", "PATCH", "Lock", "PURGE"} {
		out, changed := NormalizeMethod(in)
		if out != in || changed {
			t.Fatalf("NormalizeMethod(%q) = %q, changed=%v; want unchanged", in, out, changed)
		}
	}
}

func TestIsSafelistedMethod_OnlyGetHeadPost(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST"} {
		if !IsSafelistedMethod(m) {
			t.Fatalf("%s should be safelisted", m)
		}
	}
	// The comparison is byte-exact; PUT and lowercase get are not safelisted.
	for _, m := range []string{"PUT", "DELETE", "PATCH", "get", "post"} {
		if IsSafelistedMethod(m) {
			t.Fatalf("%s should not be safelisted", m)
		}
	}
}

func TestSafelistedRequestHeader_AcceptValueAndSizeRules(t *testing.T) {
	if ok, reason := SafelistedRequestHeader("Accept", "text/html,application/xhtml+xml;q=0.9"); !ok {
		t.Fatalf("plain Accept should be safelisted, got: %s", reason)
	}
	if ok, reason := SafelistedRequestHeader("Accept", strings.Repeat("a", 129)); ok || !strings.Contains(reason, "128") {
		t.Fatalf("129-byte value must fail the safelist, got ok=%v reason=%q", ok, reason)
	}
	// '@' is a CORS-unsafe request-header byte.
	if ok, _ := SafelistedRequestHeader("Accept", "text/@html"); ok {
		t.Fatal("Accept with '@' must not be safelisted")
	}
	// Horizontal tab is the one control byte that IS allowed.
	if ok, reason := SafelistedRequestHeader("Accept", "text/html,\tapplication/xml"); !ok {
		t.Fatalf("tab is a safe byte, got: %s", reason)
	}
}

func TestSafelistedRequestHeader_LanguageByteSet(t *testing.T) {
	if ok, reason := SafelistedRequestHeader("Accept-Language", "en-US,en;q=0.9"); !ok {
		t.Fatalf("typical Accept-Language should pass, got: %s", reason)
	}
	// '/' is outside the tight language byte set even though Accept allows it.
	if ok, _ := SafelistedRequestHeader("Content-Language", "en/us"); ok {
		t.Fatal("'/' must disqualify Content-Language")
	}
}

func TestSafelistedRequestHeader_ContentTypeEssenceRules(t *testing.T) {
	for _, v := range []string{
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=----x",
		"text/plain;charset=UTF-8",
		"Text/Plain", // essence comparison is lowercase
	} {
		if ok, reason := SafelistedRequestHeader("Content-Type", v); !ok {
			t.Fatalf("%q should be safelisted, got: %s", v, reason)
		}
	}
	// The classic: application/json always triggers a preflight.
	ok, reason := SafelistedRequestHeader("Content-Type", "application/json")
	if ok || !strings.Contains(reason, "application/json") {
		t.Fatalf("application/json must fail with the essence named, got ok=%v reason=%q", ok, reason)
	}
	// Unparseable values disqualify the header outright.
	for _, v := range []string{"json", "/json", "text/", "te xt/plain"} {
		if ok, _ := SafelistedRequestHeader("Content-Type", v); ok {
			t.Fatalf("%q does not parse as a MIME type and must fail", v)
		}
	}
}

func TestSafelistedRequestHeader_RangeRules(t *testing.T) {
	// Only a single bytes range with an explicit start is safelisted.
	for _, v := range []string{"bytes=0-1023", "bytes=100-"} {
		if ok, reason := SafelistedRequestHeader("Range", v); !ok {
			t.Fatalf("%q should be safelisted, got: %s", v, reason)
		}
	}
	for _, v := range []string{"bytes=-500", "bytes=0-50,100-150", "items=0-10", "bytes=a-b"} {
		if ok, _ := SafelistedRequestHeader("Range", v); ok {
			t.Fatalf("%q must not be safelisted", v)
		}
	}
}

func TestSafelistedRequestHeader_UnknownNameFails(t *testing.T) {
	ok, reason := SafelistedRequestHeader("X-Api-Key", "abc")
	if ok || !strings.Contains(reason, "not on the CORS safelist") {
		t.Fatalf("custom header must fail by name, got ok=%v reason=%q", ok, reason)
	}
}

func TestIsForbiddenRequestHeader_NamesPrefixesAndOverrides(t *testing.T) {
	for _, name := range []string{"Cookie", "origin", "Referer", "Host", "Sec-Fetch-Mode", "Proxy-Authorization", "User-Agent"} {
		if !IsForbiddenRequestHeader(name, "x") {
			t.Fatalf("%s should be treated as browser-owned", name)
		}
	}
	// Authorization is author-settable and must NOT be forbidden — it is
	// the header the "*" wildcard famously never covers.
	for _, name := range []string{"Authorization", "X-Api-Key", "Content-Type"} {
		if IsForbiddenRequestHeader(name, "x") {
			t.Fatalf("%s must not be forbidden", name)
		}
	}
	// Method-override headers are forbidden only when smuggling a
	// forbidden method.
	if !IsForbiddenRequestHeader("X-HTTP-Method-Override", "TRACE") {
		t.Fatal("smuggling TRACE via a method-override header is forbidden")
	}
	if IsForbiddenRequestHeader("X-HTTP-Method-Override", "PATCH") {
		t.Fatal("PATCH via method-override is fine")
	}
}

func TestClassify_SimpleRequestsNeedNoPreflight(t *testing.T) {
	c := Classify("GET", Headers{{Name: "Accept", Value: "application/json"}})
	if c.PreflightRequired {
		t.Fatalf("simple GET must not require a preflight: %+v", c.Reasons)
	}
	if len(c.UnsafeHeaderNames) != 0 {
		t.Fatalf("no unsafe header names expected, got %v", c.UnsafeHeaderNames)
	}
	// A form POST is the canonical simple request.
	c = Classify("POST", Headers{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}})
	if c.PreflightRequired {
		t.Fatalf("a form POST must stay simple: %v", c.Reasons)
	}
}

func TestClassify_MethodAloneTriggersPreflight(t *testing.T) {
	c := Classify("DELETE", nil)
	if !c.PreflightRequired || c.MethodSafelisted {
		t.Fatalf("DELETE must trigger a preflight: %+v", c)
	}
	if len(c.Reasons) != 1 || !strings.Contains(c.Reasons[0], "DELETE") {
		t.Fatalf("the reason must name the method, got %v", c.Reasons)
	}
}

func TestClassify_ForbiddenHeadersNeverTriggerPreflight(t *testing.T) {
	// A wire capture is full of browser-owned headers; classifying them as
	// preflight triggers would produce false diagnoses on every HAR.
	c := Classify("GET", Headers{
		{Name: "Cookie", Value: "sid=1"},
		{Name: "User-Agent", Value: "Mozilla/5.0"},
		{Name: "Sec-Fetch-Site", Value: "cross-site"},
		{Name: "Origin", Value: "https://app.example.test"},
	})
	if c.PreflightRequired {
		t.Fatalf("browser-owned headers must be ignored, got reasons %v", c.Reasons)
	}
}

func TestClassify_UnsafeNamesLowercasedSortedDeduped(t *testing.T) {
	c := Classify("GET", Headers{
		{Name: "X-Trace", Value: "1"},
		{Name: "Authorization", Value: "Bearer t"},
		{Name: "x-trace", Value: "2"},
	})
	want := []string{"authorization", "x-trace"}
	if !reflect.DeepEqual(c.UnsafeHeaderNames, want) {
		t.Fatalf("UnsafeHeaderNames = %v, want %v (this is the Access-Control-Request-Headers value)", c.UnsafeHeaderNames, want)
	}
}

func TestClassify_AggregateSafelistSizeOver1024(t *testing.T) {
	// Individually safelisted headers spill into the preflight when their
	// combined value size exceeds 1024 bytes.
	long := strings.Repeat("en,", 42) + "en" // 128 bytes, individually fine
	var h Headers
	for i := 0; i < 9; i++ {
		h = append(h, Header{Name: "Accept-Language", Value: long})
	}
	c := Classify("GET", h)
	if !c.PreflightRequired {
		t.Fatal("9×128 bytes of safelisted values exceed the 1024 aggregate limit")
	}
	if !strings.Contains(c.Headers[0].Reason, "1024") {
		t.Fatalf("the reason must cite the aggregate rule, got %q", c.Headers[0].Reason)
	}
}
