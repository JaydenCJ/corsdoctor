package cors

import (
	"fmt"
	"sort"
	"strings"
)

// This file implements the Fetch standard's request-side safelists: which
// methods and headers a browser will send cross-origin *without* asking the
// server first. Anything outside these lists is what triggers a preflight,
// so getting the value-level rules right (not just the header names) is the
// difference between diagnosing a preflight and hallucinating one.

// normalizableMethods are the methods Fetch byte-uppercases before sending.
// Famously, PATCH is absent: fetch(url, {method: "patch"}) goes out as
// "patch" and is compared byte-for-byte against Access-Control-Allow-Methods.
var normalizableMethods = map[string]string{
	"delete": "DELETE", "get": "GET", "head": "HEAD",
	"options": "OPTIONS", "post": "POST", "put": "PUT",
}

// NormalizeMethod applies Fetch's "normalize a method": uppercase the six
// well-known methods, leave everything else (PATCH, LOCK, custom verbs)
// byte-exact. Returns the wire method and whether it changed.
func NormalizeMethod(m string) (string, bool) {
	if up, ok := normalizableMethods[strings.ToLower(m)]; ok {
		return up, up != m
	}
	return m, false
}

// IsSafelistedMethod reports whether m is a CORS-safelisted method
// (`GET`, `HEAD`, or `POST`). The comparison is byte-exact; callers must
// normalize first, as the browser does.
func IsSafelistedMethod(m string) bool {
	return m == "GET" || m == "HEAD" || m == "POST"
}

// forbiddenMethods can never be smuggled through method-override headers.
func isForbiddenMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "CONNECT", "TRACE", "TRACK":
		return true
	}
	return false
}

// forbiddenRequestHeaders are header names the browser controls itself; page
// script cannot set them, so they never count toward the preflight decision.
// Diagnosing a captured request without this list produces false "this
// header forces a preflight" claims for Cookie, Referer, User-Agent, etc.
var forbiddenRequestHeaders = map[string]bool{
	"accept-charset": true, "accept-encoding": true,
	"access-control-request-headers": true, "access-control-request-method": true,
	"connection": true, "content-length": true, "cookie": true, "cookie2": true,
	"date": true, "dnt": true, "expect": true, "host": true, "keep-alive": true,
	"origin": true, "referer": true, "set-cookie": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true, "via": true,
	// Not in Fetch's list but always browser-generated in practice.
	"user-agent": true,
}

// IsForbiddenRequestHeader implements Fetch's "forbidden request-header":
// the fixed name list, the `Proxy-` and `Sec-` prefixes, and the
// method-override names when their value smuggles a forbidden method.
func IsForbiddenRequestHeader(name, value string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "proxy-") || strings.HasPrefix(n, "sec-") {
		return true
	}
	if forbiddenRequestHeaders[n] {
		return true
	}
	switch n {
	case "x-http-method", "x-http-method-override", "x-method-override":
		for _, m := range splitList(value) {
			if isForbiddenMethod(m) {
				return true
			}
		}
	}
	return false
}

// hasCORSUnsafeByte reports whether v contains a "CORS-unsafe
// request-header byte": a control byte other than HT, or one of
// "():<>?@[\]{} and DEL.
func hasCORSUnsafeByte(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 && b != 0x09 {
			return true
		}
		switch b {
		case '"', '(', ')', ':', '<', '>', '?', '@', '[', '\\', ']', '{', '}', 0x7f:
			return true
		}
	}
	return false
}

// isLanguageValue checks the tight byte set Fetch allows for
// Accept-Language and Content-Language: 0-9 A-Z a-z and " *,-.;=".
func isLanguageValue(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		switch {
		case b >= '0' && b <= '9', b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z':
		case b == 0x20, b == '*', b == ',', b == '-', b == '.', b == ';', b == '=':
		default:
			return false
		}
	}
	return true
}

// mimeEssence extracts and validates "type/subtype" from a Content-Type
// value, lowercased with parameters stripped, per MIME Sniffing "parse a
// MIME type". Returns ok=false when the value does not parse as a MIME type
// (which by itself disqualifies the header from the safelist).
func mimeEssence(v string) (string, bool) {
	v = strings.Trim(v, " \t")
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = strings.TrimRight(v[:i], " \t")
	}
	slash := strings.IndexByte(v, '/')
	if slash <= 0 || slash == len(v)-1 {
		return "", false
	}
	typ, sub := v[:slash], v[slash+1:]
	if !isHTTPToken(typ) || !isHTTPToken(sub) {
		return "", false
	}
	return strings.ToLower(typ) + "/" + strings.ToLower(sub), true
}

// isSimpleRangeValue implements Fetch's safelisted Range check: exactly one
// `bytes=` range whose start position is present (e.g. `bytes=0-1023` or
// `bytes=100-`); suffix ranges (`bytes=-500`) and multi-ranges trigger a
// preflight.
func isSimpleRangeValue(v string) bool {
	rest, ok := strings.CutPrefix(v, "bytes=")
	if !ok {
		return false
	}
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 { // no dash, or empty start position
		return false
	}
	return isDigits(rest[:dash]) && (rest[dash+1:] == "" || isDigits(rest[dash+1:]))
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// safelistedContentTypes are the three MIME essences a cross-origin request
// may carry without a preflight — the ones HTML forms could always send.
var safelistedContentTypes = map[string]bool{
	"application/x-www-form-urlencoded": true,
	"multipart/form-data":               true,
	"text/plain":                        true,
}

// SafelistedRequestHeader implements Fetch's "CORS-safelisted
// request-header" check for a single (name, value) pair, returning whether
// the pair is safelisted and, when it is not, a human-readable reason
// naming the exact rule that disqualified it.
func SafelistedRequestHeader(name, value string) (bool, string) {
	lower := strings.ToLower(name)
	switch lower {
	case "accept", "accept-language", "content-language", "content-type", "range":
	default:
		return false, "the name is not on the CORS safelist (accept, accept-language, content-language, content-type, range)"
	}
	if len(value) > 128 {
		return false, fmt.Sprintf("the value is %d bytes; the safelist cuts off at 128", len(value))
	}
	switch lower {
	case "accept":
		if hasCORSUnsafeByte(value) {
			return false, "the value contains a CORS-unsafe byte"
		}
	case "accept-language", "content-language":
		if !isLanguageValue(value) {
			return false, `the value contains a byte outside 0-9 A-Z a-z " *,-.;="`
		}
	case "content-type":
		if hasCORSUnsafeByte(value) {
			return false, "the value contains a CORS-unsafe byte"
		}
		essence, ok := mimeEssence(value)
		if !ok {
			return false, fmt.Sprintf("%q does not parse as a MIME type", value)
		}
		if !safelistedContentTypes[essence] {
			return false, fmt.Sprintf("MIME essence %q is not application/x-www-form-urlencoded, multipart/form-data, or text/plain", essence)
		}
	case "range":
		if !isSimpleRangeValue(value) {
			return false, "only a single bytes range with an explicit start (e.g. bytes=0-1023) is safelisted"
		}
	}
	return true, ""
}

// HeaderFinding is the classification of one captured request header.
type HeaderFinding struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	Safelisted bool   `json:"safelisted"`
	Forbidden  bool   `json:"forbidden,omitempty"` // browser-owned, ignored by CORS
	Reason     string `json:"reason,omitempty"`
}

// Classification is the verdict of the request-side algorithm: whether a
// preflight is needed, and the exact reasons.
type Classification struct {
	Method            string          `json:"method"`
	MethodSafelisted  bool            `json:"method_safelisted"`
	Headers           []HeaderFinding `json:"headers"`
	UnsafeHeaderNames []string        `json:"unsafe_header_names"` // = Access-Control-Request-Headers
	PreflightRequired bool            `json:"preflight_required"`
	Reasons           []string        `json:"preflight_reasons,omitempty"`
}

// Classify runs the request side of the CORS algorithm: normalize the
// method, drop forbidden (browser-owned) headers, apply the per-header
// value rules, and apply the aggregate 1024-byte rule under which even
// safelisted headers spill into the preflight. The returned
// UnsafeHeaderNames is byte-lowercased and sorted — exactly the list the
// browser would send as Access-Control-Request-Headers.
func Classify(method string, headers Headers) Classification {
	c := Classification{Method: method, MethodSafelisted: IsSafelistedMethod(method)}
	if !c.MethodSafelisted {
		c.Reasons = append(c.Reasons,
			fmt.Sprintf("method %s is not CORS-safelisted (only GET, HEAD, POST are)", method))
	}

	safelistedValueSize := 0
	var safelistedIdx []int
	for _, h := range headers {
		f := HeaderFinding{Name: h.Name, Value: h.Value}
		switch {
		case IsForbiddenRequestHeader(h.Name, h.Value):
			f.Forbidden = true
			f.Reason = "set by the browser, never part of the preflight decision"
		default:
			f.Safelisted, f.Reason = SafelistedRequestHeader(h.Name, h.Value)
			if f.Safelisted {
				safelistedValueSize += len(h.Value)
				safelistedIdx = append(safelistedIdx, len(c.Headers))
			}
		}
		c.Headers = append(c.Headers, f)
	}

	// Aggregate rule: if the combined size of safelisted values exceeds
	// 1024 bytes, every safelisted header is treated as unsafe too.
	if safelistedValueSize > 1024 {
		for _, i := range safelistedIdx {
			c.Headers[i].Safelisted = false
			c.Headers[i].Reason = fmt.Sprintf(
				"safelisted on its own, but the combined safelisted value size is %d bytes (limit 1024)", safelistedValueSize)
		}
	}

	seen := map[string]bool{}
	for _, f := range c.Headers {
		if f.Forbidden || f.Safelisted {
			continue
		}
		lower := strings.ToLower(f.Name)
		if !seen[lower] {
			seen[lower] = true
			c.UnsafeHeaderNames = append(c.UnsafeHeaderNames, lower)
			c.Reasons = append(c.Reasons, fmt.Sprintf("header %s: %s", lower, f.Reason))
		}
	}
	sort.Strings(c.UnsafeHeaderNames)
	sort.Slice(c.Headers, func(i, j int) bool {
		return strings.ToLower(c.Headers[i].Name) < strings.ToLower(c.Headers[j].Name)
	})
	c.PreflightRequired = !c.MethodSafelisted || len(c.UnsafeHeaderNames) > 0
	return c
}
