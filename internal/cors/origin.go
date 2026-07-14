package cors

import (
	"fmt"
	"net/url"
	"strings"
)

// Origin is a tuple origin (scheme, host, port) or the opaque origin
// serialized as "null". CORS compares *serialized* origins byte-for-byte,
// so the canonical serialization here (lowercased, default port elided,
// no trailing slash) is what every check runs against.
type Origin struct {
	Scheme string
	Host   string
	Port   string // empty when it is the scheme's default
	Opaque bool   // the "null" origin (sandboxed iframe, file://, data:)
}

// defaultPorts maps schemes to the port their serialization elides.
var defaultPorts = map[string]string{
	"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21",
}

// ParseOrigin parses a serialized origin such as "https://app.example.test"
// or the literal "null". It is deliberately lenient about one thing a human
// will paste — a single trailing slash — and strict about everything else,
// because an Origin header never carries a path, query, or fragment.
func ParseOrigin(s string) (Origin, error) {
	s = strings.TrimSpace(s)
	if s == "null" {
		return Origin{Opaque: true}, nil
	}
	trimmed := strings.TrimSuffix(s, "/")
	u, err := url.Parse(trimmed)
	if err != nil {
		return Origin{}, fmt.Errorf("not a serialized origin: %v", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return Origin{}, fmt.Errorf("%q is not a serialized origin (need scheme://host[:port])", s)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return Origin{}, fmt.Errorf("%q is not a serialized origin: it carries a path, query, fragment, or userinfo", s)
	}
	return originOf(u), nil
}

// OriginOfURL computes the origin of an absolute request URL.
func OriginOfURL(u *url.URL) Origin { return originOf(u) }

func originOf(u *url.URL) Origin {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == defaultPorts[scheme] {
		port = "" // https://x:443 and https://x are the same origin
	}
	return Origin{Scheme: scheme, Host: host, Port: port}
}

// Serialize returns the ASCII serialization used in the Origin header and
// compared byte-for-byte against Access-Control-Allow-Origin.
func (o Origin) Serialize() string {
	if o.Opaque {
		return "null"
	}
	s := o.Scheme + "://" + o.Host
	if o.Port != "" {
		s += ":" + o.Port
	}
	return s
}

// SameOrigin reports whether a and b are the same origin. Opaque origins
// are never same-origin with anything, including each other.
func SameOrigin(a, b Origin) bool {
	if a.Opaque || b.Opaque {
		return false
	}
	return a.Scheme == b.Scheme && a.Host == b.Host && a.Port == b.Port
}

// diagnoseOriginMismatch explains *why* an Access-Control-Allow-Origin
// value failed the byte comparison against the request origin — the single
// most common CORS failure, and the one where a generic "mismatch" helps
// nobody. It names the first structural difference it can prove.
func diagnoseOriginMismatch(allow string, origin Origin) string {
	serialized := origin.Serialize()
	if strings.Contains(allow, ",") {
		return fmt.Sprintf("the header carries multiple values (%q); browsers join duplicate fields with \", \" and the result can never byte-match one origin — two layers (e.g. a proxy and the app) are probably both setting it", allow)
	}
	if allow == "null" {
		return fmt.Sprintf("the server allows only the literal \"null\" origin, but the request came from %s", serialized)
	}
	if origin.Opaque {
		return fmt.Sprintf("the request origin is the opaque \"null\" origin (sandboxed iframe, file://, or data: page); only the literal value null would match, the server sent %q", allow)
	}
	if strings.HasSuffix(allow, "/") || strings.Count(allow, "/") > 2 {
		return fmt.Sprintf("%q carries a trailing slash or path; serialized origins never do — the exact value must be %q", allow, serialized)
	}
	if strings.EqualFold(allow, serialized) {
		return fmt.Sprintf("%q differs from the request origin only in letter case; browsers lowercase the scheme and host when serializing, and the comparison is byte-exact — send exactly %q", allow, serialized)
	}
	got, err := ParseOrigin(allow)
	if err != nil {
		return fmt.Sprintf("%q does not even parse as a serialized origin (%v)", allow, err)
	}
	switch {
	case got.Scheme != origin.Scheme && got.Host == origin.Host:
		return fmt.Sprintf("scheme mismatch: the page is on %s:// but the server allows %s:// — %q vs %q", origin.Scheme, got.Scheme, serialized, allow)
	case got.Scheme == origin.Scheme && got.Host == origin.Host && got.Port != origin.Port:
		return fmt.Sprintf("port mismatch: the page origin is %q but the server allows %q — ports are part of the origin, and default ports (80/443) are elided when serialized", serialized, allow)
	case strings.HasSuffix(origin.Host, "."+got.Host) || strings.HasSuffix(got.Host, "."+origin.Host):
		return fmt.Sprintf("host mismatch on a related domain (%q vs %q); origins do not inherit across subdomains — each subdomain must be allowed exactly", allow, serialized)
	default:
		return fmt.Sprintf("%q is byte-for-byte different from the request origin %q", allow, serialized)
	}
}
