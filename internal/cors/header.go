// Package cors implements the CORS algorithm from the WHATWG Fetch standard
// over captured requests and responses: request classification (does this
// request need a preflight, and why), the CORS-preflight checks, and the
// CORS check proper. Every check is a named step with a spec reference, so
// a failure can be pinpointed instead of guessed at.
package cors

import "strings"

// Header is a single HTTP header field as captured on the wire.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Headers is an ordered header list, mirroring Fetch's "header list".
type Headers []Header

// Get returns the combined value for name: every field whose name matches
// byte-case-insensitively, joined with ", ". This is exactly how Fetch's
// `get` combines duplicate fields — and why a duplicated
// Access-Control-Allow-Origin turns into "a, b" and fails the byte
// comparison against the origin.
func (h Headers) Get(name string) (string, bool) {
	var parts []string
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			parts = append(parts, f.Value)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ", "), true
}

// Count reports how many separate fields carry name (case-insensitive).
func (h Headers) Count(name string) int {
	n := 0
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			n++
		}
	}
	return n
}

// Has reports whether at least one field carries name.
func (h Headers) Has(name string) bool { return h.Count(name) > 0 }
