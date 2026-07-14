package capture

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JaydenCJ/corsdoctor/internal/cors"
)

// This file reads the subset of HAR 1.2 that CORS diagnosis needs. The
// interesting work is pairing: finding the entry to diagnose, finding its
// preflight, and — when the preflight failed and the browser therefore
// never sent the real request — reconstructing that request from the
// preflight's Access-Control-Request-* headers.

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request struct {
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers []harHeader `json:"headers"`
	} `json:"request"`
	Response struct {
		Status  int         `json:"status"`
		Headers []harHeader `json:"headers"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func harHeaders(hh []harHeader) cors.Headers {
	out := make(cors.Headers, 0, len(hh))
	for _, h := range hh {
		// Browsers export HTTP/2 pseudo-headers (:method, :path…); they
		// are transport artifacts, not header fields.
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		out = append(out, cors.Header{Name: h.Name, Value: h.Value})
	}
	return out
}

// isPreflight recognizes a preflight entry: OPTIONS plus the
// Access-Control-Request-Method header the browser always attaches.
func (e harEntry) isPreflight() bool {
	return strings.EqualFold(e.Request.Method, "OPTIONS") &&
		harHeaders(e.Request.Headers).Has("Access-Control-Request-Method")
}

// parseHAR selects and assembles the capture from a HAR export.
func parseHAR(data []byte, opts Options) (cors.Capture, error) {
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return cors.Capture{}, fmt.Errorf("HAR: %v", err)
	}
	var candidates []harEntry
	for _, e := range har.Log.Entries {
		if opts.URLFilter == "" || strings.Contains(e.Request.URL, opts.URLFilter) {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		if opts.URLFilter != "" {
			return cors.Capture{}, fmt.Errorf("HAR: no entry matches --url %q", opts.URLFilter)
		}
		return cors.Capture{}, fmt.Errorf("HAR: the file contains no entries")
	}

	var mains, preflights []harEntry
	for _, e := range candidates {
		if e.isPreflight() {
			preflights = append(preflights, e)
		} else {
			mains = append(mains, e)
		}
	}

	if len(mains) == 0 {
		// Only preflights matched: the browser never sent the real
		// request — which is itself diagnostic (the preflight failed).
		return captureFromPreflight(preflights[0])
	}

	main := mains[0]
	c := cors.Capture{
		Request: cors.Request{
			Method:  main.Request.Method,
			URL:     main.Request.URL,
			Headers: harHeaders(main.Request.Headers),
		},
		Response: &cors.Response{
			Status:  main.Response.Status,
			Headers: harHeaders(main.Response.Headers),
		},
	}
	if len(mains) > 1 {
		c.Notes = append(c.Notes, fmt.Sprintf(
			"%d non-preflight entries matched; diagnosing the first (%s %s) — narrow with --url to pick another",
			len(mains), main.Request.Method, main.Request.URL))
	}

	// Pair the preflight: same URL, and (when present) an
	// Access-Control-Request-Method that matches the main method.
	for _, p := range preflights {
		if p.Request.URL != main.Request.URL {
			continue
		}
		acrm, _ := harHeaders(p.Request.Headers).Get("Access-Control-Request-Method")
		if acrm != "" && !strings.EqualFold(acrm, main.Request.Method) {
			continue
		}
		c.Preflight = &cors.Response{Status: p.Response.Status, Headers: harHeaders(p.Response.Headers)}
		break
	}

	// HAR does not record fetch's credentials mode; infer it from what
	// actually went over the wire, and say so.
	if c.Request.Headers.Has("Cookie") || c.Request.Headers.Has("Authorization") {
		c.Request.Credentials = true
		c.Notes = append(c.Notes,
			"credentials mode inferred as \"include\" (the request carried Cookie or Authorization); override with --no-credentials if that is wrong")
	}
	return c, nil
}

// captureFromPreflight rebuilds the request the browser *intended* to send
// from the preflight's Access-Control-Request-Method / -Headers, so a HAR
// of a failed preflight is still fully diagnosable.
func captureFromPreflight(p harEntry) (cors.Capture, error) {
	reqHeaders := harHeaders(p.Request.Headers)
	method, ok := reqHeaders.Get("Access-Control-Request-Method")
	if !ok {
		return cors.Capture{}, fmt.Errorf("HAR: the OPTIONS entry has no Access-Control-Request-Method header")
	}
	origin, _ := reqHeaders.Get("Origin")
	c := cors.Capture{
		Request: cors.Request{
			Method: method,
			URL:    p.Request.URL,
			Origin: origin,
		},
		Preflight: &cors.Response{Status: p.Response.Status, Headers: harHeaders(p.Response.Headers)},
		Notes: []string{
			"only the preflight is in the HAR — the browser never sent the real request; it was reconstructed from Access-Control-Request-Method/-Headers",
		},
	}
	if acrh, ok := reqHeaders.Get("Access-Control-Request-Headers"); ok {
		for _, name := range strings.Split(acrh, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				// Values are unknown (only names cross the wire in a
				// preflight); an empty value classifies every one of
				// these names as unsafe, which is what being listed in
				// Access-Control-Request-Headers already proves.
				c.Request.Headers = append(c.Request.Headers, cors.Header{Name: name, Value: ""})
			}
		}
	}
	return c, nil
}
