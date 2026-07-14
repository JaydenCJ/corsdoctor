// Package capture parses the two input formats corsdoctor understands —
// its own JSON capture format (docs/capture-format.md) and HAR files saved
// from a browser's network panel — into a cors.Capture ready to evaluate.
package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/JaydenCJ/corsdoctor/internal/cors"
)

// Options tune parsing.
type Options struct {
	// URLFilter selects the HAR entry to diagnose (substring match).
	URLFilter string
	// Credentials, when non-nil, overrides the capture's credentials mode
	// (--credentials / --no-credentials).
	Credentials *bool
}

// Parse sniffs the format (a top-level "log" key means HAR) and parses.
func Parse(data []byte, opts Options) (cors.Capture, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return cors.Capture{}, fmt.Errorf("input is not valid JSON: %v", err)
	}
	var c cors.Capture
	var err error
	if _, isHAR := probe["log"]; isHAR {
		c, err = parseHAR(data, opts)
	} else {
		c, err = parseCaptureJSON(data)
	}
	if err != nil {
		return cors.Capture{}, err
	}
	if opts.Credentials != nil {
		c.Request.Credentials = *opts.Credentials
		c.Notes = append(c.Notes, fmt.Sprintf("credentials mode forced to %v by flag", *opts.Credentials))
	}
	return c, nil
}

// headerValue accepts both `"k": "v"` and `"k": ["v1", "v2"]` in JSON.
type headerValue []string

func (h *headerValue) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*h = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*h = many
		return nil
	}
	return fmt.Errorf("header values must be a string or an array of strings")
}

// credentialsValue accepts a bool or fetch's credentials-mode strings.
type credentialsValue struct {
	set bool
	val bool
}

func (c *credentialsValue) UnmarshalJSON(b []byte) error {
	var asBool bool
	if err := json.Unmarshal(b, &asBool); err == nil {
		c.set, c.val = true, asBool
		return nil
	}
	var asString string
	if err := json.Unmarshal(b, &asString); err == nil {
		switch asString {
		case "include":
			c.set, c.val = true, true
			return nil
		case "omit", "same-origin":
			c.set, c.val = true, false
			return nil
		}
		return fmt.Errorf("credentials must be a bool or one of \"include\", \"same-origin\", \"omit\"; got %q", asString)
	}
	return fmt.Errorf("credentials must be a bool or a fetch credentials-mode string")
}

type jsonMessage struct {
	Status  int                    `json:"status"`
	Headers map[string]headerValue `json:"headers"`
}

type jsonCapture struct {
	Request *struct {
		Method      string                 `json:"method"`
		URL         string                 `json:"url"`
		Origin      string                 `json:"origin"`
		Headers     map[string]headerValue `json:"headers"`
		Credentials credentialsValue       `json:"credentials"`
	} `json:"request"`
	Preflight *jsonMessage `json:"preflight"`
	Response  *jsonMessage `json:"response"`
}

// parseCaptureJSON parses corsdoctor's own capture format.
func parseCaptureJSON(data []byte) (cors.Capture, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw jsonCapture
	if err := dec.Decode(&raw); err != nil {
		return cors.Capture{}, fmt.Errorf("capture JSON: %v (see docs/capture-format.md)", err)
	}
	if raw.Request == nil {
		return cors.Capture{}, fmt.Errorf("capture JSON: a \"request\" object is required (see docs/capture-format.md)")
	}
	if raw.Request.URL == "" {
		return cors.Capture{}, fmt.Errorf("capture JSON: request.url is required")
	}
	c := cors.Capture{
		Request: cors.Request{
			Method:      raw.Request.Method,
			URL:         raw.Request.URL,
			Origin:      raw.Request.Origin,
			Headers:     mapHeaders(raw.Request.Headers),
			Credentials: raw.Request.Credentials.val,
		},
	}
	if raw.Preflight != nil {
		c.Preflight = toResponse(raw.Preflight)
	}
	if raw.Response != nil {
		c.Response = toResponse(raw.Response)
	}
	if c.Preflight != nil && c.Preflight.Status == 0 {
		return cors.Capture{}, fmt.Errorf("capture JSON: preflight.status is required when a preflight is given")
	}
	if c.Response != nil && c.Response.Status == 0 {
		return cors.Capture{}, fmt.Errorf("capture JSON: response.status is required when a response is given")
	}
	return c, nil
}

func toResponse(m *jsonMessage) *cors.Response {
	return &cors.Response{Status: m.Status, Headers: mapHeaders(m.Headers)}
}

// mapHeaders flattens the JSON header object into an ordered list. JSON
// objects have no order, so keys are sorted for deterministic output.
func mapHeaders(m map[string]headerValue) cors.Headers {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var h cors.Headers
	for _, k := range keys {
		for _, v := range m[k] {
			h = append(h, cors.Header{Name: k, Value: v})
		}
	}
	return h
}
