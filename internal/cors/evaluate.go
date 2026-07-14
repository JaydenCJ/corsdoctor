package cors

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Request is the captured cross-origin request as the browser sent it (or
// would send it).
type Request struct {
	Method      string  `json:"method"`
	URL         string  `json:"url"`
	Origin      string  `json:"origin"` // serialized origin of the requesting page, or "null"
	Headers     Headers `json:"-"`
	Credentials bool    `json:"credentials"` // credentials mode "include"
}

// Response is a captured HTTP response (status + headers; CORS never looks
// at the body).
type Response struct {
	Status  int
	Headers Headers
}

// Capture pairs the request with the responses that came back. Preflight
// and Response are each optional — the doctor reports what it can prove
// and names what is missing.
type Capture struct {
	Request   Request
	Preflight *Response
	Response  *Response
	Notes     []string // provenance notes from the parser (e.g. HAR inference)
}

// Outcome is the overall verdict.
type Outcome string

const (
	// OutcomeAllowed: every check the browser would run passes.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeBlocked: a check failed; Verdict.Failed names it.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeIncomplete: nothing failed, but a required message was not
	// captured, so the diagnosis cannot be finished.
	OutcomeIncomplete Outcome = "incomplete"
	// OutcomeNotCORS: the request is same-origin; CORS does not apply.
	OutcomeNotCORS Outcome = "not-cors"
	// OutcomeAdvisory: no responses captured at all — the verdict is the
	// list of requirements the server must meet.
	OutcomeAdvisory Outcome = "advisory"
)

// Verdict is the full diagnosis.
type Verdict struct {
	Request        Request        `json:"request"`
	Origin         string         `json:"origin"` // canonical serialization used in checks
	CrossOrigin    bool           `json:"cross_origin"`
	Classification Classification `json:"classification"`
	Steps          []Step         `json:"steps"`
	Failed         *Step          `json:"failed_step,omitempty"`
	Outcome        Outcome        `json:"outcome"`
	Summary        string         `json:"summary"`
	BrowserMessage string         `json:"browser_message,omitempty"`
	Fixes          []string       `json:"fixes,omitempty"`
	Requirements   []string       `json:"requirements,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
	Notes          []string       `json:"notes,omitempty"`
	ExposedHeaders []string       `json:"exposed_headers,omitempty"`
}

// Evaluate runs the CORS algorithm over a capture and returns the verdict.
// It returns an error only when the input is unusable (relative URL, no
// origin); a *failing* request is a successful diagnosis.
func Evaluate(c Capture) (*Verdict, error) {
	req := c.Request
	if strings.TrimSpace(req.URL) == "" {
		return nil, errors.New("request.url is required")
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("request.url %q is not an absolute URL", req.URL)
	}
	if req.Origin == "" {
		if v, ok := req.Headers.Get("Origin"); ok {
			req.Origin = v
		} else {
			return nil, errors.New("the requesting origin is unknown: set request.origin, include an Origin request header, or pass --origin")
		}
	}
	pageOrigin, err := ParseOrigin(req.Origin)
	if err != nil {
		return nil, fmt.Errorf("origin %q: %v", req.Origin, err)
	}

	if req.Method == "" {
		req.Method = "GET"
	}
	method, changed := NormalizeMethod(req.Method)
	v := &Verdict{Request: req, Origin: pageOrigin.Serialize(), Notes: append([]string(nil), c.Notes...)}
	v.Request.Method = method
	if changed {
		v.Notes = append(v.Notes, fmt.Sprintf("method %q normalized to %q, as the browser does before sending", req.Method, method))
	}

	// Same-origin requests never run CORS checks; a "CORS error" on one
	// means the two URLs are not actually the same origin.
	target := OriginOfURL(u)
	v.CrossOrigin = !SameOrigin(pageOrigin, target)
	if !v.CrossOrigin {
		v.Outcome = OutcomeNotCORS
		v.Summary = fmt.Sprintf("%s and the request URL share scheme, host, and port — this is a same-origin request and the browser applies no CORS checks", v.Origin)
		v.Notes = append(v.Notes, "if the browser still reports a CORS error, the page's real origin differs from the one given here; read it from the actual Origin request header in DevTools")
		return v, nil
	}

	v.Classification = Classify(method, req.Headers)
	cls := v.Classification

	// Preflight phase.
	preflightBlocks := cls.PreflightRequired
	if c.Preflight != nil {
		steps := evaluatePreflight(pageOrigin, req.Credentials, method, cls.UnsafeHeaderNames, c.Preflight)
		for i := range steps {
			steps[i].Blocking = preflightBlocks
		}
		if !preflightBlocks {
			v.Notes = append(v.Notes, "a preflight was captured but this request does not require one; it is evaluated below without affecting the verdict")
		}
		v.Steps = append(v.Steps, steps...)
	}

	preflightFailed := false
	for _, s := range v.Steps {
		if s.Blocking && s.Status == StatusFail {
			preflightFailed = true
			break
		}
	}

	// Response phase.
	if c.Response != nil {
		if preflightFailed {
			v.Steps = append(v.Steps, Step{
				ID: "response.cors-check", Phase: "response",
				Title:  "CORS check on the actual response",
				Status: StatusSkip,
				Detail: "the browser never sends the actual request when the preflight fails",
			})
		} else {
			steps := corsCheck("response", pageOrigin, req.Credentials, c.Response)
			for i := range steps {
				steps[i].Blocking = true
			}
			v.Steps = append(v.Steps, steps...)
		}
	}

	v.finish(c, pageOrigin)
	return v, nil
}

// finish computes the verdict, warnings, browser message, fixes, and
// exposed headers once all steps are in place.
func (v *Verdict) finish(c Capture, origin Origin) {
	for i := range v.Steps {
		s := &v.Steps[i]
		if s.Blocking && s.Status == StatusFail {
			v.Failed = s
			break
		}
	}
	for _, s := range v.Steps {
		if !s.Blocking && s.Status == StatusFail {
			v.Warnings = append(v.Warnings, fmt.Sprintf(
				"the captured preflight would fail at %s if the browser ever sent one (%s)", s.ID, s.Detail))
		}
	}

	cls := v.Classification
	switch {
	case v.Failed != nil:
		v.Outcome = OutcomeBlocked
		v.Summary = fmt.Sprintf("blocked at %s — %s", v.Failed.ID, v.Failed.Title)
		v.BrowserMessage = browserMessage(v.Failed, v.Request.URL, v.Origin)
		if v.Failed.Fix != "" {
			v.Fixes = append(v.Fixes, v.Failed.Fix)
		}
		v.crossPhaseHints(c)
	case cls.PreflightRequired && c.Preflight == nil && c.Response == nil:
		v.Outcome = OutcomeAdvisory
		v.Summary = "no responses captured — listing what the server must send for this request to pass"
		v.Requirements = v.requirements(origin)
	case c.Preflight == nil && c.Response == nil:
		v.Outcome = OutcomeAdvisory
		v.Summary = "no responses captured — this request needs no preflight; listing what the response must carry"
		v.Requirements = v.requirements(origin)
	case cls.PreflightRequired && c.Preflight == nil:
		v.Outcome = OutcomeIncomplete
		v.Summary = "the actual response passes the CORS check, but this request also requires a preflight — capture the OPTIONS exchange to finish the diagnosis"
		v.Requirements = v.preflightRequirements(origin)
	case c.Response == nil:
		v.Outcome = OutcomeIncomplete
		v.Summary = "the preflight passes, but the actual response was not captured — its CORS check is still unverified"
		v.Requirements = v.responseRequirements(origin)
	default:
		v.Outcome = OutcomeAllowed
		v.Summary = "every CORS check passes; the browser would hand this response to the page"
		if c.Response != nil {
			v.ExposedHeaders = exposedHeaders(v.Request.Credentials, c.Response)
		}
	}

	v.warnings(c, origin)
}

// crossPhaseHints adds the fixes that need knowledge of both messages —
// most importantly the "your middleware only decorates OPTIONS" bug, where
// the preflight passes and the actual response has no CORS headers.
func (v *Verdict) crossPhaseHints(c Capture) {
	if v.Failed == nil || v.Failed.Phase != "response" || v.Failed.Code != CodeMissingAllowOrigin {
		return
	}
	if c.Preflight != nil && c.Preflight.Headers.Has("Access-Control-Allow-Origin") {
		v.Fixes = append(v.Fixes,
			"the preflight DID carry Access-Control-Allow-Origin — your CORS layer only decorates OPTIONS; apply it to the actual method's response too (a common bug with hand-written OPTIONS handlers)")
	}
}

// requirements spells out, for advisory mode, exactly what the server must
// send — the preflight contract first, then the actual response contract.
func (v *Verdict) requirements(origin Origin) []string {
	var reqs []string
	if v.Classification.PreflightRequired {
		reqs = append(reqs, v.preflightRequirements(origin)...)
	}
	reqs = append(reqs, v.responseRequirements(origin)...)
	return reqs
}

func (v *Verdict) preflightRequirements(origin Origin) []string {
	cls := v.Classification
	r := fmt.Sprintf("answer `OPTIONS` with a 2xx (no redirect) carrying `Access-Control-Allow-Origin: %s`", origin.Serialize())
	if v.Request.Credentials {
		r += " and `Access-Control-Allow-Credentials: true`"
	}
	reqs := []string{r}
	if !cls.MethodSafelisted {
		reqs = append(reqs, fmt.Sprintf("the preflight must list the method: `Access-Control-Allow-Methods: %s`", cls.Method))
	}
	if len(cls.UnsafeHeaderNames) > 0 {
		reqs = append(reqs, fmt.Sprintf("the preflight must cover the unsafe headers: `Access-Control-Allow-Headers: %s`", strings.Join(cls.UnsafeHeaderNames, ", ")))
	}
	return reqs
}

func (v *Verdict) responseRequirements(origin Origin) []string {
	r := fmt.Sprintf("the actual %s response itself needs `Access-Control-Allow-Origin: %s`", v.Classification.Method, origin.Serialize())
	if v.Request.Credentials {
		r += " and `Access-Control-Allow-Credentials: true`"
	}
	return []string{r}
}

// warnings collects the non-fatal hazards worth flagging regardless of the
// verdict.
func (v *Verdict) warnings(c Capture, origin Origin) {
	for _, m := range []struct {
		name string
		resp *Response
	}{{"preflight", c.Preflight}, {"actual response", c.Response}} {
		if m.resp == nil {
			continue
		}
		acao, ok := m.resp.Headers.Get("Access-Control-Allow-Origin")
		if !ok {
			continue
		}
		if acao != "*" && !varyIncludesOrigin(m.resp.Headers) {
			v.Warnings = append(v.Warnings, fmt.Sprintf(
				"the %s echoes a specific origin without `Vary: Origin` — a shared cache may serve this response, with your origin baked in, to a different origin", m.name))
		}
		if acao == "null" {
			v.Warnings = append(v.Warnings, fmt.Sprintf(
				"the %s allows the \"null\" origin; any sandboxed iframe or local file can produce Origin: null, so this is broader than it looks", m.name))
		}
	}
	if c.Preflight != nil {
		if age, ok := c.Preflight.Headers.Get("Access-Control-Max-Age"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(age)); err == nil && n > 0 {
				v.Notes = append(v.Notes, fmt.Sprintf(
					"the preflight result may be cached for %ds (Access-Control-Max-Age) — after a server fix, a stale cached preflight can keep failing until it expires", n))
			}
		}
	}
	if origin.Opaque {
		v.Notes = append(v.Notes, `the request origin is "null" (sandboxed iframe, file://, or data: page) — many servers refuse it on purpose; serve the page over http(s) to get a real origin`)
	}
}

// varyIncludesOrigin checks whether Vary names Origin (or is "*").
func varyIncludesOrigin(h Headers) bool {
	vary, ok := h.Get("Vary")
	if !ok {
		return false
	}
	for _, f := range splitList(vary) {
		if f == "*" || strings.EqualFold(f, "Origin") {
			return true
		}
	}
	return false
}

// safelistedResponseHeaders are always readable by page script on a
// CORS response, no Expose-Headers needed.
var safelistedResponseHeaders = []string{
	"cache-control", "content-language", "content-length", "content-type",
	"expires", "last-modified", "pragma",
}

// exposedHeaders reports which response header names page JavaScript can
// actually read: the CORS-safelisted response headers that are present,
// plus whatever Access-Control-Expose-Headers grants ("*" grants
// everything only without credentials).
func exposedHeaders(credentials bool, resp *Response) []string {
	set := map[string]bool{}
	for _, name := range safelistedResponseHeaders {
		if resp.Headers.Has(name) {
			set[name] = true
		}
	}
	if raw, ok := resp.Headers.Get("Access-Control-Expose-Headers"); ok {
		names := splitList(raw)
		if containsExact(names, "*") && !credentials {
			// A valid wildcard exposes every response header except the
			// forbidden Set-Cookie pair.
			for _, h := range resp.Headers {
				lower := strings.ToLower(h.Name)
				if lower != "set-cookie" && lower != "set-cookie2" {
					set[lower] = true
				}
			}
		} else {
			for _, n := range names {
				if n != "*" {
					set[strings.ToLower(n)] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
