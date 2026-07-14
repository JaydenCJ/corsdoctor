package cors

import (
	"fmt"
	"sort"
	"strings"
)

// nonWildcardHeaderName is the one request-header name the "*" wildcard in
// Access-Control-Allow-Headers never covers.
const nonWildcardHeaderName = "authorization"

// evaluatePreflight runs the response side of Fetch's "CORS-preflight
// fetch" (step 7) against a captured OPTIONS response: the CORS check,
// the ok-status requirement, then the methods and headers coverage checks.
// Steps come back in the order the browser evaluates them.
func evaluatePreflight(origin Origin, credentials bool, method string, unsafeNames []string, resp *Response) []Step {
	steps := corsCheck("preflight", origin, credentials, resp)
	corsFailed := false
	for _, s := range steps {
		if s.Status == StatusFail {
			corsFailed = true
		}
	}

	steps = append(steps, preflightStatusStep(resp))
	statusFailed := steps[len(steps)-1].Status == StatusFail

	blockedEarlier := corsFailed || statusFailed
	steps = append(steps, preflightMethodStep(credentials, method, resp, blockedEarlier))
	if steps[len(steps)-1].Status == StatusFail {
		blockedEarlier = true
	}
	steps = append(steps, preflightHeadersStep(credentials, unsafeNames, resp, blockedEarlier))
	return steps
}

// preflightStatusStep checks the ok-status requirement, with a dedicated
// redirect diagnosis because browsers report that case with its own error.
// It runs regardless of whether the CORS check already failed.
func preflightStatusStep(resp *Response) Step {
	step := Step{
		ID: "preflight.status", Phase: "preflight",
		Title: "preflight response status is ok (2xx)",
		Ref:   refPreflightStatus,
	}
	s := resp.Status
	switch {
	case s >= 200 && s <= 299:
		step.Status = StatusPass
		step.Detail = fmt.Sprintf("status %d", s)
	case s >= 300 && s <= 399:
		step.Status = StatusFail
		step.Code = CodePreflightRedirect
		step.Detail = fmt.Sprintf("status %d — a preflight must not be redirected, even to the same resource over https", s)
		step.Fix = "answer OPTIONS directly with 204 from the original URL; move http→https and trailing-slash redirects after the CORS layer"
	default:
		step.Status = StatusFail
		step.Code = CodePreflightStatus
		step.Detail = fmt.Sprintf("status %d is not an ok status", s)
		step.Fix = preflightStatusFix(s)
	}
	return step
}

// preflightStatusFix maps the observed status class to the usual culprit.
// These are the boring, real-world reasons preflights fail.
func preflightStatusFix(status int) string {
	switch {
	case status == 401 || status == 403:
		return "browsers send preflights WITHOUT credentials or custom headers — an auth middleware is rejecting OPTIONS; exempt OPTIONS from authentication"
	case status == 404 || status == 405:
		return "the route has no OPTIONS handler; register one (or enable your framework's CORS middleware, which answers OPTIONS for you)"
	case status >= 500:
		return "the OPTIONS handler itself is erroring; check the server log for this request"
	default:
		return "make the OPTIONS handler return 204 with the CORS response headers"
	}
}

// preflightMethodStep implements the methods coverage check: the request
// method must be listed byte-exactly, be CORS-safelisted, or — when the
// request carries no credentials — be covered by a literal "*".
func preflightMethodStep(credentials bool, method string, resp *Response, blockedEarlier bool) Step {
	step := Step{
		ID: "preflight.allow-methods", Phase: "preflight",
		Title: "Access-Control-Allow-Methods covers the method",
		Ref:   refPreflightMethods,
	}
	raw, present := resp.Headers.Get("Access-Control-Allow-Methods")
	var methods []string
	if present {
		methods = splitList(raw)
	}
	switch {
	case containsExact(methods, method):
		step.Status = StatusPass
		step.Detail = fmt.Sprintf("%s is listed (Access-Control-Allow-Methods: %s)", method, raw)
	case IsSafelistedMethod(method):
		step.Status = StatusPass
		step.Detail = fmt.Sprintf("%s is CORS-safelisted, so it is allowed even when not listed", method)
	case !credentials && containsExact(methods, "*"):
		step.Status = StatusPass
		step.Detail = `"*" covers any method because the request is sent without credentials`
	default:
		step.Status = StatusFail
		step.Code = CodeMethodNotAllowed
		step.Subject = method
		step.Detail = methodFailureDetail(credentials, method, methods, present, raw)
		step.Fix = fmt.Sprintf("add %s to Access-Control-Allow-Methods in the preflight response", method)
	}
	if step.Status == StatusFail && blockedEarlier {
		// Still evaluated (the doctor reports every problem), but the
		// browser never got this far; the earlier step is the verdict.
		step.Detail += " (evaluated for completeness; the preflight already failed earlier)"
	}
	return step
}

// methodFailureDetail distinguishes the three ways the methods check fails:
// header absent, wildcard neutered by credentials, or a byte-case miss —
// the classic `PATCH` vs `patch` trap, since PATCH is not one of the six
// methods browsers normalize to uppercase.
func methodFailureDetail(credentials bool, method string, methods []string, present bool, raw string) string {
	if !present {
		return fmt.Sprintf("the preflight response has no Access-Control-Allow-Methods header, and %s is not CORS-safelisted", method)
	}
	if containsExact(methods, "*") && credentials {
		return fmt.Sprintf(`"*" is compared literally because the request carries credentials; %s must be listed by name`, method)
	}
	if containsFold(methods, method) {
		return fmt.Sprintf("the list (%s) contains %s in different byte case; methods compare byte-for-byte, and browsers only uppercase DELETE/GET/HEAD/OPTIONS/POST/PUT — never %s", raw, method, method)
	}
	return fmt.Sprintf("%s is not in Access-Control-Allow-Methods: %s", method, raw)
}

// preflightHeadersStep implements the headers coverage check: every
// CORS-unsafe request-header name must appear (byte-case-insensitively) in
// Access-Control-Allow-Headers. The "*" wildcard only helps requests
// without credentials, and never covers Authorization.
func preflightHeadersStep(credentials bool, unsafeNames []string, resp *Response, blockedEarlier bool) Step {
	step := Step{
		ID: "preflight.allow-headers", Phase: "preflight",
		Title: "Access-Control-Allow-Headers covers every unsafe header",
		Ref:   refPreflightHeaders,
	}
	raw, present := resp.Headers.Get("Access-Control-Allow-Headers")
	var allowed []string
	if present {
		allowed = splitList(raw)
	}
	wildcard := containsExact(allowed, "*") && !credentials

	var missing []string
	var wildcardBlocked []string
	for _, name := range unsafeNames {
		if containsFold(allowed, name) {
			continue
		}
		if name == nonWildcardHeaderName {
			// Authorization is a "CORS non-wildcard request-header name":
			// even a valid "*" does not cover it.
			missing = append(missing, name)
			continue
		}
		if wildcard {
			continue
		}
		if containsExact(allowed, "*") && credentials {
			wildcardBlocked = append(wildcardBlocked, name)
			continue
		}
		missing = append(missing, name)
	}
	missing = append(missing, wildcardBlocked...)
	sort.Strings(missing)

	switch {
	case len(unsafeNames) == 0:
		step.Status = StatusPass
		step.Detail = "the request has no CORS-unsafe headers to authorize (the preflight was triggered by the method alone)"
	case len(missing) == 0:
		step.Status = StatusPass
		if wildcard {
			step.Detail = `"*" covers the unsafe headers because the request is sent without credentials`
		} else {
			step.Detail = fmt.Sprintf("all of [%s] are covered by Access-Control-Allow-Headers: %s", strings.Join(unsafeNames, ", "), raw)
		}
	default:
		step.Status = StatusFail
		step.Code = CodeHeaderNotAllowed
		step.Subject = missing[0]
		step.Detail = headersFailureDetail(credentials, missing, allowed, present, raw)
		step.Fix = fmt.Sprintf("add %s to Access-Control-Allow-Headers in the preflight response", strings.Join(missing, ", "))
	}
	if step.Status == StatusFail && blockedEarlier {
		step.Detail += " (evaluated for completeness; the preflight already failed earlier)"
	}
	return step
}

func headersFailureDetail(credentials bool, missing, allowed []string, present bool, raw string) string {
	if !present {
		return fmt.Sprintf("the preflight response has no Access-Control-Allow-Headers header; uncovered: %s", strings.Join(missing, ", "))
	}
	var notes []string
	if containsExact(allowed, "*") && credentials {
		notes = append(notes, `"*" is compared literally because the request carries credentials`)
	}
	if containsFold(missing, nonWildcardHeaderName) && containsExact(allowed, "*") {
		notes = append(notes, `"*" never covers authorization — it must be listed by name`)
	}
	detail := fmt.Sprintf("not covered by Access-Control-Allow-Headers (%s): %s", raw, strings.Join(missing, ", "))
	if len(notes) > 0 {
		detail += " — " + strings.Join(notes, "; ")
	}
	return detail
}
