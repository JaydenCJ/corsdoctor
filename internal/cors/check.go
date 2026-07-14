package cors

import (
	"fmt"
	"strings"
)

// StepStatus is the result of one named check.
type StepStatus string

const (
	StatusPass StepStatus = "pass"
	StatusFail StepStatus = "fail"
	StatusSkip StepStatus = "skip"
)

// Failure codes, used to select the browser-console message and to give
// machine consumers something stabler than prose.
const (
	CodeMissingAllowOrigin  = "missing-allow-origin"
	CodeOriginMismatch      = "origin-mismatch"
	CodeMultipleValues      = "multiple-allow-origin-values"
	CodeWildcardCredentials = "wildcard-with-credentials"
	CodeCredentialsFlag     = "credentials-flag"
	CodePreflightStatus     = "preflight-status"
	CodePreflightRedirect   = "preflight-redirect"
	CodeMethodNotAllowed    = "method-not-allowed"
	CodeHeaderNotAllowed    = "header-not-allowed"
)

// Step is one check of the CORS algorithm, in the order the browser runs
// them. The first failing step with Blocking set is the verdict.
type Step struct {
	ID       string     `json:"id"`    // e.g. "preflight.allow-headers"
	Phase    string     `json:"phase"` // "preflight" or "response"
	Title    string     `json:"title"`
	Status   StepStatus `json:"status"`
	Code     string     `json:"code,omitempty"` // stable failure code
	Detail   string     `json:"detail,omitempty"`
	Ref      string     `json:"ref,omitempty"` // where in the Fetch standard
	Fix      string     `json:"fix,omitempty"`
	Blocking bool       `json:"blocking"`
	// Subject carries the failing item (a header name, a method) for
	// browser-message construction.
	Subject string `json:"-"`
}

// Spec references cited on each step. Section numbers drift between
// snapshots of the living standard, so steps are cited by algorithm name.
const (
	refCORSCheckPresent = `Fetch "CORS check" step 2: an absent Access-Control-Allow-Origin is an immediate failure`
	refCORSCheckMatch   = `Fetch "CORS check" steps 3-4: "*" short-circuits only without credentials; otherwise the value must byte-match the serialized origin`
	refCORSCheckCreds   = `Fetch "CORS check" steps 5-6: with credentials, Access-Control-Allow-Credentials must be exactly "true"`
	refPreflightStatus  = `Fetch "CORS-preflight fetch" step 7: the preflight response must pass the CORS check and have an ok status (2xx)`
	refPreflightMethods = `Fetch "CORS-preflight fetch" methods check: the method must be listed byte-exactly, be CORS-safelisted, or be wildcard-matched (no credentials)`
	refPreflightHeaders = `Fetch "CORS-preflight fetch" headers check: every CORS-unsafe request-header name must be covered; "*" never covers Authorization and is literal with credentials`
)

// corsCheck runs Fetch's "CORS check" against resp for the given serialized
// origin and credentials mode, returning the three steps in spec order.
// phase is "preflight" or "response"; it prefixes the step IDs because the
// same algorithm runs against both messages.
func corsCheck(phase string, origin Origin, credentials bool, resp *Response) []Step {
	serialized := origin.Serialize()
	value, present := resp.Headers.Get("Access-Control-Allow-Origin")
	fieldCount := resp.Headers.Count("Access-Control-Allow-Origin")

	presentStep := Step{
		ID: phase + ".allow-origin", Phase: phase,
		Title: "Access-Control-Allow-Origin is present",
		Ref:   refCORSCheckPresent,
	}
	matchStep := Step{
		ID: phase + ".origin-match", Phase: phase,
		Title: "Access-Control-Allow-Origin matches the request origin",
		Ref:   refCORSCheckMatch,
	}
	credsStep := Step{
		ID: phase + ".allow-credentials", Phase: phase,
		Title: "Access-Control-Allow-Credentials permits credentials",
		Ref:   refCORSCheckCreds,
	}

	if !present {
		presentStep.Status = StatusFail
		presentStep.Code = CodeMissingAllowOrigin
		presentStep.Detail = "the response has no Access-Control-Allow-Origin header at all"
		presentStep.Fix = missingAllowOriginFix(origin, credentials)
		matchStep.Status, matchStep.Detail = StatusSkip, "not reached: the header is absent"
		credsStep.Status, credsStep.Detail = StatusSkip, "not reached: the header is absent"
		return []Step{presentStep, matchStep, credsStep}
	}
	presentStep.Status = StatusPass
	presentStep.Detail = fmt.Sprintf("Access-Control-Allow-Origin: %s", value)

	switch {
	case !credentials && value == "*":
		matchStep.Status = StatusPass
		matchStep.Detail = `"*" matches any origin because the request is sent without credentials`
	case value == serialized:
		matchStep.Status = StatusPass
		matchStep.Detail = fmt.Sprintf("byte-for-byte match with %q", serialized)
	case value == "*" && credentials:
		matchStep.Status = StatusFail
		matchStep.Code = CodeWildcardCredentials
		matchStep.Detail = `the wildcard "*" is compared literally when the request carries credentials — and "*" is not the origin`
		matchStep.Fix = fmt.Sprintf("echo the exact origin instead of the wildcard: `Access-Control-Allow-Origin: %s` plus `Vary: Origin`", serialized)
	default:
		matchStep.Status = StatusFail
		matchStep.Code = CodeOriginMismatch
		if fieldCount > 1 || strings.Contains(value, ",") {
			matchStep.Code = CodeMultipleValues
		}
		matchStep.Detail = diagnoseOriginMismatch(value, origin)
		matchStep.Subject = value
		matchStep.Fix = fmt.Sprintf("send exactly one header: `Access-Control-Allow-Origin: %s` (echo the request's Origin, add `Vary: Origin`)", serialized)
	}

	if !credentials {
		credsStep.Status = StatusSkip
		credsStep.Detail = "the request is sent without credentials; this check does not run"
	} else if matchStep.Status == StatusFail {
		credsStep.Status, credsStep.Detail = StatusSkip, "not reached: the origin comparison already failed"
	} else if creds, ok := resp.Headers.Get("Access-Control-Allow-Credentials"); !ok {
		credsStep.Status = StatusFail
		credsStep.Code = CodeCredentialsFlag
		credsStep.Detail = "the request carries credentials but the response has no Access-Control-Allow-Credentials header"
		credsStep.Subject = ""
		credsStep.Fix = "add `Access-Control-Allow-Credentials: true` (and keep Access-Control-Allow-Origin an exact origin, never \"*\")"
	} else if creds != "true" {
		credsStep.Status = StatusFail
		credsStep.Code = CodeCredentialsFlag
		credsStep.Subject = creds
		credsStep.Detail = fmt.Sprintf("the value is %q; the comparison is byte-case-sensitive and only the exact string \"true\" passes", creds)
		credsStep.Fix = "send exactly `Access-Control-Allow-Credentials: true` — lowercase, no quotes, not \"1\""
	} else {
		credsStep.Status = StatusPass
		credsStep.Detail = "Access-Control-Allow-Credentials: true"
	}

	return []Step{presentStep, matchStep, credsStep}
}

// missingAllowOriginFix suggests the right ACAO value: the wildcard is fine
// for public, credential-less resources; otherwise echo the origin.
func missingAllowOriginFix(origin Origin, credentials bool) string {
	if credentials {
		return fmt.Sprintf("send `Access-Control-Allow-Origin: %s` and `Access-Control-Allow-Credentials: true` on this response", origin.Serialize())
	}
	return fmt.Sprintf("send `Access-Control-Allow-Origin: %s` (or `*` if the resource is public) on this response", origin.Serialize())
}
