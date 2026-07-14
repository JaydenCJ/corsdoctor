package cors

import "fmt"

// browserMessage reconstructs, for the failing step, the console error a
// Chromium-based browser would print. Developers google these strings; a
// diagnosis that reproduces the exact message proves the tool found the
// same failure the browser did.
func browserMessage(failed *Step, requestURL, origin string) string {
	prefix := fmt.Sprintf("Access to fetch at '%s' from origin '%s' has been blocked by CORS policy: ", requestURL, origin)
	preflight := failed.Phase == "preflight"
	pf := func(s string) string {
		if preflight {
			return "Response to preflight request doesn't pass access control check: " + s
		}
		return s
	}
	switch failed.Code {
	case CodeMissingAllowOrigin:
		return prefix + pf("No 'Access-Control-Allow-Origin' header is present on the requested resource.")
	case CodeMultipleValues:
		return prefix + pf(fmt.Sprintf("The 'Access-Control-Allow-Origin' header contains multiple values '%s', but only one is allowed.", failed.Subject))
	case CodeWildcardCredentials:
		return prefix + pf("The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.")
	case CodeOriginMismatch:
		return prefix + pf(fmt.Sprintf("The 'Access-Control-Allow-Origin' header has a value '%s' that is not equal to the supplied origin.", failed.Subject))
	case CodeCredentialsFlag:
		return prefix + pf(fmt.Sprintf("The value of the 'Access-Control-Allow-Credentials' header in the response is '%s' which must be 'true' when the request's credentials mode is 'include'.", failed.Subject))
	case CodePreflightRedirect:
		return prefix + "Response to preflight request doesn't pass access control check: Redirect is not allowed for a preflight request."
	case CodePreflightStatus:
		return prefix + "Response to preflight request doesn't pass access control check: It does not have HTTP ok status."
	case CodeMethodNotAllowed:
		return prefix + fmt.Sprintf("Method %s is not allowed by Access-Control-Allow-Methods in preflight response.", failed.Subject)
	case CodeHeaderNotAllowed:
		return prefix + fmt.Sprintf("Request header field %s is not allowed by Access-Control-Allow-Headers in preflight response.", failed.Subject)
	default:
		return prefix + "Request blocked."
	}
}
