package cors

import "strings"

// splitList is a pragmatic version of Fetch's "extracting header list
// values" for the comma-separated token lists CORS uses
// (Access-Control-Allow-Methods, -Headers, -Expose-Headers): split on
// commas, trim optional whitespace, drop empty members.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, " \t")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// containsExact reports byte-exact membership (method comparisons).
func containsExact(list []string, item string) bool {
	for _, m := range list {
		if m == item {
			return true
		}
	}
	return false
}

// containsFold reports byte-case-insensitive membership (header-name
// comparisons).
func containsFold(list []string, item string) bool {
	for _, m := range list {
		if strings.EqualFold(m, item) {
			return true
		}
	}
	return false
}

// isHTTPToken reports whether s is a non-empty HTTP token (RFC 9110
// tchar set) — used to validate MIME type/subtype.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= '0' && b <= '9', b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0:
		default:
			return false
		}
	}
	return true
}
