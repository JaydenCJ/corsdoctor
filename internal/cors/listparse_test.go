// Tests for the comma-list parsing shared by every Access-Control-* list
// header.
package cors

import (
	"reflect"
	"testing"
)

func TestSplitList_TrimsOWSAndDropsEmptyMembers(t *testing.T) {
	got := splitList(" GET, PUT\t,  , DELETE,")
	want := []string{"GET", "PUT", "DELETE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
}

func TestContainsExactVersusFold(t *testing.T) {
	list := []string{"PATCH", "x-api-key"}
	// Methods compare byte-exactly…
	if containsExact(list, "patch") {
		t.Fatal("exact match must be case-sensitive")
	}
	// …header names compare case-insensitively.
	if !containsFold(list, "X-Api-Key") {
		t.Fatal("fold match must be case-insensitive")
	}
}

func TestIsHTTPToken(t *testing.T) {
	for _, ok := range []string{"application", "x-www-form-urlencoded", "vnd.api+json"} {
		if !isHTTPToken(ok) {
			t.Fatalf("%q is a valid token", ok)
		}
	}
	for _, bad := range []string{"", "te xt", "a/b", "a@b"} {
		if isHTTPToken(bad) {
			t.Fatalf("%q is not a valid token", bad)
		}
	}
}
