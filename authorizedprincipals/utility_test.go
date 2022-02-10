package authorizedprincipals

import "testing"

func TestIntersectionAmongStringLists(t *testing.T) {
	if intersectionAmongStringLists([]string{"a", "abc", "def"}, []string{"ab", "bc", "de", "ef"}) {
		t.Errorf("intersectionAmongStringLists failing to give expected results")
	}
	if !intersectionAmongStringLists([]string{"abc", "def"}, []string{"ab", "bc", "def", "ef"}) {
		t.Errorf("intersectionAmongStringLists failing to give expected results")
	}
	if intersectionAmongStringLists(nil, nil) {
		t.Errorf("intersectionAmongStringLists failing to give expected results for 2 nil string lists")
	}
	if !intersectionAmongStringLists([]string{"abc", "def"}, []string{"abc", "def"}) {
		t.Errorf("intersectionAmongStringLists failing to give expected results")
	}
}
