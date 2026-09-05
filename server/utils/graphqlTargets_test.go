package utils

import (
	"strings"
	"testing"
)

// The list arrives in TWO shapes and both have to produce the same URLs: the config modal posts one
// string with a URL per line, while the API and MCP post a JSON array. An array used to be flattened
// by stringifySetting with "; " and then split on whitespace only, so every URL but the last kept a
// trailing semicolon and was SCANNED AT THAT URL. Two of three bypass targets on ginandjuice.shop
// were scanned as /admin; and /admin/login;, and both reported clean for a path nobody chose.
func TestEndpointListSurvivesEveryShapeItArrivesIn(t *testing.T) {
	want := []string{
		"https://ginandjuice.shop/admin",
		"https://ginandjuice.shop/admin/login",
		"https://ginandjuice.shop/admin/users",
	}
	shapes := map[string]string{
		"newline separated (the config modal)": "https://ginandjuice.shop/admin\nhttps://ginandjuice.shop/admin/login\nhttps://ginandjuice.shop/admin/users",
		"semicolon joined (a flattened array)": "https://ginandjuice.shop/admin; https://ginandjuice.shop/admin/login; https://ginandjuice.shop/admin/users",
		"comma separated":                      "https://ginandjuice.shop/admin,https://ginandjuice.shop/admin/login,https://ginandjuice.shop/admin/users",
	}
	for name, raw := range shapes {
		got := splitEndpointList(raw)
		if len(got) != len(want) {
			t.Errorf("%s: got %d urls, want %d: %v", name, len(got), len(want), got)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: url %d is %q, want %q", name, i, got[i], want[i])
			}
		}
	}

	// The specific corruption, called out on its own so a regression names itself.
	for _, url := range splitEndpointList("https://a/admin; https://a/b") {
		if strings.HasSuffix(url, ";") {
			t.Errorf("a separator survived onto the end of a URL: %q", url)
		}
	}
}
