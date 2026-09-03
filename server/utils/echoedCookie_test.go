package utils

import (
	"strings"
	"testing"
)

// THE SECOND CARRIER. Measured on ginandjuice.shop: every GET /catalog?category=<value> returned
// Set-Cookie: category=<the same value>, identical across five different values. That parameter is
// also the one with confirmed SQL injection, so the same injectable input arrived by a route that had
// zero vectors and therefore reported clean in every section, every time.
func TestAResponseCookieBuiltFromAParameterBecomesItsOwnVector(t *testing.T) {
	names, signals := echoedCookieInputs(
		`{"set-cookie":"category=Juice; Secure; HttpOnly","content-type":"text/html"}`,
		`{"category":"Juice"}`, `{}`)

	if len(names) != 1 || names[0] != "category" {
		t.Fatalf("the echoed cookie must become a testable input, got %v", names)
	}
	if !containsString(signals, "server_set") {
		t.Errorf("an echoed cookie needs its own signal so an operator can tell it apart from the "+
			"cookies the browser was merely carrying, got %v", signals)
	}
}

// The counterpart, and the one that decides whether this is useful or noise. An ordinary session
// cookie is set by the server on every response and has nothing to do with caller input. Emitting a
// vector for it would add a row to every capture on every target and bury the real signal.
func TestAnOrdinaryServerCookieIsNotAnEchoedOne(t *testing.T) {
	for name, headers := range map[string]string{
		"a fresh session":  `{"set-cookie":"session=NUNKXjd3u9kabUmeewAa6kqKMAk4OqyU; Secure; HttpOnly"}`,
		"a routing cookie": `{"set-cookie":"AWSALB=XHx+dZCy/nBRqGQhd7vYVvi0r+ln; Path=/"}`,
		"no cookies":       `{"content-type":"text/html"}`,
		"malformed":        `not json at all`,
	} {
		if got, _ := echoedCookieInputs(headers, `{"category":"Juice"}`, `{}`); len(got) != 0 {
			t.Errorf("%s: must not produce a vector, the value did not come from the caller; got %v",
				name, got)
		}
	}
	// And with no caller input at all there is nothing to echo.
	if got, _ := echoedCookieInputs(`{"set-cookie":"category=Juice"}`, `{}`, `{}`); len(got) != 0 {
		t.Errorf("with no request parameters nothing can be an echo of one, got %v", got)
	}
}

// Set-Cookie arrives as a bare string or as an array depending on how the capture was stored, and
// attributes after the first semicolon are not part of the value.
func TestSetCookieParsingHandlesBothShapesAndIgnoresAttributes(t *testing.T) {
	one := setCookieValues(`{"set-cookie":"a=1; Path=/; Secure"}`)
	if one["a"] != "1" {
		t.Errorf("attributes must not be folded into the value, got %q", one["a"])
	}
	many := setCookieValues(`{"Set-Cookie":["a=1; Path=/","b=2; HttpOnly"]}`)
	if many["a"] != "1" || many["b"] != "2" {
		t.Errorf("an array of Set-Cookie headers must all be read, got %v", many)
	}
	if len(setCookieValues(`{"set-cookie":"novalue"}`)) != 0 {
		t.Error("a header with no = is not a cookie pair")
	}
}

// A body parameter echoed into a cookie is the same defect arriving from the other direction.
func TestABodyParameterEchoedIntoACookieCountsToo(t *testing.T) {
	names, _ := echoedCookieInputs(`{"set-cookie":"pref=dark"}`, `{}`, `{"pref":"dark"}`)
	if len(names) != 1 || names[0] != "pref" {
		t.Errorf("a POST parameter echoed into a response cookie is also a second carrier, got %v", names)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
