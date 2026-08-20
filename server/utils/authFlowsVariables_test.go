package utils

import (
	"strings"
	"testing"
)

// Carrying a captured value from one step into the next.
//
// This exists because an auth flow could not log into anything with a per-request CSRF token, which
// is most applications. Measured live against ginandjuice.shop on 2026-08-19:
//
//	POST /login with no csrf      -> 400 "Missing parameter 'csrf'"
//	POST /login with a stale csrf -> 400 "Invalid CSRF token"
//
// so the token is bound to the session that issued it. The cookie jar already carried the session;
// nothing carried the token.

const loginTemplate = "POST /login HTTP/1.1\r\n" +
	"Host: ginandjuice.shop\r\n" +
	"Content-Type: application/x-www-form-urlencoded\r\n" +
	"Content-Length: 9\r\n" +
	"\r\n" +
	"csrf={{af:csrf}}&username=rs0n&password=rs0n"

func TestSubstitutionFillsTheTokenAndFixesTheFraming(t *testing.T) {
	out, used, reason := prepareStepRequest(loginTemplate, map[string]string{
		"csrf": "eGT0VoglYrl7SmTtgNGSDdMkYc4Oul1V",
	})
	if reason != "" {
		t.Fatalf("the step should have been sent: %s", reason)
	}
	if len(used) != 1 || used[0] != "csrf" {
		t.Errorf("the substitution should be reported so the wiring is visible, got %v", used)
	}
	if strings.Contains(out, "{{af:") {
		t.Fatalf("a placeholder survived into the request:\n%s", out)
	}

	_, _, body := splitRawRequestHeadBody(out)
	want := "csrf=eGT0VoglYrl7SmTtgNGSDdMkYc4Oul1V&username=rs0n&password=rs0n"
	if body != want {
		t.Errorf("body = %q, want %q", body, want)
	}

	// The stored Content-Length described the TEMPLATE. Left alone, sendRawRequest would send the
	// first 9 bytes of a 65 byte body and the target would answer with something that looks like an
	// application error rather than a truncated request.
	if !strings.Contains(out, "Content-Length: 65") {
		t.Errorf("Content-Length was not corrected to the substituted body of %d bytes:\n%s",
			len(want), out)
	}
}

// A value that is safe raw in a header is not safe raw in a form body. Dropping a token containing
// & or = straight into a urlencoded body silently splits it into extra parameters, and the request
// goes out malformed with no error anywhere.
func TestSubstitutionEncodesForWhereTheValueLands(t *testing.T) {
	out, _, reason := prepareStepRequest(loginTemplate, map[string]string{"csrf": "a&b=c d+e"})
	if reason != "" {
		t.Fatalf("unexpected refusal: %s", reason)
	}
	_, _, body := splitRawRequestHeadBody(out)
	if body != "csrf=a%26b%3Dc+d%2Be&username=rs0n&password=rs0n" {
		t.Errorf("form body was not escaped for its context: %q", body)
	}

	jsonStep := "POST /api/login HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/json\r\n\r\n" +
		`{"token":"{{af:csrf}}"}`
	out, _, _ = prepareStepRequest(jsonStep, map[string]string{"csrf": `he said "hi"\`})
	_, _, body = splitRawRequestHeadBody(out)
	if body != `{"token":"he said \"hi\"\\"}` {
		t.Errorf("JSON body was not escaped for its context: %q", body)
	}

	// A header takes the value as it is: percent-encoding an Authorization header would break it.
	headerStep := "GET /me HTTP/1.1\r\nHost: x.test\r\nX-CSRF: {{af:csrf}}\r\n\r\n"
	out, _, _ = prepareStepRequest(headerStep, map[string]string{"csrf": "a+b/c="})
	if !strings.Contains(out, "X-CSRF: a+b/c=") {
		t.Errorf("a header value should be substituted verbatim:\n%s", out)
	}

	// And the operator can always override.
	out, _, _ = prepareStepRequest(
		"POST /x HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nv={{af:t|raw}}",
		map[string]string{"t": "a&b"})
	_, _, body = splitRawRequestHeadBody(out)
	if body != "v=a&b" {
		t.Errorf("|raw should defeat the contextual encoding, got %q", body)
	}
}

// THE regression guard for the framing. normalizeRawRequest is the obvious function to reach for
// here and it is wrong: it replaces every \r\n in the WHOLE string, body included, then recomputes
// the length from the shortened bytes. An imported multipart step replays byte-exact today, and
// running it through that would rewrite every boundary CRLF to LF and quietly corrupt the upload.
func TestAStepWithNoPlaceholdersIsSentByteIdentical(t *testing.T) {
	multipart := "POST /upload HTTP/1.1\r\n" +
		"Host: x.test\r\n" +
		"Content-Type: multipart/form-data; boundary=----B\r\n" +
		"Content-Length: 96\r\n" +
		"\r\n" +
		"------B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\n" +
		"\x89PNG\r\n\x1a\n\r\n------B--\r\n"

	out, used, reason := prepareStepRequest(multipart, map[string]string{"csrf": "unused"})
	if reason != "" {
		t.Fatalf("unexpected refusal: %s", reason)
	}
	if len(used) != 0 {
		t.Errorf("nothing was substituted, so nothing should be reported as used: %v", used)
	}
	if out != multipart {
		t.Errorf("a step with no placeholders must not be rewritten at all.\n got: %q\nwant: %q",
			out, multipart)
	}
}

// A missing value must stop the step, not be papered over with an empty string. Sending a blank
// csrf produces a 400 the operator then debugs at the target instead of in the flow.
func TestAnUnresolvedPlaceholderRefusesTheStep(t *testing.T) {
	out, _, reason := prepareStepRequest(loginTemplate, map[string]string{})
	if reason == "" {
		t.Fatal("a step needing a value nobody captured must not be sent")
	}
	if out != "" {
		t.Error("no request should be produced when the step cannot be sent")
	}
	if !strings.Contains(reason, "{{af:csrf}}") {
		t.Errorf("the reason must name the placeholder that is missing, got %q", reason)
	}
}

// The SSTI payloads this framework fires at targets must never be mistaken for a placeholder.
func TestThePlaceholderGrammarCannotCollideWithRealBytes(t *testing.T) {
	notPlaceholders := []string{
		"{{7*7}}",
		"{{config.items()}}",
		"${jndi:ldap://x}",
		`{"a":"{{b}}"}`,
		"{{af:}}",
		"{{af:has-a-dash}}",
		"{{ af:csrf }}",
	}
	for _, sample := range notPlaceholders {
		if names := authFlowVarNames(sample); len(names) != 0 {
			t.Errorf("%q was read as a placeholder %v", sample, names)
		}
	}
	if names := authFlowVarNames("a {{af:csrf}} b {{af:token|url}} c {{af:csrf}}"); len(names) != 2 {
		t.Errorf("expected csrf and token once each, got %v", names)
	}
}

func TestExtractionReadsBodyHeaderAndCookie(t *testing.T) {
	headers := map[string][]string{
		"Set-Cookie": {
			"session=abc123; Secure; HttpOnly",
			"XSRF-TOKEN=tok-42; Path=/",
		},
		"X-Request-Id": {"req-7"},
	}
	body := `<input required type="hidden" name="csrf" value="eGT0Vogl">`

	values, outcomes := runAuthFlowExtractions([]AuthFlowExtraction{
		{Name: "csrf", Source: "body", Pattern: `name="csrf" value="([^"]+)"`},
		{Name: "xsrf", Source: "cookie", Key: "XSRF-TOKEN"},
		{Name: "rid", Source: "header", Key: "x-request-id"},
	}, headers, body)

	if values["csrf"] != "eGT0Vogl" {
		t.Errorf("body capture = %q", values["csrf"])
	}
	// The double-submit case: the token arrives as a cookie and has to be echoed back as a value,
	// so it has to be readable rather than only riding in the jar.
	if values["xsrf"] != "tok-42" {
		t.Errorf("cookie capture = %q", values["xsrf"])
	}
	if values["rid"] != "req-7" {
		t.Errorf("header capture = %q (matching is case insensitive)", values["rid"])
	}
	for _, outcome := range outcomes {
		if !outcome.Matched {
			t.Errorf("%s did not match: %s", outcome.Name, outcome.Problem)
		}
	}
}

// A rule that finds nothing has to say so. Reporting it as an empty value would send a blank token
// and turn a flow problem into a target problem.
func TestAFailedExtractionIsReportedRatherThanReturnedEmpty(t *testing.T) {
	values, outcomes := runAuthFlowExtractions([]AuthFlowExtraction{
		{Name: "csrf", Source: "body", Pattern: `name="csrf" value="([^"]+)"`},
	}, map[string][]string{}, "<html>no token here</html>")

	if _, present := values["csrf"]; present {
		t.Error("a rule that matched nothing must not contribute a value")
	}
	if len(outcomes) != 1 || outcomes[0].Matched {
		t.Fatalf("expected one unmatched outcome, got %+v", outcomes)
	}
	if outcomes[0].Problem == "" {
		t.Error("the outcome has to carry the reason")
	}
}

// Go's html.UnescapeString decodes the LEGACY entity set WITHOUT requiring a trailing semicolon, so
// "abc&param=1" becomes "abc<paragraph sign>m=1". Captured values are very often URL shaped (an
// OAuth authorize or redirect URL, a SAML RelayState), which is exactly where bare &param= lives.
// Decoding by default would corrupt them silently, so the default is none.
func TestDecodingIsOptInBecauseTheDefaultWouldCorruptURLs(t *testing.T) {
	redirect := "https://idp.test/authorize?client_id=x&param=1&not_after=2&lt=3"

	values, _ := runAuthFlowExtractions([]AuthFlowExtraction{
		{Name: "next", Source: "header", Key: "Location"},
	}, map[string][]string{"Location": {redirect}}, "")
	if values["next"] != redirect {
		t.Errorf("a captured URL must survive byte-identical by default.\n got: %q\nwant: %q",
			values["next"], redirect)
	}

	// Opt in, and it decodes.
	values, _ = runAuthFlowExtractions([]AuthFlowExtraction{
		{Name: "t", Source: "body", Pattern: `value="([^"]+)"`, Decode: "html"},
	}, map[string][]string{}, `<input value="a&amp;b&lt;c">`)
	if values["t"] != "a&b<c" {
		t.Errorf("html decoding was asked for and should apply, got %q", values["t"])
	}
}

func TestExtractionRulesAreRejectedAtSaveTime(t *testing.T) {
	bad := map[string]AuthFlowExtraction{
		"no name":                  {Source: "body", Pattern: "(x)"},
		"unusable name":            {Name: "csrf token", Source: "body", Pattern: "(x)"},
		"no source":                {Name: "csrf", Pattern: "(x)"},
		"unknown source":           {Name: "csrf", Source: "elsewhere", Pattern: "(x)"},
		"header with no key":       {Name: "csrf", Source: "header"},
		"body with no rule":        {Name: "csrf", Source: "body"},
		"pattern will not compile": {Name: "csrf", Source: "body", Pattern: "([a-z"},
		// The one an operator gets wrong most: a pattern that matches but captures nothing.
		"pattern with no capture group": {Name: "csrf", Source: "body", Pattern: `value="[^"]+"`},
		"unknown decoding":              {Name: "csrf", Source: "body", Pattern: "(x)", Decode: "rot13"},
	}
	for label, rule := range bad {
		if problem := validateAuthFlowExtraction(rule); problem == "" {
			t.Errorf("%s should have been refused at save time", label)
		}
	}

	good := AuthFlowExtraction{Name: "csrf", Source: "body", Pattern: `name="csrf" value="([^"]+)"`}
	if problem := validateAuthFlowExtraction(good); problem != "" {
		t.Errorf("a workable rule was refused: %s", problem)
	}
}

// A rule omitted from JSON must default to REQUIRED, because the zero value is what an operator
// gets when they do not think about it, and the safe answer is to refuse rather than to send a
// placeholder at the target.
func TestAnOmittedOptionalFlagMeansRequired(t *testing.T) {
	var rule AuthFlowExtraction
	if rule.Optional {
		t.Error("the zero value must be the required one")
	}
}
