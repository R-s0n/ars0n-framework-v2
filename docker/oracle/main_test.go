package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE SEMICOLON. Go 1.17 made net/url reject a semicolon as a parameter separator: parseQuery sees a
// ';' in a key=value pair, records an error and skips that pair. r.URL.Query() discards the error, so
// the parameter comes back as "" and every handler behaves as though nothing was sent.
//
// A semicolon is the first separator every command injection scanner reaches for. The one endpoint
// whose entire purpose is to look injectable answered "not injectable" to the most common payload
// shape there is, which is the fail-open this oracle exists to detect, occurring inside the
// instrument meant to detect it.
func TestARawSemicolonInTheQueryIsNotDropped(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/cmdi?cmd=127.0.0.1;echo+hi", nil)

	if viaStdlib := request.URL.Query().Get("cmd"); viaStdlib != "" {
		t.Fatalf("premise of this test no longer holds: net/url returned %q for a value containing a "+
			"semicolon, so the workaround it guards may be unnecessary", viaStdlib)
	}
	if got := queryParam(request, "cmd"); got != "127.0.0.1;echo hi" {
		t.Errorf("queryParam dropped a semicolon-bearing value: got %q. Every payload a command "+
			"injection scanner sends starts with one, so the control target answers clean to all of "+
			"them and its scanners are recorded as having proved something", got)
	}
}

// A malformed percent escape must not blank the parameter either. A vulnerable application
// concatenates whatever bytes arrived; answering as though nothing was sent is the same fail-open.
func TestAMalformedEscapeStillReachesTheHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/xss?q=100%+of+it", nil)
	if got := queryParam(request, "q"); !strings.Contains(got, "of it") {
		t.Errorf("a value with a stray %% came back as %q, so a scanner sending one would be answered "+
			"as though it sent nothing", got)
	}
}

// COMMIX'S CLASSIC TECHNIQUE, verbatim. From cb_payloads.py the decision payload is
//
//	;echo TAG$((a+b))$(echo TAG)TAG
//
// and injector.injection_test_results looks for TAG + str(a+b) + TAG + TAG in the body. An emulation
// that echoes its argument unchanged returns the payload text, the sum is never computed, and commix
// files a target it can trivially inject as clean.
func TestTheEmulatedShellComputesWhatCommixChecksFor(t *testing.T) {
	recorder := httptest.NewRecorder()
	cmdiHandler(recorder, httptest.NewRequest(http.MethodGet,
		"/cmdi?cmd=1%3Becho%20SUTLLX%24%28%2882%2B28%29%29%24%28echo%20SUTLLX%29SUTLLX", nil))

	body := recorder.Body.String()
	if !strings.Contains(body, "SUTLLX110SUTLLXSUTLLX") {
		t.Errorf("the emulated shell did not produce commix's expected result. Its detection regex is "+
			"TAG+sum+TAG+TAG and it will report this endpoint clean without it. Body was:\n%s", body)
	}
}

// The backtick spelling of the same arithmetic, which commix uses under --use-backticks and whenever
// it believes a WAF is present.
func TestTheEmulatedShellUnderstandsTheBacktickSpelling(t *testing.T) {
	recorder := httptest.NewRecorder()
	cmdiHandler(recorder, httptest.NewRequest(http.MethodGet,
		"/cmdi?cmd=1%3Becho%20T%60expr%2082%20%2B%2028%60T", nil))

	if body := recorder.Body.String(); !strings.Contains(body, "T110T") {
		t.Errorf("`expr 82 + 28` was not evaluated, so commix's WAF-mode payloads find nothing:\n%s", body)
	}
}

// Nothing may be executed. The emulation is a lookup table with arithmetic in it, and a command it
// does not recognise has to produce the empty output a failed command would rather than passing the
// text anywhere.
func TestAnUnknownCommandSubstitutionProducesNothing(t *testing.T) {
	if got := runEmulatedCommand("cat /etc/shadow"); got != "" {
		t.Errorf("runEmulatedCommand returned %q for a command it must not understand", got)
	}
	if got := runEmulatedCommand("curl http://evil.example"); got != "" {
		t.Errorf("runEmulatedCommand returned %q for a command it must not understand", got)
	}
}

// SSTImap's FreeMarker plugin sends header + probe + trailer as one value and partitions the response
// on the two rendered sums. All three have to render, in order, with nothing between them.
func TestTheTemplateEndpointRendersWhatSSTImapPartitionsOn(t *testing.T) {
	rendered, err := renderEmulatedTemplate("${(1234+5678)?c}${777}<#--9-->${888}${(4321+8765)?c}")
	if err != "" {
		t.Fatalf("a valid FreeMarker probe raised a template error: %s", err)
	}
	if rendered != "691277788813086" {
		t.Errorf("got %q, want %q. SSTImap cuts the response between the header sum and the trailer "+
			"sum and compares what is left against its expected render, so any extra or missing "+
			"character here makes it report the parameter not injectable", rendered, "691277788813086")
	}
}

// TInjA fingerprints by sending four polyglots and classifying each response as unmodified, modified
// or error. Measured against TInjA 1.2.0: with these exact reactions it reports "Freemarker was
// identified (certainty: Very High)". Rendering an expression it cannot evaluate back verbatim makes
// all four "unmodified" and TInjA concludes "No template engine could be detected".
func TestTheTemplateEndpointReactsToTInjAsPolyglotsAsFreeMarkerDoes(t *testing.T) {
	for _, tc := range []struct {
		polyglot string
		wantErr  bool
		want     string
	}{
		// Nested braces inside the interpolation. A regex of the form \$\{[^{}]*\} matches neither of
		// these, which is why the render scans braces instead.
		{polyglot: `<%'${{/#{@}}%>{{`, wantErr: true},
		{polyglot: `p ">[[${{1}}]]`, wantErr: true},
		// #{1} is FreeMarker's legacy numeric interpolation and is the only part of this one a
		// FreeMarker renders. It is the probe that turns "no engine" into "Freemarker".
		{polyglot: `<%=1%>@*#{1}`, want: `<%=1%>@*1`},
		{polyglot: `{##}/*{{.}}*/`, want: `{##}/*{{.}}*/`},
		// The verification payload TInjA sends once it suspects FreeMarker.
		{polyglot: `${7*7}`, want: `49`},
	} {
		rendered, err := renderEmulatedTemplate(tc.polyglot)
		if tc.wantErr {
			if err == "" {
				t.Errorf("polyglot %q rendered as %q instead of raising a template error, so TInjA "+
					"records it as unmodified and identifies no engine", tc.polyglot, rendered)
			}
			continue
		}
		if err != "" {
			t.Errorf("polyglot %q raised a template error %q; FreeMarker renders it", tc.polyglot, err)
		}
		if rendered != tc.want {
			t.Errorf("polyglot %q rendered %q, want %q", tc.polyglot, rendered, tc.want)
		}
	}
}

// A template error has to be a 500 that names the engine, for the same reason /sqli names PostgreSQL.
// TInjA classifies a status change as "error", and a fingerprinter given a 200 for everything has
// nothing to fingerprint.
func TestATemplateErrorIsAFiveHundredThatNamesTheEngine(t *testing.T) {
	recorder := httptest.NewRecorder()
	sstiHandler(recorder, httptest.NewRequest(http.MethodGet, "/ssti?tpl=%24%7B%7B1%7D%7D", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("a malformed interpolation returned %d, want 500", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "FreeMarker template error") {
		t.Errorf("the error page does not name the engine, so nothing can fingerprint it:\n%s", body)
	}
}

// Nothing in the template path may evaluate anything beyond the closed grammar. An expression that
// reaches for a class, a global or a shell is an error, never a render.
func TestTheTemplateEngineRefusesEverythingOutsideItsClosedGrammar(t *testing.T) {
	for _, expr := range []string{
		`"freemarker.template.utility.Execute"?new()("id")`,
		`.data_model`,
		`7*7*object.class`,
		`statics['java.lang.Runtime']`,
	} {
		if value, ok := evalTemplateExpr(expr); ok {
			t.Errorf("evalTemplateExpr(%q) = %q, true. The emulation must refuse anything it cannot "+
				"prove is two integers, an operator or a literal", expr, value)
		}
	}
}

// Every vulnerable response has to carry the marker, or the framework cannot tell a tool that reached
// the control from a tool that reached something else.
func TestEveryControlEndpointCarriesTheMarker(t *testing.T) {
	for path, handler := range map[string]http.HandlerFunc{
		"/xss?q=1":                   xssHandler,
		"/sqli?id=1":                 sqliHandler,
		"/lfi?file=../../etc/passwd": lfiHandler,
		"/cmdi?cmd=1":                cmdiHandler,
		"/ssti?tpl=1":                sstiHandler,
		// The error page too: a scanner that only ever sees the failure branch still has to be able to
		// tell it is looking at the control.
		"/ssti?tpl=%24%7B%7B1%7D%7D": sstiHandler,
	} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if !strings.Contains(recorder.Body.String(), canaryMarker) {
			t.Errorf("%s does not carry %s, so a finding on it cannot be recognised as the control",
				path, canaryMarker)
		}
	}
}
