package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// ---------------------------------------------------------------------------------------------
// CLEAN CONTROLS.
//
// Every route above this line is vulnerable, which means a detector that fires on everything scores
// full marks and so does a detector hardwired to return true. Until a classifier can be shown
// STAYING SILENT, nothing about it is verified. These tests are the silent half.
//
// They drive requests THROUGH newMux(), never into a handler directly, because the failure mode
// being guarded is a path that was never registered: "/" is a catch-all, so an unbuilt route answers
// 200 with the index page and a handler-level test passes on a build that does not serve it.
// ---------------------------------------------------------------------------------------------

// cleanRoutes is the canonical list. A detector must produce NOTHING on any of them.
var cleanRoutes = []string{
	"/clean/noisy", "/clean/dberror", "/clean/intcast", "/clean/validate", "/clean/waf",
	"/clean/always500", "/clean/echo", "/clean/spa", "/clean/nonidem", "/clean/empty204",
	"/clean/nothing", "/clean/drift", "/clean/echoparser", "/clean/junk", "/clean/inert",
	"/clean/passwddoc", "/clean/b64noise", "/clean/mongoprose", "/clean/echomongo",
	"/clean/versionprose",
	// Not under /clean, and a clean route all the same: /rfi/inband-reject is the place the
	// in-band RFI tier must conclude NOTHING, so it carries no canary marker and belongs to every
	// assertion that guards the silent half.
	"/rfi/inband-reject",
	// The expression-language and NoSQL negatives. Each is a place a detector must stay silent
	// and each is silent for a DIFFERENT reason: /eli/hardened reflects with no evaluator behind
	// it, /eli/echo returns the answers it was sent, /eli/devmode carries its one signature in
	// the baseline, and /nosqli/strict refuses an operator and a bare number identically.
	//
	// /eli/longmath is deliberately NOT on this list. Something there really does evaluate
	// arithmetic, so it carries the canary marker and a scanner that found it would be right;
	// what the class owes on it is suspicious (el_overflow_unwrapped), which is neither a finding
	// nor a clean.
	"/eli/hardened", "/eli/echo", "/eli/devmode", "/nosqli/strict",
	// The client-side template negatives. /csti/jinja is not among them: the server really does
	// evaluate there, and what the class owes on it is a hand-off to the server-side class rather
	// than a silence.
	"/csti/escaped", "/csti/nonbindable", "/csti/inscript", "/csti/pct-literal",
	"/csti/product-in-baseline", "/csti/calculator", "/csti/aot", "/csti/vue-runtime",
	"/csti/corpus-blocked", "/csti/angular-attr", "/csti/angular-hash",
}

func serve(t *testing.T, method, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	recorder := httptest.NewRecorder()
	newMux().ServeHTTP(recorder, httptest.NewRequest(method, target, reader))
	return recorder
}

func get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, http.MethodGet, target, "")
}

// The single most important structural test in the file. A route that is not registered is answered
// by the index page with a 200 and no marker header, and every classifier then measures the index
// page while believing it measured a control.
func TestEveryCleanRouteIsActuallyRegistered(t *testing.T) {
	for _, route := range append(append([]string{}, cleanRoutes...),
		"/sqli/mssql", "/sqli/mysql", "/sqli/json", "/csti/angular", "/csti/angular.min.js",
		"/csti/plain", "/xss/encoded", "/xss/entity",
		"/sqli/blind", "/sqli/status200", "/rfi/inband-include",
		"/eli", "/eli/spel", "/eli/ognl", "/eli/longmath",
		"/nosqli/mongo", "/nosqli/noscripting", "/nosqli/where", "/nosqli/where/hello",
		"/nosqli/lucene",
		"/csti/jinja", "/csti/escaped", "/csti/nonbindable", "/csti/inscript", "/csti/pct-literal",
		"/csti/product-in-baseline", "/csti/calculator", "/csti/aot", "/csti/vue-runtime",
		"/csti/corpus-blocked", "/csti/blocked.js", "/csti/angular-attr", "/csti/angular-hash") {
		recorder := get(t, route)
		if recorder.Header().Get("X-Ars0n-Oracle") == "" {
			t.Errorf("%s carries no X-Ars0n-Oracle header, so it is being answered by the \"/\" "+
				"catch-all index page rather than by a handler. Every classifier pointed at it would "+
				"measure the index page and record the result as a property of the control", route)
		}
	}
}

// The canary marker means "this response is the vulnerable control". A clean route carrying it turns
// every marker-grep detector into a false positive on the exact routes built to catch false
// positives. Reachability on a clean route is proved by the header, not by the body.
func TestNoCleanRouteCarriesTheCanaryMarker(t *testing.T) {
	for _, route := range cleanRoutes {
		for _, target := range []string{route, route + "?id=1", route + "?id=1%27%20OR%201%3D1--"} {
			if body := get(t, target).Body.String(); strings.Contains(body, canaryMarker) {
				t.Errorf("%s carries %s, so a detector that greps for the marker reports a finding on "+
					"a route whose whole purpose is to have none", target, canaryMarker)
			}
		}
	}
}

// THE NOISE MODEL'S ONLY CONTROL. Without a route that is never byte-identical to itself, every
// differential in the system is untested: a comparator that calls any two different responses a
// finding scores perfectly against an oracle whose responses never change.
func TestNoisyIsNeverByteIdenticalToItselfAndIgnoresInput(t *testing.T) {
	bodies := map[string]bool{}
	lengths := map[int]bool{}
	for i := 0; i < 12; i++ {
		body := get(t, "/clean/noisy?id=1").Body.String()
		if bodies[body] {
			t.Fatalf("/clean/noisy returned a byte-identical body twice. It is the only control the "+
				"noise model has, and a comparator that treats any difference as a signal passes "+
				"every test in this suite without it. Body:\n%s", body)
		}
		bodies[body] = true
		lengths[len(body)] = true
	}
	// Length has to move too. A comparator that compares only content-length is not exercised by a
	// body that jitters at a fixed width.
	if len(lengths) < 2 {
		t.Errorf("every /clean/noisy body was the same %d distinct lengths, so a length-only "+
			"comparator sees a perfectly stable endpoint and that half of the noise model is "+
			"untested", len(lengths))
	}
	// And the noise must be INPUT-INDEPENDENT, or a differential detector could legitimately
	// attribute it to the payload.
	payloaded := get(t, "/clean/noisy?id=1%27").Body.String()
	if strings.Contains(payloaded, "'") {
		t.Errorf("/clean/noisy reflected the payload. Noise attributable to the input is not noise, " +
			"and a detector firing here would be right, which defeats the control")
	}
}

// The naive signature matcher's control: the DBMS error is in the baseline, so it says nothing about
// the payload. Only a rule requiring this run's own marker inside the error phrase survives here.
func TestDberrorCarriesADatabaseErrorOnTheBaselineToo(t *testing.T) {
	for _, target := range []string{"/clean/dberror", "/clean/dberror?id=1", "/clean/dberror?id=1%27"} {
		body := get(t, target).Body.String()
		if !strings.Contains(body, "org.postgresql.util.PSQLException") {
			t.Errorf("%s does not carry a PSQLException. The point of this route is that the "+
				"signature is present BEFORE any payload is sent, so a matcher that greps for it "+
				"fires on the baseline", target)
		}
	}
	// It must not echo, or the marker-in-the-phrase rule would fire here legitimately and this
	// stops being a clean control.
	if body := get(t, "/clean/dberror?id=ZQMK7X").Body.String(); strings.Contains(body, "ZQMK7X") {
		t.Errorf("/clean/dberror echoed the parameter into a page that always shows a database " +
			"error. That is a genuine marker-in-the-phrase hit, not a false positive, so the route " +
			"no longer tests what it claims to")
	}
}

// An integer cast is not cleanliness. 1' reads exactly like 1, so the class must answer CAST, and a
// classifier that answers "clean" here has quietly told the operator the parameter is safe when the
// truth is that it could not see it.
func TestIntcastMakesAQuotedValueByteIdenticalToTheCleanOne(t *testing.T) {
	plain := get(t, "/clean/intcast?id=1").Body.String()
	for _, payload := range []string{"1%27", "1%27%20OR%20%271%27%3D%271", "1%20AND%201%3D1", "1abc"} {
		if got := get(t, "/clean/intcast?id="+payload).Body.String(); got != plain {
			t.Errorf("id=%s produced a different body from id=1, so the tail was not discarded and "+
				"the cast detector has no fixture. got:\n%s\nwant:\n%s", payload, got, plain)
		}
	}
	// It must still be RESPONSIVE, or it would be indistinguishable from a route that ignores the
	// parameter entirely, which is /clean/inert and a different verdict.
	if get(t, "/clean/intcast?id=2").Body.String() == plain {
		t.Error("/clean/intcast answers id=2 the same as id=1, so it is inert rather than casting " +
			"and cannot tell the two verdicts apart")
	}
}

// Input validation is not a SQL error. Both the break probe and its balanced repair are rejected
// identically, so the verdict is metachar_not_delivered and nothing about the sink was learned.
func TestValidateRejectsEveryMetacharacterIdenticallyAndNamesNoEngine(t *testing.T) {
	first := ""
	for _, payload := range []string{"1%27", "1%22", "1%27%27", "1%60", "1%3B", "%7B%22a%22%3A1%7D"} {
		recorder := get(t, "/clean/validate?id="+payload)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("id=%s returned %d, want 400: a validation layer rejects the metacharacter "+
				"before any sink sees it", payload, recorder.Code)
		}
		body := recorder.Body.String()
		for _, engineWord := range []string{"SQL", "PSQLException", "syntax error", "MongoServerError"} {
			if strings.Contains(body, engineWord) {
				t.Errorf("the validation 400 for %s contains %q. A rejection that talks like a "+
					"database turns this control into a positive", payload, engineWord)
			}
		}
		if first == "" {
			first = body
		} else if body != first {
			t.Errorf("the 400 body differs between payloads, so a detector can read a differential "+
				"out of the rejection itself. got:\n%s\nfirst:\n%s", body, first)
		}
	}
	if code := get(t, "/clean/validate?id=1").Code; code != http.StatusOK {
		t.Errorf("a benign value returned %d, want 200. If the route control is also rejected the "+
			"endpoint is simply unreachable, which is a different reason from metachar_not_delivered",
			code)
	}
}

// A uniform non-baseline response is a WAF, not a finding. Payloads from six different classes have
// to produce the same page, because cannot_determine (blocked) is only reachable when the classifier
// can see that its own distinct payloads were answered identically.
func TestWafBlocksEveryClassIdentically(t *testing.T) {
	first := ""
	for _, payload := range []string{
		"1%27%20OR%201%3D1--",                 // SQL
		"%3Cscript%3Ealert(1)%3C%2Fscript%3E", // XSS
		"%24%7B7*7%7D",                        // SSTI
		"%3Bsleep%205",                        // CMDI
		"..%2F..%2Fetc%2Fpasswd",              // traversal
		"%7B%22%24ne%22%3Anull%7D",            // NoSQL
	} {
		recorder := get(t, "/clean/waf?id="+payload)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("payload %s returned %d, want 403", payload, recorder.Code)
		}
		if first == "" {
			first = recorder.Body.String()
		} else if recorder.Body.String() != first {
			t.Errorf("the block page differs between payloads, so it is not a uniform block and "+
				"blocked cannot be distinguished from responsive. payload %s gave:\n%s", payload,
				recorder.Body.String())
		}
	}
	if code := get(t, "/clean/waf?id=1").Code; code != http.StatusOK {
		t.Errorf("the benign route control returned %d, want 200. A route that blocks its own "+
			"control is unreachable, not protected", code)
	}
}

// A 500 that is not about the payload. This is also the route that catches "5xx means injection",
// which is not a rule.
func TestAlways500AnswersABenignValueWithTheSameFiveHundred(t *testing.T) {
	benign := get(t, "/clean/always500?id=1")
	payloaded := get(t, "/clean/always500?id=1%27")
	if benign.Code != 500 || payloaded.Code != 500 {
		t.Errorf("want 500 for both, got %d and %d", benign.Code, payloaded.Code)
	}
	if benign.Body.String() != payloaded.Body.String() {
		t.Error("the error page differs between a benign value and a payload, so there is a real " +
			"differential here and the route is not the control it claims to be")
	}
	for _, engineWord := range []string{"PSQLException", "SQL syntax", "FreeMarker", "Traceback"} {
		if strings.Contains(benign.Body.String(), engineWord) {
			t.Errorf("the generic 500 names %q, which makes it an error-signature positive", engineWord)
		}
	}
}

// Reflection is not injection. The echo hands back the answer string a computation oracle is looking
// for, so any detector that greps the body for its own expected answer without checking that the
// answer is absent from the wire form fires here.
func TestEchoReflectsVerbatimWithoutBeingASink(t *testing.T) {
	recorder := get(t, "/clean/echo?q=SUTLLX110SUTLLXSUTLLX%20%3Cscript%3E%2049")
	body := recorder.Body.String()
	if !strings.Contains(body, "SUTLLX110SUTLLXSUTLLX") {
		t.Errorf("the echo did not come back verbatim, so the guard it exists to test is never "+
			"exercised. body:\n%s", body)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("Content-Type is %q. A verbatim reflection served as text/html IS cross-site "+
			"scripting, and this route would be a positive control by accident", contentType)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("without nosniff a browser can sniff the reflection back into HTML, which makes the " +
			"clean control genuinely exploitable in a DOM run")
	}
}

// The answer is in a later XHR. A shell that is identical whatever you send must not read as a
// stable clean: the classifier saw nothing because there was nothing on the page to see.
func TestSpaServesTheSameShellWhateverYouSend(t *testing.T) {
	shell := get(t, "/clean/spa").Body.String()
	for _, payload := range []string{"?q=1", "?q=1%27", "?q=%3Cscript%3E", "?q=%24%7B7*7%7D"} {
		if got := get(t, "/clean/spa"+payload).Body.String(); got != shell {
			t.Errorf("%s changed the shell, so the route is reflecting and is not the SPA control", payload)
		}
	}
}

// Every response legitimately differs, and none of the differences is attributable to the payload.
// A comparator that reads a differential here reports a finding on every guestbook on the internet.
func TestNonidemGrowsOnEveryPostWithoutEchoingThePayload(t *testing.T) {
	first := serve(t, http.MethodPost, "/clean/nonidem", "comment=ZQMK7X%27").Body.String()
	second := serve(t, http.MethodPost, "/clean/nonidem", "comment=ZQMK7X%27").Body.String()
	if first == second {
		t.Error("two identical POSTs produced identical bodies, so nothing was appended and the " +
			"legitimate-differential control does not differ")
	}
	for _, body := range []string{first, second} {
		if strings.Contains(body, "ZQMK7X") {
			t.Error("/clean/nonidem echoed the submitted value. Then it is an echo route as well as " +
				"a non-idempotent one, and a hit here no longer isolates which of the two caused it")
		}
	}
	// Bounded. The container is read_only with cap_drop ALL and this list lives in memory forever.
	for i := 0; i < nonidemCap*2; i++ {
		serve(t, http.MethodPost, "/clean/nonidem", "comment=x")
	}
	if rows := strings.Count(serve(t, http.MethodGet, "/clean/nonidem", "").Body.String(), "<li>"); rows > nonidemCap {
		t.Errorf("the log holds %d rows with a cap of %d, so a scanner can grow it without bound",
			rows, nonidemCap)
	}
}

// No body at all. "Identical bodies therefore same" would make every blind oracle report clean on an
// endpoint it could not see.
func TestEmpty204AndNothingReturnNoBodyAtAll(t *testing.T) {
	if recorder := get(t, "/clean/empty204"); recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 {
		t.Errorf("/clean/empty204 returned %d with %d bytes, want 204 and 0", recorder.Code, recorder.Body.Len())
	}
	if recorder := get(t, "/clean/nothing"); recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Errorf("/clean/nothing returned %d with %d bytes, want 200 and 0. A 200 with an empty body "+
			"is an unknown, not a green tick, and it is a different shape from a 204",
			recorder.Code, recorder.Body.Len())
	}
}

// Drift, which is NOT noise. Adjacent responses match, so a comparator sampling twice sees a stable
// endpoint, and then the baseline goes stale underneath a long ladder. A design that baselines once
// and trusts it forever passes /clean/noisy and fails here.
func TestDriftIsStableBetweenAdjacentCallsAndStaleAcrossALadder(t *testing.T) {
	// Align to a generation boundary first. Earlier tests in this package have already called the
	// route, so without this the two samples below could straddle a change and the test would fail
	// for a reason that has nothing to do with the property under test. Reading the counter is
	// honest here: the test and the handler are the same package, and the alternative is a flaky
	// assertion that gets "fixed" by loosening it.
	for driftCounter.Load()%driftPeriod != 0 {
		get(t, "/clean/drift")
	}
	first := get(t, "/clean/drift").Body.String()
	if second := get(t, "/clean/drift").Body.String(); second != first {
		t.Errorf("two adjacent calls already differ, which makes this a second /clean/noisy. Drift "+
			"has to be invisible to a two-sample check or it tests nothing new:\n%s\n%s", first, second)
	}
	for i := 0; i < driftPeriod*2; i++ {
		get(t, "/clean/drift")
	}
	if later := get(t, "/clean/drift").Body.String(); later == first {
		t.Error("the body never drifted, so a stale baseline can never be observed and the " +
			"re-baseline rule has no fixture")
	}
}

// The payload comes back AND the phrase "SQL syntax" is on the page, but they are far apart and on
// different lines. An adjacency rule is what separates this from a real error-based finding.
func TestEchoparserPutsThePhraseFarFromTheEcho(t *testing.T) {
	const marker = "ZQMK7X"
	body := get(t, "/clean/echoparser?id="+marker+"%27").Body.String()
	echoAt := strings.Index(body, marker)
	phraseAt := strings.Index(body, "SQL syntax")
	if echoAt < 0 || phraseAt < 0 {
		t.Fatalf("need both the echo (%d) and the phrase (%d) on the page", echoAt, phraseAt)
	}
	if distance := phraseAt - echoAt; distance <= 120 {
		t.Errorf("the phrase is %d bytes from the marker; the rule refuses at 120, so this route "+
			"would be a genuine hit rather than the control for that refusal", distance)
	}
	if !strings.Contains(body[echoAt:phraseAt], "\n") {
		t.Error("the echo and the phrase are on the same line, so the same-line half of the rule is " +
			"not exercised")
	}
	if !strings.Contains(get(t, "/clean/echoparser?id=1").Body.String(), "SQL syntax") {
		t.Error("the phrase is absent from the baseline, so baseline subtraction alone would clear " +
			"this route and the adjacency rule would never be reached")
	}
}

// Errors on ANY modified value, including a purely alphanumeric one. The class must notice with its
// junk control and stop, rather than reading the 500 it gets from a quote as a SQL error.
func TestJunkErrorsOnAHarmlessAlphanumericValue(t *testing.T) {
	if code := get(t, "/clean/junk?id=1").Code; code != http.StatusOK {
		t.Errorf("the observed value returned %d, want 200", code)
	}
	for _, value := range []string{"zqjxwb", "2", "1x"} {
		if code := get(t, "/clean/junk?id="+value).Code; code != http.StatusInternalServerError {
			t.Errorf("a harmless value %q returned %d, want 500. The junk control exists to catch an "+
				"endpoint that breaks on anything it did not issue itself", value, code)
		}
	}
}

// The parameter is discarded. Both the break probe and its control match the route control, so the
// verdict is parameter_inert, which is neither casted nor clean.
func TestInertAnswersEveryValueIdentically(t *testing.T) {
	baseline := get(t, "/clean/inert").Body.String()
	for _, value := range []string{"1", "2", "1%27", "zqjxwb", "%3Cscript%3E"} {
		if got := get(t, "/clean/inert?id="+value).Body.String(); got != baseline {
			t.Errorf("value %q changed the response, so the parameter is not inert", value)
		}
	}
	if baseline == "" {
		t.Error("an inert route with an empty body is /clean/nothing; it needs content so that " +
			"parameter_inert and no_body stay distinguishable")
	}
}

// The signature is IN THE BASELINE. Neither a finding nor a clean: cannot_determine
// (signature_in_baseline), and each class has to reach it from its own probes.
func TestSignatureInBaselineRoutesCarryTheirSignatureBeforeAnyPayload(t *testing.T) {
	for _, tc := range []struct{ route, signature string }{
		{"/clean/passwddoc", "root:x:0:0"},
		{"/clean/mongoprose", "MongoServerError"},
		{"/clean/mongoprose", "unknown operator: $"},
		{"/clean/versionprose", "ImageMagick 7.1.1"},
	} {
		if body := get(t, tc.route).Body.String(); !strings.Contains(body, tc.signature) {
			t.Errorf("%s does not carry %q on the unperturbed baseline, which is the only thing that "+
				"makes it a control for baseline subtraction", tc.route, tc.signature)
		}
	}
}

// A JWT and a PNG data URI must produce zero base64 hits. This is the control for the rule that
// replaced every base64 signature in the file class.
func TestB64noiseCarriesRealBase64ThatDecodesToNothingInteresting(t *testing.T) {
	body := get(t, "/clean/b64noise").Body.String()
	if !strings.Contains(body, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Error("no JWT on the page, so the commonest base64 false positive is not represented")
	}
	if !strings.Contains(body, "data:image/png;base64,iVBORw0KGgo") {
		t.Error("no PNG data URI on the page, so the second commonest base64 false positive is not " +
			"represented")
	}
	if strings.Contains(body, "cm9vdDp4OjA6MDpyb290") {
		t.Error("the page contains base64 of /etc/passwd, which would be a correct hit and not a " +
			"false one")
	}
}

// The payload comes back with its own characters in it, and the computation oracle must want the
// PRODUCT, not the expression. A substring search for the operands passes here and is wrong.
func TestEchomongoReturnsTheExpressionButNeverTheProduct(t *testing.T) {
	recorder := serve(t, http.MethodPost, "/clean/echomongo",
		`{"u":{"$where":"8123*7 == 56861"}}`)
	body := recorder.Body.String()
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", recorder.Code)
	}
	if !strings.Contains(body, "8123*7") {
		t.Errorf("the expression did not come back, so the echo guard is not exercised:\n%s", body)
	}
	// 56861 is 8123*7. It may only be present because the CLIENT sent it, which is exactly the case
	// the answer_not_in_wire guard exists for; the route must not compute it.
	if strings.Count(body, "56861") > 1 {
		t.Errorf("the product appears more often than the client sent it, so the route evaluated "+
			"the expression and is a positive:\n%s", body)
	}
}

// ---------------------------------------------------------------------------------------------
// POSITIVE CONTROLS added alongside the clean ones. Each is a context that no existing route can
// reach, so a class that handles it has never been observed doing so.
// ---------------------------------------------------------------------------------------------

// A bracketed identifier. Nothing in a quote ladder reaches it: only a closing bracket does, which
// is the one contribution the bracket payloads make and the one context verified nowhere today.
func TestMssqlBreaksOnlyOnABracket(t *testing.T) {
	for _, inert := range []string{"1%27", "1%22", "1%60", "1%3B--"} {
		if code := get(t, "/sqli/mssql?sort="+inert).Code; code != http.StatusOK {
			t.Errorf("payload %s returned %d; inside a bracketed identifier every one of these is a "+
				"literal character and the statement still parses", inert, code)
		}
	}
	recorder := get(t, "/sqli/mssql?sort=%5D123")
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("a closing bracket returned %d, want 500", recorder.Code)
	}
	for _, want := range []string{"Incorrect syntax near", "Msg 102"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("the error page lacks %q, so nothing can fingerprint it as SQL Server", want)
		}
	}
}

func TestMysqlBreaksOnlyOnABacktick(t *testing.T) {
	for _, inert := range []string{"1%27", "1%22", "1%5D"} {
		if code := get(t, "/sqli/mysql?sort="+inert).Code; code != http.StatusOK {
			t.Errorf("payload %s returned %d; inside a backtick identifier it is a literal", inert, code)
		}
	}
	recorder := get(t, "/sqli/mysql?sort=%60123")
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("a backtick returned %d, want 500", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "You have an error in your SQL syntax") {
		t.Errorf("the error page does not talk like MySQL:\n%s", recorder.Body.String())
	}
}

// THE PER-CONTENT-TYPE ENCODING RULE. A raw double quote never reaches the database, because the
// JSON parser rejects the document first; a single quote is inert to JSON and lands in the query.
// Getting this backwards makes the whole SQL arm on JSON APIs noise.
func TestJsonApiSeparatesAParseErrorFromASqlError(t *testing.T) {
	parse := serve(t, http.MethodPost, "/sqli/json", `{"id":"1""}`)
	if parse.Code != http.StatusBadRequest {
		t.Errorf("a malformed document returned %d, want 400", parse.Code)
	}
	for _, sqlWord := range []string{"PSQLException", "SQL"} {
		if strings.Contains(parse.Body.String(), sqlWord) {
			t.Errorf("the JSON parse error mentions %q; a detector reading it as a database error "+
				"files a finding on an endpoint whose parser never let the payload through", sqlWord)
		}
	}
	injected := serve(t, http.MethodPost, "/sqli/json", `{"id":"1'"}`)
	if injected.Code != http.StatusInternalServerError {
		t.Errorf("a single quote returned %d, want 500: it is valid JSON and reaches the query",
			injected.Code)
	}
	if !strings.Contains(injected.Body.String(), "PSQLException") {
		t.Errorf("the quote that reached SQL produced no database error:\n%s", injected.Body.String())
	}
	if code := serve(t, http.MethodPost, "/sqli/json", `{"id":"1"}`).Code; code != http.StatusOK {
		t.Errorf("the benign document returned %d, want 200", code)
	}
}

// CSTI has no positive control of any kind today: its detectors have only ever been observed staying
// silent, which is exactly as unverified as only ever being observed firing.
func TestAngularRouteShipsAClientTemplateEngineAndPlainDoesNot(t *testing.T) {
	page := get(t, "/csti/angular?q=%7B%7B7*7%7D%7D").Body.String()
	if !strings.Contains(page, "ng-app") {
		t.Error("no ng-app attribute, so the framework detector has nothing to find")
	}
	if !strings.Contains(page, "angular.min.js") {
		t.Error("no angular script reference, so corpus-based framework detection cannot fire")
	}
	if !strings.Contains(page, "{{7*7}}") {
		t.Errorf("the delimiters were not reflected into the compiled region, so there is nothing "+
			"for the browser tier to evaluate:\n%s", page)
	}
	script := get(t, "/csti/angular.min.js")
	if contentType := script.Header().Get("Content-Type"); !strings.Contains(contentType, "javascript") {
		t.Errorf("the script is served as %q and a browser will not execute it", contentType)
	}
	if !strings.Contains(script.Body.String(), "ng-app") {
		t.Error("the emulated engine does not look for ng-app, so it compiles nothing")
	}

	plain := get(t, "/csti/plain?q=%7B%7B7*7%7D%7D").Body.String()
	if strings.Contains(plain, "ng-app") || strings.Contains(plain, "angular") {
		t.Error("/csti/plain ships a framework, so not_applicable (no_client_template_engine) has " +
			"no fixture")
	}
	if !strings.Contains(plain, "{{7*7}}") {
		t.Error("/csti/plain must still reflect the delimiters: the point is that they come back " +
			"unevaluated with no engine to evaluate them")
	}
}

// Reflected does not mean executable.
func TestXssEncodedAndEntityRoutesNeverReturnARawTag(t *testing.T) {
	for _, route := range []string{"/xss/encoded", "/xss/entity"} {
		body := get(t, route+"?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").Body.String()
		if strings.Contains(body, "<script>alert(1)") {
			t.Errorf("%s returned the raw tag, so it is a positive and not the control it claims to "+
				"be:\n%s", route, body)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s did not reflect the value at all. A route that drops the input is "+
				"value_ignored, a different verdict from encoded", route)
		}
	}
	// The same reflection served as JSON with nosniff is cannot_determine (needs_dom_run), never a
	// finding and never a clean, so the content type has to actually change.
	recorder := get(t, "/xss/encoded?json=1&q=%3Cscript%3E")
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("?json=1 served %q, so the JSON half of the route does not exist", contentType)
	}
}

// =================================================================================================
// THE FOUR ROUTES OTHER CLASSES NAMED AND THIS CONTAINER DID NOT SERVE
//
// Every route below was named, in prose, by the class that depends on it, and answered by the "/"
// catch-all instead. A named-but-absent control is worse than no control: the class's own atlas
// says "verified against /sqli/blind", the operator reads that as coverage, and the route returns
// the index page with a 200.
// =================================================================================================

// The exact bytes the framework's own classes put on the wire. They are written out here rather
// than imported because this container must not depend on the server module, and a control that
// answers a payload nobody sends is decoration.
const (
	// server/triageclasses/sql.go, SQL-A1 through SQL-A3 on a slot whose observed value is "hello".
	realA1 = `hello' AND (4093*7)=28651 AND 'a'='a`
	realA2 = `hello' AND (4093*7)=28652 AND 'a'='a`
	realA3 = `hello' AND 28651 28652 AND 'a'='a`
	// SQL-A4 and SQL-A5 on a slot whose observed value is "1". The numeric arm is planned only
	// against a digits-only value, which is why this pair belongs to a different route.
	realA4 = `1+4093-4093`
	realA5 = `1+4093-4094`
	// server/triageclasses/rfi.go, the in-band tier. H0 is H1 with the scheme stripped.
	realH0 = `zqjrfi00000009xx.rfi-inband.invalid/f.txt`
	realH1 = `http://zqjrfi00000009xx.rfi-inband.invalid/f.txt`
	realH2 = `https://zqjrfi00000009xx.rfi-inband.invalid/f.txt`
)

func getValue(t *testing.T, route, param, value string) *httptest.ResponseRecorder {
	t.Helper()
	return get(t, route+"?"+param+"="+url.QueryEscape(value))
}

// THE DEFECT, MEASURED. reAlwaysT is `(or|and)\s+(\d+)\s*=\s*(\d+)`, and the boolean arm of the
// SQL class sends `AND (4093*7)=28651`. A parenthesised product is not two integers, so the
// matcher sees nothing, the true arm and the false arm produce the same page, and the ONE
// detector that can see an endpoint which suppresses its errors has no positive control anywhere
// in this container.
func TestTheBooleanMatcherRecognisesTheFormsTheClassActuallySends(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"1 OR 1=1", true},
		{"1 OR 1=2", false},
		{realA1, true},
		{realA2, false},
		{`x'/**/AND/**/(4093*7)=28651/**/AND/**/'a'='a`, true},
		{`x'/**/AND/**/(4093*7)=28652/**/AND/**/'a'='a`, false},
	} {
		truth, ok := sqlInjectedTruth(tc.value)
		if !ok {
			t.Errorf("no boolean condition recognised in %q, so the true arm and the false arm of "+
				"the framework's own detector produce the same page and the blind oracle has no "+
				"positive control", tc.value)
			continue
		}
		if truth != tc.want {
			t.Errorf("%q evaluated to %v, want %v", tc.value, truth, tc.want)
		}
	}
	// Two integers with no operator between them are a syntax error in every engine, and the
	// invalid-syntax control depends on NOT being read as a true condition.
	if !sqlBrokenCondition(realA3) {
		t.Errorf("%q was not read as a syntax error. SQL-A3 exists to prove the detector is not "+
			"firing on any payload at all, and a control that behaves like the true arm disables "+
			"the whole boolean rule", realA3)
	}
	if sqlBrokenCondition(realA1) {
		t.Errorf("%q was read as a syntax error, so the true arm can never match the control", realA1)
	}
}

// /sqli/blind: errors suppressed, 200 on everything. server/triageclasses/sql.go names it for
// SQL-A1, SQL-A2 and SQL-A3 and says "only the boolean arm can see it".
//
// THE ASSERTION IS THE WHOLE DIFFERENTIAL, not that a payload changed something. The true arm has
// to be BYTE-IDENTICAL to the benign baseline, the false arm has to differ, and the syntax
// control must not look like the true arm. Any two of those three passing is not a positive
// control: d2Confirmed requires all three and a repeat of the true arm.
func TestBlindRouteCarriesTheWholeBooleanDifferential(t *testing.T) {
	baseline := getValue(t, "/sqli/blind", "id", "hello")
	if baseline.Header().Get("X-Ars0n-Oracle") == "" {
		t.Fatal(`/sqli/blind is answered by the "/" catch-all, so the class's atlas claims a positive control that does not exist`)
	}
	if baseline.Code != http.StatusOK {
		t.Errorf("baseline answered %d; this route suppresses errors and is 200 on everything", baseline.Code)
	}
	base := baseline.Body.String()

	trueArm := getValue(t, "/sqli/blind", "id", realA1)
	falseArm := getValue(t, "/sqli/blind", "id", realA2)
	syntax := getValue(t, "/sqli/blind", "id", realA3)

	for name, recorder := range map[string]*httptest.ResponseRecorder{
		"true arm": trueArm, "false arm": falseArm, "syntax control": syntax,
	} {
		if recorder.Code != http.StatusOK {
			t.Errorf("%s answered %d. An endpoint that changes status is visible to the error "+
				"oracle, and then this route is no longer the blind control it claims to be",
				name, recorder.Code)
		}
	}
	if trueArm.Body.String() != base {
		t.Errorf("the true arm did not reproduce the baseline page, so cmp(SQL-A1, control) is not "+
			"'same' and the boolean rule cannot fire:\nbaseline: %s\ntrue arm: %s",
			base, trueArm.Body.String())
	}
	if falseArm.Body.String() == base {
		t.Error("the false arm reproduced the baseline page, so cmp(SQL-A2, control) is not " +
			"'different' and the differential is flat")
	}
	if syntax.Body.String() == base {
		t.Error("the invalid-syntax control reproduced the baseline page, which d2Confirmed reads " +
			"as 'the control looks TRUE' and refuses the whole finding on")
	}
	if second := getValue(t, "/sqli/blind", "id", realA1); second.Body.String() != trueArm.Body.String() {
		t.Error("the true arm did not reproduce itself. d2Confirmed requires two sends of the true " +
			"arm precisely so a page that simply alternates cannot look like an injection")
	}
}

// /sqli/status200: the numeric arm against an endpoint that never changes its status. The numeric
// arm carries NO metacharacter at all, so it is the only probe in the class that survives a quote
// filter, and it was verified against nothing.
func TestStatus200RouteAnswersTheNumericArmAndNeverMovesItsStatus(t *testing.T) {
	baseline := getValue(t, "/sqli/status200", "id", "1")
	if baseline.Header().Get("X-Ars0n-Oracle") == "" {
		t.Fatal(`/sqli/status200 is answered by the "/" catch-all`)
	}
	base := baseline.Body.String()
	trueArm := getValue(t, "/sqli/status200", "id", realA4)
	falseArm := getValue(t, "/sqli/status200", "id", realA5)
	syntax := getValue(t, "/sqli/status200", "id", realA3)

	for name, recorder := range map[string]*httptest.ResponseRecorder{
		"baseline": baseline, "true arm": trueArm, "false arm": falseArm, "syntax control": syntax,
	} {
		if recorder.Code != http.StatusOK {
			t.Errorf("%s answered %d, and the entire point of this route is that the status never "+
				"moves, so a detector reading status cannot pass here by accident", name, recorder.Code)
		}
	}
	if trueArm.Body.String() != base {
		t.Errorf("1+4093-4093 is 1 and did not reproduce the page for id=1:\nbaseline: %s\ntrue arm: %s",
			base, trueArm.Body.String())
	}
	if falseArm.Body.String() == base {
		t.Error("1+4093-4094 is 0 and reproduced the page for id=1, so the numeric differential is flat")
	}
	if syntax.Body.String() == base {
		t.Error("the invalid-syntax control reproduced the baseline page")
	}
}

// /rfi/inband-include. server/triageclasses/rfi.go: "a route that passes the value to an include
// and prints the PHP warning naming the URL and allow_url_include. H1 must fire, the
// scheme-stripped H0 must NOT".
//
// H0 IS THE HALF THAT MATTERS. The in-band tier concludes anything at all only because the same
// bytes without a scheme produce a DIFFERENT error, and a route that printed the same warning for
// both would make this control prove the opposite of what it claims.
func TestInbandIncludeNamesTheWrapperOnlyForARemoteScheme(t *testing.T) {
	control := getValue(t, "/rfi/inband-include", "file", realH0)
	if control.Header().Get("X-Ars0n-Oracle") == "" {
		t.Fatal(`/rfi/inband-include is answered by the "/" catch-all, so the in-band tier's positive control does not exist`)
	}
	controlBody := control.Body.String()
	for _, phrase := range []string{"allow_url_include", "no suitable wrapper could be found"} {
		if strings.Contains(controlBody, phrase) {
			t.Errorf("the scheme-stripped control RFI-H0 produced %q. rfiJudgeInBand subtracts every "+
				"primary signature the control fired from the remote probes, so this route would "+
				"report error_not_specific_to_a_remote_url and the positive control would be a "+
				"negative one:\n%s", phrase, controlBody)
		}
	}
	if !strings.Contains(controlBody, "failed to open stream") {
		t.Error("RFI-H0 produced no include error at all. A route that answers a relative path with " +
			"a normal page is not the same application answering H1, and the differential then " +
			"measures two different code paths")
	}
	if !strings.Contains(controlBody, realH0) {
		t.Error("the control does not echo the value, so its marker is nowhere near the phrase and " +
			"the three in-band responses risk being byte-identical, which reads as 'blocked'")
	}

	for _, remote := range []string{realH1, realH2} {
		body := getValue(t, "/rfi/inband-include", "file", remote).Body.String()
		if !strings.Contains(body, "allow_url_include") {
			t.Errorf("%s produced no wrapper-disabled warning, so no primary signature in "+
				"rfiFetchSigs fires and the tier reports no_fetch_error_observed on a route built "+
				"to be its positive:\n%s", remote, body)
		}
		if !strings.Contains(body, remote) {
			t.Errorf("%s is not named in the error, so rfiHitNearMarker cannot place the marker "+
				"within 512 bytes of the phrase and the verdict is graded unattributed", remote)
		}
	}
	// http and https must not produce the same sentence: PHP names the scheme it disabled, and
	// RFI-H2 exists because a stack that refuses plain http never reaches its fetcher for H1.
	if getValue(t, "/rfi/inband-include", "file", realH1).Body.String() ==
		getValue(t, "/rfi/inband-include", "file", realH2).Body.String() {
		t.Error("http and https produced byte-identical pages, so RFI-H2 tests nothing RFI-H1 did not")
	}
}

// /rfi/inband-reject. THE ROUTE THAT KEEPS THE IN-BAND TIER FROM CALLING EVERY STRICT INPUT
// VALIDATOR A REMOTE FETCHER. It 500s with a stack trace for any value carrying a dot-separated
// host, remote or not, so the control fires the SAME primary phrase as the remote probes and the
// tier must answer error_not_specific_to_a_remote_url.
func TestInbandRejectFiresTheSamePhraseForTheSchemeStrippedControl(t *testing.T) {
	// A two-label value is an ordinary FILENAME, not a host, and it has to stay benign. A route
	// that 500s on report.tpl 500s on the baseline of every vector whose observed value is a
	// filename, faDisabledByBaseline then disables the one phrase this route emits, and the tier
	// answers no_fetch_error_observed: the right state for the wrong reason.
	for _, benignValue := range []string{"hello", "report.tpl", "archive.zip"} {
		recorder := getValue(t, "/rfi/inband-reject", "file", benignValue)
		if recorder.Code != http.StatusOK {
			t.Errorf("%q answered %d. It is a filename, not a host, and a baseline that already "+
				"carries the stack trace disables the signature before a single probe is sent",
				benignValue, recorder.Code)
		}
	}
	benign := getValue(t, "/rfi/inband-reject", "file", "hello")
	if benign.Header().Get("X-Ars0n-Oracle") == "" {
		t.Fatal(`/rfi/inband-reject is answered by the "/" catch-all, so the in-band tier's false-positive control does not exist and every strict validator reads as a fetcher`)
	}
	if strings.Contains(benign.Body.String(), "UnknownHostException") {
		t.Error("the benign baseline already carries the phrase. faDisabledByBaseline then disables " +
			"the signature and the verdict becomes signature_in_baseline, which is a different " +
			"finding from the one this route is built to force")
	}

	bodies := map[string]string{}
	for _, value := range []string{realH0, realH1, realH2} {
		recorder := getValue(t, "/rfi/inband-reject", "file", value)
		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("%s answered %d; this route 500s for any dotted host", value, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, "java.net.UnknownHostException") {
			t.Errorf("%s produced no primary remote-fetch phrase:\n%s", value, body)
		}
		if !strings.Contains(body, value) {
			t.Errorf("%s is not echoed, so the three responses are byte-identical and the tier "+
				"reports 'blocked' rather than the error_not_specific_to_a_remote_url this route "+
				"is the control for", value)
		}
		bodies[value] = body
	}
	if bodies[realH0] == bodies[realH1] {
		t.Error("the control and the remote probe are byte-identical, which faUniformBlock reads as " +
			"a filter answering rather than the application")
	}
}

// A route that is named by a class and not registered here is answered by the index page with a
// 200 and no marker header, and the class's atlas is then a claim of coverage that does not exist.
func TestEveryRouteTheClassesNameIsRegistered(t *testing.T) {
	for _, route := range []string{"/sqli/blind", "/sqli/status200", "/rfi/inband-include", "/rfi/inband-reject"} {
		if get(t, route).Header().Get("X-Ars0n-Oracle") == "" {
			t.Errorf(`%s carries no X-Ars0n-Oracle header, so it is the catch-all index page`, route)
		}
	}
}

// THE EARLY EXIT THAT WOULD DELETE THE ARM THESE ROUTES EXIST FOR.
//
// sqlUniformBlock calls three or more of the class's distinct payloads sharing one non-control
// page a filter answering everything, and stops the ladder before the boolean arm is sent. The
// one thing that disproves the filter is SQL-NC1, which carries no metacharacter at all, landing
// in that same bucket: a metacharacter filter cannot be what produced it.
//
// So the not-found page has to be what an UNRECOGNISED BENIGN VALUE gets, not only what a
// quote-laden one gets. A route that returned the row for any non-empty value would keep SQL-NC1
// out of the bucket, the class would stop at uniform_block after four probes, and these two
// routes would verify nothing.
func TestBlindRoutesKeepTheMetacharacterFreeProbeInTheNotFoundBucket(t *testing.T) {
	for route, observed := range map[string]string{"/sqli/blind": "hello", "/sqli/status200": "1"} {
		control := getValue(t, route, "id", observed).Body.String()
		// SQL-NC1: the observed value, this class's marker and its four-digit tail. Purely
		// alphanumeric, no metacharacter anywhere.
		nc1 := getValue(t, route, "id", observed+"zqjsql0000004ju84093").Body.String()
		if nc1 == control {
			t.Errorf("%s answered a benign unrecognised value with the control page, so SQL-NC1 "+
				"never lands in the shared not-found bucket, nothing disproves the uniform-block "+
				"rule, and the ladder stops before the boolean arm is sent", route)
		}
		falseArm := getValue(t, route, "id", realA2).Body.String()
		if route == "/sqli/status200" {
			falseArm = getValue(t, route, "id", realA5).Body.String()
		}
		if nc1 != falseArm {
			t.Errorf("%s gave SQL-NC1 and the false arm different pages. They have to share one "+
				"bucket: that is what makes the metacharacter-free probe the thing that disproves "+
				"the filter", route)
		}
	}
}

// An unbalanced quote is a broken statement, and on a route whose errors are suppressed a broken
// statement returns the empty page rather than a 500. Without this the error oracle would see a
// status change and the route would stop being blind.
func TestBlindRouteSuppressesTheErrorRatherThanHidingIt(t *testing.T) {
	control := getValue(t, "/sqli/blind", "id", "hello")
	broken := getValue(t, "/sqli/blind", "id", `hello'`)
	if broken.Code != http.StatusOK {
		t.Errorf("an unbalanced quote answered %d, so the error oracle can see this route and the "+
			"boolean arm is no longer the only detector that reaches it", broken.Code)
	}
	if broken.Body.String() == control.Body.String() {
		t.Error("an unbalanced quote returned the record. The statement did not parse, so no row " +
			"came back, and a route that returns one anyway is not emulating a query at all")
	}
	if strings.Contains(broken.Body.String(), "PSQLException") {
		t.Error("the suppressed-error route leaked a database error, which is /sqli's job and not this one")
	}
}

// =================================================================================================
// EXPRESSION LANGUAGE AND NOSQL, THE TWO CLASSES THAT HAD NO POSITIVE CONTROL AT ALL
//
// Before these routes existed, ELI's six declared endpoints and NOSQL's six were every one of them
// answered by the "/" catch-all index page: 1,228 probes per run against a static HTML document,
// and not one row in either class had ever been anything but cannot_determine. These tests are
// the assertion that the routes are what the two classes read, in the bytes they read them in.
// =================================================================================================

// eliTestMarker is marker-SHAPED on purpose: anchor plus thirteen alphanumerics is what the
// framework mints, and the adjacency rule these routes have to satisfy is "this run's marker, then
// at most eight bytes of whitespace, then the answer". A test with a shorter token would pass on a
// route that put the answer somewhere the class cannot anchor it.
const eliTestMarker = "zqjr2d9x00000271"

const (
	eliTestGeneric  = `1*((1).valueOf('1900000000')+1900000000)`
	eliTestConfirm  = `1*((1).valueOf('1800000000')+1800000000)`
	eliTestSpelBody = `T(java.lang.Integer).valueOf('1900000000')+1900000000`
	eliTestOgnlBody = `1*(@java.lang.Integer@valueOf('1900000000')+1900000000)`
	eliTestWrapped  = "-494967296"
	eliTestConfirm2 = "-694967296"
	eliTestLong     = "3800000000"
)

// THE PRIMARY ORACLE, AND THE REASON THE CLASS EXISTS SEPARATELY FROM SSTI. 1900000000 twice in a
// Java int is -494967296; in Python, JavaScript, Ruby, PHP and a JVM long it is 3800000000. One
// request therefore proves WHICH TYPE SYSTEM evaluated, which is the difference between "point a
// scanner here" and "run sstimap with -e ognl".
//
// The answer has to land IMMEDIATELY AFTER the marker. The class anchors on that adjacency, so a
// route that computed the right number and printed it in a footer would be a route where the
// detector is right and silent.
func TestTheExpressionRoutesComputeTheJavaInt32Wrap(t *testing.T) {
	for _, row := range []struct{ route, payload string }{
		{"/eli", "${" + eliTestGeneric + "}"},
		{"/eli", eliTestGeneric},
		{"/eli/spel", "#{" + eliTestSpelBody + "}"},
		{"/eli/spel", "${{" + eliTestSpelBody + "}}"},
		{"/eli/ognl", "%{" + eliTestOgnlBody + "}"},
	} {
		body := getValue(t, row.route, "q", eliTestMarker+row.payload).Body.String()
		if !strings.Contains(body, eliTestMarker+eliTestWrapped) {
			t.Errorf("%s did not answer %s with the marker glued to %s. Without it this class has "+
				"never been observed firing anywhere and its 38 rows are all cannot_determine. Body:\n%s",
				row.route, row.payload, eliTestWrapped, body)
		}
		if strings.Contains(body, eliTestLong) {
			t.Errorf("%s answered %s with the UNWRAPPED sum as well. The two are different states "+
				"and a route that carries both makes the type-system oracle meaningless", row.route, row.payload)
		}
	}
}

// THE BARE SINK IS THE ONLY ARM THAT CAN FIRE TODAY, so it gets its own assertion.
//
// MEASURED: nothing in the framework applies ProbeSpec.MarkerPos, so every ELI payload reaches the
// wire with no marker in it and every anchored rule is structurally blind. The bare probes are the
// ones whose matcher drops the marker by construction, and their rule is an unanchored substring
// search with two guards: the byte before the answer must not be alphanumeric and the byte after
// must not be a digit. A route that rendered "id-494967296" or "-4949672960" would satisfy the
// human eye and nothing else.
func TestTheBareExpressionSinkAnswersWhereTheUnanchoredRuleCanSeeIt(t *testing.T) {
	body := getValue(t, "/eli", "q", eliTestGeneric).Body.String()
	at := strings.Index(body, eliTestWrapped)
	if at < 0 {
		t.Fatalf("/eli did not evaluate a bare expression, which is the one arm of this class that "+
			"can fire at all until the runner splices markers. Body:\n%s", body)
	}
	if at > 0 {
		previous := body[at-1]
		if (previous >= '0' && previous <= '9') || (previous >= 'a' && previous <= 'z') ||
			(previous >= 'A' && previous <= 'Z') {
			t.Errorf("the answer is preceded by %q, which is alphanumeric, and the class's own guard "+
				"refuses a match in the middle of a longer run", string(previous))
		}
	}
	if end := at + len(eliTestWrapped); end < len(body) && body[end] >= '0' && body[end] <= '9' {
		t.Errorf("the answer is followed by the digit %q, so it is part of a longer number and the "+
			"class correctly refuses it", string(body[end]))
	}
	if !strings.Contains(getValue(t, "/eli", "q", eliTestConfirm).Body.String(), eliTestConfirm2) {
		t.Error("the fresh-operand confirmation did not reproduce with its own different answer. " +
			"Without it every overflow hit stays suspicious, because a confirmation that returns the " +
			"FIRST answer is a cached body and not a reproduction")
	}
}

// THE SECOND ARM, AND IT IS INDEPENDENT RATHER THAN CORROBORATING. A method allow-list on valueOf
// kills the arithmetic and leaves the string oracle; a firewall rule on .replace( does the reverse.
//
// The answer is deliberately not a substring of the expression that computes it, which is what
// makes an echo unable to satisfy the rule. This test asserts that property of the PAYLOAD as well
// as the behaviour of the route, because if it ever stopped holding the guard would start
// suppressing real hits.
func TestTheStringOracleResolvesAMethodAndTheAnswerIsNotInTheExpression(t *testing.T) {
	const expression = `'qmkvbnkw'.replace('k','7')`
	if strings.Contains(expression, "qm7vbn7w") {
		t.Fatal("the expression contains its own answer, so an echoing endpoint would satisfy the " +
			"rule and the string arm would fire on every reflection in the corpus")
	}
	body := getValue(t, "/eli", "q", eliTestMarker+"${"+expression+"}").Body.String()
	if !strings.Contains(body, eliTestMarker+"qm7vbn7w") {
		t.Errorf("/eli did not resolve replace(). A method that ran is an expression evaluator and "+
			"not a formatter, and it is the arm that survives a method allow-list. Body:\n%s", body)
	}
	upper := getValue(t, "/eli", "q", eliTestMarker+"${'qmkvbnkw'.toUpperCase()}").Body.String()
	if !strings.Contains(upper, eliTestMarker+"QMKVBNKW") {
		t.Errorf("/eli did not resolve the SECOND method, which is what separates an expression "+
			"evaluator from a message interpolator with a narrow API. Body:\n%s", upper)
	}
}

// THE ERROR ARM IDENTIFIES AS WELL AS DETECTING, which is the only reason it is worth its request:
// it proves the parser was reached and not that anything evaluated.
//
// Each route must name ITS OWN engine and no other. A route that answered a SpEL exception to an
// OGNL payload would hand the operator the wrong sstimap plugin, and a route that named two
// engines would make the dialect label a coin toss.
func TestEachExpressionRouteNamesItsOwnDialectAndNoOther(t *testing.T) {
	for _, row := range []struct {
		route, payload, want string
		forbid               []string
	}{
		{"/eli", "${(1).zqjNoSuchMethod()}", "javax.el.MethodNotFoundException",
			[]string{"SpelEvaluationException", "ognl."}},
		{"/eli", "#{" + eliTestSpelBody + "}", "javax.el.ELException",
			[]string{"SpelParseException", "ognl."}},
		{"/eli/spel", "${(1).zqjNoSuchMethod()}", "org.springframework.expression.spel.SpelEvaluationException",
			[]string{"javax.el.", "ognl."}},
		{"/eli/spel", "%{" + eliTestOgnlBody + "}", "org.springframework.expression.spel.SpelParseException",
			[]string{"javax.el.", "ognl."}},
		{"/eli/ognl", "%{}", "ognl.ExpressionSyntaxException",
			[]string{"javax.el.", "Spel"}},
		{"/eli/ognl", "#{" + eliTestSpelBody + "}", "ognl.ExpressionSyntaxException",
			[]string{"javax.el.", "Spel"}},
	} {
		recorder := getValue(t, row.route, "q", eliTestMarker+row.payload)
		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("%s answered %s with %d, want 500: a refusal that is not an error page is a "+
				"silence, and a silence here is indistinguishable from an endpoint with no parser",
				row.route, row.payload, recorder.Code)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, row.want) {
			t.Errorf("%s answered %s without %q, so the dialect cannot be identified from it:\n%s",
				row.route, row.payload, row.want, body)
		}
		for _, forbidden := range row.forbid {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s answered %s with %q in it as well, so the dialect label is a guess",
					row.route, row.payload, forbidden)
			}
		}
	}
}

// THE MOST VALUABLE NEGATIVE IN THE SET. The same arithmetic in a 64-bit long carries 3800000000
// and never -494967296. An implementation that only looks for the wrapped answer records CLEAN on
// a real long-typed JVM EL sink, and one that accepts either records a finding it cannot support.
//
// The route also has no string method and raises no exception, so the row it produces can only be
// the unwrapped-overflow state: there is nothing else on it for a stronger oracle to pick first.
func TestLongmathAnswersTheUnwrappedSumAndNothingElse(t *testing.T) {
	body := getValue(t, "/eli/longmath", "q", eliTestMarker+"${"+eliTestGeneric+"}").Body.String()
	if !strings.Contains(body, eliTestMarker+eliTestLong) {
		t.Errorf("/eli/longmath did not answer with %s adjacent to the marker:\n%s", eliTestLong, body)
	}
	if strings.Contains(body, eliTestWrapped) {
		t.Errorf("/eli/longmath produced the int32 wrap, which is the whole thing it exists not to do:\n%s", body)
	}
	for _, payload := range []string{`${'qmkvbnkw'.replace('k','7')}`, `${(1).zqjNoSuchMethod()}`, "%{}"} {
		recorder := getValue(t, "/eli/longmath", "q", eliTestMarker+payload)
		if recorder.Code != http.StatusOK {
			t.Errorf("/eli/longmath answered %s with %d. It must stay quiet: an exception here would "+
				"outrank the unwrapped state in the class's own ordering and the route would stop "+
				"testing the thing it is for", payload, recorder.Code)
		}
		if strings.Contains(recorder.Body.String(), "qm7vbn7w") {
			t.Error("/eli/longmath resolved a string method. The string arm would then fire and be " +
				"promoted to a finding, on the one route whose verdict must be suspicious")
		}
	}
}

// THE ROUTE THAT PROVES THE CLASS CAN REACH A LEGITIMATE CLEAN AT ALL, which is the half a
// fire-only rig never tests. The marker comes back, so the slot demonstrably reflects and the
// oracles are demonstrably not blind; the expression comes back unevaluated, so every arm is
// silent for the right reason.
func TestTheHardenedRouteReflectsAndEvaluatesNothing(t *testing.T) {
	body := getValue(t, "/eli/hardened", "q", eliTestMarker+"${"+eliTestGeneric+"}").Body.String()
	if !strings.Contains(body, eliTestMarker) {
		t.Errorf("the marker did not come back, so this route reads as no_reflection and the class "+
			"is entitled to say cannot_determine instead of clean:\n%s", body)
	}
	for _, answer := range []string{eliTestWrapped, eliTestLong, "qm7vbn7w", "QMKVBNKW"} {
		if strings.Contains(body, answer) {
			t.Errorf("the hardened route produced %q, so it is not a clean control at all", answer)
		}
	}
	for _, phrase := range []string{"javax.el", "Spel", "ognl.", "Struts"} {
		if strings.Contains(body, phrase) {
			t.Errorf("the hardened route carries %q, which the error arm would read as a finding", phrase)
		}
	}
}

// THE GUARD'S ROUTE. Three negative controls send the ANSWERS as literal text. Reflected verbatim
// they land exactly where a computed answer would, so the adjacency rule WILL match and only the
// answer-not-in-what-was-sent subtraction suppresses it. This route verifies the GUARD, and the
// guard is what stops every echoing endpoint in the world reading as an expression language
// finding.
func TestTheEchoRouteReturnsTheAnswersItWasSentVerbatim(t *testing.T) {
	for _, answer := range []string{eliTestWrapped, "qm7vbn7w", eliTestLong} {
		body := getValue(t, "/eli/echo", "q", eliTestMarker+answer).Body.String()
		if body != eliTestMarker+answer {
			t.Errorf("/eli/echo returned %q for %q. The control only tests the guard if the bytes "+
				"come back as the bytes, marker adjacent to answer", body, eliTestMarker+answer)
		}
	}
	if body := getValue(t, "/eli/echo", "q", eliTestMarker+"${"+eliTestGeneric+"}").Body.String(); strings.Contains(body, eliTestWrapped) {
		t.Errorf("/eli/echo evaluated something. It is a reflection and reflection is not injection:\n%s", body)
	}
}

// struts.devMode=true prints a Problem Report on EVERY request, the baseline included. Without
// baseline differencing per signature this class reports a finding on every slot of every such
// application forever.
//
// The route carries that one phrase and NO OTHER OGNL phrase, which is what makes it a test of
// the subtraction rather than of the signature list: a class that subtracts per response and one
// that subtracts per signature both stay silent here, and the difference between them is caught
// by the class's own unit tests. What this route catches is the class that subtracts nothing.
func TestDevmodeCarriesItsSignatureOnTheBaselineAndCarriesNoOther(t *testing.T) {
	baseline := get(t, "/eli/devmode").Body.String()
	if !strings.Contains(baseline, "Struts Problem Report") {
		t.Fatalf("the unperturbed response does not carry the signature, so there is nothing for a "+
			"detector to subtract and the route tests nothing:\n%s", baseline)
	}
	probed := getValue(t, "/eli/devmode", "q", eliTestMarker+"${"+eliTestGeneric+"}").Body.String()
	for _, phrase := range []string{"OgnlException", "MethodFailedException", "NoSuchPropertyException",
		"ExpressionSyntaxException", eliTestWrapped} {
		if strings.Contains(probed, phrase) {
			t.Errorf("the devMode route answered a payload with %q. It must carry ONE signature and "+
				"that signature must be in the baseline, or the route stops being a test of the "+
				"subtraction and becomes a second positive", phrase)
		}
	}
}

// THE HEADER AND COOKIE PATHS, which CATALOGUE 6.1 asks for by name on the OGNL route because the
// percent-encoding rule is this class's likeliest silent failure and these are the two slots that
// do not depend on the query encoder getting it right.
//
// A route that read only the query would answer a header probe with the SAME page it answers an
// unperturbed request with, and the slot would be recorded as tested when nothing reached it.
func TestTheExpressionRoutesReadAHeaderAndACookieSlot(t *testing.T) {
	for _, row := range []struct{ name, header, cookie string }{
		{"header", "Referer", ""},
		{"cookie", "", "session"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/eli/ognl", nil)
		value := eliTestMarker + "%{" + eliTestOgnlBody + "}"
		if row.header != "" {
			request.Header.Set(row.header, value)
		} else {
			request.AddCookie(&http.Cookie{Name: row.cookie, Value: value})
		}
		recorder := httptest.NewRecorder()
		newMux().ServeHTTP(recorder, request)
		if !strings.Contains(recorder.Body.String(), eliTestMarker+eliTestWrapped) {
			t.Errorf("a probe delivered in the %s slot was not evaluated, so that slot answers the "+
				"same page whether it was probed or not:\n%s", row.name, recorder.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------------------------
// NOSQL
// ---------------------------------------------------------------------------------------------

const nosqlTestMarker = "zqjnos5x00000275"

func postJSON(t *testing.T, route, body string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, http.MethodPost, route, body)
}

// nosqlRowCount reads the array length the class's widening oracle counts. It counts ROWS and
// never bytes, and so does this helper, for the same reason: a body that grew could have grown
// because a row was added, because an error string was added or because a banner changed.
func nosqlRowCount(t *testing.T, recorder *httptest.ResponseRecorder) int {
	t.Helper()
	var parsed struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("the response is not JSON with a rows array, so the widening oracle has nothing to "+
			"count and the honest verdict on a positive control is cannot_determine: %v\n%s",
			err, recorder.Body.String())
	}
	return len(parsed.Rows)
}

// OPERATOR INJECTION, MEASURED IN ROWS. The response has to be a JSON ARRAY: an endpoint that
// returns one object per query widens invisibly and the cardinality oracle has nothing to count.
func TestOperatorInjectionMovesTheRowCount(t *testing.T) {
	baseline := nosqlRowCount(t, postJSON(t, "/nosqli/mongo", `{"name":"hello"}`))
	if baseline != 1 {
		t.Fatalf("the unperturbed filter returned %d rows, want 1. A widening differential is only "+
			"observable when the baseline returns something for the false arm to take away", baseline)
	}
	for _, row := range []struct {
		name, filter string
		want         int
	}{
		{"the parse control, semantically identical to the observed value", `{"name":{"$eq":"hello"}}`, 1},
		{"$ne with a junk argument, the widening differential", `{"name":{"$ne":"` + nosqlTestMarker + `"}}`, 4},
		{"$gt on the empty string, the second widening path", `{"name":{"$gt":""}}`, 4},
		{"an array, which the raw driver matches as an array", `{"name":["hello"]}`, 0},
		{"a bare number, the benign-type control", `{"name":8123}`, 0},
	} {
		if got := nosqlRowCount(t, postJSON(t, "/nosqli/mongo", row.filter)); got != row.want {
			t.Errorf("%s: %s returned %d rows, want %d", row.name, row.filter, got, row.want)
		}
	}
}

// THE ERROR CONTROL. The operator name IS this run's marker, so nothing on earth but this payload
// could have produced the sentence, and the engine answering by name proves the object reached
// the query as an object.
//
// "unknown TOP LEVEL operator" is a DIFFERENT SENTENCE from "unknown operator", and the difference
// is what tells the operator whether the whole document reaches the query or only one field of it.
// A route that answered the same phrase to both would collapse two verdicts into one.
func TestTheEngineNamesTheUnknownOperatorAndFieldDiffersFromRoot(t *testing.T) {
	field := postJSON(t, "/nosqli/mongo", `{"name":{"$`+nosqlTestMarker+`":1}}`).Body.String()
	if !strings.Contains(field, "unknown operator: $"+nosqlTestMarker) {
		t.Errorf("the field-level unknown operator was not named back:\n%s", field)
	}
	root := postJSON(t, "/nosqli/mongo", `{"name":"hello","$`+nosqlTestMarker+`":[1]}`).Body.String()
	if !strings.Contains(root, "unknown top level operator: $"+nosqlTestMarker) {
		t.Errorf("the root-level operator produced no top-level sentence:\n%s", root)
	}
	if strings.Contains(field, "top level") {
		t.Errorf("the field-level answer claims the filter root, which is the more serious of the "+
			"two verdicts and would be reported on evidence that does not support it:\n%s", field)
	}
	expr := postJSON(t, "/nosqli/mongo", `{"name":"hello","$expr":{"$`+nosqlTestMarker+`":[1,2]}}`).Body.String()
	if !strings.Contains(expr, "Unrecognized expression '$"+nosqlTestMarker+"'") {
		t.Errorf("the aggregation expression parser, which is a THIRD code path below the match "+
			"parser, produced nothing:\n%s", expr)
	}
}

// THE STRONGEST ORACLE IN THE CLASS, AND THE ONE THAT HAS TO SURVIVE THE COMMONEST HARDENING.
// $expr asks the server to compute 8123*7 and compare it with a constant: the true arm is true of
// every document and the false twin, one byte different, is true of none. It is a computation the
// server performed rather than a difference anybody interpreted, and it works with server-side
// scripting disabled, which kills every $where oracle there is.
func TestExprArithmeticEvaluatesWithAndWithoutScripting(t *testing.T) {
	for _, route := range []string{"/nosqli/mongo", "/nosqli/noscripting"} {
		truthy := nosqlRowCount(t, postJSON(t, route,
			`{"name":"hello","$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}`))
		falsy := nosqlRowCount(t, postJSON(t, route,
			`{"name":"hello","$expr":{"$eq":[{"$multiply":[8123,7]},56862]}}`))
		if truthy == falsy {
			t.Errorf("%s answered both arms of the arithmetic pair with %d rows. The server did not "+
				"compute anything and the class's tier-1 oracle has no positive control", route, truthy)
		}
		if falsy != 0 {
			t.Errorf("%s answered the FALSE twin with %d rows, want 0. A true arm whose false arm "+
				"also moves is a detector nobody has watched stay silent", route, falsy)
		}
	}
}

// SCRIPTING DISABLED IS A NAMED DEFENCE AND NOT A SILENCE, and that distinction is worth more to
// an operator than a clean: the $where string DID reach the engine, which means the sink is real
// and the effort belongs on the $expr arm.
func TestScriptingDisabledRefusesWhereInTheEnginesOwnWords(t *testing.T) {
	refused := postJSON(t, "/nosqli/noscripting", `{"name":"hello","$where":"1"}`).Body.String()
	if !strings.Contains(refused, "no globalScriptEngine") {
		t.Errorf("the hardened route did not refuse $where by name, so the class cannot tell a "+
			"defence from an endpoint that never parsed the key:\n%s", refused)
	}
	ran := postJSON(t, "/nosqli/mongo",
		`{"name":"hello","$where":"throw new Error('`+nosqlTestMarker+`'+(8123*7))"}`).Body.String()
	if strings.Contains(ran, "no globalScriptEngine") {
		t.Errorf("the route with scripting ON also refused it, so the pair proves nothing:\n%s", ran)
	}
	if !strings.Contains(ran, nosqlTestMarker+"56861") {
		t.Errorf("the route with scripting on did not run the predicate:\n%s", ran)
	}
}

// THE CONCATENATED $where, which needs no object and is therefore the only arm a path segment, a
// plain cookie or a query slot with no bracket encoder can reach. It is, today, the one NoSQL
// surface the class can exercise end to end.
//
// THE HIT IS THE MARKER GLUED TO THE PRODUCT WITH NO BYTE IN BETWEEN. That is the one shape an
// echo of the payload cannot produce: an echo shows the quote, the plus and the parenthesis. This
// test asserts the gluing, not merely the presence of both strings.
func TestTheConcatenatedWhereGluesTheMarkerToTheProduct(t *testing.T) {
	thrown := getValue(t, "/nosqli/where", "q",
		`hello' && (function(){throw new Error('`+nosqlTestMarker+`'+(8123*7))})() && 'a'=='a`).Body.String()
	if !strings.Contains(thrown, nosqlTestMarker+"56861") {
		t.Errorf("the server did not concatenate the marker with a product it computed:\n%s", thrown)
	}
	if strings.Contains(thrown, nosqlTestMarker+"'+(8123*7)") {
		t.Error("the response is an ECHO of the payload rather than the result of evaluating it, " +
			"which is exactly the false positive the glued-bytes rule refuses")
	}

	baseline := nosqlRowCount(t, getValue(t, "/nosqli/where", "q", "hello"))
	truthy := nosqlRowCount(t, getValue(t, "/nosqli/where", "q", `hello' && 8123*7==56861 && 'a'=='a`))
	falsy := nosqlRowCount(t, getValue(t, "/nosqli/where", "q", `hello' && 8123*7==56862 && 'a'=='a`))
	if truthy != baseline || falsy == truthy {
		t.Errorf("the concatenated predicate did not behave like an evaluated boolean: baseline %d, "+
			"true arm %d, false arm %d", baseline, truthy, falsy)
	}

	// THE REPAIR CONTROL DECIDES WHETHER THE DIFFERENTIAL MAY BE GRADED AT ALL. An escaped quote
	// must make any syntax error go away; if it does not, something other than the quote is
	// breaking the endpoint and no differential here can be attributed to the predicate.
	repaired := getValue(t, "/nosqli/where", "q", `hello`+nosqlTestMarker+`\'`)
	if repaired.Code != http.StatusOK {
		t.Errorf("the repair control answered %d. An escaped quote is inert and a route that errors "+
			"on it turns every N-JS verdict on this slot into detector_unverified", repaired.Code)
	}
	if strings.Contains(repaired.Body.String(), "MongoServerError") {
		t.Errorf("the repair control produced an engine error:\n%s", repaired.Body.String())
	}
}

// THE LUCENE SURFACE. An unbalanced quote yields a parse error that REFLECTS THE ASSEMBLED QUERY,
// which is what turns a bare parse failure into an attributable one: the marker rides in front of
// the quote precisely so that it lands inside that reflection.
func TestTheLuceneBreakReflectsTheAssembledQueryAndTheRepairIsInert(t *testing.T) {
	broken := getValue(t, "/nosqli/lucene", "q", "hello"+nosqlTestMarker+`"`)
	body := broken.Body.String()
	for _, want := range []string{"query_shard_exception", "Failed to parse query [", nosqlTestMarker} {
		if !strings.Contains(body, want) {
			t.Errorf("the break is missing %q, so it is neither an engine identification nor "+
				"attributable to this probe:\n%s", want, body)
		}
	}
	repaired := getValue(t, "/nosqli/lucene", "q", "hello"+nosqlTestMarker+`\"`)
	if repaired.Code != http.StatusOK || strings.Contains(repaired.Body.String(), "query_shard_exception") {
		t.Errorf("the escaped quote errored too (%d), so whatever is breaking is not my quote and "+
			"the break cannot be attributed to the payload:\n%s", repaired.Code, repaired.Body.String())
	}
}

// THE CONTROL THAT STOPS THIS CLASS CALLING EVERY VALIDATOR AN INJECTION. A bare number carries no
// dollar, is not an operator and cannot trip a NoSQL parser, so a rejection it SHARES with the
// operator probe came from the validator and the finding is dead. Same status, same sentence, or
// the discriminator does not work.
func TestTheSchemaValidatorRefusesTheOperatorAndTheBenignTypesIdentically(t *testing.T) {
	operator := postJSON(t, "/nosqli/strict", `{"name":{"$`+nosqlTestMarker+`":1}}`)
	for _, benign := range []string{`{"name":8123}`, `{"name":null}`} {
		control := postJSON(t, "/nosqli/strict", benign)
		if control.Code != operator.Code {
			t.Errorf("%s was answered %d and the operator probe %d. The benign-type control only "+
				"kills the false positive when the two are answered the same way",
				benign, control.Code, operator.Code)
		}
		if control.Body.String() != operator.Body.String() {
			t.Errorf("%s and the operator probe produced different bodies:\n%s\n%s",
				benign, control.Body.String(), operator.Body.String())
		}
	}
	if !strings.Contains(operator.Body.String(), "must be string") {
		t.Errorf("the refusal does not talk like a schema validator, so the class cannot tell it "+
			"from an engine error:\n%s", operator.Body.String())
	}
	for _, phrase := range []string{"MongoServerError", "unknown operator", "query_shard_exception"} {
		if strings.Contains(operator.Body.String(), phrase) {
			t.Errorf("the validator's refusal carries %q, which is an ENGINE phrase, and the class "+
				"would read a validator as a database that parsed the object", phrase)
		}
	}
}

// THE FAIL-CLOSED ON A MISSING PARAMETER, WHICH IS A MEASUREMENT AND NOT A STYLE CHOICE.
//
// The runner's name-slot encoder renders an object probe by replacing the parameter NAME with the
// raw JSON, so ?q=hello becomes {"$ne":"<marker>"}=hello and q is GONE. An application that built
// find({name: req.query.q}) would drop the undefined key and return every row, and the class would
// then observe a widening produced by nothing but the encoder deleting the parameter. That is a
// finding manufactured out of a runner defect, and refusing the request instead is the one answer
// that cannot be mistaken for evidence.
func TestAMissingParameterIsRefusedRatherThanAnsweredWithEveryRow(t *testing.T) {
	for _, route := range []string{"/nosqli/mongo", "/nosqli/noscripting", "/nosqli/where", "/nosqli/lucene", "/nosqli/strict"} {
		recorder := get(t, route+"?"+url.QueryEscape(`{"$ne":"`+nosqlTestMarker+`"}`)+"=hello")
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s answered a request whose only parameter is a name-slotted object with %d. "+
				"If that is a 200 carrying every row, the widening oracle reports a finding on an "+
				"encoder defect", route, recorder.Code)
		}
		if count := strings.Count(recorder.Body.String(), `"name"`); count > 0 {
			t.Errorf("%s returned %d rows for a request that carries no filter at all", route, count)
		}
	}
}

// THE IDENTIFIER CONTEXTS, AND THE ESCAPE THAT MAKES THEM READABLE.
//
// MEASURED DEFECT, 2026-09-18: both routes broke on the mere PRESENCE of their delimiter, so the
// break payload and its DOUBLED control got the identical error page. By the class's own rule an
// identical answer to both means the delimiter never reached the parser, which reads as
// metachar_not_delivered, and the one bracket context and the one backtick context in this
// framework each resolved to cannot_determine on a route built to be a positive.
//
// A real engine consumes the doubled form as an ESCAPE. The two payloads then reach two different
// answers: a syntax error for the lone delimiter and an unknown-column error for the escaped one,
// both of which this class already whitelists, and only with both does the pair resolve.
func TestTheDoubledDelimiterIsAnEscapeAndNotABreak(t *testing.T) {
	for _, row := range []struct {
		route, breakValue, controlValue, breakPhrase, controlPhrase string
	}{
		{"/sqli/mssql", "hello]" + eliTestMarker + "[", "hello]]" + eliTestMarker,
			"Incorrect syntax near", "Invalid column name"},
		{"/sqli/mysql", "hello`" + eliTestMarker + "`", "hello``" + eliTestMarker,
			"right syntax to use near", "Unknown column"},
	} {
		broken := getValue(t, row.route, "sort", row.breakValue)
		control := getValue(t, row.route, "sort", row.controlValue)
		if broken.Body.String() == control.Body.String() {
			t.Errorf("%s answered the break and its doubled control identically. That is the class's "+
				"own definition of the delimiter never having reached the parser, and the pair "+
				"resolves to cannot_determine on a positive control", row.route)
		}
		if !strings.Contains(broken.Body.String(), row.breakPhrase) {
			t.Errorf("%s did not answer the lone delimiter with %q:\n%s", row.route, row.breakPhrase,
				broken.Body.String())
		}
		if !strings.Contains(control.Body.String(), row.controlPhrase) {
			t.Errorf("%s did not answer the DOUBLED delimiter with %q. A real engine consumes the "+
				"doubled form as an escape and then fails to resolve the identifier, which is the "+
				"identifier-context signal this class reads:\n%s", row.route, row.controlPhrase,
				control.Body.String())
		}
		if !strings.Contains(control.Body.String(), eliTestMarker) {
			t.Errorf("%s answered the doubled control without naming the marker back, so the answer "+
				"is not attributable to this probe", row.route)
		}
		if code := getValue(t, row.route, "sort", "hello").Code; code != http.StatusOK {
			t.Errorf("%s answered a delimiter-free value with %d, so the route control is not a "+
				"healthy baseline and every differential on it is measured against an error page",
				row.route, code)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// CLIENT-SIDE TEMPLATE INJECTION, THE SILENT HALF
//
// A CSTI finding is a browser observation and no HTTP route can produce one; /csti/angular and
// the emulated engine beside it were already the whole of what the browser tier needs. What had
// no route at all was every NEGATIVE, and those are the rows that tell a working detector from
// one hardwired to return true.
// ---------------------------------------------------------------------------------------------

const (
	cstiTestHTTPProduct    = "49660049" // 7919*6271, the HTTP pair
	cstiTestBrowserProduct = "49088107" // 7793*6299, the browser pair
)

// THE ONE CSTI ROW AN ORACLE WITH NO BROWSER CAN MAKE MOVE, and the one thing that must never be
// reported as client-side template injection: the SERVER rendered it. An AngularJS application
// served from a Jinja2 template is one of the commonest stacks there is, and a class that read
// its own product out of the HTTP body would name the wrong class, the wrong tool and the wrong
// fix.
func TestTheServerSideTemplateRouteEvaluatesBeforeTheBrowserEverSeesIt(t *testing.T) {
	rendered := getValue(t, "/csti/jinja", "q", "{{7919*6271}}").Body.String()
	if !strings.Contains(rendered, cstiTestHTTPProduct) {
		t.Errorf("/csti/jinja did not evaluate the mustache server-side, so the hand-off rule has no "+
			"control anywhere and a server-rendered product cannot be told from a client-rendered "+
			"one:\n%s", rendered)
	}
	if strings.Contains(rendered, "{{") {
		t.Error("/csti/jinja returned the delimiters as well as the product, so the response is an " +
			"echo and not a render")
	}
	client := getValue(t, "/csti/angular", "q", "{{7919*6271}}").Body.String()
	if strings.Contains(client, cstiTestHTTPProduct) {
		t.Errorf("/csti/angular evaluated the mustache SERVER-side. It is the client-side control: "+
			"its whole point is that the HTTP response looks safe:\n%s", client)
	}
}

// EACH NEGATIVE IS SILENT FOR A DIFFERENT REASON, AND THE REASON IS WHAT IS BEING TESTED. A row
// that says clean where the truth is "the payload never arrived" has told the operator a slot is
// safe when nothing was measured, and that is the expensive error: a false positive costs a
// scanner run, a false negative means the tool is never pointed there again.
func TestEachClientTemplateNegativeCarriesItsOwnNamedReason(t *testing.T) {
	for _, row := range []struct {
		route, value string
		want, forbid []string
	}{
		{"/csti/escaped", "{{7919*6271}}",
			[]string{"7919*6271", "ng-app"}, []string{"{{", "}}", cstiTestHTTPProduct}},
		{"/csti/nonbindable", "{{7919*6271}}",
			[]string{"ng-non-bindable", "{{7919*6271}}"}, []string{cstiTestHTTPProduct}},
		{"/csti/inscript", "{{7919*6271}}",
			[]string{"<script>var lastQuery", "{{7919*6271}}"}, []string{cstiTestHTTPProduct}},
		{"/csti/product-in-baseline", "hello",
			[]string{cstiTestBrowserProduct, "ng-app"}, []string{"{{"}},
		{"/csti/aot", "{{7919*6271}}",
			[]string{"ng-version=", "_ngcontent-"}, []string{"ng-app", cstiTestHTTPProduct}},
		{"/csti/vue-runtime", "{{7919*6271}}",
			[]string{"runtime compilation is not supported"}, []string{cstiTestHTTPProduct}},
		{"/csti/corpus-blocked", "{{7919*6271}}",
			[]string{"/csti/blocked.js"}, []string{cstiTestHTTPProduct}},
	} {
		body := getValue(t, row.route, "q", row.value).Body.String()
		for _, want := range row.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q, which is the signal a detector reads to reach its named "+
					"reason on this route:\n%s", row.route, want, body)
			}
		}
		for _, forbidden := range row.forbid {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s carries %q, which contradicts the reason the route exists for", row.route, forbidden)
			}
		}
	}
	if code := get(t, "/csti/blocked.js").Code; code != http.StatusForbidden {
		t.Errorf("the blocked script answered %d, want 403. The framework has to be UNDETERMINED "+
			"there, and a readable script determines it", code)
	}
}

// THE VALUE THAT WAS NEVER PERCENT-DECODED. The braces come back as %7B and %7D, so no engine
// anywhere will compile them: the delimiters were not delivered, nothing was tested, and the
// answer is cannot_determine rather than clean.
func TestThePercentLiteralRouteNeverDecodesTheDelimiters(t *testing.T) {
	body := getValue(t, "/csti/pct-literal", "q", "{{7919*6271}}").Body.String()
	if !strings.Contains(body, "%7B%7B") {
		t.Errorf("the percent-encoded braces did not come back as text, so this route does not test "+
			"the undelivered-delimiter case at all:\n%s", body)
	}
	if strings.Contains(body, "{{") {
		t.Errorf("a raw brace came back, so the value WAS decoded and the route is a second copy of "+
			"/csti/angular:\n%s", body)
	}
}

// WITHOUT THIS ROUTE A CALCULATOR IS A CSTI FINDING. The application multiplies the two numbers
// itself, so the product appears for the probe AND for the negative control. The observation is
// real and it is evidence of nothing, which is what cannot_determine (control_contaminated) is
// for.
func TestTheCalculatorRouteContaminatesItsOwnControl(t *testing.T) {
	probe := getValue(t, "/csti/calculator", "q", "{{7919*6271}}").Body.String()
	control := getValue(t, "/csti/calculator", "q", "7919*6271").Body.String()
	if !strings.Contains(probe, cstiTestHTTPProduct) || !strings.Contains(control, cstiTestHTTPProduct) {
		t.Errorf("the product has to appear for BOTH the delimited probe and the bare control, or "+
			"the control is not contaminated and the route tests nothing.\nprobe:\n%s\ncontrol:\n%s",
			probe, control)
	}
	if strings.Contains(getValue(t, "/csti/calculator", "q", "hello").Body.String(), cstiTestHTTPProduct) {
		t.Error("the route prints the product for a value that contains no arithmetic, so it is a " +
			"product-in-baseline route and not a calculator")
	}
}

// BRACES STRIPPED FROM TEXT, ATTRIBUTE VALUES UNFILTERED: the mustache route closed and the
// directive route wide open, which is the commonest real shape of this bug.
//
// The route must let the attribute probe CREATE an attribute and must not let anything open a
// tag. A page that allowed both would be a markup-injection positive as well, two classes would
// fire on it, and neither result would mean anything.
func TestTheAttributeRouteCreatesAnAttributeAndNeverATag(t *testing.T) {
	body := getValue(t, "/csti/angular-attr", "q", `" csti0q="1`).Body.String()
	if !strings.Contains(body, `csti0q="1"`) {
		t.Errorf("the attribute probe could not create its attribute, so silence from the directive "+
			"probes here is four hypotheses wearing one observation:\n%s", body)
	}
	tagged := getValue(t, "/csti/angular-attr", "q", `"><svg onload=x>`).Body.String()
	if strings.Contains(tagged, "<svg") {
		t.Errorf("a tag was opened, so this route is a markup-injection positive as well and no "+
			"result on it belongs to one class:\n%s", tagged)
	}
	if strings.Contains(getValue(t, "/csti/angular-attr", "q", "{{7919*6271}}").Body.String(), "{{") {
		t.Error("the braces survived in TEXT, which is the case /csti/angular already covers; this " +
			"route exists because they do not")
	}
}
