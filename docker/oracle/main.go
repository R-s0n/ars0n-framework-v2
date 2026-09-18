// The canary oracle: a deliberately vulnerable service that exists so a scan reporting nothing can
// be told apart from a scan that tested nothing.
//
// WHY THIS EXISTS. Every scanner in this framework fails open. Handed an argument it does not
// understand, or a session that has died, or a flag it silently ignores, it exits having sent no
// requests and the runner records "clean" for every vector. A clean result and a never-ran result are
// byte-identical in the UI, and clean is the one an operator acts on. On the first target this
// framework was developed against, that produced 53 vectors reported free of SQL injection in forty
// seconds, on an application that demonstrably had SQL injection in it.
//
// The fix is a control. Every scan also tests one target that is KNOWN to be vulnerable. If the tool
// does not find the thing that is definitely there, the run proved nothing and its verdict is
// withheld. That is what this service is for.
//
// WHAT IT DELIBERATELY IS NOT. This is not DVWA and not a training target. It is an instrument, so it
// values determinism over realism: the same request always produces the same response, and every
// endpoint is the simplest thing that the corresponding detector will recognise.
//
// SAFETY. Reflected XSS and the SQL emulation below are genuinely what they claim to be, because
// neither can do anything except to a client that asked for it. Command injection, file inclusion and
// template injection are EMULATED rather than implemented: /cmdi understands sleep and echo and
// nothing else, /lfi serves fixed strings from a map, and /ssti rewrites two integers and an operator
// with no template library anywhere in the image. Shipping a real remote code execution into an
// operator's docker network in order to test a scanner would be trading a large real risk for a small
// measurement, and the detectors cannot tell the difference anyway, which is the whole point of a
// control.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// canaryMarker appears in every vulnerable response and nowhere else. It is what the framework greps
// for when deciding whether a tool actually reached this service, and it is deliberately unusual
// enough that it cannot appear by chance in a target's own output.
const canaryMarker = "ARS0N_CANARY_OK"

func main() {
	addr := ":" + envOr("ORACLE_PORT", "8000")
	log.Printf("canary oracle listening on %s", addr)
	log.Fatal((&http.Server{
		Addr:              addr,
		Handler:           newMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}).ListenAndServe())
}

// newMux builds the routing table. It is a function rather than inline in main so that the tests can
// drive REQUESTS THROUGH THE MUX rather than calling handlers directly.
//
// That distinction is the whole bug this file's header describes. Go's ServeMux treats "/" as a
// catch-all, so a path with no handler answers 200 with the index page instead of 404, and a test
// that calls cleanNoisyHandler directly would pass on a build where "/clean/noisy" was never
// registered. On 2026-08-23 exactly that inverted the meaning of three controls. Every route test in
// main_test.go goes through newMux() and asserts the X-Ars0n-Oracle header, which an index
// fallthrough cannot carry.
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	// Every REAL control surface is marked. Go's ServeMux treats "/" as a catch-all, so an oracle
	// build that predates a handler still answers 200 at that path with the index page.
	//
	// That is not hypothetical and it inverted the meaning of three controls at once. On 2026-08-23
	// the running image was built on 2026-08-21 and served no /ssti; SSTImap and TInjA fired their
	// controls at it, got the index page, found no template injection in it, and the operator was told
	// THE SCANNER had found nothing. A positive control exists to answer "does this tool work", so a
	// stale oracle silently converts that answer to "every tool is broken".
	//
	// The header is what the framework checks. An index fallthrough cannot carry it, so
	// "serves /ssti" and "serves something at /ssti" stop being the same observation.
	marked := func(name string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Ars0n-Oracle", name)
			h(w, r)
		}
	}
	mux.HandleFunc("/xss", marked("xss", xssHandler))
	mux.HandleFunc("/sqli", marked("sqli", sqliHandler))
	mux.HandleFunc("/redirect", marked("redirect", redirectHandler))
	mux.HandleFunc("/lfi", marked("lfi", lfiHandler))
	mux.HandleFunc("/cmdi", marked("cmdi", cmdiHandler))
	mux.HandleFunc("/ssti", marked("ssti", sstiHandler))

	registerCleanControls(mux, marked)
	registerExtraPositives(mux, marked)
	registerNamedControls(mux, marked)
	registerELIControls(mux, marked)
	registerNoSQLControls(mux, marked)
	registerCSTIControls(mux, marked)

	return mux
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>canary oracle</title>
<h1>Canary oracle</h1>
<p>Deliberately vulnerable control target. Not a real application. Every endpoint below is a known
positive so that a scanner finding nothing here can be reported as broken rather than as clean.</p>
<ul>
<li><a href="/xss?q=hello">/xss?q=</a> reflected, unencoded, in HTML and in a script string</li>
<li><a href="/sqli?id=1">/sqli?id=</a> boolean, error and time differentials</li>
<li><a href="/redirect?next=/">/redirect?next=</a> unvalidated Location</li>
<li><a href="/lfi?file=readme">/lfi?file=</a> emulated traversal</li>
<li><a href="/cmdi?cmd=localhost">/cmdi?cmd=</a> emulated shell, sleep and echo only</li>
<li><a href="/ssti?tpl=hello">/ssti?tpl=</a> emulated template rendering, ${...} only</li>
<li><a href="/sqli/mssql?sort=name">/sqli/mssql?sort=</a> bracketed identifier, only ] breaks it</li>
<li><a href="/sqli/mysql?sort=name">/sqli/mysql?sort=</a> backtick identifier, only `+"`"+` breaks it</li>
<li>/sqli/json POST {"id":"1"}, a raw " is a JSON parse error and a ' reaches SQL</li>
<li><a href="/csti/angular?q=hello">/csti/angular?q=</a> emulated client-side template engine</li>
<li><a href="/eli?q=hello">/eli?q=</a> emulated JVM expression language, int32 arithmetic and two string methods</li>
<li><a href="/eli/spel?q=hello">/eli/spel?q=</a> the same, plus SpEL's T() type operator, and SpEL names itself on a refusal</li>
<li><a href="/eli/ognl?q=hello">/eli/ognl?q=</a> the same, plus OGNL's @class@member through %{ }, over query, header and cookie</li>
<li><a href="/eli/longmath?q=hello">/eli/longmath?q=</a> the identical arithmetic in a 64-bit long: 3800000000 and never the int32 wrap</li>
<li><a href="/nosqli/mongo?q=hello">/nosqli/mongo?q=</a> find() over four documents, operator objects honoured, rows[] to count</li>
<li><a href="/nosqli/noscripting?q=hello">/nosqli/noscripting?q=</a> the same with server-side JavaScript off: $where refused, $expr still computes</li>
<li><a href="/nosqli/where?q=hello">/nosqli/where?q=</a> the value concatenated into a $where predicate, path form at /nosqli/where/hello</li>
<li><a href="/nosqli/lucene?q=hello">/nosqli/lucene?q=</a> a query_string surface that reflects the assembled query in its parse error</li>
</ul>
<h2>Clean controls</h2>
<p>These are NOT vulnerable, and none of them carries the canary marker. They exist because a
detector that fires on everything scores full marks against a target where everything is a
positive. Each one is a place a detector must stay SILENT, and each is silent for a different
reason, so the reason is what is being tested. Reachability here is proved by the X-Ars0n-Oracle
response header, not by anything in the body.</p>
<ul>
<li><a href="/clean/noisy">/clean/noisy</a> never byte-identical to itself, input-independent</li>
<li><a href="/clean/drift">/clean/drift</a> stable between adjacent calls, changes every 8 requests</li>
<li><a href="/clean/dberror">/clean/dberror</a> a PSQLException on every response, baseline included</li>
<li><a href="/clean/mongoprose">/clean/mongoprose</a> MongoServerError in the baseline footer</li>
<li><a href="/clean/versionprose">/clean/versionprose</a> names ImageMagick 7.1.1 in every footer</li>
<li><a href="/clean/passwddoc">/clean/passwddoc</a> root:x:0:0 in a documentation pre block</li>
<li><a href="/clean/b64noise">/clean/b64noise</a> a JWT and a PNG data URI, decoding to nothing</li>
<li><a href="/clean/echoparser?id=1">/clean/echoparser?id=</a> echo, then the SQL phrase 200 bytes away</li>
<li><a href="/clean/intcast?id=1">/clean/intcast?id=</a> parses an int, discards the tail: casted, not clean</li>
<li><a href="/clean/validate?id=1">/clean/validate?id=</a> 400 on any metacharacter: not a SQL error</li>
<li><a href="/clean/waf?id=1">/clean/waf?id=</a> identical 403 block page for every class</li>
<li><a href="/clean/always500">/clean/always500</a> 500 for every input, benign included</li>
<li><a href="/clean/junk?id=1">/clean/junk?id=</a> 500 on any value but the observed one</li>
<li><a href="/clean/inert?id=1">/clean/inert?id=</a> discards the parameter entirely</li>
<li><a href="/clean/echo?q=hello">/clean/echo?q=</a> verbatim reflection, text/plain, no sink</li>
<li><a href="/clean/echomongo">/clean/echomongo</a> POST, echoes the filter into a 400</li>
<li><a href="/clean/spa">/clean/spa</a> the same shell whatever you send</li>
<li><a href="/clean/nonidem">/clean/nonidem</a> POST appends a row, so every response differs</li>
<li><a href="/clean/empty204">/clean/empty204</a> 204, no body</li>
<li><a href="/clean/nothing">/clean/nothing</a> 200, empty body, which is not the same thing</li>
<li><a href="/sqli/blind?id=hello">/sqli/blind?id=</a> errors suppressed, 200 on everything, so only the boolean arm can see it</li>
<li><a href="/sqli/status200?id=1">/sqli/status200?id=</a> the metacharacter-free numeric arm, on a status that never moves</li>
<li><a href="/rfi/inband-include?file=http://x.rfi-inband.invalid/f.txt">/rfi/inband-include?file=</a> a PHP include that names allow_url_include for a remote scheme and not for a relative path</li>
<li><a href="/rfi/inband-reject?file=x.y.invalid/f.txt">/rfi/inband-reject?file=</a> 500s on any dotted host, remote or not: the control that keeps a strict validator from reading as a fetcher</li>
<li><a href="/csti/plain?q=hello">/csti/plain?q=</a> the same page with no template engine</li>
<li><a href="/xss/encoded?q=hello">/xss/encoded?q=</a> htmlspecialchars, and ?json=1 for the JSON form</li>
<li><a href="/xss/entity?q=hello">/xss/entity?q=</a> markup characters entity-encoded, quotes left alone</li>
<li><a href="/eli/hardened?q=hello">/eli/hardened?q=</a> the value reflected with no evaluator behind it: the expression-language clean</li>
<li><a href="/eli/echo?q=hello">/eli/echo?q=</a> verbatim text/plain, where the answers-sent-as-text controls must stay silent</li>
<li><a href="/eli/devmode?q=hello">/eli/devmode?q=</a> a Struts Problem Report in the baseline of every response</li>
<li><a href="/nosqli/strict?q=hello">/nosqli/strict?q=</a> a schema validator refusing an operator and a bare number identically</li>
<li><a href="/csti/jinja?q=hello">/csti/jinja?q=</a> an AngularJS page whose {{ }} is rendered on the SERVER: the class must hand off, never claim it</li>
<li><a href="/csti/escaped?q=hello">/csti/escaped?q=</a> AngularJS, braces stripped with nothing in their place: the client-template clean</li>
<li><a href="/csti/nonbindable?q=hello">/csti/nonbindable?q=</a> the reflection inside ng-non-bindable: a named defence</li>
<li><a href="/csti/inscript?q=hello">/csti/inscript?q=</a> the reflection inside a script, which no client engine compiles</li>
<li><a href="/csti/pct-literal?q=hello">/csti/pct-literal?q=</a> the value echoed without percent-decoding: the delimiters never arrive</li>
<li><a href="/csti/product-in-baseline?q=hello">/csti/product-in-baseline?q=</a> the browser pair's product already on the unperturbed page</li>
<li><a href="/csti/calculator?q=hello">/csti/calculator?q=</a> AngularJS, and the application does the multiplication itself</li>
<li><a href="/csti/aot?q=hello">/csti/aot?q=</a> Angular 17 ahead-of-time compiled: not applicable, at zero requests</li>
<li><a href="/csti/vue-runtime?q=hello">/csti/vue-runtime?q=</a> the runtime-only Vue build, which compiles no in-DOM template</li>
<li><a href="/csti/corpus-blocked?q=hello">/csti/corpus-blocked?q=</a> the only script 403s: undetermined, which is not the same as absent</li>
<li><a href="/csti/angular-attr?q=hello">/csti/angular-attr?q=</a> braces stripped from text, attribute values unfiltered</li>
<li><a href="/csti/angular-hash?q=hello">/csti/angular-hash?q=</a> the fragment rendered client-side, which no HTTP request can carry</li>
</ul>`)
}

// queryParam reads a query parameter from the RAW query string rather than through r.URL.Query().
//
// MEASURED, and it silently blinded the command injection control. Go 1.17 made net/url reject a
// semicolon as a parameter separator: parseQuery sees a ';' anywhere in a key=value pair, records an
// error, and SKIPS THAT PAIR ENTIRELY. r.URL.Query() swallows that error, so
//
//	/cmdi?host=127.0.0.1;echo+hi   ->   host is "" and the oracle answers as though nothing was sent
//
// A semicolon is the first separator every command injection scanner reaches for, so the one endpoint
// whose whole purpose is to look injectable answered "not injectable" to the most common payload
// shape there is. A real vulnerable application in PHP, Python or Node does not drop that parameter,
// and the control has to behave like the application it stands in for rather than like Go.
//
// Splitting on '&' only, and falling back to the raw text when percent-decoding fails, is a superset
// of what Query() returns for every input that does not contain a semicolon, so nothing that worked
// before changes.
func queryParam(r *http.Request, names ...string) string {
	pairs := strings.Split(r.URL.RawQuery, "&")
	for _, name := range names {
		for _, pair := range pairs {
			key, value, _ := strings.Cut(pair, "=")
			decodedKey, err := url.QueryUnescape(key)
			if err != nil {
				decodedKey = key
			}
			if decodedKey != name {
				continue
			}
			decodedValue, err := url.QueryUnescape(value)
			if err != nil {
				// A malformed escape is not a reason to drop the input. A vulnerable application
				// concatenates whatever bytes arrived, and a scanner sending a stray '%' must not be
				// answered as though it sent nothing.
				decodedValue = strings.ReplaceAll(value, "+", " ")
			}
			if decodedValue != "" {
				return decodedValue
			}
		}
	}
	return ""
}

// xssHandler reflects the parameter twice with no encoding at all: once into HTML text where an
// element-based payload fires, and once into a single-quoted JavaScript string literal where a
// string-breaking payload fires. Two contexts because the tools disagree about which they probe, and
// a control that only covers one of them would fail for the wrong reason.
func xssHandler(w http.ResponseWriter, r *http.Request) {
	q := queryParam(r, "q", "search")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>canary</title><!-- %s -->
<div id="out">%s</div>
<script>var searchText = '%s';</script>`, canaryMarker, q, q)
}

var (
	// Recognised well enough to behave correctly, not parsed properly. A real parser would be a worse
	// control: it would start rejecting payloads for reasons a real vulnerable application would not.
	reSleep     = regexp.MustCompile(`(?i)(sleep|pg_sleep|waitfor\s+delay)\s*\(?\s*'?([0-9]{1,2})`)
	reAlwaysT   = regexp.MustCompile(`(?i)(or|and)\s+([0-9]+)\s*=\s*([0-9]+)`)
	reUnionSel  = regexp.MustCompile(`(?i)union\s+(all\s+)?select`)
	reQuoteOdd  = regexp.MustCompile(`'`)
	reCommentSQ = regexp.MustCompile(`(--|#|/\*)`)
)

// sqliHandler emulates a string-concatenated query closely enough for the three techniques these
// scanners rely on, without running a database.
//
// The emulation is honest about what it is. It does not execute SQL; it decides what a vulnerable
// application WOULD have returned, which is the only thing the detector can observe. Boolean-based
// detection compares two responses, error-based looks for a database error page, and time-based
// measures the clock, so those three behaviours are what is reproduced.
func sqliHandler(w http.ResponseWriter, r *http.Request) {
	id := queryParam(r, "id", "category")

	// Time-based: an injected sleep really does sleep, capped hard so this cannot be used to wedge the
	// oracle. Ten seconds is above every default threshold these tools use and low enough to be safe.
	if m := reSleep.FindStringSubmatch(id); m != nil {
		secs, _ := strconv.Atoi(m[2])
		if secs > 10 {
			secs = 10
		}
		time.Sleep(time.Duration(secs) * time.Second)
	}

	// Error-based: an unbalanced quote with no comment to swallow the rest is a broken statement, and a
	// vulnerable application built this way leaks the engine's complaint. Deliberately verbose,
	// deliberately naming a real engine, because signature matchers look for exactly this.
	quotes := len(reQuoteOdd.FindAllString(id, -1))
	if quotes%2 == 1 && !reCommentSQ.MatchString(id) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Database error</h1>
<pre>org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near "'"
  Position: 42
  Query: SELECT name, price FROM products WHERE id = '%s'</pre>`, canaryMarker, id)
		return
	}

	// Boolean-based: the row comes back when the condition is true and does not when it is false. A
	// UNION is treated as true so the extra columns appear, which is what turns a blind finding into a
	// data-returning one.
	//
	// sqlRowVisible replaced an inline `(or|and)\s+(\d+)=(\d+)` match here. That match saw the
	// textbook OR 1=1 and NEITHER of the two forms the framework's own boolean arm sends, so the
	// true arm and the false arm of its own detector produced the same page on every route in this
	// container. It also ANDed nothing: an injected condition overwrote the base predicate outright,
	// so `id=hello' AND 1=1--` returned the row a real engine would not have returned.
	baseValue := sqlLeadingLiteral(id)
	visible, broken := sqlRowVisible(id, baseValue == "" || baseValue == "1")

	// A condition no engine would parse. `AND 28651 28652` is a syntax error on PostgreSQL 18 and
	// MariaDB 11.8.9, and SQL-A3 sends exactly that as its invalid-syntax control: the probe whose
	// whole job is to NOT look like the true arm. Answering it with the ordinary page made it look
	// like the false arm instead, which is the same bytes as the control on this route and reads to
	// d2Confirmed as "the control looks TRUE", disabling the boolean rule outright.
	if broken {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Database error</h1>
<pre>org.postgresql.util.PSQLException: ERROR: syntax error at or near "%s"
  Position: 42
  Query: SELECT name, price FROM products WHERE id = '%s'</pre>`, canaryMarker,
			html.EscapeString(reBrokenCondition.FindString(sqlNormaliseWhitespace(id))),
			html.EscapeString(id))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n", canaryMarker)
	if visible {
		fmt.Fprint(w, `<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>
<p>1 product matched.</p>`)
		return
	}
	fmt.Fprint(w, `<p>0 products matched.</p>`)
}

// =================================================================================================
// WHAT A VULNERABLE ENGINE WOULD MAKE OF AN INJECTED CONDITION
//
// MEASURED DEFECT, 2026-09-18. reAlwaysT is `(or|and)\s+(\d+)\s*=\s*(\d+)`, which matches the
// textbook `OR 1=1` and NEITHER of the two forms the framework's own boolean arm actually sends:
//
//	SQL-A1/A2   ' AND (4093*7)=28651 AND 'a'='a      a parenthesised product, not two integers
//	SQL-A4/A5   +4093-4093                            a value transform, no comparison at all
//
// So every boolean probe in the framework produced the SAME page as its own negation, the
// differential was flat on every route in this container, and the one detector that can see an
// endpoint which suppresses its errors had no positive control anywhere. The fix belongs here and
// not in the class: an oracle that only answers the payloads it happens to match is an oracle that
// grades the scanner on the oracle's vocabulary.
//
// This is still recognition and not a parser. A real SQL parser would be a WORSE control, because
// it would start rejecting payloads for reasons a vulnerable application built by string
// concatenation never would.
// =================================================================================================

var (
	// An inline comment is whitespace to every SQL lexer, which is exactly why SQL-A1w spells its
	// spaces `/**/`: a cookie cannot carry a space. Normalising here means the cookie form and the
	// query form are answered identically, rather than the cookie arm silently testing nothing.
	reInlineComment = regexp.MustCompile(`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/`)

	// The arithmetic comparison. One binary operator, optional parentheses, compared to a
	// constant: `AND (4093*7)=28651`, `OR 100-1=99`.
	reArithCondition = regexp.MustCompile(`(?i)\b(or|and)\s+\(?\s*([0-9]{1,9})\s*([-+*/])\s*([0-9]{1,9})\s*\)?\s*=\s*([0-9]{1,12})\b`)

	// Two integers with no operator between them. `AND 28651 28652` is a syntax error on
	// PostgreSQL 18 and MariaDB 11.8.9, which is the whole reason SQL-A3 is the invalid-syntax
	// control: a route that answered it like the true arm would disable the boolean rule.
	reBrokenCondition = regexp.MustCompile(`(?i)\b(or|and)\s+[0-9]+\s+[0-9]+(\s|$|'|\))`)

	// The whole value is integer arithmetic. This is SQL-A4's shape once it is appended to a
	// digits-only observed value: `1+4093-4093`.
	reNumericExpression = regexp.MustCompile(`^\s*[0-9]{1,9}(\s*[-+]\s*[0-9]{1,9})+\s*$`)
	reNumericTerm       = regexp.MustCompile(`[-+]?\s*[0-9]{1,9}`)
)

// sqlNormaliseWhitespace turns inline comments into the spaces they stand for.
func sqlNormaliseWhitespace(value string) string {
	return reInlineComment.ReplaceAllString(value, " ")
}

// sqlBrokenCondition reports whether the value carries a condition no engine would parse.
func sqlBrokenCondition(value string) bool {
	return reBrokenCondition.MatchString(sqlNormaliseWhitespace(value))
}

// sqlInjectedCondition evaluates the boolean condition appended to the value and names the
// CONNECTIVE that joined it to the base predicate.
//
// THE CONNECTIVE IS NOT DECORATION AND LEAVING IT OUT WAS A SECOND DEFECT HERE. The old inline
// match assigned the condition's truth to the row's visibility outright, so
// `id=hello' AND 1=1--` returned the row on an endpoint where the base predicate selects
// nothing, which is not what any engine does. OR widens and AND narrows, and a control that gets
// that backwards teaches the detector the wrong differential.
//
// ok is false when the value carries no recognisable condition, and the caller must then fall
// back to what the base predicate alone would have returned. "false with ok" and "false without
// ok" are different answers, and collapsing them is how the false arm and an unrecognised payload
// became the same page.
func sqlInjectedCondition(value string) (string, bool, bool) {
	normalised := sqlNormaliseWhitespace(value)
	if reBrokenCondition.MatchString(normalised) {
		return "", false, false
	}
	if m := reArithCondition.FindStringSubmatch(normalised); m != nil {
		left, errLeft := strconv.ParseInt(m[2], 10, 64)
		right, errRight := strconv.ParseInt(m[4], 10, 64)
		want, errWant := strconv.ParseInt(m[5], 10, 64)
		if errLeft != nil || errRight != nil || errWant != nil {
			return "", false, false
		}
		var got int64
		switch m[3] {
		case "+":
			got = left + right
		case "-":
			got = left - right
		case "*":
			got = left * right
		case "/":
			if right == 0 {
				// Division by zero is an engine error, not a false condition, and an oracle that
				// answered it "false" would hand the detector a clean differential for a payload
				// that never evaluated.
				return "", false, false
			}
			got = left / right
		}
		return strings.ToLower(m[1]), got == want, true
	}
	if m := reAlwaysT.FindStringSubmatch(normalised); m != nil {
		return strings.ToLower(m[1]), m[2] == m[3], true
	}
	return "", false, false
}

// sqlInjectedTruth is the condition's own truth value, without the connective.
func sqlInjectedTruth(value string) (bool, bool) {
	_, truth, ok := sqlInjectedCondition(value)
	return truth, ok
}

// sqlLeadingLiteral is the part of the value that stays INSIDE the quoted literal of a
// concatenated statement: everything before the first quote the payload brings.
//
// It is what makes the base predicate answerable at all. In
// WHERE id = 'hello' AND (4093*7)=28651 AND 'a'='a' the engine compares id against `hello`, not
// against the whole payload, so an oracle that looked up the whole payload would find no record
// for every probe, the true arm and the false arm would both return the empty page, and the
// differential the boolean arm exists to produce would be flat on every route in this container.
func sqlLeadingLiteral(value string) string {
	if i := strings.Index(value, "'"); i >= 0 {
		return value[:i]
	}
	return value
}

// sqlNumericValue evaluates a value that is nothing but integer addition and subtraction, which is
// what the numeric arm turns a digits-only parameter into. It carries no metacharacter at all, so
// it is the only probe in the class that survives a quote filter, and an oracle that could not
// evaluate it was blind to the only detector that reaches a filtered endpoint.
func sqlNumericValue(value string) (int64, bool) {
	normalised := sqlNormaliseWhitespace(value)
	if !reNumericExpression.MatchString(normalised) {
		return 0, false
	}
	total := int64(0)
	for _, term := range reNumericTerm.FindAllString(normalised, -1) {
		cleaned := strings.ReplaceAll(strings.ReplaceAll(term, " ", ""), "\t", "")
		n, err := strconv.ParseInt(strings.TrimPrefix(cleaned, "+"), 10, 64)
		if err != nil {
			return 0, false
		}
		total += n
	}
	return total, true
}

// sqlRowVisible is the one decision every SQL control route shares: given the value that arrived
// and what the base predicate alone would have returned, would a vulnerable engine have produced
// the row? broken is true when the statement would not have parsed at all, which the routes that
// show errors turn into a 500 and the route that suppresses them turns into an empty result.
func sqlRowVisible(value string, baseVisible bool) (visible bool, broken bool) {
	if sqlBrokenCondition(value) {
		return false, true
	}
	if connective, truth, ok := sqlInjectedCondition(value); ok {
		if connective == "or" {
			return baseVisible || truth, false
		}
		return baseVisible && truth, false
	}
	if reUnionSel.MatchString(value) {
		return true, false
	}
	if n, ok := sqlNumericValue(value); ok {
		// The id column. 1 is the row that exists; anything else selects nothing.
		return n == 1, false
	}
	return baseVisible, false
}

// redirectHandler sends the browser wherever it is told, to any origin, with no validation.
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := queryParam(r, "next", "url")
	if next == "" {
		next = "/"
	}
	w.Header().Set("Location", next)
	w.Header().Set("X-Canary", canaryMarker)
	w.WriteHeader(http.StatusFound)
	fmt.Fprintf(w, "redirecting to %s", next)
}

// lfiHandler EMULATES traversal. Any path containing a traversal sequence and a recognised filename
// returns that file's canned contents; nothing touches the real filesystem, so this cannot be turned
// into a genuine read of the container.
func lfiHandler(w http.ResponseWriter, r *http.Request) {
	file := queryParam(r, "file", "page")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	canned := map[string]string{
		"passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
			"canary:x:1000:1000:" + canaryMarker + ":/home/canary:/bin/sh\n",
		"hosts":  "127.0.0.1\tlocalhost\n::1\tip6-localhost\n",
		"readme": "canary oracle. " + canaryMarker + "\n",
	}
	lower := strings.ToLower(file)
	for name, body := range canned {
		if strings.Contains(lower, name) {
			fmt.Fprint(w, body)
			return
		}
	}
	fmt.Fprintf(w, "no such document: %s\n", file)
}

// cmdiHandler EMULATES a shell. It understands sleep and echo, which between them cover the two safe
// proofs every command injection detector uses, plus the two EXPANSIONS those proofs are wrapped in.
// It understands nothing else. There is no exec anywhere in this file.
//
// WHY THE EXPANSIONS ARE NOT OPTIONAL, measured against commix 4.2.dev76. Its results-based classic
// technique, which is the only one of its five this emulation can satisfy, does not send a bare
// `echo TAG`. From cb_payloads.py the decision payload is
//
//	;echo TAG$((24+89))$(echo TAG)TAG
//
// and injector.injection_test_results then looks for the regex TAG + str(24+89) + TAG + TAG in the
// body. An emulation that echoes the argument verbatim returns the payload text back, the sum is
// never computed, the regex never matches, and commix reports a target it can trivially inject as
// clean. That is the exact fail-open this whole oracle exists to catch, reproduced inside the
// instrument that was supposed to catch it.
//
// Arithmetic and echo-substitution are pure string rewriting over a closed grammar: two integers and
// one of + - *, or the word echo. Nothing is parsed as a command, nothing is looked up, and an
// unrecognised substitution renders empty exactly as a failed command's stdout would.
func cmdiHandler(w http.ResponseWriter, r *http.Request) {
	host := queryParam(r, "host", "cmd")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Only what follows a shell separator is treated as an injected command, which is what makes this
	// a control for injection rather than a generic command runner.
	injected := ""
	for _, sep := range []string{";", "&&", "|", "&", "`", "$(", "\n"} {
		if i := strings.Index(host, sep); i >= 0 {
			injected = strings.TrimSpace(host[i+len(sep):])
			break
		}
	}
	injected = strings.Trim(injected, "`)\"'")

	fmt.Fprintf(w, "PING %s: 56 data bytes\n", strings.Split(host, " ")[0])
	if injected == "" {
		fmt.Fprintf(w, "1 packets transmitted, 1 received\n%s\n", canaryMarker)
		return
	}
	fields := strings.Fields(injected)
	switch strings.ToLower(fields[0]) {
	case "sleep":
		secs := 0
		if len(fields) > 1 {
			secs, _ = strconv.Atoi(fields[1])
		}
		if secs > 10 {
			secs = 10
		}
		time.Sleep(time.Duration(secs) * time.Second)
	case "echo":
		fmt.Fprintln(w, strings.Trim(expandShellText(strings.Join(fields[1:], " ")), `"'`))
	case "id":
		fmt.Fprintln(w, "uid=1000(canary) gid=1000(canary) groups=1000(canary)")
	case "whoami":
		fmt.Fprintln(w, "canary")
	}
	fmt.Fprintln(w, canaryMarker)
}

var (
	// $((a+b)). Bounded to two operands and ten digits, so this is a lookup table with arithmetic in
	// it rather than an expression evaluator with an attack surface.
	reArithExpansion = regexp.MustCompile(`\$\(\(\s*(-?\d{1,10})\s*([-+*])\s*(-?\d{1,10})\s*\)\)`)
	// $(...) and `...`, with no nesting. commix uses whichever its --use-backticks setting selects.
	reCommandExpansion = regexp.MustCompile("\\$\\(([^()]*)\\)|`([^`]*)`")
)

// expandShellText performs the two expansions a shell would, and no others.
//
// Arithmetic first: $(( and $( overlap, and running command substitution first would consume the
// opening of an arithmetic expansion and leave a stray bracket.
func expandShellText(s string) string {
	s = reArithExpansion.ReplaceAllStringFunc(s, func(match string) string {
		parts := reArithExpansion.FindStringSubmatch(match)
		left, err1 := strconv.Atoi(parts[1])
		right, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			return match
		}
		return strconv.Itoa(applyIntOp(left, parts[2], right))
	})
	return reCommandExpansion.ReplaceAllStringFunc(s, func(match string) string {
		parts := reCommandExpansion.FindStringSubmatch(match)
		inner := parts[1]
		if inner == "" {
			inner = parts[2]
		}
		return runEmulatedCommand(inner)
	})
}

// runEmulatedCommand is what a command substitution returns. NOT a dispatcher onto anything real: it
// recognises echo and expr, and everything else produces the empty string a failed command would.
func runEmulatedCommand(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	switch strings.ToLower(fields[0]) {
	case "echo":
		return strings.Join(fields[1:], " ")
	case "expr":
		// `expr 24 + 89` is the form commix falls back to with --use-backticks or when it thinks a WAF
		// is present, so the control has to cover both spellings of the same arithmetic.
		if len(fields) == 4 {
			left, err1 := strconv.Atoi(fields[1])
			right, err2 := strconv.Atoi(fields[3])
			if err1 == nil && err2 == nil {
				return strconv.Itoa(applyIntOp(left, fields[2], right))
			}
		}
	case "id":
		return "uid=1000(canary) gid=1000(canary) groups=1000(canary)"
	case "whoami":
		return "canary"
	}
	return ""
}

func applyIntOp(left int, op string, right int) int {
	switch op {
	case "+":
		return left + right
	case "-":
		return left - right
	case "*":
		return left * right
	}
	return 0
}

// sstiHandler EMULATES a template engine, and is the reason SSTImap and TInjA can have a control at
// all. Before it they had none, which meant a run of either could send nothing and be recorded
// identically to a run that tested everything.
//
// FREEMARKER, AND ONLY FREEMARKER. One engine rather than every syntax at once, for the reason this
// file gives everywhere else: a control has to be recognised, not merely vulnerable. Rendering
// ${...}, {{...}}, <%= %> and #{} together would make several scanners' fingerprints match at once
// and produce an engine identification that is a fact about this emulation rather than about the
// tool. FreeMarker's detection payloads are also the smallest closed grammar of any engine SSTImap
// supports: from plugins/java/freemarker.py the header is ${(a+b)?c}, the trailer is the same, and
// the render test is ${n}<#--m-->${n2}. Two integers, one operator, and a comment.
//
// NOTHING IS EXECUTED. There is no template library here and no eval. The grammar below is integers,
// one of + - *, a quoted literal, an optional ?c/?string/?long/?int builtin, and one layer of
// brackets. Anything outside it raises a template error, which is what FreeMarker does and, measured,
// is also what TInjA fingerprints on: it sends four polyglots and classifies each response as
// unmodified, modified or error. An emulation that renders an expression it does not understand back
// verbatim answers "unmodified" to all four and TInjA concludes "No template engine could be
// detected" on a target that is deliberately injectable.
func sstiHandler(w http.ResponseWriter, r *http.Request) {
	tpl := queryParam(r, "tpl", "template", "name")
	rendered, err := renderEmulatedTemplate(tpl)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// A template error is a 500 carrying the engine's own complaint, deliberately verbose and
	// deliberately naming the engine, for the same reason /sqli names PostgreSQL: a fingerprinting
	// scanner looks for exactly this text, and a control that hides its errors is testing the
	// scanner's guesswork rather than its detection.
	if err != "" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>500 Internal Server Error</h1>
<pre>FreeMarker template error:
%s
The failing instruction:
==&gt; ${...} [in template "canary.ftl" at line 1, column 1]

Java backtrace for programmers:
freemarker.core.ParseException: %s
	at freemarker.core.FMParser.generateParseException(FMParser.java)
	at freemarker.core.Template.&lt;init&gt;(Template.java)</pre>`, canaryMarker, err, err)
		return
	}

	fmt.Fprintf(w, `<!doctype html><title>canary</title><!-- %s -->
<h1>Hello, %s!</h1>
<p>Rendered by the canary oracle's emulated template engine.</p>`, canaryMarker, rendered)
}

var (
	reTemplateComment = regexp.MustCompile(`(?s)<#--.*?-->`)
	reTemplateInt     = regexp.MustCompile(`^-?\d{1,12}$`)
	reTemplateBinary  = regexp.MustCompile(`^(-?\d{1,12})\s*([-+*])\s*(-?\d{1,12})$`)
)

// renderEmulatedTemplate is the whole "engine": drop comments, substitute the interpolations it
// understands, and report a template error for anything else. The second return value is the error
// text, empty when the render succeeded.
//
// SCANNED WITH BRACE COUNTING, NOT A REGEX. Three of TInjA's four polyglots nest braces inside the
// interpolation on purpose: `${{1}}` and `${{/#{@}}` are what tell a FreeMarker apart from a Jinja2.
// A regex of the form \$\{[^{}]*\} does not match either of them, so it would leave both untouched
// and the emulation would answer "unmodified" to the two probes that carry the whole signal.
func renderEmulatedTemplate(src string) (string, string) {
	src = reTemplateComment.ReplaceAllString(src, "")

	var out strings.Builder
	for i := 0; i < len(src); i++ {
		// $ { starts a normal interpolation, # { the legacy numeric one. FreeMarker supports both, and
		// #{1} is the only part of TInjA's third polyglot that a FreeMarker renders.
		if (src[i] != '$' && src[i] != '#') || i+1 >= len(src) || src[i+1] != '{' {
			out.WriteByte(src[i])
			continue
		}

		end, ok := matchingBrace(src, i+1)
		if !ok {
			return "", `Encountered "<EOF>", expecting "}" - unclosed interpolation`
		}
		expr := src[i+2 : end]
		value, evaluated := evalTemplateExpr(expr)
		if !evaluated {
			return "", `Encountered "` + expr + `", expecting an expression`
		}
		// #{...} is NUMERIC interpolation. FreeMarker refuses a string there, and a control that
		// quietly accepted one would answer a fingerprint probe as an engine it is not.
		if src[i] == '#' && !reTemplateInt.MatchString(value) {
			return "", `The "#{...}" numerical interpolation requires a number, got: ` + expr
		}
		out.WriteString(value)
		i = end
	}
	return out.String(), ""
}

// matchingBrace returns the index of the '}' closing the '{' at open, counting nesting.
func matchingBrace(src string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// evalTemplateExpr covers the closed grammar described on sstiHandler and refuses everything else.
func evalTemplateExpr(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	// One pass of builtins then one pass of brackets, twice, because ${(a+b)?c} needs the builtin
	// stripped before the brackets and ${(a+b)} needs only the brackets. Bounded, not recursive.
	for i := 0; i < 2; i++ {
		for _, builtin := range []string{"?c", "?string", "?long", "?int"} {
			if strings.HasSuffix(expr, builtin) {
				expr = strings.TrimSpace(strings.TrimSuffix(expr, builtin))
			}
		}
		if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
			expr = strings.TrimSpace(expr[1 : len(expr)-1])
		}
	}

	if reTemplateInt.MatchString(expr) {
		return expr, true
	}
	if parts := reTemplateBinary.FindStringSubmatch(expr); parts != nil {
		left, err1 := strconv.Atoi(parts[1])
		right, err2 := strconv.Atoi(parts[3])
		if err1 == nil && err2 == nil {
			return strconv.Itoa(applyIntOp(left, parts[2], right)), true
		}
	}
	if len(expr) >= 2 && (expr[0] == '"' || expr[0] == '\'') && expr[len(expr)-1] == expr[0] {
		return expr[1 : len(expr)-1], true
	}
	return "", false
}

// =================================================================================================
// CLEAN CONTROLS
//
// Every route above this line is vulnerable. That is a problem, and it is the problem this section
// exists to fix: when every route is a positive, a detector that fires on everything scores full
// marks, and so does a detector hardwired to return true. A verification pass that only counts hits
// cannot tell a working classifier from `return true`.
//
// So each of these routes is a place a detector MUST STAY SILENT, and each is silent for a
// DIFFERENT reason. The reason is the point. "Clean" is one verdict among many, and most of these
// routes are not clean at all: they are cannot_determine, or casted, or blocked, or inert. A
// classifier that answers "clean" on /clean/intcast has told the operator the parameter is safe
// when the truth is that it could not see it, and that is the expensive error. A false positive
// costs a scanner run; a false negative means the operator never points the tool there and the bug
// is never found.
//
// THIS IS NOT HYPOTHETICAL. The runner shipped an isolation bug where SSTI reported a FreeMarker
// parse exception on a page containing no error text at all, and it was caught only because one
// test asserted the silent half. Everything below is that assertion, as a route.
//
// SAFETY. Same constraints as the rest of the file: the container is read_only with cap_drop ALL
// and no shell, so every control here is a pure function of the request plus a bounded in-memory
// counter. Nothing writes to disk, nothing sleeps, nothing grows without a cap.
// =================================================================================================

const (
	// nonidemCap bounds the append log behind /clean/nonidem. The container is read_only and this
	// list lives in memory for the life of the process, so a scanner hammering the route must not be
	// able to grow it: past the cap the oldest rows fall off the front.
	nonidemCap = 200

	// driftPeriod is how many requests /clean/drift serves before its content changes. It has to be
	// larger than the two samples a comparator takes when it is deciding whether an endpoint is
	// stable, and small enough that a probe ladder crosses it. Eight does both.
	driftPeriod = 8

	// maxBodyBytes bounds every body read in this section.
	maxBodyBytes = 64 << 10
)

func registerCleanControls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/clean/noisy":        cleanNoisy,
		"/clean/dberror":      cleanDberror,
		"/clean/intcast":      cleanIntcast,
		"/clean/validate":     cleanValidate,
		"/clean/waf":          cleanWaf,
		"/clean/always500":    cleanAlways500,
		"/clean/echo":         cleanEcho,
		"/clean/spa":          cleanSpa,
		"/clean/nonidem":      cleanNonidem,
		"/clean/empty204":     cleanEmpty204,
		"/clean/nothing":      cleanNothing,
		"/clean/drift":        cleanDrift,
		"/clean/echoparser":   cleanEchoparser,
		"/clean/junk":         cleanJunk,
		"/clean/inert":        cleanInert,
		"/clean/passwddoc":    cleanPasswddoc,
		"/clean/b64noise":     cleanB64noise,
		"/clean/mongoprose":   cleanMongoprose,
		"/clean/echomongo":    cleanEchomongo,
		"/clean/versionprose": cleanVersionprose,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// NO CLEAN ROUTE CARRIES canaryMarker, and that is deliberate. The marker means "this response is
// the vulnerable control"; putting it on a clean route would turn every marker-grep detector into a
// false positive on the exact routes built to catch false positives. Reachability on a clean route
// is proved by the X-Ars0n-Oracle response header instead, which the "/" catch-all cannot forge.

// readRequestBody reads at most maxBodyBytes. A control that can be made to buffer an unbounded
// body is a denial of service dressed as an instrument.
func readRequestBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	return string(raw)
}

// injectableHeaders is the set of headers a probe is plausibly carried in.
//
// USER-AGENT IS NOT ON IT, on purpose. A normal browser User-Agent contains parentheses and
// semicolons, so a firewall emulation that inspected it would answer 403 to its own baseline, and
// /clean/waf would stop being "uniform block" and start being "unreachable", which is a different
// verdict reached for a reason that has nothing to do with the classifier under test. Same for
// Accept, whose q-values are full of semicolons.
var injectableHeaders = []string{
	"Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Original-Url", "X-Api-Version",
	"X-Request-Id", "Origin",
}

// requestValues gathers everything a probe could have been placed in, split by how strictly it can
// be judged. direct is the query and the body, where a scanner controls the whole value. side is
// the header and cookie slots, where legitimate traffic carries punctuation of its own.
func requestValues(r *http.Request) (direct []string, side []string) {
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		_, value, found := strings.Cut(pair, "=")
		if !found || value == "" {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			decoded = strings.ReplaceAll(value, "+", " ")
		}
		direct = append(direct, decoded)
	}
	if body := readRequestBody(r); body != "" {
		direct = append(direct, body)
	}
	for _, name := range injectableHeaders {
		if value := r.Header.Get(name); value != "" {
			side = append(side, value)
		}
	}
	for _, cookie := range r.Cookies() {
		if cookie.Value != "" {
			side = append(side, cookie.Value)
		}
	}
	return direct, side
}

// looksLikeAnAttack is a signature list, which is exactly what a firewall is. It is deliberately
// crude: the control being built is "a uniform block page", and the realism that matters is that
// the block is the same for every class, not that the rule is clever.
func looksLikeAnAttack(value string) bool {
	if strings.ContainsAny(value, "'\"`;|&<>(){}[]$\\\x00") {
		return true
	}
	lowered := strings.ToLower(value)
	for _, sequence := range []string{"../", "..\\", "--", "/*", "%00", "%27", "%3c", "0x"} {
		if strings.Contains(lowered, sequence) {
			return true
		}
	}
	return false
}

// isPlainValue is the allow-list an input validator applies: letters, digits, space and three
// punctuation marks. Everything else is a metacharacter and is refused before any sink sees it.
func isPlainValue(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ', r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// carriesAPayload reports whether any slot of the request looks perturbed.
func carriesAPayload(r *http.Request, strict bool) bool {
	direct, side := requestValues(r)
	for _, value := range direct {
		if looksLikeAnAttack(value) || (strict && !isPlainValue(value)) {
			return true
		}
	}
	// Header and cookie slots are judged by signature only, never by the strict allow-list, for the
	// reason given on injectableHeaders.
	for _, value := range side {
		if looksLikeAnAttack(value) {
			return true
		}
	}
	return false
}

// THE MOST IMPORTANT ROUTE IN THIS FILE.
//
// /clean/noisy is never byte-identical to itself. Without it the entire noise model is untested:
// against an oracle whose responses never change, a comparator that calls any two different
// responses a finding is indistinguishable from one that models noise properly, and every
// differential verdict in the system rests on a comparator nobody has ever seen make a mistake.
//
// The noise is INPUT-INDEPENDENT. Noise attributable to the payload is not noise: a detector firing
// on it would be right, and the control would be testing nothing. So this handler never reads a
// parameter. It also jitters the LENGTH, because a comparator that only compares content-length
// sees a perfectly stable endpoint otherwise and that half of the model goes unexercised.
var noisyCounter atomic.Uint64

func cleanNoisy(w http.ResponseWriter, r *http.Request) {
	served := noisyCounter.Add(1)
	entropy := make([]byte, 24)
	if _, err := rand.Read(entropy); err != nil {
		// crypto/rand does not fail in practice. If it ever did, the counter and the clock still
		// guarantee this response differs from the previous one, which is the property under test,
		// so the control degrades rather than silently becoming a stable endpoint.
		for i := range entropy {
			entropy[i] = byte(served >> (i % 8 * 8))
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html><title>status</title>
<h1>Service status</h1>
<p>request id: <code>%s</code></p>
<p>served at: <code>%s</code></p>
<p>form nonce: <code>%s</code></p>
<p>requests served: %d</p>
<!-- padding %s -->
`,
		hex.EncodeToString(entropy[:8]),
		time.Now().UTC().Format(time.RFC3339Nano),
		base64.RawURLEncoding.EncodeToString(entropy[8:20]),
		served,
		strings.Repeat(".", int(entropy[20])%37))
}

// The naive signature matcher's control. The database error is in the BASELINE, so its presence
// after a payload says nothing whatever about the payload. The only rule that survives here is one
// that requires this run's own marker inside the error phrase, which is why this route does not
// echo: an echo would put the marker in the phrase legitimately and the route would become a
// positive.
func cleanDberror(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Orders</title>
<h1>Recent orders</h1>
<table><tr><td>A-1180</td><td>shipped</td></tr><tr><td>A-1181</td><td>pending</td></tr></table>
<div class="debug-footer"><p>Last background job failure, retained for support:</p>
<pre>org.postgresql.util.PSQLException: ERROR: relation "orders_archive_2019" does not exist
  Position: 15
	at org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2675)
	at org.postgresql.jdbc.PgStatement.executeInternal(PgStatement.java:512)</pre></div>
`)
}

// An integer cast is not cleanliness. 1' reads exactly like 1 because the tail is discarded, so the
// class must answer CAST. A classifier that answers "clean" here has told the operator the
// parameter is safe when the truth is that it could not see it.
//
// It stays RESPONSIVE to the leading integer, or it would be indistinguishable from /clean/inert,
// and casted and parameter_inert are different verdicts with different next actions.
func cleanIntcast(w http.ResponseWriter, r *http.Request) {
	catalogue := map[int]string{0: "Unknown item", 1: "Rosewood Gin", 2: "Copper Rye", 3: "Sloe Nine"}
	id := leadingInt(queryParam(r, "id", "product"))
	name, known := catalogue[id]
	if !known {
		name = "Unknown item"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>product</title>\n<h1>%s</h1>\n<p>product id %d</p>\n",
		html.EscapeString(name), id)
}

// leadingInt parses the leading integer and throws the rest away, which is what every
// strtol/parseInt/to_i in every language does and is the commonest reason a quote reaches nothing.
func leadingInt(value string) int {
	end := 0
	if strings.HasPrefix(value, "-") {
		end = 1
	}
	for end < len(value) && value[end] >= '0' && value[end] <= '9' && end < 10 {
		end++
	}
	parsed, err := strconv.Atoi(value[:end])
	if err != nil {
		return 0
	}
	return parsed
}

// INPUT VALIDATION IS NOT A SQL ERROR. Every metacharacter is refused at the validation layer with
// the same 400, so the break probe and its balanced repair are answered identically and the verdict
// is metachar_not_delivered: nothing whatever was learned about the sink. The rejection deliberately
// talks like a form validator and not like a database, because a 400 that names an engine is a
// signature positive.
func cleanValidate(w http.ResponseWriter, r *http.Request) {
	if carriesAPayload(r, true) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		// Identical for every rejected input. A rejection page that varied would let a detector read
		// a differential out of the refusal itself.
		fmt.Fprint(w, `<!doctype html><title>Invalid input</title>
<h1>That value could not be accepted</h1>
<p>Fields may contain letters, numbers, spaces, hyphens, underscores and full stops only.</p>
`)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>product</title>
<h1>Rosewood Gin</h1>
<p>In stock.</p>
`)
}

// A uniform non-baseline response is a WAF, not a finding. Every payload from every class gets the
// same page with the same reference id, so cannot_determine (blocked) is reachable: the classifier
// can see that its own three distinct payloads were answered identically. The benign route control
// passes, because a route that blocks its own control is unreachable rather than protected, and
// those are different verdicts.
func cleanWaf(w http.ResponseWriter, r *http.Request) {
	if carriesAPayload(r, false) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "canary-edge")
		w.WriteHeader(http.StatusForbidden)
		// Fixed reference id. A real firewall varies it, and a varying id here would make the block
		// page noisy as well as uniform, which conflates this control with /clean/noisy.
		fmt.Fprint(w, `<!doctype html><title>Request blocked</title>
<h1>403 Forbidden</h1>
<p>This request was blocked by the web application firewall.</p>
<p>Reference RQ-0000-0000</p>
`)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>product</title>
<h1>Rosewood Gin</h1>
<p>In stock.</p>
`)
}

// A 500 that is not about the payload. This is also the route that catches "5xx means injection",
// which is not a rule, and the blind three-way error split, which must not fire when all three
// errors are the same error.
func cleanAlways500(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	// Names no engine and no language. An error page that named one would be an error-signature
	// positive rather than a control.
	fmt.Fprint(w, `<!doctype html><title>Error</title>
<h1>Something went wrong</h1>
<p>The service could not complete your request. Please try again later.</p>
`)
}

// REFLECTION IS NOT INJECTION. The echo hands back, verbatim, whatever the probe sent, including
// the exact answer string a computation oracle is looking for. Any detector that greps the body for
// its own expected answer without first checking that the answer is absent from the wire form fires
// here, and that check is the one thing separating an oracle from a substring search.
//
// text/plain with nosniff, deliberately. A verbatim reflection served as text/html IS cross-site
// scripting, and this route would become a positive control by accident, in the XSS class of all
// places.
func cleanEcho(w http.ResponseWriter, r *http.Request) {
	direct, side := requestValues(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprintln(w, "echo")
	for _, value := range append(direct, side...) {
		fmt.Fprintln(w, value)
	}
}

// The answer is in a later XHR. A shell identical whatever you send must not read as a stable clean:
// the classifier saw nothing because there was nothing on the page to see yet, which is
// cannot_determine and not a green tick.
func cleanSpa(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><title>Console</title></head>
<body><div id="app"><p>Loading...</p></div>
<script src="/static/app.bundle.js"></script></body></html>
`)
}

// Every response legitimately differs, because a POST appends a row. A comparator that reads a
// differential out of that reports a finding on every guestbook, every basket and every audit log
// on the internet.
//
// The row records only a sequence number. Recording anything derived from the submitted value, its
// length included, would make the difference attributable to the payload and the route would
// deserve the finding; recording the value itself would make it an echo route as well, and a hit
// would no longer isolate which of the two caused it.
var (
	nonidemMu  sync.Mutex
	nonidemLog []string
	nonidemSeq uint64
)

func cleanNonidem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		readRequestBody(r)
		nonidemMu.Lock()
		nonidemSeq++
		nonidemLog = append(nonidemLog, fmt.Sprintf("comment %d accepted", nonidemSeq))
		if len(nonidemLog) > nonidemCap {
			nonidemLog = append([]string(nil), nonidemLog[len(nonidemLog)-nonidemCap:]...)
		}
		nonidemMu.Unlock()
	}
	nonidemMu.Lock()
	rows := append([]string(nil), nonidemLog...)
	nonidemMu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><title>comments</title>\n<h1>Comments</h1>\n<ul>")
	for _, row := range rows {
		fmt.Fprintf(w, "<li>%s</li>", html.EscapeString(row))
	}
	fmt.Fprint(w, "</ul>\n")
}

// No body at all, in the two shapes that mean different things. "Identical bodies therefore same"
// would make every blind oracle report clean on an endpoint it could not see, and a 204 and an
// empty 200 are distinguishable to a classifier that looks and identical to one that does not.
func cleanEmpty204(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func cleanNothing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
}

// DRIFT, WHICH IS NOT NOISE, and the distinction is the whole point of having both.
//
// /clean/noisy changes on every call, so two samples are enough to detect it. This one is stable
// between adjacent calls and changes every driftPeriod requests, so a comparator that samples twice
// concludes the endpoint is stable and then watches its baseline go quietly stale underneath a long
// probe ladder. A design that baselines once and trusts it forever passes /clean/noisy and fails
// here, which is exactly the failure this route exists to expose.
var driftCounter atomic.Uint64

func cleanDrift(w http.ResponseWriter, r *http.Request) {
	generation := driftCounter.Add(1) / driftPeriod
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>dashboard</title>
<h1>Fleet dashboard</h1>
<p>cache generation %d</p>
<p>build 4.%d.0</p>
<p>queue depth %d</p>
`, generation, generation, generation*3)
}

// The payload comes back AND the phrase is on the page, but they are 200 bytes and a newline apart.
// An error-based rule that requires its marker INSIDE the error phrase stays silent; a rule that
// greps the whole body for a signature and separately for its marker fires, and is wrong.
func cleanEchoparser(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "id", "q", "search")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><title>search</title>\n<h1>No results</h1>\n"+
		"<p>Nothing matched %s.</p>\n", html.EscapeString(value))
	fmt.Fprint(w, `<p>Try a shorter search term, or browse the catalogue by category. Popular
categories this week are gin, rye and vermouth. Saved searches are kept for thirty days and can be
exported from your account settings at any time.</p>
<div class="debug-footer">
<p>Last logged application error, retained for support:</p>
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server
version for the right syntax to use near &#39;LIMIT 0, 25&#39; at line 3</pre>
</div>
`)
}

// Errors on ANY modified value, including a purely alphanumeric one. The class has to notice with
// its own junk control and stop, rather than reading the 500 it gets from a quote as a SQL error.
// Without this route, junk_sensitive is a verdict nothing has ever produced.
func cleanJunk(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "id", "q")
	if value != "" && value != "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		// Names no engine: the point is that the 500 is caused by the value being different, not by
		// the value being dangerous.
		fmt.Fprint(w, `<!doctype html><title>Error</title>
<h1>Unhandled exception</h1>
<p>The request could not be processed.</p>
`)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>product</title>
<h1>Rosewood Gin</h1>
<p>In stock.</p>
`)
}

// The parameter is discarded entirely, so the break probe and its control both match the route
// control. The verdict is parameter_inert, which is neither casted nor clean: nothing reached a
// sink because nothing reached anything.
func cleanInert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>product</title>
<h1>Featured product</h1>
<p>Rosewood Gin, 42.00. The product shown here is chosen by the merchandising team and does not
depend on the request.</p>
`)
}

// THE SIGNATURE IS IN THE BASELINE. Each of the next three routes carries, before any payload is
// sent, the exact string one class's signature list greps for. Neither a finding nor a clean:
// cannot_determine (signature_in_baseline), reached from each class's own probes.

func cleanPasswddoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Documentation: users and permissions</title>
<h1>Users and permissions</h1>
<p>A typical passwd file on a container image looks like this. Your service account should be the
last line, with no login shell.</p>
<pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
appuser:x:1000:1000::/home/appuser:/usr/sbin/nologin</pre>
<p>Do not add your account to the wheel group.</p>
`)
}

func cleanMongoprose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Admin: jobs</title>
<h1>Background jobs</h1>
<table><tr><td>nightly-rollup</td><td>ok</td></tr><tr><td>reindex</td><td>failed</td></tr></table>
<div class="debug-footer"><p>Last job error, retained for support:</p>
<pre>MongoServerError: unknown operator: $lookupp
    at Connection.onMessage (/app/node_modules/mongodb/lib/cmap/connection.js:203:30)</pre></div>
`)
}

func cleanVersionprose(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Thumbnails</title>
<h1>Thumbnail service</h1>
<p>Upload an image and it will be resized.</p>
<footer>Thumbnails rendered with ImageMagick 7.1.1-21 and libvips 8.15.1. Report problems to the
platform team.</footer>
`)
}

// A JWT and a PNG data URI, both real base64, neither interesting. This is the control for the rule
// that replaced every base64 signature in the file-inclusion family: a detector that fires on
// "there is base64 on the page" fires here, and a detector that decodes it and looks at what came
// out does not.
func cleanB64noise(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><title>Session</title>
<h1>Your session</h1>
<p>token: <code>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIiwibmFtZSI6IkNhbmFyeSJ9.`+
		`c2lnbmF0dXJlLXBsYWNlaG9sZGVyLW5vdC1hLXJlYWwta2V5</code></p>
<img alt="spacer" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA`+
		`DUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==">
<p>Nothing on this page decodes to a file, a credential or a path.</p>
`)
}

// The payload comes back verbatim in a 400, including its own operands. The computation oracle must
// want the PRODUCT, and the product is not here: a detector that searches for the operands, or for
// any part of its own payload, fires on an endpoint that did nothing but repeat what it was told.
func cleanEchomongo(w http.ResponseWriter, r *http.Request) {
	received := readRequestBody(r)
	if received == "" {
		received = queryParam(r, "filter", "u", "q")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "{\"ok\":false,\"error\":\"could not parse filter\",\"received\":%s}\n",
		strconv.Quote(received))
}

// =================================================================================================
// POSITIVE CONTROLS added alongside the clean ones.
//
// Each is a context no existing route can reach. A class that handles it has never been observed
// doing so, and a rule that has only ever been observed staying silent is exactly as unverified as
// one that has only ever been observed firing.
// =================================================================================================

func registerExtraPositives(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/sqli/mssql":          sqliMssqlHandler,
		"/sqli/mysql":          sqliMysqlHandler,
		"/sqli/json":           sqliJSONHandler,
		"/csti/angular":        cstiAngularHandler,
		"/csti/angular.min.js": cstiAngularScriptHandler,
		"/csti/plain":          cstiPlainHandler,
		"/xss/encoded":         xssEncodedHandler,
		"/xss/entity":          xssEntityHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// A BRACKETED IDENTIFIER, which nothing in a quote ladder reaches. Inside [] a quote, a backtick and
// a semicolon are all literal characters and the statement still parses; only a closing bracket ends
// the identifier early. It is the one context that is verified nowhere in this framework today, and
// the only thing the bracket payloads contribute.
//
// MEASURED DEFECT, 2026-09-18, AND THE REASON THIS ROUTE NOW HAS A LEXER. It used to break on the
// mere PRESENCE of a right bracket, so SQL-K1 (]<marker>[) and SQL-K2 (]]<marker>), which is the
// DOUBLED control, got the identical Msg 102. By the class's own rule an identical answer to the
// break and to its escaped twin means the delimiter never reached the parser, so the honest
// reading of that pair was metachar_not_delivered and the one bracket context in the framework
// resolved to cannot_determine on a route built to be a positive.
//
// A real SQL Server consumes ]] as an ESCAPE for a literal right bracket (Microsoft Learn,
// Database Identifiers), so the two payloads reach two different answers: the lone bracket ends
// the identifier early and is Msg 102, and the doubled one leaves a well-formed identifier that
// no column is called, which is Msg 207 Invalid column name. Both phrases are already in this
// class's whitelist, and only with both does the pair resolve.
func sqliMssqlHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "sort", "order", "id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	identifier, rest, broken := sqlBracketIdentifier(value)
	switch {
	case broken:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Server Error</h1>
<pre>System.Data.SqlClient.SqlException (0x80131904): Msg 102, Level 15, State 1, Line 1
Incorrect syntax near %s.
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)
   Statement: SELECT name, price FROM products ORDER BY [%s]</pre>`,
			canaryMarker, html.EscapeString("'"+rest+"'"), html.EscapeString(value))
		return
	case identifier != value:
		// The doubled form was consumed as an escape, so the identifier is well formed and the
		// engine got as far as resolving it. A column with a bracket in its name is not one of
		// this table's, and saying so by NAME is the identifier-context signal.
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Server Error</h1>
<pre>System.Data.SqlClient.SqlException (0x80131904): Msg 207, Level 16, State 1, Line 1
Invalid column name '%s'.
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)
   Statement: SELECT name, price FROM products ORDER BY [%s]</pre>`,
			canaryMarker, html.EscapeString(identifier), html.EscapeString(value))
		return
	}
	fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n"+
		"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n<p>sorted by [%s]</p>\n",
		canaryMarker, html.EscapeString(value))
}

// sqlBracketIdentifier is SQL Server's delimited-identifier lexer, and it is the whole fix.
//
// Scanning ORDER BY [<value>]: a doubled ]] is one literal right bracket INSIDE the identifier,
// and a lone ] ENDS it, leaving whatever follows as junk the parser then chokes on. identifier is
// the name the engine resolved (with the escapes collapsed), rest is the junk after an early
// close, and broken says the statement did not parse.
//
// A value with no bracket in it at all comes back unchanged and is treated as a resolvable column
// by the caller, which keeps the route control a healthy 200. An identifier carrying an EMBEDDED
// bracket cannot be a column of this table, and that is the only case the unknown-column branch
// claims.
func sqlBracketIdentifier(value string) (identifier, rest string, broken bool) {
	var name strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != ']' {
			name.WriteByte(value[i])
			continue
		}
		if i+1 < len(value) && value[i+1] == ']' {
			name.WriteByte(']')
			i++
			continue
		}
		return name.String(), value[i+1:], true
	}
	return name.String(), "", false
}

// A BACKTICK IDENTIFIER, the MySQL equivalent, and the only context the three backtick payloads
// reach. A quote here is a literal, which is the whole reason a quote ladder reports this parameter
// clean when it is not.
//
// SAME MEASURED DEFECT AS THE BRACKET ROUTE, and the same fix. Erroring on the mere presence of a
// backtick gave SQL-B1 and its DOUBLED control SQL-B2 the identical 1064, which by the class's
// own rule says the delimiter never reached the parser. MariaDB 11.8.9, VERIFIED in the class's
// own research, consumes a doubled backtick as an escape and answers
// Unknown column 'name`<marker>' in 'order clause'. That phrase is already whitelisted, and only
// with both answers does the pair resolve to a finding instead of to cannot_determine.
func sqliMysqlHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "sort", "order", "id")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	identifier, rest, broken := sqlBacktickIdentifier(value)
	switch {
	case broken:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Database error</h1>
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server
version for the right syntax to use near %s at line 1
Statement: SELECT name, price FROM products ORDER BY %s</pre>`,
			canaryMarker, html.EscapeString("'"+rest+"'"), html.EscapeString("`"+value+"`"))
		return
	case identifier != value:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>Database error</h1>
<pre>ERROR 1054 (42S22): Unknown column '%s' in 'order clause'
Statement: SELECT name, price FROM products ORDER BY %s</pre>`,
			canaryMarker, html.EscapeString(identifier), html.EscapeString("`"+value+"`"))
		return
	}
	fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n"+
		"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n<p>sorted by %s</p>\n",
		canaryMarker, html.EscapeString(value))
}

// sqlBacktickIdentifier is MySQL's quoted-identifier lexer: a doubled backtick is one literal
// backtick inside the name, a lone one ends it. Same shape and reasoning as sqlBracketIdentifier.
func sqlBacktickIdentifier(value string) (identifier, rest string, broken bool) {
	var name strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '`' {
			name.WriteByte(value[i])
			continue
		}
		if i+1 < len(value) && value[i+1] == '`' {
			name.WriteByte('`')
			i++
			continue
		}
		return name.String(), value[i+1:], true
	}
	return name.String(), "", false
}

// THE PER-CONTENT-TYPE ENCODING RULE, which decides whether the SQL arm on a JSON API is a detector
// or noise.
//
// A raw double quote never reaches the database: it terminates the JSON string and the parser
// rejects the document, so the 400 that comes back is a fact about the parser and nothing else. A
// single quote is inert to JSON, survives into the query, and produces a real database error. A
// scanner that cannot tell those two 4xx/5xx apart reports a finding on every JSON endpoint it
// touches, or, worse, reports clean because it saw a 400 and assumed it was blocked.
func sqliJSONHandler(w http.ResponseWriter, r *http.Request) {
	raw := readRequestBody(r)
	w.Header().Set("Content-Type", "application/json")
	if strings.TrimSpace(raw) == "" {
		fmt.Fprintf(w, "{\"usage\":\"POST {\\\"id\\\":\\\"1\\\"}\",\"canary\":%q}\n", canaryMarker)
		return
	}

	var document struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		// Deliberately says nothing about a database. This branch is the SILENT half of this route.
		fmt.Fprintf(w, "{\"ok\":false,\"error\":%q}\n", "invalid JSON body: "+err.Error())
		return
	}

	// Past the parser, the value is concatenated exactly as /sqli does it, so an odd number of
	// quotes with no comment is a broken statement.
	if strings.Count(document.ID, "'")%2 == 1 && !reCommentSQ.MatchString(document.ID) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"ok\":false,\"error\":%q,\"canary\":%q}\n",
			"org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near \"'\""+
				" Position: 42 Query: SELECT name, price FROM products WHERE id = '"+document.ID+"'",
			canaryMarker)
		return
	}
	fmt.Fprintf(w, "{\"ok\":true,\"rows\":[{\"name\":\"Rosewood Gin\",\"price\":\"42.00\"}],\"canary\":%q}\n",
		canaryMarker)
}

// CSTI HAS NO POSITIVE CONTROL OF ANY KIND TODAY. Its detectors have only ever been observed staying
// silent, which is exactly as unverified as only ever being observed firing.
//
// The reflection is HTML-ESCAPED, as a real AngularJS application's would be. Escaping does not
// touch braces, so the client-side template delimiters still arrive intact and still get evaluated
// by the engine in the browser, which is the entire point of the class: the sink is in the client,
// and the server-side response looks perfectly safe. Escaping also keeps this route from being an
// accidental reflected-XSS positive, which would make two classes fire on one page and neither
// result would mean anything.
func cstiAngularHandler(w http.ResponseWriter, r *http.Request) {
	q := queryParam(r, "q", "search")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title>
<script src="/csti/angular.min.js"></script></head>
<body ng-app>
<h1>Search</h1>
<div id="view">You searched for %s</div>
<span ng-non-bindable>{{ this region is never compiled }}</span>
</body></html>
`, html.EscapeString(q))
}

// cstiAngularScriptHandler serves an EMULATED AngularJS, for exactly the reasons sstiHandler
// emulates FreeMarker: the image is FROM scratch with no network and no vendored third-party code,
// and a control has to be recognised rather than merely present.
//
// It is a client-side template engine in the only sense the class measures: it finds [ng-app],
// walks TEXT NODES ONLY, and substitutes {{ }} over a closed grammar of two integers and one
// operator, or a quoted literal. It sets window.angular.version so a framework fingerprint has
// something to read.
//
// TEXT NODES ONLY IS A SAFETY PROPERTY, not an implementation detail. The substitution writes
// nodeValue and never innerHTML, so nothing this engine does can introduce markup or script into the
// page: it can compute 7*7 and it can delete a delimiter run, which is all the class needs to
// observe, and it cannot be turned into a real DOM sink.
func cstiAngularScriptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, `/* Emulated AngularJS for the canary oracle. Not AngularJS. See main.go. */
window.angular = {version: {full: "1.5.8", major: 1, minor: 5, dot: 8, codeName: "canary-emulation"}};
(function () {
  function evaluate(expression) {
    var binary = /^\s*(-?\d{1,10})\s*([*+\-])\s*(-?\d{1,10})\s*$/.exec(expression);
    if (binary) {
      var left = parseInt(binary[1], 10), right = parseInt(binary[3], 10);
      if (binary[2] === "*") { return String(left * right); }
      if (binary[2] === "+") { return String(left + right); }
      return String(left - right);
    }
    if (/^\s*-?\d{1,15}\s*$/.test(expression)) { return expression.trim(); }
    var concat = /^\s*'([^']*)'\s*\+\s*'([^']*)'\s*$/.exec(expression);
    if (concat) { return concat[1] + concat[2]; }
    /* AngularJS renders an expression it cannot resolve as the empty string. That is also the
       consumption oracle: the delimiters vanish and nothing takes their place. */
    return "";
  }
  function compile(node) {
    if (node.nodeType === 3) {
      node.nodeValue = node.nodeValue.replace(/\{\{([^{}]*)\}\}/g, function (whole, expression) {
        return evaluate(expression);
      });
      return;
    }
    if (node.nodeType !== 1) { return; }
    if (node.hasAttribute && node.hasAttribute("ng-non-bindable")) { return; }
    if (node.tagName === "SCRIPT" || node.tagName === "STYLE") { return; }
    var children = node.childNodes;
    for (var i = 0; i < children.length; i++) { compile(children[i]); }
  }
  function bootstrap() {
    var root = document.querySelector("[ng-app]");
    if (root) { compile(root); }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
`)
}

// The silent half of the CSTI pair: the same page with no engine anywhere. The delimiters come back
// unevaluated, which is not_applicable (no_client_template_engine) and must cost zero requests. A
// detector that reports a finding because it can see its own braces in the response fires here.
func cstiPlainHandler(w http.ResponseWriter, r *http.Request) {
	q := queryParam(r, "q", "search")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title></head>
<body>
<h1>Search</h1>
<div id="view">You searched for %s</div>
</body></html>
`, html.EscapeString(q))
}

// REFLECTED DOES NOT MEAN EXECUTABLE. /xss/encoded is htmlspecialchars with ENT_QUOTES: the value is
// reflected into text AND into a double-quoted attribute, and neither can break out. ?json=1 serves
// the same reflection as application/json with nosniff, which is cannot_determine (needs_dom_run)
// and never a finding and never a clean.
func xssEncodedHandler(w http.ResponseWriter, r *http.Request) {
	q := queryParam(r, "q", "search")
	if queryParam(r, "json") != "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, "{\"query\":%s,\"results\":0}\n", strconv.Quote(q))
		return
	}
	encoded := html.EscapeString(q)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>search</title>
<div id="out">%s</div>
<input name="q" value="%s">
`, encoded, encoded)
}

// /xss/entity encodes the three markup characters and leaves quotes alone, which is the commonest
// half-measure in the wild and the most important control in the family: the marker comes back
// looking exactly like the payload, as &lt;M&gt;, and a detector that greps for its own marker
// rather than for a parsed element fires on it.
func xssEntityHandler(w http.ResponseWriter, r *http.Request) {
	q := queryParam(r, "q", "search")
	entity := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(q)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>search</title>
<div id="out">%s</div>
<p>The value above is shown as text, not as markup.</p>
`, entity)
}

// =================================================================================================
// THE ROUTES THE CLASSES NAMED AND THIS CONTAINER DID NOT SERVE
//
// Each of the four below is named, in prose, by the class that depends on it:
// server/triageclasses/sql.go lists /sqli/blind and /sqli/status200 in OracleCases, and
// server/triageclasses/rfi.go lists /rfi/inband-include and /rfi/inband-reject in its failure
// atlas. All four were answered by the "/" catch-all, which returns the index page with a 200 and
// no X-Ars0n-Oracle header.
//
// A NAMED ROUTE THAT DOES NOT EXIST IS WORSE THAN NO ROUTE. The class's own atlas reads as a
// coverage claim, the operator reads it as "this detector is verified", and what the detector was
// actually pointed at is a page of links.
// =================================================================================================

func registerNamedControls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/sqli/blind":         sqliBlindHandler,
		"/sqli/status200":     sqliStatus200Handler,
		"/rfi/inband-include": rfiInbandIncludeHandler,
		"/rfi/inband-reject":  rfiInbandRejectHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// sqlDemoRecords is the blind routes' dataset. A lookup endpoint returns the row for a key it
// knows and one byte-identical "nothing found" page for every key it does not, and THAT SHAPE IS
// LOAD-BEARING rather than cosmetic: sqlUniformBlock reads three or more of the class's distinct
// payloads sharing one non-control page as a filter answering everything, and only SQL-NC1, the
// metacharacter-free probe, landing in that same bucket tells the class it is the application's
// own answer and that the ladder may continue to the boolean arm. A route that returned the row
// for any non-empty value would keep SQL-NC1 out of the bucket, the class would stop at
// uniform_block after four probes, and the arm these two routes exist for would never be sent.
var sqlDemoRecords = map[string]bool{"1": true, "2": true, "hello": true, "gin": true}

// sqlBlindVisible is the decision both suppressed-error routes share: what the row lookup would
// have returned, with a statement that would not parse producing the empty page rather than an
// error, because that is what "errors suppressed" means.
func sqlBlindVisible(id string) bool {
	visible, broken := sqlRowVisible(id, sqlDemoRecords[sqlLeadingLiteral(id)])
	if broken {
		return false
	}
	// An unbalanced quote with no comment to swallow the rest is a broken statement too. It is
	// caught here and not in sqlRowVisible because on /sqli the same condition leaks the engine's
	// complaint, and these routes are the ones that do not.
	if strings.Count(id, "'")%2 == 1 && !reCommentSQ.MatchString(id) {
		return false
	}
	return visible
}

// sqliBlindHandler is the boolean arm's positive control: errors suppressed, 200 on everything,
// no echo of any kind.
//
// WHY THE ERRORS HAVE TO BE SUPPRESSED, and why /sqli could not double as this route. On /sqli
// the error oracle fires first and settles the slot, so the boolean differential is never the
// thing being tested. Here there is nothing to see but which of two pages came back, which is the
// only signal the boolean arm reads and the only one that reaches an application that has turned
// its error pages off.
//
// AND WHY IT ECHOES NOTHING. cmp(SQL-A1, control) must be "same", and "same" means the bytes are
// the bytes. A route that printed the payload back would make the true arm differ from the
// control by the length of the payload and the differential could never close.
//
// The uniform-response bucket this shape produces is deliberate and is documented in
// sqlUniformBlock: every unrecognised value, quote-laden or not, returns one byte-identical
// "nothing found" page, and it is SQL-NC1 landing in that bucket that tells the class a
// metacharacter filter is not what produced it.
func sqliBlindHandler(w http.ResponseWriter, r *http.Request) {
	id := queryParam(r, "id", "category", "q")
	// The base predicate must MATCH for the observed value, because a boolean differential is
	// only observable when the unperturbed page shows something for the false arm to take away.
	// The canonical URL for this route is /sqli/blind?id=hello.
	visible := sqlBlindVisible(id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 200 on everything, the syntax error included. That is what "errors suppressed" means, and a
	// route that answered SQL-A3 with a 500 would be visible to the error oracle and would stop
	// being the blind control it is here to be.
	if visible {
		fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n<h1>Record</h1>\n"+
			"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n", canaryMarker)
		return
	}
	fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n<h1>Record</h1>\n"+
		"<p>No matching record.</p>\n", canaryMarker)
}

// sqliStatus200Handler is the same differential for the NUMERIC arm, on an endpoint whose status
// never moves.
//
// THE NUMERIC ARM IS THE ONLY PROBE IN THE CLASS THAT CARRIES NO METACHARACTER. `+4093-4093`
// passes every quote filter and every WAF quote rule there is, so it is the one detector that
// still reaches a filtered endpoint, and until this route existed it had been verified against
// nothing at all.
//
// ITS SLOT MUST HAVE A DIGITS-ONLY OBSERVED VALUE. SQL-A4 and SQL-A5 are defined against a
// numeric parameter and the class refuses to plan them otherwise, with
// not_planned (not_a_numeric_value), so a vector pointed here with ?id=hello measures nothing.
// The canonical URL for this route is /sqli/status200?id=1.
func sqliStatus200Handler(w http.ResponseWriter, r *http.Request) {
	id := queryParam(r, "id", "product", "q")
	visible := sqlBlindVisible(id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if visible {
		fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n<h1>Product</h1>\n"+
			"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n", canaryMarker)
		return
	}
	fmt.Fprintf(w, "<!doctype html><title>canary</title><!-- %s -->\n<h1>Product</h1>\n"+
		"<p>No such product.</p>\n", canaryMarker)
}

// rfiRemoteScheme names the remote scheme a value asks for, or "" when the value is a relative
// path. It is the whole difference between RFI-H1 and RFI-H0.
func rfiRemoteScheme(value string) string {
	switch lower := strings.ToLower(strings.TrimSpace(value)); {
	case strings.HasPrefix(lower, "https://"):
		return "https"
	case strings.HasPrefix(lower, "http://"):
		return "http"
	default:
		return ""
	}
}

// rfiInbandIncludeHandler is the in-band RFI tier's positive control: a PHP include that is
// handed the value and prints the wrapper warning when the value names a remote URL.
//
// THE CONTROL BRANCH IS THE HALF THAT MATTERS. RFI-H0 is RFI-H1 with the scheme stripped, and
// rfiJudgeInBand subtracts every primary signature the control fired from the remote probes
// before deciding anything. So this route must answer a relative path with an error that matches
// NO primary phrase in rfiFetchSigs: "No such file or directory" is what a local open produces
// and is deliberately absent from that table, while "failed to open stream" on its own is
// corroborating and never sufficient. A route that printed the same warning for both values would
// turn its own positive control into error_not_specific_to_a_remote_url.
//
// NOTHING IS FETCHED. This handler contains no HTTP client. It decides what a PHP build with
// allow_url_include=0 WOULD have printed, which is the only thing the detector can observe, and
// every host the class sends is under .invalid and could not resolve in any case.
func rfiInbandIncludeHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "file", "page", "path", "template", "url", "q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	scheme := rfiRemoteScheme(value)
	if scheme == "" {
		// A relative path. The include fails locally, in words that name no wrapper and no
		// resolver, because that is what makes the remote branch mean something.
		fmt.Fprintf(w, `<!doctype html><title>canary</title><!-- %s -->
<h1>Render</h1>
<br />
<b>Warning</b>:  include(%s): failed to open stream: No such file or directory in <b>/var/www/html/render.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  include(): Failed opening '%s' for inclusion (include_path='.:/usr/share/php') in <b>/var/www/html/render.php</b> on line <b>18</b><br />
`, canaryMarker, html.EscapeString(value), html.EscapeString(value))
		return
	}
	// The remote branch. PHP names the SCHEME it disabled, which is why RFI-H2 exists and is not
	// gated on RFI-H1: http and https are different sentences from the same build.
	fmt.Fprintf(w, `<!doctype html><title>canary</title><!-- %s -->
<h1>Render</h1>
<br />
<b>Warning</b>:  include(): %s:// wrapper is disabled in the server configuration by allow_url_include=0 in <b>/var/www/html/render.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  include(%s): failed to open stream: no suitable wrapper could be found in <b>/var/www/html/render.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  include(): Failed opening '%s' for inclusion (include_path='.:/usr/share/php') in <b>/var/www/html/render.php</b> on line <b>18</b><br />
`, canaryMarker, scheme, html.EscapeString(value), html.EscapeString(value))
}

// reDottedHost is a dot-separated host: THREE OR MORE labels, a name under a domain.
//
// WHY NOT TWO, WHICH WAS THE FIRST VERSION AND WAS MEASURED WRONG. Two labels is also every
// ordinary filename: report.tpl, archive.zip, main.js. A route that 500s on those 500s on the
// BASELINE of any vector whose observed value is a filename, and faDisabledByBaseline then
// disables java_unknown_host because the phrase already appears in the unperturbed response. The
// verdict becomes no_fetch_error_observed and the route stops being the control it exists to be:
// measured on run 076630fb, /rfi/inband-reject?file=report.tpl answered
// no_fetch_error_observed instead of error_not_specific_to_a_remote_url, the right state reached
// for the wrong reason, which is a control that passes by accident.
//
// Three labels is still "any dotted host, remote or not", which is the whole trap this route
// stands for: RFI-H0 carries <marker>.rfi-inband.invalid with no scheme at all and is refused
// exactly as RFI-H1 is.
var reDottedHost = regexp.MustCompile(`(?i)[a-z0-9_-]+(\.[a-z0-9_-]+){2,}`)

// rfiInbandRejectHandler IS THE ROUTE THAT KEEPS THE IN-BAND TIER FROM CALLING EVERY STRICT INPUT
// VALIDATOR A REMOTE FETCHER, and it is a NEGATIVE control.
//
// It is a strict application that 500s with a stack trace for any value carrying a dotted host,
// whether or not that value is a URL and whether or not anything was ever fetched. RFI-H0, the
// scheme-stripped control, therefore produces the SAME primary phrase as RFI-H1 and RFI-H2, and
// rfiJudgeInBand must answer error_not_specific_to_a_remote_url rather than a suspicion.
//
// Without it the in-band tier is untested in the only direction that costs anything. A tier that
// reads "this endpoint errored on a URL-shaped string" as "this endpoint fetches remote URLs"
// fires on every validator on the web, and a detector that fires everywhere is worth exactly what
// a detector that always returns true is worth.
//
// IT ECHOES THE VALUE, on purpose. Three byte-identical error pages are what faUniformBlock reads
// as a filter answering instead of the application, and the verdict would then be "blocked": the
// right state for the wrong reason, and a control that passes for the wrong reason is not one.
//
// NO CANARY MARKER. This route is a place the classes must NOT conclude anything, and a
// marker-grep detector finding the canary here would score a false positive on the route built to
// catch false positives.
func rfiInbandRejectHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "file", "page", "path", "template", "url", "q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !reDottedHost.MatchString(value) {
		fmt.Fprint(w, `<!doctype html><title>Document</title>
<h1>Document</h1>
<p>Nothing to render.</p>
`)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<!doctype html><title>Application error</title>
<h1>500 Internal Server Error</h1>
<pre>java.net.UnknownHostException: %s
	at java.base/java.net.InetAddress.getAllByName(InetAddress.java:1519)
	at com.example.render.DocumentName.validate(DocumentName.java:44)
	at com.example.render.RenderServlet.doGet(RenderServlet.java:81)</pre>
<p>Rejected document name: %s. It was refused before anything was opened.</p>
`, html.EscapeString(reDottedHost.FindString(value)), html.EscapeString(value))
}

// =================================================================================================
// EXPRESSION LANGUAGE INJECTION
//
// WHY THESE ROUTES EXIST. Class ELI had NO positive control anywhere in this container. Its six
// declared routes were all answered by the "/" catch-all index page, so 504 probes per run reached
// a static HTML document and every one of its 38 rows was cannot_determine. A detector never shown
// to FIRE is exactly as unverified as one never shown to stay silent, and ELI had neither half.
//
// WHAT IS EMULATED, AND WHAT IS NOT. There is no JVM in this image and there is not going to be
// one. These handlers are a CLOSED REWRITE over a fixed grammar: they recognise the exact shapes a
// JVM expression language sink would have evaluated, compute the answer the way that engine would
// have computed it, and substitute it in place. Nothing is parsed in general, nothing is reflected
// upon, and no code is executed. That is the same bargain /ssti and /cmdi already make and it is
// sound for the same reason: a detector observes a response, so what a response WOULD have
// contained is the whole of what it can measure.
//
// THE GRAMMAR IS DELIBERATELY CLOSED AND WILL NOT COMPUTE 7*7. An evaluator here that did general
// arithmetic would also answer SSTI's probes and CSTI's, and one page would then be a positive
// control for three classes at once, which is precisely the confusion the isolation law exists to
// prevent. What is under test on these routes is the JVM int32 oracle and the method-resolution
// oracle, so those are the shapes the grammar knows and everything else comes back untouched.
//
// THE INT32 WRAPAROUND IS THE POINT. 1900000000 + 1900000000 renders as -494967296 in a Java int
// and as 3800000000 in Python, JavaScript, Ruby, PHP and a JVM long. One request therefore proves
// not merely that something evaluated but WHICH TYPE SYSTEM evaluated, and that is the difference
// between "point a scanner here" and "run sstimap with -e ognl". /eli/longmath is the same
// arithmetic in a 64-bit long and exists so that the weaker answer has a route of its own: a
// detector that accepts either has claimed a dialect it cannot support, and one that only looks
// for the wrapped form records CLEAN on a real long-typed sink.
// =================================================================================================

// eliJavaVersion is what the version read answers. It is a READ of a system property with no side
// effect, and it is here because the JVM major version decides which gadget chains a later
// exploitation step could use, which is worth exactly one request once.
const eliJavaVersion = "17.0.11"

// eliDialectSpec describes a route's evaluator by WHAT IT ACCEPTS rather than by a name, because
// the thing under test is which syntax reaches a sink and not what the sink is called.
type eliDialectSpec struct {
	// label is the engine this route stands in for, and it is what the error page names.
	label string
	// delims are the interpolation openers this engine expands. They matter: %{ } is OGNL's and
	// no other dialect's, *{ } is SpEL's selection syntax, and a route that expanded all of them
	// would make the dialect identification probes meaningless.
	delims []string
	// bare is true when the engine is handed the whole value as an expression with no delimiter
	// around it. That is the single most commonly missed EL sink and, until the runner honours
	// MarkerPos, it is also the ONLY arm of this class that can fire at all: see eliRenderedPage.
	bare bool
	// The three body grammars. A body the route does not accept is REFUSED with this engine's own
	// exception rather than ignored, which is what makes the error arm identify the dialect.
	generic, spel, ognl bool
	// methods enables the string oracle, which is an independent arm: a method allow-list on
	// valueOf kills the arithmetic and leaves .replace, and a firewall rule on .replace( does the
	// reverse.
	methods bool
	// longMath computes in a 64-bit long, so the response carries 3800000000 and never
	// -494967296.
	longMath bool
	// quiet suppresses every refusal: the expression comes back untouched instead of raising.
	// /eli/longmath sets it so that its row is purely the unwrapped-overflow state with no error
	// signature anywhere to outrank it.
	quiet bool
}

// The recognised bodies. Every one is anchored to a shape a JVM EL engine resolves and to no other.
var (
	// The 1*( ) wrapper forces integer arithmetic rather than string concatenation. It is matched
	// first and as a whole so that the wrapper is consumed with the expression it wraps.
	reELIWrapGeneric = regexp.MustCompile(`1\*\(\(1\)\.valueOf\('(\d{1,12})'\)\+(\d{1,12})\)`)
	reELIWrapSpel    = regexp.MustCompile(`1\*\(T\(java\.lang\.Integer\)\.valueOf\('(\d{1,12})'\)\+(\d{1,12})\)`)
	reELIWrapOgnl    = regexp.MustCompile(`1\*\(@java\.lang\.Integer@valueOf\('(\d{1,12})'\)\+(\d{1,12})\)`)

	// (1).valueOf is the autoboxed-Integer form. It names no class, uses no T() and no @, and it
	// is the only arithmetic body that survives a SpEL SimpleEvaluationContext, which is what
	// most hardened Spring applications run.
	reELIGeneric = regexp.MustCompile(`\(1\)\.valueOf\('(\d{1,12})'\)\+(\d{1,12})`)
	// T(...) is SpEL's type operator and exists in no other dialect.
	reELISpel = regexp.MustCompile(`T\(java\.lang\.Integer\)\.valueOf\('(\d{1,12})'\)\+(\d{1,12})`)
	// @class@member is OGNL's static access and exists in no other dialect.
	reELIOgnl = regexp.MustCompile(`@java\.lang\.Integer@valueOf\('(\d{1,12})'\)\+(\d{1,12})`)

	reELIReplace = regexp.MustCompile(`'([A-Za-z0-9]{1,64})'\.replace\('([^'])','([^'])'\)`)
	reELIUpper   = regexp.MustCompile(`'([A-Za-z0-9]{1,64})'\.toUpperCase\(\)`)
	reELIVersion = regexp.MustCompile(`\(1\)\.getClass\(\)\.forName\('java\.lang\.System'\)\.getProperty\('java\.version'\)`)
	// A method that does not exist on Integer. This is the error oracle's whole payload shape and
	// it must reach the engine's method resolution rather than its parser, because those are two
	// different code paths and a stack that swallows one may still leak the other.
	reELINoMethod = regexp.MustCompile(`\(1\)\.([A-Za-z_$][A-Za-z0-9_$]{0,60})\(\)`)
)

// eliBodyKind says which grammar a match belongs to, which is what the per-route gate decides on.
type eliBodyKind int

const (
	eliKindGeneric eliBodyKind = iota
	eliKindSpel
	eliKindOgnl
	eliKindMethod
	eliKindNoMethod
)

type eliMatcher struct {
	re   *regexp.Regexp
	kind eliBodyKind
	eval func(m []string, d eliDialectSpec) string
}

// eliMatchers is in priority order: the wrapped forms first so the 1*( ) wrapper is consumed with
// the body, then the bare arithmetic, then the string methods, then the failure shape.
var eliMatchers = []eliMatcher{
	{reELIWrapGeneric, eliKindGeneric, eliSum},
	{reELIWrapSpel, eliKindSpel, eliSum},
	{reELIWrapOgnl, eliKindOgnl, eliSum},
	{reELIGeneric, eliKindGeneric, eliSum},
	{reELISpel, eliKindSpel, eliSum},
	{reELIOgnl, eliKindOgnl, eliSum},
	{reELIVersion, eliKindMethod, func([]string, eliDialectSpec) string { return eliJavaVersion }},
	{reELIReplace, eliKindMethod, func(m []string, _ eliDialectSpec) string {
		return strings.ReplaceAll(m[1], m[2], m[3])
	}},
	{reELIUpper, eliKindMethod, func(m []string, _ eliDialectSpec) string { return strings.ToUpper(m[1]) }},
	{reELINoMethod, eliKindNoMethod, func([]string, eliDialectSpec) string { return "" }},
}

// eliSum is the whole arithmetic oracle: add the two operands and render the result in the width
// the route's type system uses. int32 is the default because that is what every JVM EL evaluates
// an int expression in, and the truncation is the signal.
func eliSum(m []string, d eliDialectSpec) string {
	left, errLeft := strconv.ParseInt(m[1], 10, 64)
	right, errRight := strconv.ParseInt(m[2], 10, 64)
	if errLeft != nil || errRight != nil {
		return ""
	}
	if d.longMath {
		return strconv.FormatInt(left+right, 10)
	}
	return strconv.FormatInt(int64(int32(left+right)), 10)
}

// eliFailure is a refusal, named by kind so each route can phrase it in its own engine's words.
type eliFailure struct {
	kind string // "method_not_found" or "unparseable"
	name string // the method name, for method_not_found
	expr string // the expression that was refused
}

// eliAccepts applies the per-route dialect gate. A body this engine does not implement is a
// refusal and not a silence: that is what turns the error arm into a dialect identification.
func eliAccepts(kind eliBodyKind, d eliDialectSpec) bool {
	switch kind {
	case eliKindGeneric:
		return d.generic
	case eliKindSpel:
		return d.spel
	case eliKindOgnl:
		return d.ognl
	case eliKindMethod:
		return d.methods
	}
	return false
}

// eliEvalExpr evaluates one interpolation body. evaluated is false when nothing in the grammar
// matched, which is NOT an error: an engine that raised on every expression it did not recognise
// would answer a 500 to every probe of every class and would be a filter rather than a sink.
func eliEvalExpr(expr string, d eliDialectSpec) (value string, fail *eliFailure, evaluated bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		// An empty interpolation is a parse error in every dialect, and three of this class's
		// negative controls are exactly that. Its error is a legitimate error-arm hit and is
		// deliberately not treated as a control failure by the class.
		if d.quiet {
			return "", nil, false
		}
		return "", &eliFailure{kind: "unparseable", expr: expr}, false
	}
	for _, m := range eliMatchers {
		loc := m.re.FindStringSubmatchIndex(expr)
		if loc == nil || loc[0] != 0 || loc[1] != len(expr) {
			continue
		}
		groups := m.re.FindStringSubmatch(expr)
		if !eliAccepts(m.kind, d) && m.kind != eliKindNoMethod {
			if d.quiet {
				return "", nil, false
			}
			return "", &eliFailure{kind: "unparseable", expr: expr}, false
		}
		if m.kind == eliKindNoMethod {
			if d.quiet {
				return "", nil, false
			}
			return "", &eliFailure{kind: "method_not_found", name: groups[1], expr: expr}, false
		}
		return m.eval(groups, d), nil, true
	}
	return "", nil, false
}

// eliOpenDelim reports which interpolation opener the value starts with at this position. The
// longest opener wins, so __${ is not read as a bare ${ preceded by two underscores.
func eliOpenDelim(rest string, d eliDialectSpec) (string, bool) {
	best := ""
	for _, delim := range d.delims {
		if strings.HasPrefix(rest, delim) && len(delim) > len(best) {
			best = delim
		}
	}
	return best, best != ""
}

// eliRender substitutes every interpolation this engine expands, and then, on a bare sink, the
// first bare expression in what is left. The second return value is a refusal, which the caller
// turns into this engine's own exception page.
func eliRender(value string, d eliDialectSpec) (string, *eliFailure) {
	var out strings.Builder
	substituted := false

	for i := 0; i < len(value); {
		delim, ok := eliOpenDelim(value[i:], d)
		if !ok {
			out.WriteByte(value[i])
			i++
			continue
		}
		brace := i + strings.Index(delim, "{")
		end, closed := matchingBrace(value, brace)
		if !closed {
			// An unclosed interpolation is the rest of the string, verbatim. A real engine raises
			// here; answering with the text keeps an unbalanced brace in somebody else's payload
			// from turning this route into a 500 for every class at once.
			out.WriteString(value[i:])
			break
		}
		inner := strings.TrimSpace(value[brace+1 : end])
		// ${{ }} arrives here as {expr}. Strip the extra layer so the grammar sees the expression
		// rather than a brace it cannot parse: that shape is one of the delimiters this class
		// probes with and it would otherwise be a silent no-op.
		if strings.HasPrefix(inner, "{") && strings.HasSuffix(inner, "}") {
			inner = strings.TrimSpace(inner[1 : len(inner)-1])
		}
		rendered, fail, evaluated := eliEvalExpr(inner, d)
		if fail != nil {
			return "", fail
		}
		if !evaluated {
			out.WriteString(value[i : end+1])
			i = end + 1
			continue
		}
		out.WriteString(rendered)
		i = end + 1
		substituted = true
	}

	text := out.String()
	if substituted || !d.bare {
		return text, nil
	}
	return eliRenderBare(text, d)
}

// eliRenderBare is the no-delimiter sink: the value itself is the expression. It replaces the
// FIRST recognised body in place, which is what an application that concatenates the value into
// an expression it then evaluates would produce.
func eliRenderBare(text string, d eliDialectSpec) (string, *eliFailure) {
	best := -1
	bestEnd := -1
	var chosen eliMatcher
	var groups []string
	for _, m := range eliMatchers {
		loc := m.re.FindStringSubmatchIndex(text)
		if loc == nil {
			continue
		}
		if best >= 0 && (loc[0] > best || (loc[0] == best && loc[1] <= bestEnd)) {
			continue
		}
		best, bestEnd, chosen = loc[0], loc[1], m
		groups = m.re.FindStringSubmatch(text)
	}
	if best < 0 {
		return text, nil
	}
	if !eliAccepts(chosen.kind, d) && chosen.kind != eliKindNoMethod {
		if d.quiet {
			return text, nil
		}
		return "", &eliFailure{kind: "unparseable", expr: text[best:bestEnd]}
	}
	if chosen.kind == eliKindNoMethod {
		if d.quiet {
			return text, nil
		}
		return "", &eliFailure{kind: "method_not_found", name: groups[1], expr: text[best:bestEnd]}
	}
	return text[:best] + chosen.eval(groups, d) + text[bestEnd:], nil
}

// eliInjectableValue reads the probe out of whichever slot carried it: the query first, then the
// headers a probe is plausibly placed in, then the cookies.
//
// THE HEADER AND COOKIE PATHS ARE NOT DECORATION. CATALOGUE 6.1 asks for the OGNL route to be
// exercised over a header and a cookie as well as a query, because the %25 rule is this class's
// likeliest silent failure and those two paths are the ones that do not depend on the query
// encoder getting it right. A route that only read the query would answer an identical page to a
// header probe and to no probe at all, and the slot would be recorded as tested.
func eliInjectableValue(r *http.Request) string {
	if v := queryParam(r, "q", "search", "name", "expr", "tpl", "value", "id"); v != "" {
		return eliCap(v)
	}
	for _, name := range injectableHeaders {
		if v := r.Header.Get(name); v != "" {
			return eliCap(v)
		}
	}
	for _, cookie := range r.Cookies() {
		if cookie.Value != "" {
			return eliCap(cookie.Value)
		}
	}
	return ""
}

// eliCap bounds the reflection. An oracle that echoed an unbounded value back is a bandwidth
// amplifier dressed as an instrument.
func eliCap(v string) string {
	const limit = 4096
	if len(v) > limit {
		return v[:limit]
	}
	return v
}

// eliExceptionPage is the dialect-naming error, and it is the third oracle arm. It is rank 4 on
// purpose: it proves the parser was REACHED and not that the expression evaluated. What makes it
// worth its request is that every dialect names itself in the exception, so the arm identifies as
// well as detects.
func eliExceptionPage(w http.ResponseWriter, d eliDialectSpec, fail *eliFailure) {
	var lines string
	switch d.label {
	case "spel":
		if fail.kind == "method_not_found" {
			lines = "org.springframework.expression.spel.SpelEvaluationException: EL1004E: Method call: " +
				"Method " + fail.name + "() cannot be found on type java.lang.Integer"
		} else {
			lines = "org.springframework.expression.spel.SpelParseException: EL1041E: After parsing a valid " +
				"expression, there is still more data in the expression: " + fail.expr
		}
		lines += "\n\tat org.springframework.expression.spel.standard.SpelExpressionParser.doParseExpression(SpelExpressionParser.java)"
	case "ognl":
		if fail.kind == "method_not_found" {
			lines = "ognl.MethodFailedException: Method \"" + fail.name + "\" failed for object 1"
		} else {
			lines = "ognl.ExpressionSyntaxException: Malformed OGNL expression: " + fail.expr +
				"\nCaused by: ognl.ParseException: Encountered \"" + fail.expr + "\" at line 1, column 1."
		}
		lines += "\n\tat ognl.Ognl.parseExpression(Ognl.java)"
	default:
		if fail.kind == "method_not_found" {
			lines = "javax.el.MethodNotFoundException: Method not found: class java.lang.Integer." + fail.name + "()"
		} else {
			lines = "javax.el.ELException: Error Parsing: " + fail.expr +
				"\nCaused by: org.apache.el.parser.ParseException: Encountered \"" + fail.expr + "\" at line 1, column 1."
		}
		lines += "\n\tat org.apache.el.lang.ExpressionBuilder.createNodeInternal(ExpressionBuilder.java)"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<!doctype html><title>error</title><!-- %s -->
<h1>500 Internal Server Error</h1>
<pre>%s</pre>`, canaryMarker, html.EscapeString(lines))
}

// eliRenderedPage is the success page, and the ONE detail that decides whether this whole section
// works is where the answer lands.
//
// The class anchors its answer to the marker that preceded the expression: <marker>-494967296 with
// nothing but whitespace between them. Substituting the expression IN PLACE inside the reflected
// value is what produces that, which is why the value is rendered as one run and not summarised.
//
// MEASURED, AND IT IS A RUNNER GAP AND NOT A ROUTE ONE: nothing in the framework applies
// ProbeSpec.MarkerPos today, so every ELI payload reaches the wire with NO marker in it, the
// anchored arms can never match, and the only arm that can fire is the BARE one, whose matcher
// takes the marker out of the rule by construction. These routes are built for both, so they
// start working the day the runner splices the marker, and the bare arm fires today.
func eliRenderedPage(w http.ResponseWriter, d eliDialectSpec, rendered string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>canary</title><!-- %s -->
<h1>Greeting</h1>
<p>Hello, %s!</p>
<p>Rendered by the canary oracle's emulated %s expression language.</p>`,
		canaryMarker, html.EscapeString(rendered), html.EscapeString(d.label))
}

// eliHandler is every positive ELI route, parameterised by its dialect.
func eliHandler(d eliDialectSpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rendered, fail := eliRender(eliInjectableValue(r), d)
		if fail != nil {
			eliExceptionPage(w, d, fail)
			return
		}
		eliRenderedPage(w, d, rendered)
	}
}

var (
	// /eli: the generic JVM EL sink. It is the one route that must fire, and the body it accepts
	// is the one that needs no class name, no T() and no @, so it reaches JUEL, Jakarta EL, JSP
	// EL, MVEL and a hardened SpEL alike. A T() or an @ here is REFUSED in javax.el's words,
	// which is what makes the error arm name juel on this route and spel on the next one.
	eliDialectGeneric = eliDialectSpec{
		label: "juel", delims: []string{"${", "#{", "@{", "${{", "__${"},
		bare: true, generic: true, methods: true,
	}
	// /eli/spel: the same grammar plus SpEL's type operator, so the SpEL identification arm is
	// exercised independently of the generic one and the dialect LABEL is tested rather than
	// assumed. *{ } is SpEL's selection syntax and appears here and nowhere else.
	eliDialectSpel = eliDialectSpec{
		label: "spel", delims: []string{"${", "#{", "*{", "${{", "__${"},
		bare: true, generic: true, spel: true, methods: true,
	}
	// /eli/ognl: @java.lang.Integer@valueOf reached through %{ }. The percent is the point: it
	// must arrive as %25 on a query and a form, and this is the route where a runner that sends
	// it raw produces a 400 that reads exactly like a firewall block.
	eliDialectOgnl = eliDialectSpec{
		label: "ognl", delims: []string{"%{", "${", "@{"},
		bare: true, generic: true, ognl: true, methods: true,
	}
	// /eli/longmath: THE MOST VALUABLE NEGATIVE IN THE SET. The same arithmetic in a 64-bit long,
	// so the response carries 3800000000 and never -494967296. It is quiet and has no string
	// method, so its row can only ever be the unwrapped-overflow state: an implementation that
	// only looks for the wrapped answer records CLEAN here on a real long-typed JVM EL sink, and
	// one that accepts either records a finding it cannot support. Both are wrong and this route
	// is where each is caught.
	//
	// IT CARRIES THE CANARY MARKER and it is NOT a clean route. Something here really does
	// evaluate arithmetic: it is a template-injection positive, just not THIS class's, and a
	// scanner that found it would be right. What the class owes here is suspicious
	// (el_overflow_unwrapped), which is neither a finding nor a clean, so listing it among the
	// clean controls would be the third wrong answer.
	eliDialectLong = eliDialectSpec{
		label: "juel-long", delims: []string{"${"},
		bare: true, generic: true, longMath: true, quiet: true,
	}
)

func registerELIControls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/eli":          eliHandler(eliDialectGeneric),
		"/eli/spel":     eliHandler(eliDialectSpel),
		"/eli/ognl":     eliHandler(eliDialectOgnl),
		"/eli/longmath": eliHandler(eliDialectLong),
		"/eli/hardened": eliHardenedHandler,
		"/eli/echo":     eliEchoHandler,
		"/eli/devmode":  eliDevmodeHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// THE ROUTE THAT PROVES THIS CLASS CAN REACH A LEGITIMATE CLEAN AT ALL, which is the half a
// fire-only rig never tests. The value is reflected verbatim into a page with no evaluator behind
// it of any kind: every probe must stay silent AND the verdict must be clean with ordinals, not
// cannot_determine, because the marker demonstrably comes back and the slot demonstrably reflects.
func eliHardenedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>greeting</title></head>
<body>
<h1>Greeting</h1>
<p>Hello, %s!</p>
<p>No expression language is configured for this view. The template is a string format.</p>
</body></html>
`, html.EscapeString(eliInjectableValue(r)))
}

// THE GUARD'S ROUTE, and the guard is what stops every echoing endpoint in the world reading as an
// expression language finding.
//
// Three of this class's negative controls send the ANSWERS as literal text: -494967296, qm7vbn7w
// and 3800000000. Reflected verbatim they land next to the marker exactly where a real computed
// answer would, so the adjacency rule WILL match and only the answer-not-in-wire subtraction
// suppresses it. text/plain and no escaping, because the property under test is that the bytes
// come back as the bytes.
func eliEchoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, eliInjectableValue(r))
}

// struts.devMode=true PRINTS A PROBLEM REPORT ON EVERY REQUEST, the baseline included. Without
// baseline differencing per signature, this class reports a finding on every slot of every such
// application forever, which is a false positive that never stops.
//
// The route carries that one signature and NO OTHER: there is no evaluator here and no second
// OGNL phrase, so a class that subtracts the baseline correctly has nothing at all left to report,
// and a class that subtracts per RESPONSE rather than per SIGNATURE cannot be told apart from one
// that subtracts properly. It carries no canary marker: it is a place to stay silent.
func eliDevmodeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>Struts Problem Report</title></head>
<body>
<h1>Struts Problem Report</h1>
<p>Struts has detected an unhandled exception. This page is shown because struts.devMode is true.</p>
<p>Requested value: %s</p>
<pre>Stacktraces
  No stacktrace was recorded for this request.</pre>
</body></html>
`, html.EscapeString(eliInjectableValue(r)))
}

// =================================================================================================
// NOSQL INJECTION
//
// WHY THESE ROUTES EXIST. Class NOSQL named six /nosqli/* routes and every one of them was
// answered by the "/" catch-all index page. 724 probes per run reached a static HTML document,
// the six arms reported cannot_determine or not_applicable on all 38 routes, and nobody had ever
// seen this class fire. That is not a clean and it is not a failure either: it is an untested
// detector, and an untested detector is the thing this whole container exists to prevent.
//
// WHAT IS EMULATED. There is no MongoDB in this image. These handlers are a closed interpreter
// over a FIXED FOUR-DOCUMENT COLLECTION: they read a filter document, decide which of four
// records it selects, and answer with a JSON array. Operator injection is real in the only sense
// a detector can observe: an operator object in the filter changes WHICH ROWS COME BACK, and the
// class reads that from array cardinality in the JSON projection and never from body length.
//
// THE RESPONSE MUST BE A JSON ARRAY AND THIS IS NOT CosmeTIC. The widening oracle counts rows. An
// endpoint that answered one object per query, or HTML, gives it nothing to count, and the honest
// verdict then is cannot_determine (cardinality_unavailable) on a route built to be a positive.
// So every successful response here carries rows[] even when it is empty.
//
// THE MISSING-PARAMETER BRANCH IS A DELIBERATE FAIL-CLOSED, AND IT IS A MEASUREMENT. The runner's
// name-slot encoder renders an object probe by replacing the parameter NAME with the raw JSON, so
// on a query slot /nosqli/mongo?q=hello becomes {"$ne":"<marker>"}=hello and the q parameter is
// gone. An Express application doing find({name: req.query.q}) would then be handed
// {name: undefined}, drop the key and return EVERY row, and the class would correctly observe a
// widening produced by nothing but the encoder deleting the parameter. Answering a missing
// required parameter with a 400 instead is the other, equally real, application shape and it is
// the one that does not manufacture a finding out of a runner defect. The query-bracket encoder
// (q[$ne]=x) is what these routes actually want and it does not exist yet; it is reported.
// =================================================================================================

// nosqlDoc is one record. Three fields, because the arms need a string field to match on, a
// second string to widen into and a NUMERIC field for the $mod arithmetic, which is the N-OP
// arm's only computation oracle.
type nosqlDoc struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Age  int    `json:"age"`
}

// nosqlCollection is the whole database. "hello" is in it on purpose: it is the observed value
// every exam vector carries, and a boolean or widening differential is only observable when the
// unperturbed request returns something for the false arm to take away.
var nosqlCollection = []nosqlDoc{
	{Name: "hello", Role: "user", Age: 30},
	{Name: "gin", Role: "user", Age: 41},
	{Name: "alice", Role: "admin", Age: 25},
	{Name: "bob", Role: "user", Age: 52},
}

// nosqlFault is an engine error: the sentence the database itself would have printed. The class
// matches on the PHRASE and never on the status, so the sentence is the part that matters.
type nosqlFault struct {
	status int
	text   string
}

func nosqlEngineFault(text string) *nosqlFault {
	return &nosqlFault{status: http.StatusInternalServerError, text: text}
}

// nosqlResult is the success envelope. rows is always present, even empty.
type nosqlResult struct {
	Canary string     `json:"canary,omitempty"`
	Count  int        `json:"count"`
	Rows   []nosqlDoc `json:"rows"`
}

func nosqlWriteRows(w http.ResponseWriter, rows []nosqlDoc, canary bool) {
	if rows == nil {
		rows = []nosqlDoc{}
	}
	out := nosqlResult{Count: len(rows), Rows: rows}
	if canary {
		out.Canary = canaryMarker
	}
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(out)
	if err != nil {
		// Marshalling four fixed structs cannot fail. If it ever did, saying so is better than
		// serving a truncated body that a comparator would read as a differential.
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"ok":false,"error":"result could not be serialised"}`)
		return
	}
	fmt.Fprintf(w, "%s\n", body)
}

func nosqlWriteFault(w http.ResponseWriter, f *nosqlFault, canary bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	if canary {
		fmt.Fprintf(w, "{\"ok\":false,\"error\":%s,\"canary\":%q}\n", strconv.Quote(f.text), canaryMarker)
		return
	}
	fmt.Fprintf(w, "{\"ok\":false,\"error\":%s}\n", strconv.Quote(f.text))
}

// nosqlFilterFrom builds the filter document the way a small JSON API does: the request body IS
// the filter when there is one, and otherwise the named query parameter becomes one field of it.
//
// A parameter whose VALUE is itself a JSON object is expanded, because ?filter={"name":"x"} is a
// real and common shape and it is the only way an object reaches these routes through a query
// slot until the bracket encoder exists.
func nosqlFilterFrom(r *http.Request) (map[string]json.RawMessage, bool) {
	if body := strings.TrimSpace(readRequestBody(r)); body != "" {
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &document); err == nil {
			return document, true
		}
		return nil, false
	}
	value := queryParam(r, "q", "name", "filter", "user", "search")
	if value == "" {
		return nil, false
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed)) {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &inner); err == nil {
			if _, named := inner["name"]; named || nosqlHasDollarKey(inner) {
				// The value is a whole filter document, not a field value.
				return inner, true
			}
			return map[string]json.RawMessage{"name": json.RawMessage(trimmed)}, true
		}
	}
	quoted, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	return map[string]json.RawMessage{"name": quoted}, true
}

func nosqlHasDollarKey(document map[string]json.RawMessage) bool {
	for key := range document {
		if strings.HasPrefix(key, "$") {
			return true
		}
	}
	return false
}

// nosqlSortedKeys keeps evaluation order deterministic. Two responses that differ only because Go
// ranged a map in a different order would be read as noise by the comparator, and this container
// values determinism above everything else.
func nosqlSortedKeys(document map[string]json.RawMessage) []string {
	out := make([]string, 0, len(document))
	for key := range document {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// nosqlRunFilter is the whole engine: every key of the filter document is a predicate, and a
// document comes back when all of them hold.
func nosqlRunFilter(document map[string]json.RawMessage, scripting bool) ([]nosqlDoc, *nosqlFault) {
	rows := make([]nosqlDoc, 0, len(nosqlCollection))
	for _, doc := range nosqlCollection {
		keep := true
		for _, key := range nosqlSortedKeys(document) {
			ok, fault := nosqlPredicate(key, document[key], doc, scripting)
			if fault != nil {
				return nil, fault
			}
			if !ok {
				keep = false
				break
			}
		}
		if keep {
			rows = append(rows, doc)
		}
	}
	return rows, nil
}

// nosqlPredicate evaluates one key of the filter document against one record.
func nosqlPredicate(key string, raw json.RawMessage, doc nosqlDoc, scripting bool) (bool, *nosqlFault) {
	if !strings.HasPrefix(key, "$") {
		return nosqlFieldPredicate(key, raw, doc)
	}
	switch key {
	case "$expr":
		return nosqlExprPredicate(raw)
	case "$where":
		var script string
		if err := json.Unmarshal(raw, &script); err != nil {
			return false, nosqlEngineFault("MongoServerError: $where must be a string or a function")
		}
		if !scripting {
			// THE MOST IMPORTANT NEGATIVE IN THE CLASS'S POSITIVE SET. The engine says in its own
			// words that it will not run server-side JavaScript, which means the string DID reach
			// it: the sink is real and a named defence stopped it. That is worth more to an
			// operator than a clean, and it is the configuration under which the $expr arm must
			// still fire.
			return false, nosqlEngineFault("MongoServerError: no globalScriptEngine in $where parsing")
		}
		return nosqlJSPredicate(script, doc)
	default:
		// "unknown TOP LEVEL operator" is a different sentence from "unknown operator", and the
		// difference tells the operator whether the whole document reaches the query or only one
		// field of it. Two sentences, two verdicts, one character of difference in the payload.
		return false, nosqlEngineFault("MongoServerError: unknown top level operator: " + key +
			". If you have a field name that starts with a dollar symbol, consider using $getField or $setField.")
	}
}

// nosqlFieldPredicate is field-level matching, which is where operator injection lands.
func nosqlFieldPredicate(field string, raw json.RawMessage, doc nosqlDoc) (bool, *nosqlFault) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, nosqlEngineFault("MongoParseError: filter is not valid BSON")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		var operators map[string]json.RawMessage
		if err := json.Unmarshal(raw, &operators); err != nil {
			return false, nosqlEngineFault("MongoParseError: filter is not valid BSON")
		}
		if nosqlHasDollarKey(operators) {
			return nosqlOperatorPredicate(field, operators, doc)
		}
		// An object with no dollar in it is an exact sub-document match, which no scalar field
		// can satisfy. It is not an error on the raw driver: it simply matches nothing, and that
		// is the answer a class expecting a Mongoose CastError must be able to tell apart.
		return false, nil
	case []interface{}:
		// An array compares as an array. The raw driver matches nothing; Mongoose would silently
		// rewrite it to $in and match. This route is the raw driver, which is what makes the
		// type-confusion arm's pair mean something here.
		return false, nil
	case nil:
		// null matches documents where the field is absent. Every record has every field.
		return false, nil
	case string:
		return nosqlFieldString(field, doc) == typed && nosqlFieldIsString(field), nil
	case float64:
		n, numeric := nosqlFieldNumber(field, doc)
		return numeric && float64(n) == typed, nil
	case bool:
		return false, nil
	}
	return false, nil
}

func nosqlFieldIsString(field string) bool { return field == "name" || field == "role" }

func nosqlFieldString(field string, doc nosqlDoc) string {
	switch field {
	case "name":
		return doc.Name
	case "role":
		return doc.Role
	}
	return ""
}

func nosqlFieldNumber(field string, doc nosqlDoc) (int, bool) {
	if field == "age" {
		return doc.Age, true
	}
	return 0, false
}

// nosqlOperatorPredicate is the operator table. Everything outside it is an unknown operator, by
// NAME, which is the class's error control: it sends an operator name that is this run's marker,
// so an engine that complains about it by name has demonstrably parsed the object.
func nosqlOperatorPredicate(field string, operators map[string]json.RawMessage, doc nosqlDoc) (bool, *nosqlFault) {
	value := nosqlFieldString(field, doc)
	for _, op := range nosqlSortedKeys(operators) {
		raw := operators[op]
		switch op {
		case "$eq", "$ne":
			var want string
			if err := json.Unmarshal(raw, &want); err != nil {
				continue
			}
			if (op == "$eq") != (value == want) {
				return false, nil
			}
		case "$gt", "$lt":
			var want string
			if err := json.Unmarshal(raw, &want); err != nil {
				continue
			}
			if op == "$gt" && !(value > want) {
				return false, nil
			}
			if op == "$lt" && !(value < want) {
				return false, nil
			}
		case "$in", "$nin":
			var want []string
			if err := json.Unmarshal(raw, &want); err != nil {
				continue
			}
			found := false
			for _, candidate := range want {
				if candidate == value {
					found = true
				}
			}
			if (op == "$in") != found {
				return false, nil
			}
		case "$regex":
			var pattern string
			if err := json.Unmarshal(raw, &pattern); err != nil {
				// A typed-argument error reaches the ARGUMENT VALIDATOR rather than the operator
				// lookup, which is a different code path: a stack that swallows one may still
				// leak the other, which is why the class sends both.
				return false, nosqlEngineFault("MongoServerError: $regex has to be a string")
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return false, nosqlEngineFault("MongoServerError: Regular expression is invalid: " + err.Error())
			}
			if !compiled.MatchString(value) {
				return false, nil
			}
		case "$mod":
			var pair []int
			if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 || pair[0] == 0 {
				return false, nosqlEngineFault("MongoServerError: malformed mod, not enough elements")
			}
			n, numeric := nosqlFieldNumber(field, doc)
			if !numeric || n%pair[0] != pair[1] {
				return false, nil
			}
		case "$exists":
			var want bool
			if err := json.Unmarshal(raw, &want); err != nil {
				continue
			}
			if !want {
				return false, nil
			}
		default:
			return false, nosqlEngineFault("MongoServerError: unknown operator: " + op)
		}
	}
	return true, nil
}

// nosqlExprPredicate is the aggregation expression arm, and it is the strongest oracle in the
// class: the server COMPUTES 8123*7 and compares it with a constant, so a widened result set is
// arithmetic the server performed rather than a difference we interpreted. It is also the one
// oracle that survives --noscripting, which is why /nosqli/noscripting exists.
func nosqlExprPredicate(raw json.RawMessage) (bool, *nosqlFault) {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, nosqlEngineFault("MongoServerError: $expr must be an expression")
	}
	for _, op := range nosqlSortedKeys(node) {
		switch op {
		case "$eq", "$ne", "$gt", "$lt":
			var operands []json.RawMessage
			if err := json.Unmarshal(node[op], &operands); err != nil || len(operands) != 2 {
				return false, nosqlEngineFault("MongoServerError: Invalid $expr: " + op + " takes exactly 2 arguments")
			}
			left, fault := nosqlExprValue(operands[0])
			if fault != nil {
				return false, fault
			}
			right, fault := nosqlExprValue(operands[1])
			if fault != nil {
				return false, fault
			}
			switch op {
			case "$eq":
				return left == right, nil
			case "$ne":
				return left != right, nil
			case "$gt":
				return left > right, nil
			default:
				return left < right, nil
			}
		default:
			return false, nosqlEngineFault("MongoServerError: Unrecognized expression '" + op + "'")
		}
	}
	return false, nosqlEngineFault("MongoServerError: Unrecognized expression ''")
}

// nosqlExprValue evaluates one arithmetic node. The grammar is closed for the same reason the
// expression-language grammar is: a general evaluator here would answer three other classes'
// probes on one page.
func nosqlExprValue(raw json.RawMessage) (float64, *nosqlFault) {
	var literal float64
	if err := json.Unmarshal(raw, &literal); err == nil {
		return literal, nil
	}
	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		return 0, nosqlEngineFault("MongoServerError: Invalid $expr operand")
	}
	for _, op := range nosqlSortedKeys(node) {
		var operands []float64
		if err := json.Unmarshal(node[op], &operands); err != nil || len(operands) < 2 {
			return 0, nosqlEngineFault("MongoServerError: Invalid $expr: " + op + " takes an array of numbers")
		}
		switch op {
		case "$multiply":
			total := operands[0]
			for _, n := range operands[1:] {
				total *= n
			}
			return total, nil
		case "$add":
			total := operands[0]
			for _, n := range operands[1:] {
				total += n
			}
			return total, nil
		case "$subtract":
			return operands[0] - operands[1], nil
		default:
			return 0, nosqlEngineFault("MongoServerError: Unrecognized expression '" + op + "'")
		}
	}
	return 0, nosqlEngineFault("MongoServerError: Unrecognized expression ''")
}

// -------------------------------------------------------------------------------------------
// THE $where INTERPRETER
//
// It understands conjunctions of a closed set of clauses and NOTHING else, and a clause it does
// not recognise is FALSE rather than an error. That choice is the whole difference between a
// control and a false-positive generator: an emulator that raised on everything it could not
// parse would answer an engine error to every probe of every class, and the class would read
// that as a JavaScript interpreter leaking on payloads no interpreter ever saw.
//
// The one thing that IS an error is an unbalanced quote in the assembled predicate, because that
// is a real SyntaxError and it is what the class's repair control exists to rule out.
// -------------------------------------------------------------------------------------------

var (
	reNoSQLThrow  = regexp.MustCompile(`^(?:\(function\(\)\{)?throw new Error\('([^']*)'\+\((\d{1,9})\*(\d{1,9})\)\)(?:\}\)\(\))?$`)
	reNoSQLThisEq = regexp.MustCompile(`^this\.([A-Za-z_][A-Za-z0-9_]{0,32})\s*===?\s*'([^']*)'$`)
	reNoSQLArith  = regexp.MustCompile(`^(\d{1,9})\s*([*+\-])\s*(\d{1,9})\s*(===?|!==?)\s*(\d{1,12})$`)
	reNoSQLLitEq  = regexp.MustCompile(`^'([^']*)'\s*===?\s*'([^']*)'$`)
	reNoSQLCall   = regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]{0,63})\(\)$`)
)

// nosqlUnbalancedQuote reports whether the assembled predicate has an odd number of unescaped
// single quotes, which is the one shape that does not compile.
func nosqlUnbalancedQuote(js string) bool {
	count := 0
	for i := 0; i < len(js); i++ {
		if js[i] == '\\' {
			i++
			continue
		}
		if js[i] == '\'' {
			count++
		}
	}
	return count%2 == 1
}

// nosqlSplitConjuncts splits on && outside string literals and outside parentheses.
func nosqlSplitConjuncts(js string) []string {
	var parts []string
	depth, start := 0, 0
	inQuote := false
	for i := 0; i < len(js); i++ {
		switch {
		case js[i] == '\\':
			i++
		case js[i] == '\'':
			inQuote = !inQuote
		case inQuote:
		case js[i] == '(':
			depth++
		case js[i] == ')':
			depth--
		case depth == 0 && js[i] == '&' && i+1 < len(js) && js[i+1] == '&':
			parts = append(parts, js[start:i])
			i++
			start = i + 1
		}
	}
	return append(parts, js[start:])
}

// nosqlJSPredicate evaluates the assembled $where against one record.
func nosqlJSPredicate(js string, doc nosqlDoc) (bool, *nosqlFault) {
	if nosqlUnbalancedQuote(js) {
		return false, nosqlEngineFault("MongoServerError: SyntaxError: unterminated string literal :\n@:0:0\n")
	}
	for _, clause := range nosqlSplitConjuncts(js) {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		truth, fault := nosqlJSClause(clause, doc)
		if fault != nil {
			return false, fault
		}
		if !truth {
			return false, nil
		}
	}
	return true, nil
}

func nosqlJSClause(clause string, doc nosqlDoc) (bool, *nosqlFault) {
	switch clause {
	case "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	if m := reNoSQLThrow.FindStringSubmatch(clause); m != nil {
		left, errLeft := strconv.Atoi(m[2])
		right, errRight := strconv.Atoi(m[3])
		if errLeft != nil || errRight != nil {
			return false, nil
		}
		// THE TIER-1 ORACLE. The engine concatenates the probe's own marker with a product it
		// computed and throws the result, so the response carries <marker>56861 with no byte in
		// between. An echo of the payload cannot produce those bytes in that order: an echo shows
		// the quote, the plus and the parenthesis.
		return false, nosqlEngineFault("MongoServerError: Error: " + m[1] + strconv.Itoa(left*right) + " :\n@:0:0\n")
	}
	if m := reNoSQLThisEq.FindStringSubmatch(clause); m != nil {
		return nosqlFieldString(m[1], doc) == m[2] && nosqlFieldIsString(m[1]), nil
	}
	if m := reNoSQLArith.FindStringSubmatch(clause); m != nil {
		left, errLeft := strconv.Atoi(m[1])
		right, errRight := strconv.Atoi(m[3])
		want, errWant := strconv.Atoi(m[5])
		if errLeft != nil || errRight != nil || errWant != nil {
			return false, nil
		}
		got := 0
		switch m[2] {
		case "*":
			got = left * right
		case "+":
			got = left + right
		default:
			got = left - right
		}
		if strings.HasPrefix(m[4], "!") {
			return got != want, nil
		}
		return got == want, nil
	}
	if m := reNoSQLLitEq.FindStringSubmatch(clause); m != nil {
		return m[1] == m[2], nil
	}
	if m := reNoSQLCall.FindStringSubmatch(clause); m != nil {
		// The interpreter tried to resolve an identifier that is this run's marker and said so.
		// It fires where the thrown Error does not, because a stack that catches a thrown Error
		// may still leak the interpreter's own ReferenceError.
		return false, nosqlEngineFault("MongoServerError: ReferenceError: " + m[1] + " is not defined :\n@:0:0\n")
	}
	return false, nil
}

// -------------------------------------------------------------------------------------------
// THE ROUTES
// -------------------------------------------------------------------------------------------

func registerNoSQLControls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/nosqli/mongo":       nosqlMongoHandler(true),
		"/nosqli/noscripting": nosqlMongoHandler(false),
		"/nosqli/where":       nosqlWhereHandler,
		"/nosqli/where/":      nosqlWhereHandler,
		"/nosqli/lucene":      nosqlLuceneHandler,
		"/nosqli/strict":      nosqlStrictHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/"), handler))
	}
}

// /nosqli/mongo passes the parsed filter straight into find(). /nosqli/noscripting is the same
// application with server-side JavaScript turned off, which is the commonest hardening there is
// and the one that kills every $where oracle: on that route the $where arm must report
// not_exploitable (scripting_disabled) in the engine's own words while the $expr arithmetic still
// fires. Nothing else in this container proves that the strongest oracle survives the hardening.
func nosqlMongoHandler(scripting bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		document, ok := nosqlFilterFrom(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "{\"ok\":false,\"error\":\"query parameter q is required\"}\n")
			return
		}
		rows, fault := nosqlRunFilter(document, scripting)
		if fault != nil {
			nosqlWriteFault(w, fault, true)
			return
		}
		nosqlWriteRows(w, rows, true)
	}
}

// /nosqli/where is the string-concatenated $where, which needs no object and is therefore the
// only arm a path segment, a plain cookie or a query slot with no bracket encoder can reach. It
// is, today, the one route in this section the class can actually exercise end to end.
//
// It serves the value from the path too, because the concatenation arm's tier-1 probe is planned
// only where the slot cannot carry an object at all, and a path segment is that slot.
func nosqlWhereHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "q", "name", "user", "search")
	if value == "" {
		if rest := strings.TrimPrefix(r.URL.Path, "/nosqli/where/"); rest != r.URL.Path && rest != "" {
			if decoded, err := url.PathUnescape(rest); err == nil {
				value = decoded
			} else {
				value = rest
			}
		}
	}
	if value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "{\"ok\":false,\"error\":\"query parameter q is required\"}\n")
		return
	}
	// The vulnerable line, spelled out: the value is concatenated into a JavaScript predicate.
	assembled := "this.name == '" + value + "'"
	rows := make([]nosqlDoc, 0, len(nosqlCollection))
	for _, doc := range nosqlCollection {
		keep, fault := nosqlJSPredicate(assembled, doc)
		if fault != nil {
			nosqlWriteFault(w, fault, true)
			return
		}
		if keep {
			rows = append(rows, doc)
		}
	}
	nosqlWriteRows(w, rows, true)
}

// /nosqli/lucene is the Elasticsearch surface: the value is spliced into a query_string and the
// parse error REFLECTS THE ASSEMBLED QUERY, which is what turns a bare parse failure into an
// attributable one. Its repair control matters as much as the break: an escaped quote must be
// inert, and if it errors too then whatever is breaking is not the quote and no break reported
// here can be attributed to the payload.
func nosqlLuceneHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "q", "name", "query", "search")
	if value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "{\"ok\":false,\"error\":\"query parameter q is required\"}\n")
		return
	}
	assembled := `name:"` + value + `"`
	if nosqlUnbalancedDoubleQuote(value) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "{\"error\":{\"root_cause\":[{\"type\":\"query_shard_exception\",\"reason\":%s}],"+
			"\"type\":\"search_phase_execution_exception\"},\"status\":400,\"canary\":%q}\n",
			strconv.Quote("Failed to parse query ["+assembled+"]"), canaryMarker)
		return
	}
	rows := make([]nosqlDoc, 0, len(nosqlCollection))
	widened := strings.Contains(value, " OR ")
	term := value
	if widened {
		term = strings.TrimSpace(value[:strings.Index(value, " OR ")])
	}
	term = strings.ReplaceAll(term, `\"`, `"`)
	for _, doc := range nosqlCollection {
		if widened || doc.Name == term {
			rows = append(rows, doc)
		}
	}
	nosqlWriteRows(w, rows, true)
}

// nosqlUnbalancedDoubleQuote counts the quotes a Lucene lexer would see, which is the unescaped
// ones. The escaped form is the repair control and must not break anything.
func nosqlUnbalancedDoubleQuote(value string) bool {
	count := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			continue
		}
		if value[i] == '"' {
			count++
		}
	}
	return count%2 == 1
}

// /nosqli/strict IS THE CONTROL THAT STOPS THIS CLASS CALLING EVERY VALIDATOR AN INJECTION.
//
// A JSON schema in front of the query refuses anything that is not a string, and it refuses the
// operator object and the BENIGN NUMBER with the same status and the same sentence. That
// identical treatment is the whole test: a bare number carries no dollar, is not an operator and
// cannot trip a NoSQL parser, so a rejection it shares with the operator probe came from the
// validator and the finding is dead. The verdict owed here is not_exploitable (schema_validated)
// and never clean, because a validator in front of a sink says nothing about the sink.
//
// It carries no canary marker: it is a place to stay silent.
func nosqlStrictHandler(w http.ResponseWriter, r *http.Request) {
	document, ok := nosqlFilterFrom(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "{\"ok\":false,\"error\":\"query parameter q is required\"}\n")
		return
	}
	for _, key := range nosqlSortedKeys(document) {
		// A JSON null unmarshals into a string WITHOUT error in Go, so a type check written as
		// Unmarshal-into-string quietly accepts it. Ajv with {"type":"string"} does not, and the
		// null is one of this class's two benign-type controls: letting it through would make the
		// pair disagree for a reason that is a Go detail and nothing to do with the validator.
		var value interface{}
		if err := json.Unmarshal(document[key], &value); err != nil {
			value = nil
		}
		if _, isString := value.(string); !isString {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"ok\":false,\"errors\":[{\"instancePath\":%s,\"schemaPath\":\"#/properties/name/type\","+
				"\"keyword\":\"type\",\"message\":\"must be string\"}]}\n", strconv.Quote("/"+key))
			return
		}
	}
	rows, fault := nosqlRunFilter(document, false)
	if fault != nil {
		// Unreachable: everything past the validator is a string equality. Answering honestly
		// rather than pretending is cheaper than a branch nobody can explain later.
		nosqlWriteFault(w, fault, false)
		return
	}
	nosqlWriteRows(w, rows, false)
}

// =================================================================================================
// CLIENT-SIDE TEMPLATE INJECTION: THE SILENT HALF
//
// WHAT THIS SECTION CAN AND CANNOT DO, STATED FIRST BECAUSE IT DECIDES WHICH ROUTES ARE HERE.
// A client-side template injection FINDING is a browser observation: the server's response carries
// the delimiters untouched and looks perfectly safe, and the product only appears after an engine
// in the page compiles the DOM. No HTTP route can produce that, and /csti/angular plus the
// emulated engine beside it is already everything the browser tier needs.
//
// What HTTP can decide is every one of the class's NEGATIVES, because each of them is read from
// the served document itself: a precompiled Angular, a reflection inside ng-non-bindable, braces
// stripped before they arrive, a value that was never percent-decoded, a page that already prints
// the product, an application that does the multiplication itself. Those are the rows that tell a
// working detector from `return true`, and not one of them had a route.
//
// ONE OF THEM IS ALSO A FIRE. /csti/jinja evaluates {{ }} ON THE SERVER, which is the one thing
// that must never be reported as client-side template injection: the class owes
// cannot_determine (server_side_evaluation) there, with the hand-off to the server-side class,
// and it is the only CSTI row this container can make move without a browser.
// =================================================================================================

// cstiHTTPProduct is the class's HTTP pair, 7919*6271, and cstiBrowserProduct is its browser pair,
// 7793*6299. They are DIFFERENT NUMBERS on purpose: the tier that saw the product is the tier the
// evidence belongs to, and a single pair would make a server-side render and a browser render
// indistinguishable in the evidence.
const (
	cstiHTTPProduct    = "49660049"
	cstiBrowserProduct = "49088107"
)

var (
	reCSTIMustache = regexp.MustCompile(`\{\{\s*(\d{1,10})\s*\*\s*(\d{1,10})\s*\}\}`)
	reCSTIProduct  = regexp.MustCompile(`(\d{1,10})\s*\*\s*(\d{1,10})`)
	reCSTIBraces   = regexp.MustCompile(`[{}]`)
)

func registerCSTIControls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		"/csti/jinja":               cstiJinjaHandler,
		"/csti/escaped":             cstiEscapedHandler,
		"/csti/nonbindable":         cstiNonBindableHandler,
		"/csti/inscript":            cstiInScriptHandler,
		"/csti/pct-literal":         cstiPctLiteralHandler,
		"/csti/product-in-baseline": cstiProductInBaselineHandler,
		"/csti/calculator":          cstiCalculatorHandler,
		"/csti/aot":                 cstiAOTHandler,
		"/csti/vue-runtime":         cstiVueRuntimeHandler,
		"/csti/corpus-blocked":      cstiCorpusBlockedHandler,
		"/csti/blocked.js":          cstiBlockedScriptHandler,
		"/csti/angular-attr":        cstiAngularAttrHandler,
		"/csti/angular-hash":        cstiAngularHashHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// cstiAngularShell is the page every AngularJS-bearing control below shares: the engine is
// detectable from the served HTML alone (an ng-app attribute and the script src), which is what
// makes these routes decidable without a populated asset corpus.
func cstiAngularShell(w http.ResponseWriter, view, extra string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title>
<script src="/csti/angular.min.js"></script></head>
<body ng-app>
<h1>Search</h1>
%s
%s
</body></html>
`, view, extra)
}

// THE ROUTE THAT MUST NOT BECOME A CSTI FINDING. Jinja2 renders the page on the SERVER and
// evaluates {{ }} before the browser ever sees it, so the product is in the HTTP response. An
// AngularJS application served from a Jinja2 template is one of the commonest stacks there is,
// and a class that read its own product out of the HTTP body would report client-side template
// injection on a server-side one: the wrong class, the wrong tool and the wrong fix.
//
// The verdict owed here is cannot_determine (server_side_evaluation) with the hand-off, and this
// is the one CSTI row an oracle with no browser in it can make move.
func cstiJinjaHandler(w http.ResponseWriter, r *http.Request) {
	rendered := reCSTIMustache.ReplaceAllStringFunc(queryParam(r, "q", "search"), func(match string) string {
		m := reCSTIMustache.FindStringSubmatch(match)
		left, errLeft := strconv.Atoi(m[1])
		right, errRight := strconv.Atoi(m[2])
		if errLeft != nil || errRight != nil {
			return match
		}
		return strconv.Itoa(left * right)
	})
	cstiAngularShell(w, `<div id="view">You searched for `+html.EscapeString(rendered)+`</div>`,
		`<!-- rendered server-side by the canary oracle's emulated Jinja2 -->`)
}

// BRACES STRIPPED, WITH NOTHING IN THEIR PLACE. The marker comes back and the delimiters do not,
// so the payload demonstrably arrived and was demonstrably removed. That is a legitimate CLEAN
// (delimiters_stripped) and it is the half a fire-only rig never tests: without it, "the product
// did not appear" and "the delimiters never got there" are one observation wearing two hats.
func cstiEscapedHandler(w http.ResponseWriter, r *http.Request) {
	stripped := reCSTIBraces.ReplaceAllString(queryParam(r, "q", "search"), "")
	cstiAngularShell(w, `<div id="view">You searched for `+html.EscapeString(stripped)+`</div>`, "")
}

// A NAMED DEFENCE, WHICH IS not_exploitable AND NOT CLEAN. ng-non-bindable tells AngularJS not to
// compile the region, so the delimiters arrive, stay intact, and are never evaluated. The
// distinction matters to an operator: the sink is there and one attribute is what stops it.
func cstiNonBindableHandler(w http.ResponseWriter, r *http.Request) {
	cstiAngularShell(w, `<span ng-non-bindable id="view">You searched for `+
		html.EscapeString(queryParam(r, "q", "search"))+`</span>`, "")
}

// THE ENGINE DOES NOT COMPILE SCRIPT CONTENT, so a reflection inside <script> is not a candidate
// however intact the delimiters are. The value is JSON-quoted, which keeps this route from being
// an accidental script-injection positive: two classes firing on one page and neither result
// meaning anything is the outcome every route in this file is arranged to avoid.
func cstiInScriptHandler(w http.ResponseWriter, r *http.Request) {
	quoted := strconv.Quote(queryParam(r, "q", "search"))
	quoted = strings.ReplaceAll(quoted, "<", `<`)
	quoted = strings.ReplaceAll(quoted, ">", `>`)
	cstiAngularShell(w, `<div id="view">Search</div>`,
		"<script>var lastQuery = "+quoted+";</script>")
}

// THE VALUE IS NEVER PERCENT-DECODED, so the braces come back as %7B and %7D and no engine
// anywhere will ever compile them. The delimiters were not delivered, which is
// cannot_determine and never clean: nothing was tested, and a class that called this clean has
// told the operator a slot is safe when the truth is that its payload never arrived.
func cstiPctLiteralHandler(w http.ResponseWriter, r *http.Request) {
	raw := ""
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		name, value, found := strings.Cut(pair, "=")
		if found && (name == "q" || name == "search") {
			raw = value
			break
		}
	}
	cstiAngularShell(w, `<div id="view">You searched for `+html.EscapeString(raw)+`</div>`, "")
}

// THE PRODUCT IS ALREADY ON THE PAGE. An unperturbed response carrying 49088107 makes the browser
// pair unreadable: every probe "succeeds" against a number that was there before anything was
// sent. The class must notice and switch to its fallback pair rather than report a finding on
// digits it did not cause, and there is no other way to test that it does.
func cstiProductInBaselineHandler(w http.ResponseWriter, r *http.Request) {
	cstiAngularShell(w, `<div id="view">You searched for `+
		html.EscapeString(queryParam(r, "q", "search"))+`</div>`,
		`<footer>order reference `+cstiBrowserProduct+`</footer>`)
}

// THE CALCULATOR, AND WITHOUT THIS ROUTE A CALCULATOR IS A CSTI FINDING. The application itself
// multiplies the two numbers in the parameter, so the product appears for the probe AND for the
// negative control, which is the definition of a contaminated control: the observation is real
// and it is not evidence of anything. The verdict owed is cannot_determine (control_contaminated).
func cstiCalculatorHandler(w http.ResponseWriter, r *http.Request) {
	value := queryParam(r, "q", "search")
	answer := ""
	if m := reCSTIProduct.FindStringSubmatch(value); m != nil {
		left, errLeft := strconv.Atoi(m[1])
		right, errRight := strconv.Atoi(m[2])
		if errLeft == nil && errRight == nil {
			answer = `<p id="answer">` + m[1] + ` times ` + m[2] + ` is ` + strconv.Itoa(left*right) + `</p>`
		}
	}
	cstiAngularShell(w, `<div id="view">You searched for `+html.EscapeString(value)+`</div>`+answer, "")
}

// AHEAD-OF-TIME COMPILED ANGULAR. Angular 2+ compiles its templates at build time, so server HTML
// is never interpolated and the answer is not_applicable (angular_aot) at zero requests. The
// markers a detector reads are ng-version, the _ngcontent- attribute scopes and <app-root>, and
// they are here in the served document because that is where the class reads them.
func cstiAOTHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title></head>
<body>
<app-root ng-version="17.1.0" _nghost-ng-c2037349081>
<h1 _ngcontent-ng-c2037349081>Search</h1>
<div _ngcontent-ng-c2037349081 id="view">You searched for %s</div>
</app-root>
</body></html>
`, html.EscapeString(queryParam(r, "q", "search")))
}

// THE VUE BUILD DISCRIMINATOR'S NEGATIVE. Only the FULL build compiles an in-DOM template, so a
// mustache reflected into server HTML against a runtime-only build is never compiled at all. The
// build names itself in the warning string, which is what the discriminator reads.
//
// KNOWN LIMITATION, STATED RATHER THAN HIDDEN: the class reads that string out of the fetched
// ASSET CORPUS and not out of the served HTML, and the corpus is not populated in this build, so
// this route cannot be decided today however it is written. It is here so that the day the
// corpus lands, the control does too. Reported.
func cstiVueRuntimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title>
<script src="/csti/vue.runtime.global.js"></script></head>
<body>
<div id="app">You searched for %s</div>
<script>/* You are running the runtime-only build of Vue where the template compiler is not
available. Either pre-compile the templates into render functions, or use the compiler-included
build. Component provided template option but runtime compilation is not supported. */</script>
</body></html>
`, html.EscapeString(queryParam(r, "q", "search")))
}

// A PAGE WHOSE ONLY SCRIPT IS UNREADABLE. The framework could not be determined, and that is
// cannot_determine (framework_undetermined) and NOT not_applicable: "I could not tell" and "there
// is no engine here" are different answers, and collapsing them is how a failed detection reads
// as a clean scan.
func cstiCorpusBlockedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><title>canary search</title>
<script src="/csti/blocked.js"></script></head>
<body>
<div id="view">You searched for %s</div>
</body></html>
`, html.EscapeString(queryParam(r, "q", "search")))
}

func cstiBlockedScriptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, "403 Forbidden\n")
}

// BRACES STRIPPED FROM TEXT, ATTRIBUTE VALUES UNFILTERED. It is the commonest real shape of this
// bug and it is the reason the class has an attribute probe at all: the mustache route is closed
// and the directive route is wide open.
//
// The reflection escapes < and > and leaves the quote alone. That is deliberate and it is the
// narrowest thing that makes the route what it is: the class's attribute probe must be able to
// create an attribute, and no payload here can open a tag, so the page cannot double as a
// markup-injection positive for another class.
func cstiAngularAttrHandler(w http.ResponseWriter, r *http.Request) {
	value := reCSTIBraces.ReplaceAllString(queryParam(r, "q", "search"), "")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	cstiAngularShell(w, `<div id="view" data-query="`+value+`">Search</div>`, "")
}

// THE FRAGMENT PATH. $location in hash mode renders the fragment, and a fragment never leaves the
// browser: RFC 3986 section 3.5. The HTTP tier is therefore not_applicable here BY CONSTRUCTION,
// and this endpoint is the only place the navigation tier's fragment slot can ever be proved.
func cstiAngularHashHandler(w http.ResponseWriter, r *http.Request) {
	cstiAngularShell(w, `<div id="view">Fragment: <span id="frag"></span></div>`,
		`<script>document.getElementById("frag").textContent = location.hash.replace(/^#/, "");</script>`)
}
