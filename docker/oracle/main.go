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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// canaryMarker appears in every vulnerable response and nowhere else. It is what the framework greps
// for when deciding whether a tool actually reached this service, and it is deliberately unusual
// enough that it cannot appear by chance in a target's own output.
const canaryMarker = "ARS0N_CANARY_OK"

func main() {
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

	addr := ":" + envOr("ORACLE_PORT", "8000")
	log.Printf("canary oracle listening on %s", addr)
	log.Fatal((&http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}).ListenAndServe())
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
	visible := id == "" || id == "1"
	if m := reAlwaysT.FindStringSubmatch(id); m != nil {
		visible = m[2] == m[3]
	}
	if reUnionSel.MatchString(id) {
		visible = true
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
