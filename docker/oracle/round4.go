package main

// ROUND 4 CONTROLS: the routes the five newest classes asked for, plus the one route this whole
// round exists to answer a question about.
//
// THE QUESTION. The operator's real target is a JSON REST API that ECHOES NOTHING. Before this
// round only two classes of fourteen could reach a conclusion on that shape, because every other
// class gated itself on seeing its own marker come back. Nothing in docker/oracle had that shape
// either: /clean/inert is an HTML page and /clean/echo is the opposite of the problem. So
// /api/items below is an echo-free JSON API and every route in this file answers JSON, which
// makes the whole round-4 route set a corpus of the shape that matters rather than one route
// bolted on the end.
//
// WHY THESE ROUTES ARE MOSTLY NEGATIVES. Eleven of the routes here exist to keep a class SILENT.
// A positive fixture only shows that a detector can fire; it is the negative that says the
// detector measures the thing it claims to measure. /cors/allowlist, /hosthdr/echo, /hpp/last,
// /orm/othererror and /pp/frozen are each the single route that separates their class from a
// grep, and each one is named as such in its own class's OracleCases.
//
// NOTHING HERE IS A REAL VULNERABILITY. The prototype pollution below is a Go map with a string
// in it, the ORM error is a string constant, the traversal is a map lookup, and no template
// engine, no ORM and no JavaScript runtime is in this image. The detectors cannot tell the
// difference, which is the point of a control.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

func registerRound4Controls(mux *http.ServeMux, marked func(string, http.HandlerFunc) http.HandlerFunc) {
	for path, handler := range map[string]http.HandlerFunc{
		// The shape of the operator's target.
		"/api/items": apiItemsHandler,

		// CORS(28)
		"/cors/reflect":        corsReflectHandler(true),
		"/cors/reflectnocreds": corsReflectHandler(false),
		"/cors/allowlist":      corsAllowlistHandler,
		"/cors/null":           corsNullHandler,
		"/cors/rawecho":        corsRawEchoHandler,
		"/cors/starcreds":      corsStarCredsHandler,
		"/cors/portblind":      corsPortBlindHandler,
		"/cors/originlist":     corsOriginListHandler,
		"/cors/preset":         corsPresetHandler,
		"/cors/cacheable":      corsCacheableHandler,

		// HOSTHDR(20)
		"/hosthdr/absurl":      hostHdrAbsURLHandler(false),
		"/hosthdr/cacheable":   hostHdrAbsURLHandler(true),
		"/hosthdr/location":    hostHdrLocationHandler(http.StatusFound),
		"/hosthdr/loc200":      hostHdrLocationHandler(http.StatusOK),
		"/hosthdr/echo":        hostHdrEchoHandler,
		"/hosthdr/originalurl": hostHdrOriginalURLHandler,
		"/hosthdr/portconcat":  hostHdrPortConcatHandler,
		"/hosthdr/nohttp":      hostHdrNoHTTPHandler,
		"/hosthdr/wrapinert":   hostHdrWrapInertHandler,

		// HPP(26)
		"/hpp/first":     hppPrecedenceHandler(hppFirst, false),
		"/hpp/last":      hppPrecedenceHandler(hppLast, false),
		"/hpp/arity":     hppPrecedenceHandler(hppLast, true),
		"/hpp/reparse":   hppReparseHandler("&"),
		"/hpp/semicolon": hppReparseHandler(";"),

		// ORM-LEAK(29)
		"/orm/django":     ormDjangoHandler,
		"/orm/djangoprod": ormDjangoProdHandler,
		"/orm/othererror": ormOtherErrorHandler,

		// PP-SERVER(22)
		"/pp/express":   ppMergeHandler(ppOpts{}),
		"/pp/ctoronly":  ppMergeHandler(ppOpts{BlockProtoKey: true}),
		"/pp/frozen":    ppMergeHandler(ppOpts{Frozen: true}),
		"/pp/htmlonly":  ppMergeHandler(ppOpts{HTML: true}),
		"/pp/norestore": ppMergeHandler(ppOpts{IgnoreRestore: true}),

		// The non-reflective arms of SSTI(1), ELI(2) and TRAVERSAL(13).
		"/ssti/blind":      blindParseHandler(blindSSTI),
		"/ssti/lengthecho": blindLengthEchoHandler,
		"/eli/blind":       blindParseHandler(blindELI),
		"/trav/blind":      travBlindHandler,
		"/trav/append":     travAppendHandler,
		"/trav/ignored":    travIgnoredHandler,
	} {
		mux.HandleFunc(path, marked(strings.TrimPrefix(path, "/"), handler))
	}
}

// ---------------------------------------------------------------------------------------------
// SHARED
// ---------------------------------------------------------------------------------------------

// r4JSON writes a JSON document and nothing else. Every route in this file answers through it or
// through a deliberate variation on it, so "the body is JSON and carries none of the request" is
// a property of the file rather than a promise in each handler.
func r4JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	_, _ = w.Write(append(b, '\n'))
}

// r4Sanitise strips the bytes that would make a JSON document invalid or would turn one of these
// routes into a CRLF positive by accident. A route that also injected headers would make every
// CRLF cell in the matrix unreadable, and CRLF has its own routes.
func r4Sanitise(s string) string {
	return strings.NewReplacer("\r", "", "\n", "", `"`, "", `\`, "").Replace(s)
}

// r4Digest is how these routes vary their answer WITHOUT echoing. Fixed length on purpose: a
// response whose length tracked its input would fire every length differential in the registry
// and the matrix would be measuring this file instead of the classes.
func r4Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// r4Answer is the one document every inert route in this file returns.
var r4Answer = map[string]any{
	"ok":     true,
	"items":  []any{map[string]any{"id": 1, "sku": "RW-GIN-700"}, map[string]any{"id": 2, "sku": "RW-RYE-700"}},
	"page":   1,
	"canary": canaryMarker,
}

// r4KnownNames are the parameter names this file's routes expect. A name outside the set is what
// ORM-LEAK's name_slot encoder produces, and it is the only signal the /orm routes act on.
var r4KnownNames = map[string]bool{
	"q": true, "id": true, "page": true, "search": true, "sort": true, "filter": true,
	"tpl": true, "url": true, "next": true, "value": true, "file": true, "redirect": true,
	"name": true, "limit": true, "offset": true,
}

// r4UnknownName returns the first query parameter name this route does not recognise.
func r4UnknownName(r *http.Request) (string, bool) {
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		key, _, _ := strings.Cut(pair, "=")
		if key == "" {
			continue
		}
		if !r4KnownNames[key] {
			return key, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// THE SHAPE OF THE OPERATOR'S TARGET
// ---------------------------------------------------------------------------------------------

// /api/items is a JSON REST API that reads its parameters, acts on none of them in any way a
// response can show, and ECHOES NOTHING. It is not a trick route: it is what most of the
// operator's live corpus looks like, and it is the only honest test of whether a class that
// cannot see its own marker come back can still reach a conclusion.
//
// The verdict owed here is CLEAN from every class whose oracle does not need reflection, and
// cannot_determine from every class whose oracle does. Which classes land where is the number
// this round exists to produce, and it is not asserted here: it is measured.
func apiItemsHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, r4Answer)
}

// ---------------------------------------------------------------------------------------------
// CORS(28)
// ---------------------------------------------------------------------------------------------

const (
	acao = "Access-Control-Allow-Origin"
	acac = "Access-Control-Allow-Credentials"
)

// corsIsOrigin is the parse a correctly written server does before it compares anything. A bare
// hostname is not an origin (RFC 6454 requires a scheme) and neither is a comma-separated list:
// the Fetch standard sends exactly one. The routes that DO accept those are the bugs.
func corsIsOrigin(v string) bool {
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return false
	}
	rest := v[strings.Index(v, "://")+3:]
	return rest != "" && !strings.ContainsAny(rest, ",/ ?#")
}

// corsReflectHandler copies a syntactically valid Origin straight back. With credentials it is
// the worst shape there is; without them it is still a cross-origin read of everything this
// endpoint serves. The two need different reports, which is why one handler serves two routes
// and the only difference between them is one header.
func corsReflectHandler(creds bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r4Sanitise(r.Header.Get("Origin")); corsIsOrigin(o) {
			w.Header().Set(acao, o)
			w.Header().Set("Vary", "Origin")
			if creds {
				w.Header().Set(acac, "true")
			}
		}
		r4JSON(w, http.StatusOK, r4Answer)
	}
}

// THE MOST IMPORTANT NEGATIVE IN THE CLASS. A correctly configured API: it emits a CORS grant on
// every request and the grant always names ITS OWN origin. A detector built on "the response
// carries Access-Control-Allow-Origin" fires here, and on a large fraction of every real corpus.
// The verdict owed is clean.
func corsAllowlistHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(acao, "http://"+r.Host)
	w.Header().Set(acac, "true")
	w.Header().Set("Vary", "Origin")
	r4JSON(w, http.StatusOK, r4Answer)
}

// Answers any unrecognised origin with the literal null. A sandboxed iframe, a redirected request
// and a file:// page all send Origin: null, so a grant to null is a grant to an attacker who can
// arrange any one of them.
func corsNullHandler(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		w.Header().Set(acao, "null")
		w.Header().Set(acac, "true")
	}
	r4JSON(w, http.StatusOK, r4Answer)
}

// No parse at all: whatever arrived in Origin goes into the grant, so the bare-hostname control
// is echoed too. That is a WORSE answer than reflection rather than a broken control, because it
// means the allowlist the developers believe they wrote is never consulted.
func corsRawEchoHandler(w http.ResponseWriter, r *http.Request) {
	if o := r4Sanitise(r.Header.Get("Origin")); o != "" {
		w.Header().Set(acao, o)
		w.Header().Set(acac, "true")
	}
	r4JSON(w, http.StatusOK, r4Answer)
}

// The pair every browser refuses. Suspicious and not a finding: a class that called it a finding
// would be reporting a cross-origin read that cannot happen.
func corsStarCredsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(acao, "*")
	w.Header().Set(acac, "true")
	r4JSON(w, http.StatusOK, r4Answer)
}

// Parses the Origin, compares the HOSTNAME only, and rebuilds the grant from the parse, so the
// port is dropped. Byte equality against what we sent cannot see this and the class needs its
// second reading for it.
func corsPortBlindHandler(w http.ResponseWriter, r *http.Request) {
	o := r4Sanitise(r.Header.Get("Origin"))
	if corsIsOrigin(o) {
		scheme, rest, _ := strings.Cut(o, "://")
		host, _, _ := strings.Cut(rest, ":")
		w.Header().Set(acao, scheme+"://"+host)
		w.Header().Set(acac, "true")
	}
	r4JSON(w, http.StatusOK, r4Answer)
}

// Splits the header on commas, checks the FIRST entry against its allowlist and reflects the
// SECOND. A list parser in front of an allowlist is how an origin gets smuggled past a check.
func corsOriginListHandler(w http.ResponseWriter, r *http.Request) {
	o := r4Sanitise(r.Header.Get("Origin"))
	if parts := strings.Split(o, ","); len(parts) >= 2 {
		if second := strings.TrimSpace(parts[1]); corsIsOrigin(second) {
			w.Header().Set(acao, second)
			w.Header().Set(acac, "true")
		}
	}
	r4JSON(w, http.StatusOK, r4Answer)
}

// THE SIGNATURE IS IN THE BASELINE. A grant naming a host under .cors.invalid on every response
// including the unperturbed one, as an intermediary replaying a cached response would produce.
// Every arm of the class would otherwise fire. cannot_determine, never a finding.
func corsPresetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(acao, "https://preset.cors.invalid")
	w.Header().Set(acac, "true")
	r4JSON(w, http.StatusOK, r4Answer)
}

// STORABLE. Cache-Control: public with a lifetime, no Set-Cookie, and no Vary on the header we
// would perturb. An Origin header is unkeyed on essentially every shared cache, so a reflected
// grant stored here is served to the next user. Nothing may be sent; the verdict owed is
// not_probed, and it must not be clean.
func corsCacheableHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	if o := r4Sanitise(r.Header.Get("Origin")); corsIsOrigin(o) {
		w.Header().Set(acao, o)
		w.Header().Set(acac, "true")
	}
	r4JSON(w, http.StatusOK, r4Answer)
}

// ---------------------------------------------------------------------------------------------
// HOSTHDR(20)
// ---------------------------------------------------------------------------------------------

// hhValue is the routing header these routes read, in the order a framework behind a proxy reads
// them. It falls back to Host so the route is honest about what it is: a site that trusts the
// client's idea of its own hostname.
func hhValue(r *http.Request) string {
	for _, n := range []string{"X-Forwarded-Host", "X-Original-Host", "X-Host", "X-Forwarded-Server"} {
		if v := r.Header.Get(n); v != "" {
			return r4Sanitise(v)
		}
	}
	return r4Sanitise(r.Host)
}

// Builds an absolute URL out of the routing header and puts it in the body, which is what a
// password-reset template does. storable=true is the same sink behind a cacheable response,
// where nothing may be sent at all.
func hostHdrAbsURLHandler(storable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if storable {
			w.Header().Set("Cache-Control", "public, max-age=600")
		}
		r4JSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"reset_url": "https://" + hhValue(r) + "/account/reset?token=8f2c",
			"canary":    canaryMarker,
		})
	}
}

// A Location built from the header. On a 302 a browser acts on it with nothing for the user to
// read, which is why the Location arm outranks the body arm. On a 200 NO CLIENT FOLLOWS IT, so
// the same bytes must not score, and that is the whole reason /hosthdr/loc200 exists.
func hostHdrLocationHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+hhValue(r)+"/account/reset")
		r4JSON(w, status, r4Answer)
	}
}

// THE MOST IMPORTANT NEGATIVE IN THE CLASS. The value is in the response, as plain text, with no
// scheme and no slashes in front of it. A detector that searched for the bytes fires here and on
// every framework with a verbose error page. The verdict owed is clean.
func hostHdrEchoHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"debug": map[string]any{"forwarded_host": hhValue(r), "upstream": "app-7"},
	})
}

// X-Original-URL treated as a base. A bare authority in this header is a relative path and tests
// nothing, which is why the class ships a second payload family for it.
func hostHdrOriginalURLHandler(w http.ResponseWriter, r *http.Request) {
	base := r4Sanitise(r.Header.Get("X-Original-URL"))
	if base == "" {
		base = r4Sanitise(r.Header.Get("X-Rewrite-URL"))
	}
	if base == "" {
		base = "/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	r4JSON(w, http.StatusOK, map[string]any{"ok": true, "logout": base + "logout", "canary": canaryMarker})
}

// Concatenates the RAW header into a URL rather than parsing it, so a port in the header survives
// into the authority. A sink that copies and a sink that splits on the colon are different bugs,
// and an attacker who can name a port is in a different position from one who cannot.
func hostHdrPortConcatHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, map[string]any{
		"ok": true, "cdn": "https://" + hhValue(r) + "/static/app.js", "canary": canaryMarker,
	})
}

// Rejects any X-Rewrite-URL containing the string http and otherwise treats the value as a base.
// It is the commonest filter there is, and a class shipping only an https payload reports clean
// on every site that has one.
func hostHdrNoHTTPHandler(w http.ResponseWriter, r *http.Request) {
	v := r4Sanitise(r.Header.Get("X-Rewrite-URL"))
	if v == "" {
		v = r4Sanitise(r.Header.Get("X-Original-URL"))
	}
	if v == "" || strings.Contains(strings.ToLower(v), "http") {
		r4JSON(w, http.StatusOK, r4Answer)
		return
	}
	r4JSON(w, http.StatusOK, map[string]any{"ok": true, "next": v + "account", "canary": canaryMarker})
}

// Wraps WHATEVER it is given in https:// and prints it, so even the inert control's value lands
// in authority position. On such a route the positional test cannot separate a URL built from our
// value from one that would have been built from anything, and the verdict owed is
// detector_unverified rather than a finding.
func hostHdrWrapInertHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, map[string]any{
		"ok": true, "site": "https://" + hhValue(r) + "/", "canary": canaryMarker,
	})
}

// ---------------------------------------------------------------------------------------------
// HPP(26)
// ---------------------------------------------------------------------------------------------

type hppPick int

const (
	hppFirst hppPick = iota
	hppLast
)

// hppValues returns every raw value of the named parameter IN WIRE ORDER, which is the fact this
// whole class turns on and the one Go's r.URL.Query() throws away by handing back a map.
func hppValues(r *http.Request, name string) []string {
	var out []string
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if k == name {
			out = append(out, v)
		}
	}
	return out
}

// hppSlot is the parameter these routes render from. A vector naming something else would make
// the route silently see nothing, which is the failure this container exists to prevent, so the
// first known name present wins and the fallback is the first pair on the wire.
func hppSlot(r *http.Request) []string {
	for _, n := range []string{"q", "id", "search", "page", "value", "name"} {
		if v := hppValues(r, n); len(v) > 0 {
			return v
		}
	}
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		if k, _, _ := strings.Cut(pair, "="); k != "" {
			return hppValues(r, k)
		}
	}
	return nil
}

// A precedence differential and NOTHING ELSE: the answer is a fixed-length digest of the chosen
// occurrence, so the response depends on WHICH occurrence the parser picked and carries none of
// it. requireDuplicate is the arity route: it 400s when the parameter arrives once, which is what
// separates "the first occurrence is ignored" from "the first occurrence is counted but not read".
func hppPrecedenceHandler(pick hppPick, requireDuplicate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vals := hppSlot(r)
		if len(vals) == 0 {
			r4JSON(w, http.StatusOK, r4Answer)
			return
		}
		if requireDuplicate && len(vals) < 2 {
			r4JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "parameter_arity"})
			return
		}
		chosen := vals[0]
		if pick == hppLast {
			chosen = vals[len(vals)-1]
		}
		r4JSON(w, http.StatusOK, map[string]any{"ok": true, "result": r4Digest(chosen), "canary": canaryMarker})
	}
}

// Splits its own parameter's DECODED value on a separator and takes a second pair seriously,
// which is what a downstream client library does when it forwards the value into another query
// string. The effect is STRUCTURAL: the document grows two keys. It has to be, because arm S's
// oracle was rebuilt on structure after a plain body comparison called every echoing route a
// re-parse.
func hppReparseHandler(sep string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vals := hppSlot(r)
		if len(vals) == 0 {
			r4JSON(w, http.StatusOK, r4Answer)
			return
		}
		parts := strings.Split(r4DecodeQuery(vals[0]), sep)
		doc := map[string]any{"ok": true, "result": r4Digest(parts[0]), "canary": canaryMarker}
		if len(parts) > 1 && strings.Contains(parts[1], "=") {
			k, v, _ := strings.Cut(parts[1], "=")
			doc["extra_count"] = len(parts) - 1
			doc["extra_digest"] = r4Digest(k + v)
		}
		r4JSON(w, http.StatusOK, doc)
	}
}

// r4DecodeQuery is a percent-decode that does not fail. A malformed escape is not a reason to
// drop the input: a vulnerable application concatenates whatever arrived.
func r4DecodeQuery(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			var v int
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &v); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------------------------
// ORM-LEAK(29)
// ---------------------------------------------------------------------------------------------

// ormChoices is the column list a Django FieldError leaks, which is the evidence this class hands
// the operator: the real table shape, from one request, with no blind enumeration.
const ormChoices = "created_at, id, owner_id, price_cents, sku, slug, title, updated_at"

// THE ESCAPED APOSTROPHE IS THE POINT. Django's technical 500 page runs the exception value
// through django.utils.html.escape, so on the DEBUG=True deployment where this error is visible
// the quotes arrive as &#x27; and a detector matching only the plain form is silent on every real
// instance of the bug it was written for.
func ormDjangoHandler(w http.ResponseWriter, r *http.Request) {
	name, ok := r4UnknownName(r)
	if !ok {
		r4JSON(w, http.StatusOK, r4Answer)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>FieldError at /api/items</title></head>
<body><div id="summary"><h1>FieldError at /api/items</h1>
<pre class="exception_value">Cannot resolve keyword &#x27;%s&#x27; into field. Choices are: %s</pre>
<table><tr><th>Request Method:</th><td>GET</td></tr>
<tr><th>Django Version:</th><td>6.1.1</td></tr>
<tr><th>Exception Type:</th><td>FieldError</td></tr></table></div>
<div id="traceback"><p>catalogue/views.py in list_items, line 42</p></div>
<p>%s</p></body></html>
`, name, ormChoices, canaryMarker)
}

// THE SAME APPLICATION WITH DEBUG=False. A bare 500 with no keyword and no column list. The
// degradation must be HANDLED rather than asserted: something about our parameter name broke the
// view, so this is suspicious at a status differential, never a finding and never a clean.
func ormDjangoProdHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := r4UnknownName(r); !ok {
		r4JSON(w, http.StatusOK, r4Answer)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, "<h1>Server Error (500)</h1>\n")
}

// A REAL FieldError, in every response including the baseline, naming a keyword that is not ours.
// The phrase is the CONTEXT and the quoted token is the EVIDENCE, and this route is where that
// claim is tested rather than demonstrated. A detector that greps for the phrase fires here.
func ormOtherErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Catalogue</title></head>
<body><h1>Catalogue</h1><p>Two products.</p>
<div class="debug-footer"><p>Last logged application error, retained for support:</p>
<pre>FieldError: Cannot resolve keyword &#x27;author&#x27; into field. Choices are: %s</pre></div>
<p>%s</p></body></html>
`, ormChoices, canaryMarker)
}

// ---------------------------------------------------------------------------------------------
// PP-SERVER(22)
// ---------------------------------------------------------------------------------------------

// ppOpts selects which of the five shapes a merge endpoint has. One handler, five routes, because
// the difference between them is exactly one predicate each and five near-copies of a recursive
// merge would drift apart.
type ppOpts struct {
	BlockProtoKey bool // filters the literal __proto__ key and nothing else
	Frozen        bool // the merge runs and the prototype refuses the write
	HTML          bool // the merge runs and the oracle is unreadable
	IgnoreRestore bool // accepts the pollution and ignores the restoring value
}

// ppProto is the emulated Object.prototype, one per route. It is process-global exactly as the
// real thing is, which is WHY the class pairs every polluter with its restore in the same batch
// and why the runner's budget is checked before the first byte rather than between requests.
var ppProto sync.Map // route -> indent string

func ppMergeHandler(o ppOpts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.Path
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		ppMerge(route, body, o, 0)

		if o.HTML {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><title>settings</title><h1>Saved</h1><p>%s</p>\n", canaryMarker)
			return
		}
		stored, _ := ppProto.Load(route)
		indent, _ := stored.(string)
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.MarshalIndent(r4Answer, "", ppGap(indent))
		_, _ = w.Write(append(b, '\n'))
	}
}

// ppGap is JSON.stringify's rule for a string space argument, and getting it wrong made this
// route lie about the class.
//
// ECMA-262 24.5.2: when the space argument is a string longer than ten code units, the gap is its
// FIRST TEN. Go's json.MarshalIndent uses the whole string. Measured with the full sixteen-byte
// indent, PP-SERVER read CLEAN on this route: its token is the marker's first ten bytes, so
// stripping that token left the other six bytes behind, the stripped body was not JSON, and the
// gate that requires "a JSON document indented with our token" refused a response that was
// exactly that. A green tick on a polluted endpoint, produced entirely by the oracle's own
// infidelity. The class was right and the emulation was wrong.
func ppGap(space string) string {
	if len(space) > 10 {
		return space[:10]
	}
	return space
}

// ppMerge is the recursive merge itself, which is the whole bug: a key named __proto__ reached at
// ANY depth writes to the prototype instead of to the object, so a nested JSON node is as good as
// a top-level one. The depth cap is not a defence, it is a stack guard.
func ppMerge(route string, node map[string]any, o ppOpts, depth int) {
	if node == nil || depth > 12 {
		return
	}
	for k, v := range node {
		child, isObj := v.(map[string]any)
		if !isObj {
			continue
		}
		switch {
		case k == "__proto__" && !o.BlockProtoKey:
			ppWriteProto(route, child, o)
		case k == "constructor":
			if proto, ok := child["prototype"].(map[string]any); ok {
				ppWriteProto(route, proto, o)
			}
		default:
			ppMerge(route, child, o, depth+1)
		}
	}
}

// ppWriteProto is where Object.freeze and a route that refuses to be restored both live. The
// restoring value is the NUMBER 0, which in Express means no indent at all, and a route that
// ignores it leaves the process polluted: the loudest code path in the class and, until this
// route existed, one nobody had ever seen run.
func ppWriteProto(route string, gadget map[string]any, o ppOpts) {
	v, ok := gadget["json spaces"]
	if !ok || o.Frozen {
		return
	}
	switch t := v.(type) {
	case string:
		ppProto.Store(route, t)
	case float64:
		if o.IgnoreRestore {
			return
		}
		if t == 0 {
			ppProto.Delete(route)
			return
		}
		ppProto.Store(route, strings.Repeat(" ", int(t)))
	}
}

// ---------------------------------------------------------------------------------------------
// THE NON-REFLECTIVE ARMS: SSTI(1) AND ELI(2)
// ---------------------------------------------------------------------------------------------

type blindKind int

const (
	blindSSTI blindKind = iota
	blindELI
)

// blindParseHandler is the route shape both non-reflective arms were built for and neither had:
// the value goes into an expression the response NEVER SHOWS, and a value that does not parse
// fails earlier and differently. Nothing of the request comes back under any outcome, so a class
// gated on reflection is structurally silent here and the whole question is whether the parse
// differential can still conclude.
//
// The rule is the same for both engines because it IS the same rule: parentheses must be
// well-nested. (3*4/2) parses and 3*)2(/4 does not; (2).intValue() parses and (2).intValue)( does
// not. One predicate serving eight probes across two classes is honest rather than lazy: a real
// engine's parser rejects both members for the same reason.
func blindParseHandler(kind blindKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := blindExtract(blindValue(r), kind)
		if !ok {
			// No delimiter, so the value never reached the engine. Identical to the baseline on
			// purpose: the arm's inert length controls must not be able to move this response.
			r4JSON(w, http.StatusOK, r4Answer)
			return
		}
		if !blindParens(body) {
			r4JSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "render_failed"})
			return
		}
		// It rendered. The product is written to a field the response does not carry, which is
		// what makes this route blind rather than merely quiet.
		r4JSON(w, http.StatusOK, r4Answer)
	}
}

func blindValue(r *http.Request) string {
	if v := queryParam(r, envelopeNames...); v != "" {
		return v
	}
	return envelopeValue(r)
}

// blindExtract pulls the expression body out of whichever delimiter this engine speaks. The two
// kinds share only ${ }: %{ } is OGNL and belongs to ELI, {{ }} is the template family and
// belongs to SSTI, and a route answering both would let each class read the other's positive.
func blindExtract(v string, kind blindKind) (string, bool) {
	open := []string{"{{", "${"}
	if kind == blindELI {
		open = []string{"${", "%{"}
	}
	for _, o := range open {
		i := strings.Index(v, o)
		if i < 0 {
			continue
		}
		rest := v[i+len(o):]
		closing := "}"
		if o == "{{" {
			closing = "}}"
		}
		j := strings.LastIndex(rest, closing)
		if j < 0 {
			continue
		}
		return rest[:j], true
	}
	return "", false
}

// blindParens is the parse. Depth may never go negative and must end at zero.
func blindParens(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// THE BLIND ARM'S SINGLE FALSE-POSITIVE MODE, AS A ROUTE. The response length tracks the input
// length and no engine runs anywhere. A length differential read without a length control fires
// here on every pair, so this route is where the two inert controls earn their requests: the arm
// must DISABLE itself and say length_sensitive_endpoint.
func blindLengthEchoHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"canary":  canaryMarker,
		"padding": strings.Repeat("x", len(blindValue(r))),
	})
}

// ---------------------------------------------------------------------------------------------
// TRAVERSAL(13)
// ---------------------------------------------------------------------------------------------

// travFiles is the emulated filesystem. There is no filesystem in this image, which is why this
// is a map: shipping a real path traversal into an operator's docker network to test a detector
// would trade a large real risk for a small measurement.
var travFiles = map[string]string{
	"etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
}

// travInDocroot is the part a first cut of this route left out, and leaving it out silenced the
// class the route was built for.
//
// A DOCUMENT SERVER SERVES ITS OWN DOCUMENTS. Without that, every unperturbed request here was a
// 404, TR-NC2 (a nonexistent directory placed in front of the observed value) was also a 404, and
// TRAVERSAL's value-ignored control correctly concluded that nothing about this response depends
// on the parameter. The class then never reached the three-way differential the route exists to
// offer. A plain filename with no separator in it is inside the document root and is served;
// anything carrying a slash has left it.
func travInDocroot(path string) bool {
	return path != "" && !strings.Contains(path, "/")
}

// travNormalise resolves the dot segments the way open(2) does, so a payload that walks above the
// root lands on an absolute path rather than being refused.
func travNormalise(v string) string {
	var out []string
	for _, seg := range strings.Split(strings.ReplaceAll(v, `\`, "/"), "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

// THE BLIND READ, which is the arm that needs no file content and therefore the only traversal
// oracle that works on an API. Three answers: the file opened, the file exists and permission was
// refused, the file is not there. None of them carries a byte of the file, so a class that can
// only confirm a read by quoting /etc/passwd is silent here and the three-way differential is the
// entire measurement.
func travBlindHandler(w http.ResponseWriter, r *http.Request) {
	v := blindValue(r)
	if v == "" {
		r4JSON(w, http.StatusOK, r4Answer)
		return
	}
	switch path := travNormalise(v); {
	case travInDocroot(path):
		r4JSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": 1841, "canary": canaryMarker})
	case travFiles[path] != "":
		r4JSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(travFiles[path]), "canary": canaryMarker})
	case path == "etc/shadow":
		r4JSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "EACCES"})
	default:
		r4JSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "ENOENT"})
	}
}

// Appends an extension before opening, which is the commonest shape of this bug in the wild and
// the reason a truncation byte is a technique at all. A payload with no truncation reaches
// etc/passwd.html and finds nothing.
func travAppendHandler(w http.ResponseWriter, r *http.Request) {
	v := blindValue(r)
	if i := strings.IndexByte(v, 0); i >= 0 {
		v = v[:i] // a C string ends at the first NUL and so does the filename
	} else {
		v += ".html"
	}
	if body := travFiles[travNormalise(v)]; body != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, body+canaryMarker+"\n")
		return
	}
	r4JSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "ENOENT"})
}

// The parameter is READ AND DISCARDED. Every payload gets the identical document, which is the
// shape the class's own value-ignored control exists to recognise, and the verdict owed is
// cannot_determine: identical bytes cannot tell an application that dropped the value from a
// cache that answered before the application ever saw it.
func travIgnoredHandler(w http.ResponseWriter, r *http.Request) {
	r4JSON(w, http.StatusOK, r4Answer)
}
