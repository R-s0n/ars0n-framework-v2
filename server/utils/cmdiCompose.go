package utils

import (
	"sort"
	"strings"
)

// Turning one attack vector into a commix, SSTImap or TInjA command line.
//
// The three reach their insertion points by three different mechanisms, and every one of them was
// measured rather than read:
//
//	                commix                    SSTImap              TInjA
//	  query         native                    native (-P Q)        native
//	  body          --data                    -d (-P B)            -d
//	  cookie        --level 2                 -C  (-P C)           NOT REACHABLE
//	  header        user-agent/referer/host   -H  (-P H)           --testheaders <name>
//	  path          INJECT_HERE in the URL    * marker in the URL  NOT REACHABLE
//
// Two of those are silent when wrong. commix below --level 2 never tests a cookie, and TInjA without
// --testheaders never tests a header: both exit 0 having sent nothing at the input the vector names.

// commixMarker is commix's own injection tag, from src/utils/settings.py: INJECT_TAG = "INJECT_HERE".
// It is a literal string, NOT the asterisk sqlmap and SSTImap use, and putting the wrong one in a
// URL produces a scan of the literal text.
const commixMarker = "INJECT_HERE"

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------
//
// THE DEFECT THIS SECTION EXISTS TO CLOSE, measured on 2026-08-21 against OWASP Juice Shop at
// 10.0.0.18:3000. The target had two session tokens in the Session Manager, both is_active, both
// validated live minutes before the run (the bearer answered 200 against /api/Addresss where an
// anonymous request got 401). SSTImap used NEITHER, and could not have: sstimapOptions had no cookie
// key at all, so there was nothing for the composer to read and no field on the form to type one in.
//
// It is not cosmetic. Juice Shop's server-side template injection is Pug on the AUTHENTICATED
// /profile page: POST /profile with the username rendered server side. Unauthenticated that vector is
// unreachable, so the one thing SSTImap exists to find on this target was out of reach for the whole
// run, and the result was recorded exactly like a tool that looked and found nothing.
//
// Three layers, weakest first, each overwriting the last BY NAME:
//
//  1. the vector's own recorded request. A cookie the application actually answered is better
//     evidence than anything guessed, and it costs nothing: the bytes are already stored on the row.
//  2. the credentials the framework holds for this host, through LoadScopedAuthContext, which is the
//     same layering endpoint validation and investigation use: Session Manager tokens on top,
//     manual-crawl captures and the saved ffuf config underneath.
//  3. the operator's own Cookies and Headers settings, which are an explicit instruction and win.

// cmdiHeldCredentials reaches the credentials the framework already holds for one host.
//
// A package variable rather than a direct call so composing stays a pure function: every test in this
// package runs without a database, and a composer that queried one directly could not be tested at
// all. The nil dbPool guard is what makes the default safe in those tests rather than a panic.
var cmdiHeldCredentials = func(scopeTargetID, host string) *ScopedAuthMaterial {
	if scopeTargetID == "" || host == "" || dbPool == nil {
		return nil
	}
	material, _ := LoadScopedAuthContext(scopeTargetID).For(host)
	return material
}

// cmdiCredentialHeaderNames are the header names read back out of a vector's recorded request and
// treated as credentials.
//
// Deliberately the same list scanCredentials.go applies to the manual crawl captures. Every other
// recorded header is left alone: replaying a stored Content-Length or Host onto a mutated request is
// how a scan starts sending requests the target rejects before they reach the parameter under test.
var cmdiCredentialHeaderNames = map[string]bool{
	"authorization":   true,
	"x-api-key":       true,
	"x-auth-token":    true,
	"x-access-token":  true,
	"x-csrf-token":    true,
	"x-xsrf-token":    true,
	"x-session-token": true,
}

// cmdiCredentials is what every request of a scan should carry so the tool is testing the same
// authenticated surface the operator is looking at.
type cmdiCredentials struct {
	// Cookies are "name=value" pairs in a stable order.
	Cookies []string
	// Headers are "Name: value" lines, sorted by name so a command line is reproducible.
	Headers []string
	// Sources names where the material came from, so a result can say whether it was measured
	// authenticated. An empty Sources on a target that needs a login is the whole failure mode.
	Sources []string
	// Marked lists credential values carrying an asterisk. commix and SSTImap both read * as an
	// injection marker, so such a value silently moves the injection point off the vector.
	Marked []string
}

// cmdiCredentialsFor layers every source of credentials for one vector.
//
// targetHeader is the header this vector injects into, if any. It is excluded: the composer already
// sends that header with the value under test, and sending it twice means the tool and the framework
// disagree about what is on the wire.
func cmdiCredentialsFor(v VectorInput, settings map[string]any, targetHeader string) cmdiCredentials {
	var out cmdiCredentials
	sources := map[string]bool{}

	cookieOrder := []string{}
	cookieByName := map[string]string{}
	addCookies := func(raw, source string) {
		added := false
		for _, pair := range strings.Split(raw, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, _, ok := strings.Cut(pair, "=")
			key := strings.ToLower(strings.TrimSpace(name))
			if !ok || key == "" {
				continue
			}
			if _, seen := cookieByName[key]; !seen {
				cookieOrder = append(cookieOrder, key)
			}
			cookieByName[key] = pair
			added = true
		}
		if added {
			sources[source] = true
		}
	}

	headerByName := map[string]string{}
	addHeader := func(name, value, source string) {
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		key := strings.ToLower(name)
		if name == "" || value == "" || key == strings.ToLower(strings.TrimSpace(targetHeader)) {
			return
		}
		headerByName[key] = name + ": " + value
		sources[source] = true
	}

	// 1. The vector's own recorded request.
	recorded := observedRequestValues(v.RawRequestOverride, "header")
	for name, value := range recorded {
		if strings.EqualFold(strings.TrimSpace(name), "cookie") {
			addCookies(value, "the vector's recorded request")
			continue
		}
		if cmdiCredentialHeaderNames[strings.ToLower(strings.TrimSpace(name))] {
			addHeader(name, value, "the vector's recorded request")
		}
	}

	// 2. What the framework holds for this host.
	if material := cmdiHeldCredentials(v.ScopeTargetID, v.Domain); material != nil {
		source := "the framework's stored credentials (" + authMaterialSource(material) + ")"
		addCookies(material.Cookies, source)
		for name, value := range material.Headers {
			addHeader(name, value, source)
		}
	}

	// 3. The operator's own settings, which win over both. Their headers are emitted by
	// composeVectorSettings for the tools that take a repeatable header flag, so they are recorded
	// here only to stop the layers below duplicating a name the operator has already set.
	addCookies(stringifySetting(settings["cookie"]), "your Cookies setting")
	for _, item := range settingValues(settings["header"]) {
		name := headerNameOf(item)
		if name == "" || strings.TrimSpace(item) == "" {
			continue
		}
		// Dropped from this list rather than added to it: the tools with a stackable header flag get
		// the operator's own headers from composeVectorSettings, and emitting them here as well would
		// put the same header on the command line twice.
		delete(headerByName, name)
		// It still counts as authentication. Without this an operator whose only credential is a
		// bearer typed into the Headers field would be told the scan ran with NO CREDENTIALS, which is
		// the opposite of true and trains them to ignore the warning.
		sources["your Headers setting"] = true
	}

	for _, key := range cookieOrder {
		out.Cookies = append(out.Cookies, cookieByName[key])
	}
	names := make([]string, 0, len(headerByName))
	for key := range headerByName {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		out.Headers = append(out.Headers, headerByName[key])
	}
	for source := range sources {
		out.Sources = append(out.Sources, source)
	}
	sort.Strings(out.Sources)

	// An asterisk inside a credential is not a cosmetic problem. commix's
	// custom_injection_marker_character() sets COOKIE_INJECTION the moment it sees one in --cookie,
	// and SSTImap's default marker is the same character, so the scan quietly moves off the parameter
	// the vector names and onto the session value instead.
	for _, value := range append(append([]string{}, out.Cookies...), out.Headers...) {
		if !strings.Contains(value, "*") {
			continue
		}
		// The NAME only. The value is a live credential and the warning is read on screen and stored
		// in the scan record, neither of which is a place to print a session token.
		name := value
		if cut, _, ok := strings.Cut(value, "="); ok {
			name = cut
		} else if cut, _, ok := strings.Cut(value, ":"); ok {
			name = cut
		}
		out.Marked = append(out.Marked, strings.TrimSpace(name))
	}
	sort.Strings(out.Marked)
	return out
}

// cmdiCredentialWarnings turns the credential state into something the operator reads next to the
// verdict. Silence here is the failure this whole file guards against: a tool that tested only the
// anonymous surface and a tool that tested the authenticated one produce the same clean row.
func cmdiCredentialWarnings(tool string, creds cmdiCredentials) []string {
	var warnings []string
	if len(creds.Sources) == 0 {
		return []string{"NO CREDENTIALS were attached, so " + tool + " tested this vector as an " +
			"anonymous user. A clean result therefore says nothing about anything behind the login, " +
			"which on most applications is where the interesting surface is. Add a session token in " +
			"the Session Manager, or a Cookies or Headers value in this tool's settings."}
	}
	warnings = append(warnings, "Authenticated from "+joinAnd(creds.Sources)+".")
	if len(creds.Marked) > 0 {
		warnings = append(warnings, "The credential "+joinAnd(creds.Marked)+" carries an asterisk, "+
			"which "+tool+" reads as an injection marker: it will inject into that value instead of "+
			"into the input this vector names. Replace or re-capture it before trusting this result.")
	}
	return warnings
}

// cmdiCookiesExcept returns the credential cookies minus the one the vector is injecting into. The
// vector's own value is authoritative for that name; carrying the operator's stale copy as well sends
// the name twice and leaves which one the application reads to chance.
func cmdiCookiesExcept(creds cmdiCredentials, targetName string) []string {
	if targetName == "" {
		return creds.Cookies
	}
	var kept []string
	for _, pair := range creds.Cookies {
		name, _, _ := strings.Cut(pair, "=")
		if strings.EqualFold(strings.TrimSpace(name), targetName) {
			continue
		}
		kept = append(kept, pair)
	}
	return kept
}

// ComposeCommix builds the commix argv for one vector.
func ComposeCommix(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("commix")
	var warnings []string

	args := []string{"/opt/commix/commix.py", "-u", commixTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "--method", method)
	}
	if v.InsertionPoint == "body" {
		args = append(args, "--data", cmdiBodyFor(v))
	}

	// -p keeps commix on the parameter this vector claims. Without it a URL carrying three
	// parameters costs three times as long and can attribute a finding to a vector that never
	// named the parameter that produced it.
	if (v.InsertionPoint == "query" || v.InsertionPoint == "body") && len(v.Parameters) > 0 {
		args = append(args, "-p", strings.Join(v.Parameters, ","))
	}

	targetHeader := ""
	if v.InsertionPoint == "header" {
		targetHeader = strings.ToLower(markableParam(v))
	}
	creds := cmdiCredentialsFor(v, settings, targetHeader)
	warnings = append(warnings, cmdiCredentialWarnings("commix", creds)...)

	if v.InsertionPoint == "cookie" {
		name := markableParam(v)
		// NOT mergeCookieHeader: that appends sqlmap's * marker, and commix's marker is the literal
		// INJECT_HERE. An asterisk glued to a session value is a changed cookie, which is a different
		// request from the one that was observed.
		args = append(args, "--cookie", joinCookies(strings.Join(cmdiCookiesExcept(creds, name), "; "),
			name, v.valueFor(name)))
		// THE RULE. Measured: with the default level commix never sets the cookie for testing and the
		// run ends reporting nothing; at --level 2 it reports "Cookie parameter 'name' appears to be
		// injectable". Only raised when the operator has not asked for more.
		if levelBelow(settings["level"], 2) {
			args = append(args, "--level", "2")
			warnings = append(warnings, "Raised commix to --level 2 for this cookie vector: below it "+
				"commix does not test cookies at all and the run would report nothing.")
		}
	} else if len(creds.Cookies) > 0 {
		args = append(args, "--cookie", strings.Join(creds.Cookies, "; "))
	}

	// A header vector only gets here when commixVectorEligible allowed it, which means the header is
	// one of the three commix knows. Level 3 is what turns header testing on.
	if v.InsertionPoint == "header" {
		if levelBelow(settings["level"], 3) {
			args = append(args, "--level", "3")
			warnings = append(warnings, "Raised commix to --level 3 for this header vector: headers "+
				"are not tested below it.")
		}
		name := strings.ToLower(markableParam(v))
		value := v.valueFor(name)
		switch name {
		case "referer":
			args = append(args, "--referer", value)
		case "user-agent":
			args = append(args, "--user-agent", value)
		case "host":
			args = append(args, "--host", value)
		}
	}

	// --headers, NOT -H, and the framework builds the whole value.
	//
	// MEASURED, because the option table said the opposite and the option table was wrong. commix
	// declares -H with action="store" (src/utils/menu.py), so a second -H REPLACES the first and says
	// nothing about it. Captured on the wire against a listener, with `-H "X-Auth-A: aaa" -H
	// "X-Auth-B: bbb"`, every scan request carried X-Auth-B alone. The same two headers passed as
	// `--headers "X-Auth-A: aaa\nX-Auth-B: bbb"` both appeared on every request. That separator is a
	// literal backslash-n: commix splits on settings.END_LINE.ESCAPED_LF, which is the two-character
	// string, not a newline.
	if headers := commixHeaderList(settings, creds); headers != "" {
		args = append(args, "--headers", headers)
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"cookie": true, "header": true}, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--batch",            // no terminal to answer prompts from
		"--disable-coloring", // escape codes corrupt stored evidence
		// ALWAYS. commix keeps a session per target and consults it on the next run, and the second
		// run of a vector it has already seen reports NOTHING. Measured on a target with a live
		// command injection: without this flag two consecutive runs both report 0 injectable
		// parameters; with it, both report 1. A scan whose results depend on whether the same target
		// was scanned before is worse than a slow one, because the empty result looks like an answer.
		"--flush-session",
		"--output-dir", "/tmp/commix-out",
	)
	return args, warnings
}

// commixHeaderList builds commix's --headers value: the operator's own headers plus the credential
// headers the framework holds, joined by the literal backslash-n commix splits on.
func commixHeaderList(settings map[string]any, creds cmdiCredentials) string {
	var lines []string
	for _, item := range settingValues(settings["header"]) {
		if item = strings.TrimSpace(item); item != "" {
			lines = append(lines, item)
		}
	}
	lines = append(lines, creds.Headers...)
	return strings.Join(lines, `\n`)
}

// ComposeSSTImap builds the SSTImap argv.
//
// It needs the least help of the three: -P defaults to QBHC, so query, body, headers and cookies are
// all tested with no marker and no level. Only a path vector needs the marker placed.
//
// Credentials were the one thing it was never given. -C and --cookie were both listed as framework
// owned while no cookie setting existed to compose from, so the flag was advertised as "composed per
// vector" with nothing behind it. Both halves are fixed: the option exists in cmdiTools.go and the
// composer now layers the recorded request, the framework's held credentials and the operator's
// setting into it. Verified on the wire: -C and -H are both stackable ("[Stackable]" in its own help,
// action="append" in utils/cliparser.py), and every request of a three-request run carried
// `Cookie: session=abc; csrf=xyz` and `Authorization: Bearer tok`.
func ComposeSSTImap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("sstimap")
	var warnings []string

	args := []string{"/opt/SSTImap/sstimap.py", "-u", sstimapTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "-m", method)
	}
	if v.InsertionPoint == "body" {
		args = append(args, "-d", cmdiBodyFor(v))
	}

	targetCookie, targetHeader := "", ""
	switch v.InsertionPoint {
	case "cookie":
		targetCookie = markableParam(v)
		args = append(args, "-C", targetCookie+"="+v.valueFor(targetCookie))
	case "header":
		targetHeader = markableParam(v)
		args = append(args, "-H", targetHeader+": "+v.valueFor(targetHeader))
	}

	creds := cmdiCredentialsFor(v, settings, targetHeader)
	warnings = append(warnings, cmdiCredentialWarnings("SSTImap", creds)...)

	// A COOKIE VECTOR KEEPS ITS SESSION. This used to bail out entirely for a cookie vector, which
	// meant the one insertion point most likely to be behind a login was the one point tested logged
	// out: a vector on TrackingId dropped the session cookie that sits beside it, so every response
	// was the login page and the tool reported nothing. SSTImap merges every -C into one Cookie
	// header, verified on the wire, so sending both is the same request the browser sends.
	for _, pair := range cmdiCookiesExcept(creds, targetCookie) {
		args = append(args, "-C", pair)
	}
	for _, header := range creds.Headers {
		args = append(args, "-H", header)
	}

	args = append(args, composeVectorSettings(tool, settings, "", map[string]bool{"cookie": true}, &warnings)...)
	args = append(args, "--no-color")
	_ = reportPath
	return args, warnings
}

// tinjaCommaWarning reports a credential TInjA is about to truncate.
//
// MEASURED on the wire, because nothing in TInjA's help says it: -c and -H are both declared as pflag
// "strings", which is a StringSlice and SPLITS ITS VALUE ON COMMAS. Passing `-c "sess=aaa,bbb"` put
// `Cookie: sess=aaa` on the request; the rest of the value became a second entry with no name and was
// dropped. A session whose value contains a comma is therefore silently truncated, every request
// after it is unauthenticated, and the scan reports clean.
//
// It is reported rather than repaired on purpose. Percent-encoding the comma changes the credential,
// and a target that does not decode its cookies would reject the altered value just as quietly.
func tinjaCommaWarning(kind, value string) []string {
	if !strings.Contains(value, ",") {
		return nil
	}
	name := value
	if cut, _, ok := strings.Cut(value, "="); ok && kind == "cookie" {
		name = cut
	} else if cut, _, ok := strings.Cut(value, ":"); ok {
		name = cut
	}
	return []string{"The " + kind + " " + strings.TrimSpace(name) + " contains a comma, and TInjA " +
		"splits -c and -H values on commas: it will send everything up to the comma and drop the " +
		"rest, so this run is very likely unauthenticated. Measured on the wire. Use a credential " +
		"without a comma, or treat a clean TInjA result on this target as unproven."}
}

// ComposeTInjA builds the TInjA argv.
//
// --testheaders is the rule here. Measured: with the header named, TInjA identifies Jinja2 at Very
// High certainty; without it the same run sends one polyglot and reports zero suspected injections.
func ComposeTInjA(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("tinja")
	var warnings []string

	args := []string{"url", "-u", v.TargetURL()}

	if v.InsertionPoint == "body" {
		// TInjA switches to POST when -d is given; it has no method flag of its own.
		args = append(args, "-d", cmdiBodyFor(v))
	}
	targetHeader := ""
	if v.InsertionPoint == "header" {
		targetHeader = markableParam(v)
		args = append(args, "--testheaders", targetHeader, "-H", targetHeader+": "+v.valueFor(targetHeader))
	}

	// TInjA has no flag that fuzzes a cookie, so there is no target cookie to hold back: everything
	// here is authentication. Verified on the wire that -c and -H both stack and that the cookies
	// arrive merged into one Cookie header.
	creds := cmdiCredentialsFor(v, settings, targetHeader)
	warnings = append(warnings, cmdiCredentialWarnings("TInjA", creds)...)
	for _, pair := range creds.Cookies {
		args = append(args, "-c", pair)
		warnings = append(warnings, tinjaCommaWarning("cookie", pair)...)
	}
	for _, header := range creds.Headers {
		args = append(args, "-H", header)
		warnings = append(warnings, tinjaCommaWarning("header", header)...)
	}

	args = append(args, composeVectorSettings(tool, settings, "", map[string]bool{"cookie": true}, &warnings)...)

	// A DIRECTORY, with the trailing slash. TInjA treats --reportpath as a prefix and appends
	// <timestamp>_Report.jsonl to it, so passing a filename produces report.json2026-..._Report.jsonl
	// and nothing ever appears at the path the runner then tries to read.
	args = append(args, "--reportpath", reportPath+"/")
	return args, warnings
}

// commixTargetURL places commix's INJECT_HERE marker in a path segment.
//
// REPLACING the segment, not appended to it. Measured against a target whose path segment reaches a
// shell: /cmd/path/INJECT_HERE is reported injectable, /cmd/path/worldINJECT_HERE finds nothing at
// all. commix substitutes the whole tag rather than treating it as a suffix, so a marker glued onto
// a value is a marker it never recognises, and the run ends clean.
func commixTargetURL(v VectorInput) string {
	if v.InsertionPoint != "path" {
		return v.TargetURL()
	}
	return markLastPathSegment(v.TargetURL(), commixMarker, true)
}

// sstimapTargetURL places SSTImap's * marker in a path segment.
func sstimapTargetURL(v VectorInput) string {
	if v.InsertionPoint != "path" {
		return v.TargetURL()
	}
	return markLastPathSegment(v.TargetURL(), "*", true)
}

// markLastPathSegment replaces or suffixes the last path segment with a marker.
//
// Edited as TEXT rather than through net/url, for the reason the SQL section found the hard way:
// URL.String() percent-encodes an asterisk to %2A, and a tool looking for a literal marker then
// finds none, falls back to whatever parameters exist, and reports the path clean.
//
// replace says whether the marker stands IN PLACE of the segment (SSTImap's *, which marks where a
// payload goes) or is appended to it (commix's INJECT_HERE, which it substitutes).
func markLastPathSegment(rawURL, marker string, replace bool) string {
	pathPart, queryPart, hasQuery := strings.Cut(rawURL, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return rawURL
	}
	host, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return rawURL
	}

	segments := strings.Split(path, "/")

	// The TEMPLATED segment is the injectable one when there is one. /users/{uuid}/settings has its
	// identifier in the middle, and marking the last segment would test the literal word settings
	// while the thing the vector is actually about goes untouched. Falls back to the last segment
	// when nothing is templated, which is the concrete-identifier case.
	target := -1
	for i, seg := range segments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			target = i
			break
		}
	}
	if target == -1 {
		for i := len(segments) - 1; i >= 0; i-- {
			if segments[i] != "" {
				target = i
				break
			}
		}
	}
	if target >= 0 {
		templated := strings.HasPrefix(segments[target], "{") && strings.HasSuffix(segments[target], "}")
		if replace || templated {
			segments[target] = marker
		} else {
			segments[target] += marker
		}
	}

	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out
}

// cmdiBodyFor returns the body to send, building one from the vector's parameter names when no body
// was recorded. Without it the tool is handed an empty body and tests nothing.
func cmdiBodyFor(v VectorInput) string {
	if strings.TrimSpace(v.Body) != "" {
		return v.Body
	}
	var pairs []string
	for _, name := range v.Parameters {
		pairs = append(pairs, name+"="+v.valueFor(name))
	}
	return strings.Join(pairs, "&")
}

// levelBelow reports whether a stored level setting is absent or lower than the one a vector needs.
// The operator's own higher level is never lowered.
func levelBelow(stored any, need int) bool {
	switch t := stored.(type) {
	case float64:
		return int(t) < need
	case int:
		return t < need
	case string:
		if t == "" {
			return true
		}
		return len(t) == 1 && t[0] < byte('0'+need)
	}
	return true
}

// joinCookies builds a Cookie string from the operator's auth cookies plus the vector's own, with no
// marker of any kind. commix finds a cookie by testing it at --level 2, not by marking it.
func joinCookies(authCookies, targetName, targetValue string) string {
	var kept []string
	for _, pair := range strings.Split(authCookies, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		// The operator's stale copy of the target cookie is dropped, or the request carries the name
		// twice and which one the application reads is not something to leave to chance.
		if strings.EqualFold(strings.TrimSpace(name), targetName) {
			continue
		}
		kept = append(kept, pair)
	}
	if targetName != "" {
		kept = append(kept, targetName+"="+targetValue)
	}
	return strings.Join(kept, "; ")
}
