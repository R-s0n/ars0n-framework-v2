package utils

import (
	"net/url"
	"sort"
	"strings"
)

// The URL fragment as an attack vector.
//
// WHY IT IS A SEPARATE INSERTION POINT AND NOT A VARIETY OF QUERY. A fragment never reaches the
// server. RFC 3986 section 3.5 makes it a client-side reference and every browser strips it before
// the request goes out, so it appears in no access log, no WAF rule and no raw_request capture. The
// consequence for this framework is blunt: every HTTP-level tool it ships is structurally blind to
// it, and a fragment vector handed to one of them would be scanned, found clean and counted, having
// tested nothing. That is the failure mode vectorEligibility.go exists to prevent, so the fragment
// gets its own point and the HTTP tools declare it unreachable.
//
// WHY IT IS WORTH HAVING ANYWAY. It is where DOM XSS lives. The payload is read back by
// location.hash and written into a sink by client code, which is exactly the class no reflection
// based scanner can see. The framework already ships a tool that fuzzes it: domdig's own usage text
// for -m says fuzz mode injects into the query string and the hash, and its findings carry a param
// of literally "hash" (see vectorExplain.go:155). Until this change the corpus could never hand
// domdig a hash target, so half of that tool's fuzz mode had never been used.
//
// MEASURED BEFORE WRITING ANY OF THIS, on 2026-09-17 against the live database:
//
//   - insertion_point across every scope target held five values and no fragment:
//     query 129, path 97, cookie 86, header 64, body 41.
//   - consolidated_url_endpoints already has a client_route column, filled by
//     endpointConsolidationRun.go from endpointIdentity's clientRouteFrom. Rows with a non-empty
//     client_route, across the whole database: 0. Rows flagged had_fragment, meaning a fragment
//     that is not an SPA route: 2.
//   - manual_crawl_captures holds 6 URLs containing a hash, all on privatealps.net, all scroll
//     anchors (#billing, #profile, #security, #preferences). Hash-routed ones, matching #/ or #!: 0.
//
// So fragments ARE stored at capture time. captureBridgeUtils.go:1026 does clear parsed.Fragment,
// but that function is normalizeURLForMatch and its only caller is the auto-detect identifier
// grouping key at captureBridgeUtils.go:725. It is a dedupe key, not the storage path, and clearing
// the fragment there is correct for its own purpose: /settings#billing and /settings#profile are one
// endpoint for the purpose of counting how many endpoints a session cookie rides on. Nothing was
// ripped out.

// fragmentParts is one observed fragment, split into the pieces that decide a vector's identity.
type fragmentParts struct {
	// Route is the identity-bearing part, templated the same way a path is so that #/orders/12345
	// and #/orders/67890 are one vector seen twice rather than two vectors.
	Route string
	// Names are the keys of any key=value list carried INSIDE the fragment. Two shapes produce
	// them, and both are real: an SPA route with its own query (#/route?tab=x), and the OAuth
	// implicit grant, whose whole point is that the token arrives in the fragment so it never
	// touches the server (#access_token=...&token_type=bearer&expires_in=3600).
	Names []string
	// Signals describe what those values LOOK like, so a fragment carrying a bearer token reads
	// differently from one carrying a tab name. Same vocabulary as every other insertion point.
	Signals []string
	// Kind records which of the three shapes this was, because an operator triages them
	// differently: credentials in a fragment are an exposure question before they are an XSS one.
	Kind string
}

const (
	fragmentKindRoute    = "route"          // #/dashboard, #!/users/1
	fragmentKindImplicit = "implicit_grant" // #access_token=...&token_type=bearer
	fragmentKindAnchor   = "anchor"         // #billing, #section-3
)

// parseFragment splits a raw fragment into its parts, and reports false when there is nothing there.
//
// The fragment is taken exactly as observed. It is never synthesised: a fragment slot exists on
// every URL ever served, so emitting a vector for each one would put a row beside every endpoint
// carrying no evidence that anything reads it. That is the same discipline the rest of this section
// holds to, and the reason the honest count on a target with no observed fragments is zero.
func parseFragment(raw string) (fragmentParts, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "#"))
	if raw == "" {
		return fragmentParts{}, false
	}

	route, query := raw, ""
	if i := strings.Index(raw, "?"); i >= 0 {
		route, query = raw[:i], raw[i+1:]
	}

	out := fragmentParts{Kind: fragmentKindAnchor}
	switch {
	case strings.HasPrefix(route, "/"), strings.HasPrefix(route, "!"):
		// The two hashbang forms endpointIdentity.go:371 clientRouteFrom already recognises. Kept
		// in step with it deliberately: if the identity layer calls #/x a route, so does this.
		out.Kind = fragmentKindRoute
	case query == "" && strings.Contains(route, "="):
		// No route and no question mark, but key=value pairs: the fragment IS the parameter list.
		// This is the OAuth implicit grant shape, and it is the case worth naming, because the value
		// sitting in it is usually an access token.
		route, query = "", raw
		out.Kind = fragmentKindImplicit
	}

	out.Route = templateFragmentRoute(route)
	out.Names, out.Signals = fragmentQueryInputs(query)
	if out.Route == "" && len(out.Names) == 0 {
		return fragmentParts{}, false
	}
	return out, true
}

// templateFragmentRoute runs the route through the same segment templating a path gets, so an
// identifier inside a client route collapses instead of putting a row in the list for every object
// the operator happened to open.
//
// The leading "!" of a hashbang is held aside first. templateVectorPath splits on "/", so the "!"
// would otherwise arrive as a first segment of its own and be classified as a token.
func templateFragmentRoute(route string) string {
	if route == "" {
		return ""
	}
	bang := ""
	if strings.HasPrefix(route, "!") {
		bang, route = "!", strings.TrimPrefix(route, "!")
	}
	if route == "" {
		return bang
	}
	if !strings.HasPrefix(route, "/") {
		// An anchor is one opaque label rather than a path. Templating it would turn #2024 into
		// #{id} and merge two anchors that address two different places on the page.
		return bang + route
	}
	templated, _ := templateVectorPath(route)
	return bang + templated
}

// fragmentQueryInputs reads the key=value list inside a fragment.
//
// url.ParseQuery is deliberately NOT used. It fails the whole string on one malformed escape, and a
// fragment is written by client code that was never required to percent-encode anything, so a single
// stray percent sign would silently cost every name in an OAuth callback. Splitting by hand keeps
// the names that are there and drops only the pair that is broken.
func fragmentQueryInputs(query string) (names []string, signals []string) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	seenName := map[string]bool{}
	seenSignal := map[string]bool{}
	isSeparator := func(r rune) bool { return r == '&' || r == ';' }
	for _, pair := range strings.FieldsFunc(query, isSeparator) {
		name, value := pair, ""
		if i := strings.Index(pair, "="); i >= 0 {
			name, value = pair[:i], pair[i+1:]
		}
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		name = strings.TrimSpace(name)
		if name == "" || seenName[name] {
			continue
		}
		seenName[name] = true
		names = append(names, name)
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		if kind := classifyInputValue(value); kind != "" && !seenSignal[kind] {
			seenSignal[kind] = true
			signals = append(signals, kind)
		}
	}
	names = usefulParameterNames(names)
	sort.Strings(signals)
	return names, signals
}

// captureFragment pulls the fragment out of a captured URL, as it was written.
//
// EscapedFragment rather than Fragment, for the same reason endpointIdentity.go:173 takes
// EscapedPath: url.Parse decodes percent escapes into Fragment, so a payload written as %3Cimg
// would arrive already decoded and a templated route built from it would no longer match the string
// the browser holds.
func captureFragment(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.EscapedFragment()
}

// fragmentVectorFrom builds the fragment vector for one observed URL, on top of a base vector that
// already carries the verb, host and path.
//
// Returns false when the URL has no fragment, which is the overwhelmingly common case.
func fragmentVectorFrom(base attackVector, rawFragment string) (attackVector, bool) {
	parts, ok := parseFragment(rawFragment)
	if !ok {
		return attackVector{}, false
	}
	v := base
	v.InsertionPoint = "fragment"
	v.Fragment = parts.Route
	v.Parameters = parts.Names
	v.Signals = parts.Signals
	// The shape is carried as a signal so it survives into the row and can be filtered on. An
	// implicit-grant fragment is the one an operator wants to see first.
	if parts.Kind != fragmentKindAnchor {
		v.Signals = append([]string{parts.Kind}, v.Signals...)
	}
	// A fragment is observed by the browser, never by a server, so there is no such thing as an
	// implied one: either a capture recorded it or it is not here.
	v.InsertionConfidence = "observed"
	return v, true
}

// fragmentSpans renders a fragment vector's fragment, the part that goes after the "#", as the
// pieces it is made of, marking each piece an attacker controls.
//
// ONE function with TWO callers, deliberately, because the two were written separately and they
// disagreed. fragmentTargetURL rebuilt the URL from v.Fragment alone, but fragmentVectorFrom puts
// the names carried INSIDE a fragment in v.Parameters, so every shape except a bare route lost its
// content on the way to the tool. Measured on a real OAuth implicit grant: the row held
// Fragment="" Parameters=[access_token token_type expires_in] and the composed argv was
// [/app/domdig.js -J -q https://app.example.com/callback], with no hash on it whatsoever. domdig
// navigated, found nothing, and the row was recorded as a clean test of a fragment vector. That is
// the same fail-open VectorHTTPInsertionPoints removed from the tool registry, reappearing one layer
// down at the composer.
//
// It was worse than silent, because appendFragmentParts rendered the fragment CORRECTLY under the
// request: the operator was shown #access_token=FUZZ&token_type=FUZZ for a scan that sent none of
// it. Sharing the renderer is what makes the preview and the argv agree by construction rather than
// by two authors remembering the same rule.
//
// value supplies what stands in for a value nobody recorded, which is the only thing the two callers
// differ on: the composer sends the canary every tool looks for, the preview shows a reader a slot.
func fragmentSpans(fragment string, parameters []string, value func(name string) string) []vectorRequestPart {
	if len(parameters) == 0 {
		// A bare route or a scroll anchor. There are no names in it, so the whole fragment is the
		// one slot, exactly as a path vector treats its last segment.
		text := fragment
		if text == "" {
			// Neither a route nor a name. Consolidation cannot produce this (parseFragment returns
			// false on an empty fragment) and both API handlers now refuse it, so it is only ever a
			// row that predates those guards. Emitting the slot hands the tool a hash to fuzz, which
			// is what the preview has always claimed was sent; emitting nothing would drop the row
			// back into the fail-open this function exists to close.
			text = value("")
		}
		return []vectorRequestPart{{Text: text, Input: true}}
	}
	var out []vectorRequestPart
	if fragment != "" {
		// A client route carrying its own query: #/connect/edit?token=x&tab=y. The route is the
		// address, not the input, so it is not marked; the names after the "?" are.
		out = append(out, vectorRequestPart{Text: fragment + "?"})
	}
	for i, name := range parameters {
		if i > 0 {
			out = append(out, vectorRequestPart{Text: "&"})
		}
		out = append(out, vectorRequestPart{
			Text: name + "=" + value(name), Input: true, Param: name})
	}
	return out
}

// fragmentString is fragmentSpans joined back up: the fragment as one string, for a caller that
// needs a URL rather than a marked-up preview.
func fragmentString(fragment string, parameters []string, value func(name string) string) string {
	var b strings.Builder
	for _, part := range fragmentSpans(fragment, parameters, value) {
		b.WriteString(part.Text)
	}
	return b.String()
}

// fragmentTargetURL rebuilds the URL a browser-driven tool must be pointed at, with the fragment
// LAST, after the path and any query string, and with everything the fragment carries still in it.
//
// Order is half the point. A URL written as /settings#/billing?tab=x puts "tab=x" inside the
// fragment, where no server ever sees it; the same pair written /settings?tab=x#/billing is a query
// parameter. Composing these the wrong way round would send a different request and the tool would
// have no way to report that it had.
//
// Completeness is the other half, and it is the one that was wrong. See fragmentSpans.
func fragmentTargetURL(base, rawQuery, fragment string, parameters []string,
	value func(name string) string) string {
	out := base
	if rawQuery != "" {
		out += "?" + rawQuery
	}
	if f := fragmentString(fragment, parameters, value); f != "" {
		out += "#" + f
	}
	return out
}

// fragmentVectorError states the one rule a fragment vector has to satisfy: it has to actually carry
// a fragment, either a route or anchor of its own or the names of the parameters inside it.
//
// Shared by the create and the update handler so the two cannot drift, which is exactly what had
// happened. Create refused an empty one and update stored it, and a fragment vector with an empty
// fragment composes to the plain URL: it is scanned, it comes back clean, and the clean result is
// filed against the fragment.
func fragmentVectorError(insertionPoint, fragment string, parameters []string) string {
	if insertionPoint != "fragment" || fragment != "" || len(parameters) > 0 {
		return ""
	}
	return "A fragment vector needs a fragment. Put it on the URL, e.g. " +
		"https://host/settings#/billing, or name the parameters carried inside it."
}

// fragmentUpdateError is the extra rule an EDIT has to satisfy, on top of fragmentVectorError.
//
// Moving an existing vector to the fragment point needs the fragment supplied with the edit. The
// parameters already on the row belong to the point it is leaving: a query vector's names are query
// names, and carrying them over would compose #tab=rs0n on a hash the application does not read,
// then file whatever came back against a fragment nobody ever observed. Refusing is the honest
// answer, and it is why the edit form has a fragment field.
func fragmentUpdateError(newPoint, oldPoint, fragment string, parameters []string, fragmentGiven bool) string {
	if newPoint != "fragment" {
		return ""
	}
	if oldPoint != "fragment" && !fragmentGiven {
		return "Moving a vector to the fragment insertion point needs the fragment itself, " +
			"e.g. /billing or access_token=... Fill in the fragment field. The parameters on this " +
			"row name " + oldPoint + " inputs and are not what a client-side script reads."
	}
	return fragmentVectorError(newPoint, fragment, parameters)
}
