package utils

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Recognising user-controlled input wherever it hides.
//
// A parameter list is the obvious place and not the only one. Everything below is an input the
// application reads and the user can change, and every one of them was found sitting in this
// framework's own capture tables while the consolidation walked past it:
//
//   - A JWT in an Authorization header or a cookie. Measured on one target: authorization carried one
//     on 16 of 16 rows, a custom x-sd-sessid on 17 of 17, and 35 of 40 cookie headers. Algorithm
//     confusion, an unverified signature and a swapped subject all live there, and none of them is a
//     query parameter.
//   - A high-entropy PATH SEGMENT. /global-wallet/v1/accounts/global_wallet.bd032fac-... is an
//     identifier in a path, and the same template appeared with three different account ids on the
//     same capture session, which is the evidence that it is swappable.
//   - A custom header the application invented. Anything not on the browser's own list was put there
//     by the site's code, which means the site's code reads it back.
//
// The counterpart matters as much: a name that is itself random, like dd_cookie_test_<uuid>, is one
// input per session rather than a thousand, and treating each as its own vector would bury the list.

// jwtValue matches a JSON Web Token anywhere inside a value. Deliberately the same shape the
// credential checker uses, because a token worth blocking a scan over is a token worth testing.
var jwtValue = regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{5,}\.[A-Za-z0-9_=-]{5,}\.[A-Za-z0-9_=-]*`)

var (
	uuidValue       = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	longHexValue    = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	numericID       = regexp.MustCompile(`^[0-9]{4,}$`)
	vectorBase64ish = regexp.MustCompile(`^[A-Za-z0-9_=-]{20,}$`)
)

// InputSignal names why a span is worth testing. Reported to the UI so a row says what it is rather
// than only that it exists.
const (
	SignalJWT         = "jwt"
	SignalUUID        = "uuid"
	SignalHighEntropy = "high_entropy"
	SignalNumericID   = "numeric_id"
	SignalCustom      = "custom_header"
)

// classifyInputValue reports what a value looks like, or "" when it looks like ordinary data.
//
// Ordered by how much it tells you: a JWT is a structured credential, a UUID is an object reference,
// and raw entropy is the fallback for a token whose shape nobody recognises. All three mean the same
// thing operationally, which is that the value identifies or authorises something and swapping it is
// the test.
func classifyInputValue(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	switch {
	case jwtValue.MatchString(v):
		return SignalJWT
	case uuidValue.MatchString(v):
		return SignalUUID
	case numericID.MatchString(v):
		return SignalNumericID
	case longHexValue.MatchString(v), vectorBase64ish.MatchString(v) && shannonEntropy(v) >= 3.2:
		return SignalHighEntropy
	}
	return ""
}

// browserSetHeaders are the ones the BROWSER decides. They are on every request, the application does
// not read most of them, and admitting them would add a hundred and seventy rows of noise to a list
// whose whole value is being short enough to work through.
//
// Everything not on this list was invented by the site, which is the definition of a header the site
// reads back.
var browserSetHeaders = map[string]bool{
	"accept": true, "accept-charset": true, "accept-encoding": true, "accept-language": true,
	"cache-control": true, "connection": true, "content-length": true, "content-type": true,
	"cookie": true, "dnt": true, "host": true, "origin": true, "pragma": true, "priority": true,
	"range": true, "referer": true, "sec-gpc": true, "te": true, "trailer": true,
	"upgrade-insecure-requests": true, "user-agent": true, "via": true, "expect": true,
	"if-modified-since": true, "if-none-match": true, "device-memory": true, "downlink": true,
	"ect": true, "rtt": true, "save-data": true, "viewport-width": true, "width": true,
	// Hop-by-hop headers, siblings of "connection" already above. "upgrade" is on this list because
	// of a measured row rather than on principle: the Socket.IO handshake on Juice Shop produced a
	// header vector whose single parameter was "upgrade", which is the value the browser writes to
	// ask for a WebSocket. No application reads it as input, and it was one of only two distinct
	// header names in a list of 43 header vectors.
	"upgrade": true, "keep-alive": true, "proxy-connection": true, "transfer-encoding": true,
	"alt-used": true,
}

// appControlledHeader reports whether a header is one the application put there rather than the
// browser. sec-ch-* and sec-fetch-* are matched by prefix because the browser keeps inventing them.
func appControlledHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || browserSetHeaders[n] {
		return false
	}
	if strings.HasPrefix(n, "sec-ch-") || strings.HasPrefix(n, "sec-fetch-") ||
		strings.HasPrefix(n, "sec-websocket-") || strings.HasPrefix(n, ":") {
		return false
	}
	return true
}

// templateInputName collapses a name that carries its own random component.
//
// dd_cookie_test_6c0ed146-cc1b-4cce-9623-af10812bd2f6 and fp_token_7c6a6574-f011-... are one input
// generated per session, not one input per session. Left alone they would add a row to the list every
// time the operator reloads the page, which is how a list stops being read.
func templateInputName(name string) string {
	out := uuidValue.ReplaceAllString(name, "{uuid}")
	if out != name {
		return out
	}
	// A long hex run inside a longer name is the same thing wearing a different hat.
	return longHexInName.ReplaceAllString(name, "{hex}")
}

var longHexInName = regexp.MustCompile(`(?i)[0-9a-f]{16,}`)

// templatePath replaces path segments that are identifiers with a marker, and reports what it found.
//
// This is what makes /users/user.dedc6ad0-... and /users/user.ea064fd5-... ONE vector rather than one
// per account the operator happens to have looked at. The template is the vector; the concrete value
// is an example of it, and the example is kept on the row so the request can still be sent.
//
// The prefix is preserved: user.{uuid} rather than {uuid}, because "this is a user id" is exactly the
// fact an operator needs when deciding whether swapping it is worth trying.
//
// IT USED TO BE WRONG IN BOTH DIRECTIONS AND ONE RUN PROVED BOTH HALVES. Against Juice Shop:
//
//   - /api/Products/1, /api/Products/6, /api/Products/24, /api/Addresss/7, /api/Addresss/8,
//     /api/Cards/8, /api/Quantitys/1, /rest/basket/6 and /rest/products/1/reviews were all left
//     LITERAL, because classifyInputValue only calls a number an id at four digits or more. Nine
//     ID-bearing paths carrying 31 vectors between them, one row per object the operator happened to
//     click on, and no row for the route those objects share.
//   - /rest/admin/application-configuration was templated to /rest/admin/{token}. That segment is a
//     fixed route name somebody typed. It matched only because it is 25 characters of [A-Za-z-] and
//     its Shannon entropy is 3.513.
//
// The second one is the dangerous one, and the sibling route says why. /rest/admin/application-version
// has HIGHER entropy, 3.577, and survived untouched purely because it is 19 characters against a
// 20-character floor. The rule was measuring LENGTH, not identity. Name that route
// application-versions and the two would have collapsed into one /rest/admin/{token} row, and one of
// two real admin routes would never have been tested at all.
//
// So the two errors are not symmetric and the rules below are not either. An identifier left literal
// costs one extra row in a list; a route templated away DELETES a route.
func templateVectorPath(path string) (templated string, signals []string) {
	if path == "" {
		return "/", nil
	}
	segments := strings.Split(path, "/")
	seen := map[string]bool{}
	// Counted over non-empty segments so that a leading "/" and a "//" typo do not shift what counts
	// as the first segment.
	position := 0
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		kind := classifyPathSegment(seg, position)
		position++
		if kind == "" {
			continue
		}
		switch kind {
		case SignalUUID:
			segments[i] = uuidValue.ReplaceAllString(seg, "{uuid}")
		case SignalJWT:
			segments[i] = jwtValue.ReplaceAllString(seg, "{jwt}")
		case SignalNumericID:
			segments[i] = "{id}"
		default:
			segments[i] = "{token}"
		}
		if !seen[kind] {
			seen[kind] = true
			signals = append(signals, kind)
		}
	}
	return strings.Join(segments, "/"), signals
}

// classifyPathSegment decides whether one PATH SEGMENT is an identifier.
//
// classifyInputValue is deliberately not reused whole. It answers "does this value identify or
// authorise something", which is the right question for a cookie value or a header value and the
// wrong one for a route segment, where a name a developer typed has to survive intact. Two rules
// differ:
//
//   - A run of digits is an identifier at ANY length once something precedes it, because a number
//     under a collection segment is a REST id: /api/Products/1 and /api/Products/24 are one vector
//     seen with two products. At position 0 there is nothing in front of it to make it an id, so the
//     four-digit floor still applies there and a bare /2 style root is left alone.
//   - The opaque-token fallback also asks for a digit, which is what keeps application-configuration
//     a route. See pathSegmentIsRouteWord.
func classifyPathSegment(seg string, position int) string {
	switch {
	case jwtValue.MatchString(seg):
		return SignalJWT
	case uuidValue.MatchString(seg):
		return SignalUUID
	case pathNumericSegment.MatchString(seg):
		if position > 0 || numericID.MatchString(seg) {
			return SignalNumericID
		}
		return ""
	// Anchored and hex-only, so there is no word it can reach: nothing a developer types as a route
	// name is sixteen or more characters drawn from abcdef0123456789 alone.
	case longHexValue.MatchString(seg):
		return SignalHighEntropy
	case vectorBase64ish.MatchString(seg) && !pathSegmentIsRouteWord(seg) &&
		shannonEntropy(seg) >= 3.2:
		return SignalHighEntropy
	}
	return ""
}

var pathNumericSegment = regexp.MustCompile(`^[0-9]+$`)

// pathSegmentIsRouteWord reports whether a segment is a name somebody TYPED rather than a value
// somebody generated.
//
// The discriminator is a digit. Generated identifiers are drawn from an alphabet that includes digits
// and, at the twenty characters the token fallback already requires, containing none of them is
// vanishingly unlikely. Route names are words, and words do not contain digits.
//
// This is why application-configuration and applicationConfiguration stay literal. Both clear the
// twenty-character length bar and both clear the 3.2 entropy bar, which between them used to be the
// whole test. Real tokens are unaffected, because a JWT, a UUID and a long hex run each have a rule
// of their own above and never reach this one.
//
// It errs towards leaving a segment literal on purpose, for the reason recorded on templateVectorPath:
// under-templating adds a row, over-templating removes a route.
func pathSegmentIsRouteWord(seg string) bool {
	return !strings.ContainsAny(seg, "0123456789")
}

// appHeaderInputs returns the header names an application put on a request, and what their values
// look like. Browser-set headers are dropped: they are on every request and the site does not read
// them, so admitting them would add roughly a hundred and seventy rows of noise per target.
func appHeaderInputs(headersJSON string) (names []string, signals []string) {
	var headers map[string]any
	if json.Unmarshal([]byte(headersJSON), &headers) != nil {
		return nil, nil
	}
	seenSignal := map[string]bool{}
	for name, value := range headers {
		if !appControlledHeader(name) {
			continue
		}
		names = append(names, templateInputName(strings.ToLower(name)))
		if text, ok := value.(string); ok {
			if kind := classifyInputValue(text); kind != "" && !seenSignal[kind] {
				seenSignal[kind] = true
				signals = append(signals, kind)
			}
		}
	}
	sort.Strings(names)
	sort.Strings(signals)
	if len(names) > 0 {
		signals = append(signals, SignalCustom)
	}
	return names, signals
}

// cookieInputs reads the cookie names out of a captured Cookie header. There is no cookie column on
// the capture table, so the header is the only place they exist.
func cookieInputs(headersJSON string) (names []string, signals []string) {
	var headers map[string]any
	if json.Unmarshal([]byte(headersJSON), &headers) != nil {
		return nil, nil
	}
	raw, _ := headers["cookie"].(string)
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	seenSignal := map[string]bool{}
	for _, pair := range strings.Split(raw, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(pair), "=")
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		names = append(names, templateInputName(name))
		if kind := classifyInputValue(value); kind != "" && !seenSignal[kind] {
			seenSignal[kind] = true
			signals = append(signals, kind)
		}
	}
	sort.Strings(names)
	sort.Strings(signals)
	return names, signals
}

// echoedCookieInputs finds response cookies whose VALUE is a request parameter's value.
//
// THE GAP THIS CLOSES. A cookie a crawl records is one the browser happened to be carrying, so
// cookie vectors are always the ones an application already had. A cookie the SERVER sets from a
// request parameter is different: it is the same attacker-controlled input arriving by a second
// route, and on the next request it arrives with no query string at all.
//
// Measured on the target this framework was developed against. Every GET /catalog?category=<value>
// returned Set-Cookie: category=<the same value>, byte for byte, across five different values. The
// category parameter is also the one with CONFIRMED SQL injection. So a second injection carrier for
// a known-vulnerable input sat one insertion point away, and because the vector list held zero cookie
// vectors, every scan correctly reported nothing wrong with cookies.
//
// It matters beyond that one bug. A payload in a cookie appears in no URL, so it is absent from
// access logs, from the Referer header, and from anything that inspects query strings.
func echoedCookieInputs(responseHeadersJSON, getParamsJSON, postParamsJSON string) (names, signals []string) {
	setCookies := setCookieValues(responseHeadersJSON)
	if len(setCookies) == 0 {
		return nil, nil
	}
	// The values the CALLER supplied on this request. A response cookie matching one of these was
	// built from caller-controlled input.
	supplied := map[string]bool{}
	for _, blob := range []string{getParamsJSON, postParamsJSON} {
		var values map[string]any
		if json.Unmarshal([]byte(blob), &values) != nil {
			continue
		}
		for _, v := range values {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				supplied[s] = true
			}
		}
	}
	if len(supplied) == 0 {
		return nil, nil
	}

	seenSignal := map[string]bool{}
	for name, value := range setCookies {
		if !supplied[value] {
			continue
		}
		names = append(names, templateInputName(name))
		if kind := classifyInputValue(value); kind != "" && !seenSignal[kind] {
			seenSignal[kind] = true
			signals = append(signals, kind)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	// A signal of its own, because this cookie is not like the others in the jar: the operator should
	// see at a glance that the server built it from something they sent.
	signals = append(signals, "server_set")
	sort.Strings(names)
	sort.Strings(signals)
	return names, signals
}

// setCookieValues pulls name/value pairs out of a response's Set-Cookie headers, which arrive either
// as one string or as an array depending on how the capture was stored.
func setCookieValues(responseHeadersJSON string) map[string]string {
	var headers map[string]any
	if json.Unmarshal([]byte(responseHeadersJSON), &headers) != nil {
		return nil
	}
	out := map[string]string{}
	for key, raw := range headers {
		if !strings.EqualFold(strings.TrimSpace(key), "set-cookie") {
			continue
		}
		var lines []string
		switch v := raw.(type) {
		case string:
			lines = append(lines, v)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					lines = append(lines, s)
				}
			}
		}
		for _, line := range lines {
			// Only the first segment is the pair; everything after a semicolon is an attribute.
			pair, _, _ := strings.Cut(line, ";")
			name, value, found := strings.Cut(strings.TrimSpace(pair), "=")
			if !found {
				continue
			}
			if name = strings.TrimSpace(name); name != "" {
				out[name] = strings.TrimSpace(value)
			}
		}
	}
	return out
}

// inputSignalsFor reports what the VALUES of a set of parameters look like, so a query string
// carrying a session token reads differently from one carrying a page number.
func inputSignalsFor(blob string, names []string) []string {
	var values map[string]any
	if json.Unmarshal([]byte(blob), &values) != nil {
		return nil
	}
	seen := map[string]bool{}
	var signals []string
	for _, name := range names {
		text, ok := values[name].(string)
		if !ok {
			continue
		}
		if kind := classifyInputValue(text); kind != "" && !seen[kind] {
			seen[kind] = true
			signals = append(signals, kind)
		}
	}
	sort.Strings(signals)
	return signals
}
