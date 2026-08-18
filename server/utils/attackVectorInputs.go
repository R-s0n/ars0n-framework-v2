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
func templateVectorPath(path string) (templated string, signals []string) {
	if path == "" {
		return "/", nil
	}
	segments := strings.Split(path, "/")
	seen := map[string]bool{}
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		kind := classifyInputValue(seg)
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
