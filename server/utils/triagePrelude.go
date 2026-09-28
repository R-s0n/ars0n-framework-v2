package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"ars0n-framework-v2-server/utils/triage"
)

// The request prelude: fetching a fresh single-use token before every probe, and saying honestly
// when one could not be fetched.
//
// WHY THIS EXISTS AND WHY IT IS NOT OPTIONAL. On a synchronizer-token application, replaying a
// captured body reuses a token the server has already burned. Every probe then fails validation
// in exactly the same way, at exactly the same status, with exactly the same body. The
// differential sees no variance between probes, the baseline sees no variance either, and the
// vector comes out UNSTABLE or CLEAN while having examined nothing at all. In the measured corpus
// that silences roughly 44 mutating vectors including all 23 POSTs, and it does it while looking
// like coverage.
//
// The failure state is therefore DISTINCT and it is an unknown. PreludeTokenUnobtainable means
// "this probe needs a token we could not get, so the slot is untested". It is never unstable, it
// is never clean, and PreludeBlockedVerdict is the only sanctioned way to turn it into a
// ClassVerdict so that no class can accidentally spell it as a negative.
//
// A FRESHLY FETCHED TOKEN IS VOLATILE BY CONSTRUCTION. It is different on every fetch, by design,
// so if it reaches the comparator unsuppressed then every probe differs from the baseline in the
// token bytes and every vector reads as changed. That exclusion is coordinated through the
// Observation record, via PreludeVolatility.SuppressIn and .Regions, and not by editing the
// comparator, which is another agent's file.

// ---------------------------------------------------------------------------------------------
// 1. WHICH NAMES ARE TOKENS
// ---------------------------------------------------------------------------------------------

// PreludeTokenKind says what kind of single-use material a field carries, because the three kinds
// fail differently and only one of them can be refreshed by a plain GET.
type PreludeTokenKind string

const (
	// TokenKindSynchronizer is the classic per-session or per-request CSRF token. A fresh GET of
	// the form page yields a usable one.
	TokenKindSynchronizer PreludeTokenKind = "synchronizer"

	// TokenKindDoubleSubmit is the cookie-and-field pair. The field must equal the cookie, so the
	// Set-Cookie from the prelude fetch has to be carried forward with the value.
	TokenKindDoubleSubmit PreludeTokenKind = "double_submit"

	// TokenKindViewState is ASP.NET __VIEWSTATE and friends. It is a MAC over the WHOLE form, so
	// mutating any field invalidates it and no prelude can fix that. It gets its own state,
	// PreludeViewstateBound, rather than being refreshed and silently failing anyway.
	TokenKindViewState PreludeTokenKind = "viewstate"

	// TokenKindOAuthState is the OAuth/OIDC state parameter. Single-use in the same way and for
	// the same reason, and it is in the request-side name list because a probe against an
	// authorization callback that replays a burnt state tests the state check, not the slot.
	TokenKindOAuthState PreludeTokenKind = "oauth_state"
)

// tokenNameRule matches a parameter, header or cookie name against the token vocabulary.
//
// Substring matching is per-name and deliberately not universal. "csrf" and "xsrf" are matched as
// substrings because the wild variety is enormous (X-CSRF-Token, X-CSRFToken, csrf_token,
// csrfmiddlewaretoken, _csrf) and every one of them is the same mechanism. "state" is matched
// EXACTLY, because as a substring it also matches state, estate, statement, us_state and
// stateCode, and a false token requirement makes every probe on that vector fetch a prelude it
// does not need and then report unobtainable when the fetch finds nothing.
type tokenNameRule struct {
	name      string
	substring bool
	kind      PreludeTokenKind
}

var preludeTokenRules = []tokenNameRule{
	{"authenticity_token", false, TokenKindSynchronizer},
	{"authenticitytoken", false, TokenKindSynchronizer},
	{"__requestverificationtoken", false, TokenKindSynchronizer},
	{"requestverificationtoken", false, TokenKindSynchronizer},
	{"_token", false, TokenKindSynchronizer},
	{"csrf", true, TokenKindSynchronizer},
	{"xsrf", true, TokenKindDoubleSubmit},
	{"state", false, TokenKindOAuthState},
	{"__viewstate", false, TokenKindViewState},
	{"__viewstategenerator", false, TokenKindViewState},
	{"__eventvalidation", false, TokenKindViewState},
}

// ClassifyTokenName reports whether a field name is a single-use token name, and which kind.
func ClassifyTokenName(name string) (PreludeTokenKind, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "", false
	}
	for _, r := range preludeTokenRules {
		if r.substring {
			if strings.Contains(n, r.name) {
				return r.kind, true
			}
			continue
		}
		if n == r.name {
			return r.kind, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// 1b. A NAME IN THE VOCABULARY IS NOT YET A REQUIREMENT: THE OAUTH `state` PROBLEM
// ---------------------------------------------------------------------------------------------
//
// MEASURED, live run a218419a. 821 verdicts, every one cannot_determine, across 4 slot kinds on
// 5 vectors, and ALL of them were caused by one word: `state`. There was no CSRF token anywhere
// on that estate. The two request shapes were
//
//	GET  /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&state=bbtest123
//	POST /api/v1/oauth/client  {"response_type":"code","client_id":"...","state":"bbtest123"}
//
// and in both of them `state` is the OAuth state parameter on the way OUT. RFC 6749 gives that
// value to the CLIENT to mint and to the CLIENT to check when it comes back. The server never
// issues it, never stores it and never burns it; here it was literally the string the operator
// typed. So no response can ever serve a fresh one, the prelude reports unobtainable every time,
// and the whole vector is thrown away for a token that does not exist. Worse, the requirement is
// per VECTOR, so one client-minted `state` in a JSON body also silenced every header and cookie
// slot on that vector: 300 cookie and 270 header verdicts in that run were collateral.
//
// The same rule fires on ordinary REST data. A field named `state` holding "active", "CA" or
// "pending" is matched exactly, and the exact match does not help: the spelling was never the
// problem, the SEMANTICS were.
//
// So the vocabulary and the requirement are separated. ClassifyTokenName still answers "is this
// name in the token vocabulary", unchanged, because the response side uses it to recognise a
// token a server published. Whether a REQUEST must refresh one is decided here, from the request
// around the name, and it has three answers rather than two.

// preludeOAuthRole is which leg of an OAuth exchange a request is on, read from the parameter
// names RFC 6749 defines rather than from the path, because a callback is routinely mounted on a
// path with no telltale word in it and an authorization endpoint is routinely called /authorize,
// /oauth2/auth or /connect/authorize.
type preludeOAuthRole string

const (
	// oauthRoleNone: no OAuth parameters at all, so a field called `state` is application data.
	oauthRoleNone preludeOAuthRole = "not_oauth"

	// oauthRoleAuthzRequest: the client is STARTING the exchange. state is client-minted here.
	oauthRoleAuthzRequest preludeOAuthRole = "oauth_authorization_request"

	// oauthRoleCallback: the authorization server is RETURNING to the client, so the state in
	// this request is one a strict client checks against what it stored, and replaying a burnt
	// one tests that check and not the slot. No GET can mint a fresh one, so this stays a hard
	// requirement and the honest unobtainable is the right answer for it.
	oauthRoleCallback preludeOAuthRole = "oauth_callback"
)

// The parameter names that decide the role. Exact matches only: code_challenge is not code.
var (
	preludeAuthzRequestMarkers = map[string]bool{
		"response_type": true, "client_id": true, "code_challenge": true,
		"code_challenge_method": true, "response_mode": true,
	}
	preludeCallbackMarkers = map[string]bool{
		"code": true, "error": true, "id_token": true, "access_token": true,
		"authorization_code": true,
	}
)

// preludeRequestFieldNames is every field name the request carries in its query and its body, at
// any depth. Header names are not included: OAuth parameters do not travel in headers, and a
// header called Code-Version would otherwise turn an ordinary request into a callback.
func preludeRequestFieldNames(r PreludeRequest) map[string]bool {
	out := map[string]bool{}
	if u, err := url.Parse(r.URL); err == nil && u.RawQuery != "" {
		if vals, err := url.ParseQuery(u.RawQuery); err == nil {
			for k := range vals {
				out[strings.ToLower(k)] = true
			}
		}
	}
	switch r.Media {
	case triage.BodyForm:
		if vals, err := url.ParseQuery(string(r.Body)); err == nil {
			for k := range vals {
				out[strings.ToLower(k)] = true
			}
		}
	case triage.BodyJSON:
		var doc any
		if json.Unmarshal(r.Body, &doc) == nil {
			preludeWalkJSONKeys(doc, func(k string) { out[strings.ToLower(k)] = true })
		}
	}
	return out
}

// preludeWalkJSONKeys visits every object key at every depth, including the keys of objects whose
// values are not strings. triageWalkJSONStrings cannot be reused here: it only reaches keys whose
// value is a string, and response_type is a string but client_id may be a number and
// redirect_uri may sit under a nested object.
func preludeWalkJSONKeys(node any, visit func(string)) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			visit(k)
			preludeWalkJSONKeys(child, visit)
		}
	case []any:
		for i := range v {
			preludeWalkJSONKeys(v[i], visit)
		}
	}
}

// preludeRoleOf reads the OAuth role off the request's own parameter names.
func preludeRoleOf(r PreludeRequest) preludeOAuthRole {
	names := preludeRequestFieldNames(r)
	for m := range preludeAuthzRequestMarkers {
		if names[m] {
			return oauthRoleAuthzRequest
		}
	}
	for m := range preludeCallbackMarkers {
		if names[m] {
			return oauthRoleCallback
		}
	}
	return oauthRoleNone
}

// preludeTokenDemand is how hard the prelude must work for one discovered name.
type preludeTokenDemand int

const (
	// demandNone: this name is not a token in this request.
	demandNone preludeTokenDemand = iota

	// demandSoft: this name MIGHT be a server-issued token and we will not guess. The prelude
	// asks the server for one. If the server publishes one under that exact name, in a place a
	// server publishes tokens, it is refreshed exactly like a hard one. If the server publishes
	// nothing, the answer is a MEASURED "no token is required here" and the probes go out. See
	// PreludeSoftUnserved.
	demandSoft

	// demandHard: a token is required. No fresh value means no probe, and the slot is unknown.
	demandHard
)

// preludeDemandFor decides how hard a discovered name is demanded, given the request's role.
//
// Everything in the vocabulary except `state` is hard, because csrf, xsrf, authenticity_token,
// _token, __RequestVerificationToken and the viewstate family name ONE mechanism each and a
// server-issued one. `state` names two different things, so it is the only one the role decides.
func preludeDemandFor(name string, role preludeOAuthRole) (PreludeTokenKind, preludeTokenDemand) {
	kind, ok := ClassifyTokenName(name)
	if !ok {
		return "", demandNone
	}
	if kind != TokenKindOAuthState {
		return kind, demandHard
	}
	if role == oauthRoleCallback {
		return kind, demandHard
	}
	return kind, demandSoft
}

// ---------------------------------------------------------------------------------------------
// 2. REQUEST-SIDE DISCOVERY: DOES THIS VECTOR NEED A TOKEN AT ALL
// ---------------------------------------------------------------------------------------------

// TokenSlot is one place in the captured request that carries a single-use token.
//
// Observed is the STALE value from the capture. It is kept because it is the only reliable way to
// find the token again in the raw body bytes: replacing the stale value in place preserves the
// byte order of the capture, where re-serialising a parsed body would reorder the fields and turn
// every probe into a diff against a baseline built from different bytes.
type TokenSlot struct {
	Name      string
	Kind      PreludeTokenKind
	Where     triage.SlotKind
	FieldPath string
	Observed  string

	// Soft says this name might be a server-issued token and might be ordinary application data,
	// and that the prelude will let the SERVER settle it rather than guessing. A soft slot the
	// server serves no value for does not block the probe, and the result says so by name
	// (PreludeResult.SoftUnserved) rather than by silence. See preludeTokenDemand.
	Soft bool
}

// PreludeRequest is the captured request under examination. It is a plain struct rather than an
// *http.Request because discovery runs against rows read back from the corpus, long after the
// request object is gone.
type PreludeRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
	Media  triage.BodyMedia
}

// Mutating reports whether this verb can change state. Only mutating requests are gated on a
// token in practice, but discovery does not filter on it: the measured corpus has 168 GETs and
// some frameworks put the token on every request, and a GET that needs one and does not get one
// fails just as silently.
func (r PreludeRequest) Mutating() bool {
	switch strings.ToUpper(r.Method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// DiscoverRequiredTokens finds every token-shaped field in the captured request: query, headers,
// cookies and body.
//
// It reads the RAW REQUEST, and never the stored parameter-name array that SlotsFor owns. That
// array is empty for all 51 path vectors in the measured corpus, and a discovery pass iterating it
// would report "no token required" for every one of them and then record them tested. The guard
// in triageTypes_test.go scans these files for that column by name, which is why it is described
// here rather than spelled.
func DiscoverRequiredTokens(r PreludeRequest) []TokenSlot {
	return AssessPreludeRequirement(r).Slots
}

// PreludeRequirement is the whole answer to "does this request need a fresh token", with the
// evidence that produced it.
//
// WHY IT CARRIES A BASIS. "No token-shaped field was found" is an ABSENCE, and this codebase has
// been bitten seven times in one week by an absence that reads as a positive fact. Basis is the
// positive half: the mechanism that makes a CSRF token unnecessary on this request, named, so
// that "no token is required here" is an answer rather than a shrug. It is reported and never
// load-bearing on its own, with one exception recorded in preludeDemandFor: an OAuth `state` on
// an authorization request is client-minted by the protocol, and that IS decisive.
type PreludeRequirement struct {
	// Slots is what DiscoverRequiredTokens returns: every token-shaped field, hard and soft.
	Slots []TokenSlot

	// Role is the OAuth leg this request is on, as a readable string for the reason text.
	Role string

	// Basis is the positive evidence, strongest first, for a not-required answer.
	Basis []string
}

// Hard reports whether any discovered slot blocks the probe when it cannot be refreshed.
func (q PreludeRequirement) Hard() bool {
	for _, s := range q.Slots {
		if !s.Soft {
			return true
		}
	}
	return false
}

// Why renders the basis as one sentence for a reason string.
func (q PreludeRequirement) Why() string {
	if len(q.Basis) == 0 {
		return "no positive evidence either way was recorded, which is itself the defect"
	}
	return strings.Join(q.Basis, "; ")
}

// The positive reasons a request needs no CSRF token. Each one names a MECHANISM, because a
// reason a reader cannot check is the same as no reason.
const (
	// PreludeBasisBearerAuthority is the strongest and the commonest on a JSON API: the request's
	// authority is an Authorization header, which a browser does not attach to a cross-site
	// request on its own. There is no ambient authority to forge, so a CSRF token would defend
	// nothing, and applications built this way overwhelmingly do not deploy one. 170 of the 215
	// captures in the measured corpus are this shape.
	PreludeBasisBearerAuthority = "the request's authority is an Authorization header, which a browser never attaches cross-site, so there is no ambient authority for a CSRF token to protect"

	// PreludeBasisPreflightedMedia: a content type outside the three a plain HTML form can
	// produce forces a CORS preflight, so the request cannot be forged by a cross-site form post.
	PreludeBasisPreflightedMedia = "the body media forces a CORS preflight, so no cross-site form can produce this request"

	// PreludeBasisPreflightedMethod: likewise for a verb outside GET/HEAD/POST.
	PreludeBasisPreflightedMethod = "the verb is outside the CORS-simple set, so no cross-site form can produce this request"

	// PreludeBasisOAuthStateClientMinted is the decisive one for the 821 verdicts this cost.
	PreludeBasisOAuthStateClientMinted = "the state parameter on an OAuth authorization request is minted by the client and never issued or burnt by the server, so there is nothing to refresh"

	// PreludeBasisNoTokenField is the weak fallback, and it says it is weak.
	PreludeBasisNoTokenField = "no token-shaped field appears anywhere in the captured request, which is an absence rather than a proof"
)

// AssessPreludeRequirement finds every token-shaped field in the captured request and decides,
// per field, whether the prelude must refresh it, may refresh it, or must leave it alone.
//
// It reads the RAW REQUEST, and never the stored parameter-name array that SlotsFor owns. That
// array is empty for all 51 path vectors in the measured corpus, and a discovery pass iterating it
// would report "no token required" for every one of them and then record them tested. The guard
// in triageTypes_test.go scans these files for that column by name, which is why it is described
// here rather than spelled.
func AssessPreludeRequirement(r PreludeRequest) PreludeRequirement {
	role := preludeRoleOf(r)
	q := PreludeRequirement{Role: string(role)}
	out := &q.Slots

	add := func(name string, where triage.SlotKind, fieldPath, observed string) {
		kind, demand := preludeDemandFor(name, role)
		if demand == demandNone {
			return
		}
		*out = append(*out, TokenSlot{
			Name: name, Kind: kind, Where: where, FieldPath: fieldPath,
			Observed: observed, Soft: demand == demandSoft,
		})
	}

	if u, err := url.Parse(r.URL); err == nil && u.RawQuery != "" {
		if vals, err := url.ParseQuery(u.RawQuery); err == nil {
			for _, name := range triageSortedQueryKeys(vals) {
				add(name, triage.KindQuery, "", vals.Get(name))
			}
		}
	}

	for _, name := range triageSortedHeaderNames(r.Header) {
		if strings.EqualFold(name, "Cookie") {
			continue
		}
		add(name, triage.KindHeader, "", r.Header.Get(name))
	}

	// Cookies are read by splitting the Cookie header by hand. http.Request.Cookies would work
	// for reading, but the write side must not use http.Cookie at all (it drops ; " and \ with
	// only a line on the stdlib logger), and keeping both directions in one hand-rolled form is
	// what stops somebody reaching for AddCookie on the way back.
	for _, c := range triageParseCookieHeader(r.Header.Get("Cookie")) {
		add(c[0], triage.KindCookie, "", c[1])
	}

	before := len(q.Slots)
	switch r.Media {
	case triage.BodyForm:
		if vals, err := url.ParseQuery(string(r.Body)); err == nil {
			for _, name := range triageSortedQueryKeys(vals) {
				add(name, triage.KindBody, name, vals.Get(name))
			}
		}
	case triage.BodyJSON:
		var doc any
		if json.Unmarshal(r.Body, &doc) == nil {
			triageWalkJSONStrings(doc, "", func(path, key, value string) {
				add(key, triage.KindBody, path, value)
			})
			body := q.Slots[before:]
			sort.Slice(body, func(i, j int) bool { return body[i].FieldPath < body[j].FieldPath })
		}
	}

	q.Basis = preludeNoTokenBasis(r, role, q.Slots)
	return q
}

// preludeNoTokenBasis is the positive evidence, strongest first, that this request needs no
// server-issued token. It is computed whether or not a slot was found, because the reason text
// for a soft slot the server did not serve needs the same evidence as the reason text for a
// request with no token-shaped field at all.
func preludeNoTokenBasis(r PreludeRequest, role preludeOAuthRole, slots []TokenSlot) []string {
	var basis []string
	if role == oauthRoleAuthzRequest {
		for _, s := range slots {
			if s.Kind == TokenKindOAuthState {
				basis = append(basis, PreludeBasisOAuthStateClientMinted)
				break
			}
		}
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		basis = append(basis, PreludeBasisBearerAuthority)
	}
	switch strings.ToUpper(strings.TrimSpace(r.Method)) {
	case "", http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		basis = append(basis, PreludeBasisPreflightedMethod)
	}
	// The CORS-simple body media are the ones a plain HTML form can produce: urlencoded,
	// multipart and text/plain. Everything else is preflighted, so a cross-site page cannot make
	// the browser send it at all. BodyNone is not evidence either way and earns no basis: a
	// request whose media we did not recognise is not a request we get to call safe.
	switch r.Media {
	case triage.BodyJSON, triage.BodyXML, triage.BodyGraphQL:
		if len(r.Body) > 0 {
			basis = append(basis, PreludeBasisPreflightedMedia)
		}
	}
	if len(slots) == 0 {
		basis = append(basis, PreludeBasisNoTokenField)
	}
	return basis
}

func triageWalkJSONStrings(node any, path string, visit func(path, key, value string)) {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := path + "/" + k
			if s, ok := v[k].(string); ok {
				visit(child, k, s)
				continue
			}
			triageWalkJSONStrings(v[k], child, visit)
		}
	case []any:
		for i := range v {
			triageWalkJSONStrings(v[i], fmt.Sprintf("%s/%d", path, i), visit)
		}
	}
}

// triageParseCookieHeader splits a Cookie header into ordered name/value pairs without decoding
// anything. Order is preserved because the header is rebuilt from it, and a reordered Cookie
// header is a different request byte for byte.
func triageParseCookieHeader(h string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(h, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		out = append(out, [2]string{strings.TrimSpace(name), value})
	}
	return out
}

func triageSortedQueryKeys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func triageSortedHeaderNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------------
// 3. RESPONSE-SIDE LOCATORS: WHERE A FRESH TOKEN CAN BE READ FROM
// ---------------------------------------------------------------------------------------------

// The four sources a fresh token is read from.
const (
	TokenSourceMetaTag     = "meta_tag"
	TokenSourceHiddenInput = "hidden_input"
	TokenSourceSetCookie   = "set_cookie"
	TokenSourceJSONField   = "json_field"
	TokenSourceHeader      = "response_header"
)

// TokenLocator is one fresh token found in a prelude response.
type TokenLocator struct {
	Source string
	Name   string
	Value  string
	Kind   PreludeTokenKind
}

var (
	triageMetaTagPattern  = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	triageInputTagPattern = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	triageAttrPattern     = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

func triageTagAttrs(tag string) map[string]string {
	out := map[string]string{}
	for _, m := range triageAttrPattern.FindAllStringSubmatch(tag, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		if v == "" {
			v = m[4]
		}
		// Token values are routinely base64 and routinely contain + and =, which templating
		// layers HTML-escape. Unescaping here is what stops a token being sent back as
		// "a&#43;b" and rejected for a reason that looks like the probe.
		out[strings.ToLower(m[1])] = html.UnescapeString(v)
	}
	return out
}

// LocateTokens finds every fresh token in a prelude response: meta tags, hidden inputs,
// Set-Cookie, JSON fields and response headers.
func LocateTokens(body []byte, header http.Header) []TokenLocator {
	var out []TokenLocator

	for _, tag := range triageMetaTagPattern.FindAllString(string(body), -1) {
		a := triageTagAttrs(tag)
		name := a["name"]
		if name == "" {
			name = a["property"]
		}
		// Rails writes <meta name="csrf-param" content="authenticity_token"> next to
		// <meta name="csrf-token" content="...">, so the param tag names the FIELD and the token
		// tag holds the value. Only the one with a usable content value is a locator.
		if kind, ok := ClassifyTokenName(name); ok && a["content"] != "" {
			out = append(out, TokenLocator{Source: TokenSourceMetaTag, Name: name, Value: a["content"], Kind: kind})
		}
	}

	for _, tag := range triageInputTagPattern.FindAllString(string(body), -1) {
		a := triageTagAttrs(tag)
		if kind, ok := ClassifyTokenName(a["name"]); ok && a["value"] != "" {
			out = append(out, TokenLocator{Source: TokenSourceHiddenInput, Name: a["name"], Value: a["value"], Kind: kind})
		}
	}

	for _, sc := range header.Values("Set-Cookie") {
		name, rest, found := strings.Cut(sc, "=")
		if !found {
			continue
		}
		value, _, _ := strings.Cut(rest, ";")
		if kind, ok := ClassifyTokenName(strings.TrimSpace(name)); ok && value != "" {
			out = append(out, TokenLocator{Source: TokenSourceSetCookie, Name: strings.TrimSpace(name), Value: value, Kind: kind})
		}
	}

	for _, name := range triageSortedHeaderNames(header) {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		if kind, ok := ClassifyTokenName(name); ok && header.Get(name) != "" {
			out = append(out, TokenLocator{Source: TokenSourceHeader, Name: name, Value: header.Get(name), Kind: kind})
		}
	}

	var doc any
	if err := json.Unmarshal(body, &doc); err == nil {
		triageWalkJSONStrings(doc, "", func(_, key, value string) {
			if kind, ok := ClassifyTokenName(key); ok && value != "" {
				out = append(out, TokenLocator{Source: TokenSourceJSONField, Name: key, Value: value, Kind: kind})
			}
		})
	}
	return out
}

// triageMatchLocator picks the fresh value for one required slot. Exact name first, then same-kind, so
// a page that serves the token as <meta name="csrf-token"> still satisfies a body field called
// authenticity_token. The kind fallback is what makes the mechanism work on Rails, Django and
// ASP.NET without a per-framework table.
//
// NEITHER CONVENIENCE IS OFFERED TO AN AMBIGUOUS NAME, and `state` is ambiguous however hard it
// is demanded. MEASURED against the pre-change code on the request shapes from run a218419a: a
// response body of {"ok":true,"state":"active"} satisfied a `state` slot, and the prelude
// reported token_obtained and would have rewritten the OAuth state parameter to the word
// "active" before sending every probe. That is worse than the block it sometimes produced
// instead: a corrupted request that the differential then reads as a finding or as stability.
//
// So for a soft slot and for every oauth_state slot: exact name only, no kind fallback, and only
// from the four places a server PUBLISHES a token for the client to hand back. A JSON field is
// data the API returned, not a mint.
func triageMatchLocator(slot TokenSlot, locs []TokenLocator) (TokenLocator, bool) {
	if slot.Soft || slot.Kind == TokenKindOAuthState {
		for _, l := range locs {
			if strings.EqualFold(l.Name, slot.Name) && preludeSourceIsAMint(l.Source) {
				return l, true
			}
		}
		return TokenLocator{}, false
	}
	for _, l := range locs {
		if strings.EqualFold(l.Name, slot.Name) {
			return l, true
		}
	}
	for _, l := range locs {
		if l.Kind == slot.Kind {
			return l, true
		}
	}
	return TokenLocator{}, false
}

// preludeSourceIsAMint reports whether a locator source is a place a server publishes a token for
// the client to hand back, as opposed to a place it returns application data.
func preludeSourceIsAMint(source string) bool {
	switch source {
	case TokenSourceMetaTag, TokenSourceHiddenInput, TokenSourceSetCookie, TokenSourceHeader:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------------------------
// 4. THE FETCH
// ---------------------------------------------------------------------------------------------

// PreludeSpec is where and how to get a fresh token.
type PreludeSpec struct {
	URL      string
	Method   string
	Header   http.Header
	Cookies  string
	Required []TokenSlot

	// Basis is the positive evidence from AssessPreludeRequirement that this request needs no
	// server-issued token, carried through so a not-required answer arrives with its reason
	// attached instead of as a silence. Purely descriptive: it changes no decision.
	Basis []string

	// Fallbacks are extra same-origin URLs to try, in order, when URL yields no usable token.
	// They are tried before the derived ones.
	Fallbacks []string

	// NoAutoFallback switches off the derived candidates. Off by default, because the derived
	// walk only ever runs where the single-URL version had already given up and thrown the whole
	// vector away, and a handful of GETs is cheaper than a missed bug.
	NoAutoFallback bool

	// MaxBody caps the prelude response read. Zero means preludeDefaultMaxBody.
	MaxBody int64
}

const preludeDefaultMaxBody = 4 << 20

// preludeMaxAttempts caps the candidate walk, the primary URL included.
const preludeMaxAttempts = 5

// WHY THE PRELUDE FETCHES MORE THAN ONE URL. The runner hands this a single URL: the vector's
// own. On a form-per-page application that is right, because the token is minted by the page the
// form lives on. On a JSON REST API it cannot work, and the measured corpus is a JSON REST API:
// the vector is POST /api/v1/oauth/client, a GET of that same URL answers 404, 405 or an empty
// envelope, and no amount of looking at it will ever produce a token. An API that does use a
// CSRF token publishes it somewhere else entirely, in a meta tag on the SPA shell at /, in a
// Set-Cookie on any authenticated GET, or on a dedicated /csrf route.
//
// So a failed primary is followed by same-origin candidates, in the order most likely to be the
// mint: the document the capture says referred it (that IS the page that minted the token, when
// there was one), then the origin root, then the request path's ancestors. The walk never leaves
// the origin, never changes verb, and stops the moment every hard slot is satisfied.
func preludeCandidateURLs(spec PreludeSpec) []string {
	primary, err := url.Parse(spec.URL)
	if err != nil || primary.Host == "" {
		return []string{spec.URL}
	}
	out := []string{spec.URL}
	seen := map[string]bool{spec.URL: true}
	push := func(raw string) {
		if raw == "" || seen[raw] || len(out) >= preludeMaxAttempts {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != primary.Scheme || u.Host != primary.Host {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}

	for _, f := range spec.Fallbacks {
		push(f)
	}
	if spec.NoAutoFallback {
		return out
	}

	// The Referer from the capture. On the measured corpus this is the OAuth authorization page
	// the XHR was fired from, which is exactly where a token would have lived.
	if ref := strings.TrimSpace(spec.Header.Get("Referer")); ref != "" {
		push(ref)
	}
	push(primary.Scheme + "://" + primary.Host + "/")
	for p := primary.EscapedPath(); ; {
		i := strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/')
		if i <= 0 {
			break
		}
		p = p[:i]
		push(primary.Scheme + "://" + primary.Host + p)
	}
	return out
}

// preludeAttempt is one candidate fetch, kept so the reason can say where it looked. A prelude
// that says "unobtainable" without saying where it went is not a measurement either.
type preludeAttempt struct {
	URL          string
	Status       int
	Err          string
	Contaminated string
	Missing      []string
}

func (a preludeAttempt) describe() string {
	switch {
	case a.Err != "":
		return a.URL + " (" + a.Err + ")"
	case a.Contaminated != "":
		return fmt.Sprintf("%s (%d, carried our own marker %s)", a.URL, a.Status, a.Contaminated)
	case len(a.Missing) > 0:
		return fmt.Sprintf("%s (%d, served no value for %s)", a.URL, a.Status, strings.Join(a.Missing, ", "))
	default:
		return fmt.Sprintf("%s (%d)", a.URL, a.Status)
	}
}

func preludeDescribeAttempts(as []preludeAttempt) string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.describe())
	}
	return strings.Join(out, "; ")
}

// PreludeVolatility carries the values that are different on every fetch by construction, so the
// comparator can be told to ignore them. See SuppressIn.
type PreludeVolatility struct {
	Values []string
	Names  []string
}

// PreludeResult is one prelude fetch. State is the honest answer and is never inferred by the
// caller from whether Tokens is empty.
type PreludeResult struct {
	State  triage.PreludeState
	Reason string

	Tokens     map[string]string
	Locators   []TokenLocator
	SetCookies string
	Status     int
	FetchedAt  time.Time
	Volatility PreludeVolatility

	// SourceURL is the candidate that actually served the tokens, which is not always spec.URL.
	SourceURL string

	// SoftUnserved names the soft slots the server published nothing for, each as where:name.
	// This is the MEASURED "no token is required here": we asked, and the server has none. It is
	// recorded rather than left silent, because a soft slot that quietly disappeared would be
	// the same absence-read-as-a-fact this file exists to stop.
	SoftUnserved []string

	// Basis is the positive evidence behind a PreludeTokenNotRequired answer, from
	// PreludeRequirement.Basis. Empty on any other state.
	Basis []string

	// Obs is the fetch recorded as an ObsPreludeControl observation. It carries no payload and no
	// class, so NewReplay accepts it: the prelude fetch is a control, shared by everyone, which
	// is allowed precisely because nothing about it is perturbed.
	Obs triage.Observation
}

// Blocked reports whether this prelude stops the probe from being sent. It is PreludeState.Failed
// by another name, kept here so a caller reads it off the result it already has rather than
// reaching for the state and spelling the comparison itself.
func (r PreludeResult) Blocked() bool { return r.State.Failed() }

// FetchPreludeTokens performs one prelude fetch. Call it BEFORE EACH PROBE, not once per vector:
// a single-use token burnt by probe 1 fails probe 2 identically to the way a replayed capture
// fails probe 1, which is the exact failure this whole file exists to prevent.
//
// "One fetch" now means one WALK: the primary URL and, only if that yields nothing usable, the
// same-origin candidates preludeCandidateURLs derives. The walk stops at the first candidate
// that satisfies every hard slot, so on a form-per-page application it is exactly the one fetch
// it always was.
func FetchPreludeTokens(ctx context.Context, client *http.Client, spec PreludeSpec) PreludeResult {
	res := PreludeResult{FetchedAt: time.Now(), Tokens: map[string]string{}}

	if len(spec.Required) == 0 {
		res.State = triage.PreludeTokenNotRequired
		res.Basis = spec.Basis
		res.Reason = "no token is required here: " + preludeJoinBasis(spec.Basis)
		return res
	}
	if spec.URL == "" {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "no prelude url: " + triageDescribeSlots(spec.Required) + " are required and there is nowhere to fetch them from"
		return res
	}
	if client == nil {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "no http client supplied to the prelude fetch"
		return res
	}

	// A VIEWSTATE IS DECIDED BEFORE ANY FETCH. It is a MAC over the whole form, the probe is
	// about to mutate a field the MAC covers, and the server will reject every probe for that
	// reason and not for anything the probe did. Refreshing it cannot help, so fetching for it
	// is a request sent for nothing. This used to be checked only AFTER a fetch that satisfied
	// every slot, so a viewstate form whose fetch failed reported unobtainable instead, and the
	// two states are different answers to the operator.
	for _, slot := range spec.Required {
		if slot.Kind == TokenKindViewState {
			res.State = triage.PreludeViewstateBound
			res.Reason = "field " + slot.Name + " is a viewstate MAC over the whole form, so any mutated field is rejected regardless of the payload"
			return res
		}
	}

	var attempts []preludeAttempt
	var best *preludeOutcome
	for _, candidate := range preludeCandidateURLs(spec) {
		out := preludeFetchOnce(ctx, client, spec, candidate)
		attempts = append(attempts, out.attempt)
		if res.Obs.Kind == "" {
			res.Obs = out.obs
		}
		if out.attempt.Err != "" {
			continue
		}
		if best == nil || out.better(*best) {
			o := out
			best = &o
		}
		if out.satisfied() {
			break
		}
	}

	if best == nil {
		// Every candidate failed before it served a body. The last attempt's observation is on
		// the result already, carrying the transport error kind.
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "no prelude candidate served a usable response for " + triageDescribeSlots(spec.Required) +
			". Tried: " + preludeDescribeAttempts(attempts)
		return res
	}

	res.Status = best.attempt.Status
	res.SetCookies = best.setCookies
	res.SourceURL = best.attempt.URL
	res.Locators = best.locators
	res.Obs = best.obs

	// A control that contains one of our own markers is not a control. Either the prelude URL is
	// itself a probed surface with a stored reflection, or the fetch went through a cache holding
	// a probe response. Either way the token read out of it may be a probe artefact, so the state
	// says so instead of the probes proceeding on it. Reported only when NO candidate came back
	// clean, because a clean sibling is a perfectly good control and refusing it would throw the
	// vector away for a contamination the walk routed around.
	if best.attempt.Contaminated != "" {
		res.State = triage.PreludeControlContaminated
		res.Reason = fmt.Sprintf("the prelude response carries marker %s (class %s), so it is a probe artefact and not a control",
			best.contaminant, best.contaminantClass)
		return res
	}

	for _, name := range best.tokenOrder {
		value := best.tokens[name]
		res.Tokens[name] = value
		res.Volatility.Values = triageAppendUnique(res.Volatility.Values, value)
		res.Volatility.Names = triageAppendUnique(res.Volatility.Names, name)
	}
	res.SoftUnserved = best.softUnserved

	if len(best.missing) > 0 {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "the prelude served no value for " + strings.Join(best.missing, ", ") +
			"; the probe would have replayed a burnt token and failed validation identically every time. Tried: " +
			preludeDescribeAttempts(attempts)
		return res
	}

	// EVERY HARD SLOT IS SATISFIED, AND THERE WERE NONE. If every slot was soft and the server
	// published nothing for any of them, the answer is not "we failed to find a token", it is
	// "we asked the server and it mints nothing under these names". That is a measurement, and
	// it is the confident not-required this whole soft mechanism exists to produce.
	if len(res.Tokens) == 0 && len(res.SoftUnserved) > 0 {
		res.State = triage.PreludeTokenNotRequired
		res.Basis = spec.Basis
		res.Reason = "no token is required here, measured: " + strings.Join(res.SoftUnserved, ", ") +
			" are token-shaped names, and nothing served by " + preludeDescribeAttempts(attempts) +
			" publishes a value under them. " + preludeJoinBasis(spec.Basis)
		return res
	}

	res.State = triage.PreludeTokenObtained
	res.Reason = fmt.Sprintf("fetched %d fresh token(s) from %s", len(res.Tokens), res.SourceURL)
	if len(res.SoftUnserved) > 0 {
		res.Reason += "; nothing is published for " + strings.Join(res.SoftUnserved, ", ") + ", which is measured and not assumed"
	}
	return res
}

func preludeJoinBasis(basis []string) string {
	if len(basis) == 0 {
		return "no positive evidence either way was recorded, which is itself the defect"
	}
	return strings.Join(basis, "; ")
}

// preludeOutcome is one candidate's result, before the walk decides which candidate to believe.
type preludeOutcome struct {
	attempt          preludeAttempt
	obs              triage.Observation
	locators         []TokenLocator
	tokens           map[string]string
	tokenOrder       []string
	missing          []string
	softUnserved     []string
	setCookies       string
	contaminant      triage.Marker
	contaminantClass triage.ClassID
}

// satisfied reports whether this candidate ends the walk: a clean control with every hard slot
// filled.
func (o preludeOutcome) satisfied() bool {
	return o.attempt.Err == "" && o.attempt.Contaminated == "" && len(o.missing) == 0
}

// better ranks two candidates so the walk reports the most informative one rather than the last.
// A clean control beats a contaminated one; among equals, fewer unfilled hard slots wins.
func (o preludeOutcome) better(than preludeOutcome) bool {
	if (o.attempt.Contaminated == "") != (than.attempt.Contaminated == "") {
		return o.attempt.Contaminated == ""
	}
	return len(o.missing) < len(than.missing)
}

func preludeFetchOnce(ctx context.Context, client *http.Client, spec PreludeSpec, candidate string) preludeOutcome {
	out := preludeOutcome{attempt: preludeAttempt{URL: candidate}, tokens: map[string]string{}}
	at := time.Now()

	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, candidate, nil)
	if err != nil {
		out.attempt.Err = "could not be built: " + err.Error()
		return out
	}
	for k, vs := range spec.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if spec.Cookies != "" {
		// BY HAND. http.Cookie.String silently drops ; " and \ from a value, measured on this
		// machine, and a session cookie that lost a byte fetches the anonymous page, which has no
		// token, which reads as unobtainable for a reason that is entirely our own doing.
		req.Header.Set("Cookie", spec.Cookies)
	}

	resp, err := client.Do(req)
	if err != nil {
		out.attempt.Err = "fetch failed: " + err.Error()
		out.obs = triage.Observation{Kind: triage.ObsPreludeControl, ReqMethod: method, ReqWireURL: candidate,
			TransportErr: triageClassifyTransportErr(err), TransportMsg: err.Error(), SentAt: at}
		return out
	}
	defer resp.Body.Close()

	maxBody := spec.MaxBody
	if maxBody <= 0 {
		maxBody = preludeDefaultMaxBody
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	out.attempt.Status = resp.StatusCode
	out.setCookies = triageJoinSetCookiePairs(resp.Header.Values("Set-Cookie"))
	out.obs = triagePreludeObservation(method, candidate, resp, body, at)

	if readErr != nil {
		out.attempt.Err = "response could not be read: " + readErr.Error()
		return out
	}
	if resp.StatusCode >= 400 {
		out.attempt.Err = fmt.Sprintf("returned %d, so no fresh token was served", resp.StatusCode)
		return out
	}

	for _, s := range ScanMarkers(body) {
		if s.Completeness == MarkerComplete && s.Integrity == triage.MarkerValid {
			out.attempt.Contaminated = string(s.Hit.Marker)
			out.contaminant = s.Hit.Marker
			out.contaminantClass = s.Class
			return out
		}
	}

	out.locators = LocateTokens(body, resp.Header)
	for _, slot := range spec.Required {
		loc, ok := triageMatchLocator(slot, out.locators)
		if ok && loc.Value != "" {
			if _, seen := out.tokens[slot.Name]; !seen {
				out.tokenOrder = append(out.tokenOrder, slot.Name)
			}
			out.tokens[slot.Name] = loc.Value
			continue
		}
		label := string(slot.Where) + ":" + slot.Name
		if slot.Soft {
			out.softUnserved = append(out.softUnserved, label)
			continue
		}
		out.missing = append(out.missing, label)
	}
	out.attempt.Missing = out.missing
	return out
}

func triageDescribeSlots(slots []TokenSlot) string {
	out := make([]string, 0, len(slots))
	for _, s := range slots {
		out = append(out, string(s.Where)+":"+s.Name)
	}
	return strings.Join(out, ", ")
}

func triageAppendUnique(xs []string, x string) []string {
	if x == "" {
		return xs
	}
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// triageJoinSetCookiePairs turns the response Set-Cookie lines into a Cookie header value, attributes
// dropped. Built by hand for the reason documented on FetchPreludeTokens.
func triageJoinSetCookiePairs(setCookies []string) string {
	var pairs []string
	for _, sc := range setCookies {
		pair, _, _ := strings.Cut(sc, ";")
		if strings.Contains(pair, "=") {
			pairs = append(pairs, strings.TrimSpace(pair))
		}
	}
	return strings.Join(pairs, "; ")
}

func triageClassifyTransportErr(err error) triage.TransportErrKind {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "invalid header field value"):
		return triage.TransportInvalidHeader
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		return triage.TransportTimeout
	case strings.Contains(s, "no such host") || strings.Contains(s, "dns"):
		return triage.TransportDNS
	case strings.Contains(s, "tls") || strings.Contains(s, "certificate"):
		return triage.TransportTLS
	case strings.Contains(s, "reset"):
		return triage.TransportReset
	default:
		return triage.TransportConnect
	}
}

func triagePreludeObservation(method, wireURL string, resp *http.Response, body []byte, at time.Time) triage.Observation {
	obs := triage.Observation{
		Kind:        triage.ObsPreludeControl,
		ReqMethod:   method,
		ReqWireURL:  wireURL,
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		Proto:       resp.Proto,
		Body:        body,
		BodyLen:     len(body),
		BodySHA256:  sha256.Sum256(body),
		ContentType: resp.Header.Get("Content-Type"),
		FinalURL:    wireURL,
		SentAt:      at,
	}
	if resp.Request != nil && resp.Request.URL != nil {
		obs.FinalURL = resp.Request.URL.String()
	}
	for _, name := range triageSortedHeaderNames(resp.Header) {
		for _, v := range resp.Header.Values(name) {
			obs.RespHeaders = append(obs.RespHeaders, [2]string{name, v})
		}
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, rest, found := strings.Cut(sc, "=")
		if !found {
			continue
		}
		value, attrs, _ := strings.Cut(rest, ";")
		co := triage.CookieObs{Name: strings.TrimSpace(name), Value: value, ValueSHA: sha256.Sum256([]byte(value))}
		for _, a := range strings.Split(attrs, ";") {
			if a = strings.TrimSpace(a); a != "" {
				co.Attributes = append(co.Attributes, a)
			}
		}
		obs.SetCookies = append(obs.SetCookies, co)
	}
	return obs
}

// ---------------------------------------------------------------------------------------------
// 5. APPLYING THE FRESH TOKEN TO THE PROBE REQUEST
// ---------------------------------------------------------------------------------------------

// ApplyTo writes the fresh tokens into a built probe request and returns the body to send.
//
// FAILS CLOSED. If a required token cannot be written, it returns an error and the caller records
// PreludeTokenUnobtainable. The alternative, sending the probe with the stale token anyway, is the
// bug: the request fails validation, the response is identical for every probe, and the slot is
// recorded as examined.
func (r PreludeResult) ApplyTo(req *http.Request, slots []TokenSlot, body []byte, media triage.BodyMedia) ([]byte, error) {
	if r.State == triage.PreludeTokenNotRequired {
		return body, nil
	}
	if r.State != triage.PreludeTokenObtained {
		return nil, fmt.Errorf("triage: refusing to send a probe with prelude state %q: %s", r.State, r.Reason)
	}

	out := body
	for _, slot := range slots {
		fresh, ok := r.Tokens[slot.Name]
		if !ok || fresh == "" {
			// A SOFT SLOT THE SERVER PUBLISHES NOTHING FOR IS LEFT EXACTLY AS CAPTURED. That is
			// not a silent failure, it is the measured answer: the name was ambiguous, we asked
			// the server, and the server mints nothing under it, so the captured bytes are the
			// client's own value and replaying them is correct. PreludeResult.SoftUnserved names
			// every slot this happened to. A HARD slot with no fresh value still refuses, which
			// is the whole point of the file.
			if slot.Soft {
				continue
			}
			return nil, fmt.Errorf("triage: no fresh value for required token %s:%s", slot.Where, slot.Name)
		}
		switch slot.Where {
		case triage.KindHeader:
			req.Header.Set(slot.Name, fresh)
		case triage.KindQuery:
			if req.URL == nil {
				return nil, fmt.Errorf("triage: cannot place token %s in the query of a request with no url", slot.Name)
			}
			q, replaced := triageReplaceURLEncodedField(req.URL.RawQuery, slot.Name, fresh)
			if !replaced {
				return nil, fmt.Errorf("triage: query field %s is required but is not present in the probe url", slot.Name)
			}
			req.URL.RawQuery = q
		case triage.KindCookie:
			// BY HAND, per the measurement on this machine: (&http.Cookie{Value: "1' OR 1=1;
			// DROP"}).String() drops the ; " and \, which are exactly the probe characters, and
			// logs one line to the stdlib logger rather than returning an error.
			hdr, replaced := triageReplaceCookieValue(req.Header.Get("Cookie"), slot.Name, fresh)
			if !replaced {
				return nil, fmt.Errorf("triage: cookie %s is required but is not present in the probe request", slot.Name)
			}
			req.Header.Set("Cookie", hdr)
		case triage.KindBody:
			next, err := triageReplaceBodyToken(out, slot, fresh, media)
			if err != nil {
				return nil, err
			}
			out = next
		default:
			return nil, fmt.Errorf("triage: token %s sits in a %s slot, which the prelude cannot rewrite", slot.Name, slot.Where)
		}
	}
	return out, nil
}

// triageReplaceURLEncodedField swaps one field's value in an application/x-www-form-urlencoded string,
// in place, leaving every other byte alone.
//
// It does NOT rebuild with url.Values.Encode: Encode sorts the keys, so a rebuilt query is a
// different byte sequence from the capture, and the differential would then be measuring the
// reordering rather than the payload. It uses QueryEscape and never PathEscape: measured,
// PathEscape("a=b") is "a=b" and PathEscape("a&b") is "a&b", both raw, so a token containing
// either would silently split into extra fields.
func triageReplaceURLEncodedField(s, name, fresh string) (string, bool) {
	if s == "" {
		return s, false
	}
	parts := strings.Split(s, "&")
	replaced := false
	for i, p := range parts {
		k, _, found := strings.Cut(p, "=")
		if !found && p != name {
			continue
		}
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if k != name {
			continue
		}
		parts[i] = url.QueryEscape(name) + "=" + url.QueryEscape(fresh)
		replaced = true
	}
	return strings.Join(parts, "&"), replaced
}

// triageReplaceCookieValue swaps one cookie's value in a Cookie header by SURGERY ON THE RAW
// STRING, leaving every other byte of the header exactly as it was.
//
// WHY NOT SPLIT AND REJOIN. 75 of the 218 vectors in the measured corpus are cookie vectors, and
// a cookie probe's whole point is a value containing ; " and \. Splitting the header on ';' and
// rejoining would drop the payload's semicolons, which is the same data loss http.Cookie.String
// causes and which the hand-built Cookie header exists to avoid: measured on this machine,
// (&http.Cookie{Name:"s", Value:"1' OR 1=1; DROP"}).String() yields s="1' OR 1=1 DROP". The wire
// is genuinely ambiguous about a raw ';' inside a value, and that ambiguity is the target's to
// resolve; ours is to deliver the bytes the probe asked for.
//
// There is a separate reader, triageParseCookieHeader, used for DISCOVERY only. It splits, and it
// is lossy in exactly the way the wire is; nothing that writes a request uses it.
func triageReplaceCookieValue(header, name, fresh string) (string, bool) {
	needle := name + "="
	for i := 0; i+len(needle) <= len(header); i++ {
		if header[i:i+len(needle)] != needle {
			continue
		}
		// The name must start the header or follow a ';', so a cookie called "id" does not match
		// inside "session_id=".
		j := i - 1
		for j >= 0 && (header[j] == ' ' || header[j] == '\t') {
			j--
		}
		if j >= 0 && header[j] != ';' {
			continue
		}
		end := strings.IndexByte(header[i:], ';')
		if end < 0 {
			end = len(header)
		} else {
			end += i
		}
		return header[:i+len(needle)] + fresh + header[end:], true
	}
	return header, false
}

// triageReplaceBodyToken swaps the stale token value for the fresh one inside the raw body.
//
// Form bodies get a field-level rewrite. Everything else gets a byte replacement of the observed
// stale value, which requires that value to be present EXACTLY ONCE. That requirement is the
// point: a token value that appears twice, or not at all, means the capture does not say where
// the token is, and guessing is how a probe gets sent with a body the server rejects for reasons
// that have nothing to do with the payload.
func triageReplaceBodyToken(body []byte, slot TokenSlot, fresh string, media triage.BodyMedia) ([]byte, error) {
	if media == triage.BodyForm {
		s, ok := triageReplaceURLEncodedField(string(body), slot.Name, fresh)
		if !ok {
			return nil, fmt.Errorf("triage: form field %s is required but is not present in the probe body", slot.Name)
		}
		return []byte(s), nil
	}
	if slot.Observed == "" {
		return nil, fmt.Errorf("triage: the captured value of %s is empty, so there is nothing to replace it at", slot.Name)
	}
	stale := []byte(slot.Observed)
	if n := bytes.Count(body, stale); n != 1 {
		return nil, fmt.Errorf("triage: the captured value of %s occurs %d times in the body, and a rewrite needs exactly one", slot.Name, n)
	}
	return bytes.Replace(body, stale, []byte(fresh), 1), nil
}

// ---------------------------------------------------------------------------------------------
// 6. THE GATE: A FRESH TOKEN BEFORE EVERY PROBE
// ---------------------------------------------------------------------------------------------

// PreludeGate is what the runner holds. Before is called once per probe, and that is the whole
// mechanism: one fetch, one probe, no reuse.
type PreludeGate struct {
	Spec   PreludeSpec
	Client *http.Client

	// Fetches counts prelude fetches performed. A run where Fetches is lower than the number of
	// mutating probes sent is a run where a token was reused, and the count is what makes that
	// visible in the report rather than inferable from nothing.
	Fetches int
}

// Before fetches a fresh token and writes it into req, returning the body to send. On any prelude
// failure it returns the result with Blocked() true and a nil body, and the caller records the
// slot with PreludeBlockedVerdict.
func (g *PreludeGate) Before(ctx context.Context, req *http.Request, body []byte, media triage.BodyMedia) (PreludeResult, []byte, error) {
	res := FetchPreludeTokens(ctx, g.Client, g.Spec)
	g.Fetches++
	if res.Blocked() {
		return res, nil, fmt.Errorf("triage: prelude %s: %s", res.State, res.Reason)
	}
	// Carry the prelude's session material forward. A double-submit token is only valid against
	// the cookie the same response set, so sending the field without the cookie fails every probe
	// in the same way a stale token does.
	if res.SetCookies != "" {
		merged := res.SetCookies
		if existing := req.Header.Get("Cookie"); existing != "" {
			merged = existing + "; " + res.SetCookies
		}
		req.Header.Set("Cookie", merged)
	}
	out, err := res.ApplyTo(req, g.Spec.Required, body, media)
	if err != nil {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = err.Error()
		return res, nil, err
	}
	return res, out, nil
}

// ---------------------------------------------------------------------------------------------
// 7. THE HONEST FAILURE STATE, AND KEEPING THE TOKEN OUT OF THE DIFFERENTIAL
// ---------------------------------------------------------------------------------------------

// PreludeBlockedVerdict turns a failed prelude into a ClassVerdict.
//
// It returns StateCannotDetermine, which IsUnknown. It cannot return clean, it cannot return an
// unstable-flavoured negative, and it carries no grade, so ClassVerdict.Validate accepts it and
// Coverage.RendersAsClean is false for any slot that got one. That is the whole contract: a slot
// whose probes could not be sent is untested, and untested is an unknown with a reason on it.
func PreludeBlockedVerdict(class triage.ClassID, slot triage.SlotKey, res PreludeResult) triage.ClassVerdict {
	reason := res.Reason
	if reason == "" {
		reason = "prelude state " + string(res.State) + " with no reason recorded, which is itself the defect"
	}
	return triage.ClassVerdict{
		Class:   class,
		SlotKey: slot,
		State:   triage.StateCannotDetermine,
		Reason:  "prelude_" + string(preludeReasonCode(res.State)) + ": " + reason,
		Oracle:  "request_prelude",
	}
}

// preludeReasonCode is the short machine-readable half of the reason string. The caller prefixes
// it with "prelude_", so a state name that already carries that prefix has it stripped here:
// PreludeControlContaminated used to compose as prelude_prelude_control_contaminated, which is a
// second spelling of one state and the kind of thing a report groups on.
func preludeReasonCode(s triage.PreludeState) triage.PreludeState {
	if s == "" {
		return triage.PreludeState("unknown")
	}
	return triage.PreludeState(strings.TrimPrefix(string(s), "prelude_"))
}

// PreludeTokenPlaceholder is what a fresh token is replaced with in the normalised body. It is a
// fixed string so two observations taken with two different tokens normalise to the same bytes.
const PreludeTokenPlaceholder = "<prelude-token>"

// Empty reports whether there is nothing to suppress.
func (v PreludeVolatility) Empty() bool { return len(v.Values) == 0 }

// Regions locates each fresh token in body, as VolatileRegions the runner folds into
// BaselineModel.VolatileRegions. This is the coordination path with the comparator: the comparator
// already excludes volatile regions, and the prelude's job is to declare which ones it created.
func (v PreludeVolatility) Regions(body []byte) []triage.VolatileRegion {
	var out []triage.VolatileRegion
	for _, val := range v.Values {
		if val == "" {
			continue
		}
		needle := []byte(val)
		for off := 0; ; {
			i := bytes.Index(body[off:], needle)
			if i < 0 {
				break
			}
			out = append(out, triage.VolatileRegion{Offset: off + i, Length: len(needle), Source: "prelude_token"})
			off += i + len(needle)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// SeedSuppression is the map form, for BaselineModel.SeedSuppressed: token value to placeholder.
func (v PreludeVolatility) SeedSuppression() map[string]string {
	out := map[string]string{}
	for _, val := range v.Values {
		if val != "" {
			out[val] = PreludeTokenPlaceholder
		}
	}
	return out
}

// SuppressIn rewrites the fresh token out of an observation's NORMALISED body and returns how many
// occurrences it replaced.
//
// WHY THIS AND NOT AN EDIT TO THE COMPARATOR. The token is different on every fetch by
// construction, so left in place it makes every probe differ from the baseline in those bytes and
// every vector reads as changed. The exclusion therefore has to travel with the observation, and
// Proj.NormBody is the field the comparator reads and the field whose documented job is "volatile
// regions removed". obs.Body is never touched: it is the raw evidence, and rewriting evidence to
// make a comparison come out is the other way to get this wrong.
//
// NormBody is seeded from Body when nil. If the comparator later re-derives NormBody it must
// re-apply suppression, which is what Regions and SeedSuppression are for.
func (v PreludeVolatility) SuppressIn(obs *triage.Observation) int {
	if obs == nil || v.Empty() {
		return 0
	}
	if obs.Proj.NormBody == nil {
		obs.Proj.NormBody = append([]byte(nil), obs.Body...)
	}
	replaced := 0
	for _, val := range v.Values {
		if val == "" {
			continue
		}
		n := bytes.Count(obs.Proj.NormBody, []byte(val))
		if n == 0 {
			continue
		}
		replaced += n
		obs.Proj.NormBody = bytes.ReplaceAll(obs.Proj.NormBody, []byte(val), []byte(PreludeTokenPlaceholder))
	}
	for i, s := range obs.Proj.JSONScalars {
		for _, val := range v.Values {
			if val != "" && strings.Contains(s, val) {
				s = strings.ReplaceAll(s, val, PreludeTokenPlaceholder)
			}
		}
		obs.Proj.JSONScalars[i] = s
	}
	obs.Proj.NormBodySHA256 = sha256.Sum256(obs.Proj.NormBody)
	return replaced
}
