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
	var out []TokenSlot

	if u, err := url.Parse(r.URL); err == nil && u.RawQuery != "" {
		if vals, err := url.ParseQuery(u.RawQuery); err == nil {
			for _, name := range triageSortedQueryKeys(vals) {
				if kind, ok := ClassifyTokenName(name); ok {
					out = append(out, TokenSlot{Name: name, Kind: kind, Where: triage.KindQuery, Observed: vals.Get(name)})
				}
			}
		}
	}

	for _, name := range triageSortedHeaderNames(r.Header) {
		if strings.EqualFold(name, "Cookie") {
			continue
		}
		if kind, ok := ClassifyTokenName(name); ok {
			out = append(out, TokenSlot{Name: name, Kind: kind, Where: triage.KindHeader, Observed: r.Header.Get(name)})
		}
	}

	// Cookies are read by splitting the Cookie header by hand. http.Request.Cookies would work
	// for reading, but the write side must not use http.Cookie at all (it drops ; " and \ with
	// only a line on the stdlib logger), and keeping both directions in one hand-rolled form is
	// what stops somebody reaching for AddCookie on the way back.
	for _, c := range triageParseCookieHeader(r.Header.Get("Cookie")) {
		if kind, ok := ClassifyTokenName(c[0]); ok {
			out = append(out, TokenSlot{Name: c[0], Kind: kind, Where: triage.KindCookie, Observed: c[1]})
		}
	}

	out = append(out, triageDiscoverBodyTokens(r.Body, r.Media)...)
	return out
}

func triageDiscoverBodyTokens(body []byte, media triage.BodyMedia) []TokenSlot {
	var out []TokenSlot
	switch media {
	case triage.BodyForm:
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil
		}
		for _, name := range triageSortedQueryKeys(vals) {
			if kind, ok := ClassifyTokenName(name); ok {
				out = append(out, TokenSlot{Name: name, Kind: kind, Where: triage.KindBody, FieldPath: name, Observed: vals.Get(name)})
			}
		}
	case triage.BodyJSON:
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil
		}
		triageWalkJSONStrings(doc, "", func(path, key, value string) {
			if kind, ok := ClassifyTokenName(key); ok {
				out = append(out, TokenSlot{Name: key, Kind: kind, Where: triage.KindBody, FieldPath: path, Observed: value})
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].FieldPath < out[j].FieldPath })
	}
	return out
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
func triageMatchLocator(slot TokenSlot, locs []TokenLocator) (TokenLocator, bool) {
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

	// MaxBody caps the prelude response read. Zero means preludeDefaultMaxBody.
	MaxBody int64
}

const preludeDefaultMaxBody = 4 << 20

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
func FetchPreludeTokens(ctx context.Context, client *http.Client, spec PreludeSpec) PreludeResult {
	res := PreludeResult{FetchedAt: time.Now(), Tokens: map[string]string{}}

	if len(spec.Required) == 0 {
		res.State = triage.PreludeTokenNotRequired
		res.Reason = "no token-shaped field in the captured request"
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

	method := spec.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, spec.URL, nil)
	if err != nil {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "prelude request could not be built: " + err.Error()
		return res
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
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "prelude fetch failed: " + err.Error()
		res.Obs = triage.Observation{Kind: triage.ObsPreludeControl, ReqMethod: method, ReqWireURL: spec.URL, TransportErr: triageClassifyTransportErr(err), TransportMsg: err.Error(), SentAt: res.FetchedAt}
		return res
	}
	defer resp.Body.Close()

	maxBody := spec.MaxBody
	if maxBody <= 0 {
		maxBody = preludeDefaultMaxBody
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	res.Status = resp.StatusCode
	res.SetCookies = triageJoinSetCookiePairs(resp.Header.Values("Set-Cookie"))
	res.Obs = triagePreludeObservation(method, spec.URL, resp, body, res.FetchedAt)

	if readErr != nil {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "prelude response could not be read: " + readErr.Error()
		return res
	}
	if resp.StatusCode >= 400 {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = fmt.Sprintf("prelude fetch returned %d, so no fresh token was served", resp.StatusCode)
		return res
	}

	// A control that contains one of our own markers is not a control. Either the prelude URL is
	// itself a probed surface with a stored reflection, or the fetch went through a cache holding
	// a probe response. Either way the token read out of it may be a probe artefact, so the state
	// says so instead of the probes proceeding on it.
	for _, s := range ScanMarkers(body) {
		if s.Completeness == MarkerComplete && s.Integrity == triage.MarkerValid {
			res.State = triage.PreludeControlContaminated
			res.Reason = fmt.Sprintf("the prelude response carries marker %s (class %s), so it is a probe artefact and not a control", s.Hit.Marker, s.Class)
			return res
		}
	}

	res.Locators = LocateTokens(body, resp.Header)

	var missing []string
	for _, slot := range spec.Required {
		loc, ok := triageMatchLocator(slot, res.Locators)
		if !ok {
			missing = append(missing, string(slot.Where)+":"+slot.Name)
			continue
		}
		res.Tokens[slot.Name] = loc.Value
		res.Volatility.Values = triageAppendUnique(res.Volatility.Values, loc.Value)
		res.Volatility.Names = triageAppendUnique(res.Volatility.Names, slot.Name)
	}

	if len(missing) > 0 {
		res.State = triage.PreludeTokenUnobtainable
		res.Reason = "the prelude response served no value for " + strings.Join(missing, ", ") +
			"; the probe would have replayed a burnt token and failed validation identically every time"
		return res
	}

	// A viewstate is a MAC over the whole form. Refreshing it does not help, because the probe is
	// about to mutate a field the MAC covers, and the server will reject every probe for that
	// reason and not for anything the probe did. This is a distinct state, not a success.
	for _, slot := range spec.Required {
		if slot.Kind == TokenKindViewState {
			res.State = triage.PreludeViewstateBound
			res.Reason = "field " + slot.Name + " is a viewstate MAC over the whole form, so any mutated field is rejected regardless of the payload"
			return res
		}
	}

	res.State = triage.PreludeTokenObtained
	res.Reason = fmt.Sprintf("fetched %d fresh token(s) from %s", len(res.Tokens), spec.URL)
	return res
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
		co := triage.CookieObs{Name: strings.TrimSpace(name), ValueSHA: sha256.Sum256([]byte(value))}
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
