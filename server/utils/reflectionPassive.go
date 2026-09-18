package utils

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
)

// THE PASSIVE PASS: find reflections in the request/response pairs we already have, sending nothing.
//
// Investigate is two phases now. This is the first one, and it exists because a large share of the
// answer is already in the database. The manual crawl stored the request AND the response for
// thousands of exchanges; if a value the request actually sent comes back whole in the response that
// actually came back, that input is echoed, and no packet had to leave the machine to learn it.
//
// MEASURED on the engaged target before this was written: 4383 stored captures carry a non-empty
// response body, and 214 of its 218 attack vectors carry a raw request.
//
// WHY IT MATTERS BEYOND SPEED. The active probe cannot answer a body vector without sending the
// verb that carries a body, and on a live estate a POST body probe creates a record. The passive
// pass reads a POST that the operator's own browser already made and the response the application
// already gave, so body, cookie and header are answered exactly as well as query is, and the
// question of whether Investigate may write to somebody's estate stops existing. Investigate now
// never sends POST, PATCH, PUT or DELETE at any setting.
//
// WHAT A PASSIVE ROW CANNOT SAY. The crawl almost certainly never sent a `<`. So a value coming back
// intact proves the input is ECHOED and says nothing about whether markup survives, which is the
// question that decides whether a reflection is an XSS candidate. That is why a passive match lands
// on reflected_observed and not on reflected_raw, and why reflected_observed grades as xss_unknown.
// The active pass is what upgrades it. reflected_raw is written passively in exactly one case: the
// observed value ITSELF contained one of < > " ' and came back with it intact, which is a real
// measurement of raw reflection rather than an inference.

// ---------------------------------------------------------------- the false-positive rule
//
// THIS IS THE PART THAT DECIDES WHETHER THE PASS IS WORTH ANYTHING. Searching a response for a value
// the request sent is trivial; the whole difficulty is that short and common values appear in
// responses by coincidence. page=1, limit=10, status=active, order=desc and true are in a
// paginated JSON response whether or not the application echoes anything, so a naive matcher
// reports a reflection on every parameter of every endpoint and the list means nothing.
//
// Three rules, and every one of them was chosen against the real corpus rather than in the abstract.
// Each is its own function so the test names it, and so a row can say WHICH rule let it through.
//
//  1. SUBSTANCE  the value has to be improbable enough that a coincidental appearance is not the
//     likely explanation: at least passiveMinValueLength bytes, at least passiveMinDistinctRunes
//     distinct characters, not a bare number, and not one of the common words below.
//  2. ATTRIBUTION  the value has to appear EXACTLY ONCE among the request's own inputs. If the same
//     string is in the path and the query, or in a cookie and a header, finding it in the response
//     does not say which input produced it, and a row that names the wrong input is worse than no
//     row. This is also what answers "the value is in the request URL, so it may just be routing":
//     a body or cookie value that is also in the URL is ambiguous and is dropped.
//  3. WHOLE VALUE  the occurrence in the response has to be the whole value, not a substring of a
//     longer token. `abc12345` inside `abc123456789` is not a reflection of `abc12345`.

// passiveMinValueLength is the shortest value the pass will look for.
//
// Eight, from the corpus: it drops 1, 10, 100, true, false, desc, active, AAPL and every other
// short enumeration value, and keeps every uuid, every symbol list of more than one ticker, every
// opaque id and every free-text field. A shorter floor puts `inactive` and `2026-01` back in, and
// both appear in responses that never echoed an input.
const passiveMinValueLength = 8

// passiveMinDistinctRunes rejects a long value made of almost nothing: 00000000, ----------,
// 2222222222. Those are long enough to pass the length rule and are exactly as likely to appear by
// coincidence as a short one.
const passiveMinDistinctRunes = 4

// passiveCommonValues are strings that clear the length and variety rules and are still furniture.
//
// Kept short and EXACT rather than becoming a substring blocklist. A greedy rule here silently
// deletes real findings, which is the more expensive mistake: a coincidental match costs the
// operator one look at a row, and a dropped match costs the finding.
var passiveCommonValues = map[string]bool{
	"undefined": true, "inactive": true, "disabled": true, "enabled": true, "pending": true,
	"complete": true, "completed": true, "canceled": true, "cancelled": true, "rejected": true,
	"accepted": true, "ascending": true, "descending": true, "unknown": true, "default": true,
	"application/json": true, "text/html": true, "xmlhttprequest": true, "no-cache": true,
	"same-origin": true, "cross-site": true, "same-site": true, "navigate": true, "document": true,
	"max-age=0": true, "keep-alive": true, "identity": true, "gzip, deflate, br": true,
	"no-referrer": true, "strict-origin-when-cross-origin": true, "empty": true,
}

// PassiveValueHasSubstance is rule 1. The reason is returned rather than logged, because a value the
// pass refused to look for is a thing an operator asks about.
func PassiveValueHasSubstance(value string) (bool, string) {
	v := strings.TrimSpace(value)
	if len(v) < passiveMinValueLength {
		return false, "too_short"
	}
	if passiveCommonValues[strings.ToLower(v)] {
		return false, "common_value"
	}
	distinct := map[rune]bool{}
	digitsOnly := true
	for _, r := range v {
		distinct[r] = true
		if r < '0' || r > '9' {
			// A separator inside an otherwise numeric value keeps it numeric: 2026-09-17 and
			// 1,000,000 are numbers wearing punctuation, and both turn up in responses that echo
			// nothing.
			if r != '-' && r != '.' && r != ',' && r != ':' && r != '/' && r != '+' {
				digitsOnly = false
			}
		}
	}
	if digitsOnly {
		return false, "numeric"
	}
	if len(distinct) < passiveMinDistinctRunes {
		return false, "too_few_distinct_characters"
	}
	return true, ""
}

// PassiveValueIsAttributable is rule 2: the value occurs exactly once among the REQUEST's own
// inputs, across every insertion point, so an echo of it names one input.
//
// The whole request is searched, not just the insertion point being tested, and that is the point.
// A uuid that is both the path segment and a query parameter is the commonest shape on this estate,
// and attributing its echo to the query parameter would be a guess presented as a measurement.
func PassiveValueIsAttributable(c PassiveCapture, value string) bool {
	seen := 0
	for _, point := range passiveInputPoints {
		for _, v := range PassiveInputValues(c, point) {
			if v == value {
				seen++
				if seen > 1 {
					return false
				}
			}
		}
	}
	return seen == 1
}

// passiveInputPoints is every place a value can come from in a stored request. Fragment is absent
// because a fragment never reaches the server, so no stored capture can carry one.
var passiveInputPoints = []string{"query", "path", "cookie", "header", "body"}

// PassiveWholeValueIndex is rule 3: the index of the first occurrence of value in body that is the
// WHOLE value, or -1.
//
// Bounded by identifier characters on both sides. `"id":"abc12345"` matches because a quote is not
// an identifier character; `abc123456789` does not, because the byte after the match is a digit.
// The dot is deliberately NOT an identifier character: dots separate file names, JSON paths and
// decimal places far more often than they extend an identifier, and treating one as a continuation
// would drop `AAPL.json` style echoes that are real.
func PassiveWholeValueIndex(body, value string) int {
	if value == "" {
		return -1
	}
	for from := 0; from+len(value) <= len(body); {
		i := strings.Index(body[from:], value)
		if i < 0 {
			return -1
		}
		i += from
		beforeOK := i == 0 || !passiveIdentifierByte(body[i-1])
		afterIdx := i + len(value)
		afterOK := afterIdx >= len(body) || !passiveIdentifierByte(body[afterIdx])
		if beforeOK && afterOK {
			return i
		}
		from = i + 1
	}
	return -1
}

func passiveIdentifierByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
		b == '_' || b == '-'
}

// ---------------------------------------------------------------- reading a stored exchange

// PassiveCapture is one stored request/response pair, in the shape the pass reads it.
//
// A struct rather than the database row, so every rule above is testable over a literal and the
// query that fills it can change without touching the rules.
type PassiveCapture struct {
	ID       string
	Method   string
	URL      string
	Endpoint string
	// RequestHeaders is keyed by LOWER CASE header name, which is how the crawl extension stores
	// them. Cookie arrives here as the whole header value and is split out by PassiveInputValues.
	RequestHeaders map[string]string
	RequestBody    string
	ResponseBody   string
	ContentType    string
	StatusCode     int
}

// Host is the capture's host, lower cased, or empty when the URL will not parse.
func (c PassiveCapture) Host() string {
	parsed, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// Path is the CONCRETE path of the request, taken from the URL rather than from the endpoint
// column.
//
// MEASURED, and this is not a style preference: of 4383 stored captures on the engaged target,
// 2676 have an endpoint that is ALREADY TEMPLATED (/api/v1/paper_accounts/{uuid}/orders) and 1707
// do not. The path insertion point's whole input is the concrete segment, so reading the endpoint
// column would hand the pass the literal string "{uuid}" for three out of five captures and it
// would look for that in the response. The URL is the one field that is always the bytes that were
// sent. The endpoint column is the fallback for a URL that will not parse.
func (c PassiveCapture) Path() string {
	if parsed, err := url.Parse(c.URL); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	return c.Endpoint
}

// PassiveMatchKey is how a capture is paired with a vector: host plus TEMPLATED path.
//
// THE JOIN, AND WHAT IT COSTS. A vector's path is already templated by the consolidator
// (/api/v1/paper_accounts/{uuid}/orders), so a raw endpoint string never equals it, and a LIKE over
// every capture per vector is both slow and wrong at the edges. Running templateVectorPath over the
// capture's path puts both sides in the same vocabulary and makes the pairing an equality on a map
// key: one pass over the captures, O(captures + vectors), instead of one scan per vector.
//
// What it costs is precision at the template. Two different accounts' orders collapse to one key, so
// a value observed on one account's request is searched in that same request's own response and
// never in another's. That is safe because the pairing below is per CAPTURE, never per key: the key
// only decides which vectors are interested in this exchange.
//
// Not templated on the method, deliberately. A vector's method is the verb the crawl happened to
// record; the same path answered by GET and by POST reflects or does not reflect as a property of
// the handler, and requiring the verbs to agree threw away most of the corpus for no gain.
func PassiveMatchKey(host, path string) string {
	templated, _ := templateVectorPath(path)
	return strings.ToLower(strings.TrimSpace(host)) + "|" + templated
}

// PassiveInputValues is what THIS request actually carried at one insertion point.
//
// The values come from the capture and not from the vector row, so the request and the response
// being compared are the same exchange. A value taken from one request and looked for in another
// request's response is not a reflection, it is a coincidence with extra steps.
func PassiveInputValues(c PassiveCapture, insertionPoint string) map[string]string {
	out := map[string]string{}
	switch insertionPoint {
	case "query":
		parsed, err := url.Parse(c.URL)
		if err != nil {
			return out
		}
		for name, values := range parsed.Query() {
			if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
				out[name] = values[0]
			}
		}
	case "path":
		// A path vector has NO parameter name: the segment is the input, and the active probe puts
		// its canary in the last non-empty segment. The passive pass reads the same segment, under
		// the same empty parameter name, so the two passes describe the same input.
		if v := passivePathIdentifier(c.Path()); v != "" {
			out[""] = v
		}
	case "cookie":
		for _, pair := range strings.Split(c.RequestHeaders["cookie"], ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.TrimSpace(v) != "" {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	case "header":
		for name, value := range c.RequestHeaders {
			if strings.EqualFold(name, "cookie") {
				// The whole Cookie header is not a header input: its parts are cookie inputs, and
				// counting it here would make every cookie value ambiguous under rule 2.
				continue
			}
			if strings.TrimSpace(value) != "" {
				out[name] = value
			}
		}
	case "body":
		for name, value := range passiveBodyValues(c.RequestHeaders["content-type"], c.RequestBody) {
			out[name] = value
		}
	}
	return out
}

// passivePathIdentifier is the concrete value of the LAST segment the templater would replace.
//
// The last one because that is the segment the active path probe replaces
// (reflectionPathProbeURL), so both passes are talking about the same input. A path with no
// templated segment has no identifier to look for and returns empty: a fixed route name is not an
// input, and searching for the literal string "orders" in a response about orders is the purest
// possible false positive.
func passivePathIdentifier(path string) string {
	templated, _ := templateVectorPath(path)
	raw := strings.Split(path, "/")
	tpl := strings.Split(templated, "/")
	if len(raw) != len(tpl) {
		return ""
	}
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] != tpl[i] && strings.TrimSpace(raw[i]) != "" {
			return raw[i]
		}
	}
	return ""
}

// passiveBodyValues reads the top-level fields of a stored request body.
//
// Top level only, matching reflectionBodyProbe, which replaces a top-level field and refuses to
// invent one. A nested object is not read, so a reflection of a nested field is missed rather than
// attributed to the wrong name.
func passiveBodyValues(contentType, body string) map[string]string {
	out := map[string]string{}
	body = strings.TrimSpace(body)
	if body == "" {
		return out
	}
	essence := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(essence, ';'); i >= 0 {
		essence = strings.TrimSpace(essence[:i])
	}
	switch {
	case strings.Contains(essence, "json") || strings.HasPrefix(body, "{"):
		var doc map[string]any
		if json.Unmarshal([]byte(body), &doc) != nil {
			return out
		}
		for name, value := range doc {
			if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
				out[name] = s
			}
		}
	case strings.Contains(essence, "x-www-form-urlencoded"):
		values, err := url.ParseQuery(body)
		if err != nil {
			return out
		}
		for name, vs := range values {
			if len(vs) > 0 && strings.TrimSpace(vs[0]) != "" {
				out[name] = vs[0]
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- the verdict

// ClassifyPassiveReflection decides whether one input of one stored exchange is a reflection.
//
// ok is false for every value the rules refused and for every value that simply did not come back,
// and NOTHING IS WRITTEN in that case. That is deliberate: passive silence is not not_reflected. The
// crawl sent whatever value the application happened to be handling, not a probe, so its absence
// from the response says very little, and writing a negative here would manufacture exactly the
// silent clean the status vocabulary exists to prevent. The active pass is what writes a negative.
func ClassifyPassiveReflection(insertionPoint, name, value string, c PassiveCapture) (ReflectionOutcome, bool) {
	if ok, _ := PassiveValueHasSubstance(value); !ok {
		return ReflectionOutcome{}, false
	}
	if !PassiveValueIsAttributable(c, value) {
		return ReflectionOutcome{}, false
	}
	idx := PassiveWholeValueIndex(c.ResponseBody, value)
	if idx < 0 {
		return ReflectionOutcome{}, false
	}

	out := ReflectionOutcome{
		InsertionPoint: insertionPoint,
		ContentType:    c.ContentType,
		HTTPStatus:     c.StatusCode,
		Evidence:       reflectionSnippet(c.ResponseBody, idx),
		// The exchange carried a credential, or it did not. Read from the stored request rather
		// than from what the framework holds now, because this row describes a request that was
		// made in the past.
		AuthApplied: c.RequestHeaders["authorization"] != "" || c.RequestHeaders["cookie"] != "",
	}

	// THE ONE CASE A PASSIVE ROW MAY CLAIM reflected_raw: the value the request sent CONTAINED a
	// dangerous character and it came back with the character intact. That is a measurement, not an
	// inference, and it is graded like any other raw reflection.
	survived := passiveSurvivedChars(value)
	label := insertionPoint
	if name != "" {
		label = insertionPoint + " " + name
	}
	if len(survived) > 0 {
		out.Status = ReflectionRaw
		out.Survived = survived
		out.Detail = "passive_raw(" + label + "): " + strings.Join(survived, " ") +
			" came back intact. No request was sent."
		return out, true
	}

	out.Status = ReflectionObserved
	// ONE SHORT SENTENCE plus the no-request caveat. What the row used to spell out here, that the
	// encoding is untested, is what reflected_observed MEANS and what the grade column already says.
	out.Detail = "passive_echo(" + label + "): the value came back whole. No request was sent."
	return out, true
}

// passiveSurvivedChars is which of the four probe characters the observed value itself carried.
//
// The match was whole-value and exact, so a character present in the value is present in the
// response by construction. Ordered by reflectionProbeChars so a passive row's survived list reads
// the same way an active one does.
func passiveSurvivedChars(value string) []string {
	var survived []string
	for _, ch := range reflectionProbeChars {
		if strings.ContainsRune(value, ch) {
			survived = append(survived, string(ch))
		}
	}
	return survived
}

// ---------------------------------------------------------------- the pass

// PassiveVectorRef is the vector side of the pairing: everything the pass needs and nothing else.
type PassiveVectorRef struct {
	VectorID       string
	InsertionPoint string
	Parameters     []string
	// Plan carries the per-host credential names, so an input that IS the session is left alone
	// here exactly as the active pass leaves it alone. A session token found echoed would be a real
	// observation and storing its value in an evidence column is not a thing this codebase does.
	Plan ReflectionPlanContext
}

// passiveProbeKey identifies one stored probe row.
func passiveProbeKey(vectorID, parameter string) string { return vectorID + "\x00" + parameter }

// PassiveReflectionResult is one input's passive verdict plus the capture it came from.
type PassiveReflectionResult struct {
	VectorID  string
	Parameter string
	CaptureID string
	// CaptureURL becomes the row's probe_url, so the row names an exchange that can be reopened in
	// the crawl rather than a request that was never made.
	CaptureURL string
	Outcome    ReflectionOutcome
}

// PassiveScanCaptures runs the whole pass over an already-loaded set of captures.
//
// Separated from the database so the pass can be run over the real corpus in a test, read only,
// without the run machinery. index maps a PassiveMatchKey to the vectors interested in it.
func PassiveScanCaptures(index map[string][]PassiveVectorRef,
	captures []PassiveCapture) map[string]PassiveReflectionResult {

	best := map[string]PassiveReflectionResult{}
	for _, c := range captures {
		refs := index[PassiveMatchKey(c.Host(), c.Path())]
		if len(refs) == 0 {
			continue
		}
		for _, ref := range refs {
			values := PassiveInputValues(c, ref.InsertionPoint)
			for _, param := range passiveVectorParameters(ref) {
				value, seen := values[param]
				if !seen {
					continue
				}
				if ReflectionInputIsCredential(ref.InsertionPoint, param, value, ref.Plan) {
					continue
				}
				outcome, ok := ClassifyPassiveReflection(ref.InsertionPoint, param, value, c)
				if !ok {
					continue
				}
				key := passiveProbeKey(ref.VectorID, param)
				// The most interesting exchange wins, the same way reflectionFromBody keeps the
				// most dangerous occurrence: an input echoed into HTML on one capture and into JSON
				// on another is an input echoed into HTML.
				if prev, exists := best[key]; exists && !passiveOutcomeBeats(outcome, prev.Outcome) {
					continue
				}
				best[key] = PassiveReflectionResult{
					VectorID: ref.VectorID, Parameter: param, CaptureID: c.ID,
					CaptureURL: c.URL, Outcome: outcome,
				}
			}
		}
	}
	return best
}

// passiveOutcomeBeats decides which of two exchanges describes an input better.
//
// Status first, on the one ranking this package has. On a tie, a response a browser would RENDER
// beats one it would not: the same echo into text/html and into application/json is one candidate
// and one curiosity, and the grade turns on exactly that.
func passiveOutcomeBeats(candidate, held ReflectionOutcome) bool {
	cr, hr := ReflectionStatusRank(candidate.Status), ReflectionStatusRank(held.Status)
	if cr != hr {
		return cr < hr
	}
	return ReflectionContentTypeRenders(candidate.ContentType) &&
		!ReflectionContentTypeRenders(held.ContentType)
}

// passiveVectorParameters is the input names to test for one vector.
//
// A path vector has none, and its single unnamed input is keyed by the empty string, which is the
// same key the active path probe stores under.
func passiveVectorParameters(ref PassiveVectorRef) []string {
	if ref.InsertionPoint == "path" {
		return []string{""}
	}
	out := make([]string, 0, len(ref.Parameters))
	for _, p := range ref.Parameters {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// BuildPassiveIndex turns the vector table into the map the pass looks captures up in.
//
// Fragment vectors are absent: a fragment never reaches the server, so no stored response can
// contain one and a passive row for it would be a claim about something nobody could have seen.
func BuildPassiveIndex(vectors []vectorRow, auth *ScopedAuthContext) map[string][]PassiveVectorRef {
	index := map[string][]PassiveVectorRef{}
	for _, v := range vectors {
		if v.InsertionPoint == "fragment" || !ReflectionProbeApplies(v.InsertionPoint) {
			continue
		}
		ref := PassiveVectorRef{
			VectorID:       v.ID,
			InsertionPoint: v.InsertionPoint,
			Parameters:     v.Parameters,
		}
		if auth != nil {
			if material, _ := auth.For(strings.ToLower(v.Domain)); material != nil {
				ref.Plan.CredentialCookies, ref.Plan.CredentialHeaders =
					ReflectionCredentialNames(material)
			}
		}
		key := PassiveMatchKey(v.Domain, v.Path)
		index[key] = append(index[key], ref)
	}
	return index
}

// loadPassiveCaptures reads the stored exchanges that any vector is interested in.
//
// TWO QUERIES ON PURPOSE. The corpus on the engaged target is 4383 captures holding 52MB of response
// bodies, and almost all of it is JavaScript and CSS that no vector points at. The first query pulls
// only the addressing columns, which is cheap, and decides which rows matter; the second pulls the
// bodies for those rows alone. Fetching every body to throw most of them away would move tens of
// megabytes through the pool for nothing.
func loadPassiveCaptures(ctx context.Context, scopeTargetID string,
	index map[string][]PassiveVectorRef) ([]PassiveCapture, error) {

	rows, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(url,''), COALESCE(endpoint,'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND COALESCE(response_body,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	var wanted []string
	for rows.Next() {
		var id, rawURL, endpoint string
		if rows.Scan(&id, &rawURL, &endpoint) != nil {
			continue
		}
		probe := PassiveCapture{URL: rawURL, Endpoint: endpoint}
		if len(index[PassiveMatchKey(probe.Host(), probe.Path())]) > 0 {
			wanted = append(wanted, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	full, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(method,''), COALESCE(url,''), COALESCE(endpoint,''),
		       COALESCE(headers, '{}'::jsonb), COALESCE(post_data,''), COALESCE(response_body,''),
		       COALESCE(response_headers, '{}'::jsonb), COALESCE(mime_type,''),
		       COALESCE(status_code,0)
		FROM manual_crawl_captures
		WHERE id = ANY($1::uuid[])`, wanted)
	if err != nil {
		return nil, err
	}
	defer full.Close()

	out := make([]PassiveCapture, 0, len(wanted))
	for full.Next() {
		var c PassiveCapture
		var reqHeaders, respHeaders map[string]any
		var mime string
		if full.Scan(&c.ID, &c.Method, &c.URL, &c.Endpoint, &reqHeaders, &c.RequestBody,
			&c.ResponseBody, &respHeaders, &mime, &c.StatusCode) != nil {
			continue
		}
		c.RequestHeaders = passiveHeaderMap(reqHeaders)
		c.ContentType = passiveResponseContentType(passiveHeaderMap(respHeaders), mime)
		out = append(out, c)
	}
	return out, full.Err()
}

// passiveHeaderMap flattens a stored jsonb header object to lower-cased string keys.
func passiveHeaderMap(raw map[string]any) map[string]string {
	out := map[string]string{}
	for name, value := range raw {
		if s, ok := value.(string); ok {
			out[strings.ToLower(strings.TrimSpace(name))] = s
		}
	}
	return out
}

// passiveResponseContentType prefers the RESPONSE HEADER over the stored mime_type.
//
// Measured on the corpus: mime_type carries text/html for a stylesheet, because it is the browser's
// resource classification rather than the header the server sent. The grade turns on whether a
// browser would parse the response as markup, so reading the wrong one would grade JSON and CSS
// responses as renderable and invent xss_candidate_high rows.
func passiveResponseContentType(respHeaders map[string]string, mime string) string {
	if ct := strings.TrimSpace(respHeaders["content-type"]); ct != "" {
		return ct
	}
	return strings.TrimSpace(mime)
}
