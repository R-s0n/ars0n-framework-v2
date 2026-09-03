package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// Attack vectors: one request carrying user-controlled input the application actually processes.
//
// The operator's definition, which this file implements literally: a vector has an HTTP verb, a
// domain, a path, a parameter combination and a payload insertion point. Two rows differing only in
// the VALUE sent are the same vector. Two differing in which parameters are in play, or in where the
// payload goes, are different vectors.
//
// IDENTITY IS THE PARAMETER SET, not one row per parameter. /search?q=&page= is ONE vector listing
// both names, and the insertion point says which container they live in. That is the operator's call
// and it halves the row count against the per-parameter reading.
//
// WHAT THIS FILE REFUSES TO PRETEND. Three facts about the upstream data decide most of the design,
// and every one of them is recorded on the row rather than smoothed over:
//
//   - The VERB is fabricated for crawled and archived rows. endpointConsolidationRun.go hardcodes
//     GET for every katana, gospider, linkfinder, gau and waybackurls endpoint, because none of those
//     tools reports a method. Those vectors carry method_confidence 'implied'.
//   - The parameter COMBINATION is destroyed by consolidation. consolidated_url_parameters holds the
//     UNION of every parameter name ever seen for an endpoint, not the set seen together in one
//     request, so a combination taken from it is a plausible request rather than an observed one.
//     Those vectors carry parameters_origin 'union'. Manual crawl captures are the only source that
//     preserves the real per-request combination, and they carry 'observed'.
//   - Arjun's insertion point is GUESSED from the verb (query for GET, body otherwise) rather than
//     observed; x8's is observed. Those carry insertion_confidence 'implied'.
//
// An operator deciding what to test needs to know which of these numbers were measured and which
// were assumed, because the assumed ones are where wasted hours come from.

// attackVectorInsertionPoints is the closed set of places a payload can go.
var attackVectorInsertionPoints = map[string]string{
	"query":  "the URL query string",
	"body":   "the request body",
	"header": "a request header",
	"cookie": "a cookie",
	"path":   "a path segment, where the value is part of the URL itself",
}

// attackVector is one row, as built by consolidation or typed by hand.
type attackVector struct {
	Method              string
	MethodConfidence    string
	Scheme              string
	Domain              string
	Port                int
	Path                string
	InsertionPoint      string
	InsertionConfidence string
	Parameters          []string
	ParametersOrigin    string
	Sources             []string
	EvidenceURL         string
	RawRequest          string
	Notes               string
	ManualAdded         bool
	Signals             []string
}

// key is the identity: verb, host, path, insertion point and the parameter SET.
//
// Parameters are sorted and lowercased-on-compare so that ?b=1&a=2 and ?a=2&b=1 are one vector, which
// they are: the order a browser happened to serialise them in is not part of the attack surface. The
// separator is a NUL because it cannot occur in any component, so no combination of values can be
// made to collide with another by embedding the separator.
func (v attackVector) key() string {
	params := append([]string(nil), v.Parameters...)
	sort.Strings(params)
	host := v.Domain
	if v.Port > 0 {
		host = fmt.Sprintf("%s:%d", v.Domain, v.Port)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToUpper(v.Method), strings.ToLower(host), v.Path,
		v.InsertionPoint, strings.Join(params, ","),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// upsertAttackVector stores one vector, merging provenance into anything already there.
//
// A row the operator has EDITED or DELETED is never overwritten by a later consolidation. That is the
// same invariant the endpoint workflow holds and for the same reason: re-running discovery must not
// undo a human decision, or the operator learns that their edits are temporary and stops making them.
func upsertAttackVector(ctx context.Context, scopeTargetID string, v attackVector) (bool, error) {
	// Never nil. A path vector has no parameters at all, and a nil slice reaches Postgres as NULL,
	// which the NOT NULL column rejects: the insert failed, the error was counted as "not inserted",
	// and the five real path findings vanished without a word.
	params := []string{}
	params = append(params, v.Parameters...)
	sort.Strings(params)
	sources := []string{}
	sources = append(sources, v.Sources...)
	signals := []string{}
	signals = append(signals, v.Signals...)

	// A key the operator has already edited away from is not re-created. Without this, correcting a
	// vector frees its old identity and the next consolidation inserts the uncorrected version again.
	var superseded bool
	if dbPool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM attack_vectors
		               WHERE scope_target_id = $1 AND $2 = ANY(superseded_keys))`,
		scopeTargetID, v.key()).Scan(&superseded) == nil && superseded && !v.ManualAdded {
		return false, nil
	}

	var inserted bool
	err := dbPool.QueryRow(ctx, `
		INSERT INTO attack_vectors (scope_target_id, vector_key, method, method_confidence, scheme,
		    domain, port, path, insertion_point, insertion_confidence, parameters, parameters_origin,
		    sources, evidence_url, raw_request, notes, manual_added, signals)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,0),$8,$9,$10,$11,$12,$13,NULLIF($14,''),NULLIF($15,''),
		        NULLIF($16,''),$17,$18)
		ON CONFLICT (scope_target_id, vector_key) DO UPDATE
		SET last_seen = NOW(),
		    times_seen = attack_vectors.times_seen + 1,
		    -- Provenance accumulates: a vector three tools agree on is worth more than one only a
		    -- crawler guessed at, and that is only visible if every source is kept.
		    sources = (
		        SELECT array_agg(DISTINCT s ORDER BY s)
		        FROM unnest(attack_vectors.sources || EXCLUDED.sources) AS s
		    ),
		    -- Confidence only ever improves. A vector first seen with an implied verb and later
		    -- observed with a real one is observed; the reverse is not a downgrade worth making.
		    method_confidence = CASE WHEN attack_vectors.method_confidence = 'observed'
		        OR EXCLUDED.method_confidence = 'observed' THEN 'observed' ELSE 'implied' END,
		    parameters_origin = CASE WHEN attack_vectors.parameters_origin = 'observed'
		        OR EXCLUDED.parameters_origin = 'observed' THEN 'observed' ELSE 'union' END,
		    insertion_confidence = CASE WHEN attack_vectors.insertion_confidence = 'observed'
		        OR EXCLUDED.insertion_confidence = 'observed' THEN 'observed' ELSE 'implied' END,
		    signals = (
		        SELECT COALESCE(array_agg(DISTINCT g ORDER BY g), '{}')
		        FROM unnest(attack_vectors.signals || EXCLUDED.signals) AS g
		    ),
		    evidence_url = COALESCE(attack_vectors.evidence_url, EXCLUDED.evidence_url),
		    raw_request = COALESCE(NULLIF(attack_vectors.raw_request, ''), NULLIF(EXCLUDED.raw_request, ''))
		RETURNING (xmax = 0)`,
		scopeTargetID, v.key(), strings.ToUpper(v.Method), v.MethodConfidence, v.Scheme,
		strings.ToLower(v.Domain), v.Port, v.Path, v.InsertionPoint, v.InsertionConfidence,
		params, v.ParametersOrigin, sources, v.EvidenceURL, v.RawRequest, v.Notes,
		v.ManualAdded, signals).Scan(&inserted)
	return inserted, err
}

// ConsolidateAttackVectors answers POST /attack-vectors/{scope_target_id}/consolidate.
func ConsolidateAttackVectors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	type sourceResult struct {
		Source   string   `json:"source"`
		Added    int      `json:"added"`
		Seen     int      `json:"seen"`
		Excluded int      `json:"excluded"`
		Notes    []string `json:"notes,omitempty"`
	}
	results := []sourceResult{}

	for _, fn := range []func(context.Context, string) (sourceResult, error){
		func(c context.Context, id string) (sourceResult, error) {
			res, err := vectorsFromManualCrawl(c, id)
			return sourceResult(res), err
		},
		func(c context.Context, id string) (sourceResult, error) {
			res, err := vectorsFromEndpoints(c, id)
			return sourceResult(res), err
		},
		func(c context.Context, id string) (sourceResult, error) {
			res, err := vectorsFromParamEnum(c, id)
			return sourceResult(res), err
		},
		func(c context.Context, id string) (sourceResult, error) {
			res, err := vectorsFromFuzz(c, id)
			return sourceResult(res), err
		},
	} {
		res, err := fn(ctx, scopeTargetID)
		if err != nil {
			res.Notes = append(res.Notes, "stopped early: "+err.Error())
		}
		results = append(results, res)
	}

	total, hosts, manual, withNotes := attackVectorTotals(ctx, scopeTargetID)
	added := 0
	for _, r := range results {
		added += r.Added
	}

	// The count next to what the count is made of. A total on its own reads as input variety and is
	// not: see attackVectorDiversity.
	diversity := attackVectorDiversity(ctx, scopeTargetID)
	summary := fmt.Sprintf("%d unique vectors across %d host(s); %d new this run.",
		total, hosts, added)
	for _, d := range diversity {
		if d.Note != "" {
			summary += " " + d.Note
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": total, "hosts": hosts, "manual": manual, "with_notes": withNotes,
		"added":              added,
		"by_source":          results,
		"by_insertion_point": diversity,
		"summary":            summary,
	})
}

type vectorSourceResult struct {
	Source   string   `json:"source"`
	Added    int      `json:"added"`
	Seen     int      `json:"seen"`
	Excluded int      `json:"excluded"`
	Notes    []string `json:"notes,omitempty"`
}

// vectorsFromManualCrawl is the highest-fidelity source and the only one that preserves a real
// parameter COMBINATION: every capture is one request the browser actually sent, so the query keys
// seen together were seen together.
func vectorsFromManualCrawl(ctx context.Context, scopeTargetID string) (vectorSourceResult, error) {
	out := vectorSourceResult{Source: "manual_crawl"}

	rows, err := dbPool.Query(ctx, `
		SELECT url, upper(COALESCE(method,'GET')),
		       COALESCE(get_params::text,'{}'), COALESCE(post_params::text,'{}'),
		       COALESCE(headers::text,'{}'),
		       COALESCE(post_data,''), COALESCE(body_type,''),
		       -- Response headers, for the echoed-cookie check. A cookie the server builds from a
		       -- request parameter is that parameter arriving by a second, untested route.
		       COALESCE(response_headers::text,'{}')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		  -- Preflights and HEAD carry no user input worth testing and duplicate the real request that
		  -- follows them, one for one.
		  AND upper(COALESCE(method,'GET')) NOT IN ('OPTIONS','HEAD')`, scopeTargetID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	store := func(v attackVector) {
		if ins, err := upsertAttackVector(ctx, scopeTargetID, v); err == nil && ins {
			out.Added++
		}
	}

	// Cookie and header vectors are not stored as they are met. They go here instead, and only the
	// maximal observation of each endpoint's jar survives to the end of the scan. See ambientHold.
	held := &ambientHold{}

	for rows.Next() {
		var rawURL, method, getParams, postParams, headers, postData, bodyType string
		var responseHeaders string
		if rows.Scan(&rawURL, &method, &getParams, &postParams, &headers,
			&postData, &bodyType, &responseHeaders) != nil {
			continue
		}
		out.Seen++
		immediate, ambient, ok := manualCrawlCaptureVectors(manualCrawlCapture{
			Method: method, URL: rawURL, GetParams: getParams, PostParams: postParams,
			Headers: headers, PostData: postData, BodyType: bodyType,
			ResponseHeaders: responseHeaders,
		})
		if !ok {
			out.Excluded++
			continue
		}
		for _, v := range immediate {
			store(v)
		}
		for _, v := range ambient {
			held.add(v)
		}
	}

	for _, v := range held.vectors() {
		store(v)
	}
	if subsumed := held.subsumed(); subsumed > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d cookie or header observation(s) were the same endpoint's jar earlier in the session, "+
				"carrying a strict subset of the names another capture of that endpoint already "+
				"carries, so they add no name that is not already testable there.", subsumed))
	}
	return out, nil
}

// manualCrawlCapture is one row of manual_crawl_captures, as the builder below needs it.
type manualCrawlCapture struct {
	Method          string
	URL             string
	GetParams       string
	PostParams      string
	Headers         string
	PostData        string
	BodyType        string
	ResponseHeaders string
}

// manualCrawlCaptureVectors turns one capture into the vectors it produces, split by whether each one
// can be stored on sight or has to be held.
//
// SEPARATE FROM THE QUERY FOR THE SAME REASON manualCrawlVector IS. The note on that function records
// that the builder was easy to cover and the WIRING was not, and that the gap let 10 body vectors be
// scanned with no body at all. The identical gap opened here the moment cookie and header rows
// stopped being stored on sight: a mutation that sent every held observation straight to the database
// passed every test, because the tests reached the subsumption rule directly and nothing reached the
// call to it. Which bucket a vector goes in is a return value now, so a test can hold the routing to
// it without a database.
//
// The ambient bucket is cookie and header only, which are the two containers the BROWSER fills.
func manualCrawlCaptureVectors(c manualCrawlCapture) (immediate, ambient []attackVector, ok bool) {
	base, pathSignals, ok := manualCrawlVector(c.Method, c.URL, c.Headers, c.PostData, c.BodyType)
	if !ok {
		return nil, nil, false
	}
	path := base.Path

	for point, blob := range map[string]string{"query": c.GetParams, "body": c.PostParams} {
		names := usefulParameterNames(jsonObjectKeys(blob))
		if len(names) == 0 || vectorIsNoise(path, names) {
			continue
		}
		v := base
		v.InsertionPoint = point
		v.Parameters = names
		v.Signals = inputSignalsFor(blob, names)
		immediate = append(immediate, v)
	}
	// Map iteration order is random in Go, so without this query and body arrive in either order and
	// a test that reads the slice is flaky one run in two.
	sort.Slice(immediate, func(i, j int) bool {
		return immediate[i].InsertionPoint < immediate[j].InsertionPoint
	})

	// A static file gets cookies and headers because the BROWSER attaches them to everything, not
	// because the file reads them. Those are the one case where the presence of an input proves
	// nothing, so they are skipped here while a query or body parameter on the same path is still
	// judged on what it carries.
	staticPath := vectorPathIsStaticAsset(path)

	// An identifier IN THE PATH is user-controlled input the application reads, and swapping it is
	// the whole of an access-control test. Without this the richest vectors on a real target,
	// /global-wallet/v1/accounts/{uuid} among them, were not in the list at all.
	if len(pathSignals) > 0 && !staticPath {
		v := base
		v.InsertionPoint = "path"
		v.Signals = pathSignals
		immediate = append(immediate, v)
	}

	// Headers the application invented, and the cookies inside them. A JWT in an Authorization
	// header or a session cookie is the highest-value input on most targets and is not a parameter
	// by any reading.
	headerNames, headerSignals := appHeaderInputs(c.Headers)
	if len(headerNames) > 0 && !staticPath {
		v := base
		v.InsertionPoint = "header"
		v.Parameters = headerNames
		v.Signals = headerSignals
		ambient = append(ambient, v)
	}
	cookieNames, cookieSignals := cookieInputs(c.Headers)
	if len(cookieNames) > 0 && !staticPath {
		v := base
		v.InsertionPoint = "cookie"
		v.Parameters = cookieNames
		v.Signals = cookieSignals
		ambient = append(ambient, v)
	}
	// A cookie the SERVER built from a request parameter, which is the same attacker-controlled
	// input arriving by a route nothing tests. Emitted as its own vector rather than folded into
	// the one above, because the two are different propositions: the jar's cookies are whatever
	// the browser was carrying, and this one is a value the caller chose.
	//
	// IMMEDIATE, not ambient, and the difference matters. A server-set cookie name is very often ALSO
	// in the jar on the next request, so holding it would let the jar's larger set swallow the one
	// cookie vector on the row that is worth having. Subsumption is about repeated observations of
	// the same ambient jar, and this is not one of those.
	echoedNames, echoedSignals := echoedCookieInputs(c.ResponseHeaders, c.GetParams, c.PostParams)
	if len(echoedNames) > 0 && !staticPath {
		v := base
		v.InsertionPoint = "cookie"
		v.Parameters = echoedNames
		v.Signals = echoedSignals
		immediate = append(immediate, v)
	}
	return immediate, ambient, true
}

// ambientHold accumulates cookie and header observations and drops any whose name set another
// observation of the SAME verb, host, path and insertion point already contains.
//
// WHAT THIS IS NOT. It is not a change to what counts as one vector. Identity is still verb + host +
// path + parameter SET + insertion point, and the same cookie jar on two different endpoints is still
// two vectors, correctly: a payload in that cookie has to be sent to each endpoint separately and the
// two will not answer the same way. Collapsing those would understate the work rather than overstate
// the coverage, and that definition is the methodology's, not this file's, to change.
//
// WHAT IT REMOVES. One endpoint recorded three times because the JAR GREW while the operator browsed.
// Measured against Juice Shop: 77 cookie vectors sat on 55 distinct verb-and-path pairs. GET /,
// GET /api/Challenges/, GET /rest/products/search and seven others each appeared three times, with
//
//	{continueCode, language, welcomebanner_status}
//	{continueCode, cookieconsent_status, language, welcomebanner_status}
//	{continueCode, cookieconsent_status, language, token, welcomebanner_status}
//
// which is the consent banner being dismissed and then a login, not three combinations. Each set is a
// strict subset of the next, so the largest already puts a payload in every name the other two would.
// Twenty-two rows that cannot find anything the rows beside them cannot.
//
// WHY THE SAME REASONING DOES NOT REACH QUERY OR BODY. There the CALLER chose which parameters to
// send, so ?q= and ?q=&page= are two propositions and the smaller one can behave differently. Here
// the browser attached whatever it happened to be holding; the operator never chose, and no request
// they can compose corresponds to the smaller set except by clearing cookies first.
//
// A covered set is DROPPED, never merged into a union. These rows carry parameters_origin 'observed'
// and a union would be a combination that was never sent.
//
// Incremental rather than buffer-then-filter because a long crawl is thousands of captures and every
// held vector carries its own request bytes. Keeping only the maximal set as it goes bounds this at a
// few rows per endpoint instead of two per capture.
type ambientHold struct {
	groups map[string][]attackVector
	order  []string
	seen   int
}

// add applies the subsumption rule WITHIN one verb, host, path and insertion point, and never across
// them. That boundary is the whole safety of this: comparing every held vector against every other
// would collapse two endpoints carrying the same jar into one row, which is exactly the redefinition
// of identity that must not happen.
func (a *ambientHold) add(v attackVector) {
	if a.groups == nil {
		a.groups = map[string][]attackVector{}
	}
	a.seen++
	key := ambientVectorGroupKey(v)
	group, exists := a.groups[key]
	if !exists {
		a.order = append(a.order, key)
	}
	incoming := ambientNameSet(v)
	kept := group[:0]
	for _, existing := range group {
		// An observation already here that covers the new one makes the new one redundant. Equality
		// counts as covering, so the first sighting of a jar stands in for every repeat of it and a
		// run of identical jars cannot delete itself.
		if ambientNamesContain(ambientNameSet(existing), incoming) {
			a.groups[key] = group
			return
		}
		// The reverse: the new observation covers an older one, which is the jar having grown.
		if !ambientNamesContain(incoming, ambientNameSet(existing)) {
			kept = append(kept, existing)
		}
	}
	a.groups[key] = append(kept, v)
}

// vectors returns the survivors in the order their endpoint was first seen, so re-running the same
// crawl stores the same rows in the same order.
func (a *ambientHold) vectors() []attackVector {
	out := make([]attackVector, 0, a.seen)
	for _, key := range a.order {
		out = append(out, a.groups[key]...)
	}
	return out
}

// subsumed is how many observations were dropped as covered by another on the same endpoint.
func (a *ambientHold) subsumed() int {
	return a.seen - len(a.vectors())
}

func ambientNameSet(v attackVector) map[string]bool {
	set := make(map[string]bool, len(v.Parameters))
	for _, name := range v.Parameters {
		set[strings.ToLower(strings.TrimSpace(name))] = true
	}
	return set
}

// maximalAmbientObservations is ambientHold applied to a whole batch at once. Consolidation feeds
// rows in one at a time; this is the same rule in the form a test can read.
func maximalAmbientObservations(observations []attackVector) []attackVector {
	hold := &ambientHold{}
	for _, v := range observations {
		hold.add(v)
	}
	return hold.vectors()
}

// ambientVectorGroupKey is the identity MINUS the parameter set: verb, host, path, insertion point.
//
// Only maximalAmbientObservations uses it. It is deliberately not attackVector.key with the
// parameters removed, because that key IS the identity and nothing else may be tempted to weaken it.
func ambientVectorGroupKey(v attackVector) string {
	host := v.Domain
	if v.Port > 0 {
		host = fmt.Sprintf("%s:%d", v.Domain, v.Port)
	}
	return strings.Join([]string{
		strings.ToUpper(v.Method), strings.ToLower(host), v.Path, v.InsertionPoint,
	}, "\x00")
}

// ambientNamesContain reports whether outer holds every name in inner.
func ambientNamesContain(outer, inner map[string]bool) bool {
	if len(inner) > len(outer) {
		return false
	}
	for name := range inner {
		if !outer[name] {
			return false
		}
	}
	return true
}

// vectorsFromEndpoints covers live crawling, archive and JavaScript mining, which are all
// consolidated into consolidated_url_endpoints before they get here.
//
// Two honest caveats travel with every row this produces. The verb is whatever consolidation
// recorded, which for crawler and archive rows is a hardcoded GET, so method_confidence follows the
// endpoint's own method_confidence. And the parameter set is the UNION of everything ever seen on
// that endpoint rather than a combination observed in one request, so parameters_origin is 'union'.
func vectorsFromEndpoints(ctx context.Context, scopeTargetID string) (vectorSourceResult, error) {
	out := vectorSourceResult{Source: "crawl_archive_endpoints"}

	rows, err := dbPool.Query(ctx, `
		SELECT e.url, upper(COALESCE(e.method,'GET')), COALESCE(e.method_confidence,''),
		       COALESCE(e.domain,''), e.port, COALESCE(e.path,'/'), COALESCE(e.scheme,'https'),
		       COALESCE(e.sources,'{}'), p.param_type, array_agg(DISTINCT p.param_name)
		FROM consolidated_url_endpoints e
		JOIN consolidated_url_parameters p ON p.endpoint_id = e.id
		WHERE e.scope_target_id = $1
		  AND e.deleted_at IS NULL
		  -- A path validation measured as not existing cannot be carrying user input anywhere.
		  AND COALESCE(e.override_status, e.validation_status, '') <> 'ruled_out'
		  AND upper(COALESCE(e.method,'GET')) NOT IN ('OPTIONS','HEAD')
		  AND COALESCE(p.param_name,'') <> ''
		GROUP BY e.url, e.method, e.method_confidence, e.domain, e.port, e.path, e.scheme,
		         e.sources, p.param_type`, scopeTargetID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var rawURL, method, confidence, domain, path, scheme, paramType string
		var port *int
		var sources, names []string
		if rows.Scan(&rawURL, &method, &confidence, &domain, &port, &path, &scheme,
			&sources, &paramType, &names) != nil {
			continue
		}
		out.Seen++
		point := normaliseInsertionPoint(paramType)
		names = usefulParameterNames(names)
		if point == "" || domain == "" || len(names) == 0 || vectorIsNoise(path, names) {
			out.Excluded++
			continue
		}
		path, pathSignals := templateVectorPath(path)
		if confidence == "" {
			confidence = "implied"
		}
		v := attackVector{
			Method: method, MethodConfidence: confidence, Scheme: scheme, Domain: domain,
			Path: path, InsertionPoint: point, InsertionConfidence: "observed",
			Parameters: names, ParametersOrigin: "union",
			Sources: sources, EvidenceURL: rawURL, Signals: pathSignals,
		}
		if port != nil {
			v.Port = *port
		}
		if len(v.Sources) == 0 {
			v.Sources = []string{"crawl"}
		}
		if ins, err := upsertAttackVector(ctx, scopeTargetID, v); err == nil && ins {
			out.Added++
		}
	}
	return out, nil
}

// vectorsFromParamEnum covers Arjun and x8: parameter NAMES discovered on an endpoint.
func vectorsFromParamEnum(ctx context.Context, scopeTargetID string) (vectorSourceResult, error) {
	out := vectorSourceResult{Source: "arjun_x8"}

	rows, err := dbPool.Query(ctx, `
		SELECT endpoint_url, upper(COALESCE(http_method,'GET')), COALESCE(parameter_type,''),
		       lower(COALESCE(scan_type,'')), array_agg(DISTINCT parameter_name)
		FROM parameter_enumeration_results
		WHERE scope_target_id = $1 AND COALESCE(parameter_name,'') <> ''
		GROUP BY endpoint_url, http_method, parameter_type, scan_type`, scopeTargetID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var rawURL, method, paramType, tool string
		var names []string
		if rows.Scan(&rawURL, &method, &paramType, &tool, &names) != nil {
			continue
		}
		out.Seen++
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			out.Excluded++
			continue
		}
		point := normaliseInsertionPoint(paramType)
		names = usefulParameterNames(names)
		if point == "" || len(names) == 0 {
			out.Excluded++
			continue
		}
		domain, port := splitHostPort(u)
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		// Arjun does not observe where it put the parameter: arjunUtils.go derives the place from the
		// verb, query for GET and body for anything else. x8 is told the place and reports it back.
		insertionConfidence := "observed"
		if tool == "arjun" {
			insertionConfidence = "implied"
		}
		v := attackVector{
			Method: method, MethodConfidence: "observed", Scheme: u.Scheme, Domain: domain,
			Port: port, Path: path, InsertionPoint: point,
			InsertionConfidence: insertionConfidence,
			Parameters:          names, ParametersOrigin: "observed",
			Sources: []string{tool}, EvidenceURL: rawURL,
		}
		if ins, err := upsertAttackVector(ctx, scopeTargetID, v); err == nil && ins {
			out.Added++
		}
	}
	return out, nil
}

// vectorsFromFuzz promotes ffuf findings, which know their insertion point exactly because a step
// is literal request bytes with a marked position.
//
// TWO TESTS, NOT ONE. A finding is promoted only when it differs from its rs0n baseline AND its
// response shape is not the one most of that step's findings share. Differing from the baseline alone
// is necessary and nowhere near sufficient: on this target one step produced 278 findings that all
// answer 500 with the same 89 bytes while the canary answers 404, so all 278 "differ" while showing
// only that the endpoint rejects any unknown key. Promoting them would invent 278 attack vectors out
// of one behaviour.
func vectorsFromFuzz(ctx context.Context, scopeTargetID string) (vectorSourceResult, error) {
	out := vectorSourceResult{Source: "ffuf"}

	rows, err := dbPool.Query(ctx, `
		WITH shapes AS (
		    SELECT step_id, http_status, response_words, response_lines, count(*) AS n,
		           sum(count(*)) OVER (PARTITION BY step_id) AS step_total
		    FROM fuzz_findings
		    WHERE scope_target_id = $1 AND triage <> 'dismissed'
		    GROUP BY step_id, http_status, response_words, response_lines
		)
		SELECT f.url, f.method, f.payload, COALESCE(p.role,''), s.raw_request,
		       f.http_status, f.response_size, f.response_words, f.response_lines,
		       b.http_status, b.response_size, b.response_words, b.response_lines,
		       sh.n, sh.step_total
		FROM fuzz_findings f
		JOIN fuzz_steps s ON s.id = f.step_id
		LEFT JOIN fuzz_positions p ON p.step_id = s.id AND p.token = f.position_token
		JOIN fuzz_baselines b ON b.id = f.baseline_id
		JOIN shapes sh ON sh.step_id = f.step_id AND sh.http_status = f.http_status
		     AND sh.response_words = f.response_words AND sh.response_lines = f.response_lines
		WHERE f.scope_target_id = $1 AND f.triage <> 'dismissed'`, scopeTargetID)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	uniform := 0
	sameAsBaseline := 0
	for rows.Next() {
		var rawURL, method, payload, role, raw string
		var status, words, lines, bStatus, bWords, bLines int
		var size, bSize int64
		var shapeN, stepTotal int
		if rows.Scan(&rawURL, &method, &payload, &role, &raw, &status, &size, &words, &lines,
			&bStatus, &bSize, &bWords, &bLines, &shapeN, &stepTotal) != nil {
			continue
		}
		out.Seen++

		if baselineVerdict(status, size, words, lines, bStatus, bSize, bWords, bLines) == "same" {
			sameAsBaseline++
			out.Excluded++
			continue
		}
		// The shape test. A response most of the step shares is the step's own wall, whatever the
		// canary happened to answer.
		if stepTotal >= noiseGuardMinRows && float64(shapeN) >= noiseGuardShare*float64(stepTotal) {
			uniform++
			out.Excluded++
			continue
		}

		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			out.Excluded++
			continue
		}
		domain, port := splitHostPort(u)
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}

		point, name := fuzzInsertionPoint(role, raw, payload)
		if point == "" {
			out.Excluded++
			continue
		}
		v := attackVector{
			Method: method, MethodConfidence: "observed", Scheme: u.Scheme, Domain: domain,
			Port: port, Path: path, InsertionPoint: point, InsertionConfidence: "observed",
			ParametersOrigin: "observed", Sources: []string{"ffuf"}, EvidenceURL: rawURL,
			// The step's TEMPLATE with the payload put back in, not the template itself. Storing the
			// template meant a path vector for /META-INF displayed as GET /{{p01}}: a marker the
			// operator cannot send, describing a step rather than this vector.
			RawRequest: fuzzTokenRe.ReplaceAllString(raw, fuzzPayloadWord(payload)),
		}
		if name != "" {
			v.Parameters = []string{name}
		}
		ins, err := upsertAttackVector(ctx, scopeTargetID, v)
		if err != nil {
			out.Excluded++
			if len(out.Notes) < 6 {
				out.Notes = append(out.Notes, "could not store a vector: "+err.Error())
			}
			continue
		}
		if ins {
			out.Added++
		}
	}

	if sameAsBaseline > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d finding(s) answered the same as their rs0n baseline, so nothing about the payload was "+
				"being processed.", sameAsBaseline))
	}
	if uniform > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d finding(s) share one response shape with most of their step, which is that step's wall "+
				"rather than one vector per payload.", uniform))
	}
	return out, nil
}

// fuzzInsertionPoint maps a position's role onto an insertion point, and works out which parameter is
// in play.
//
// The subtlety is that a marked position can be a parameter's VALUE or its NAME, and the two mean
// opposite things. A step whose body reads {"phone":"+1...","{{p01}}":"rs0n"} is fuzzing the KEY, so
// the payload IS the parameter name; a step whose body reads {"phone":"{{p01}}"} is fuzzing the value
// of phone. Reading the character before the token tells them apart.
func fuzzInsertionPoint(role, raw, payload string) (point, name string) {
	switch role {
	case "path":
		// The value is the URL itself, so there is no parameter and none is invented.
		return "path", ""
	case "query_value":
		point = "query"
	case "body_value":
		point = "body"
	case "header_value", "header_name":
		point = "header"
	case "cookie_value":
		point = "cookie"
	default:
		return "", ""
	}

	word := fuzzPayloadWord(payload)
	idx := strings.Index(raw, "{{p")
	if idx < 0 {
		return point, word
	}
	before := raw[:idx]

	// A token sitting where a KEY goes: the payload is the parameter name.
	trimmed := strings.TrimRight(before, " \t")
	if strings.HasSuffix(trimmed, "{") || strings.HasSuffix(trimmed, ",") ||
		strings.HasSuffix(trimmed, "{\"") || strings.HasSuffix(trimmed, ",\"") ||
		strings.HasSuffix(trimmed, "&") || strings.HasSuffix(trimmed, "?") {
		return point, word
	}

	// Otherwise the token is a value, and the name is the key immediately before it.
	if at := strings.LastIndexAny(before, "\"'"); at >= 0 {
		seg := before[:at]
		if start := strings.LastIndexAny(seg, "\"'"); start >= 0 {
			if key := seg[start+1:]; key != "" && !strings.ContainsAny(key, "{}:,") {
				return point, key
			}
		}
	}
	if at := strings.LastIndex(before, "="); at >= 0 {
		seg := before[:at]
		// ';' belongs in this set because cookies are separated by "; " INSIDE one header line.
		// Without it the search ran back to the start of the line and produced the parameter name
		//
		//	Cookie: session=s7KgQhXLHEoN4hbvdDBoaH4daz4DO7LC; AWSALB
		//
		// which is most of a header rather than a cookie name. That single row then carried a stale
		// session token into every scan that read it: dalfox aborted on SESSION_LOST and 35 of its
		// vectors were left with no verdict at all, across two separate runs.
		if start := strings.LastIndexAny(seg, "?&;\n"); start >= 0 {
			if key := strings.TrimSpace(seg[start+1:]); key != "" {
				return point, stripHeaderPrefix(key)
			}
		}
	}
	if at := strings.LastIndex(before, "\n"); at >= 0 {
		if header, _, ok := strings.Cut(before[at+1:], ":"); ok {
			if h := strings.TrimSpace(header); h != "" {
				return point, h
			}
		}
	}
	return point, word
}

// stripHeaderPrefix removes a "Header-Name: " prefix from a key pulled out of a raw request.
//
// The FIRST cookie in a Cookie header has no ';' in front of it, so even with ';' in the delimiter
// set above the search runs back to the start of the line and takes "Cookie: " with it. A cookie
// name cannot contain a colon, so whatever follows one is the name.
func stripHeaderPrefix(key string) string {
	if at := strings.Index(key, ":"); at >= 0 {
		if rest := strings.TrimSpace(key[at+1:]); rest != "" {
			return rest
		}
	}
	return key
}

// --- helpers ---------------------------------------------------------------------------------

func splitHostPort(u *url.URL) (string, int) {
	host := u.Hostname()
	port := 0
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			// A default port is not part of the identity: https://h and https://h:443 are one host.
			if !(u.Scheme == "https" && n == 443) && !(u.Scheme == "http" && n == 80) {
				port = n
			}
		}
	}
	return strings.ToLower(host), port
}

// normaliseInsertionPoint maps whatever a source calls a place onto the closed set.
func normaliseInsertionPoint(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "query", "get", "url", "querystring", "query_string":
		return "query"
	case "body", "post", "json", "form", "data":
		return "body"
	case "header", "headers":
		return "header"
	case "cookie", "cookies":
		return "cookie"
	case "path", "url_path":
		return "path"
	}
	if _, ok := attackVectorInsertionPoints[s]; ok {
		return s
	}
	return ""
}

// jsonObjectKeys returns the top-level keys of a JSON object, which is what the capture tables store.
func jsonObjectKeys(blob string) []string {
	var m map[string]any
	if json.Unmarshal([]byte(blob), &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		if strings.TrimSpace(k) != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// withNotes counts the vectors an operator has written something against, which is the closest
// thing the list has to "looked at": a note is only ever there because somebody typed it.
func attackVectorTotals(ctx context.Context, scopeTargetID string) (total, hosts, manual, withNotes int) {
	_ = dbPool.QueryRow(ctx, `
		SELECT count(*), count(DISTINCT domain), count(*) FILTER (WHERE manual_added),
		       count(*) FILTER (WHERE COALESCE(TRIM(notes),'') <> '')
		FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL`,
		scopeTargetID).Scan(&total, &hosts, &manual, &withNotes)
	return total, hosts, manual, withNotes
}

// attackVectorPointDiversity is one insertion point's count reported next to what that count is made
// of.
type attackVectorPointDiversity struct {
	InsertionPoint string   `json:"insertion_point"`
	Vectors        int      `json:"vectors"`
	Endpoints      int      `json:"endpoints"`
	DistinctNames  int      `json:"distinct_names"`
	Names          []string `json:"names,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// attackVectorDiversity reports, per insertion point, how many vectors there are AND how many
// distinct parameter names they carry between them.
//
// WHY THE SECOND NUMBER HAD TO EXIST. The Juice Shop run produced 202 vectors, of which 77 were
// cookie and 43 header. Those two numbers read as the healthiest part of the list, because the
// coverage endpoint's own warning is about a ZERO at an insertion point and neither of these is zero.
// Between them the 77 cookie vectors carry five names, language, welcomebanner_status, continueCode,
// cookieconsent_status and token, and the 43 header vectors carry one, authorization. So a clean
// result across all 120 rules out six things, and the count invites the reader to believe it ruled
// out a hundred and twenty.
//
// This is reported rather than fixed by collapsing rows, and that is the deliberate choice. The 120
// requests are all real and all have to be sent: authorization on /rest/user/whoami and authorization
// on /api/Challenges are two tests with two answers. The count is honest about the WORK. It is the
// diversity that was missing, so the diversity is what gets added, and the identity that the rest of
// this framework is built on is left exactly as the methodology defines it.
func attackVectorDiversity(ctx context.Context, scopeTargetID string) []attackVectorPointDiversity {
	rows, err := dbPool.Query(ctx, `
		WITH v AS (
		    SELECT insertion_point, method, path, parameters
		    FROM attack_vectors
		    WHERE scope_target_id = $1 AND deleted_at IS NULL
		), names AS (
		    SELECT v.insertion_point,
		           array_agg(DISTINCT lower(n) ORDER BY lower(n)) AS names
		    FROM v, unnest(v.parameters) AS n
		    WHERE COALESCE(n,'') <> ''
		    GROUP BY v.insertion_point
		)
		SELECT v.insertion_point, count(*), count(DISTINCT (v.method, v.path)),
		       COALESCE(names.names, '{}')
		FROM v LEFT JOIN names ON names.insertion_point = v.insertion_point
		GROUP BY v.insertion_point, names.names
		ORDER BY count(*) DESC`, scopeTargetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []attackVectorPointDiversity{}
	for rows.Next() {
		var d attackVectorPointDiversity
		var names []string
		if rows.Scan(&d.InsertionPoint, &d.Vectors, &d.Endpoints, &names) != nil {
			continue
		}
		d.DistinctNames = len(names)
		// Enough names to recognise the list, not so many that a query point with two hundred of them
		// buries the numbers beside it.
		if len(names) > attackVectorNamesShown {
			d.Names = append([]string(nil), names[:attackVectorNamesShown]...)
		} else {
			d.Names = names
		}
		d.Note = attackVectorDiversityNote(d)
		out = append(out, d)
	}
	return out
}

const attackVectorNamesShown = 20

// attackVectorReplicationFloor is where a count stops describing inputs and starts describing
// endpoints. Three vectors per distinct name is the point at which the Juice Shop cookie list, at
// fifteen per name, is called out and an ordinary query list, where most names appear once or twice,
// is not.
const attackVectorReplicationFloor = 3

func attackVectorDiversityNote(d attackVectorPointDiversity) string {
	if d.DistinctNames == 0 {
		if d.InsertionPoint == "path" {
			return ""
		}
		return fmt.Sprintf("%d %s vector(s) carry no parameter name at all.", d.Vectors, d.InsertionPoint)
	}
	if d.Vectors < attackVectorReplicationFloor*d.DistinctNames {
		return ""
	}
	return fmt.Sprintf(
		"%d %s vector(s) carrying only %d distinct name(s) across %d endpoint(s). That is %d input(s) "+
			"replicated, not %d, so a clean result here rules out %d thing(s). The requests are still "+
			"all worth sending, because the same name on two endpoints reaches two pieces of code, but "+
			"the count measures endpoints reached rather than input variety found.",
		d.Vectors, d.InsertionPoint, d.DistinctNames, d.Endpoints,
		d.DistinctNames, d.Vectors, d.DistinctNames)
}

// usefulParameterNames drops names that are not parameters an application reads.
//
// Three kinds of rubbish reach this point, all of them measured on live data rather than imagined:
//
//   - "$" and friends, produced when JavaScript mining regexes match a fragment of minified code and
//     hand it to the query parser. There were 12 of these on one target.
//   - "amp;adid" and friends, produced when a URL stored with HTML entities (&amp;) is split on "&",
//     so the entity tail becomes the next parameter's name.
//   - "_body", which the capture extension writes when a request body is a scalar or a bare array
//     rather than an object. It is a placeholder for "there was a body", not a parameter name.
func usefulParameterNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		n := strings.TrimSpace(name)
		if n == "" || n == "_body" || strings.HasPrefix(n, "amp;") {
			continue
		}
		if !attackVectorParamName.MatchString(n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

var attackVectorParamName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\[\]-]*$`)

// isStaticAsset reports whether a path is a file served as-is rather than an endpoint that processes
// input.
//
// A script or a stylesheet with a query string is a cache-buster or a third-party tag, not an attack
// vector: on this target three of the first 47 vectors were iovation's fingerprinting script carrying
// its own configuration in the query. Testing those spends requests on a CDN and finds nothing.
func vectorPathIsStaticAsset(path string) bool {
	clean := strings.ToLower(path)
	if at := strings.IndexAny(clean, "?#"); at >= 0 {
		clean = clean[:at]
	}
	for _, ext := range []string{".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".avif"} {
		if strings.HasSuffix(clean, ext) {
			return true
		}
	}
	return false
}

// vectorIsNoise decides whether a path-and-parameter pair is worth testing at all.
//
// Classified by BEHAVIOUR rather than by file extension. Excluding every .js and .css outright is the
// obvious rule and it is wrong: on this target it threw away
// /iojs/general5/wdp.js?tp_host=https://web.onepay.com/iojs, whose tp_host takes a URL and is exactly
// the shape a server-side request forgery or a script-source injection lives in. A script endpoint
// that reads a meaningful parameter is a server-processed endpoint whatever it is named.
//
// So a static-looking path is only dropped when everything it carries is a cache-buster or a tracking
// tag, which is the case that really is a CDN fetch with decoration on it.
func vectorIsNoise(path string, names []string) bool {
	if !vectorPathIsStaticAsset(path) {
		return false
	}
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if !cacheBusterParams[strings.ToLower(strings.TrimSpace(n))] {
			return false
		}
	}
	return true
}

// cacheBusterParams are the names that only ever exist to defeat a cache or to tag a campaign. None
// of them is read by application code, so a request carrying nothing else is not an attack vector.
var cacheBusterParams = map[string]bool{
	"v": true, "ver": true, "version": true, "t": true, "ts": true, "time": true,
	"cb": true, "cachebust": true, "cache": true, "_": true, "rnd": true, "random": true,
	"hash": true, "rev": true, "build": true, "nocache": true, "dt": true, "r": true,
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "gclid": true, "fbclid": true, "msclkid": true,
}

// attackVectorSkippedMethod covers verbs that carry no user input worth testing. OPTIONS in
// particular duplicates the real request that follows it, one preflight for one call.
func attackVectorSkippedMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "OPTIONS", "HEAD", "TRACE", "CONNECT", "WEBSOCKET":
		return true
	}
	return false
}

// manualCrawlVector maps one capture row onto the vector every insertion point is then derived from.
//
// Pure, and separate from the query, for one reason: the RawRequest line below was missing for the
// whole life of this function, and no test could see it because the only caller needs a database.
// The builder was easy to cover and the WIRING was not, which is the shape of gap that let 10 body
// vectors be scanned with no body at all. Now both are reachable from a test.
func manualCrawlVector(method, rawURL, headers, postData, bodyType string) (attackVector, []string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return attackVector{}, nil, false
	}
	domain, port := splitHostPort(u)
	rawPath := u.EscapedPath()
	if rawPath == "" {
		rawPath = "/"
	}
	// The path is TEMPLATED before it becomes an identity. /users/user.dedc6ad0-... and
	// /users/user.ea064fd5-... are one vector seen with two account ids, not two vectors, and
	// keeping them apart would put a row in the list for every object the operator happened to
	// open while browsing.
	path, pathSignals := templateVectorPath(rawPath)

	return attackVector{
		Method: method, MethodConfidence: "observed",
		Scheme: u.Scheme, Domain: domain, Port: port, Path: path,
		InsertionConfidence: "observed", ParametersOrigin: "observed",
		Sources: []string{"manual_crawl"}, EvidenceURL: rawURL,
		// The request bytes as captured. toInput reads the body, the content type and the real
		// cookie and header VALUES back out of this, so a vector without it is tested with an
		// empty body and a canary in place of every token.
		RawRequest: buildRawRequest(method, rawURL, headers, postData, bodyType),
	}, pathSignals, true
}

// buildRawRequest reconstructs the request bytes from a manual-crawl capture.
//
// This is the single input behind three things the runner reads back out of raw_request in
// vectorRow.toInput: VectorInput.Body, VectorInput.ContentType, and the OBSERVED VALUES of cookies
// and headers. Without it:
//
//   - every body vector is handed an empty body, so dalfox posted nothing at all and sqlmap and
//     ghauri fell back to a synthesised name=rs0n pair. All 10 body vectors on ginandjuice.shop
//     were in that state, including POST /catalog/product/stock, whose XML body is the one
//     plausible route to XXE on the target.
//   - every cookie vector loses its real token and gets the canary instead, so a scanner tests
//     TrackingId=rs0n against an application that base64-decodes that value and gives up long
//     before the payload reaches a query.
//
// The capture already holds all of it: post_data is stored untruncated alongside the headers.
// Nothing was missing except the code to assemble it, because RawRequest was only ever set by the
// fuzz source.
//
// The shape is exactly what rawRequestBody and observedRequestValues parse: a request line, one
// header per line, a blank line, then the body. Header order is sorted so the same capture always
// produces the same bytes, which matters because the upsert compares them.
func buildRawRequest(method, rawURL, headersJSON, postData, bodyType string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}

	headers := map[string]string{}
	if headersJSON != "" {
		var decoded map[string]any
		if json.Unmarshal([]byte(headersJSON), &decoded) == nil {
			for name, value := range decoded {
				name = strings.TrimSpace(name)
				// HTTP/2 pseudo-headers are not headers on the wire and would be parsed as a header
				// named ":method". Content-Length is dropped because every tool recomputes it and a
				// stale one makes the request unparseable.
				if name == "" || strings.HasPrefix(name, ":") ||
					strings.EqualFold(name, "content-length") ||
					strings.EqualFold(name, "host") {
					continue
				}
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					headers[name] = strings.TrimSpace(text)
				}
			}
		}
	}
	// A recorded body with no recorded content type is unparseable by the receiver, so the capture's
	// own body_type stands in. It is only ever a fallback: a real Content-Type header wins.
	if strings.TrimSpace(bodyType) != "" {
		hasCT := false
		for name := range headers {
			if strings.EqualFold(name, "content-type") {
				hasCT = true
				break
			}
		}
		if !hasCT {
			headers["Content-Type"] = strings.TrimSpace(bodyType)
		}
	}

	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(strings.ToUpper(method) + " " + target + " HTTP/1.1\n")
	b.WriteString("Host: " + u.Host + "\n")
	for _, name := range names {
		b.WriteString(name + ": " + headers[name] + "\n")
	}
	b.WriteString("\n")
	b.WriteString(postData)
	return b.String()
}
