package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Reading, adding, editing and deleting attack vectors.
//
// Consolidation builds vectors from what the tools found; this is where the operator disagrees with
// it. A list nobody can correct is a list nobody trusts, so an edited or deleted vector is never
// silently rebuilt by the next consolidation.

// GetAttackVectorSummary answers GET /attack-vectors/{scope_target_id}/summary. The card reads it.
func GetAttackVectorSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	total, hosts, manual, withNotes := attackVectorTotals(context.Background(), mux.Vars(r)["scope_target_id"])
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": total, "hosts": hosts, "manual": manual, "with_notes": withNotes,
	})
}

// GetAttackVectorCoverage answers GET /attack-vectors/{scope_target_id}/coverage: how many vectors
// exist at each insertion point. Six of them: the five that are SENT, and the fragment, which is
// not.
//
// WHY A ZERO HERE IS THE MOST IMPORTANT NUMBER ON THE PAGE. Every scan is bounded by this list. If
// there are no header vectors then every tool will report nothing wrong with headers, not because
// headers are safe but because nothing was ever sent to one, and the results modal will say "clean"
// in exactly the same words it uses for a genuine negative.
//
// This is not hypothetical. On the target this framework was developed against the list held zero
// header vectors and zero path vectors, so every report about headers and paths was accurate and
// completely misleading.
//
// AND A NON-ZERO COUNT IS NOT COVERAGE EITHER, which is the subtler half. That same target had 19
// cookie vectors, which looks healthy. Every one of them was a cookie the BROWSER was carrying,
// because that is all a crawl can observe. The cookie that mattered was the one the SERVER set from
// the category parameter, mirrored back byte for byte, on the one input with confirmed SQL injection.
// A second injection carrier sat one insertion point away, the count said 19, and nothing tested it.
//
// The structural cause is recorded here rather than left for the reader to rediscover:
// vectorsFromEndpoints CANNOT produce header, cookie or path vectors at all, because consolidation
// only ever writes param_type 'query' or 'body'. So on any target whose vectors come mostly from
// endpoint discovery, three of the five points are empty by construction.
func GetAttackVectorCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	counts := map[string]int{}
	for _, point := range VectorInsertionPoints {
		counts[point] = 0
	}
	rows, err := dbPool.Query(context.Background(), `
		SELECT insertion_point, count(*)
		FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		GROUP BY insertion_point`, scopeTargetID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var point string
			var n int
			if rows.Scan(&point, &n) == nil {
				counts[point] = n
			}
		}
	}

	// The gaps are named explicitly rather than left as zeroes for a caller to notice. A number a
	// reader has to interpret is a number a reader skips.
	gaps := []map[string]string{}
	for _, point := range VectorInsertionPoints {
		if counts[point] > 0 {
			continue
		}
		gaps = append(gaps, map[string]string{
			"insertion_point": point,
			"consequence":     insertionPointGapConsequence(point),
			"why":             insertionPointGapReason(point),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"by_insertion_point": counts,
		"gaps":               gaps,
		"points":             VectorInsertionPoints,
	})
}

// insertionPointGapConsequence says what an empty count at this point actually costs.
//
// It is per point because it was not, and the one generic sentence ended up arguing with the `why`
// beside it in the same JSON object. The generic text says every tool in every section reports
// nothing wrong, which is true of the five points that are SENT and false of the fragment: only
// domdig can ever test one, and an application using history routing genuinely has none, so zero
// there is the correct count rather than missing coverage. A reader handed both sentences at once
// learns only that the framework does not know.
func insertionPointGapConsequence(point string) string {
	if point == "fragment" {
		return "No fragment vectors exist. A fragment never leaves the browser, so this is not a " +
			"gap the other sections share: domdig is the only tool that can test one, and only " +
			"where a fragment was actually observed. On an application that uses history routing " +
			"rather than hash routing, and whose captured URLs carry no hash, zero is the correct " +
			"count and not a hole in coverage."
	}
	return "No " + point + " vectors exist, so every tool in every section will report nothing " +
		"wrong with " + point + " input on this target. That is a gap in coverage, not a clean " +
		"result."
}

// insertionPointGapReason explains why a point is usually empty, in terms of how this framework
// discovers vectors rather than in terms of the target.
func insertionPointGapReason(point string) string {
	switch point {
	case "header":
		return "Header vectors only come from a manual crawl, and a browser sends an unremarkable " +
			"set of headers, so a crawl rarely produces one. Endpoint discovery cannot produce them " +
			"at all. Add them by hand on endpoints that log, cache, or build URLs from a header."
	case "cookie":
		return "Cookie vectors come only from a manual crawl. Endpoint discovery cannot produce " +
			"them. Look for any response cookie whose value echoes a request parameter: that is the " +
			"same input arriving by a second route that nothing has tested."
	case "path":
		return "Path vectors need a segment that was observed varying. Add them by hand on routes " +
			"that end in an identifier, a filename or a template name."
	case "fragment":
		return "Fragment vectors are only produced where a fragment was actually observed: a " +
			"captured URL carrying one, or a client route consolidation recognised. A fragment " +
			"never reaches the server, so no crawler, archive or parameter miner can find one, and " +
			"an application using history routing rather than hash routing genuinely has none. " +
			"Zero here is usually the truth rather than a gap. Where it is not, the fragment is " +
			"where DOM XSS lives and domdig is the only tool that can test it."
	case "body":
		return "Body vectors come from requests that were actually submitted. A form nobody " +
			"submitted during the crawl produces none, and neither does a widget that posts JSON " +
			"without being a form element."
	default:
		return "Query vectors are the easiest to discover, so an empty count here usually means " +
			"consolidation has not been run rather than that the target has no query parameters."
	}
}

// attackVectorListFilters turns the list query string into a WHERE clause and its bind values.
//
// PULLED OUT OF THE HANDLER BECAUSE THAT IS WHERE THE BUG COULD HIDE. The search filter bound one
// value and wrote THREE %d verbs, so Sprintf produced
// `path ILIKE '%'||$5||'%' OR domain ILIKE '%'||%!d(MISSING)`, and every list call carrying search
// alongside any other filter answered 500 with `syntax error at or near "$"`. It then "repaired" the
// numbering with a strings.Replace whose old and new arguments were built by identical Sprintf
// calls, so it replaced the text with itself and did nothing at all.
//
// Measured on the Juice Shop target on 2026-08-21: insertion_point=path&search=/ returned 500. None
// of this was reachable from a test while it lived inline in an http.HandlerFunc that needs a live
// Postgres, which is the reason it survived.
func attackVectorListFilters(scopeTargetID string, q url.Values) (string, []interface{}) {
	where := "scope_target_id = $1"
	args := []interface{}{scopeTargetID}
	if q.Get("deleted") == "true" {
		where += " AND deleted_at IS NOT NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	// add binds ONE value and fills ONE placeholder. A clause carrying more than one %d silently
	// becomes malformed SQL, because Sprintf writes %!d(MISSING) for every verb past the first
	// argument. TestAttackVectorFiltersNeverEmitAMalformedPlaceholder is what keeps that true.
	add := func(clause string, value interface{}) {
		args = append(args, value)
		where += fmt.Sprintf(clause, len(args))
	}
	if v := strings.TrimSpace(q.Get("insertion_point")); v != "" {
		add(" AND insertion_point = $%d", v)
	}
	if v := strings.TrimSpace(q.Get("method")); v != "" {
		add(" AND method = $%d", strings.ToUpper(v))
	}
	if v := strings.TrimSpace(q.Get("domain")); v != "" {
		add(" AND domain = $%d", strings.ToLower(v))
	}
	if v := strings.TrimSpace(q.Get("source")); v != "" {
		add(" AND $%d = ANY(sources)", v)
	}
	if v := strings.TrimSpace(q.Get("search")); v != "" {
		// One value, three columns, ONE placeholder referenced three times. Postgres allows reusing
		// $n, so there is nothing to renumber and nothing to repair afterwards.
		args = append(args, v)
		n := len(args)
		where += fmt.Sprintf(
			" AND (path ILIKE '%%'||$%d||'%%' OR domain ILIKE '%%'||$%d||'%%'"+
				" OR array_to_string(parameters,',') ILIKE '%%'||$%d||'%%')", n, n, n)
	}
	return where, args
}

// GetAttackVectors answers GET /attack-vectors/{scope_target_id}.
func GetAttackVectors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()
	q := r.URL.Query()

	where, args := attackVectorListFilters(scopeTargetID, q)

	rows, err := dbPool.Query(ctx, `
		SELECT id::text, method, method_confidence, scheme, domain, port, path, insertion_point,
		       insertion_confidence, parameters, parameters_origin, sources,
		       COALESCE(evidence_url,''), COALESCE(raw_request,''), COALESCE(notes,''),
		       manual_added, edited_at, first_seen, last_seen, times_seen,
		       COALESCE(fragment,''),
		       COALESCE(reflection_status,''),
		       COALESCE((SELECT p.content_type FROM vector_reflection_probes p
		                 WHERE p.vector_id = attack_vectors.id AND p.status = attack_vectors.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ''),
		       COALESCE((SELECT p.survived FROM vector_reflection_probes p
		                 WHERE p.vector_id = attack_vectors.id AND p.status = attack_vectors.reflection_status
		                 ORDER BY p.probed_at DESC LIMIT 1), ARRAY[]::text[])
		FROM attack_vectors WHERE `+where+`
		ORDER BY domain, path, method, insertion_point`, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	type vector struct {
		ID               string `json:"id"`
		Method           string `json:"method"`
		MethodConfidence string `json:"method_confidence"`
		Scheme           string `json:"scheme"`
		Domain           string `json:"domain"`
		Port             *int   `json:"port,omitempty"`
		Path             string `json:"path"`
		Fragment         string `json:"fragment,omitempty"`
		// The reflection probe's verdict and the grade derived from it. reflection_grade is computed
		// HERE rather than by each client, because the client and the MCP layer had already drifted
		// apart on the content type rule: XML graded high on screen and low in the filter.
		ReflectionStatus      string     `json:"reflection_status,omitempty"`
		ReflectionContentType string     `json:"reflection_content_type,omitempty"`
		ReflectionSurvived    []string   `json:"reflection_survived,omitempty"`
		ReflectionGrade       string     `json:"reflection_grade,omitempty"`
		InsertionPoint        string     `json:"insertion_point"`
		InsertionConfidence   string     `json:"insertion_confidence"`
		Parameters            []string   `json:"parameters"`
		ParametersOrigin      string     `json:"parameters_origin"`
		Sources               []string   `json:"sources"`
		EvidenceURL           string     `json:"evidence_url,omitempty"`
		RawRequest            string     `json:"raw_request,omitempty"`
		Notes                 string     `json:"notes,omitempty"`
		ManualAdded           bool       `json:"manual_added"`
		EditedAt              *time.Time `json:"edited_at,omitempty"`
		FirstSeen             time.Time  `json:"first_seen"`
		LastSeen              time.Time  `json:"last_seen"`
		TimesSeen             int        `json:"times_seen"`
		// The probe's own rows for this vector, one per input.
		//
		// IT WAS ALREADY BEING RENDERED AND NEVER SENT. AttackVectorsModal has drawn a per-input
		// table off vector.reflection_probes since the probe shipped, and nothing ever populated
		// the field, so the table has never once appeared: every vector showed only the rolled-up
		// badge, and a roll-up hides the useful half. A vector with five parameters where exactly
		// one reflects is a vector with one thing to test, and the detail saying WHY an input was
		// not measured only exists down here.
		ReflectionProbes []reflectionProbeRow `json:"reflection_probes,omitempty"`
	}
	out := []vector{}
	for rows.Next() {
		var v vector
		if rows.Scan(&v.ID, &v.Method, &v.MethodConfidence, &v.Scheme, &v.Domain, &v.Port, &v.Path,
			&v.InsertionPoint, &v.InsertionConfidence, &v.Parameters, &v.ParametersOrigin,
			&v.Sources, &v.EvidenceURL, &v.RawRequest, &v.Notes, &v.ManualAdded, &v.EditedAt,
			&v.FirstSeen, &v.LastSeen, &v.TimesSeen, &v.Fragment,
			&v.ReflectionStatus, &v.ReflectionContentType, &v.ReflectionSurvived) == nil {
			v.ReflectionGrade = XSSCandidateGrade(v.ReflectionStatus, v.ReflectionContentType, v.ReflectionSurvived,
				v.InsertionPoint)
			out = append(out, v)
		}
	}

	// ONE query for every vector on the page rather than one per vector: a two hundred vector list
	// would otherwise be two hundred round trips to draw a table.
	if probes := loadReflectionProbeRows(ctx, scopeTargetID); len(probes) > 0 {
		for i := range out {
			out[i].ReflectionProbes = probes[out[i].ID]
		}
	}

	total, hosts, manual, withNotes := attackVectorTotals(ctx, scopeTargetID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"vectors": out, "returned": len(out),
		"total": total, "hosts": hosts, "manual": manual, "with_notes": withNotes,
		"insertion_points": attackVectorInsertionPoints,
		"note": "method_confidence 'implied' means no tool observed the verb and GET was assumed. " +
			"parameters_origin 'union' means the parameter set is every name ever seen on that " +
			"endpoint rather than a combination observed in one request. insertion_confidence " +
			"'implied' means the tool derived the place from the verb instead of measuring it.",
	})
}

// reflectionProbeRow is one input's stored verdict, as the vector list hands it to the UI.
type reflectionProbeRow struct {
	Parameter      string `json:"parameter"`
	InsertionPoint string `json:"insertion_point"`
	Status         string `json:"status"`
	// Grade is the SERVER'S verdict for this one input, and it is on the row because without it
	// the client had to derive one. It derived it from status and content type alone, because
	// those were the only two fields this payload carried, so every raw reflection into an HTML or
	// empty content type rendered XSS High: the two fail-loud defaults for an absent survived list
	// and an absent insertion point both said yes. The results panel one tab over showed the
	// server's grade for the same input, so the same row read High here and Needs a Chain there.
	// Go is the authority on the grade and there is now only one derivation of it.
	Grade       string   `json:"grade"`
	Survived    []string `json:"survived"`
	ContentType string   `json:"content_type,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	// Detail is WHY, in the row, which is where a reason belongs. A refusal, a block, a dead
	// credential and a passive echo each have something to say about one input, and saying it on
	// the card instead turns a card into a paragraph.
	Detail string `json:"detail,omitempty"`
	// EvidenceSource is "active" (a canary was sent) or "passive" (a value the crawl already sent
	// was found in the response the crawl already stored). The row means a different thing in each
	// case, so the table shows it rather than leaving the reader to infer it from the status.
	EvidenceSource string `json:"evidence_source,omitempty"`
}

// withGrade fills Grade from the four fields that belong together, derived on read and never
// stored, exactly as the results endpoint does it. Any row leaving this file goes through here.
func (p reflectionProbeRow) withGrade() reflectionProbeRow {
	p.Grade = XSSCandidateGrade(p.Status, p.ContentType, p.Survived, p.InsertionPoint)
	return p
}

// loadReflectionProbeRows returns every stored probe row for a target, grouped by vector.
func loadReflectionProbeRows(ctx context.Context, scopeTargetID string) map[string][]reflectionProbeRow {
	rows, err := dbPool.Query(ctx, `
		SELECT vector_id::text, COALESCE(parameter,''), COALESCE(insertion_point,''), status,
		       COALESCE(survived, ARRAY[]::text[]), COALESCE(content_type,''), http_status,
		       COALESCE(evidence,''), COALESCE(detail,''), COALESCE(evidence_source,'active')
		FROM vector_reflection_probes
		WHERE scope_target_id = $1
		ORDER BY vector_id, parameter`, scopeTargetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string][]reflectionProbeRow{}
	for rows.Next() {
		var vectorID string
		var p reflectionProbeRow
		if rows.Scan(&vectorID, &p.Parameter, &p.InsertionPoint, &p.Status, &p.Survived,
			&p.ContentType, &p.HTTPStatus, &p.Evidence, &p.Detail, &p.EvidenceSource) != nil {
			continue
		}
		out[vectorID] = append(out[vectorID], p.withGrade())
	}
	return out
}

type attackVectorRequest struct {
	Method         string   `json:"method"`
	URL            string   `json:"url"`
	Scheme         string   `json:"scheme"`
	Domain         string   `json:"domain"`
	Port           int      `json:"port"`
	Path           string   `json:"path"`
	InsertionPoint string   `json:"insertion_point"`
	Parameters     []string `json:"parameters"`
	Notes          string   `json:"notes"`
	RawRequest     string   `json:"raw_request"`
	// Fragment is the hash, with or without its leading "#", for a fragment vector whose URL is not
	// being pasted whole. The edit form has no URL box at all, so without this field the insertion
	// point could be SET to fragment and the fragment itself could never be supplied.
	Fragment string `json:"fragment"`
}

// CreateAttackVector answers POST /attack-vectors/{scope_target_id}.
//
// Takes either a filled-in form or a RAW HTTP REQUEST pasted whole. The raw path exists because that
// is what an operator has in front of them: a request copied out of a proxy. Parsing it here means
// they do not have to take it apart by hand into a verb, a host, a path and a parameter list, and
// that the vector matches the request rather than their transcription of it.
func CreateAttackVector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	var req attackVectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	candidates, errs := attackVectorsFromRequest(req)
	if len(errs) > 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_vector", strings.Join(errs, " "))
		return
	}

	added, existing := 0, 0
	for _, v := range candidates {
		v.ManualAdded = true
		v.Sources = []string{"manual"}
		v.Notes = req.Notes
		ins, err := upsertAttackVector(ctx, scopeTargetID, v)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if ins {
			added++
		} else {
			existing++
		}
		// A vector added by hand is the operator's, even where consolidation found it first.
		_, _ = dbPool.Exec(ctx, `
			UPDATE attack_vectors SET manual_added = TRUE, deleted_at = NULL,
			    notes = COALESCE(NULLIF($3,''), notes)
			WHERE scope_target_id = $1 AND vector_key = $2`, scopeTargetID, v.key(), req.Notes)
		// Adding it back by hand is an explicit reversal of having edited it away.
		_, _ = dbPool.Exec(ctx, `
			UPDATE attack_vectors SET superseded_keys = array_remove(superseded_keys, $2)
			WHERE scope_target_id = $1`, scopeTargetID, v.key())
	}

	total, hosts, manual, withNotes := attackVectorTotals(ctx, scopeTargetID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"added": added, "already_present": existing, "vectors": len(candidates),
		"total": total, "hosts": hosts, "manual": manual, "with_notes": withNotes,
		"summary": fmt.Sprintf("%d vector(s) added, %d already present.", added, existing),
	})
}

// attackVectorsFromRequest turns one submission into the vectors it describes.
//
// A raw request can describe MORE THAN ONE vector, and silently picking one would be wrong: a POST
// carrying both a query string and a body has a payload insertion point in each, and they are
// different vectors by the operator's own definition. So every container that actually holds
// parameters becomes its own vector unless the caller named one explicitly.
func attackVectorsFromRequest(req attackVectorRequest) ([]attackVector, []string) {
	var errs []string

	if strings.TrimSpace(req.RawRequest) != "" {
		parsed, perrs := parseRawAttackRequest(req.RawRequest)
		if len(perrs) > 0 {
			return nil, perrs
		}
		// An explicit insertion point narrows the parse rather than contradicting it.
		if point := normaliseInsertionPoint(req.InsertionPoint); point != "" {
			kept := parsed[:0]
			for _, v := range parsed {
				if v.InsertionPoint == point {
					kept = append(kept, v)
				}
			}
			if len(kept) == 0 {
				return nil, []string{fmt.Sprintf(
					"The request carries no parameters in the %s, so there is no vector to add there. "+
						"Leave the insertion point empty to add every one the request does carry.", point)}
			}
			parsed = kept
		}
		if len(req.Parameters) > 0 {
			for i := range parsed {
				parsed[i].Parameters = req.Parameters
			}
		}
		return parsed, nil
	}

	// The structured form.
	v := attackVector{
		Method: strings.ToUpper(strings.TrimSpace(req.Method)), MethodConfidence: "observed",
		Scheme: req.Scheme, Domain: strings.ToLower(strings.TrimSpace(req.Domain)),
		Port: req.Port, Path: req.Path, InsertionConfidence: "observed",
		ParametersOrigin: "observed", Parameters: req.Parameters,
	}
	// The point the operator actually asked for, resolved BEFORE the URL is taken apart, because
	// the two branches below have to know whether this row is going to be a fragment vector. It is
	// applied again at the end: this is the same value, read early, not a second decision.
	wantedPoint := normaliseInsertionPoint(req.InsertionPoint)
	if u := strings.TrimSpace(req.URL); u != "" {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			errs = append(errs, "That URL could not be parsed. It needs a scheme and a host, e.g. https://host/path.")
		} else {
			v.Scheme = parsed.Scheme
			v.Domain, v.Port = splitHostPort(parsed)
			v.Path = parsed.EscapedPath()
			if v.Path == "" {
				v.Path = "/"
			}
			// A query string in the URL names the parameters, so the operator does not have to twice.
			//
			// Not when the operator explicitly asked for the fragment. The names in a query string
			// are QUERY names, and lending them to a fragment vector composes a hash out of inputs
			// no client-side script reads, then files whatever comes back against a fragment nobody
			// observed. It also slips past fragmentVectorError, whose only test for "this fragment
			// vector has something in it" is a non-empty fragment OR a parameter: measured, POSTing
			// https://h.example.com/x?a=1 with insertion_point=fragment was ACCEPTED as
			// fragment="" parameters=[a] and composed #a=rs0n. This is the create-side twin of the
			// rule fragmentUpdateError already applies to an edit.
			if len(v.Parameters) == 0 && parsed.RawQuery != "" && wantedPoint != "fragment" {
				v.Parameters = queryKeys(parsed.RawQuery)
				if req.InsertionPoint == "" {
					v.InsertionPoint = "query"
				}
			}
			// A hash in the pasted URL is read the same way, and it WINS over the query string when
			// the operator named no insertion point. Someone who types a URL with a fragment on it
			// meant the fragment: the query string is usually just the rest of the address they
			// copied, and defaulting to query would silently file the row under a point no DOM sink
			// is reachable from.
			if fragment := parsed.EscapedFragment(); fragment != "" {
				if parts, ok := parseFragment(fragment); ok {
					v.Fragment = parts.Route
					if req.InsertionPoint == "" {
						v.InsertionPoint = "fragment"
					}
					// The fragment's own names are adopted whenever the row IS a fragment vector,
					// not only when the operator left the point blank. Pasting
					// #/connect/edit?token=abc and then picking `fragment` from the select used to
					// drop the token and compose the bare route, which is the same silent loss of
					// the payload slot that D1 was, one layer up.
					if (req.InsertionPoint == "" || wantedPoint == "fragment") && len(req.Parameters) == 0 {
						v.Parameters = parts.Names
						v.Signals = parts.Signals
					}
				}
			}
		}
	}
	// A fragment typed into its own field, rather than pasted on the end of a URL. Same parser, so
	// #/connect/edit?tab=x typed by hand becomes the same row as the same string pasted on a URL.
	if raw := strings.TrimSpace(req.Fragment); raw != "" {
		if parts, ok := parseFragment(raw); ok {
			v.Fragment = parts.Route
			if len(parts.Names) > 0 && len(req.Parameters) == 0 {
				v.Parameters = parts.Names
				v.Signals = parts.Signals
			}
			if req.InsertionPoint == "" {
				v.InsertionPoint = "fragment"
			}
		}
	}
	if point := normaliseInsertionPoint(req.InsertionPoint); point != "" {
		v.InsertionPoint = point
	}

	if v.Method == "" {
		v.Method = "GET"
	}
	if v.Scheme == "" {
		v.Scheme = "https"
	}
	if v.Path == "" {
		v.Path = "/"
	}
	if v.Domain == "" {
		errs = append(errs, "A vector needs a host. Give a full URL, or fill in the domain.")
	}
	if v.InsertionPoint == "" {
		errs = append(errs, "A vector needs an insertion point: query, body, header, cookie, path "+
			"or fragment.")
	}
	// The fragment joins the path as a point whose value is not a named parameter. A bare client
	// route or a scroll anchor, #/billing or #preferences, is one opaque slot and has no names in it
	// at all, so requiring one would refuse the most common fragment there is.
	if len(v.Parameters) == 0 && v.InsertionPoint != "path" && v.InsertionPoint != "fragment" {
		errs = append(errs, "A vector needs at least one parameter name, unless the insertion point "+
			"is the path or the fragment itself.")
	}
	if msg := fragmentVectorError(v.InsertionPoint, v.Fragment, v.Parameters); msg != "" {
		errs = append(errs, msg)
	}
	return []attackVector{v}, errs
}

// parseRawAttackRequest reads a pasted HTTP request into the vectors it contains.
func parseRawAttackRequest(raw string) ([]attackVector, []string) {
	text := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, []string{"That does not look like an HTTP request: the first line is empty."}
	}

	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return nil, []string{"The first line is not a request line. It should read like: " +
			"POST /path?a=1 HTTP/1.1"}
	}
	method := strings.ToUpper(fields[0])
	target := fields[1]

	if strings.Contains(target, "://") {
		return nil, []string{"The request line names an absolute URL. Write the path only and put " +
			"the host in a Host header, which is what decides where the request goes."}
	}

	host := HostFromRawRequest(text)
	if host == "" {
		return nil, []string{"There is no Host header, so there is no way to know which host this " +
			"request is for."}
	}

	port := 0
	scheme := "https"
	for _, line := range lines[1:] {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "host") {
			if _, p, found := strings.Cut(strings.TrimSpace(value), ":"); found {
				if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
					if n == 80 {
						scheme = "http"
					} else if n != 443 {
						port = n
					}
				}
			}
		}
	}

	path, query, _ := strings.Cut(target, "?")
	if path == "" {
		path = "/"
	}

	base := attackVector{
		Method: method, MethodConfidence: "observed", Scheme: scheme, Domain: host, Port: port,
		Path: path, InsertionConfidence: "observed", ParametersOrigin: "observed",
		RawRequest: raw,
	}

	var out []attackVector
	if keys := queryKeys(query); len(keys) > 0 {
		v := base
		v.InsertionPoint = "query"
		v.Parameters = keys
		out = append(out, v)
	}
	if keys := bodyKeys(body, headerValue(lines, "content-type")); len(keys) > 0 {
		v := base
		v.InsertionPoint = "body"
		v.Parameters = keys
		out = append(out, v)
	}
	if keys := cookieKeys(headerValue(lines, "cookie")); len(keys) > 0 {
		v := base
		v.InsertionPoint = "cookie"
		v.Parameters = keys
		out = append(out, v)
	}

	if len(out) == 0 {
		return nil, []string{"That request carries no parameters in its query string, body or " +
			"cookies, so there is no user-controlled input to test. Add one, or add the vector with " +
			"the path as the insertion point if the path segment itself is the input."}
	}
	return out, nil
}

func headerValue(lines []string, want string) string {
	for _, line := range lines {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), want) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func queryKeys(rawQuery string) []string {
	if strings.TrimSpace(rawQuery) == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, pair := range strings.Split(rawQuery, "&") {
		key, _, _ := strings.Cut(pair, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if key = strings.TrimSpace(key); key != "" {
			seen[key] = true
		}
	}
	return attackVectorSetKeys(seen)
}

// bodyKeys reads parameter names out of a JSON or form-encoded body. Nested JSON contributes its
// top-level keys only, which is the same thing the manual crawl capture stores.
func bodyKeys(body, contentType string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(body, "{") {
		return jsonObjectKeys(body)
	}
	return queryKeys(body)
}

func cookieKeys(cookie string) []string {
	if strings.TrimSpace(cookie) == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, pair := range strings.Split(cookie, ";") {
		key, _, _ := strings.Cut(pair, "=")
		if key = strings.TrimSpace(key); key != "" {
			seen[key] = true
		}
	}
	return attackVectorSetKeys(seen)
}

func attackVectorSetKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// UpdateAttackVector answers PUT /attack-vectors/item/{id}.
//
// Editing anything in the identity re-keys the row, because the key IS the identity: a vector whose
// parameters changed is a different vector, and leaving the old key would make it un-findable and
// let consolidation insert a duplicate beside it.
func UpdateAttackVector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]
	ctx := context.Background()

	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "That is not a vector id.")
		return
	}

	var req attackVectorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	var cur attackVector
	var scopeTargetID string
	if dbPool.QueryRow(ctx, `
		SELECT scope_target_id::text, method, scheme, domain, COALESCE(port,0), path,
		       insertion_point, parameters, COALESCE(fragment,'')
		FROM attack_vectors WHERE id = $1`, id).
		Scan(&scopeTargetID, &cur.Method, &cur.Scheme, &cur.Domain, &cur.Port, &cur.Path,
			&cur.InsertionPoint, &cur.Parameters, &cur.Fragment) != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "No such attack vector.")
		return
	}

	if v := strings.TrimSpace(req.Method); v != "" {
		cur.Method = strings.ToUpper(v)
	}
	if v := strings.TrimSpace(req.Domain); v != "" {
		cur.Domain = strings.ToLower(v)
	}
	if v := strings.TrimSpace(req.Path); v != "" {
		cur.Path = v
	}
	if v := strings.TrimSpace(req.Scheme); v != "" {
		cur.Scheme = v
	}
	wasPoint := cur.InsertionPoint
	if point := normaliseInsertionPoint(req.InsertionPoint); point != "" {
		cur.InsertionPoint = point
	}
	// A fragment supplied with the edit, read through the same parser as the create path, so a route
	// carrying its own query arrives as a route plus its names rather than as one opaque string.
	fragmentGiven := false
	if raw := strings.TrimSpace(req.Fragment); raw != "" {
		if parts, ok := parseFragment(raw); ok {
			fragmentGiven = true
			cur.Fragment = parts.Route
			// The names come off the fragment only when the row IS a fragment vector after this
			// edit. Without that test, `manage_attack_vectors update` carrying a fragment but no
			// insertion_point and no parameters replaces a QUERY vector's parameter names with the
			// fragment's, re-keys the row, and pushes its real key into superseded_keys, which
			// permanently blocks consolidation from ever re-creating it. The hash itself is
			// discarded a few lines down for exactly this reason; the names have to go with it.
			// The UI never hit this because it sends '' for every non-fragment point.
			if len(parts.Names) > 0 && req.Parameters == nil && cur.InsertionPoint == "fragment" {
				cur.Parameters = parts.Names
			}
		}
	}
	// Only a fragment vector carries a fragment. An operator moving a row to another point is saying
	// the payload goes somewhere that IS sent, and leaving the old hash on it would keep it in the
	// identity of a vector that no longer has one.
	if cur.InsertionPoint != "fragment" {
		cur.Fragment = ""
	}
	if req.Parameters != nil {
		cur.Parameters = req.Parameters
	}
	// THE GUARD THE CREATE PATH HAD AND THIS ONE DID NOT. Without it, switching a query vector to
	// fragment stored insertion_point='fragment' with fragment='', TargetURL composed the ordinary
	// query URL, domdig scanned it, and the clean result was filed against a fragment that never
	// existed. The edit form now has a fragment field, so the answer to a switch with no fragment is
	// to refuse it rather than to store an empty one.
	if msg := fragmentUpdateError(cur.InsertionPoint, wasPoint, cur.Fragment, cur.Parameters,
		fragmentGiven); msg != "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_vector", msg)
		return
	}
	// fragment is exempt for the same reason path is: its value is not a named parameter. cur.Fragment
	// was loaded above and is carried through untouched, which it has to be. key() folds the fragment
	// in, so an edit that read the row without it would recompute a DIFFERENT key for a vector nobody
	// changed, record the real one in superseded_keys, and permanently block consolidation from
	// re-creating it.
	if len(cur.Parameters) == 0 && cur.InsertionPoint != "path" && cur.InsertionPoint != "fragment" {
		writeJSONError(w, http.StatusBadRequest, "invalid_vector",
			"A vector needs at least one parameter name unless its insertion point is the path "+
				"or the fragment.")
		return
	}

	params := append([]string(nil), cur.Parameters...)
	sort.Strings(params)
	if _, err := dbPool.Exec(ctx, `
		UPDATE attack_vectors
		SET method = $2, scheme = $3, domain = $4, path = $5, insertion_point = $6,
		    parameters = $7, vector_key = $8, notes = COALESCE(NULLIF($9,''), notes),
		    fragment = $10,
		    edited_at = NOW(),
		    -- Remember the identity this row is moving away from, so consolidation does not put the
		    -- uncorrected version back the next time it runs.
		    superseded_keys = CASE WHEN vector_key = $8 THEN superseded_keys
		        ELSE array_append(superseded_keys, vector_key) END,
		    -- The operator has now said what this is, so nothing about it is assumed any more.
		    method_confidence = 'observed', parameters_origin = 'observed',
		    insertion_confidence = 'observed'
		WHERE id = $1`,
		id, cur.Method, cur.Scheme, cur.Domain, cur.Path, cur.InsertionPoint, params,
		cur.key(), req.Notes, cur.Fragment); err != nil {
		// The only way this collides is an edit onto a vector that already exists, which is a merge
		// rather than an error worth a stack trace.
		writeJSONError(w, http.StatusConflict, "already_exists",
			"Those changes make this the same vector as one already in the list.")
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": true, "id": id})
}

// DeleteAttackVector answers DELETE /attack-vectors/item/{id}.
//
// Soft, and consolidation does not bring it back. An operator who deletes a vector has made a
// judgement, and a list that undoes it on the next run is a list they stop curating.
func DeleteAttackVector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "That is not a vector id.")
		return
	}
	restore := r.URL.Query().Get("restore") == "true"
	clause := "deleted_at = NOW()"
	if restore {
		clause = "deleted_at = NULL"
	}
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE attack_vectors SET `+clause+` WHERE id = $1`, id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": !restore, "restored": restore})
}

// SetAttackVectorNotes answers PUT /attack-vectors/item/{id}/notes.
//
// Separate from the edit endpoint on purpose. Editing a vector is a claim about what the request IS,
// and it re-keys the row and marks every assumed field as now known. Writing a note is neither: it
// records what the operator thinks about a vector without asserting that anybody observed its verb.
// Folding the two together would quietly launder a guess into a fact every time somebody typed a
// reminder to themselves.
func SetAttackVectorNotes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "That is not a vector id.")
		return
	}

	var req struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	tag, err := dbPool.Exec(context.Background(),
		`UPDATE attack_vectors SET notes = NULLIF($2,'') WHERE id = $1`,
		id, strings.TrimSpace(req.Notes))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "not_found", "No such attack vector.")
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"saved": true, "notes": req.Notes})
}
