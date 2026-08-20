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

// GetAttackVectors answers GET /attack-vectors/{scope_target_id}.
func GetAttackVectors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()
	q := r.URL.Query()

	where := "scope_target_id = $1"
	args := []interface{}{scopeTargetID}
	if q.Get("deleted") == "true" {
		where += " AND deleted_at IS NOT NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
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
		add(" AND (path ILIKE '%%'||$%d||'%%' OR domain ILIKE '%%'||$%d||'%%' "+
			"OR array_to_string(parameters,',') ILIKE '%%'||$%d||'%%')", v)
		// One value, three placeholders: repeat it so the numbering stays right.
		args = append(args, v, v)
		where = strings.Replace(where, fmt.Sprintf("$%d||'%%' OR domain", len(args)-2),
			fmt.Sprintf("$%d||'%%' OR domain", len(args)-2), 1)
	}

	rows, err := dbPool.Query(ctx, `
		SELECT id::text, method, method_confidence, scheme, domain, port, path, insertion_point,
		       insertion_confidence, parameters, parameters_origin, sources,
		       COALESCE(evidence_url,''), COALESCE(raw_request,''), COALESCE(notes,''),
		       manual_added, edited_at, first_seen, last_seen, times_seen
		FROM attack_vectors WHERE `+where+`
		ORDER BY domain, path, method, insertion_point`, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	type vector struct {
		ID                  string     `json:"id"`
		Method              string     `json:"method"`
		MethodConfidence    string     `json:"method_confidence"`
		Scheme              string     `json:"scheme"`
		Domain              string     `json:"domain"`
		Port                *int       `json:"port,omitempty"`
		Path                string     `json:"path"`
		InsertionPoint      string     `json:"insertion_point"`
		InsertionConfidence string     `json:"insertion_confidence"`
		Parameters          []string   `json:"parameters"`
		ParametersOrigin    string     `json:"parameters_origin"`
		Sources             []string   `json:"sources"`
		EvidenceURL         string     `json:"evidence_url,omitempty"`
		RawRequest          string     `json:"raw_request,omitempty"`
		Notes               string     `json:"notes,omitempty"`
		ManualAdded         bool       `json:"manual_added"`
		EditedAt            *time.Time `json:"edited_at,omitempty"`
		FirstSeen           time.Time  `json:"first_seen"`
		LastSeen            time.Time  `json:"last_seen"`
		TimesSeen           int        `json:"times_seen"`
	}
	out := []vector{}
	for rows.Next() {
		var v vector
		if rows.Scan(&v.ID, &v.Method, &v.MethodConfidence, &v.Scheme, &v.Domain, &v.Port, &v.Path,
			&v.InsertionPoint, &v.InsertionConfidence, &v.Parameters, &v.ParametersOrigin,
			&v.Sources, &v.EvidenceURL, &v.RawRequest, &v.Notes, &v.ManualAdded, &v.EditedAt,
			&v.FirstSeen, &v.LastSeen, &v.TimesSeen) == nil {
			out = append(out, v)
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
			if len(v.Parameters) == 0 && parsed.RawQuery != "" {
				v.Parameters = queryKeys(parsed.RawQuery)
				if req.InsertionPoint == "" {
					v.InsertionPoint = "query"
				}
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
		errs = append(errs, "A vector needs an insertion point: query, body, header, cookie or path.")
	}
	if len(v.Parameters) == 0 && v.InsertionPoint != "path" {
		errs = append(errs, "A vector needs at least one parameter name, unless the insertion point "+
			"is the path itself.")
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
		       insertion_point, parameters
		FROM attack_vectors WHERE id = $1`, id).
		Scan(&scopeTargetID, &cur.Method, &cur.Scheme, &cur.Domain, &cur.Port, &cur.Path,
			&cur.InsertionPoint, &cur.Parameters) != nil {
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
	if point := normaliseInsertionPoint(req.InsertionPoint); point != "" {
		cur.InsertionPoint = point
	}
	if req.Parameters != nil {
		cur.Parameters = req.Parameters
	}
	if len(cur.Parameters) == 0 && cur.InsertionPoint != "path" {
		writeJSONError(w, http.StatusBadRequest, "invalid_vector",
			"A vector needs at least one parameter name unless its insertion point is the path.")
		return
	}

	params := append([]string(nil), cur.Parameters...)
	sort.Strings(params)
	if _, err := dbPool.Exec(ctx, `
		UPDATE attack_vectors
		SET method = $2, scheme = $3, domain = $4, path = $5, insertion_point = $6,
		    parameters = $7, vector_key = $8, notes = COALESCE(NULLIF($9,''), notes),
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
		cur.key(), req.Notes); err != nil {
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
