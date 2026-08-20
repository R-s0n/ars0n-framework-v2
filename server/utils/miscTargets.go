package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Three tools, three different ideas of what a target is, which is why this section needs its own
// file rather than reusing one row source.
//
//   - Upload_Bypass needs a REQUEST that already uploads a file successfully, because every technique
//     it has is a mutation of a working upload. Only a person can say which request that is, so the
//     operator marks them.
//   - jwt_tool needs a TOKEN, and a token is recognisable on sight, so the framework finds them.
//   - pphack needs a URL loaded in a browser, and client-side prototype pollution lives in the query
//     string, so it takes the GET vectors.

// jwtInTextPattern finds a JSON Web Token INSIDE a larger blob of text.
//
// Distinct from the anchored jwtPattern in captureBridgeUtils.go, which asks whether a whole value
// IS a token. This one hunts for tokens inside a header dump or a raw request.
//
// Three base64url segments separated by dots, where the first two decode to JSON. "eyJ" is the
// base64url encoding of `{"`, so a token's header and payload both begin with it, and requiring that
// on the first TWO segments is what keeps this from matching every long dotted string in a cookie.
var jwtInTextPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// jwtSourceTables is where captured traffic lives. Headers and raw requests both, because a token
// arrives in an Authorization header, a cookie or a body depending on the application.
var jwtSourceTables = []struct {
	Name    string
	Table   string
	URL     string
	Columns []string
}{
	{"manual-crawl", "manual_crawl_captures", "url", []string{"headers::text"}},
	{"consolidated-endpoints", "consolidated_url_endpoints", "url", []string{"headers::text"}},
	{"attack-vectors", "attack_vectors", "evidence_url", []string{"raw_request"}},
	// auth_flow_steps carries neither scope_target_id nor a URL: it hangs off auth_flows by
	// auth_flow_id. Selecting from it directly errors, and because a failing source here is skipped
	// rather than fatal, that error would have been invisible and auth flows would simply never have
	// contributed a token.
	{"auth-flow", authFlowStepsSource, "url", []string{"raw_request"}},
}

// authFlowStepsSource joins the steps to the flow that owns them, so the caller's
// "WHERE scope_target_id = $1" has a column to bind to.
const authFlowStepsSource = `(SELECT s.raw_request, f.base_url AS url, f.scope_target_id
	                              FROM auth_flow_steps s
	                              JOIN auth_flows f ON f.id = s.auth_flow_id) AS auth_flow_source`

// FoundJWT is one token and where it was seen.
type FoundJWT struct {
	Token  string `json:"token"`
	URL    string `json:"url"`
	Source string `json:"source"`
	Alg    string `json:"alg"`
	Issuer string `json:"issuer"`
}

// findJWTs scans the capture tables for tokens.
//
// Deduplicated by TOKEN rather than by URL: the same token on forty endpoints is one thing to attack,
// and attacking it forty times would be forty rounds of signature cracking for one answer.
func findJWTs(ctx context.Context, scopeTargetID string) ([]FoundJWT, error) {
	var found []FoundJWT
	seen := map[string]bool{}

	for _, source := range jwtSourceTables {
		for _, column := range source.Columns {
			rows, err := dbPool.Query(ctx,
				`SELECT COALESCE(`+source.URL+`,''), COALESCE(`+column+`,'') FROM `+source.Table+
					` WHERE scope_target_id = $1 AND `+column+` ~ 'eyJ[A-Za-z0-9_-]{8,}\.eyJ'`,
				scopeTargetID)
			if err != nil {
				// A table this deployment does not have is not worth failing the whole lookup for, but
				// it IS worth saying: a silently skipped source is a source that never contributes a
				// token, and the section would look like it had simply found nothing.
				log.Printf("[MISC] jwt source %s unavailable: %v", source.Name, err)
				continue
			}
			for rows.Next() {
				var url, blob string
				if err := rows.Scan(&url, &blob); err != nil {
					continue
				}
				for _, token := range jwtInTextPattern.FindAllString(blob, -1) {
					if seen[token] {
						continue
					}
					seen[token] = true
					alg, issuer := describeJWT(token)
					found = append(found, FoundJWT{
						Token: token, URL: url, Source: source.Name, Alg: alg, Issuer: issuer,
					})
				}
			}
			rows.Close()
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].URL < found[j].URL })
	return found, nil
}

// describeJWT reads the algorithm and issuer without verifying anything, so the operator can see at a
// glance which tokens are worth attacking. An alg of none or HS256 on a token that should be
// asymmetric is the interesting case.
func describeJWT(token string) (alg, issuer string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if raw, err := base64URLDecode(parts[0]); err == nil {
		_ = json.Unmarshal(raw, &header)
	}
	var payload struct {
		Iss string `json:"iss"`
	}
	if raw, err := base64URLDecode(parts[1]); err == nil {
		_ = json.Unmarshal(raw, &payload)
	}
	return header.Alg, payload.Iss
}

// jwtRowSource hands the runner one row per distinct token.
func jwtRowSource(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
	found, err := findJWTs(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}

	var out []vectorRow
	for _, jwt := range found {
		row := vectorRow{
			ID:              deterministicUUID(scopeTargetID + "|jwt|" + jwt.Token),
			Method:          "GET",
			InsertionPoint:  "header",
			EvidenceURL:     jwt.URL,
			RawRequest:      jwt.Token,
			IsGraphQLTarget: true,
		}
		row.Scheme, row.Domain, row.Port, row.Path = splitURLParts(jwt.URL)
		out = append(out, row)
	}
	return out, nil
}

// GetFoundJWTs serves what was detected, so the card's count is explainable rather than a number the
// operator has to trust.
func GetFoundJWTs(w http.ResponseWriter, r *http.Request) {
	found, err := findJWTs(r.Context(), mux.Vars(r)["scope_target_id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The token itself is truncated: it is a live credential and there is no reason to paint it
	// across a screen that may be shared.
	type shown struct {
		Preview string `json:"preview"`
		URL     string `json:"url"`
		Source  string `json:"source"`
		Alg     string `json:"alg"`
		Issuer  string `json:"issuer"`
	}
	out := make([]shown, 0, len(found))
	for _, jwt := range found {
		out = append(out, shown{
			Preview: truncateSecret(jwt.Token), URL: jwt.URL, Source: jwt.Source,
			Alg: jwt.Alg, Issuer: jwt.Issuer,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"tokens": out,
		"count":  len(out),
		"note": "Found automatically wherever this target's captured traffic carries a JSON Web " +
			"Token. Deduplicated by token: the same token on many endpoints is one thing to attack.",
	})
}

// uploadRequestRowSource hands the runner the requests the operator marked as uploads.
//
// Stored as request IDs rather than URLs, because a URL is not enough: Upload_Bypass mutates a
// specific request, and two uploads to the same endpoint with different bodies are two different
// things to test.
func uploadRequestRowSource(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
	settings := loadVectorSettings(ctx, scopeTargetID, "upload-bypass")
	wanted := map[string]bool{}
	for _, id := range splitIDList(stringifySetting(settings[graphqlEndpointsSetting])) {
		wanted[id] = true
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	candidates, err := uploadCandidates(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}

	var out []vectorRow
	for _, candidate := range candidates {
		if !wanted[candidate.ID] {
			continue
		}
		row := vectorRow{
			ID:              deterministicUUID(scopeTargetID + "|upload|" + candidate.ID),
			Method:          candidate.Method,
			InsertionPoint:  "body",
			EvidenceURL:     candidate.URL,
			RawRequest:      candidate.RawRequest,
			IsGraphQLTarget: true,
		}
		row.Scheme, row.Domain, row.Port, row.Path = splitURLParts(candidate.URL)
		out = append(out, row)
	}
	return out, nil
}

// urlFromRawRequest rebuilds where a saved request was going, from its request line and Host header.
func urlFromRawRequest(raw string) string {
	lines := strings.Split(normaliseRawRequest(raw), "\r\n")
	if len(lines) == 0 {
		return ""
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return ""
	}
	path := fields[1]
	// An absolute-form request line already carries everything.
	if strings.Contains(path, "://") {
		return path
	}
	for _, line := range lines[1:] {
		if line == "" {
			break // end of headers
		}
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		host := strings.TrimSpace(value)
		if host == "" {
			break
		}
		scheme := "https"
		if strings.HasSuffix(host, ":80") {
			scheme = "http"
		}
		return scheme + "://" + host + path
	}
	return path
}

// isHTTPMethod says whether the first word of a stored request is a verb rather than the start of a
// body somebody pasted without its request line.
func isHTTPMethod(word string) bool {
	switch strings.ToUpper(word) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

// splitIDList reads the marked-request list.
//
// Separate from splitEndpointList, which turns a bare value into https://value because the tools it
// serves want URLs. A request id is not a URL, and going through that helper would store every id
// with a scheme glued to the front.
func splitIDList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
	seen := map[string]bool{}
	var out []string
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		out = append(out, field)
	}
	return out
}

// UploadCandidate is one request an operator might mark as a file upload.
type UploadCandidate struct {
	ID              string `json:"id"`
	Method          string `json:"method"`
	URL             string `json:"url"`
	Source          string `json:"source"`
	RawRequest      string `json:"-"`
	LooksLikeUpload bool   `json:"looks_like_upload"`
	HasBody         bool   `json:"has_body"`
	// Markable says whether this request can be turned into the marked form Upload_Bypass needs.
	// Shown in the picker because an operator marking an unmarkable request would otherwise only find
	// out when the scan skipped it.
	Markable bool   `json:"markable"`
	Hint     string `json:"hint"`
}

// uploadCandidates reads every stored request that could plausibly be an upload.
func uploadCandidates(ctx context.Context, scopeTargetID string) ([]UploadCandidate, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(method,'POST'), COALESCE(evidence_url,''), COALESCE(raw_request,''), 'attack-vector'
		  FROM attack_vectors
		 WHERE scope_target_id = $1 AND deleted_at IS NULL AND COALESCE(raw_request,'') <> ''
		UNION ALL
		SELECT s.id::text, 'POST', COALESCE(f.base_url,''), COALESCE(s.raw_request,''), 'auth-flow'
		  FROM auth_flow_steps s
		  JOIN auth_flows f ON f.id = s.auth_flow_id
		 WHERE f.scope_target_id = $1 AND COALESCE(s.raw_request,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Never nil: an empty list has to serialise as [] rather than null, or the picker's
	// candidates.filter throws and the whole tab renders blank instead of saying there is nothing yet.
	out := []UploadCandidate{}
	for rows.Next() {
		var c UploadCandidate
		if err := rows.Scan(&c.ID, &c.Method, &c.URL, &c.RawRequest, &c.Source); err != nil {
			continue
		}
		// The stored method is only a hint for the rows that have one; the request line is the truth,
		// and an auth flow step has no method column at all.
		if fields := strings.Fields(c.RawRequest); len(fields) > 0 && isHTTPMethod(fields[0]) {
			c.Method = strings.ToUpper(fields[0])
		}
		// An auth flow keeps its URL on the flow, not the step, and that base_url is often blank. The
		// request itself always knows where it was going, and a row the operator cannot identify is a
		// row they cannot safely mark.
		if strings.TrimSpace(c.URL) == "" {
			c.URL = urlFromRawRequest(c.RawRequest)
		}
		lower := strings.ToLower(c.RawRequest)
		_, body := rawRequestBody(c.RawRequest)
		c.HasBody = strings.TrimSpace(body) != ""
		// A hint for ordering, never a filter: the operator decides what is an upload.
		c.LooksLikeUpload = strings.Contains(lower, "multipart/form-data") ||
			strings.Contains(lower, "filename=")
		_, markErr := MarkUploadRequest(c.RawRequest)
		c.Markable = markErr == nil
		c.Hint = describeUploadRequest(c.RawRequest)
		out = append(out, c)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Markable != out[j].Markable {
			return out[i].Markable
		}
		if out[i].LooksLikeUpload != out[j].LooksLikeUpload {
			return out[i].LooksLikeUpload
		}
		if out[i].HasBody != out[j].HasBody {
			return out[i].HasBody
		}
		return out[i].URL < out[j].URL
	})
	return out, rows.Err()
}

// GetUploadCandidates serves the requests an operator can mark as uploads.
//
// Every stored request is offered, not just the multipart ones. An upload does not have to be
// multipart: plenty of applications take a base64 blob in JSON, and a filter that only showed
// multipart would hide exactly the endpoints worth testing.
func GetUploadCandidates(w http.ResponseWriter, r *http.Request) {
	candidates, err := uploadCandidates(r.Context(), mux.Vars(r)["scope_target_id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"candidates": candidates,
		"count":      len(candidates),
		"note": "Requests this target has captured. Mark the ones that upload a file. Upload_Bypass " +
			"mutates a request that ALREADY WORKS, so pick an upload you know succeeds.",
	})
}

// getVectorRowSource hands pphack the GET attack vectors.
//
// Client-side prototype pollution is polluted through the URL: the payload goes in the query string
// or the fragment and the page's own JavaScript merges it into an object. A POST body never reaches
// the sink, so scanning one would be requests spent on something that cannot fire.
func getVectorRowSource(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
	all, err := loadVectorRows(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}
	var out []vectorRow
	for _, row := range all {
		if !strings.EqualFold(row.Method, "GET") {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}
