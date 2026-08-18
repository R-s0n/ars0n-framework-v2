package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Turning a discovered endpoint into an editable raw HTTP request.
//
// This is the seam the whole fuzz composer rests on. The stored artifact for a fuzz step is raw
// request TEXT, because both tools consume exactly that (ffuf -request, x8 -r) and both send it
// close to byte for byte. Keeping the text authoritative means the request an operator reads in the
// modal is the request that goes on the wire, with no second representation in between. Every time
// this codebase has kept a separate "what we will send" description, it has drifted from what was
// actually sent.
//
// Faithfulness matters more than tidiness here. The point of seeding is that the operator starts
// from what the application really did, so recorded headers and the recorded body are reproduced
// rather than normalised into something cleaner.

// headersOmittedFromSeed are dropped when rendering, each for a specific reason rather than for
// neatness.
//
//	content-length     both tools recalculate it, and a stale value in an edited template is a
//	                   silent corruption waiting to happen once a payload changes the body size.
//	connection,
//	keep-alive,
//	transfer-encoding,
//	upgrade, te,
//	proxy-*            hop-by-hop. They describe one old connection, not the request.
//	accept-encoding    invites a compressed response the operator then cannot read in the results,
//	                   and both tools set their own anyway.
//	content-encoding   the recorded body is stored decoded, so claiming an encoding would lie.
//	host               re-emitted from the URL rather than copied, so the Host line and the target
//	                   cannot disagree. Both tools take their connection target from this line.
var headersOmittedFromSeed = map[string]bool{
	"content-length": true, "connection": true, "keep-alive": true, "transfer-encoding": true,
	"upgrade": true, "te": true, "proxy-authorization": true, "proxy-connection": true,
	"accept-encoding": true, "content-encoding": true, "host": true,
}

// SeededRequest is a raw request plus what the caller needs to run it.
type SeededRequest struct {
	EndpointID string `json:"endpoint_id"`
	Raw        string `json:"raw"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	HasBody    bool   `json:"has_body"`
	// Suggested marker spots, offered rather than applied: parameter names already known for this
	// endpoint, which are the most likely things an operator wants to fuzz first.
	KnownParams []string `json:"known_params"`
	Notes       []string `json:"notes,omitempty"`
}

// RenderSeedRequest builds the raw HTTP request text for one consolidated endpoint.
func RenderSeedRequest(ctx context.Context, endpointID string) (SeededRequest, error) {
	var (
		out         SeededRequest
		rawURL      string
		method      string
		headersJSON []byte
		body        string
		contentType string
	)
	err := dbPool.QueryRow(ctx, `
		SELECT url, COALESCE(method,'GET'), COALESCE(headers,'{}'::jsonb),
		       COALESCE(request_body,''), COALESCE(content_type,'')
		FROM consolidated_url_endpoints
		WHERE id = $1 AND deleted_at IS NULL`, endpointID).
		Scan(&rawURL, &method, &headersJSON, &body, &contentType)
	if err != nil {
		return out, fmt.Errorf("endpoint not found: %w", err)
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return out, fmt.Errorf("endpoint has an unusable URL: %s", rawURL)
	}

	var headers map[string]string
	_ = json.Unmarshal(headersJSON, &headers)

	out.EndpointID = endpointID
	out.Method = strings.ToUpper(strings.TrimSpace(method))
	if out.Method == "" {
		out.Method = "GET"
	}
	out.URL = rawURL
	out.Scheme = u.Scheme
	if out.Scheme == "" {
		out.Scheme = "https"
	}
	out.Host = u.Host
	out.HasBody = strings.TrimSpace(body) != ""
	out.Raw = buildRawRequestText(u, out.Method, headers, body, contentType, &out.Notes)

	out.KnownParams = knownParamsForEndpoint(ctx, endpointID, u, body)
	return out, nil
}

// buildRawRequestText renders the request line, headers, blank line and body.
func buildRawRequestText(u *url.URL, method string, headers map[string]string,
	body, contentType string, notes *[]string) string {

	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", method, target)
	// Host first and derived from the URL, so the line that decides where the request actually goes
	// is the one the operator sees at the top.
	fmt.Fprintf(&b, "Host: %s\n", u.Host)

	// Sorted so the same endpoint always renders identically. An unstable order would make every
	// re-seed look like an edit.
	names := make([]string, 0, len(headers))
	for name := range headers {
		if headersOmittedFromSeed[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		if strings.TrimSpace(name) == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	haveContentType := false
	for _, name := range names {
		value := headers[name]
		// A header value carrying a newline would inject extra headers into the rendered request,
		// which is the one way this renderer could turn recorded data into a different request than
		// the one that was observed.
		if strings.ContainsAny(value, "\r\n") {
			value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
			if notes != nil {
				*notes = append(*notes,
					fmt.Sprintf("Header %q contained a line break, which was flattened to a space.", name))
			}
		}
		if strings.EqualFold(name, "content-type") {
			haveContentType = true
		}
		fmt.Fprintf(&b, "%s: %s\n", name, value)
	}

	hasBody := strings.TrimSpace(body) != ""
	if hasBody && !haveContentType && contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", contentType)
	}

	// Content-Length is deliberately absent: both tools recalculate it, and a fixed one becomes
	// wrong the moment a payload changes the body length.
	b.WriteString("\n")
	if hasBody {
		b.WriteString(body)
	}
	return b.String()
}

// knownParamsForEndpoint gathers parameter names already discovered for this endpoint, so the UI can
// offer them as the first things worth marking.
func knownParamsForEndpoint(ctx context.Context, endpointID string, u *url.URL, body string) []string {
	seen := map[string]bool{}
	// Non-nil so an endpoint with no known parameters serialises as [] rather than null. A null
	// here reaches the UI as "missing" instead of "none", which is a different statement.
	out := []string{}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}

	// Whatever is already in the URL is a real parameter by definition.
	for name := range u.Query() {
		add(name)
	}

	// Body fields are the most likely thing to mark on a write endpoint, and on this framework's
	// usual targets the body is JSON. Top level only: a nested object is a position an operator
	// marks by hand in the raw text, which the marker model already allows anywhere.
	if b := strings.TrimSpace(body); strings.HasPrefix(b, "{") {
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(b), &fields) == nil {
			for name := range fields {
				add(name)
			}
		}
	} else if b != "" && !strings.HasPrefix(b, "[") && !strings.HasPrefix(b, "<") {
		// Form-encoded bodies carry their names in the same shape as a query string.
		if values, err := url.ParseQuery(b); err == nil {
			for name := range values {
				add(name)
			}
		}
	}

	if rows, err := dbPool.Query(ctx,
		`SELECT param_name FROM endpoint_parameters WHERE endpoint_id = $1`, endpointID); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				add(n)
			}
		}
		rows.Close()
	}

	// Anything the parameter tools found on this exact URL, which is the highest-value set: those
	// are hidden parameters the application accepted but never advertised.
	if rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT r.parameter_name
		FROM parameter_enumeration_results r
		JOIN consolidated_url_endpoints e ON e.url = r.endpoint_url
		WHERE e.id = $1`, endpointID); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				add(n)
			}
		}
		rows.Close()
	}

	sort.Strings(out)
	return out
}

// GetFuzzSeed returns the raw request for one endpoint, ready to edit.
func GetFuzzSeed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	endpointID := mux.Vars(r)["endpoint_id"]
	if endpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_endpoint", "endpoint_id is required")
		return
	}

	seed, err := RenderSeedRequest(context.Background(), endpointID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	json.NewEncoder(w).Encode(seed)
}

// ListFuzzSeedEndpoints lists the endpoints a step can be seeded from.
//
// Deliberately the same corpus the parameter tools use, via SelectParamEnumTargets, so "the
// endpoints on the left" means the same thing everywhere in this section rather than a fourth
// definition of which endpoints count.
func ListFuzzSeedEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	includeScripts := r.URL.Query().Get("include_scripts") == "true"
	sel, err := SelectParamEnumTargets(context.Background(), scopeTargetID,
		ParamTargetOptions{IncludeScripts: includeScripts, IncludeDisabled: true})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	type row struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Method   string `json:"method"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		IsDirect bool   `json:"is_direct"`
	}
	out := make([]row, 0, len(sel.Targets))
	for _, t := range sel.Targets {
		host, path := splitURLForDisplay(t.URL)
		out = append(out, row{ID: t.ID, URL: t.URL, Method: t.Method, Host: host, Path: path})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"endpoints": out,
		"total":     len(out),
		"scope":     sel.Scope,
		"predicate": sel.Predicate,
	})
}
