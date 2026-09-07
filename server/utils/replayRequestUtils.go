package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// Replay Request: the repeater.
//
// Everything a manual crawl records is already the highest-fidelity traffic the framework holds,
// but until now it could only be read. This turns it into something you can edit and re-send: pick
// a capture out of the sitemap, take the raw bytes, change one of them, watch what comes back.
//
// Nothing here re-implements request building or sending. BuildRawHTTPRequest already renders a
// capture in the exact shape http.ReadRequest parses, and sendRawRequest already handles the
// scheme, the Host header precedence and the redirect capture. Both are shared with auth flows on
// purpose: a request replayed from the repeater and the same request replayed as an auth-flow step
// have to go out identically, or the repeater becomes a second opinion nobody can reconcile.
//
// Following redirects is built HERE, on top of sendRawRequest, rather than by handing the transport
// a redirect policy. sendRawRequest deliberately returns the 3xx itself, and that is what auth-flow
// steps depend on: a step that captures a Location is capturing the thing it was written to capture.
// Composing the chain one hop at a time in this file leaves that untouched and, more importantly,
// makes every hop a first-class result the operator can look at, instead of a redirect the transport
// swallowed on the way to the last response.

const (
	// The default page of captures. Deliberately generous: the point of the list is to scan it.
	replayCaptureDefaultLimit = 500
	replayCaptureMaxLimit     = 5000
	// A ceiling on how many rows one search may pull back to build the tree from. The corpus is a
	// few thousand rows on the largest target seen, so this is a guard against a pathological
	// future, not a page size.
	replayCaptureScanCeiling = 50000
	// Paths deeper than this collapse into their last kept ancestor. A sitemap is for orienting,
	// and no operator navigates twenty levels of tree.
	replaySitemapMaxDepth = 15
)

// ReplayCaptureSummary is one row of the capture list. Bodies are deliberately absent: the list is
// for choosing, and the chosen capture is fetched whole by the /raw endpoint.
type ReplayCaptureSummary struct {
	ID         string    `json:"id"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	Path       string    `json:"path"`
	Host       string    `json:"host"`
	StatusCode int       `json:"status_code"`
	MimeType   string    `json:"mime_type"`
	Size       int       `json:"size"`
	DurationMs int       `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp"`
}

// ReplaySitemapNode groups the matched captures by host and then by path segment. Count includes
// every descendant, so a collapsed node still says how much is underneath it.
type ReplaySitemapNode struct {
	// Set on root nodes only, where the node is a host rather than a path segment.
	Host     string               `json:"host,omitempty"`
	Name     string               `json:"name"`
	Path     string               `json:"path"`
	Count    int                  `json:"count"`
	Children []*ReplaySitemapNode `json:"children"`
}

type replayCapturesResponse struct {
	Total     int                    `json:"total"`
	Matched   int                    `json:"matched"`
	Returned  int                    `json:"returned"`
	Limit     int                    `json:"limit"`
	Offset    int                    `json:"offset"`
	Truncated bool                   `json:"truncated"`
	Query     string                 `json:"query"`
	Tree      []*ReplaySitemapNode   `json:"tree"`
	Captures  []ReplayCaptureSummary `json:"captures"`
	// Present only when the query itself is the problem. The rest of the payload is still filled in
	// with an empty result so a client that renders the shape unconditionally does not blow up.
	Error         string `json:"error,omitempty"`
	ErrorPosition int    `json:"error_position,omitempty"`
}

// GetReplayRequestCaptures handles GET /replay-request/{scope_target_id}/captures.
//
// Returns both the matching captures and a sitemap tree built from ALL of them, not just the page.
// A tree built from the first 500 rows would claim a host has 500 requests when it has 2,700, and
// a sitemap that lies about size is worse than no sitemap.
func GetReplayRequestCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required",
			"scope_target_id must be a UUID")
		return
	}

	query := r.URL.Query().Get("q")
	limit := replayParseInt(r.URL.Query().Get("limit"), replayCaptureDefaultLimit)
	if limit <= 0 {
		limit = replayCaptureDefaultLimit
	}
	if limit > replayCaptureMaxLimit {
		limit = replayCaptureMaxLimit
	}
	offset := replayParseInt(r.URL.Query().Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	total := 0
	if err := dbPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM manual_crawl_captures WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&total); err != nil {
		log.Printf("[REPLAY-REQUEST] Failed to count captures: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to count captures")
		return
	}

	// $1 is the scope target, so the filter's own placeholders start at $2.
	filter, filterArgs, err := BuildCaptureFilter(query, 2)
	if err != nil {
		// A broken query is a 400, but it carries the full response shape anyway. An operator who
		// mistypes a search must be told what is wrong with it; returning an empty list with a 200
		// is the failure this whole language exists to avoid.
		var parseErr *CaptureQueryError
		payload := replayCapturesResponse{
			Total:    total,
			Query:    query,
			Limit:    limit,
			Offset:   offset,
			Tree:     []*ReplaySitemapNode{},
			Captures: []ReplayCaptureSummary{},
			Error:    err.Error(),
		}
		if errors.As(err, &parseErr) {
			payload.ErrorPosition = parseErr.Position
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(payload)
		return
	}

	args := make([]interface{}, 0, len(filterArgs)+1)
	args = append(args, scopeTargetID)
	args = append(args, filterArgs...)

	sqlText := fmt.Sprintf(`
		SELECT id, COALESCE(method,''), COALESCE(url,''),
		       %s AS host, %s AS path,
		       COALESCE(status_code,0), COALESCE(mime_type,''),
		       COALESCE(octet_length(response_body),0), COALESCE(duration_ms,0), timestamp
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND (%s)
		ORDER BY timestamp ASC
		LIMIT %d`, captureSQLHost, captureSQLPath, filter, replayCaptureScanCeiling)

	rows, err := dbPool.Query(context.Background(), sqlText, args...)
	if err != nil {
		log.Printf("[REPLAY-REQUEST] Capture search failed (q=%q): %v", query, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The search could not be run: "+err.Error())
		return
	}
	defer rows.Close()

	matches := []ReplayCaptureSummary{}
	for rows.Next() {
		var c ReplayCaptureSummary
		if err := rows.Scan(&c.ID, &c.Method, &c.URL, &c.Host, &c.Path, &c.StatusCode,
			&c.MimeType, &c.Size, &c.DurationMs, &c.Timestamp); err != nil {
			log.Printf("[REPLAY-REQUEST] Failed to scan capture row: %v", err)
			continue
		}
		matches = append(matches, c)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[REPLAY-REQUEST] Capture search iteration failed: %v", err)
	}

	page := []ReplayCaptureSummary{}
	if offset < len(matches) {
		end := offset + limit
		if end > len(matches) {
			end = len(matches)
		}
		page = matches[offset:end]
	}

	json.NewEncoder(w).Encode(replayCapturesResponse{
		Total:     total,
		Matched:   len(matches),
		Returned:  len(page),
		Limit:     limit,
		Offset:    offset,
		Truncated: len(page) < len(matches),
		Query:     query,
		Tree:      buildReplaySitemap(matches),
		Captures:  page,
	})
}

func replayParseInt(raw string, fallback int) int {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return n
}

// buildReplaySitemap groups captures by host and then by path segment, like a filesystem.
func buildReplaySitemap(captures []ReplayCaptureSummary) []*ReplaySitemapNode {
	roots := []*ReplaySitemapNode{}
	rootByHost := map[string]*ReplaySitemapNode{}
	// Keyed host|path so a node is found in one lookup rather than by scanning its parent's
	// children, which on a few thousand captures is the difference between instant and noticeable.
	index := map[string]*ReplaySitemapNode{}

	for _, c := range captures {
		host := c.Host
		if host == "" {
			// A capture whose URL has no parseable authority still has to be reachable in the tree,
			// or it exists in the list and nowhere else.
			host = "(no host)"
		}

		root := rootByHost[host]
		if root == nil {
			root = &ReplaySitemapNode{Host: host, Name: host, Path: "", Children: []*ReplaySitemapNode{}}
			rootByHost[host] = root
			roots = append(roots, root)
		}
		root.Count++

		parent := root
		prefix := ""
		for depth, segment := range replayPathSegments(c.Path) {
			if depth >= replaySitemapMaxDepth {
				break
			}
			if segment == "/" {
				prefix = "/"
			} else {
				prefix = prefix + "/" + segment
			}
			key := host + "|" + prefix
			node := index[key]
			if node == nil {
				node = &ReplaySitemapNode{Name: segment, Path: prefix, Children: []*ReplaySitemapNode{}}
				index[key] = node
				parent.Children = append(parent.Children, node)
			}
			node.Count++
			parent = node
		}
	}

	sortReplaySitemap(roots)
	return roots
}

// replayPathSegments splits a path into the nodes it contributes. The root document gets a node of
// its own named "/" rather than folding into the host, so an operator can select the page itself.
func replayPathSegments(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			segments = append(segments, part)
		}
	}
	if len(segments) == 0 {
		return []string{"/"}
	}
	return segments
}

// sortReplaySitemap orders busiest-first, then alphabetically, at every level. Deterministic order
// matters more than the particular order: the tree is re-fetched on every search, and a list that
// reshuffles between two identical searches reads as data changing underneath you.
func sortReplaySitemap(nodes []*ReplaySitemapNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Count != nodes[j].Count {
			return nodes[i].Count > nodes[j].Count
		}
		return nodes[i].Name < nodes[j].Name
	})
	for _, node := range nodes {
		sortReplaySitemap(node.Children)
	}
}

// ---------------------------------------------------------------------------
// One capture, as raw bytes
// ---------------------------------------------------------------------------

type replayRawCaptureResponse struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	BaseURL    string `json:"base_url"`
	RawRequest string `json:"raw_request"`

	// What this request got the first time round, so the operator can tell a change they caused
	// from a difference that was always there.
	OriginalStatus      int                 `json:"original_status"`
	OriginalHeaders     map[string][]string `json:"original_headers"`
	OriginalBody        string              `json:"original_body"`
	OriginalRawResponse string              `json:"original_raw_response"`
	OriginalMimeType    string              `json:"original_mime_type"`
	OriginalDurationMs  int                 `json:"original_duration_ms"`
	Timestamp           time.Time           `json:"timestamp"`

	// Set when the recorder itself truncated the stored bodies, because an edit made against a
	// truncated body will not reproduce the original request.
	RequestBodyTruncated  bool `json:"request_body_truncated"`
	ResponseBodyTruncated bool `json:"response_body_truncated"`
}

// GetReplayRequestCaptureRaw handles GET /replay-request/capture/{id}/raw.
func GetReplayRequestCaptureRaw(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	captureID := mux.Vars(r)["id"]
	if _, err := uuid.Parse(captureID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "capture_id_required", "capture id must be a UUID")
		return
	}

	var urlStr, method, postData, responseBody, mimeType string
	var headersJSON, responseHeadersJSON []byte
	var statusCode, durationMs int
	var requestTruncated, responseTruncated bool
	var timestamp time.Time

	err := dbPool.QueryRow(context.Background(), `
		SELECT COALESCE(url,''), COALESCE(method,''), COALESCE(post_data,''),
		       headers, response_headers, COALESCE(response_body,''),
		       COALESCE(status_code,0), COALESCE(mime_type,''), COALESCE(duration_ms,0),
		       COALESCE(request_body_truncated,false), COALESCE(response_body_truncated,false),
		       timestamp
		FROM manual_crawl_captures
		WHERE id = $1`, captureID).Scan(&urlStr, &method, &postData, &headersJSON,
		&responseHeadersJSON, &responseBody, &statusCode, &mimeType, &durationMs,
		&requestTruncated, &responseTruncated, &timestamp)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "capture_not_found", "No capture with that id")
		return
	}
	if err != nil {
		log.Printf("[REPLAY-REQUEST] Failed to load capture %s: %v", captureID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load capture")
		return
	}

	var headers map[string]interface{}
	json.Unmarshal(headersJSON, &headers)
	var flatResponseHeaders map[string]interface{}
	json.Unmarshal(responseHeadersJSON, &flatResponseHeaders)

	// The same multi-value shape a live send returns, so the original and the replay render through
	// one component instead of two that can disagree.
	responseHeaders := expandHeaderMap(flatResponseHeaders)

	baseURL := ""
	if parsed, perr := url.Parse(urlStr); perr == nil && parsed.Host != "" {
		baseURL = parsed.Scheme + "://" + parsed.Host
	}

	json.NewEncoder(w).Encode(replayRawCaptureResponse{
		ID:                    captureID,
		URL:                   urlStr,
		Method:                strings.ToUpper(method),
		BaseURL:               baseURL,
		RawRequest:            BuildRawHTTPRequest(method, urlStr, headers, postData),
		OriginalStatus:        statusCode,
		OriginalHeaders:       responseHeaders,
		OriginalBody:          responseBody,
		OriginalRawResponse:   buildRawHTTPResponse(statusCode, responseHeaders, responseBody),
		OriginalMimeType:      mimeType,
		OriginalDurationMs:    durationMs,
		Timestamp:             timestamp,
		RequestBodyTruncated:  requestTruncated,
		ResponseBodyTruncated: responseTruncated,
	})
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

type replaySendPayload struct {
	RawRequest string `json:"raw_request"`
	BaseURL    string `json:"base_url"`
	RawMode    bool   `json:"raw_mode"`
	// Off unless the operator asked. A repeater's default job is to show one exchange, and a 302
	// followed silently is a 302 the operator cannot see.
	FollowRedirects bool `json:"follow_redirects"`
	// How many redirects may be followed. Zero means the default; anything above the hard cap is
	// clamped to it.
	MaxRedirects int `json:"max_redirects"`
}

type replaySendResponse struct {
	Status      int                 `json:"status"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	RawResponse string              `json:"raw_response"`
	TimeMs      float64             `json:"time_ms"`
	SizeBytes   int                 `json:"size_bytes"`
	Error       string              `json:"error"`
	// Raised only when the transport is about to overrule something the operator wrote on purpose.
	// Kept rare so that seeing one means something.
	Note string `json:"note,omitempty"`

	// Present only when follow_redirects was asked for. The flat fields above describe the FINAL
	// response so every existing reader keeps working; Hops is every exchange in order, including
	// that final one, so the 3xx that led there is still visible rather than replaced by its
	// destination.
	Hops []replayHop `json:"hops,omitempty"`
	// The chain was still redirecting when the cap was reached. Without this a truncated chain reads
	// as a chain that ended.
	RedirectCapReached bool `json:"redirect_cap_reached,omitempty"`
}

// SendReplayRequest handles POST /replay-request/send.
func SendReplayRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload replaySendPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if strings.TrimSpace(payload.RawRequest) == "" {
		writeJSONError(w, http.StatusBadRequest, "raw_request_required", "raw_request is required")
		return
	}

	request := payload.RawRequest
	note := ""
	if payload.RawMode {
		// RAW MODE SENDS THE BYTES AS TYPED. Not fixing the framing headers is the entire feature.
		//
		// normalizeRawRequest recomputes Content-Length to match the body, which is exactly right
		// for a hand-edited request and exactly wrong for a request-smuggling test, where a
		// deliberate disagreement between Content-Length and Transfer-Encoding IS the payload.
		// "Helpfully" repairing it turns a CL.TE probe into an ordinary POST and the operator
		// concludes the target is not vulnerable when they never sent the test.
		note = rawModeFramingNote(request)
	} else {
		request = normalizeRawRequest(request)
	}

	// A request that cannot parse, or has nowhere to go, is an editor problem rather than a network
	// result, and saying so beats letting the transport produce a cryptic error.
	parsed, parseErr := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	if parseErr != nil {
		writeReplaySendResult(w, replaySendResponse{
			Headers: map[string][]string{},
			Error: "This does not parse as an HTTP request: " + parseErr.Error() +
				". Expected a request line, then headers, then a blank line, then the body.",
			Note: note,
		})
		return
	}
	if parsed.Host == "" && strings.TrimSpace(payload.BaseURL) == "" {
		writeReplaySendResult(w, replaySendResponse{
			Headers: map[string][]string{},
			Error: "The request has no Host header and no base_url was given, " +
				"so there is no way to tell which server to send it to.",
			Note: note,
		})
		return
	}

	// A fresh jar per send. The repeater is for isolated experiments, and a jar that outlived one
	// send would quietly re-attach a cookie the operator had just deleted from the request.
	//
	// Within one send the jar IS shared across the hops of a redirect chain, because that is what
	// the chain is for: a login that answers 302 and a Set-Cookie is only followable if the cookie
	// travels to the next hop. The jar files cookies against the host that issued them, so a chain
	// that leaves the target does not carry the target's cookies with it.
	jar, _ := cookiejar.New(nil)

	if payload.FollowRedirects {
		hops, capReached, finalHeaders, finalBody := runReplayRedirectChain(
			request, payload.BaseURL, jar, replayRedirectCap(payload.MaxRedirects))
		writeReplaySendResult(w, buildReplayChainResult(hops, capReached, note, finalHeaders, finalBody))
		return
	}

	status, headers, body, elapsed, sendErr := sendRawRequest(request, payload.BaseURL, jar)

	result := replaySendResponse{
		Status:    status,
		Headers:   headers,
		Body:      body,
		TimeMs:    elapsed,
		SizeBytes: len([]byte(body)),
		Note:      note,
	}
	if result.Headers == nil {
		result.Headers = map[string][]string{}
	}
	if sendErr != nil {
		// A connection refused, a TLS failure and a timeout are all RESULTS. They belong in the
		// response pane next to the request that caused them, not in an error toast that vanishes
		// and takes the evidence with it, so this is a 200 with the error in the payload.
		result.Error = sendErr.Error()
	} else {
		result.RawResponse = buildRawHTTPResponse(status, headers, body)
	}

	writeReplaySendResult(w, result)
}

func writeReplaySendResult(w http.ResponseWriter, result replaySendResponse) {
	if result.Headers == nil {
		result.Headers = map[string][]string{}
	}
	json.NewEncoder(w).Encode(result)
}

// ---------------------------------------------------------------------------
// Redirect chains
// ---------------------------------------------------------------------------

const (
	// Enough to walk an OIDC dance, which is where long chains actually come from.
	replayRedirectDefaultMax = 10
	// A ceiling the operator cannot raise. Loop detection stops a two-node cycle immediately, but a
	// cycle with a rotating nonce in the path looks like a new URL every time and only this stops it.
	replayRedirectHardMax = 20
)

// replayHop is one exchange in a chain. The body is not carried separately: RawResponse already
// contains it, and a chain of ten hops that repeated every body would be three copies of the same
// megabyte on the wire.
type replayHop struct {
	Index  int    `json:"index"`
	Method string `json:"method"`
	// The absolute URL this hop was sent to, so a chain that changes host says so.
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Verbatim, as the server wrote it. A relative Location is shown relative, because "/login" and
	// "https://accounts.example.com/login" are different findings.
	Location string `json:"location,omitempty"`
	// Where that Location resolved to, which is where the next hop actually went.
	ResolvedURL string  `json:"resolved_url,omitempty"`
	RawResponse string  `json:"raw_response"`
	TimeMs      float64 `json:"time_ms"`
	SizeBytes   int     `json:"size_bytes"`
	// Why this hop's successor is not simply the same request pointed elsewhere: a method downgrade,
	// credentials dropped at a host boundary, or the reason the chain stopped here.
	Note  string `json:"note,omitempty"`
	Error string `json:"error,omitempty"`
}

func replayRedirectCap(requested int) int {
	if requested <= 0 {
		return replayRedirectDefaultMax
	}
	if requested > replayRedirectHardMax {
		return replayRedirectHardMax
	}
	return requested
}

func replayIsRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// runReplayRedirectChain sends the request, and keeps sending the request each Location names, until
// something that is not a followable redirect comes back or the cap is hit. Every exchange is
// returned, in order. The bool says the cap stopped a chain that was still going.
func runReplayRedirectChain(firstRequest, baseURL string, jar http.CookieJar, maxHops int) (
	[]replayHop, bool, map[string][]string, string) {

	hops := []replayHop{}
	// The last exchange's parsed headers and body, returned alongside the hops so the flat
	// Headers/Body fields of the response can describe the FINAL response as they claim to. They are
	// not stored per hop: RawResponse already carries each hop's bytes, and repeating a megabyte body
	// on every hop of a ten-hop chain is what that decision avoids.
	var lastHeaders map[string][]string
	lastBody := ""
	request := firstRequest
	// Two bases, and they differ for exactly one hop. sendBase is what sendRawRequest is given, and
	// for the first hop that is the operator's Base URL untouched: retargeting a request by typing a
	// different host in that box is what the box is for, and a chain that resolved it differently
	// from a send without redirects would send the first hop somewhere else. origin is the same
	// precedence sendRawRequest applies internally, worked out here so a hop can be LABELLED with
	// the absolute URL it actually went to.
	sendBase := baseURL
	origin := replayEffectiveOrigin(request, baseURL)
	seen := map[string]bool{}

	for {
		method, absURL := replayRequestTarget(request, origin)
		seen[method+" "+absURL] = true

		status, headers, body, elapsed, sendErr := sendRawRequest(request, sendBase, jar)
		lastHeaders, lastBody = headers, body
		hop := replayHop{
			Index:     len(hops),
			Method:    method,
			URL:       absURL,
			Status:    status,
			TimeMs:    elapsed,
			SizeBytes: len([]byte(body)),
		}
		// A connection refused two hops in is a result about hop three, not a failure of the whole
		// send: the first two exchanges happened and are still worth reading.
		if sendErr != nil {
			hop.Error = sendErr.Error()
			return append(hops, hop), false, lastHeaders, lastBody
		}
		hop.RawResponse = buildRawHTTPResponse(status, headers, body)
		if values := headers["Location"]; len(values) > 0 {
			hop.Location = values[0]
		}

		if !replayIsRedirect(status) || strings.TrimSpace(hop.Location) == "" {
			// A 3xx with no Location is the end of the chain rather than a broken one: 304 and 300
			// are answers, not instructions.
			return append(hops, hop), false, lastHeaders, lastBody
		}

		next, resolved, note, err := buildReplayRedirectRequest(request, absURL, status, hop.Location)
		hop.ResolvedURL = resolved
		if err != nil {
			hop.Note = replayJoinNotes(note, err.Error())
			return append(hops, hop), false, lastHeaders, lastBody
		}

		nextOrigin := replayOriginOf(resolved)
		nextMethod, nextURL := replayRequestTarget(next, nextOrigin)
		if seen[nextMethod+" "+nextURL] {
			hop.Note = replayJoinNotes(note,
				"That is a hop this chain already made, so it is a loop and the chain stops here")
			return append(hops, hop), false, lastHeaders, lastBody
		}

		hop.Note = note
		hops = append(hops, hop)
		if len(hops) > maxHops {
			return hops, true, lastHeaders, lastBody
		}
		request = next
		// From here on the Base URL box has had its say: the target of every further hop is the one
		// the previous response named.
		sendBase = nextOrigin
		origin = nextOrigin
	}
}

// buildReplayChainResult flattens a chain into the send response. The flat fields describe the FINAL
// hop, so a client that knows nothing about chains still shows the response the operator ended at,
// and TimeMs is the total across every hop because that is what they waited.
func buildReplayChainResult(hops []replayHop, capReached bool, note string,
	finalHeaders map[string][]string, finalBody string) replaySendResponse {

	result := replaySendResponse{
		Headers:            map[string][]string{},
		Note:               note,
		Hops:               hops,
		RedirectCapReached: capReached,
	}
	if len(hops) == 0 {
		return result
	}
	total := 0.0
	for _, hop := range hops {
		total += hop.TimeMs
	}
	final := hops[len(hops)-1]
	result.Status = final.Status
	result.RawResponse = final.RawResponse
	result.SizeBytes = final.SizeBytes
	result.TimeMs = total
	result.Error = final.Error
	// Headers and Body are flat fields that this function's own contract says describe the final
	// response, and for a while they described nothing: a chain returned an empty map and an empty
	// string, so any reader that had not been taught about Hops silently got a blank response for
	// every followed redirect. The pane reads raw_response and never noticed.
	result.Body = finalBody
	if finalHeaders != nil {
		result.Headers = finalHeaders
	}
	return result
}

// buildReplayRedirectRequest turns "the response said go here" into the next raw request.
//
// The rules are the ones a browser follows, because a chain that behaves differently from a browser
// is a chain that answers a question nobody asked:
//
//	301, 302, 303   a method other than GET or HEAD becomes GET and the body is dropped
//	307, 308        method and body are preserved
//
// Two things are dropped that a naive copy would carry: Authorization and Cookie when the redirect
// leaves the host family, or drops from https to http. That is not caution, it is the difference
// between testing an open redirect and handing the operator's session to whoever it points at.
func buildReplayRedirectRequest(currentRaw, currentAbs string, status int, location string) (string, string, string, error) {
	base, err := url.Parse(currentAbs)
	if err != nil || base.Host == "" {
		return "", "", "", fmt.Errorf("the URL of that hop (%q) could not be parsed, "+
			"so its Location could not be resolved and the chain stops here", currentAbs)
	}
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", "", "", fmt.Errorf("the Location header %q is not a URL, so the chain stops here", location)
	}
	target := base.ResolveReference(ref)
	if target.Scheme != "http" && target.Scheme != "https" {
		return "", target.String(), "", fmt.Errorf("the Location points at a %s:// URL, which this "+
			"repeater does not send, so the chain stops here", target.Scheme)
	}
	if target.Host == "" {
		return "", target.String(), "", fmt.Errorf("the Location %q resolves to no host, "+
			"so the chain stops here", location)
	}

	req, parseErr := http.ReadRequest(bufio.NewReader(strings.NewReader(currentRaw)))
	if parseErr != nil {
		return "", target.String(), "", fmt.Errorf("the request that produced this redirect could not "+
			"be re-read (%v), so the chain stops here", parseErr)
	}
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	method := strings.ToUpper(req.Method)
	notes := []string{}
	if status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther {
		if method != http.MethodGet && method != http.MethodHead {
			notes = append(notes, fmt.Sprintf("%d turned the %s into a GET and dropped its body, "+
				"which is what a browser does here", status, method))
			method = http.MethodGet
			bodyBytes = nil
		}
	}

	headers := map[string]interface{}{}
	for name, values := range req.Header {
		if strings.EqualFold(name, "Cookie") {
			headers[name] = strings.Join(values, "; ")
			continue
		}
		headers[name] = strings.Join(values, ", ")
	}
	if len(bodyBytes) == 0 {
		for name := range headers {
			if strings.EqualFold(name, "Content-Type") {
				delete(headers, name)
			}
		}
	}

	crossHost := !replaySameHostFamily(base.Host, target.Host)
	downgrade := base.Scheme == "https" && target.Scheme == "http"
	if crossHost || downgrade {
		dropped := []string{}
		for _, credential := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
			for name := range headers {
				if strings.EqualFold(name, credential) {
					delete(headers, name)
					dropped = append(dropped, credential)
				}
			}
		}
		if len(dropped) > 0 {
			sort.Strings(dropped)
			reason := fmt.Sprintf("the redirect left %s for %s", hostOnly(base.Host), hostOnly(target.Host))
			if downgrade {
				reason = "the redirect dropped from https to http"
			}
			notes = append(notes, fmt.Sprintf("%s, so %s was not carried to it",
				reason, strings.Join(dropped, " and ")))
		}
	}

	return BuildRawHTTPRequest(method, target.String(), headers, string(bodyBytes)),
		target.String(), replayJoinNotes(notes...), nil
}

// replaySameHostFamily is the same test Go's own client uses to decide whether a redirect may keep
// its credentials: the same host, or one a subdomain of the other.
func replaySameHostFamily(from, to string) bool {
	a := strings.ToLower(hostOnly(from))
	b := strings.ToLower(hostOnly(to))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasSuffix(b, "."+a) || strings.HasSuffix(a, "."+b)
}

// replayEffectiveOrigin works out the scheme and host a raw request will actually be sent to, using
// the same precedence sendRawRequest applies: a base URL, if there is one, wins over the Host header,
// and the scheme defaults to https. Duplicated here rather than inferred, because a hop labelled
// with a host other than the one it was sent to is a lie in the one place the operator is looking to
// find out where their request went.
func replayEffectiveOrigin(rawRequest, baseURL string) string {
	scheme, host := "https", ""
	if req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest))); err == nil {
		host = req.Host
	}
	if trimmed := strings.TrimSpace(baseURL); trimmed != "" {
		if parsed, err := url.Parse(trimmed); err == nil && parsed.Host != "" {
			if parsed.Scheme != "" {
				scheme = parsed.Scheme
			}
			host = parsed.Host
		}
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

// replayRequestTarget reports the method and the absolute URL a raw request will be sent to, which
// is what a hop has to be labelled with: a request-target of "/login" says nothing about which host
// received it, and the whole point of showing a chain is showing where it went.
//
// The origin wins over anything in the request-target, because that is what the transport does: it
// overwrites the URL's scheme and host before sending. An absolute-form request line is not where
// the request goes.
func replayRequestTarget(rawRequest, origin string) (string, string) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil || req.URL == nil {
		return "", origin
	}
	method := strings.ToUpper(req.Method)
	target := *req.URL
	if base, perr := url.Parse(origin); perr == nil && base.Host != "" {
		target.Scheme = base.Scheme
		target.Host = base.Host
	}
	if target.Scheme == "" {
		target.Scheme = "https"
	}
	return method, target.String()
}

func replayOriginOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + parsed.Host
}

func replayJoinNotes(notes ...string) string {
	kept := make([]string, 0, len(notes))
	for _, note := range notes {
		if strings.TrimSpace(note) != "" {
			kept = append(kept, strings.TrimSpace(note))
		}
	}
	return strings.Join(kept, ". ")
}

// buildRawHTTPResponse reconstructs the wire form of a response from the parts net/http kept.
// Header order is lost by the time it reaches us, so names are sorted: a stable rendering is worth
// more than a fictional ordering, and it makes two responses diffable.
func buildRawHTTPResponse(status int, headers map[string][]string, body string) string {
	if status == 0 {
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))

	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range headers[name] {
			fmt.Fprintf(&sb, "%s: %s\r\n", name, value)
		}
	}

	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

// rawModeFramingNote tells the operator when raw mode cannot deliver what they typed.
//
// Raw mode skips normalizeRawRequest, so the headers reach the transport as written. The transport
// is still net/http, and net/http re-frames the body on its way out. Every sentence below was
// checked against the bytes a listening socket actually received, because a note that describes the
// wrong behaviour is worse than no note: the operator reads it, believes their probe was neutered,
// and throws away a result that was real. The three cases behave differently and are described
// differently.
//
//	chunked present  the body is DECODED by http.ReadRequest and RE-ENCODED by the client. It
//	                 still leaves as Transfer-Encoding: chunked, and any Content-Length is dropped.
//	                 Valid chunked bodies survive intact; a hand-built chunk sequence does not,
//	                 because anything after the terminating 0-chunk is discarded on the way in.
//	CL < body        the declared Content-Length goes out VERBATIM and the body is TRUNCATED to it.
//	                 The bytes past the declared length are silently dropped.
//	CL > body        http.ReadRequest cannot read that many bytes, the short read is swallowed, and
//	                 the client sends the real, smaller length instead.
//
// Kept rare on purpose: a note on every raw-mode send would be wallpaper, and wallpaper is not read.
func rawModeFramingNote(raw string) string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, found := strings.Cut(normalized, "\n\n")
	if !found {
		head = normalized
		body = ""
	}

	declaredLength := -1
	chunked := false
	for _, line := range strings.Split(head, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "content-length:") {
			if n, err := strconv.Atoi(strings.TrimSpace(lower[len("content-length:"):])); err == nil {
				declaredLength = n
			}
		}
		if strings.HasPrefix(lower, "transfer-encoding:") && strings.Contains(lower, "chunked") {
			chunked = true
		}
	}

	switch {
	case chunked && declaredLength >= 0:
		return "This request declares both Content-Length and a chunked Transfer-Encoding. Only the " +
			"chunked framing survives: Go's client drops the Content-Length header and re-encodes the " +
			"body as chunks, so the CL/TE disagreement never reaches the target and anything after " +
			"the terminating 0-chunk is discarded. Send a CL.TE or TE.CL probe through a raw socket " +
			"tool instead."
	case chunked:
		return "The body is decoded and re-encoded as chunks by Go's HTTP client. It does leave as " +
			"Transfer-Encoding: chunked, but a hand-built chunk sequence will not survive that round " +
			"trip: anything after the terminating 0-chunk is discarded before the request is sent."
	case declaredLength >= 0 && declaredLength > len(body):
		return fmt.Sprintf("Content-Length says %d but the body is only %d bytes. Go's HTTP client "+
			"cannot read the missing bytes, so it sends the real length of %d and the declared %d "+
			"never reaches the target.", declaredLength, len(body), len(body), declaredLength)
	case declaredLength >= 0 && declaredLength < len(body):
		return fmt.Sprintf("Content-Length says %d but the body is %d bytes. The declared %d IS sent, "+
			"and the body is truncated to match it: the last %d bytes you typed will not leave this "+
			"machine.", declaredLength, len(body), declaredLength, len(body)-declaredLength)
	}
	return ""
}
