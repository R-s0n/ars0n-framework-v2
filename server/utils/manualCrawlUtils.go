package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Manual crawl capture is driven by the browser extension. Everything here is deliberately
// stateless: the extension owns the session id and sends it with every request. The previous
// implementation kept the active session in a package-level global, which meant an API restart
// (or a second target) silently voided an in-progress recording and every capture 400'd.
//
// Liveness is tracked with `last_heartbeat_at` rather than status alone, because an MV3 service
// worker can be terminated by the browser at any time. A session whose heartbeat has gone quiet is
// reported as not live so the UI stops claiming it is recording.

// A session is considered live if it has heartbeat within this window. The extension beats every
// 20s, so this tolerates roughly four missed beats before the session is treated as dead.
const manualCrawlHeartbeatTimeout = 90 * time.Second

type ManualCrawlCapture struct {
	ID              string                 `json:"id"`
	SessionID       string                 `json:"session_id"`
	ScopeTargetID   string                 `json:"scope_target_id"`
	URL             string                 `json:"url"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"status_code"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	PostData        string                 `json:"post_data,omitempty"`
	ResponseBody    string                 `json:"response_body,omitempty"`
	GetParams       map[string]interface{} `json:"get_params,omitempty"`
	PostParams      map[string]interface{} `json:"post_params,omitempty"`
	BodyType        string                 `json:"body_type,omitempty"`
	TabID           *int                   `json:"tab_id,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	MimeType        string                 `json:"mime_type"`
	// Provenance and richer detail from the multi-source extension. `Sources` names which of
	// webrequest / hook / debugger contributed, which is how a metadata-only record is told apart
	// from one carrying real request and response bodies.
	// Direct means the capture is on the scope target's own host; adjacent means any other in-scope
	// host, which is where an application's API usually lives.
	IsDirect              bool          `json:"is_direct"`
	Sources               []string      `json:"sources"`
	GraphQLOperation      string        `json:"graphql_operation,omitempty"`
	ResourceType          string        `json:"resource_type,omitempty"`
	Initiator             string        `json:"initiator,omitempty"`
	RedirectChain         []interface{} `json:"redirect_chain,omitempty"`
	Error                 string        `json:"error,omitempty"`
	DurationMs            int           `json:"duration_ms"`
	RequestBodyTruncated  bool          `json:"request_body_truncated"`
	ResponseBodyTruncated bool          `json:"response_body_truncated"`
}

type ManualCrawlSession struct {
	ID                 string         `json:"id"`
	ScopeTargetID      string         `json:"scope_target_id"`
	TargetURL          string         `json:"target_url"`
	Status             string         `json:"status"`
	StartedAt          time.Time      `json:"started_at"`
	EndedAt            *time.Time     `json:"ended_at,omitempty"`
	LastHeartbeatAt    *time.Time     `json:"last_heartbeat_at,omitempty"`
	RequestCount       int            `json:"request_count"`
	EndpointCount      int            `json:"endpoint_count"`
	IsLive             bool           `json:"is_live"`
	ObservedOutOfScope map[string]int `json:"observed_out_of_scope,omitempty"`
}

type CaptureRequest struct {
	SessionID       string                 `json:"sessionId"`
	URL             string                 `json:"url"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"statusCode"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"responseHeaders"`
	PostData        string                 `json:"postData,omitempty"`
	ResponseBody    string                 `json:"responseBody,omitempty"`
	GetParams       map[string]interface{} `json:"getParams,omitempty"`
	PostParams      map[string]interface{} `json:"postParams,omitempty"`
	BodyType        string                 `json:"bodyType,omitempty"`
	TabID           *int                   `json:"tabId,omitempty"`
	Timestamp       string                 `json:"timestamp"`
	MimeType        string                 `json:"mimeType"`

	Sources               []string      `json:"sources,omitempty"`
	GraphQLOperation      string        `json:"graphqlOperation,omitempty"`
	ResourceType          string        `json:"resourceType,omitempty"`
	Initiator             string        `json:"initiator,omitempty"`
	RedirectChain         []interface{} `json:"redirectChain,omitempty"`
	Error                 string        `json:"error,omitempty"`
	DurationMs            int           `json:"durationMs,omitempty"`
	RequestBodyTruncated  bool          `json:"requestBodyTruncated,omitempty"`
	ResponseBodyTruncated bool          `json:"responseBodyTruncated,omitempty"`
}

type BatchCaptureRequest struct {
	SessionID string           `json:"sessionId"`
	Captures  []CaptureRequest `json:"captures"`
}

type StartCaptureRequest struct {
	TargetURL     string `json:"targetUrl"`
	ScopeTargetID string `json:"scopeTargetId"`
}

// SessionStatsRequest is the payload for heartbeat and stop. Stats are advisory only: the
// authoritative counts are recomputed from manual_crawl_captures so a session that dies without a
// clean stop still reports the right numbers.
type SessionStatsRequest struct {
	SessionID string `json:"sessionId"`
	Stats     struct {
		RequestCount  int `json:"requestCount"`
		EndpointCount int `json:"endpointCount"`
	} `json:"stats"`
	// Hosts the extension rejected as out of scope. Surfaced in the results modal so "where is my
	// API traffic" is answerable from the framework rather than only from the extension popup.
	ObservedOutOfScope map[string]int `json:"observedOutOfScope,omitempty"`
}

// sessionLookupError distinguishes "this session id is unknown" from "this session was already
// stopped" so the extension can react differently (drop the queue vs stop recording).
type sessionLookupError struct {
	code    string
	status  int
	message string
}

func (e *sessionLookupError) Error() string { return e.message }

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "ars0n-framework",
	})
}

// resolveActiveCrawlSession validates a session id and returns the scope target it belongs to.
func resolveActiveCrawlSession(sessionID string) (string, error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", &sessionLookupError{"session_id_required", http.StatusBadRequest, "sessionId is required"}
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return "", &sessionLookupError{"session_not_found", http.StatusNotFound, "Unknown capture session"}
	}

	var scopeTargetID, status string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id, status FROM manual_crawl_sessions WHERE id = $1`, sessionID).
		Scan(&scopeTargetID, &status)
	if err != nil {
		return "", &sessionLookupError{"session_not_found", http.StatusNotFound, "Unknown capture session"}
	}
	if status != "active" {
		return "", &sessionLookupError{"session_not_active", http.StatusConflict, "Capture session is no longer active"}
	}
	return scopeTargetID, nil
}

func respondSessionError(w http.ResponseWriter, err error) {
	if lookupErr, ok := err.(*sessionLookupError); ok {
		writeJSONError(w, lookupErr.status, lookupErr.code, lookupErr.message)
		return
	}
	writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

func StartManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req StartCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if req.TargetURL == "" {
		writeJSONError(w, http.StatusBadRequest, "target_url_required", "targetUrl is required")
		return
	}
	if req.ScopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scopeTargetId is required")
		return
	}

	var scopeTargetExists bool
	err := dbPool.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1 AND type = 'URL')",
		req.ScopeTargetID).Scan(&scopeTargetExists)

	if err != nil || !scopeTargetExists {
		log.Printf("[MANUAL-CRAWL] Invalid scope target ID: %s", req.ScopeTargetID)
		writeJSONError(w, http.StatusBadRequest, "scope_target_not_found", "Invalid scopeTargetId - target not found")
		return
	}

	// Close out any session still marked active for this target. Multiple targets can record
	// concurrently, but a single target recording twice is always a stale row from a dead worker.
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE manual_crawl_sessions
		SET status = 'abandoned', ended_at = COALESCE(last_heartbeat_at, started_at)
		WHERE scope_target_id = $1 AND status = 'active'`, req.ScopeTargetID); err != nil {
		log.Printf("[MANUAL-CRAWL] Failed to close previous sessions for %s: %v", req.ScopeTargetID, err)
	}

	sessionID := uuid.New().String()
	now := time.Now()

	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO manual_crawl_sessions (id, scope_target_id, target_url, status, started_at, last_heartbeat_at)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		sessionID, req.ScopeTargetID, req.TargetURL, "active", now)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error creating session: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create capture session")
		return
	}

	log.Printf("[MANUAL-CRAWL] Started session %s for target %s", sessionID, req.TargetURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"sessionId":        sessionID,
		"scopeTargetId":    req.ScopeTargetID,
		"heartbeatSeconds": int(manualCrawlHeartbeatTimeout.Seconds()) / 3,
	})
}

// CaptureManualCrawlRequest stores a single capture. Kept for compatibility with older extension
// builds; the current extension posts batches to /manual-crawl/capture/batch.
func CaptureManualCrawlRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding capture request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	scopeTargetID, err := resolveActiveCrawlSession(req.SessionID)
	if err != nil {
		respondSessionError(w, err)
		return
	}

	stored, err := insertManualCrawlCaptures(req.SessionID, scopeTargetID, []CaptureRequest{req})
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error storing capture: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store capture")
		return
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error refreshing session counts: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"stored":        stored,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

// CaptureManualCrawlBatch stores many captures in one round trip. The extension queues captures
// locally and flushes them here, so a slow or briefly unavailable API costs latency, not data.
func CaptureManualCrawlBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding batch capture request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	scopeTargetID, err := resolveActiveCrawlSession(req.SessionID)
	if err != nil {
		respondSessionError(w, err)
		return
	}

	if len(req.Captures) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "stored": 0})
		return
	}

	stored, err := insertManualCrawlCaptures(req.SessionID, scopeTargetID, req.Captures)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error storing capture batch: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store captures")
		return
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error refreshing session counts: %v", err)
	}

	if stored < len(req.Captures) {
		log.Printf("[MANUAL-CRAWL] Stored %d/%d captures for session %s (%d unstorable)",
			stored, len(req.Captures), req.SessionID, len(req.Captures)-stored)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"stored":        stored,
		"received":      len(req.Captures),
		"rejected":      len(req.Captures) - stored,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

// PostgreSQL text and jsonb columns cannot hold a NUL byte, and captured bodies genuinely contain
// them (a response with a texty content-type but binary payload, or JSON carrying an escaped
// null). A single such byte used to fail the whole multi-row INSERT, silently destroying every
// other capture batched with it. Strip them, and drop anything else that is not valid UTF-8.
func sanitizeForPostgres(s string) string {
	if s == "" {
		return s
	}
	if !strings.ContainsRune(s, 0) && utf8.ValidString(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0:
			// dropped: not representable in a Postgres text column
		case r == utf8.RuneError:
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeJSONValue walks a decoded JSON value and cleans every string it contains, so header maps
// and parameter maps are safe to store as jsonb.
func sanitizeJSONValue(v interface{}) interface{} {
	switch typed := v.(type) {
	case string:
		return sanitizeForPostgres(typed)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, value := range typed {
			out[sanitizeForPostgres(key)] = sanitizeJSONValue(value)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, value := range typed {
			out[i] = sanitizeJSONValue(value)
		}
		return out
	default:
		return v
	}
}

func sanitizeJSONMap(m map[string]interface{}) map[string]interface{} {
	cleaned, _ := sanitizeJSONValue(orEmptyMap(m)).(map[string]interface{})
	if cleaned == nil {
		return map[string]interface{}{}
	}
	return cleaned
}

// insertManualCrawlCaptures writes captures with a single multi-row INSERT, falling back to
// one-row-at-a-time on failure so a single unstorable capture costs one record instead of the
// whole batch.
func insertManualCrawlCaptures(sessionID, scopeTargetID string, captures []CaptureRequest) (int, error) {
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)

	stored, err := insertCaptureBatch(sessionID, scopeTargetID, targetDomain, captures)
	if err == nil {
		return stored, nil
	}

	log.Printf("[MANUAL-CRAWL] Batch insert failed (%v); retrying %d captures individually", err, len(captures))

	inserted := 0
	var lastErr error
	for _, capture := range captures {
		one, oneErr := insertCaptureBatch(sessionID, scopeTargetID, targetDomain, []CaptureRequest{capture})
		if oneErr != nil {
			lastErr = oneErr
			log.Printf("[MANUAL-CRAWL] Dropping unstorable capture %s %s: %v", capture.Method, capture.URL, oneErr)
			continue
		}
		inserted += one
	}

	if inserted == 0 && lastErr != nil {
		return 0, lastErr
	}
	return inserted, nil
}

func insertCaptureBatch(sessionID, scopeTargetID, targetDomain string, captures []CaptureRequest) (int, error) {
	const columnCount = 27

	valueGroups := make([]string, 0, len(captures))
	args := make([]interface{}, 0, len(captures)*columnCount)

	for _, capture := range captures {
		if strings.TrimSpace(capture.URL) == "" {
			continue
		}

		timestamp, err := time.Parse(time.RFC3339, capture.Timestamp)
		if err != nil {
			timestamp = time.Now()
		}

		method := strings.ToUpper(strings.TrimSpace(capture.Method))
		if method == "" {
			method = "GET"
		}
		// The column is VARCHAR(10); a malformed method must not fail the whole batch.
		if len(method) > 10 {
			method = method[:10]
		}

		endpoint := capture.Endpoint
		if endpoint == "" {
			endpoint = capture.URL
		}

		// Same host as the scope target is direct; anything else in scope is adjacent. Matches the
		// rule the crawlers and the consolidation step already use.
		isDirect := false
		if parsed, perr := url.Parse(capture.URL); perr == nil && targetDomain != "" {
			isDirect = strings.EqualFold(parsed.Hostname(), targetDomain)
		}

		headersJSON, _ := json.Marshal(sanitizeJSONMap(capture.Headers))
		responseHeadersJSON, _ := json.Marshal(sanitizeJSONMap(capture.ResponseHeaders))
		getParamsJSON, _ := json.Marshal(sanitizeJSONMap(capture.GetParams))
		postParamsJSON, _ := json.Marshal(sanitizeJSONMap(capture.PostParams))

		redirectChain := capture.RedirectChain
		if redirectChain == nil {
			redirectChain = []interface{}{}
		}
		redirectChainJSON, _ := json.Marshal(sanitizeJSONValue(redirectChain))

		sources := capture.Sources
		if sources == nil {
			sources = []string{}
		}

		base := len(args)
		placeholders := make([]string, columnCount)
		for i := 0; i < columnCount; i++ {
			placeholders[i] = fmt.Sprintf("$%d", base+i+1)
		}
		valueGroups = append(valueGroups, "("+strings.Join(placeholders, ", ")+")")

		args = append(args,
			uuid.New().String(),
			sessionID,
			scopeTargetID,
			sanitizeForPostgres(capture.URL),
			sanitizeForPostgres(endpoint),
			method,
			capture.StatusCode,
			headersJSON,
			responseHeadersJSON,
			sanitizeForPostgres(capture.PostData),
			sanitizeForPostgres(capture.ResponseBody),
			getParamsJSON,
			postParamsJSON,
			sanitizeForPostgres(capture.BodyType),
			capture.TabID,
			timestamp,
			sanitizeForPostgres(capture.MimeType),
			sources,
			sanitizeForPostgres(capture.GraphQLOperation),
			sanitizeForPostgres(capture.ResourceType),
			sanitizeForPostgres(capture.Initiator),
			redirectChainJSON,
			sanitizeForPostgres(capture.Error),
			capture.DurationMs,
			capture.RequestBodyTruncated,
			capture.ResponseBodyTruncated,
			isDirect,
		)
	}

	if len(valueGroups) == 0 {
		return 0, nil
	}

	query := `
		INSERT INTO manual_crawl_captures
		(id, session_id, scope_target_id, url, endpoint, method, status_code, headers, response_headers,
		 post_data, response_body, get_params, post_params, body_type, tab_id, timestamp, mime_type,
		 sources, graphql_operation, resource_type, initiator, redirect_chain, error, duration_ms,
		 request_body_truncated, response_body_truncated, is_direct)
		VALUES ` + strings.Join(valueGroups, ", ")

	if _, err := dbPool.Exec(context.Background(), query, args...); err != nil {
		return 0, err
	}

	return len(valueGroups), nil
}

func orEmptyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

// refreshManualCrawlSessionCounts recomputes the session totals from the captures actually stored
// and stamps the heartbeat. Counts used to be written only on an explicit stop, so any session that
// died reported zero forever.
func refreshManualCrawlSessionCounts(sessionID string) (int, int, error) {
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		SET request_count = c.request_count,
		    endpoint_count = c.endpoint_count,
		    last_heartbeat_at = NOW()
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, sessionID).Scan(&requestCount, &endpointCount)
	return requestCount, endpointCount, err
}

// HeartbeatManualCrawl keeps a session marked live while the extension is still recording. Without
// it the framework cannot tell a real recording from one whose service worker was terminated.
func HeartbeatManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SessionStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if _, err := resolveActiveCrawlSession(req.SessionID); err != nil {
		respondSessionError(w, err)
		return
	}

	if len(req.ObservedOutOfScope) > 0 {
		if payload, mErr := json.Marshal(req.ObservedOutOfScope); mErr == nil {
			if _, uErr := dbPool.Exec(context.Background(),
				`UPDATE manual_crawl_sessions SET observed_out_of_scope = $1 WHERE id = $2`,
				payload, req.SessionID); uErr != nil {
				log.Printf("[MANUAL-CRAWL] Failed to record out-of-scope hosts: %v", uErr)
			}
		}
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Heartbeat failed for session %s: %v", req.SessionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to record heartbeat")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"sessionId":     req.SessionID,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

func StopManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SessionStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding stop request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if strings.TrimSpace(req.SessionID) == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id_required", "sessionId is required")
		return
	}

	// Stop is idempotent on purpose: the extension may retry it, and stopping an already-stopped
	// session should not surface an error to the user.
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		SET status = 'completed',
		    ended_at = NOW(),
		    request_count = c.request_count,
		    endpoint_count = c.endpoint_count
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, req.SessionID).Scan(&requestCount, &endpointCount)

	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error stopping session %s: %v", req.SessionID, err)
		writeJSONError(w, http.StatusNotFound, "session_not_found", "Unknown capture session")
		return
	}

	log.Printf("[MANUAL-CRAWL] Stopped session %s. Requests: %d, Endpoints: %d",
		req.SessionID, requestCount, endpointCount)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"sessionId":     req.SessionID,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

const manualCrawlSessionSelect = `
	SELECT id, scope_target_id, target_url, status, started_at, ended_at, last_heartbeat_at,
	       request_count, endpoint_count, COALESCE(observed_out_of_scope, '{}'::jsonb)
	FROM manual_crawl_sessions`

func scanManualCrawlSessions(rows interface {
	Next() bool
	Scan(...interface{}) error
}) []ManualCrawlSession {
	sessions := make([]ManualCrawlSession, 0)
	for rows.Next() {
		var session ManualCrawlSession
		var endedAt, lastHeartbeatAt *time.Time
		var outOfScopeJSON []byte

		err := rows.Scan(
			&session.ID,
			&session.ScopeTargetID,
			&session.TargetURL,
			&session.Status,
			&session.StartedAt,
			&endedAt,
			&lastHeartbeatAt,
			&session.RequestCount,
			&session.EndpointCount,
			&outOfScopeJSON,
		)
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning session: %v", err)
			continue
		}

		if len(outOfScopeJSON) > 0 {
			json.Unmarshal(outOfScopeJSON, &session.ObservedOutOfScope)
		}
		session.EndedAt = endedAt
		session.LastHeartbeatAt = lastHeartbeatAt
		session.IsLive = isManualCrawlSessionLive(session.Status, lastHeartbeatAt)
		sessions = append(sessions, session)
	}
	return sessions
}

// isManualCrawlSessionLive is the single definition of "actively recording" used by every surface,
// so the framework card, the results modal, and cleanup cannot disagree.
func isManualCrawlSessionLive(status string, lastHeartbeatAt *time.Time) bool {
	if status != "active" {
		return false
	}
	if lastHeartbeatAt == nil {
		return false
	}
	return time.Since(*lastHeartbeatAt) <= manualCrawlHeartbeatTimeout
}

func GetManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	rows, err := dbPool.Query(context.Background(),
		manualCrawlSessionSelect+` WHERE scope_target_id = $1 ORDER BY started_at DESC`, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query sessions")
		return
	}
	defer rows.Close()

	json.NewEncoder(w).Encode(scanManualCrawlSessions(rows))
}

func GetAllManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := dbPool.Query(context.Background(),
		manualCrawlSessionSelect+` ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying all sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query all sessions")
		return
	}
	defer rows.Close()

	sessions := scanManualCrawlSessions(rows)
	log.Printf("[MANUAL-CRAWL] Returning %d total sessions", len(sessions))
	json.NewEncoder(w).Encode(sessions)
}

// CleanupStaleSessions closes sessions whose extension stopped heartbeating. The old version only
// closed sessions with request_count = 0, and request_count was only written on a clean stop, so
// any session that captured anything and then died stayed 'active' forever.
func CleanupStaleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cutoff := time.Now().Add(-manualCrawlHeartbeatTimeout)

	rows, err := dbPool.Query(context.Background(), `
		UPDATE manual_crawl_sessions
		SET status = 'abandoned',
		    ended_at = COALESCE(last_heartbeat_at, started_at)
		WHERE status = 'active'
		  AND COALESCE(last_heartbeat_at, started_at) < $1
		RETURNING id`, cutoff)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error cleaning up stale sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to cleanup sessions")
		return
	}
	defer rows.Close()

	staleIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			staleIDs = append(staleIDs, id)
		}
	}
	rows.Close()

	// Backfill counts for the sessions we just closed so their captures are not reported as zero.
	for _, id := range staleIDs {
		if _, _, err := refreshManualCrawlSessionCountsPreservingStatus(id); err != nil {
			log.Printf("[MANUAL-CRAWL] Failed to backfill counts for stale session %s: %v", id, err)
		}
		log.Printf("[MANUAL-CRAWL] Cleaned up stale session: %s", id)
	}

	log.Printf("[MANUAL-CRAWL] Cleaned up %d stale sessions", len(staleIDs))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"cleaned": len(staleIDs),
	})
}

// refreshManualCrawlSessionCountsPreservingStatus recomputes counts without touching the heartbeat,
// used when closing out a session that is already known to be dead.
func refreshManualCrawlSessionCountsPreservingStatus(sessionID string) (int, int, error) {
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		SET request_count = c.request_count,
		    endpoint_count = c.endpoint_count
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, sessionID).Scan(&requestCount, &endpointCount)
	return requestCount, endpointCount, err
}

func GetManualCrawlCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sessionID := mux.Vars(r)["session_id"]

	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id_required", "session_id is required")
		return
	}

	query := `
		SELECT id, session_id, scope_target_id, url, endpoint, method, status_code,
		       headers, response_headers, post_data, response_body, get_params, post_params,
		       body_type, tab_id, timestamp, mime_type, sources, graphql_operation, resource_type,
		       initiator, redirect_chain, error, duration_ms, request_body_truncated,
		       response_body_truncated, COALESCE(is_direct, false)
		FROM manual_crawl_captures
		WHERE session_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, sessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying captures: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query captures")
		return
	}
	defer rows.Close()

	json.NewEncoder(w).Encode(scanManualCrawlCaptures(rows))
}

// GetManualCrawlCapturesForTarget returns every capture for a scope target in one call. The results
// modal used to fetch captures session-by-session in a loop driven by possibly-stale state.
func GetManualCrawlCapturesForTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	query := `
		SELECT id, session_id, scope_target_id, url, endpoint, method, status_code,
		       headers, response_headers, post_data, response_body, get_params, post_params,
		       body_type, tab_id, timestamp, mime_type, sources, graphql_operation, resource_type,
		       initiator, redirect_chain, error, duration_ms, request_body_truncated,
		       response_body_truncated, COALESCE(is_direct, false)
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying captures for target: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query captures")
		return
	}
	defer rows.Close()

	json.NewEncoder(w).Encode(scanManualCrawlCaptures(rows))
}

func scanManualCrawlCaptures(rows interface {
	Next() bool
	Scan(...interface{}) error
}) []ManualCrawlCapture {
	captures := make([]ManualCrawlCapture, 0)
	for rows.Next() {
		var capture ManualCrawlCapture
		var headersJSON, responseHeadersJSON, getParamsJSON, postParamsJSON, redirectChainJSON []byte
		var bodyType, postData, responseBody, mimeType *string
		var graphqlOperation, resourceType, initiator, captureError *string
		var statusCode, tabID, durationMs *int
		var requestBodyTruncated, responseBodyTruncated *bool

		err := rows.Scan(
			&capture.ID,
			&capture.SessionID,
			&capture.ScopeTargetID,
			&capture.URL,
			&capture.Endpoint,
			&capture.Method,
			&statusCode,
			&headersJSON,
			&responseHeadersJSON,
			&postData,
			&responseBody,
			&getParamsJSON,
			&postParamsJSON,
			&bodyType,
			&tabID,
			&capture.Timestamp,
			&mimeType,
			&capture.Sources,
			&graphqlOperation,
			&resourceType,
			&initiator,
			&redirectChainJSON,
			&captureError,
			&durationMs,
			&requestBodyTruncated,
			&responseBodyTruncated,
			&capture.IsDirect,
		)
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning capture: %v", err)
			continue
		}

		if statusCode != nil {
			capture.StatusCode = *statusCode
		}
		if postData != nil {
			capture.PostData = *postData
		}
		if responseBody != nil {
			capture.ResponseBody = *responseBody
		}
		if bodyType != nil {
			capture.BodyType = *bodyType
		}
		if mimeType != nil {
			capture.MimeType = *mimeType
		}
		if graphqlOperation != nil {
			capture.GraphQLOperation = *graphqlOperation
		}
		if resourceType != nil {
			capture.ResourceType = *resourceType
		}
		if initiator != nil {
			capture.Initiator = *initiator
		}
		if captureError != nil {
			capture.Error = *captureError
		}
		if durationMs != nil {
			capture.DurationMs = *durationMs
		}
		if requestBodyTruncated != nil {
			capture.RequestBodyTruncated = *requestBodyTruncated
		}
		if responseBodyTruncated != nil {
			capture.ResponseBodyTruncated = *responseBodyTruncated
		}
		if capture.Sources == nil {
			capture.Sources = []string{}
		}
		if len(redirectChainJSON) > 0 {
			json.Unmarshal(redirectChainJSON, &capture.RedirectChain)
		}
		capture.TabID = tabID

		json.Unmarshal(headersJSON, &capture.Headers)
		json.Unmarshal(responseHeadersJSON, &capture.ResponseHeaders)
		if len(getParamsJSON) > 0 {
			json.Unmarshal(getParamsJSON, &capture.GetParams)
		}
		if len(postParamsJSON) > 0 {
			json.Unmarshal(postParamsJSON, &capture.PostParams)
		}

		captures = append(captures, capture)
	}
	return captures
}

func GetManualCrawlEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	query := `
		SELECT capture_host(url) AS host, endpoint, method, COUNT(*) as request_count,
		       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
		       bool_or(COALESCE(is_direct, false)) as is_direct
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		GROUP BY capture_host(url), endpoint, method
		ORDER BY last_seen DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying endpoints: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query endpoints")
		return
	}
	defer rows.Close()

	type EndpointSummary struct {
		Host         string    `json:"host"`
		Endpoint     string    `json:"endpoint"`
		Method       string    `json:"method"`
		RequestCount int       `json:"request_count"`
		FirstSeen    time.Time `json:"first_seen"`
		LastSeen     time.Time `json:"last_seen"`
		IsDirect     bool      `json:"is_direct"`
	}

	endpoints := make([]EndpointSummary, 0)
	for rows.Next() {
		var ep EndpointSummary
		if err := rows.Scan(&ep.Host, &ep.Endpoint, &ep.Method, &ep.RequestCount, &ep.FirstSeen, &ep.LastSeen, &ep.IsDirect); err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning endpoint: %v", err)
			continue
		}
		endpoints = append(endpoints, ep)
	}

	json.NewEncoder(w).Encode(endpoints)
}
