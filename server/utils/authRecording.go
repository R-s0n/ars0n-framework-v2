package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// Browser-extension recording of an authentication flow.
//
// A recording is the raw, ordered truth of what the browser did during one login, registration,
// MFA challenge, magic link or password reset. Everything here exists to preserve that order and
// then hand it to the replay engine in authFlowsUtils.go as an auth_flows row with one step per
// request.
//
// Captures are deliberately UNFILTERED BY SCOPE. An auth flow routinely crosses to an identity
// provider on a different domain: the app posts to accounts.google.com, or to an Auth0 tenant, or
// to a corporate SSO host, and comes back with the token. Filtering the recording by the scope
// target's domain would cut the flow exactly where the interesting part is and leave a "flow" that
// cannot reproduce a session. Recording is observation, not traffic we generate, so the scope
// boundary enforced in scanScope.go does not apply to it. Replay is a different matter: that sends
// requests, and the operator sees every host in the step list before they press it.
//
// The JSON the extension posts to /auth-recording/capture is snake_case, matching the rest of this
// contract:
//
//	{"recording_id": "...", "requests": [{
//	   "seq": 1, "method": "POST", "url": "https://...", "host": "...",
//	   "raw_request": "POST /login HTTP/1.1\r\n...", "request_headers": {...}, "request_body": "...",
//	   "response_status": 200, "response_headers": {...}, "response_body": "...",
//	   "set_cookies": ["session=...; Path=/; HttpOnly"], "resource_type": "xmlhttprequest",
//	   "duration_ms": 120, "included": true, "occurred_at": "2026-08-03T12:00:00Z"
//	}]}
//
// Every field except url is optional. raw_request is rebuilt from method, url, headers and body
// when the extension cannot supply it, because raw_request is what replay parses and the column is
// NOT NULL.

// Categories a recording may carry. This repeats rather than reuses validAuthFlowCategories from
// authFlowsUtils.go on purpose: the auth_flows CHECK constraint was widened to include magic_link
// and that older map was not updated, so validating against it would refuse to import exactly the
// flow the extension was built to record.
var validAuthRecordingCategories = map[string]bool{
	"register":   true,
	"login":      true,
	"mfa_otp":    true,
	"magic_link": true,
	"reset":      true,
}

// Resource types the browser reports for subresources that are never part of an authentication
// exchange. These are marked included=false on the way in so the generated flow is the auth
// requests and not two hundred 200s for images. The rows are kept: a request excluded from the flow
// is still evidence, and deleting it would punch holes in the sequence, which is the one thing a
// recording exists to preserve.
var authRecordingNoiseResourceTypes = map[string]bool{
	"image":      true,
	"font":       true,
	"stylesheet": true,
	"media":      true,
	"script":     true,
	// The same things under the spellings Chrome and Firefox actually emit.
	"img":        true,
	"imageset":   true,
	"css":        true,
	"ping":       true,
	"beacon":     true,
	"csp_report": true,
}

// Extensions that mark a URL as a static asset regardless of what resource_type says, because
// resource_type is empty on anything the extension saw through the debugger rather than webRequest.
//
// isStaticAsset in urlScanUtils.go is deliberately not reused here: it counts .json, .xml and .txt
// as static, and POST /api/v1/login.json is precisely the request that must survive into the flow.
var authRecordingStaticExtensions = []string{
	".css", ".js", ".mjs", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".tiff",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".webm", ".ogg", ".mp3", ".wav", ".m4a",
	".pdf", ".zip", ".gz",
}

// AuthRecording is the recording header row as the UI reads it.
type AuthRecording struct {
	ID            string     `json:"id"`
	ScopeTargetID string     `json:"scope_target_id"`
	Name          string     `json:"name"`
	Category      string     `json:"category"`
	Status        string     `json:"status"`
	BaseURL       string     `json:"base_url"`
	Notes         string     `json:"notes"`
	RequestCount  int        `json:"request_count"`
	IncludedCount int        `json:"included_count"`
	AuthFlowID    *string    `json:"auth_flow_id"`
	StartedAt     *time.Time `json:"started_at"`
	StoppedAt     *time.Time `json:"stopped_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	CreatedAt     *time.Time `json:"created_at"`
}

// AuthRecordedRequest is one captured exchange, returned in seq order.
type AuthRecordedRequest struct {
	ID              string                 `json:"id"`
	RecordingID     string                 `json:"recording_id"`
	Seq             int                    `json:"seq"`
	Method          string                 `json:"method"`
	URL             string                 `json:"url"`
	Host            string                 `json:"host"`
	RawRequest      string                 `json:"raw_request"`
	RequestHeaders  map[string]interface{} `json:"request_headers"`
	RequestBody     string                 `json:"request_body"`
	ResponseStatus  *int                   `json:"response_status"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	ResponseBody    string                 `json:"response_body"`
	SetCookies      []string               `json:"set_cookies"`
	ResourceType    string                 `json:"resource_type"`
	DurationMs      int                    `json:"duration_ms"`
	Included        bool                   `json:"included"`
	OccurredAt      *time.Time             `json:"occurred_at"`
}

// AuthRecordedRequestInput is one exchange as the extension posts it.
type AuthRecordedRequestInput struct {
	// Seq is honoured when the extension supplies it, because the extension is the only thing that
	// knows the true order of two requests it observed in the same millisecond. Zero means "you
	// assign it".
	Seq             int                    `json:"seq"`
	Method          string                 `json:"method"`
	URL             string                 `json:"url"`
	Host            string                 `json:"host"`
	RawRequest      string                 `json:"raw_request"`
	RequestHeaders  map[string]interface{} `json:"request_headers"`
	RequestBody     string                 `json:"request_body"`
	ResponseStatus  *int                   `json:"response_status"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	ResponseBody    string                 `json:"response_body"`
	SetCookies      []interface{}          `json:"set_cookies"`
	ResourceType    string                 `json:"resource_type"`
	DurationMs      int                    `json:"duration_ms"`
	// Included overrides the static-noise default. A pointer so "the extension said nothing" is
	// distinguishable from "the extension said false".
	Included *bool `json:"included"`
	// OccurredAt is interface{} because the extension has Date.now() to hand and sending a number is
	// the obvious thing to do. Typing this as a string would fail the decode of the whole batch over
	// a timestamp, which is the least important field in the row.
	OccurredAt interface{} `json:"occurred_at"`
}

// ---------------------------------------------------------------------------
// Sequence allocation
// ---------------------------------------------------------------------------

// Sequence is the point of a recording. Two batch posts can be in flight at once (the extension
// flushes on a timer and again on navigation), and both would otherwise compute the same "next"
// number from MAX(seq) and collide. The counter is per recording and held across the whole
// allocation, so a concurrent flush gets the block after this one rather than the same block.
//
// UNIQUE(recording_id, seq) is the backstop, and the insert uses ON CONFLICT DO NOTHING, so an
// extension that retries a batch it already delivered writes nothing instead of duplicating steps.
var (
	authRecordingSeqMu sync.Mutex
	authRecordingSeq   = map[string]int{}
)

// allocAuthRecordingSeqs returns the sequence number to use for each input, honouring any the
// extension supplied and assigning the rest from the per-recording counter.
func allocAuthRecordingSeqs(recordingID string, inputs []AuthRecordedRequestInput) []int {
	authRecordingSeqMu.Lock()
	defer authRecordingSeqMu.Unlock()

	counter, known := authRecordingSeq[recordingID]
	if !known {
		// Seed from what is already stored. An API restart in the middle of a recording must not
		// restart numbering at 1: every reused number would be swallowed by ON CONFLICT DO NOTHING
		// and the rest of the flow would vanish without an error anywhere.
		var maxSeq int
		if err := dbPool.QueryRow(context.Background(),
			`SELECT COALESCE(MAX(seq), 0) FROM auth_recorded_requests WHERE recording_id = $1`,
			recordingID).Scan(&maxSeq); err != nil {
			log.Printf("[AUTH-RECORDING] Could not read current seq for %s, starting from 0: %v", recordingID, err)
		}
		counter = maxSeq
	}

	seqs := make([]int, len(inputs))
	for i, input := range inputs {
		if input.Seq > 0 {
			seqs[i] = input.Seq
			if input.Seq > counter {
				counter = input.Seq
			}
			continue
		}
		counter++
		seqs[i] = counter
	}

	authRecordingSeq[recordingID] = counter
	return seqs
}

func forgetAuthRecordingSeq(recordingID string) {
	authRecordingSeqMu.Lock()
	delete(authRecordingSeq, recordingID)
	authRecordingSeqMu.Unlock()
}

// ---------------------------------------------------------------------------
// Start / capture / heartbeat / stop
// ---------------------------------------------------------------------------

// StartAuthRecording handles POST /auth-recording/start.
func StartAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		ScopeTargetID string `json:"scope_target_id"`
		Name          string `json:"name"`
		Category      string `json:"category"`
		BaseURL       string `json:"base_url"`
		Notes         string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if strings.TrimSpace(payload.ScopeTargetID) == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}
	if _, err := uuid.Parse(payload.ScopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_not_found", "Invalid scope_target_id")
		return
	}

	category := strings.ToLower(strings.TrimSpace(payload.Category))
	if category == "" {
		category = "login"
	}
	if !validAuthRecordingCategories[category] {
		writeJSONError(w, http.StatusBadRequest, "invalid_category",
			"category must be register, login, mfa_otp, magic_link or reset")
		return
	}

	var exists bool
	if err := dbPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1)`, payload.ScopeTargetID).Scan(&exists); err != nil || !exists {
		writeJSONError(w, http.StatusBadRequest, "scope_target_not_found", "Unknown scope_target_id")
		return
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = fmt.Sprintf("%s recording %s", category, time.Now().Format("2006-01-02 15:04"))
	}

	// Close out anything still marked as recording for this target. A target recording twice at once
	// is always a stale row from a browser that was closed without stopping, and leaving it there
	// makes GetActiveAuthRecording hand the extension a dead recording to write into.
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE auth_recordings
		SET status = 'abandoned', stopped_at = COALESCE(last_seen_at, started_at)
		WHERE scope_target_id = $1 AND status = 'recording'`, payload.ScopeTargetID); err != nil {
		log.Printf("[AUTH-RECORDING] Failed to abandon previous recordings for %s: %v", payload.ScopeTargetID, err)
	}

	recordingID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO auth_recordings
		  (id, scope_target_id, name, category, status, base_url, notes, request_count,
		   started_at, last_seen_at)
		VALUES ($1, $2, $3, $4, 'recording', $5, $6, 0, NOW(), NOW())`,
		recordingID, payload.ScopeTargetID, sanitizeForPostgres(name), category,
		sanitizeForPostgres(strings.TrimSpace(payload.BaseURL)), sanitizeForPostgres(payload.Notes)); err != nil {
		log.Printf("[AUTH-RECORDING] Failed to create recording: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to start recording")
		return
	}

	forgetAuthRecordingSeq(recordingID)
	log.Printf("[AUTH-RECORDING] Started %s recording %s for target %s", category, recordingID, payload.ScopeTargetID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"recording_id":    recordingID,
		"scope_target_id": payload.ScopeTargetID,
		"name":            name,
		"category":        category,
		"status":          "recording",
	})
}

// CaptureAuthRecordingRequests handles POST /auth-recording/capture.
//
// Captures are accepted for a recording that has already stopped. Stop races with the extension's
// final flush, and the request that loses that race is the last one of the flow, which is usually
// the one that returns the session token. The rows are stored and the response says the recording
// was no longer live, so the operator can re-import and pick them up.
func CaptureAuthRecordingRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		RecordingID string                     `json:"recording_id"`
		Requests    []AuthRecordedRequestInput `json:"requests"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	status, err := lookupAuthRecordingStatus(payload.RecordingID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "recording_not_found", "Unknown recording")
		return
	}

	if len(payload.Requests) == 0 {
		total, _ := refreshAuthRecordingCounts(payload.RecordingID)
		json.NewEncoder(w).Encode(map[string]interface{}{"stored": 0, "total": total, "status": status})
		return
	}

	stored, err := insertAuthRecordedRequests(payload.RecordingID, payload.Requests)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to store captures for %s: %v", payload.RecordingID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store captured requests")
		return
	}

	total, err := refreshAuthRecordingCounts(payload.RecordingID)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to refresh counts for %s: %v", payload.RecordingID, err)
	}

	if stored < len(payload.Requests) {
		// Not an error on its own: a retried batch is expected to store nothing.
		log.Printf("[AUTH-RECORDING] Stored %d/%d captures for recording %s",
			stored, len(payload.Requests), payload.RecordingID)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"stored":   stored,
		"received": len(payload.Requests),
		"total":    total,
		"status":   status,
	})
}

// HeartbeatAuthRecording handles POST /auth-recording/heartbeat. It stamps last_seen_at so a
// recording whose extension died is distinguishable from one the operator is still driving.
func HeartbeatAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		RecordingID string `json:"recording_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	status, err := lookupAuthRecordingStatus(payload.RecordingID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "recording_not_found", "Unknown recording")
		return
	}

	total, err := refreshAuthRecordingCounts(payload.RecordingID)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Heartbeat failed for %s: %v", payload.RecordingID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to record heartbeat")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":            true,
		"recording_id":  payload.RecordingID,
		"status":        status,
		"request_count": total,
	})
}

// StopAuthRecording handles POST /auth-recording/stop.
//
// Stopping auto-imports: the operator just performed a login in the browser and the thing they want
// is a replayable flow, not a list of requests they then have to convert by hand. Import failure is
// logged and reported rather than failing the stop, because a recording that stopped without
// generating a flow is still worth keeping and can be imported again once the cause is fixed.
func StopAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		RecordingID string `json:"recording_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if _, err := uuid.Parse(strings.TrimSpace(payload.RecordingID)); err != nil {
		writeJSONError(w, http.StatusBadRequest, "recording_id_required", "recording_id is required")
		return
	}

	// Stop is idempotent. The extension retries it when the popup closes mid-request, and stopping an
	// already-stopped recording must not look like a failure to the operator.
	var requestCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE auth_recordings a
		SET status = 'stopped',
		    stopped_at = COALESCE(a.stopped_at, NOW()),
		    last_seen_at = NOW(),
		    request_count = c.total
		FROM (SELECT COUNT(*) AS total FROM auth_recorded_requests WHERE recording_id = $1) c
		WHERE a.id = $1
		RETURNING a.request_count`, payload.RecordingID).Scan(&requestCount)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to stop recording %s: %v", payload.RecordingID, err)
		writeJSONError(w, http.StatusNotFound, "recording_not_found", "Unknown recording")
		return
	}

	response := map[string]interface{}{
		"recording_id":  payload.RecordingID,
		"request_count": requestCount,
		"auth_flow_id":  nil,
		"steps":         0,
	}

	flowID, steps, importErr := importAuthRecordingToFlow(context.Background(), payload.RecordingID, "", "")
	if importErr != nil {
		log.Printf("[AUTH-RECORDING] Stopped %s but could not build a flow: %v", payload.RecordingID, importErr)
		response["import_error"] = importErr.Error()
	} else {
		response["auth_flow_id"] = flowID
		response["steps"] = steps
		log.Printf("[AUTH-RECORDING] Stopped %s, imported %d step(s) into auth flow %s",
			payload.RecordingID, steps, flowID)
	}

	forgetAuthRecordingSeq(payload.RecordingID)
	json.NewEncoder(w).Encode(response)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

const authRecordingSelect = `
	SELECT a.id, a.scope_target_id, a.name, a.category, a.status, COALESCE(a.base_url,''),
	       COALESCE(a.notes,''), COALESCE(a.request_count,0), a.auth_flow_id,
	       a.started_at, a.stopped_at, a.last_seen_at, a.created_at,
	       (SELECT COUNT(*) FROM auth_recorded_requests q
	         WHERE q.recording_id = a.id AND q.included) AS included_count
	FROM auth_recordings a`

func scanAuthRecording(row interface{ Scan(...interface{}) error }) (AuthRecording, error) {
	var rec AuthRecording
	err := row.Scan(&rec.ID, &rec.ScopeTargetID, &rec.Name, &rec.Category, &rec.Status, &rec.BaseURL,
		&rec.Notes, &rec.RequestCount, &rec.AuthFlowID, &rec.StartedAt, &rec.StoppedAt,
		&rec.LastSeenAt, &rec.CreatedAt, &rec.IncludedCount)
	return rec, err
}

// GetAuthRecordingsForTarget handles GET /auth-recording/target/{scope_target_id}.
func GetAuthRecordingsForTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	rows, err := dbPool.Query(context.Background(),
		authRecordingSelect+` WHERE a.scope_target_id = $1 ORDER BY a.created_at DESC`, scopeTargetID)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to query recordings for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query recordings")
		return
	}
	defer rows.Close()

	recordings := make([]AuthRecording, 0)
	for rows.Next() {
		rec, err := scanAuthRecording(rows)
		if err != nil {
			log.Printf("[AUTH-RECORDING] Failed to scan recording: %v", err)
			continue
		}
		recordings = append(recordings, rec)
	}

	json.NewEncoder(w).Encode(recordings)
}

// GetActiveAuthRecording handles GET /auth-recording/active/{scope_target_id}.
//
// This is how the extension discovers it is meant to be recording. The operator presses Start in the
// framework UI, not in the extension, so the extension polls this and starts capturing when a
// recording appears. Newest first, because Start abandons any older row and only the newest can be
// the live one.
func GetActiveAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	row := dbPool.QueryRow(context.Background(),
		authRecordingSelect+` WHERE a.scope_target_id = $1 AND a.status = 'recording'
		 ORDER BY a.created_at DESC LIMIT 1`, scopeTargetID)

	rec, err := scanAuthRecording(row)
	if err != nil {
		// No live recording is the normal state, not an error. The extension polls this constantly.
		//
		// A real database failure is not the same thing, though, and answering "nothing is
		// recording" to both means an outage looks exactly like an idle target: the extension stops
		// capturing and the operator watches a recording that silently collects nothing. Only
		// pgx.ErrNoRows means idle; anything else is reported so it can be seen.
		if errors.Is(err, pgx.ErrNoRows) {
			json.NewEncoder(w).Encode(map[string]interface{}{"recording": nil})
			return
		}
		log.Printf("[AUTH-RECORDING] Failed to read the active recording for %s: %v", scopeTargetID, err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"recording": nil,
			"error":     "Could not read the active recording: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"recording": rec})
}

// GetAuthRecordingRequests handles GET /auth-recording/{recording_id}/requests.
func GetAuthRecordingRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	recordingID := mux.Vars(r)["recording_id"]

	if _, err := uuid.Parse(recordingID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "recording_id_required", "recording_id is required")
		return
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, recording_id, seq, method, url, COALESCE(host,''), raw_request,
		       COALESCE(request_headers,'{}'::jsonb), COALESCE(request_body,''),
		       response_status, COALESCE(response_headers,'{}'::jsonb), COALESCE(response_body,''),
		       COALESCE(set_cookies,'[]'::jsonb), COALESCE(resource_type,''),
		       COALESCE(duration_ms,0), COALESCE(included,true), occurred_at
		FROM auth_recorded_requests
		WHERE recording_id = $1
		ORDER BY seq ASC`, recordingID)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to query requests for %s: %v", recordingID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query recorded requests")
		return
	}
	defer rows.Close()

	requests := make([]AuthRecordedRequest, 0)
	for rows.Next() {
		var req AuthRecordedRequest
		var requestHeadersJSON, responseHeadersJSON, setCookiesJSON []byte

		if err := rows.Scan(&req.ID, &req.RecordingID, &req.Seq, &req.Method, &req.URL, &req.Host,
			&req.RawRequest, &requestHeadersJSON, &req.RequestBody, &req.ResponseStatus,
			&responseHeadersJSON, &req.ResponseBody, &setCookiesJSON, &req.ResourceType,
			&req.DurationMs, &req.Included, &req.OccurredAt); err != nil {
			log.Printf("[AUTH-RECORDING] Failed to scan recorded request: %v", err)
			continue
		}

		json.Unmarshal(requestHeadersJSON, &req.RequestHeaders)
		json.Unmarshal(responseHeadersJSON, &req.ResponseHeaders)
		json.Unmarshal(setCookiesJSON, &req.SetCookies)
		if req.RequestHeaders == nil {
			req.RequestHeaders = map[string]interface{}{}
		}
		if req.ResponseHeaders == nil {
			req.ResponseHeaders = map[string]interface{}{}
		}
		if req.SetCookies == nil {
			req.SetCookies = []string{}
		}

		requests = append(requests, req)
	}

	json.NewEncoder(w).Encode(requests)
}

// UpdateAuthRecordedRequests handles PATCH /auth-recording/{recording_id}/requests.
//
// Only the included flag moves. Excluding a request never deletes it, so the operator can uncheck
// a noisy request, import, decide they needed it after all, re-check it and re-import. The recording
// itself is never edited: it is the record of what happened.
func UpdateAuthRecordedRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	recordingID := mux.Vars(r)["recording_id"]

	if _, err := uuid.Parse(recordingID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "recording_id_required", "recording_id is required")
		return
	}

	var payload struct {
		IDs      []string `json:"ids"`
		Included *bool    `json:"included"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if payload.Included == nil {
		writeJSONError(w, http.StatusBadRequest, "included_required", "included is required")
		return
	}

	// Filter to well-formed ids: one typo would otherwise fail the whole statement on the uuid cast
	// and leave every other checkbox the operator ticked unapplied.
	ids := make([]string, 0, len(payload.IDs))
	for _, id := range payload.IDs {
		if _, err := uuid.Parse(strings.TrimSpace(id)); err == nil {
			ids = append(ids, strings.TrimSpace(id))
		}
	}
	if len(ids) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"updated": 0})
		return
	}

	tag, err := dbPool.Exec(context.Background(), `
		UPDATE auth_recorded_requests
		SET included = $1
		WHERE recording_id = $2 AND id = ANY($3::uuid[])`,
		*payload.Included, recordingID, ids)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to update inclusion for %s: %v", recordingID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update recorded requests")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"updated": int(tag.RowsAffected())})
}

// DeleteAuthRecording handles DELETE /auth-recording/{recording_id}. The recorded requests go with
// it through ON DELETE CASCADE. Any auth flow generated from it is deliberately left alone: by the
// time the operator deletes the recording they may already be replaying that flow, and destroying it
// as a side effect of tidying up the recording list would be a nasty surprise.
func DeleteAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	recordingID := mux.Vars(r)["recording_id"]

	if _, err := uuid.Parse(recordingID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "recording_id_required", "recording_id is required")
		return
	}

	tag, err := dbPool.Exec(context.Background(), `DELETE FROM auth_recordings WHERE id = $1`, recordingID)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Failed to delete recording %s: %v", recordingID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete recording")
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "recording_not_found", "Unknown recording")
		return
	}

	forgetAuthRecordingSeq(recordingID)
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": true, "recording_id": recordingID})
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

// ImportAuthRecording handles POST /auth-recording/{recording_id}/import.
func ImportAuthRecording(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	recordingID := mux.Vars(r)["recording_id"]

	if _, err := uuid.Parse(recordingID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "recording_id_required", "recording_id is required")
		return
	}

	var payload struct {
		Name     string `json:"name"`
		Category string `json:"category"`
	}
	// An empty body is a valid import: it means "use the recording's own name and category".
	json.NewDecoder(r.Body).Decode(&payload)

	if cat := strings.ToLower(strings.TrimSpace(payload.Category)); cat != "" && !validAuthRecordingCategories[cat] {
		writeJSONError(w, http.StatusBadRequest, "invalid_category",
			"category must be register, login, mfa_otp, magic_link or reset")
		return
	}

	flowID, steps, err := importAuthRecordingToFlow(context.Background(), recordingID, payload.Name, payload.Category)
	if err != nil {
		log.Printf("[AUTH-RECORDING] Import of %s failed: %v", recordingID, err)
		writeJSONError(w, http.StatusBadRequest, "import_failed", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_flow_id": flowID,
		"steps":        steps,
		"recording_id": recordingID,
	})
}

// importAuthRecordingToFlow turns the included requests of a recording into an auth_flows row with
// one auth_flow_steps row per request, in seq order.
//
// It is re-runnable. Re-importing replaces the steps of the flow this recording already generated
// rather than creating a second flow, because the normal reason to re-import is "I unchecked the
// analytics beacon and want the flow rebuilt", and a second near-identical flow in the list is how
// the operator ends up replaying the wrong one.
//
// Nothing is replayed here. Replaying at import time would re-submit real credentials, and possibly
// a one-time code that only works once, before the operator has even seen the flow.
func importAuthRecordingToFlow(ctx context.Context, recordingID, nameOverride, categoryOverride string) (string, int, error) {
	var scopeTargetID, recName, recCategory, recBaseURL string
	var existingFlowID *string
	if err := dbPool.QueryRow(ctx, `
		SELECT scope_target_id, name, category, COALESCE(base_url,''), auth_flow_id
		FROM auth_recordings WHERE id = $1`, recordingID).
		Scan(&scopeTargetID, &recName, &recCategory, &recBaseURL, &existingFlowID); err != nil {
		return "", 0, fmt.Errorf("unknown recording")
	}

	name := strings.TrimSpace(nameOverride)
	if name == "" {
		name = recName
	}
	category := strings.ToLower(strings.TrimSpace(categoryOverride))
	if category == "" {
		category = recCategory
	}
	if !validAuthRecordingCategories[category] {
		return "", 0, fmt.Errorf("invalid category %q", category)
	}

	rows, err := dbPool.Query(ctx, `
		SELECT seq, method, url, COALESCE(host,''), raw_request, response_status,
		       COALESCE(response_headers,'{}'::jsonb), COALESCE(response_body,''),
		       COALESCE(set_cookies,'[]'::jsonb)
		FROM auth_recorded_requests
		WHERE recording_id = $1 AND included
		ORDER BY seq ASC`, recordingID)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read recorded requests: %w", err)
	}
	defer rows.Close()

	type importStep struct {
		name            string
		rawRequest      string
		responseStatus  *int
		responseHeaders map[string][]string
		responseBody    string
	}

	steps := make([]importStep, 0)
	baseURL := strings.TrimSpace(recBaseURL)
	baseHost := hostOf(baseURL)

	for rows.Next() {
		var seq int
		var method, rawURL, host, rawRequest, responseBody string
		var responseStatus *int
		var responseHeadersJSON, setCookiesJSON []byte

		if err := rows.Scan(&seq, &method, &rawURL, &host, &rawRequest, &responseStatus,
			&responseHeadersJSON, &responseBody, &setCookiesJSON); err != nil {
			log.Printf("[AUTH-RECORDING] Skipping unreadable recorded request in %s: %v", recordingID, err)
			continue
		}

		if baseURL == "" {
			if parsed, perr := url.Parse(rawURL); perr == nil && parsed.Host != "" {
				baseURL = parsed.Scheme + "://" + parsed.Host
				baseHost = parsed.Hostname()
			}
		}

		var flatResponseHeaders map[string]interface{}
		json.Unmarshal(responseHeadersJSON, &flatResponseHeaders)
		var setCookies []string
		json.Unmarshal(setCookiesJSON, &setCookies)

		steps = append(steps, importStep{
			name:            authStepName(seq, method, rawURL, host, baseHost),
			rawRequest:      rawRequest,
			responseStatus:  responseStatus,
			responseHeaders: authStepResponseHeaders(flatResponseHeaders, setCookies),
			responseBody:    responseBody,
		})
	}
	rows.Close()

	if len(steps) == 0 {
		return "", 0, fmt.Errorf("recording has no included requests to import")
	}

	description := fmt.Sprintf("Recorded in the browser on %s, %d step(s) from recording %q",
		time.Now().Format("2006-01-02 15:04"), len(steps), recName)

	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback(ctx)

	flowID := ""
	if existingFlowID != nil && *existingFlowID != "" {
		tag, uErr := tx.Exec(ctx, `
			UPDATE auth_flows
			SET name = $1, category = $2, description = $3, base_url = $4,
			    source = 'recorded', recording_id = $5, updated_at = NOW()
			WHERE id = $6`,
			sanitizeForPostgres(name), category, description, sanitizeForPostgres(baseURL),
			recordingID, *existingFlowID)
		if uErr != nil {
			return "", 0, fmt.Errorf("failed to update generated flow: %w", uErr)
		}
		if tag.RowsAffected() > 0 {
			flowID = *existingFlowID
			// Replace the steps wholesale rather than diffing. The sequence is what makes the flow
			// replayable, and a partial update would leave step_order values from two different
			// imports interleaved.
			if _, dErr := tx.Exec(ctx, `DELETE FROM auth_flow_steps WHERE auth_flow_id = $1`, flowID); dErr != nil {
				return "", 0, fmt.Errorf("failed to clear previous steps: %w", dErr)
			}
		}
	}

	if flowID == "" {
		// Either this recording never generated a flow, or the operator deleted the one it did.
		flowID = uuid.New().String()
		if _, iErr := tx.Exec(ctx, `
			INSERT INTO auth_flows
			  (id, scope_target_id, category, name, description, auth_type, base_url, source, recording_id)
			VALUES ($1, $2, $3, $4, $5, '', $6, 'recorded', $7)`,
			flowID, scopeTargetID, category, sanitizeForPostgres(name), description,
			sanitizeForPostgres(baseURL), recordingID); iErr != nil {
			return "", 0, fmt.Errorf("failed to create auth flow: %w", iErr)
		}
	}

	for i, step := range steps {
		headersJSON, _ := json.Marshal(step.responseHeaders)
		if _, sErr := tx.Exec(ctx, `
			INSERT INTO auth_flow_steps
			  (id, auth_flow_id, step_order, name, raw_request, response_status, response_headers, response_body)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.New().String(), flowID, i+1, sanitizeForPostgres(step.name),
			sanitizeForPostgres(step.rawRequest), step.responseStatus, headersJSON,
			sanitizeForPostgres(step.responseBody)); sErr != nil {
			return "", 0, fmt.Errorf("failed to insert step %d: %w", i+1, sErr)
		}
	}

	// base_url is written back so a recording started without one shows the host it actually hit.
	if _, uErr := tx.Exec(ctx, `
		UPDATE auth_recordings
		SET auth_flow_id = $1, base_url = CASE WHEN COALESCE(base_url,'') = '' THEN $2 ELSE base_url END
		WHERE id = $3`, flowID, sanitizeForPostgres(baseURL), recordingID); uErr != nil {
		return "", 0, fmt.Errorf("failed to link recording to flow: %w", uErr)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", 0, err
	}

	return flowID, len(steps), nil
}

// authStepName labels a step so the list reads as the flow it is. The host is included whenever it
// differs from the flow's base host, because a recorded flow crosses to the identity provider and
// two steps named "GET /authorize" on two different hosts are indistinguishable otherwise.
func authStepName(seq int, method, rawURL, host, baseHost string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	target := rawURL
	if parsed, err := url.Parse(rawURL); err == nil {
		if host == "" {
			host = parsed.Hostname()
		}
		target = parsed.RequestURI()
		if target == "" {
			target = "/"
		}
	}
	if host != "" && !strings.EqualFold(host, baseHost) {
		target = host + target
	}

	// Long query strings push the useful part of the label off the screen.
	if len(target) > 96 {
		target = target[:96] + "..."
	}
	return fmt.Sprintf("%d. %s %s", seq, method, target)
}

// authStepResponseHeaders converts the flat header map a recording stores into the multi-value shape
// auth_flow_steps.response_headers uses, which is http.Header, which is what replay's cookie jar
// seeding reads.
func authStepResponseHeaders(flat map[string]interface{}, setCookies []string) map[string][]string {
	headers := expandHeaderMap(flat)
	if len(setCookies) > 0 {
		// Every Set-Cookie has to be its own header value. http.Response.Cookies() parses one cookie
		// per value, so folding them into a single comma-joined string loses every cookie after the
		// first, and the first is rarely the session.
		delete(headers, "Set-Cookie")
		headers["Set-Cookie"] = append([]string{}, setCookies...)
	}
	return headers
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

func lookupAuthRecordingStatus(recordingID string) (string, error) {
	recordingID = strings.TrimSpace(recordingID)
	if _, err := uuid.Parse(recordingID); err != nil {
		return "", fmt.Errorf("recording_id is required")
	}
	var status string
	err := dbPool.QueryRow(context.Background(),
		`SELECT status FROM auth_recordings WHERE id = $1`, recordingID).Scan(&status)
	return status, err
}

// refreshAuthRecordingCounts recomputes request_count from the rows actually stored and stamps
// last_seen_at. Counts are never taken from the extension: a batch that was retried or partially
// rejected would otherwise inflate the number the operator is shown.
func refreshAuthRecordingCounts(recordingID string) (int, error) {
	var total int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE auth_recordings a
		SET request_count = c.total, last_seen_at = NOW()
		FROM (SELECT COUNT(*) AS total FROM auth_recorded_requests WHERE recording_id = $1) c
		WHERE a.id = $1
		RETURNING a.request_count`, recordingID).Scan(&total)
	return total, err
}

// insertAuthRecordedRequests writes a batch in one statement, falling back to one row at a time so a
// single unstorable request costs that request rather than the rest of the flow around it.
func insertAuthRecordedRequests(recordingID string, inputs []AuthRecordedRequestInput) (int, error) {
	seqs := allocAuthRecordingSeqs(recordingID, inputs)

	rows := make([][]interface{}, 0, len(inputs))
	for i, input := range inputs {
		if strings.TrimSpace(input.URL) == "" {
			continue
		}
		rows = append(rows, buildAuthRecordedRequestArgs(recordingID, seqs[i], input))
	}
	if len(rows) == 0 {
		return 0, nil
	}

	stored, err := execAuthRecordedRequestInsert(rows)
	if err == nil {
		return stored, nil
	}

	log.Printf("[AUTH-RECORDING] Batch insert failed (%v); retrying %d requests individually", err, len(rows))

	inserted := 0
	var lastErr error
	for _, row := range rows {
		one, oneErr := execAuthRecordedRequestInsert([][]interface{}{row})
		if oneErr != nil {
			lastErr = oneErr
			log.Printf("[AUTH-RECORDING] Dropping unstorable request seq %v: %v", row[2], oneErr)
			continue
		}
		inserted += one
	}

	if inserted == 0 && lastErr != nil {
		return 0, lastErr
	}
	return inserted, nil
}

func execAuthRecordedRequestInsert(rows [][]interface{}) (int, error) {
	const columnCount = 17

	valueGroups := make([]string, 0, len(rows))
	args := make([]interface{}, 0, len(rows)*columnCount)

	for _, row := range rows {
		base := len(args)
		placeholders := make([]string, columnCount)
		for i := 0; i < columnCount; i++ {
			placeholders[i] = fmt.Sprintf("$%d", base+i+1)
		}
		valueGroups = append(valueGroups, "("+strings.Join(placeholders, ", ")+")")
		args = append(args, row...)
	}

	// ON CONFLICT DO NOTHING against UNIQUE(recording_id, seq): an extension that retries a batch it
	// already delivered must not turn one login into two of every step.
	query := `
		INSERT INTO auth_recorded_requests
		  (id, recording_id, seq, method, url, host, raw_request, request_headers, request_body,
		   response_status, response_headers, response_body, set_cookies, resource_type,
		   duration_ms, included, occurred_at)
		VALUES ` + strings.Join(valueGroups, ", ") + `
		ON CONFLICT (recording_id, seq) DO NOTHING`

	tag, err := dbPool.Exec(context.Background(), query, args...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func buildAuthRecordedRequestArgs(recordingID string, seq int, input AuthRecordedRequestInput) []interface{} {
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = "GET"
	}
	// The column is VARCHAR(16); a malformed method must not fail the batch it arrived in.
	if len(method) > 16 {
		method = method[:16]
	}

	rawURL := strings.TrimSpace(input.URL)
	host := strings.TrimSpace(input.Host)
	if host == "" {
		host = hostOf(rawURL)
	}

	requestHeaders := sanitizeJSONMap(input.RequestHeaders)
	responseHeaders := sanitizeJSONMap(input.ResponseHeaders)

	rawRequest := input.RawRequest
	if strings.TrimSpace(rawRequest) == "" {
		// raw_request is NOT NULL and is the only thing replay can parse, so an extension build that
		// only forwards structured fields still has to produce a replayable step.
		rawRequest = BuildRawHTTPRequest(method, rawURL, requestHeaders, input.RequestBody)
	}

	setCookies := stringifySetCookies(input.SetCookies)
	if len(setCookies) == 0 {
		// Session token extraction reads set_cookies, so derive it from the response headers when the
		// extension did not split them out. Without this a recorded login looks like it set nothing.
		if joined := headerString(responseHeaders, "set-cookie"); joined != "" {
			setCookies = []string{joined}
		}
	}
	setCookiesJSON, _ := json.Marshal(setCookies)
	requestHeadersJSON, _ := json.Marshal(requestHeaders)
	responseHeadersJSON, _ := json.Marshal(responseHeaders)

	resourceType := strings.ToLower(strings.TrimSpace(input.ResourceType))
	if len(resourceType) > 32 {
		resourceType = resourceType[:32]
	}

	included := !isAuthRecordingNoise(rawURL, resourceType)
	if input.Included != nil {
		included = *input.Included
	}

	return []interface{}{
		uuid.New().String(),
		recordingID,
		seq,
		method,
		sanitizeForPostgres(rawURL),
		sanitizeForPostgres(host),
		sanitizeForPostgres(rawRequest),
		requestHeadersJSON,
		sanitizeForPostgres(input.RequestBody),
		input.ResponseStatus,
		responseHeadersJSON,
		sanitizeForPostgres(input.ResponseBody),
		setCookiesJSON,
		resourceType,
		input.DurationMs,
		included,
		parseRecordedTimestamp(input.OccurredAt),
	}
}

// isAuthRecordingNoise decides whether a request starts out excluded from the generated flow. The
// browser fires hundreds of subresource requests during a login and none of them authenticate
// anything, so a flow built from all of them is a flow nobody will read.
func isAuthRecordingNoise(rawURL, resourceType string) bool {
	if authRecordingNoiseResourceTypes[resourceType] {
		return true
	}

	// resource_type is empty for anything seen through the debugger rather than webRequest, so the
	// extension falls back to the path.
	path := rawURL
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	lower := strings.ToLower(path)
	for _, ext := range authRecordingStaticExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func stringifySetCookies(raw []interface{}) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text := sanitizeForPostgres(stringifyHeaderValue(item)); text != "" {
			out = append(out, text)
		}
	}
	return out
}

// parseRecordedTimestamp accepts what a browser extension actually sends: an RFC3339 string, or the
// number that came out of Date.now(). Anything unreadable falls back to now, because an approximate
// timestamp is worth more than a failed insert on the request that carried the session cookie.
func parseRecordedTimestamp(value interface{}) time.Time {
	switch typed := value.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, typed); err == nil {
				return parsed
			}
		}
	case float64:
		if typed > 1e11 {
			// Milliseconds since the epoch, which is what Date.now() returns.
			return time.UnixMilli(int64(typed))
		}
		if typed > 0 {
			return time.Unix(int64(typed), 0)
		}
	}
	return time.Now()
}
