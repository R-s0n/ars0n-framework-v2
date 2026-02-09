package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type ManualCrawlCapture struct {
	ID              string            `json:"id"`
	SessionID       string            `json:"session_id"`
	ScopeTargetID   string            `json:"scope_target_id"`
	URL             string            `json:"url"`
	Endpoint        string            `json:"endpoint"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	PostData        string            `json:"post_data,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
	MimeType        string            `json:"mime_type"`
}

type ManualCrawlSession struct {
	ID            string    `json:"id"`
	ScopeTargetID string    `json:"scope_target_id"`
	TargetURL     string    `json:"target_url"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	RequestCount  int       `json:"request_count"`
	EndpointCount int       `json:"endpoint_count"`
}

type CaptureRequest struct {
	URL             string                 `json:"url"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"statusCode"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"responseHeaders"`
	PostData        string                 `json:"postData,omitempty"`
	Timestamp       string                 `json:"timestamp"`
	MimeType        string                 `json:"mimeType"`
}

type StartCaptureRequest struct {
	TargetURL     string `json:"targetUrl"`
	ScopeTargetID string `json:"scopeTargetId"`
}

type StatsRequest struct {
	Stats struct {
		RequestCount  int `json:"requestCount"`
		EndpointCount int `json:"endpointCount"`
	} `json:"stats"`
}

var activeManualCrawlSession *ManualCrawlSession

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"service": "ars0n-framework",
	})
}

func StartManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req StartCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.TargetURL == "" {
		http.Error(w, "targetUrl is required", http.StatusBadRequest)
		return
	}

	if req.ScopeTargetID == "" {
		http.Error(w, "scopeTargetId is required", http.StatusBadRequest)
		return
	}

	var scopeTargetExists bool
	err := dbPool.QueryRow(context.Background(), 
		"SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1 AND type = 'URL')", 
		req.ScopeTargetID).Scan(&scopeTargetExists)
	
	if err != nil || !scopeTargetExists {
		log.Printf("[MANUAL-CRAWL] Invalid scope target ID: %s", req.ScopeTargetID)
		http.Error(w, "Invalid scopeTargetId - target not found", http.StatusBadRequest)
		return
	}

	scopeTargetID := req.ScopeTargetID
	sessionID := uuid.New().String()
	
	query := `
		INSERT INTO manual_crawl_sessions (id, scope_target_id, target_url, status, started_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	
	_, err = dbPool.Exec(context.Background(), query, sessionID, scopeTargetID, req.TargetURL, "active", time.Now())
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error creating session: %v", err)
		http.Error(w, "Failed to create capture session", http.StatusInternalServerError)
		return
	}

	activeManualCrawlSession = &ManualCrawlSession{
		ID:            sessionID,
		ScopeTargetID: scopeTargetID,
		TargetURL:     req.TargetURL,
		Status:        "active",
		StartedAt:     time.Now(),
		RequestCount:  0,
		EndpointCount: 0,
	}

	log.Printf("[MANUAL-CRAWL] Started session %s for target %s", sessionID, req.TargetURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"sessionId": sessionID,
		"scopeTargetId": scopeTargetID,
	})
}

func CaptureManualCrawlRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if activeManualCrawlSession == nil {
		http.Error(w, "No active capture session", http.StatusBadRequest)
		return
	}

	var req CaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding capture request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	timestamp, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		timestamp = time.Now()
	}

	headersJSON, _ := json.Marshal(req.Headers)
	responseHeadersJSON, _ := json.Marshal(req.ResponseHeaders)

	captureID := uuid.New().String()
	
	query := `
		INSERT INTO manual_crawl_captures 
		(id, session_id, scope_target_id, url, endpoint, method, status_code, headers, response_headers, post_data, timestamp, mime_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	
	_, err = dbPool.Exec(
		context.Background(),
		query,
		captureID,
		activeManualCrawlSession.ID,
		activeManualCrawlSession.ScopeTargetID,
		req.URL,
		req.Endpoint,
		req.Method,
		req.StatusCode,
		headersJSON,
		responseHeadersJSON,
		req.PostData,
		timestamp,
		req.MimeType,
	)

	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error storing capture: %v", err)
		http.Error(w, "Failed to store capture", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"captureId": captureID,
	})
}

func StopManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if activeManualCrawlSession == nil {
		http.Error(w, "No active capture session", http.StatusBadRequest)
		return
	}

	var req StatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding stats: %v", err)
	}

	endTime := time.Now()
	
	query := `
		UPDATE manual_crawl_sessions 
		SET status = $1, ended_at = $2, request_count = $3, endpoint_count = $4
		WHERE id = $5
	`
	
	_, err := dbPool.Exec(
		context.Background(),
		query,
		"completed",
		endTime,
		req.Stats.RequestCount,
		req.Stats.EndpointCount,
		activeManualCrawlSession.ID,
	)

	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error updating session: %v", err)
		http.Error(w, "Failed to update session", http.StatusInternalServerError)
		return
	}

	log.Printf("[MANUAL-CRAWL] Stopped session %s. Requests: %d, Endpoints: %d", 
		activeManualCrawlSession.ID, req.Stats.RequestCount, req.Stats.EndpointCount)

	sessionID := activeManualCrawlSession.ID
	activeManualCrawlSession = nil

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"sessionId": sessionID,
	})
}

func GetManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT id, scope_target_id, target_url, status, started_at, ended_at, request_count, endpoint_count
		FROM manual_crawl_sessions
		WHERE scope_target_id = $1
		ORDER BY started_at DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying sessions: %v", err)
		http.Error(w, "Failed to query sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	sessions := make([]ManualCrawlSession, 0)
	for rows.Next() {
		var session ManualCrawlSession
		var endedAt *time.Time
		
		err := rows.Scan(
			&session.ID,
			&session.ScopeTargetID,
			&session.TargetURL,
			&session.Status,
			&session.StartedAt,
			&endedAt,
			&session.RequestCount,
			&session.EndpointCount,
		)
		
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning session: %v", err)
			continue
		}

		session.EndedAt = endedAt
		sessions = append(sessions, session)
	}

	log.Printf("[MANUAL-CRAWL] Returning %d sessions for target %s", len(sessions), scopeTargetID)
	json.NewEncoder(w).Encode(sessions)
}

func CleanupStaleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
	
	query := `
		UPDATE manual_crawl_sessions
		SET status = 'completed', ended_at = NOW()
		WHERE status = 'active' 
		AND request_count = 0 
		AND started_at < $1
		RETURNING id
	`

	rows, err := dbPool.Query(context.Background(), query, fiveMinutesAgo)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error cleaning up stale sessions: %v", err)
		http.Error(w, "Failed to cleanup sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cleanedCount int
	for rows.Next() {
		var id string
		rows.Scan(&id)
		cleanedCount++
		log.Printf("[MANUAL-CRAWL] Cleaned up stale session: %s", id)
	}

	log.Printf("[MANUAL-CRAWL] Cleaned up %d stale sessions", cleanedCount)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"cleaned": cleanedCount,
	})
}

func GetAllManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	query := `
		SELECT id, scope_target_id, target_url, status, started_at, ended_at, request_count, endpoint_count
		FROM manual_crawl_sessions
		ORDER BY started_at DESC
		LIMIT 100
	`

	rows, err := dbPool.Query(context.Background(), query)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying all sessions: %v", err)
		http.Error(w, "Failed to query all sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	sessions := make([]ManualCrawlSession, 0)
	for rows.Next() {
		var session ManualCrawlSession
		var endedAt *time.Time
		
		err := rows.Scan(
			&session.ID,
			&session.ScopeTargetID,
			&session.TargetURL,
			&session.Status,
			&session.StartedAt,
			&endedAt,
			&session.RequestCount,
			&session.EndpointCount,
		)
		
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning session: %v", err)
			continue
		}

		session.EndedAt = endedAt
		sessions = append(sessions, session)
	}

	log.Printf("[MANUAL-CRAWL] Returning %d total sessions", len(sessions))
	json.NewEncoder(w).Encode(sessions)
}

func GetManualCrawlCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["session_id"]

	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT id, session_id, scope_target_id, url, endpoint, method, status_code, 
		       headers, response_headers, post_data, timestamp, mime_type
		FROM manual_crawl_captures
		WHERE session_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, sessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying captures: %v", err)
		http.Error(w, "Failed to query captures", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	captures := make([]ManualCrawlCapture, 0)
	for rows.Next() {
		var capture ManualCrawlCapture
		var headersJSON, responseHeadersJSON []byte
		
		err := rows.Scan(
			&capture.ID,
			&capture.SessionID,
			&capture.ScopeTargetID,
			&capture.URL,
			&capture.Endpoint,
			&capture.Method,
			&capture.StatusCode,
			&headersJSON,
			&responseHeadersJSON,
			&capture.PostData,
			&capture.Timestamp,
			&capture.MimeType,
		)
		
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning capture: %v", err)
			continue
		}

		json.Unmarshal(headersJSON, &capture.Headers)
		json.Unmarshal(responseHeadersJSON, &capture.ResponseHeaders)
		
		captures = append(captures, capture)
	}

	json.NewEncoder(w).Encode(captures)
}

func GetManualCrawlEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT DISTINCT endpoint, method, COUNT(*) as request_count, 
		       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		GROUP BY endpoint, method
		ORDER BY last_seen DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying endpoints: %v", err)
		http.Error(w, "Failed to query endpoints", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type EndpointSummary struct {
		Endpoint     string    `json:"endpoint"`
		Method       string    `json:"method"`
		RequestCount int       `json:"request_count"`
		FirstSeen    time.Time `json:"first_seen"`
		LastSeen     time.Time `json:"last_seen"`
	}

	endpoints := make([]EndpointSummary, 0)
	for rows.Next() {
		var ep EndpointSummary
		err := rows.Scan(&ep.Endpoint, &ep.Method, &ep.RequestCount, &ep.FirstSeen, &ep.LastSeen)
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning endpoint: %v", err)
			continue
		}
		endpoints = append(endpoints, ep)
	}

	json.NewEncoder(w).Encode(endpoints)
}

func findOrCreateURLScopeTarget(hostname string) (string, error) {
	var scopeTargetID string
	
	query := `
		SELECT id FROM scope_targets 
		WHERE type = 'URL' AND scope_target = $1
		LIMIT 1
	`
	
	err := dbPool.QueryRow(context.Background(), query, hostname).Scan(&scopeTargetID)
	if err == nil {
		return scopeTargetID, nil
	}

	scopeTargetID = uuid.New().String()
	insertQuery := `
		INSERT INTO scope_targets (id, type, mode, scope_target, active, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	
	_, err = dbPool.Exec(
		context.Background(),
		insertQuery,
		scopeTargetID,
		"URL",
		"Active",
		hostname,
		false,
		time.Now(),
	)
	
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			err := dbPool.QueryRow(context.Background(), query, hostname).Scan(&scopeTargetID)
			if err != nil {
				return "", err
			}
			return scopeTargetID, nil
		}
		return "", err
	}

	log.Printf("[MANUAL-CRAWL] Created new URL scope target %s for %s", scopeTargetID, hostname)
	return scopeTargetID, nil
}
