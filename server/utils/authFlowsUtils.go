package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// validAuthFlowCategories mirrors the DB CHECK constraint on auth_flows.category.
var validAuthFlowCategories = map[string]bool{
	"register": true,
	"login":    true,
	"mfa_otp":  true,
	"reset":    true,
}

// AuthFlowStep is one ordered HTTP request/response in a flow.
type AuthFlowStep struct {
	ID              string              `json:"id"`
	AuthFlowID      string              `json:"auth_flow_id"`
	StepOrder       int                 `json:"step_order"`
	Name            string              `json:"name"`
	RawRequest      string              `json:"raw_request"`
	ResponseStatus  *int                `json:"response_status"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	ResponseBody    string              `json:"response_body"`
	ResponseTimeMs  *float64            `json:"response_time_ms"`
	Error           string              `json:"error"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Auth Flows (parent) CRUD
// ---------------------------------------------------------------------------

func GetAuthFlows(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	category := r.URL.Query().Get("category")

	query := `SELECT f.id, f.scope_target_id, f.category, f.name, f.description, f.auth_type, f.base_url,
	                 f.created_at, f.updated_at,
	                 (SELECT COUNT(*) FROM auth_flow_steps s WHERE s.auth_flow_id = f.id) AS step_count
	          FROM auth_flows f
	          WHERE f.scope_target_id = $1`
	args := []interface{}{scopeTargetID}
	if category != "" {
		query += ` AND f.category = $2`
		args = append(args, category)
	}
	query += ` ORDER BY f.created_at ASC`

	rows, err := dbPool.Query(context.Background(), query, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to get auth flows: %v", err)
		http.Error(w, "Failed to fetch auth flows", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	flows := []map[string]interface{}{}
	for rows.Next() {
		var id, stID, cat, name, desc, authType, baseURL string
		var createdAt, updatedAt time.Time
		var stepCount int
		if err := rows.Scan(&id, &stID, &cat, &name, &desc, &authType, &baseURL, &createdAt, &updatedAt, &stepCount); err != nil {
			log.Printf("[ERROR] Failed to scan auth flow row: %v", err)
			continue
		}
		flows = append(flows, map[string]interface{}{
			"id":              id,
			"scope_target_id": stID,
			"category":        cat,
			"name":            name,
			"description":     desc,
			"auth_type":       authType,
			"base_url":        baseURL,
			"created_at":      createdAt,
			"updated_at":      updatedAt,
			"step_count":      stepCount,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flows)
}

func CreateAuthFlow(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Category    string `json:"category"`
		Name        string `json:"name"`
		Description string `json:"description"`
		AuthType    string `json:"auth_type"`
		BaseURL     string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !validAuthFlowCategories[payload.Category] {
		http.Error(w, "Invalid category (must be register, login, mfa_otp, or reset)", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	query := `INSERT INTO auth_flows (id, scope_target_id, category, name, description, auth_type, base_url)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING id, scope_target_id, category, name, description, auth_type, base_url, created_at, updated_at`

	flow, err := scanAuthFlowRow(dbPool.QueryRow(context.Background(), query,
		id, scopeTargetID, payload.Category, payload.Name, payload.Description, payload.AuthType, payload.BaseURL))
	if err != nil {
		log.Printf("[ERROR] Failed to create auth flow: %v", err)
		http.Error(w, "Failed to create auth flow", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

func UpdateAuthFlow(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]

	var payload struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		AuthType    *string `json:"auth_type"`
		BaseURL     *string `json:"base_url"`
		Category    *string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if payload.Category != nil && !validAuthFlowCategories[*payload.Category] {
		http.Error(w, "Invalid category", http.StatusBadRequest)
		return
	}

	query := `UPDATE auth_flows SET
	            name = COALESCE($1, name),
	            description = COALESCE($2, description),
	            auth_type = COALESCE($3, auth_type),
	            base_url = COALESCE($4, base_url),
	            category = COALESCE($5, category),
	            updated_at = NOW()
	          WHERE id = $6
	          RETURNING id, scope_target_id, category, name, description, auth_type, base_url, created_at, updated_at`

	flow, err := scanAuthFlowRow(dbPool.QueryRow(context.Background(), query,
		payload.Name, payload.Description, payload.AuthType, payload.BaseURL, payload.Category, flowID))
	if err != nil {
		log.Printf("[ERROR] Failed to update auth flow: %v", err)
		http.Error(w, "Failed to update auth flow", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flow)
}

func DeleteAuthFlow(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]
	result, err := dbPool.Exec(context.Background(), `DELETE FROM auth_flows WHERE id = $1`, flowID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete auth flow: %v", err)
		http.Error(w, "Failed to delete auth flow", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Auth flow not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scanAuthFlowRow scans a single auth_flows row (from QueryRow) into a map.
func scanAuthFlowRow(row interface{ Scan(...interface{}) error }) (map[string]interface{}, error) {
	var id, stID, cat, name, desc, authType, baseURL string
	var createdAt, updatedAt time.Time
	if err := row.Scan(&id, &stID, &cat, &name, &desc, &authType, &baseURL, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":              id,
		"scope_target_id": stID,
		"category":        cat,
		"name":            name,
		"description":     desc,
		"auth_type":       authType,
		"base_url":        baseURL,
		"created_at":      createdAt,
		"updated_at":      updatedAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Auth Flow Steps CRUD
// ---------------------------------------------------------------------------

func GetAuthFlowSteps(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]
	steps, err := getStepsByFlow(flowID)
	if err != nil {
		log.Printf("[ERROR] Failed to get auth flow steps: %v", err)
		http.Error(w, "Failed to fetch steps", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(steps)
}

func AddAuthFlowStep(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]

	var payload struct {
		Name       string `json:"name"`
		RawRequest string `json:"raw_request"`
		Replay     *bool  `json:"replay"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.RawRequest) == "" {
		http.Error(w, "raw_request is required", http.StatusBadRequest)
		return
	}

	var nextOrder int
	if err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(step_order),0)+1 FROM auth_flow_steps WHERE auth_flow_id = $1`, flowID).Scan(&nextOrder); err != nil {
		log.Printf("[ERROR] Failed to compute next step order: %v", err)
		http.Error(w, "Failed to add step", http.StatusInternalServerError)
		return
	}

	stepID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO auth_flow_steps (id, auth_flow_id, step_order, name, raw_request) VALUES ($1, $2, $3, $4, $5)`,
		stepID, flowID, nextOrder, payload.Name, payload.RawRequest); err != nil {
		log.Printf("[ERROR] Failed to insert auth flow step: %v", err)
		http.Error(w, "Failed to add step", http.StatusInternalServerError)
		return
	}

	// Replay by default (the app "records the response"), unless explicitly disabled.
	if payload.Replay == nil || *payload.Replay {
		replayStepByID(stepID)
	}

	step, err := getStepByID(stepID)
	if err != nil {
		http.Error(w, "Failed to fetch created step", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(step)
}

func UpdateAuthFlowStep(w http.ResponseWriter, r *http.Request) {
	stepID := mux.Vars(r)["step_id"]

	var payload struct {
		Name       *string `json:"name"`
		RawRequest *string `json:"raw_request"`
		StepOrder  *int    `json:"step_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if _, err := dbPool.Exec(context.Background(),
		`UPDATE auth_flow_steps SET
		   name = COALESCE($1, name),
		   raw_request = COALESCE($2, raw_request),
		   step_order = COALESCE($3, step_order),
		   updated_at = NOW()
		 WHERE id = $4`,
		payload.Name, payload.RawRequest, payload.StepOrder, stepID); err != nil {
		log.Printf("[ERROR] Failed to update auth flow step: %v", err)
		http.Error(w, "Failed to update step", http.StatusInternalServerError)
		return
	}

	step, err := getStepByID(stepID)
	if err != nil {
		http.Error(w, "Step not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(step)
}

func DeleteAuthFlowStep(w http.ResponseWriter, r *http.Request) {
	stepID := mux.Vars(r)["step_id"]
	result, err := dbPool.Exec(context.Background(), `DELETE FROM auth_flow_steps WHERE id = $1`, stepID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete auth flow step: %v", err)
		http.Error(w, "Failed to delete step", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Step not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

func ReplayAuthFlowStep(w http.ResponseWriter, r *http.Request) {
	stepID := mux.Vars(r)["step_id"]
	if err := replayStepByID(stepID); err != nil {
		log.Printf("[ERROR] Failed to replay step %s: %v", stepID, err)
	}
	step, err := getStepByID(stepID)
	if err != nil {
		http.Error(w, "Step not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(step)
}

func ReplayAuthFlow(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]

	baseURL, err := getFlowBaseURL(flowID)
	if err != nil {
		http.Error(w, "Auth flow not found", http.StatusNotFound)
		return
	}
	steps, err := getStepsByFlow(flowID)
	if err != nil {
		http.Error(w, "Failed to fetch steps", http.StatusInternalServerError)
		return
	}

	// One shared cookie jar across the whole flow, so Set-Cookie from earlier steps
	// is sent on later steps (session/token carry-over).
	jar, _ := cookiejar.New(nil)
	for _, step := range steps {
		effBase := resolveBaseURL(step.RawRequest, baseURL)
		status, headers, body, ms, sendErr := sendRawRequest(step.RawRequest, effBase, jar)
		errStr := ""
		if sendErr != nil {
			errStr = sendErr.Error()
		}
		if uErr := updateStepResponse(step.ID, status, headers, body, ms, errStr); uErr != nil {
			log.Printf("[ERROR] Failed to persist replay for step %s: %v", step.ID, uErr)
		}
	}

	updated, _ := getStepsByFlow(flowID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// replayStepByID re-sends a single step's request, seeding cookies from the responses of
// all earlier steps in the same flow, and persists the captured response.
func replayStepByID(stepID string) error {
	step, err := getStepByID(stepID)
	if err != nil {
		return err
	}
	baseURL, err := getFlowBaseURL(step.AuthFlowID)
	if err != nil {
		return err
	}
	effBase := resolveBaseURL(step.RawRequest, baseURL)

	jar, _ := cookiejar.New(nil)
	prior, err := getPriorSteps(step.AuthFlowID, step.StepOrder)
	if err == nil {
		seedJar(jar, effBase, prior)
	}

	status, headers, body, ms, sendErr := sendRawRequest(step.RawRequest, effBase, jar)
	errStr := ""
	if sendErr != nil {
		errStr = sendErr.Error()
	}
	return updateStepResponse(stepID, status, headers, body, ms, errStr)
}

// sendRawRequest parses a raw HTTP request, points it at baseURL, sends it (no redirect follow,
// TLS verification skipped for test targets) and returns the captured response.
func sendRawRequest(rawRequest, baseURL string, jar http.CookieJar) (int, map[string][]string, string, float64, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		return 0, nil, "", 0, fmt.Errorf("failed to parse raw request: %w", err)
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	scheme, host := "https", req.Host
	if baseURL != "" {
		u, perr := url.Parse(baseURL)
		if perr != nil || u.Host == "" {
			return 0, nil, "", 0, fmt.Errorf("invalid base_url %q", baseURL)
		}
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		host = u.Host
	}
	if host == "" {
		return 0, nil, "", 0, fmt.Errorf("no Host header and no base_url; cannot determine target")
	}

	hostHeader := req.Host // preserve the pasted Host header for the request
	req.URL.Scheme = scheme
	req.URL.Host = host
	req.RequestURI = ""
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	if hostHeader != "" {
		req.Host = hostHeader
	} else {
		req.Host = host
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // capture 3xx instead of following
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return 0, nil, "", elapsed, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // cap at 2MB
	return resp.StatusCode, resp.Header, string(respBody), elapsed, nil
}

// resolveBaseURL returns the flow base_url, or derives one from the raw request's Host header.
func resolveBaseURL(rawRequest, flowBaseURL string) string {
	if strings.TrimSpace(flowBaseURL) != "" {
		return flowBaseURL
	}
	if req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest))); err == nil && req.Host != "" {
		return "https://" + req.Host
	}
	return ""
}

// seedJar loads cookies from earlier steps' captured Set-Cookie response headers into the jar.
func seedJar(jar http.CookieJar, baseURL string, priorSteps []AuthFlowStep) {
	if baseURL == "" {
		return
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return
	}
	for _, s := range priorSteps {
		if len(s.ResponseHeaders) == 0 {
			continue
		}
		dummy := &http.Response{Header: http.Header(s.ResponseHeaders)}
		if cookies := dummy.Cookies(); len(cookies) > 0 {
			jar.SetCookies(u, cookies)
		}
	}
}

func updateStepResponse(stepID string, status int, headers map[string][]string, body string, ms float64, errStr string) error {
	headersJSON, _ := json.Marshal(headers)
	var statusVal interface{}
	if status > 0 {
		statusVal = status
	}
	_, err := dbPool.Exec(context.Background(),
		`UPDATE auth_flow_steps SET response_status = $1, response_headers = $2, response_body = $3,
		   response_time_ms = $4, error = $5, updated_at = NOW() WHERE id = $6`,
		statusVal, headersJSON, body, ms, errStr, stepID)
	return err
}

// ---------------------------------------------------------------------------
// Step read helpers
// ---------------------------------------------------------------------------

const stepSelectCols = `id, auth_flow_id, step_order, name, raw_request, response_status,
	response_headers, COALESCE(response_body,''), response_time_ms, COALESCE(error,''),
	created_at, updated_at`

func scanStep(row interface{ Scan(...interface{}) error }) (AuthFlowStep, error) {
	var s AuthFlowStep
	var headersJSON []byte
	if err := row.Scan(&s.ID, &s.AuthFlowID, &s.StepOrder, &s.Name, &s.RawRequest, &s.ResponseStatus,
		&headersJSON, &s.ResponseBody, &s.ResponseTimeMs, &s.Error, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return s, err
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.ResponseHeaders)
	}
	return s, nil
}

func getStepByID(stepID string) (AuthFlowStep, error) {
	row := dbPool.QueryRow(context.Background(),
		`SELECT `+stepSelectCols+` FROM auth_flow_steps WHERE id = $1`, stepID)
	return scanStep(row)
}

func getStepsByFlow(flowID string) ([]AuthFlowStep, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+stepSelectCols+` FROM auth_flow_steps WHERE auth_flow_id = $1 ORDER BY step_order ASC`, flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	steps := []AuthFlowStep{}
	for rows.Next() {
		s, err := scanStep(rows)
		if err != nil {
			log.Printf("[ERROR] Failed to scan auth flow step: %v", err)
			continue
		}
		steps = append(steps, s)
	}
	return steps, nil
}

func getPriorSteps(flowID string, beforeOrder int) ([]AuthFlowStep, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+stepSelectCols+` FROM auth_flow_steps WHERE auth_flow_id = $1 AND step_order < $2 ORDER BY step_order ASC`,
		flowID, beforeOrder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	steps := []AuthFlowStep{}
	for rows.Next() {
		s, err := scanStep(rows)
		if err != nil {
			continue
		}
		steps = append(steps, s)
	}
	return steps, nil
}

func getFlowBaseURL(flowID string) (string, error) {
	var baseURL string
	err := dbPool.QueryRow(context.Background(), `SELECT base_url FROM auth_flows WHERE id = $1`, flowID).Scan(&baseURL)
	return baseURL, err
}
