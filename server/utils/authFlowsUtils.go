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
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// validAuthFlowCategories mirrors the DB CHECK constraint on auth_flows.category.
//
// Five, not four. magic_link was added to the constraint and to the recorder's own category list
// but missed here, which broke two things: creating a magic link flow answered 400, and so did
// editing ANY flow imported from a magic link recording, because the client sends the category back
// on every update whether or not the operator touched it.
var validAuthFlowCategories = map[string]bool{
	"register":   true,
	"login":      true,
	"mfa_otp":    true,
	"magic_link": true,
	"reset":      true,
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

	// Values this step captures out of its own response, for a later step to refer to as
	// {{af:NAME}}. See authFlowsVariables.go.
	Extractions []AuthFlowExtraction `json:"extractions"`

	// Filled by a replay, never stored: what each rule actually did, and which placeholders this
	// step's request had filled in. Reported so the wiring is visible rather than inferred from a
	// step that mysteriously worked or mysteriously did not.
	Captured    []ExtractionOutcome `json:"captured,omitempty"`
	Substituted []string            `json:"substituted,omitempty"`
}

// ---------------------------------------------------------------------------
// Auth Flows (parent) CRUD
// ---------------------------------------------------------------------------

func GetAuthFlows(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	category := r.URL.Query().Get("category")

	// source and recording_id are selected because the client distinguishes a flow the browser
	// really performed from one somebody typed out. Without them the Authentication card counted
	// zero recorded flows while a recorded flow sat in the list.
	query := `SELECT f.id, f.scope_target_id, f.category, f.name, f.description, f.auth_type, f.base_url,
	                 COALESCE(f.source,'manual'), COALESCE(f.recording_id::text,''),
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
		var id, stID, cat, name, desc, authType, baseURL, source, recordingID string
		var createdAt, updatedAt time.Time
		var stepCount int
		if err := rows.Scan(&id, &stID, &cat, &name, &desc, &authType, &baseURL, &source,
			&recordingID, &createdAt, &updatedAt, &stepCount); err != nil {
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
			"source":          source,
			"recording_id":    recordingID,
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
		Name        string               `json:"name"`
		RawRequest  string               `json:"raw_request"`
		Replay      *bool                `json:"replay"`
		Extractions []AuthFlowExtraction `json:"extractions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.RawRequest) == "" {
		http.Error(w, "raw_request is required", http.StatusBadRequest)
		return
	}
	payload.RawRequest = normalizeRawRequest(payload.RawRequest)
	if problem := rawRequestProblem(payload.RawRequest); problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	// Refused here rather than at replay: a rule that cannot work is far cheaper to explain while
	// the operator is still looking at the step they just wrote.
	if problem := validateExtractionSet(payload.Extractions); problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	extractionsJSON, _ := json.Marshal(orEmptyExtractions(payload.Extractions))

	// Order is chosen and claimed in one statement. Reading MAX and then inserting let two concurrent
	// appends pick the same number, and with no uniqueness on (auth_flow_id, step_order) both
	// succeeded, leaving a flow whose replay order depended on how Postgres felt like returning the
	// rows that day.
	stepID := uuid.New().String()
	var nextOrder int
	if err := dbPool.QueryRow(context.Background(),
		`INSERT INTO auth_flow_steps (id, auth_flow_id, step_order, name, raw_request, extractions)
		 SELECT $1, $2, COALESCE(MAX(step_order),0)+1, $3, $4, $5
		 FROM auth_flow_steps WHERE auth_flow_id = $2
		 RETURNING step_order`,
		stepID, flowID, payload.Name, payload.RawRequest, extractionsJSON).Scan(&nextOrder); err != nil {
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
		// Omitted leaves the rules alone; [] clears them.
		Extractions *[]AuthFlowExtraction `json:"extractions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// Same treatment an appended step gets. An edited step is the more likely one to lose its
	// Content-Length, because editing the body is the usual reason to edit a step at all.
	if payload.RawRequest != nil {
		normalized := normalizeRawRequest(*payload.RawRequest)
		if problem := rawRequestProblem(normalized); problem != "" {
			http.Error(w, problem, http.StatusBadRequest)
			return
		}
		payload.RawRequest = &normalized
	}

	var extractionsJSON []byte
	if payload.Extractions != nil {
		if problem := validateExtractionSet(*payload.Extractions); problem != "" {
			http.Error(w, problem, http.StatusBadRequest)
			return
		}
		extractionsJSON, _ = json.Marshal(orEmptyExtractions(*payload.Extractions))
	}

	if _, err := dbPool.Exec(context.Background(),
		`UPDATE auth_flow_steps SET
		   name = COALESCE($1, name),
		   raw_request = COALESCE($2, raw_request),
		   step_order = COALESCE($3, step_order),
		   extractions = COALESCE($5, extractions),
		   updated_at = NOW()
		 WHERE id = $4`,
		payload.Name, payload.RawRequest, payload.StepOrder, stepID, extractionsJSON); err != nil {
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
	replayErr := replayStepByID(stepID)
	if replayErr != nil {
		log.Printf("[ERROR] Failed to replay step %s: %v", stepID, replayErr)
	}
	step, err := getStepByID(stepID)
	if err != nil {
		http.Error(w, "Step not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// When the replay itself failed, the row still holds the PREVIOUS run's response. Returning it
	// with no marker showed the operator a stale success for a request that had just gone wrong, so
	// the failure is attached to the payload rather than left in the log.
	if replayErr != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": step.ID, "auth_flow_id": step.AuthFlowID, "step_order": step.StepOrder,
			"name": step.Name, "raw_request": step.RawRequest,
			"response_status": step.ResponseStatus, "response_headers": step.ResponseHeaders,
			"response_body": step.ResponseBody, "response_time_ms": step.ResponseTimeMs,
			"error": step.Error, "created_at": step.CreatedAt, "updated_at": step.UpdatedAt,
			"replay_error": replayErr.Error(),
			"replay_note":  "The replay did not complete. The response shown is from the previous run.",
		})
		return
	}
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
	outcomes := replayFlowSteps(steps, baseURL, jar)

	updated, _ := getStepsByFlow(flowID)
	// The replay-time detail is not persisted, so fold it back onto the rows being returned:
	// without it the caller cannot tell a step that filled in a token from one that did not.
	for i := range updated {
		if outcome, ok := outcomes[updated[i].ID]; ok {
			updated[i].Captured = outcome.Captured
			updated[i].Substituted = outcome.Substituted
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// validateExtractionSet refuses a whole set, naming the rule that is wrong.
func validateExtractionSet(rules []AuthFlowExtraction) string {
	seen := map[string]bool{}
	for i, rule := range rules {
		if problem := validateAuthFlowExtraction(rule); problem != "" {
			return fmt.Sprintf("capture %d: %s", i+1, problem)
		}
		if seen[rule.Name] {
			return fmt.Sprintf("two captures on this step are both called %q, so one would silently "+
				"win over the other", rule.Name)
		}
		seen[rule.Name] = true
	}
	return ""
}

// orEmptyExtractions keeps the column as [] rather than null, so scanStep never has to care.
func orEmptyExtractions(rules []AuthFlowExtraction) []AuthFlowExtraction {
	if rules == nil {
		return []AuthFlowExtraction{}
	}
	return rules
}

// stepReplayOutcome is the per-step detail a replay produces but does not store.
type stepReplayOutcome struct {
	Captured    []ExtractionOutcome
	Substituted []string
}

// replayFlowSteps runs the ordered steps against one cookie jar AND one variable map.
//
// The jar was already here and carries the session. The map is what makes a per-request CSRF token
// work: each step captures values out of its own response, and a later step refers to them as
// {{af:NAME}}. Measured against ginandjuice.shop, without this a login step is answered
// 400 "Invalid CSRF token" because the token is bound to the session that issued it.
//
// A step whose placeholder has no value is NOT sent. It records why, and the loop continues rather
// than aborting: every step still gets a row, each failure lands on the step it belongs to, and no
// stale response is left behind looking like a success.
func replayFlowSteps(steps []AuthFlowStep, baseURL string, jar http.CookieJar) map[string]stepReplayOutcome {
	outcomes := make(map[string]stepReplayOutcome, len(steps))
	vars := map[string]string{}

	for _, step := range steps {
		request, substituted, refusal := prepareStepRequest(step.RawRequest, vars)
		if refusal != "" {
			// Clear the previous response rather than leaving a stale 200 next to the reason this
			// run did not happen.
			if uErr := updateStepResponse(step.ID, 0, nil, "", 0, refusal); uErr != nil {
				log.Printf("[ERROR] Failed to persist refusal for step %s: %v", step.ID, uErr)
			}
			outcomes[step.ID] = stepReplayOutcome{Substituted: substituted}
			continue
		}

		// Resolved from the SUBSTITUTED text: a placeholder can sit in the Host header.
		effBase := resolveBaseURL(request, baseURL)
		status, headers, body, ms, sendErr := sendRawRequest(request, effBase, jar)

		captured, outcomeList := runAuthFlowExtractions(step.Extractions, headers, body)
		for name, value := range captured {
			vars[name] = value
		}

		problems := []string{}
		if sendErr != nil {
			problems = append(problems, sendErr.Error())
		}
		for i, outcome := range outcomeList {
			// A rule marked optional may legitimately find nothing; a required one that misses is
			// the reason every later step is about to refuse, so it has to be said here.
			if !outcome.Matched && !step.Extractions[i].Optional {
				problems = append(problems, "capture "+outcome.Name+": "+outcome.Problem)
			}
		}

		if uErr := updateStepResponse(step.ID, status, headers, body, ms, strings.Join(problems, "; ")); uErr != nil {
			log.Printf("[ERROR] Failed to persist replay for step %s: %v", step.ID, uErr)
		}
		outcomes[step.ID] = stepReplayOutcome{Captured: outcomeList, Substituted: substituted}
	}

	return outcomes
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
	// Values every earlier step captured, re-read from the responses already recorded rather than by
	// re-sending them. Replaying one step must not fire the whole flow at the target again, but the
	// step still needs the token an earlier step produced or it cannot be sent at all.
	vars := map[string]string{}
	prior, err := getPriorSteps(step.AuthFlowID, step.StepOrder)
	if err == nil {
		seedJar(jar, effBase, prior)
		for _, earlier := range prior {
			captured, _ := runAuthFlowExtractions(earlier.Extractions, earlier.ResponseHeaders, earlier.ResponseBody)
			for name, value := range captured {
				vars[name] = value
			}
		}
	}

	request, _, refusal := prepareStepRequest(step.RawRequest, vars)
	if refusal != "" {
		// Recorded on the step rather than returned as an error, so the reason is visible where the
		// operator is looking instead of only in a toast.
		return updateStepResponse(stepID, 0, nil, "", 0, refusal+
			" Replay the whole flow, or run the earlier step first, so its captures are recorded.")
	}
	// Recomputed from the substituted text: a placeholder can sit in the Host header.
	effBase = resolveBaseURL(request, baseURL)

	status, headers, body, ms, sendErr := sendRawRequest(request, effBase, jar)
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

// normalizeRawRequest makes a pasted request actually sendable.
//
// http.ReadRequest will not read a body without a Content-Length or a chunked Transfer-Encoding, and
// it needs a blank line to end the headers. Both are easy to lose when a request is typed or pasted
// through an API rather than copied whole out of a proxy, and both fail silently: the step is stored,
// the request goes out with an empty body, and the target answers 400. The operator then debugs the
// target instead of the paste.
//
// Rather than reject those, fix what can be fixed unambiguously: terminate the headers, and compute
// the Content-Length the body actually has. An explicit Content-Length that disagrees with the body
// is corrected too, because the body is the thing the operator edited.
func normalizeRawRequest(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if strings.TrimSpace(raw) == "" {
		return raw
	}

	head, body, found := strings.Cut(raw, "\n\n")
	if !found {
		// No blank line: everything is headers, and there is no body.
		head = strings.TrimRight(raw, "\n")
		body = ""
	}

	lines := strings.Split(head, "\n")
	kept := make([]string, 0, len(lines)+1)
	for _, ln := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ln)), "content-length:") {
			continue // recomputed below
		}
		kept = append(kept, ln)
	}

	hasChunked := false
	for _, ln := range kept {
		l := strings.ToLower(ln)
		if strings.HasPrefix(strings.TrimSpace(l), "transfer-encoding:") && strings.Contains(l, "chunked") {
			hasChunked = true
		}
	}
	if body != "" && !hasChunked {
		kept = append(kept, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	out := strings.Join(kept, "\r\n") + "\r\n\r\n"
	if body != "" {
		out += body
	}
	return out
}

// rawRequestProblem returns a human explanation when a pasted request cannot be sent at all, so the
// operator is told at the moment they save rather than by a confusing response from the target.
func rawRequestProblem(raw string) string {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return "This does not parse as an HTTP request: " + err.Error() +
			". Expected a request line, then headers, then a blank line, then the body."
	}
	if req.Host == "" {
		return "The request has no Host header, so there is no way to tell which server to send it to."
	}
	return ""
}

// resolveBaseURL decides which server a step is actually sent to.
//
// The step's own Host header wins whenever it has one. base_url is only a fallback, because an auth
// flow routinely crosses hosts: the app posts to an identity provider, then back. The recorder sets
// base_url to the scope target unconditionally and there is no field for it in the UI, so treating
// it as an override meant every recorded cross-host flow replayed every step against the scope
// target. Step one would go to the CDN instead of the auth service, fail, and the operator would be
// told their credentials were wrong.
//
// base_url still matters for a hand-written step that has no Host header, and for pointing a whole
// flow at a staging origin, which is what it reads as in the UI.
func resolveBaseURL(rawRequest, flowBaseURL string) string {
	if req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest))); err == nil && req.Host != "" {
		scheme := "https"
		// Keep the flow's scheme and port if it named one for this same host, so a flow pinned to
		// http://localhost:8080 is not silently upgraded.
		if u, perr := url.Parse(strings.TrimSpace(flowBaseURL)); perr == nil && u.Host != "" &&
			strings.EqualFold(hostOnly(u.Host), hostOnly(req.Host)) {
			if u.Scheme != "" {
				scheme = u.Scheme
			}
			return scheme + "://" + u.Host
		}
		return scheme + "://" + req.Host
	}
	if strings.TrimSpace(flowBaseURL) != "" {
		return flowBaseURL
	}
	return ""
}

// hostOnly strips a port so a Host header can be compared with a base URL's authority.
func hostOnly(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i > 0 && !strings.Contains(hostport[i:], "]") {
		return hostport[:i]
	}
	return hostport
}

// seedJar loads cookies from earlier steps' captured Set-Cookie response headers into the jar.
//
// Each step's cookies are filed against the host that ISSUED them, not against the host the current
// step happens to target. Attributing them all to the current step's host handed one host's
// host-only cookies to another, so replaying step 3 alone sent the identity provider a
// load-balancer cookie minted by a different service, and single-step replay disagreed with
// full-flow replay on the same step.
func seedJar(jar http.CookieJar, baseURL string, priorSteps []AuthFlowStep) {
	for _, s := range priorSteps {
		if len(s.ResponseHeaders) == 0 {
			continue
		}
		// The step's own request says who answered it.
		issuer := resolveBaseURL(s.RawRequest, "")
		if issuer == "" {
			issuer = baseURL
		}
		if issuer == "" {
			continue
		}
		u, err := url.Parse(issuer)
		if err != nil || u.Host == "" {
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
		statusVal, headersJSON, sanitizeForTextColumn(body), ms, errStr, stepID)
	return err
}

// sanitizeForTextColumn makes an arbitrary response body storable in a Postgres text column.
//
// A text column cannot hold a NUL byte or invalid UTF-8, and a body that is neither is common: any
// gzip or brotli response that was not decoded, or an image, starts with bytes Postgres rejects. The
// UPDATE then failed, the error was only logged, and both replay endpoints answered 200 carrying the
// PREVIOUS run's response, so the operator was shown a stale success for a request that had just
// behaved differently.
func sanitizeForTextColumn(s string) string {
	if s == "" {
		return s
	}
	if utf8.ValidString(s) && !strings.ContainsRune(s, 0) {
		return s
	}
	// Replace what cannot be stored rather than dropping the body: the fact that a binary or
	// mis-encoded body came back is itself worth seeing.
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return cleaned
}

// ---------------------------------------------------------------------------
// Step read helpers
// ---------------------------------------------------------------------------

const stepSelectCols = `id, auth_flow_id, step_order, name, raw_request, response_status,
	response_headers, COALESCE(response_body,''), response_time_ms, COALESCE(error,''),
	created_at, updated_at, COALESCE(extractions,'[]'::jsonb)`

func scanStep(row interface{ Scan(...interface{}) error }) (AuthFlowStep, error) {
	var s AuthFlowStep
	var headersJSON []byte
	var extractionsJSON []byte
	if err := row.Scan(&s.ID, &s.AuthFlowID, &s.StepOrder, &s.Name, &s.RawRequest, &s.ResponseStatus,
		&headersJSON, &s.ResponseBody, &s.ResponseTimeMs, &s.Error, &s.CreatedAt, &s.UpdatedAt,
		&extractionsJSON); err != nil {
		return s, err
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.ResponseHeaders)
	}
	if len(extractionsJSON) > 0 {
		_ = json.Unmarshal(extractionsJSON, &s.Extractions)
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
