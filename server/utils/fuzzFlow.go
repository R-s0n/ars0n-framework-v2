package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// The flow, its steps, and the positions inside each step.
//
// One flow per scope target. Steps are ordered, carry a tool, and each is an independent scan: the
// tools cannot pass anything between them, so a "flow" is a sequence, never a chain. Saying that in
// the data model rather than only in a comment is why there is no step-output or variable table.
//
// POSITIONS ARE DERIVED FROM THE TEXT, not stored beside it as an independent list. The raw request
// is the authority: a token that is not in the text has no position, and a token in the text with no
// configuration is an error rather than a silently literal payload. Keeping the two in sync any
// other way means they eventually disagree, and the disagreement is invisible until a scan runs.

// ensureFuzzFlow returns the flow for a target, creating it on first use so the UI never has to.
func ensureFuzzFlow(ctx context.Context, scopeTargetID string) (string, error) {
	var id string
	err := dbPool.QueryRow(ctx, `
		INSERT INTO fuzz_flows (scope_target_id) VALUES ($1)
		ON CONFLICT (scope_target_id) DO UPDATE SET updated_at = NOW()
		RETURNING id`, scopeTargetID).Scan(&id)
	return id, err
}

func loadFuzzStep(ctx context.Context, stepID string) (FuzzStep, error) {
	var s FuzzStep
	var optionsJSON []byte
	var name, ffufMode, x8Place *string
	var port *int
	err := dbPool.QueryRow(ctx, `
		SELECT id, flow_id, ordinal, tool, name, enabled, raw_request, scheme, port,
		       target_host, ffuf_mode, x8_place, COALESCE(options,'{}'::jsonb)
		FROM fuzz_steps WHERE id = $1`, stepID).
		Scan(&s.ID, &s.FlowID, &s.Ordinal, &s.Tool, &name, &s.Enabled, &s.RawRequest,
			&s.Scheme, &port, &s.TargetHost, &ffufMode, &x8Place, &optionsJSON)
	if err != nil {
		return s, err
	}
	if name != nil {
		s.Name = *name
	}
	if port != nil {
		s.Port = *port
	}
	if ffufMode != nil {
		s.FFUFMode = *ffufMode
	}
	if x8Place != nil {
		s.X8Place = *x8Place
	}
	_ = json.Unmarshal(optionsJSON, &s.Options)

	rows, err := dbPool.Query(ctx, `
		SELECT id, token, ordinal, COALESCE(role,''), resting_value,
		       COALESCE(wordlist,''), COALESCE(encoder,'')
		FROM fuzz_positions WHERE step_id = $1 ORDER BY ordinal`, stepID)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	s.Positions = []FuzzPosition{}
	for rows.Next() {
		var p FuzzPosition
		if rows.Scan(&p.ID, &p.Token, &p.Ordinal, &p.Role, &p.RestingValue,
			&p.Wordlist, &p.Encoder) == nil {
			s.Positions = append(s.Positions, p)
		}
	}
	return s, nil
}

func loadFuzzSteps(ctx context.Context, flowID, tool string) ([]FuzzStep, error) {
	q := `SELECT id FROM fuzz_steps WHERE flow_id = $1`
	args := []interface{}{flowID}
	if tool != "" {
		q += ` AND tool = $2`
		args = append(args, tool)
	}
	q += ` ORDER BY ordinal`

	rows, err := dbPool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	out := make([]FuzzStep, 0, len(ids))
	for _, id := range ids {
		if s, err := loadFuzzStep(ctx, id); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// GetFuzzFlow returns the whole flow for a target, optionally filtered to one tool.
func GetFuzzFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	tool := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tool")))

	ctx := context.Background()
	flowID, err := ensureFuzzFlow(ctx, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	steps, err := loadFuzzSteps(ctx, flowID, tool)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"flow_id": flowID,
		"tool":    tool,
		"steps":   steps,
		"scope":   LoadScanScope(scopeTargetID).Describe(),
	})
}

type fuzzStepRequest struct {
	Tool           string         `json:"tool"`
	Name           string         `json:"name"`
	Enabled        *bool          `json:"enabled"`
	SeedEndpointID string         `json:"seed_endpoint_id"`
	RawRequest     string         `json:"raw_request"`
	Scheme         string         `json:"scheme"`
	Port           int            `json:"port"`
	FFUFMode       string         `json:"ffuf_mode"`
	X8Place        string         `json:"x8_place"`
	Options        map[string]any `json:"options"`
	Positions      []FuzzPosition `json:"positions"`
}

// CreateFuzzStep adds a round to the flow, seeded from a discovered endpoint or from raw text.
func CreateFuzzStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var req fuzzStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	if tool != "ffuf" && tool != "x8" {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool", "tool must be ffuf or x8")
		return
	}

	ctx := context.Background()
	raw, scheme, port := req.RawRequest, req.Scheme, req.Port

	// Seeding is the normal path: start from what the application really did rather than from a
	// blank buffer.
	if strings.TrimSpace(raw) == "" && req.SeedEndpointID != "" {
		seed, err := RenderSeedRequest(ctx, req.SeedEndpointID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad_seed", err.Error())
			return
		}
		raw, scheme = seed.Raw, seed.Scheme
	}
	if strings.TrimSpace(raw) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_request",
			"a step needs either raw_request or seed_endpoint_id")
		return
	}
	if scheme == "" {
		scheme = "https"
	}

	host := HostFromRawRequest(raw)
	if host == "" {
		writeJSONError(w, http.StatusBadRequest, "no_host",
			"the raw request has no Host header, so there is nothing to send it to")
		return
	}

	flowID, err := ensureFuzzFlow(ctx, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	mode := req.FFUFMode
	if tool == "ffuf" && mode == "" {
		mode = "clusterbomb"
	}
	place := req.X8Place
	if tool == "x8" && place == "" {
		place = "body"
	}
	optionsJSON, _ := json.Marshal(orEmptyOptions(req.Options))

	var stepID string
	err = dbPool.QueryRow(ctx, `
		INSERT INTO fuzz_steps (flow_id, ordinal, tool, name, seed_endpoint_id, raw_request,
		                        scheme, port, target_host, ffuf_mode, x8_place, options)
		VALUES ($1,
		        COALESCE((SELECT MAX(ordinal) + 1 FROM fuzz_steps WHERE flow_id = $1), 0),
		        $2, $3, NULLIF($4,'')::uuid, $5, $6, NULLIF($7,0), $8,
		        NULLIF($9,''), NULLIF($10,''), $11)
		RETURNING id`,
		flowID, tool, nullIfEmpty(req.Name), req.SeedEndpointID, raw, scheme, port, host,
		mode, place, optionsJSON).Scan(&stepID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	if err := reconcileFuzzPositions(ctx, stepID, raw, req.Positions); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	step, _ := loadFuzzStep(ctx, stepID)
	writeFuzzStep(w, step)
}

// UpdateFuzzStep replaces the editable parts of a step and re-derives its positions.
func UpdateFuzzStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stepID := mux.Vars(r)["step_id"]

	var req fuzzStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	ctx := context.Background()
	current, err := loadFuzzStep(ctx, stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "step not found")
		return
	}

	raw := current.RawRequest
	if strings.TrimSpace(req.RawRequest) != "" {
		raw = req.RawRequest
	}
	host := HostFromRawRequest(raw)
	if host == "" {
		writeJSONError(w, http.StatusBadRequest, "no_host",
			"the raw request has no Host header, so there is nothing to send it to")
		return
	}

	enabled := current.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	options := current.Options
	if req.Options != nil {
		options = req.Options
	}
	optionsJSON, _ := json.Marshal(orEmptyOptions(options))

	_, err = dbPool.Exec(ctx, `
		UPDATE fuzz_steps
		SET raw_request = $1, target_host = $2, enabled = $3,
		    name = COALESCE(NULLIF($4,''), name),
		    scheme = COALESCE(NULLIF($5,''), scheme),
		    ffuf_mode = COALESCE(NULLIF($6,''), ffuf_mode),
		    x8_place = COALESCE(NULLIF($7,''), x8_place),
		    options = $8, updated_at = NOW()
		WHERE id = $9`,
		raw, host, enabled, req.Name, req.Scheme, req.FFUFMode, req.X8Place, optionsJSON, stepID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	if err := reconcileFuzzPositions(ctx, stepID, raw, req.Positions); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	step, _ := loadFuzzStep(ctx, stepID)
	writeFuzzStep(w, step)
}

// reconcileFuzzPositions makes the position rows match the tokens actually in the text.
//
// The text wins. A token removed from the request loses its row, and a token added gains one, so the
// two can never drift into disagreeing about what will be fuzzed. Configuration supplied by the
// caller is applied to whichever tokens still exist; anything else keeps what it had.
func reconcileFuzzPositions(ctx context.Context, stepID, raw string, incoming []FuzzPosition) error {
	tokens := fuzzTokenRe.FindAllString(raw, -1)
	seen := map[string]bool{}
	ordered := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !seen[t] {
			seen[t] = true
			ordered = append(ordered, t)
		}
	}
	if len(ordered) > maxFuzzPositions {
		return fmt.Errorf("a step supports at most %d positions, this one has %d",
			maxFuzzPositions, len(ordered))
	}

	config := map[string]FuzzPosition{}
	for _, p := range incoming {
		config[p.Token] = p
	}

	// Drop rows whose token is gone from the text.
	if len(ordered) == 0 {
		_, err := dbPool.Exec(ctx, `DELETE FROM fuzz_positions WHERE step_id = $1`, stepID)
		return err
	}
	if _, err := dbPool.Exec(ctx,
		`DELETE FROM fuzz_positions WHERE step_id = $1 AND NOT (token = ANY($2))`,
		stepID, ordered); err != nil {
		return err
	}

	for i, token := range ordered {
		p := config[token]
		role := classifyPositionRole(raw, token)
		// Ordinal follows document order, which is what makes FUZZP01 the first marker an operator
		// sees rather than an arbitrary one.
		_, err := dbPool.Exec(ctx, `
			INSERT INTO fuzz_positions (step_id, token, ordinal, role, resting_value, wordlist, encoder)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''))
			ON CONFLICT (step_id, token) DO UPDATE
			SET ordinal = EXCLUDED.ordinal,
			    role = EXCLUDED.role,
			    resting_value = COALESCE(NULLIF(EXCLUDED.resting_value,''), fuzz_positions.resting_value),
			    wordlist = COALESCE(EXCLUDED.wordlist, fuzz_positions.wordlist),
			    encoder = COALESCE(EXCLUDED.encoder, fuzz_positions.encoder)`,
			stepID, token, i+1, role, p.RestingValue, p.Wordlist, p.Encoder)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeleteFuzzStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stepID := mux.Vars(r)["step_id"]
	tag, err := dbPool.Exec(context.Background(), `DELETE FROM fuzz_steps WHERE id = $1`, stepID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": tag.RowsAffected()})
}

// ReorderFuzzSteps sets the running order.
func ReorderFuzzSteps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		StepIDs []string `json:"step_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.StepIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "step_ids is required")
		return
	}

	ctx := context.Background()
	// Two passes with an offset, because ordinal is UNIQUE per flow and a direct renumber collides
	// with the rows it has not moved yet.
	for i, id := range req.StepIDs {
		if _, err := dbPool.Exec(ctx,
			`UPDATE fuzz_steps SET ordinal = $1 WHERE id = $2`, 100000+i, id); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
	}
	for i, id := range req.StepIDs {
		if _, err := dbPool.Exec(ctx,
			`UPDATE fuzz_steps SET ordinal = $1, updated_at = NOW() WHERE id = $2`, i, id); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"reordered": len(req.StepIDs)})
}

// PreviewFuzzStep renders exactly what the step would send, and every reason it should not run.
func PreviewFuzzStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stepID := mux.Vars(r)["step_id"]

	ctx := context.Background()
	step, err := loadFuzzStep(ctx, stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "step not found")
		return
	}

	var scopeTargetID string
	if err := dbPool.QueryRow(ctx,
		`SELECT scope_target_id FROM fuzz_flows WHERE id = $1`, step.FlowID).
		Scan(&scopeTargetID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	rendered := RenderFuzzStepFor(ctx, step, LoadScanScope(scopeTargetID), scopeTargetID,
		"/tmp/fuzz/<run>/"+step.ID+".req", "/tmp/fuzz/<run>/"+step.ID+".json")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"step":     step,
		"rendered": rendered,
		"runnable": len(rendered.Errors) == 0,
	})
}

func orEmptyOptions(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// writeFuzzStep returns a saved step along with any option key that nothing will read.
//
// Silence here is what let a step sit with options nobody honoured: the blob saves, the API answers
// 200, and the next run behaves exactly as it did before. Naming the ignored keys in the same
// response is the cheapest place to catch a typo.
func writeFuzzStep(w http.ResponseWriter, step FuzzStep) {
	body := map[string]interface{}{
		"id": step.ID, "flow_id": step.FlowID, "ordinal": step.Ordinal, "tool": step.Tool,
		"name": step.Name, "enabled": step.Enabled, "raw_request": step.RawRequest,
		"scheme": step.Scheme, "port": step.Port, "target_host": step.TargetHost,
		"ffuf_mode": step.FFUFMode, "x8_place": step.X8Place, "options": step.Options,
		"positions": step.Positions,
	}
	if unknown := UnrecognisedFuzzOptions(step.Options); len(unknown) > 0 {
		body["unrecognised_options"] = unknown
		body["warning"] = "These option keys are not read by anything and will have no effect: " +
			strings.Join(unknown, ", ") + ". See option_reference for the keys that are."
	}
	json.NewEncoder(w).Encode(body)
}

// GetFuzzOptionReference is the documented contract for a step's options, served rather than
// duplicated in a UI or an MCP tool where it would drift from what fuzfOptionArgs actually reads.
func GetFuzzOptionReference(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":     FuzzOptionKeys,
		"meta":        FuzzOptionMetas,
		"groups":      FuzzOptionGroups,
		"owned_flags": FuzzOwnedFlags,
		"note": "Options are per step. ffuf's default matcher is 200,204,301,302,307,401,403,405,500 " +
			"when matchStatus is unset, which is why a step against an endpoint behind auth reports " +
			"one finding per wordlist word. Set filterStatus or filterSize to the response the target " +
			"gives to everything, or matchStatus to what you actually want.",
		"wordlists": map[string]string{
			"builtin-default": "/app/wordlists/ffuf-wordlist-5000.txt, 5000 generic paths",
			"builtin-small":   "/app/wordlists/ffuf-wordlist-default-small.txt, 2500 generic paths",
			"builtin-large":   "/app/wordlists/ffuf-wordlist-default-long.txt, 90821 generic paths",
			"builtin-headers": "/app/wordlists/ffuf-headers.txt, 141 header names",
			"builtin-cookies": "/app/wordlists/ffuf-cookies.txt, 183 cookie and flag names",
		},
	})
}
