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
// ensureFuzzFlow returns the target's DEFAULT flow, creating it if the target has none.
//
// A target can now hold several named flows, because ffuf is used for several unrelated jobs and
// they want different wordlists, insertion points, filters and pacing. Callers that do not name one
// get the default, so everything that worked against the single-flow model still works.
func ensureFuzzFlow(ctx context.Context, scopeTargetID string) (string, error) {
	var id string
	if err := dbPool.QueryRow(ctx, `
		SELECT id FROM fuzz_flows WHERE scope_target_id = $1 AND is_default
		LIMIT 1`, scopeTargetID).Scan(&id); err == nil {
		return id, nil
	}
	// No default yet. Adopt the oldest existing flow rather than creating a second one, so a database
	// written before flows had names does not silently gain an empty flow beside its real one.
	if err := dbPool.QueryRow(ctx, `
		UPDATE fuzz_flows SET is_default = TRUE, updated_at = NOW()
		WHERE id = (SELECT id FROM fuzz_flows WHERE scope_target_id = $1
		            ORDER BY created_at LIMIT 1)
		RETURNING id`, scopeTargetID).Scan(&id); err == nil {
		return id, nil
	}
	err := dbPool.QueryRow(ctx, `
		INSERT INTO fuzz_flows (scope_target_id, name, purpose, is_default)
		VALUES ($1, 'Default flow', 'custom', TRUE)
		RETURNING id`, scopeTargetID).Scan(&id)
	return id, err
}

// FuzzFlowPurpose is one of the jobs ffuf actually gets used for.
//
// Named rather than free text because the purpose decides which template to offer, which guidance to
// attach, and what a sensible wordlist looks like. This taxonomy is Burp Intruder's, which is the
// right frame: ffuf is Intruder, and Intruder is not one thing.
type FuzzFlowPurpose struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// What is being fuzzed: the NAME of an input, its VALUE, or a path.
	Fuzzes string `json:"fuzzes"`
	Why    string `json:"why"`
	// The Intruder attack type this most resembles, for anyone who learned it there first.
	IntruderAnalogue string   `json:"intruder_analogue"`
	Wordlists        string   `json:"wordlists"`
	Watch            string   `json:"watch_for"`
	Examples         []string `json:"examples,omitempty"`
}

// FuzzFlowPurposes is the catalogue. Ordered as they are actually run.
var FuzzFlowPurposes = []FuzzFlowPurpose{
	{
		Key: "content-discovery", Title: "Content discovery", Fuzzes: "the PATH",
		Why: "Finds what nothing links to: admin panels, staging routes, old API versions, backups " +
			"and configuration left in the web root. This is the first thing to run against a new " +
			"target and the step whose absence leaves the access-control sections with no targets.",
		IntruderAnalogue: "Sniper over a single position in the URL path",
		Wordlists: "Start with common.txt or quickhits.txt to set filters, then raft-medium-" +
			"directories and raft-medium-files, then extensions matched to the stack.",
		Watch: "The not-found baseline. If a miss returns 200 with a themed page, status matching is " +
			"useless and you filter on size, words or lines. Keep 401 and 403: those are findings.",
		Examples: []string{"https://target/FUZZ", "https://target/admin/FUZZ"},
	},
	{
		Key: "name-enumeration", Title: "Hidden name enumeration", Fuzzes: "the NAME of a parameter, header or cookie",
		Why: "Finds inputs the application reads but never advertises. The value sent is irrelevant " +
			"and constant; what matters is whether NAMING the input changes the response at all. A " +
			"parameter nobody documented is a parameter nobody reviewed.",
		IntruderAnalogue: "Sniper, with the payload in the parameter name rather than its value",
		Wordlists:        "Parameter name lists, header name lists, cookie name lists.",
		Watch: "The baseline response size. This is a differential technique: you are looking for any " +
			"deviation from the unmodified request, not for a specific string.",
		Examples: []string{"https://target/page?FUZZ=canary", "Header: FUZZ: canary"},
	},
	{
		Key: "value-fuzzing", Title: "Value fuzzing", Fuzzes: "the VALUE of a known input",
		Why: "Once you know an input exists, this is how you learn what it does. Different values " +
			"produce different behaviour: an error, a redirect, a longer page, a different record. " +
			"This is where logic flaws and injection candidates surface.",
		IntruderAnalogue: "Sniper over one position, or Cluster bomb across two",
		Wordlists:        "Payload lists matched to the hypothesis: traversal, SQL, template, IDs, enum values.",
		Watch: "Anything that differs from the baseline, including timing. A value that changes the " +
			"response is telling you the application acts on it.",
		Examples: []string{"https://target/catalog?category=FUZZ"},
	},
	{
		Key: "identifier-enumeration", Title: "Identifier enumeration", Fuzzes: "an object identifier",
		Why: "Walks an id space to find records you should not be able to reach. This is how an IDOR " +
			"goes from one proven case to a demonstration of scope.",
		IntruderAnalogue: "Sniper with a number range payload",
		Wordlists:        "A numeric range, or identifiers harvested from the application itself.",
		Watch: "Responses that differ from the not-found case. Stop as soon as impact is proven: " +
			"walking a live customer table is neither necessary nor authorised.",
		Examples: []string{"https://target/order/details?orderId=FUZZ"},
	},
	{
		Key: "auth-bruteforce", Title: "Credential and token attacks", Fuzzes: "credentials or tokens",
		Why: "Password spraying, credential stuffing and token guessing. The highest-risk flow to run " +
			"and the one most likely to be out of scope, so check the program rules first.",
		IntruderAnalogue: "Cluster bomb for user and password pairs, Pitchfork for paired lists",
		Wordlists:        "Credential lists, or a single password across many usernames for spraying.",
		Watch: "Lockout. Also the difference between a wrong password and a wrong username, which is " +
			"a username enumeration finding in its own right.",
	},
	{
		Key: "vhost-discovery", Title: "Virtual host discovery", Fuzzes: "the Host header",
		Why: "Finds applications served from the same address under a different hostname, which " +
			"routine DNS enumeration never sees because those names may not resolve publicly.",
		IntruderAnalogue: "Sniper on the Host header",
		Wordlists:        "Subdomain name lists.",
		Watch: "Calibrate against a hostname you know is wrong, then look for anything that differs " +
			"from it.",
	},
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
	// Which flow to read. Empty means the target's default, so every existing caller is unaffected.
	// Without this a non-default flow's steps could never be read back, which made every flow except
	// one write-only at creation and invisible afterwards.
	requestedFlow := strings.TrimSpace(r.URL.Query().Get("flow_id"))

	ctx := context.Background()
	flowID, err := fuzzFlowIDFor(ctx, scopeTargetID, requestedFlow)
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
	// FlowID names WHICH flow this step belongs to. Without it every step landed in the target's
	// default flow no matter which flow the caller named, so a non-default flow could be created and
	// then never written to or read back: created, listed, renamed, deleted, and otherwise unreachable.
	// That made the named-flows feature look complete while being unusable for its entire purpose.
	FlowID         string         `json:"flow_id"`
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

	flowID, err := fuzzFlowIDFor(ctx, scopeTargetID, req.FlowID)
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
