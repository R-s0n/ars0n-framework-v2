package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Built flows listed alongside detected ones, and the mapping from a flow to the STRIDE threat it
// demonstrates.
//
// TWO SEPARATE PROBLEMS, ONE FILE, because they are the same idea from two directions: a flow is
// only useful when you can find it, and a threat is only credible when you can replay the sequence
// that proves it.

// BuiltFlowSummaries returns the operator-assembled flows for a target, shaped as FlowSummary so one
// list can carry both kinds.
//
// WHY BUILT FLOWS ARE NOT QUERY-FILTERED, and why that is stated rather than hidden. The list query
// is a grammar over CAPTURES: "method = POST AND status >= 400" asks what the browser actually did.
// A built flow has steps, not captures, and its steps may never have been sent, so there is no
// response to match a status against. Silently dropping built flows whenever a query is typed would
// make them vanish for a reason nobody could see; silently matching them against a query they cannot
// answer would be worse. They are always returned, and the response says so.
func BuiltFlowSummaries(ctx context.Context, scopeTargetID string) ([]FlowSummary, error) {
	if dbPool == nil {
		return nil, nil
	}
	// The verification state is DERIVED, not stored, and needs no migration.
	//
	// A built flow is trustworthy only once it has actually run: until then its steps are text
	// somebody wrote and nothing has confirmed the target still answers them. Three states fall out
	// of two timestamps:
	//   unverified - no run has ever happened
	//   stale      - a run happened, but a step has been edited since, so the run describes
	//                different bytes from the ones that would be sent now
	//   verified   - the newest run is newer than the newest step edit
	//
	// Compared against the newest STEP timestamp rather than request_flows.updated_at, because
	// editing a step does not bump the parent row - measured on this target, where a flow last
	// touched at 01:08 has steps edited at 20:22. Using the parent would report a stale flow as
	// verified, which is the one direction this must never get wrong.
	rows, err := dbPool.Query(ctx, `
		SELECT f.id::text, COALESCE(f.name,''), COALESCE(f.description,''), COALESCE(f.base_url,''),
		       COALESCE(f.source,''), f.created_at, f.updated_at,
		       (SELECT count(*) FROM request_flow_steps s WHERE s.request_flow_id = f.id),
		       (SELECT max(r.started_at) FROM request_flow_runs r WHERE r.request_flow_id = f.id),
		       (SELECT max(s.updated_at) FROM request_flow_steps s WHERE s.request_flow_id = f.id),
		       (SELECT r.id::text FROM request_flow_runs r WHERE r.request_flow_id = f.id
		         ORDER BY r.started_at DESC LIMIT 1),
		       (SELECT r.outcome FROM request_flow_runs r WHERE r.request_flow_id = f.id
		         ORDER BY r.started_at DESC LIMIT 1)
		FROM request_flows f
		WHERE f.scope_target_id = $1
		ORDER BY f.updated_at DESC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlowSummary
	for rows.Next() {
		var s FlowSummary
		var baseURL, source string
		var steps int
		var lastRun, newestStep *time.Time
		var lastRunID, lastRunOutcome *string
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &baseURL, &source,
			&s.StartedAt, &s.EndedAt, &steps, &lastRun, &newestStep, &lastRunID,
			&lastRunOutcome); err != nil {
			return nil, err
		}
		s.Kind = "built"
		s.StepCount = steps

		s.Verification = FlowVerificationState(lastRun, newestStep)
		if lastRunID != nil {
			s.LastRunID = *lastRunID
		}
		if lastRunOutcome != nil {
			s.LastRunOutcome = *lastRunOutcome
		}
		if lastRun != nil {
			s.LastRunAt = *lastRun
		}
		s.Host = hostOf(baseURL)
		// The label says where it came from, because a flow seeded from a detected one and a flow
		// typed from scratch warrant different trust and the source is the only record of which.
		s.Label = "Built flow"
		if source != "" && source != "blank" {
			s.Label = "Built from " + strings.ReplaceAll(source, "_", " ")
		}
		// RequestCount mirrors StepCount so a client that only knows the detected shape still renders
		// a sensible number rather than a zero, while StepCount carries the honest name.
		s.RequestCount = steps
		s.ShownCount = steps
		s.RootKind = "built"
		s.StatusSummary = map[string]int{}
		if strings.TrimSpace(s.Name) == "" {
			// Same rule as a detected flow: every row in the list carries a title.
			s.Name = "(Untitled Built Flow)"
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// The three verification states, as strings, so a client can switch on them without re-deriving the
// rule from two timestamps and getting it wrong in the one direction that matters.
const (
	FlowVerificationUnverified = "unverified"
	FlowVerificationStale      = "stale"
	FlowVerificationVerified   = "verified"
)

// FlowVerificationState is THE rule, in one function, because it is now read from two places: the
// flow list, which paints the badge, and the runs endpoint, which hands over the trace a map is
// drawn from. Two copies of a comparison between two timestamps is how one of them ends up using
// request_flows.updated_at and reporting a stale flow as verified.
//
// newestStep is the newest STEP updated_at and NOT the parent flow's, because editing a step does
// not bump the parent row.
func FlowVerificationState(lastRun, newestStep *time.Time) string {
	switch {
	case lastRun == nil:
		return FlowVerificationUnverified
	case newestStep != nil && newestStep.After(*lastRun):
		return FlowVerificationStale
	default:
		return FlowVerificationVerified
	}
}

// ---------------------------------------------------------------------------
// Flow -> threat mapping
// ---------------------------------------------------------------------------

// EnsureFlowThreatLinkSchema creates the mapping table.
//
// flow_id IS TEXT AND NOT A FOREIGN KEY, for the same reason the vector selection table is not:
// a flow id comes from two different spaces. A built flow is a UUID in request_flows; a DETECTED
// flow is the composite "<session>~<tab>~<root capture>" string, which is provenance rather than a
// row anywhere. One FK could only ever accept half of them, and detected flows are the half an
// operator is most likely to want to attach to a threat, because they are a record of the traffic
// that demonstrates it.
//
// The threat side IS a real foreign key with ON DELETE CASCADE, because deleting a threat should
// take its links with it; a link pointing at a threat that no longer exists would render as a
// mapping to nothing.
func EnsureFlowThreatLinkSchema(ctx context.Context) error {
	if dbPool == nil {
		return nil
	}
	_, err := dbPool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS flow_threat_links (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    threat_id UUID NOT NULL REFERENCES threat_model(id) ON DELETE CASCADE,
		    flow_id TEXT NOT NULL,
		    flow_kind VARCHAR(16) NOT NULL DEFAULT 'detected',
		    note TEXT NOT NULL DEFAULT '',
		    created_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (threat_id, flow_id)
		);`)
	if err != nil {
		return err
	}
	_, err = dbPool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_flow_threat_links_threat ON flow_threat_links(threat_id);`)
	if err != nil {
		return err
	}
	_, err = dbPool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_flow_threat_links_flow ON flow_threat_links(scope_target_id, flow_id);`)
	return err
}

type flowThreatLink struct {
	ID          string `json:"id"`
	ThreatID    string `json:"threat_id"`
	FlowID      string `json:"flow_id"`
	FlowKind    string `json:"flow_kind"`
	Note        string `json:"note,omitempty"`
	ThreatTitle string `json:"threat_title,omitempty"`
	Mechanism   string `json:"mechanism,omitempty"`
	Category    string `json:"category,omitempty"`
	FlowName    string `json:"flow_name,omitempty"`
}

// GetFlowThreatLinks lists the mappings on a target, optionally narrowed to one threat or one flow.
func GetFlowThreatLinks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := r.Context()

	if err := EnsureFlowThreatLinkSchema(ctx); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	rows, err := dbPool.Query(ctx, `
		SELECT l.id::text, l.threat_id::text, l.flow_id, l.flow_kind, l.note,
		       COALESCE(t.mechanism,''), COALESCE(t.category,''), COALESCE(t.one_sentence,'')
		FROM flow_threat_links l
		LEFT JOIN threat_model t ON t.id = l.threat_id
		WHERE l.scope_target_id = $1
		ORDER BY t.category, l.created_at`, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	// Names for BOTH kinds, so a link renders as the flow's title rather than as an id the operator
	// has never seen and cannot recognise.
	//
	// The built half was missing and it was a real gap, not a cosmetic one: this handler only read
	// detected_flow_names, so a link to a BUILT flow came back with no flow_name at all and every
	// client was forced to fetch the whole flow list and join by id just to render a label. Built
	// names live in request_flows.name, which is one more query and removes that obligation.
	names, _ := LoadDetectedFlowNames(scopeTargetID)
	builtNames := map[string]string{}
	if rows, err := dbPool.Query(ctx,
		`SELECT id::text, COALESCE(name,'') FROM request_flows WHERE scope_target_id = $1`,
		scopeTargetID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, n string
			if rows.Scan(&id, &n) == nil {
				builtNames[id] = n
			}
		}
	}

	out := []flowThreatLink{}
	for rows.Next() {
		var l flowThreatLink
		var oneSentence string
		if rows.Scan(&l.ID, &l.ThreatID, &l.FlowID, &l.FlowKind, &l.Note,
			&l.Mechanism, &l.Category, &oneSentence) != nil {
			continue
		}
		l.ThreatTitle = l.Mechanism
		if l.ThreatTitle == "" {
			l.ThreatTitle = oneSentence
		}
		// Same precedence for both kinds: an operator-chosen name wins, otherwise the placeholder that
		// kind uses. FlowName is now ALWAYS set, so a client never has to join against the flow list
		// merely to have something to print.
		if n, ok := names[l.FlowID]; ok && strings.TrimSpace(n.Name) != "" {
			l.FlowName = n.Name
		} else if n, ok := builtNames[l.FlowID]; ok && strings.TrimSpace(n) != "" {
			l.FlowName = n
		} else if l.FlowKind == "built" {
			l.FlowName = "(Untitled Built Flow)"
		} else {
			l.FlowName = DefaultDetectedFlowName
		}
		out = append(out, l)
	}

	writeJSON(w, map[string]any{
		"links": out,
		"total": len(out),
		"note": "A link records that this flow is the sequence which demonstrates that threat. " +
			"flow_id is not a foreign key because a detected flow id is a composite provenance " +
			"string rather than a row; the threat side cascades on delete.",
	})
}

// SetFlowThreatLink maps a flow onto a threat, or removes the mapping.
func SetFlowThreatLink(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := r.Context()

	if err := EnsureFlowThreatLinkSchema(ctx); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	var payload struct {
		ThreatID string `json:"threat_id"`
		FlowID   string `json:"flow_id"`
		FlowKind string `json:"flow_kind"`
		Note     string `json:"note"`
		Remove   bool   `json:"remove"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	payload.ThreatID = strings.TrimSpace(payload.ThreatID)
	payload.FlowID = strings.TrimSpace(payload.FlowID)
	if payload.ThreatID == "" || payload.FlowID == "" {
		writeJSONError(w, http.StatusBadRequest, "ids_required",
			"threat_id and flow_id are both required.")
		return
	}

	if payload.Remove {
		tag, err := dbPool.Exec(ctx, `
			DELETE FROM flow_threat_links
			WHERE scope_target_id = $1 AND threat_id = $2 AND flow_id = $3`,
			scopeTargetID, payload.ThreatID, payload.FlowID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		writeJSON(w, map[string]any{"removed": tag.RowsAffected(), "threat_id": payload.ThreatID,
			"flow_id": payload.FlowID})
		return
	}

	// The threat must belong to this target. Without the check a link could be made to a threat on a
	// different engagement, and the mapping would then render on a target whose flows have nothing to
	// do with it.
	var exists bool
	if err := dbPool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM threat_model WHERE id = $1 AND scope_target_id = $2)`,
		payload.ThreatID, scopeTargetID).Scan(&exists); err != nil || !exists {
		writeJSONError(w, http.StatusNotFound, "threat_not_found",
			"No threat with that id on this scope target.")
		return
	}

	kind := strings.TrimSpace(payload.FlowKind)
	if kind != "built" {
		// A detected flow id carries two "~" separators; anything else is a built flow's UUID. Derived
		// rather than trusted so a caller that omits the field still stores the right kind.
		if strings.Count(payload.FlowID, "~") == 2 {
			kind = "detected"
		} else {
			kind = "built"
		}
	}

	if _, err := dbPool.Exec(ctx, `
		INSERT INTO flow_threat_links (scope_target_id, threat_id, flow_id, flow_kind, note)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (threat_id, flow_id) DO UPDATE SET note = EXCLUDED.note`,
		scopeTargetID, payload.ThreatID, payload.FlowID, kind, strings.TrimSpace(payload.Note)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	writeJSON(w, map[string]any{
		"linked": true, "threat_id": payload.ThreatID, "flow_id": payload.FlowID, "flow_kind": kind,
		"note_text": fmt.Sprintf("This flow is now recorded as demonstrating that threat. It shows on " +
			"the threat and on the flow, and deleting the threat removes the link."),
	})
}
