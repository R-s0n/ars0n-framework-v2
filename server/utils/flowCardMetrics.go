package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// The four numbers above the Request Flow Replay card's buttons.
//
// Every other card in the URL workflow carries a metrics row and this one did not, so the operator
// had five buttons and no way to tell which of them had work behind it. The four here are chosen to
// map onto those buttons, left to right:
//
//	ENDPOINTS    what Detect Flows would actually send to, of everything discovered.
//	FLOWS        how many flows are currently detected, with the passive/active/both split.
//	BUILT FLOWS  how many flows the operator assembled in the Request Flow Builder.
//	VERSIONS     how many saved request versions exist in the repeater.
//
// ============================================================================
// A ZERO AND A FAILURE MUST NOT LOOK THE SAME
// ============================================================================
//
// This is the load-bearing decision in the file. "0 flows" and "we could not count the flows" render
// as the same glyph on a card, and the operator will read the first one. So a metric that could not
// be read carries NO VALUE AT ALL: Value is a pointer and is omitted from the JSON, Available is
// false, and Error says what went wrong. A client cannot accidentally read 0 out of a failed metric
// because there is no number in the payload to read.
//
// For the same reason the handler returns 200 with three good numbers and one failure, rather than
// 500. A 500 blanks the whole row, including the numbers that were read perfectly well, and tells
// the operator nothing about which one broke.
//
// ============================================================================
// IT LOADS ON EVERY RENDER, SO IT IS FOUR PARALLEL READS AND NO MORE
// ============================================================================
//
// Each metric is one query, except ENDPOINTS, which reads the candidate tables, the deselections and
// both rails because a count that ignores the rails is not the count anybody reads it for (see below). They run concurrently, so the wall time is the slowest of the four rather than their sum,
// and the slowest is FLOWS: it has to segment the capture corpus, which is the same work
// GET /replay-request/{id}/flows does, because a flow is DERIVED and there is no table to count.
//
// Nothing here writes and nothing here sends a request to anything.

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

// FlowCardMetric is one number on the card.
//
// Value is a POINTER on purpose. See the note above: an absent number is the only honest way to say
// "not counted", and a zero-valued int would be indistinguishable from a real zero the moment it
// reached JSON.
//
// Parts is the breakdown behind the headline. Cheap to compute in the same query in every case, and
// the breakdown is what makes the headline actionable: "87 flows" is a number, "87 flows, 5 of them
// found by the active scanner" is a finding.
type FlowCardMetric struct {
	Available bool `json:"available"`
	// Value is the headline number. Absent when Available is false.
	Value *int `json:"value,omitempty"`
	// Parts is the breakdown. Absent when Available is false, for the same reason Value is.
	Parts map[string]int `json:"parts,omitempty"`
	// Error is why this number is missing, in the operator's words. Present only on failure.
	Error string `json:"error,omitempty"`
	// Note qualifies a number that IS available but does not mean what it looks like. Today the only
	// user is the capture scan ceiling: past it, the flow count is a floor and not a total, and a
	// floor rendered as a total is exactly the class of defect this file is careful about.
	Note string `json:"note,omitempty"`
	// TookMs is how long this metric took to read. Kept in the payload rather than only in a log
	// line, because the thing that will eventually make this endpoint slow is a corpus nobody is
	// looking at, and the number that would have shown it needs to be somewhere it gets seen.
	TookMs int64 `json:"took_ms"`
}

func availableMetric(value int, parts map[string]int, started time.Time) FlowCardMetric {
	v := value
	return FlowCardMetric{
		Available: true,
		Value:     &v,
		Parts:     parts,
		TookMs:    time.Since(started).Milliseconds(),
	}
}

func unavailableMetric(err error, started time.Time) FlowCardMetric {
	return FlowCardMetric{
		Available: false,
		Error:     err.Error(),
		TookMs:    time.Since(started).Milliseconds(),
	}
}

// FlowCardMetrics is the whole response.
type FlowCardMetrics struct {
	ScopeTargetID string `json:"scope_target_id"`
	// Endpoints: Value is how many a run would actually SEND to, and Parts carries the whole
	// partition - total, selected, deselected, excluded, out_of_scope, sendable. The card reads
	// "22" with "of 1,872 discovered" underneath.
	//
	// The headline is sendable and not selected, because selected is total minus the operator's own
	// deselections and ignores every rail: on a live target here it read 1,872 above a button that
	// would have touched 22.
	Endpoints FlowCardMetric `json:"endpoints"`
	// Flows: Value is how many flows are detected, Parts is the passive/active/both split plus the
	// number of captures they were reconstructed from.
	Flows FlowCardMetric `json:"flows"`
	// BuiltFlows: Value is how many flows exist in the builder, Parts carries the step total. A built
	// flow with no steps replays nothing, so the two numbers together say whether the work is done.
	BuiltFlows FlowCardMetric `json:"built_flows"`
	// Versions: Value is every saved version, Parts splits the materialised originals from the edits.
	Versions FlowCardMetric `json:"versions"`
	// TookMs is the wall time of the whole handler, which is the slowest of the four and not the sum.
	TookMs int64 `json:"took_ms"`
}

// ---------------------------------------------------------------------------
// ENDPOINTS: sendable of discovered
// ---------------------------------------------------------------------------

// flowCardEndpointsMetric reads the whole partition, not just total and selected.
//
// IT USED TO SKIP THE RAILS TO SAVE THREE QUERIES, and the saving cost more than it was worth.
// Selected is Total minus the deselections and depends on no rail, which is true and is not the
// number the card is being read for: on a live target here, Configure reports total 1,872,
// selected 1,872 and SENDABLE 22, because 1,850 of those endpoints sit on hosts outside the
// boundary. A card saying "1,872 of 1,872" above a Detect Flows button that would touch 22 is a
// count that is not a count, which is the failure this file's header is otherwise careful about.
//
// So the rails are loaded and BuildFlowEndpointList computes the summary, rather than a second
// partitioner living here. It allocates a row per endpoint and sorts them, which is the cost the
// old note objected to; the filter's Limit throws all but one row away immediately and the whole
// handler still lands in ~25ms on the largest live corpus. One partitioner means the card and the
// Configure screen cannot disagree, which the old arrangement guaranteed only for two of six fields.
//
// FAILS THE METRIC, NOT THE RESPONSE, on any read error. A card that omits one number is honest; a
// card that reports every endpoint as sendable because the deny list did not load is not.
func flowCardEndpointsMetric(scopeTargetID string) FlowCardMetric {
	started := time.Now()

	candidates, err := loadFlowDetectionCandidates(scopeTargetID)
	if err != nil {
		return unavailableMetric(err, started)
	}
	// Fatal, not substituted with an empty set. An empty set here would report every endpoint as
	// selected while the operator's deselections sat unread, which is a card claiming the scanner
	// will cover surface it has been told to skip.
	deselected, err := LoadFlowEndpointDeselections(scopeTargetID)
	if err != nil {
		return unavailableMetric(err, started)
	}
	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		return unavailableMetric(err, started)
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		return unavailableMetric(err, started)
	}

	// Limit 1 because only the summary is wanted here; it is computed over every row before the
	// filter is applied, so the number is the whole corpus and not this page of it.
	_, summary := BuildFlowEndpointList(candidates, nil, deselected, rules, denied,
		LoadScanScope(scopeTargetID), FlowEndpointFilter{Limit: 1})

	return availableMetric(summary.Sendable, map[string]int{
		"total":        summary.Total,
		"selected":     summary.Selected,
		"deselected":   summary.Deselected,
		"excluded":     summary.Excluded,
		"out_of_scope": summary.OutOfScope,
		"sendable":     summary.Sendable,
	}, started)
}

// ---------------------------------------------------------------------------
// FLOWS: detected, with the passive/active/both split
// ---------------------------------------------------------------------------

// flowCardFlowsMetric counts the flows GET /replay-request/{id}/flows would return for an empty
// query, and splits them the way that endpoint's detection_sources map does.
//
// A FLOW IS DERIVED, NOT STORED. There is no flows table to count: a flow is a segment of
// manual_crawl_captures cut at navigations and idle gaps by segmentCaptureFlows, so the only honest
// count is the one that runs the same segmenter over the same rows. A cheaper SQL approximation -
// counting navigations, say, or distinct (session, tab) pairs - would produce a number that looks
// like the flow count, sits next to a button that opens the real list, and disagrees with it.
//
// ONE QUERY, and it is LEANER than the one the flows endpoint uses. The segmenter reads id, session,
// tab, resource type, url, timestamp and redirect chain; the source split adds method and
// capture_source. Everything else on that projection - status, initiator, mime type, duration and
// especially octet_length(response_body) - exists to render a summary this card does not show, and
// octet_length over a corpus of response bodies is the expensive part of it. The fields left unset
// on FlowCapture are precisely the ones neither segmentCaptureFlows nor DeriveFlowDetectionSources
// reads.
//
// It also folds in the capture_source lookup that FlowDetectionSources does as a SECOND query. Same
// two facts, one round trip, because here they are read together.
func flowCardFlowsMetric(scopeTargetID string) FlowCardMetric {
	started := time.Now()

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, session_id, tab_id, COALESCE(method,''), COALESCE(url,''),
		       COALESCE(resource_type,''), timestamp,
		       COALESCE(redirect_chain,'[]'::jsonb),
		       COALESCE(capture_source,'passive')
		  FROM manual_crawl_captures
		 WHERE scope_target_id = $1
		 ORDER BY timestamp ASC
		 LIMIT $2`, scopeTargetID, flowScanCeiling)
	if err != nil {
		return unavailableMetric(err, started)
	}
	defer rows.Close()

	captures := make([]FlowCapture, 0, 512)
	sources := make(map[string]string, 512)
	for rows.Next() {
		var c FlowCapture
		var tabID *int
		var chainJSON []byte
		var source string
		if err := rows.Scan(&c.ID, &c.SessionID, &tabID, &c.Method, &c.URL,
			&c.ResourceType, &c.Timestamp, &chainJSON, &source); err != nil {
			// One unreadable row loses one capture, not the whole number. The same choice
			// queryFlowCaptures makes, and for the same reason: the alternative is a card that goes
			// blank because a single column somewhere is malformed.
			log.Printf("[FLOW-METRICS] Skipped an unreadable capture row: %v", err)
			continue
		}
		c.TabID = tabID
		if len(chainJSON) > 0 {
			// redirect_chain is written by the browser extension and is the only column here whose
			// shape the schema does not enforce. A chain that will not parse costs this capture its
			// redirect edges, which can only ever SPLIT a flow in two - so the count errs high, and
			// it errs visibly, because the same rows split the same way in the list the operator
			// opens next.
			if uerr := json.Unmarshal(chainJSON, &c.RedirectChain); uerr != nil {
				c.RedirectChain = nil
			}
		}
		captures = append(captures, c)
		sources[c.ID] = source
	}
	if err := rows.Err(); err != nil {
		return unavailableMetric(err, started)
	}

	segments := segmentCaptureFlows(captures)

	inputs := make([]FlowDetectionInput, 0, len(segments))
	for _, flow := range segments {
		if len(flow.Captures) == 0 {
			continue
		}
		root := flow.Captures[0]
		in := FlowDetectionInput{ID: EncodeFlowID(root.SessionID, root.TabID, root.ID)}
		for _, c := range flow.Captures {
			src := sources[c.ID]
			if src == "" {
				src = FlowSourcePassive
			}
			in.CaptureSources = append(in.CaptureSources, src)
			in.Tuples = append(in.Tuples, NormalizeFlowTuple(c.Method, c.URL))
		}
		inputs = append(inputs, in)
	}

	parts := map[string]int{
		FlowSourcePassive: 0,
		FlowSourceActive:  0,
		FlowSourceBoth:    0,
		"captures":        len(captures),
	}
	for _, kind := range DeriveFlowDetectionSources(inputs) {
		parts[kind]++
	}

	metric := availableMetric(len(inputs), parts, started)
	if len(captures) >= flowScanCeiling {
		// A floor, and it says so. The flows list applies the same ceiling, so the two screens still
		// agree with each other; what they cannot do is claim to have seen the whole corpus.
		metric.Note = "the capture scan stopped at its ceiling, so this is a floor and not a total"
	}
	return metric
}

// ---------------------------------------------------------------------------
// BUILT FLOWS: what the operator assembled
// ---------------------------------------------------------------------------

// flowCardBuiltFlowsMetric counts the flows in the builder and the steps inside them, in one query.
//
// COUNT(DISTINCT f.id) rather than COUNT(*), because the join multiplies a flow by its steps: a
// three-step flow would otherwise count as three flows. The steps figure is worth carrying because a
// built flow with no steps replays nothing, and "2 built flows" with no steps behind them is a
// half-finished job that looks finished on a card.
func flowCardBuiltFlowsMetric(scopeTargetID string) FlowCardMetric {
	started := time.Now()

	var flows, steps int
	err := dbPool.QueryRow(context.Background(), `
		SELECT COUNT(DISTINCT f.id), COUNT(s.id)
		  FROM request_flows f
		  LEFT JOIN request_flow_steps s ON s.request_flow_id = f.id
		 WHERE f.scope_target_id = $1`, scopeTargetID).Scan(&flows, &steps)
	if err != nil {
		return unavailableMetric(err, started)
	}
	return availableMetric(flows, map[string]int{"steps": steps}, started)
}

// ---------------------------------------------------------------------------
// VERSIONS: the repeater's saved requests
// ---------------------------------------------------------------------------

// flowCardVersionsMetric counts saved request versions, splitting the materialised originals from
// the operator's own edits.
//
// The split is not decoration. ListReplayRequestVersions MATERIALISES an original the first time a
// capture is opened, so a target where somebody browsed the repeater and changed nothing still has
// rows in this table. Reporting that as "9 versions" would credit the operator with work they have
// not done; "9, 4 of them edits" is the true shape.
//
// EnsureReplayRequestVersionsSchema is called first because this table is created lazily by the
// handlers that own it. Without it, a fresh install renders this metric as a missing-relation error
// on every page load until somebody opens the repeater.
func flowCardVersionsMetric(scopeTargetID string) FlowCardMetric {
	started := time.Now()
	EnsureReplayRequestVersionsSchema()

	var total, originals, edited int
	err := dbPool.QueryRow(context.Background(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE is_original),
		       COUNT(*) FILTER (WHERE NOT is_original)
		  FROM replay_request_versions
		 WHERE scope_target_id = $1`, scopeTargetID).Scan(&total, &originals, &edited)
	if err != nil {
		return unavailableMetric(err, started)
	}
	return availableMetric(total, map[string]int{
		"originals": originals,
		"edited":    edited,
	}, started)
}

// ---------------------------------------------------------------------------
// GET /flow-metrics/{scope_target_id}
// ---------------------------------------------------------------------------

// GetFlowCardMetrics returns all four, reading them concurrently.
//
// Four goroutines and four pool connections for the length of one page render. The reads are
// independent and none of them writes, so there is no ordering to preserve and no transaction to
// keep them consistent with each other; what the operator sees is four facts read at the same
// moment, which is what the card claims.
//
// A metric that fails does not fail the response. See the note at the top of the file: the operator
// gets the three numbers that were read and an explicit gap where the fourth would be.
func GetFlowCardMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required",
			"scope_target_id must be a UUID")
		return
	}
	if dbPool == nil {
		writeJSONError(w, http.StatusInternalServerError, "database_unavailable",
			"The database connection is not available")
		return
	}

	started := time.Now()
	out := FlowCardMetrics{ScopeTargetID: scopeTargetID}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); out.Endpoints = flowCardEndpointsMetric(scopeTargetID) }()
	go func() { defer wg.Done(); out.Flows = flowCardFlowsMetric(scopeTargetID) }()
	go func() { defer wg.Done(); out.BuiltFlows = flowCardBuiltFlowsMetric(scopeTargetID) }()
	go func() { defer wg.Done(); out.Versions = flowCardVersionsMetric(scopeTargetID) }()
	wg.Wait()

	out.TookMs = time.Since(started).Milliseconds()

	// Logged only when something is missing or the read was slow. This endpoint runs on every render
	// of the workflow page and a line per load would bury everything else in the API log.
	for name, m := range map[string]FlowCardMetric{
		"endpoints": out.Endpoints, "flows": out.Flows,
		"built_flows": out.BuiltFlows, "versions": out.Versions,
	} {
		if !m.Available {
			log.Printf("[FLOW-METRICS] %s could not be counted for %s: %s", name, scopeTargetID, m.Error)
		}
	}
	if out.TookMs > 500 {
		log.Printf("[FLOW-METRICS] Slow read for %s: %dms total (endpoints %dms, flows %dms, "+
			"built_flows %dms, versions %dms)", scopeTargetID, out.TookMs, out.Endpoints.TookMs,
			out.Flows.TookMs, out.BuiltFlows.TookMs, out.Versions.TookMs)
	}

	json.NewEncoder(w).Encode(out)
}
