package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Request Flow Builder: the operator assembles a flow by hand.
//
// The passive detector in replayRequestFlows.go reconstructs what the browser DID. The repeater
// replays one request. Neither lets the operator say "these four requests, in this order, with the
// token from step two carried into step three, and I want to change the third one". That is the gap
// this fills, and it is the shape almost every access-control and business-logic test actually takes.
//
// ---------------------------------------------------------------------------
// Why its own tables, and not auth_flows.category = 'custom'
// ---------------------------------------------------------------------------
//
// auth_flows already has a category column, so reusing it looks like the cheap option. It is not,
// because category does not discriminate KIND, it discriminates WHICH AUTHENTICATION CEREMONY:
// register, login, mfa_otp, magic_link, reset. Three separate subsystems read the mere EXISTENCE of
// an auth_flows row as "this target has a way to authenticate", not as "here is an ordered list of
// requests":
//
//   - scopeTargetMetrics.go counts every auth_flows row into the "session" metric behind the
//     Authentication card. A hand-built checkout flow would be counted as a captured authentication.
//   - miscTargets.go's authFlowStepsSource joins auth_flow_steps to auth_flows and scans every
//     raw_request for JWTs to attack. Builder steps would silently join the jwt_tool corpus.
//   - session_tokens.auth_flow_id is documented as "the auth flow that can produce another one",
//     the refresh mechanism. Every builder flow would appear in that picker as something able to
//     mint a session, which it cannot.
//   - GetAuthFlows with no category filter returns everything, so builder flows would appear in the
//     Authentication modal's list.
//
// Fixing that under option (a) means adding `AND category <> 'custom'` in four places across files
// this feature does not own, and every one of them is a filter the next reader has to remember to
// add. The cost is not the four lines, it is that omitting the fifth is silent.
//
// Option (b) as literally worded, "a thin new table that references the same step machinery", cannot
// mean hanging steps off auth_flow_steps either: that column is
// `auth_flow_id UUID NOT NULL REFERENCES auth_flows(id)`, so a builder step needs either a
// nullable-FK migration on another feature's table or a shadow auth_flows row, and a shadow row
// reintroduces exactly the pollution above.
//
// So: two new tables, and the reuse happens at the FUNCTION layer, which is where the value actually
// is. Everything subtle about replaying a flow is already table-agnostic and is called directly from
// here, unchanged:
//
//	prepareStepRequest       substitution + honest Content-Length     authFlowsVariables.go
//	substituteAuthFlowVars   {{af:NAME}} with body-aware encoding      authFlowsVariables.go
//	runAuthFlowExtractions   capture out of a response                 authFlowsVariables.go
//	validateExtractionSet    refuse an unusable rule at save time      authFlowsUtils.go
//	sendRawRequest           the transport, no redirect follow         authFlowsUtils.go
//	resolveBaseURL           Host header wins, base_url is fallback    authFlowsUtils.go
//	seedJar                  cookies attributed to their issuer        authFlowsUtils.go
//	sanitizeForTextColumn    a body Postgres can actually store        authFlowsUtils.go
//	BuildRawHTTPRequest      capture -> editable bytes                 captureBridgeUtils.go
//	segmentCaptureFlows      which captures are one flow               replayRequestFlows.go
//
// The only thing not reused verbatim is replayFlowSteps itself, and only because its one persistence
// call, updateStepResponse, names auth_flow_steps in its SQL. runRequestFlowConditional in
// flowConditions.go is that loop with that line changed and with branching on top; the shared cookie
// jar and the variable map still come for free, and still work across a jump.
//
// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------
//
// A hand-authored step is the repeater's risk profile: the operator typed the bytes. Two things are
// still enforced here, because neither is the operator's typing.
//
// SEEDING NEVER ARMS A STATE-CHANGING REQUEST. Importing a detected flow copies in captured POST,
// PUT, PATCH and DELETE bodies, and those bodies carry real identifiers: the operator's own notes on
// one live target record six endpoints that dispatch a one-time code to a real customer when hit
// with a resolvable identifier. So a seeded step whose verb can change state arrives DISABLED, and
// the seed response says how many and why. Turning one on is a separate, deliberate action on a step
// the operator is looking at. This is the GET-only-by-default rule expressed for a builder: refusing
// POST outright would make the feature pointless, but nothing this code puts in a flow will fire a
// captured body at the target unless a human armed it.
//
// THE BOUNDARY IS ENFORCED ON EVERY SEND, and it is three checks, not one. flowSendRails carries
// them: the operator's in_scope=false deny list, the scope boundary, and the flow exclusion rules,
// applied in that order by requestFlowScopeRefusal. LoadScanScope alone is NOT sufficient and the
// earlier version of this comment claiming it was is what let two of the three be missed; see the
// comment on flowSendRails for the two sends that were measured getting through.
//
// A refused step is recorded ON the step so the reason is visible rather than logged, and the
// boundary is returned by the read and preview endpoints so the operator sees which steps will be
// refused BEFORE replaying rather than after.

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// RequestFlowBuilderSchema is the DDL for this feature, exported so it can be appended to the
// migration list in database.go without this file having to reach into it.
//
// Idempotent throughout: every statement is IF NOT EXISTS, so running it on an existing install is a
// no-op and it is safe to call on every boot.
var RequestFlowBuilderSchema = []string{
	`CREATE TABLE IF NOT EXISTS request_flows (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		-- Fallback origin for a step with no Host header. resolveBaseURL treats a step's own Host
		-- header as authoritative, so this is not an override: a flow that crosses hosts still works.
		base_url TEXT NOT NULL DEFAULT '',
		-- How the flow was made: blank, detected_flow, or captures. Kept because "why does this flow
		-- have eleven steps I do not recognise" is a question the operator will ask.
		source VARCHAR(24) NOT NULL DEFAULT 'blank',
		-- The derived flow id this was seeded from. TEXT and not a foreign key on purpose: a detected
		-- flow is computed on every request and has no row to point at, and re-segmentation can retire
		-- the id entirely (see the flow_not_found path in replayRequestFlows.go). It is provenance,
		-- not a join.
		seeded_from_flow_id TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);`,
	`CREATE TABLE IF NOT EXISTS request_flow_steps (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		request_flow_id UUID NOT NULL REFERENCES request_flows(id) ON DELETE CASCADE,
		step_order INTEGER NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		-- The full request, byte for byte, as the operator may edit it.
		raw_request TEXT NOT NULL,
		-- Which capture these bytes came from, NULL when typed by hand. Provenance again: an edited
		-- step and the recording it started as are different things and the operator should be able
		-- to tell them apart.
		source_capture_id UUID,
		-- A disabled step keeps its place and is skipped on replay. Deleting to prune, as with
		-- auth_recorded_requests.included, would destroy the sequence, and the sequence is the flow.
		-- Seeded state-changing steps arrive disabled; see requestFlowSeedEnabled.
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		-- Same shape and same code path as auth_flow_steps.extractions: {{af:NAME}} carried forward.
		extractions JSONB NOT NULL DEFAULT '[]'::jsonb,
		-- An ORDERED list of {when, then, target, message}, evaluated against the response this step
		-- produced. See flowConditions.go. JSONB and not its own table for the same reason extractions
		-- is: the list is only ever read and written whole, with the step, and its ORDER is part of its
		-- meaning (first match wins), which a row set would have to re-impose with another order column.
		conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
		response_status INTEGER,
		response_headers JSONB,
		response_body TEXT,
		response_time_ms FLOAT,
		error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW()
	);`,
	// Order is a fact, not a tie-break, for the same reason it is on auth_flow_steps: every read
	// orders by step_order alone, so two steps sharing a number make the order of those two whatever
	// the planner returned. Unlike auth_flow_steps this index is created unconditionally, because the
	// table is new and cannot already hold duplicates. requestFlowWriteOrder parks in negative space
	// so a permutation never violates it mid-transaction.
	`CREATE UNIQUE INDEX IF NOT EXISTS uq_request_flow_steps_order
	   ON request_flow_steps(request_flow_id, step_order);`,
	`CREATE INDEX IF NOT EXISTS idx_request_flows_target
	   ON request_flows(scope_target_id, created_at DESC);`,
	`CREATE INDEX IF NOT EXISTS idx_request_flow_steps_flow
	   ON request_flow_steps(request_flow_id, step_order);`,

	// Conditions arrived after the table did, so the CREATE above only covers a fresh install. An
	// existing install needs the column added, and IF NOT EXISTS keeps this a no-op afterwards. The
	// default matters: every step that predates branching reads back as an empty list, which is
	// exactly "no conditions", which is exactly the linear behaviour it had yesterday.
	`ALTER TABLE request_flow_steps
	   ADD COLUMN IF NOT EXISTS conditions JSONB NOT NULL DEFAULT '[]'::jsonb;`,

	// One row per RUN, carrying the execution trace.
	//
	// The trace is the run's explanation, and a branching run has no other one: the step rows only
	// ever hold the LAST response, so a step that ran three times leaves two of them nowhere else. It
	// is stored as JSONB rather than a row per execution because it is written once, read whole, and
	// never queried across runs - and because a trace whose rows can be deleted individually is a
	// trace that can be made to lie.
	`CREATE TABLE IF NOT EXISTS request_flow_runs (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		request_flow_id UUID NOT NULL REFERENCES request_flows(id) ON DELETE CASCADE,
		started_at TIMESTAMP NOT NULL DEFAULT NOW(),
		finished_at TIMESTAMP,
		-- completed | stopped | failed | capped
		outcome VARCHAR(16) NOT NULL DEFAULT 'completed',
		-- Which cap or condition ended it, machine readable; see the FlowStop constants.
		stop_reason VARCHAR(40) NOT NULL DEFAULT '',
		-- The same thing in the operator's words. Never empty on a capped run: "flow ended" with no
		-- reason is how somebody concludes the target is broken when it was their own flow.
		stop_detail TEXT NOT NULL DEFAULT '',
		-- Executions, not steps. A 4-step flow that looped is 4 definitions and this many executions.
		executions INTEGER NOT NULL DEFAULT 0,
		requests_sent INTEGER NOT NULL DEFAULT 0,
		caps JSONB NOT NULL DEFAULT '{}'::jsonb,
		warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
		trace JSONB NOT NULL DEFAULT '[]'::jsonb
	);`,
	`CREATE INDEX IF NOT EXISTS idx_request_flow_runs_flow
	   ON request_flow_runs(request_flow_id, started_at DESC);`,
}

// EnsureRequestFlowBuilderSchema applies the DDL. Call once at boot.
func EnsureRequestFlowBuilderSchema(ctx context.Context) error {
	for _, stmt := range RequestFlowBuilderSchema {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("request flow builder schema: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

// RequestFlow is a hand-assembled flow.
type RequestFlow struct {
	ID               string    `json:"id"`
	ScopeTargetID    string    `json:"scope_target_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	BaseURL          string    `json:"base_url"`
	Source           string    `json:"source"`
	SeededFromFlowID string    `json:"seeded_from_flow_id"`
	StepCount        int       `json:"step_count"`
	EnabledCount     int       `json:"enabled_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// RequestFlowStep is one ordered raw request in a flow.
type RequestFlowStep struct {
	ID              string               `json:"id"`
	RequestFlowID   string               `json:"request_flow_id"`
	StepOrder       int                  `json:"step_order"`
	Name            string               `json:"name"`
	RawRequest      string               `json:"raw_request"`
	SourceCaptureID string               `json:"source_capture_id"`
	Enabled         bool                 `json:"enabled"`
	Extractions     []AuthFlowExtraction `json:"extractions"`
	// Ordered, first match wins, evaluated against the response THIS step produced. Empty is the
	// straight line: the flow goes to the next step, which is what it did before branching existed.
	Conditions      []FlowCondition     `json:"conditions"`
	ResponseStatus  *int                `json:"response_status"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	ResponseBody    string              `json:"response_body"`
	ResponseTimeMs  *float64            `json:"response_time_ms"`
	Error           string              `json:"error"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`

	// Filled by a replay, never stored.
	Captured    []ExtractionOutcome `json:"captured,omitempty"`
	Substituted []string            `json:"substituted,omitempty"`
	Skipped     bool                `json:"skipped,omitempty"`
	// Filled when a save creates a loop, never stored. Carried ON the step rather than beside it so
	// the warning reaches a client that only re-reads the step it just edited.
	CycleWarnings []string `json:"cycle_warnings,omitempty"`
}

// RequestFlowStepPreview is one row of the dry run: what a replay WOULD do to this step, worked out
// without sending anything.
type RequestFlowStepPreview struct {
	StepID        string `json:"step_id"`
	StepOrder     int    `json:"step_order"`
	Name          string `json:"name"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Target        string `json:"target"`
	Enabled       bool   `json:"enabled"`
	InScope       bool   `json:"in_scope"`
	StateChanging bool   `json:"state_changing"`
	// Placeholders this step refers to. Whether they resolve depends on responses that have not
	// happened yet, so what is reported is which earlier step is expected to produce each one.
	Placeholders []string `json:"placeholders,omitempty"`
	// How many conditions this step branches on. Non-zero is the signal that the rows below it are a
	// possible path rather than the path.
	Conditions int `json:"conditions"`
	// Why this step would not be sent, empty when it would be.
	Refusal string `json:"refusal,omitempty"`
}

// ---------------------------------------------------------------------------
// The pure core
//
// Everything below this line to the next banner is a function over plain values with no database and
// no network, because these are the decisions worth arguing about and a decision that can only be
// exercised against a live table is a decision nobody will ever check.
// ---------------------------------------------------------------------------

// requestFlowStateChangingVerbs is what "state-changing" means here.
//
// Deliberately by VERB and not by path heuristics. A GET can change state on a badly built
// application, but guessing which one costs the operator a working step, while treating every POST
// as harmless costs somebody a text message. The conservative direction is to arm nothing
// automatically and let the operator arm what they recognise.
var requestFlowStateChangingVerbs = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

// requestFlowMethodOf reads the verb off a raw request without parsing the whole thing, so it works
// on bytes that are mid-edit and will not currently parse.
func requestFlowMethodOf(raw string) string {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	verb, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return strings.ToUpper(strings.TrimSpace(verb))
}

// requestFlowIsStateChanging reports whether replaying these bytes could change something.
func requestFlowIsStateChanging(raw string) bool {
	return requestFlowStateChangingVerbs[requestFlowMethodOf(raw)]
}

// requestFlowSeedEnabled decides whether a SEEDED step arrives armed.
//
// This is the single most important line in the file. Seeding copies captured request bodies in
// verbatim, and a captured body carries whatever identifier the operator's browser sent: a real
// phone number, a real account id, a real order. Replaying it is not a probe, it is the application
// doing its job again, to a real person.
//
// So a seeded state-changing step is stored disabled. allowStateChanging is the operator's explicit
// per-seed opt-in and defaults to false, which is what makes the default path safe rather than the
// careful path safe.
func requestFlowSeedEnabled(rawRequest string, allowStateChanging bool) bool {
	if allowStateChanging {
		return true
	}
	return !requestFlowIsStateChanging(rawRequest)
}

// requestFlowSeedCapture is one capture's worth of bytes, looked up by id after the detector has
// decided WHICH captures and in WHAT order. FlowCapture deliberately carries no headers or body, so
// the two halves are fetched separately and joined here.
type requestFlowSeedCapture struct {
	ID      string
	Method  string
	URL     string
	Headers map[string]interface{}
	Body    string
}

// requestFlowSeededStep is a step about to be inserted.
type requestFlowSeededStep struct {
	Name            string
	RawRequest      string
	SourceCaptureID string
	Enabled         bool
}

// requestFlowSeedName labels a step the way the rest of the framework labels one.
func requestFlowSeedName(method, rawURL string) string {
	path := flowURLPath(rawURL)
	if path == "" {
		path = "/"
	}
	verb := strings.ToUpper(strings.TrimSpace(method))
	if verb == "" {
		verb = "GET"
	}
	return verb + " " + path
}

// seedStepsFromFlow turns a detected flow into editable steps, in flow order.
//
// Selection mirrors renderFlowGraph exactly: the root is always taken, and otherwise the default is
// the significant requests. That is not a detail. The operator picked this flow by looking at a
// diagram that had already hidden the 90% of it that is images and stylesheets, and seeding the
// hidden ones would hand back a flow that does not resemble the one they chose. includeAll is the
// same escape hatch show_all is on the diagram.
//
// only, when non-empty, wins over both: an explicit selection is the operator naming captures, and
// second-guessing that with a noise filter would drop requests they deliberately ticked.
//
// A capture the detector listed but whose bytes could not be loaded is SKIPPED rather than emitted
// as an empty step. A step with no request in it is not a step, and one sitting in the middle of a
// flow would silently break the ordering the operator is relying on.
func seedStepsFromFlow(flow captureFlow, detail map[string]requestFlowSeedCapture,
	includeAll bool, only map[string]bool, allowStateChanging bool) []requestFlowSeededStep {

	steps := []requestFlowSeededStep{}
	for i, c := range flow.Captures {
		if len(only) > 0 {
			if !only[c.ID] {
				continue
			}
		} else if !(includeAll || i == 0 || isSignificantFlowCapture(c)) {
			continue
		}

		d, ok := detail[c.ID]
		if !ok {
			continue
		}
		steps = append(steps, requestFlowSeedStep(d, allowStateChanging))
	}
	return steps
}

// requestFlowSeedStep renders one capture as a step.
//
// BuildRawHTTPRequest's output is used VERBATIM and is deliberately not passed through
// normalizeRawRequest. BuildRawHTTPRequest already writes CRLF framing and a Content-Length that
// matches the body, while normalizeRawRequest rewrites every \r\n in the WHOLE string, body
// included, and recomputes the length from the shortened bytes: self-consistent and corrupt. On a
// multipart body that rewrites every boundary and the request stops being the request that was
// captured. This is the same reason refreshContentLength exists rather than reusing the normalizer.
func requestFlowSeedStep(d requestFlowSeedCapture, allowStateChanging bool) requestFlowSeededStep {
	raw := BuildRawHTTPRequest(d.Method, d.URL, d.Headers, d.Body)
	return requestFlowSeededStep{
		Name:            requestFlowSeedName(d.Method, d.URL),
		RawRequest:      raw,
		SourceCaptureID: d.ID,
		Enabled:         requestFlowSeedEnabled(raw, allowStateChanging),
	}
}

// resolveStepOrder maps a desired ordering onto the steps that actually exist.
//
// desired must be a PERMUTATION of current, and a partial list is an error rather than a convenience.
// The tempting alternative, "the ids you named go first and the rest keep their relative order
// behind them", silently moves steps the operator never touched: send four ids out of eleven and
// seven steps jump to the end of a flow whose whole meaning is its order. The client always has the
// full list because it just rendered it, so requiring it costs nothing and removes the failure mode.
//
// Stability comes from the function being a pure permutation: ids the caller left in place keep
// their positions exactly, applying the same desired twice gives the same answer, and a desired
// equal to current is a no-op.
func resolveStepOrder(current, desired []string) ([]string, error) {
	inCurrent := make(map[string]bool, len(current))
	for _, id := range current {
		inCurrent[id] = true
	}

	seen := make(map[string]bool, len(desired))
	out := make([]string, 0, len(desired))
	for _, id := range desired {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("the new order contains an empty step id")
		}
		if !inCurrent[id] {
			return nil, fmt.Errorf("step %s is not in this flow, so it cannot be given a position in it", id)
		}
		if seen[id] {
			return nil, fmt.Errorf("step %s appears twice in the new order, so it has no single position", id)
		}
		seen[id] = true
		out = append(out, id)
	}

	// Named individually rather than by count. "you sent 9 of 11" leaves the operator to work out
	// which two, and the client that produced a short list is the one that needs to be told what it
	// dropped.
	var missing []string
	for _, id := range current {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the new order leaves out %d step(s) that are in this flow (%s); "+
			"send every step id, because a partial order would move the ones you did not name",
			len(missing), strings.Join(missing, ", "))
	}

	return out, nil
}

// moveStepOrder lifts one step out and drops it back at a position, 1-based.
//
// The convenience form of a reorder, for a drag or an up/down arrow. A position past either end is
// clamped rather than refused: the operator dragged past the end of the list, which is a gesture and
// not an error, and clamping is what they meant.
func moveStepOrder(current []string, stepID string, to int) ([]string, error) {
	from := -1
	for i, id := range current {
		if id == stepID {
			from = i
			break
		}
	}
	if from < 0 {
		return nil, fmt.Errorf("step %s is not in this flow", stepID)
	}

	without := make([]string, 0, len(current))
	without = append(without, current[:from]...)
	without = append(without, current[from+1:]...)

	target := to - 1
	if target < 0 {
		target = 0
	}
	if target > len(without) {
		target = len(without)
	}

	out := make([]string, 0, len(current))
	out = append(out, without[:target]...)
	out = append(out, stepID)
	out = append(out, without[target:]...)
	return out, nil
}

// requestFlowStepHost works out which host a step would actually be sent to, using the same rule the
// replay uses: the step's own Host header wins, base_url is the fallback. Anything else would let
// the preview promise one host and the send use another.
func requestFlowStepHost(rawRequest, baseURL string) string {
	target := resolveBaseURL(rawRequest, baseURL)
	if target == "" {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// requestFlowStepURL is the whole URL a step would be sent to, not just its host, because an
// exclusion rule matches on a path and a host alone cannot be judged against one.
func requestFlowStepURL(rawRequest, baseURL string) string {
	origin := resolveBaseURL(rawRequest, baseURL)
	if origin == "" {
		return ""
	}
	path := "/"
	if req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest))); err == nil {
		if u := strings.TrimSpace(req.URL.RequestURI()); u != "" {
			path = u
		}
	}
	if !strings.HasPrefix(path, "/") {
		// An absolute-form request line (GET http://host/p HTTP/1.1) is already a URL.
		return path
	}
	return strings.TrimSuffix(origin, "/") + path
}

// flowSendRails is everything a built-flow step is judged against before it is sent.
//
// THREE CHECKS, NOT ONE, and the reason is a defect this file's own header comment used to deny.
// It claimed "LoadScanScope is the one reader of" the in_scope=false rows, which is only true for a
// host that got into the boundary BECAUSE the crawl saw it. A host marked in_scope=false that also
// sits inside the target's registrable domain is still admitted by ScanScope.Allows, so the operator
// ticks "never send here" and the builder sends there anyway. Measured against a listener on the
// compose network: a step for denied.flowlab.test, marked in_scope=false, was dialled.
//
// The exclusion list was missing outright. Active detection and the detected-flow runner both refuse
// a step matching one; the builder replayed straight through /admin/*, wire-confirmed. Three senders
// reading the operator's own "do not touch this" list two different ways is the thing that makes a
// rail worthless, so all three now read it the same way and in the same order.
type flowSendRails struct {
	Scope      *ScanScope
	Denied     map[string]bool
	Exclusions []FlowExclusion

	// Set when the rails could not be read. Every step is then refused with this sentence, so a
	// preview built from a failed load says "the list could not be read" rather than rendering a row
	// of green in-scope ticks that mean nothing. The run paths refuse on the returned error instead;
	// this is what makes the READ paths fail closed without turning a modal into a 500.
	Unreadable string
}

// LoadFlowSendRails reads the boundary for a built flow's target.
//
// FAILS CLOSED, like the detected runner's equivalent. A deny list or an exclusion list that cannot
// be read is not an empty one: substituting empty is how an operator's "this endpoint texts a real
// customer" rule is lost to a transient database error and the request goes out anyway.
func LoadFlowSendRails(scopeTargetID string) (flowSendRails, error) {
	rails := flowSendRails{Scope: LoadScanScope(scopeTargetID)}

	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		wrapped := fmt.Errorf(
			"the out-of-scope host list could not be read, so nothing may be sent: %w", err)
		return flowSendRails{Unreadable: wrapped.Error()}, wrapped
	}
	rails.Denied = denied

	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		wrapped := fmt.Errorf(
			"the exclusion list could not be read, so nothing may be sent: %w", err)
		return flowSendRails{Unreadable: wrapped.Error()}, wrapped
	}
	rails.Exclusions = rules

	return rails, nil
}

// requestFlowScopeRefusal is the one place a step is judged against the boundary, so the preview and
// the send cannot disagree about which steps are allowed.
//
// An empty return means allowed. A step with no determinable host is refused rather than sent
// somewhere guessed at.
//
// ORDER MATTERS, and it is the same order detection and the detected runner use: the operator's own
// explicit deny FIRST, because it must not be overridable by a boundary that happens to admit the
// host for a different reason; then the scope boundary; then the exclusion rules.
func requestFlowScopeRefusal(rawRequest, baseURL string, rails flowSendRails) (host, refusal string) {
	if rails.Unreadable != "" {
		return requestFlowStepHost(rawRequest, baseURL), "not sent: " + rails.Unreadable
	}
	host = requestFlowStepHost(rawRequest, baseURL)
	if host == "" {
		return "", "not sent: this step has no Host header and the flow has no base URL, " +
			"so there is no way to tell which server to send it to."
	}
	if IsDeniedFlowHost(rails.Denied, host) {
		return host, fmt.Sprintf(
			"not sent: %s is marked out of scope for this target.", host)
	}
	if !rails.Scope.Allows(host) {
		return host, fmt.Sprintf("not sent: %s is outside this target's scope. In scope: %s. "+
			"Add the host in the scope settings if the engagement covers it.", host,
			rails.Scope.Describe())
	}
	if d := FirstFlowExclusionMatch(rails.Exclusions, requestFlowStepURL(rawRequest, baseURL)); d.Excluded {
		why := d.Reason
		if strings.TrimSpace(why) == "" {
			why = "no reason was recorded on the rule"
		}
		return host, fmt.Sprintf(
			"not sent: an exclusion rule covers this URL (%s). Reason: %s", d.Pattern, why)
	}
	return host, ""
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

// The flow runner lives in flowConditions.go.
//
// It replaced a linear loop here that walked the steps 1..n. The shared cookie jar, the one variable
// map, the scope check on the substituted bytes, the disabled-step skip and the persistence call are
// all still exactly that loop; what is added is that it follows each step CONDITIONS, and that it is
// bounded by caps that a loop cannot talk its way out of. A flow with no conditions still walks
// 1..n, which is why this was a replacement and not a second code path: two runners would disagree
// about a refusal or a disarmed step the first time one of them was edited.

// replayRequestFlowStepByID re-sends one step, seeding cookies and captured values from the
// responses of all EARLIER steps rather than by re-sending them.
//
// Re-sending the earlier steps would fire the whole flow at the target every time the operator
// tweaks step four, which on a flow seeded from a real capture is exactly the thing this file exists
// to avoid. The step still needs the token an earlier step produced, so those are re-read from the
// responses already recorded.
func replayRequestFlowStepByID(stepID string) error {
	step, err := getRequestFlowStepByID(stepID)
	if err != nil {
		return err
	}
	flow, err := getRequestFlow(step.RequestFlowID)
	if err != nil {
		return err
	}
	// Fails closed. A single hand-driven step is still a request at somebody's programme, and the
	// deny list is the one thing the operator asked never to be sent to.
	rails, err := LoadFlowSendRails(flow.ScopeTargetID)
	if err != nil {
		return updateRequestFlowStepResponse(stepID, 0, nil, "", 0, "not sent: "+err.Error())
	}

	jar, _ := cookiejar.New(nil)
	vars := map[string]string{}
	prior, err := getPriorRequestFlowSteps(step.RequestFlowID, step.StepOrder)
	if err == nil {
		seedJar(jar, resolveBaseURL(step.RawRequest, flow.BaseURL), requestFlowAsAuthSteps(prior))
		for _, earlier := range prior {
			captured, _ := runAuthFlowExtractions(earlier.Extractions, earlier.ResponseHeaders, earlier.ResponseBody)
			for name, value := range captured {
				vars[name] = value
			}
		}
	}

	request, _, refusal := prepareStepRequest(step.RawRequest, vars)
	if refusal != "" {
		// Recorded on the step rather than returned as an error, so the reason is where the operator
		// is looking instead of only in a toast that vanishes.
		return updateRequestFlowStepResponse(stepID, 0, nil, "", 0, refusal+
			" Replay the whole flow, or run the earlier step first, so its captures are recorded.")
	}
	if host, scopeRefusal := requestFlowScopeRefusal(request, flow.BaseURL, rails); scopeRefusal != "" {
		rails.Scope.Refuse(host)
		return updateRequestFlowStepResponse(stepID, 0, nil, "", 0, scopeRefusal)
	}

	status, headers, body, ms, sendErr := sendRawRequest(request, resolveBaseURL(request, flow.BaseURL), jar)
	errStr := ""
	if sendErr != nil {
		errStr = sendErr.Error()
	}
	return updateRequestFlowStepResponse(stepID, status, headers, body, ms, errStr)
}

// requestFlowAsAuthSteps adapts steps for seedJar, which only reads RawRequest and ResponseHeaders.
// Converting is six lines and keeps the cookie-attribution rule (cookies filed against the host that
// ISSUED them, not the host the current step targets) in one place instead of two.
func requestFlowAsAuthSteps(steps []RequestFlowStep) []AuthFlowStep {
	out := make([]AuthFlowStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, AuthFlowStep{RawRequest: s.RawRequest, ResponseHeaders: s.ResponseHeaders})
	}
	return out
}

// ---------------------------------------------------------------------------
// Flow endpoints
// ---------------------------------------------------------------------------

// ListRequestFlows handles GET /request-flow-builder/{scope_target_id}/flows.
func ListRequestFlows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT f.id::text, f.scope_target_id::text, f.name, f.description, f.base_url, f.source,
		       f.seeded_from_flow_id, f.created_at, f.updated_at,
		       (SELECT COUNT(*) FROM request_flow_steps s WHERE s.request_flow_id = f.id),
		       (SELECT COUNT(*) FROM request_flow_steps s WHERE s.request_flow_id = f.id AND s.enabled)
		FROM request_flows f
		WHERE f.scope_target_id = $1
		ORDER BY f.updated_at DESC, f.id`, scopeTargetID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to list flows: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load request flows")
		return
	}
	defer rows.Close()

	flows := []RequestFlow{}
	for rows.Next() {
		var f RequestFlow
		if err := rows.Scan(&f.ID, &f.ScopeTargetID, &f.Name, &f.Description, &f.BaseURL, &f.Source,
			&f.SeededFromFlowID, &f.CreatedAt, &f.UpdatedAt, &f.StepCount, &f.EnabledCount); err != nil {
			log.Printf("[REQUEST-FLOW] Failed to scan flow row: %v", err)
			continue
		}
		flows = append(flows, f)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"flows": flows, "total": len(flows)})
}

// CreateRequestFlow handles POST /request-flow-builder/{scope_target_id}/flows: an empty flow.
func CreateRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var payload struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		BaseURL     string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "name_required",
			"A flow needs a name, because the list is how the operator finds it again.")
		return
	}

	flow, err := insertRequestFlow(scopeTargetID, payload.Name, payload.Description, payload.BaseURL,
		"blank", "")
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to create flow: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create the flow")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(flow)
}

// UpdateRequestFlow handles PUT /request-flow-builder/flow/{flow_id}.
//
// Every field is a POINTER and every column is COALESCEd, so omitting a field leaves it alone. A
// partial PUT that wrote zero values into the columns it did not carry is how seven columns got
// wiped on 58 rows once already.
func UpdateRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	if _, err := uuid.Parse(flowID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "flow_id_required", "flow_id must be a UUID")
		return
	}

	var payload struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		BaseURL     *string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if payload.Name != nil && strings.TrimSpace(*payload.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "name_required", "A flow needs a name.")
		return
	}

	tag, err := dbPool.Exec(context.Background(), `
		UPDATE request_flows SET
		  name = COALESCE($1, name),
		  description = COALESCE($2, description),
		  base_url = COALESCE($3, base_url),
		  updated_at = NOW()
		WHERE id = $4`, payload.Name, payload.Description, payload.BaseURL, flowID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to update flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update the flow")
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}

	flow, err := getRequestFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}
	json.NewEncoder(w).Encode(flow)
}

// DeleteRequestFlow handles DELETE /request-flow-builder/flow/{flow_id}. Steps cascade.
func DeleteRequestFlow(w http.ResponseWriter, r *http.Request) {
	flowID := mux.Vars(r)["flow_id"]
	tag, err := dbPool.Exec(context.Background(), `DELETE FROM request_flows WHERE id = $1`, flowID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to delete flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete the flow")
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetRequestFlow handles GET /request-flow-builder/flow/{flow_id}: the flow, its steps, and the
// scope boundary those steps will be judged against.
//
// The boundary is returned rather than left to be discovered by a replay that refuses half the
// steps. An operator who can see "this step is out of scope" next to the step can fix it before
// sending; one who cannot gets a run of refusals and no idea why.
func GetRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	if _, err := uuid.Parse(flowID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "flow_id_required", "flow_id must be a UUID")
		return
	}

	flow, err := getRequestFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}
	steps, err := getRequestFlowSteps(flowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the steps")
		return
	}

	rails, _ := LoadFlowSendRails(flow.ScopeTargetID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"flow":           flow,
		"steps":          steps,
		"scope_boundary": rails.Scope.Describe(),
		"preview":        requestFlowPreview(steps, flow.BaseURL, rails),
		// Recomputed on every read rather than stored, so a cycle created by DELETING a step is
		// reported too. A warning that only appears when a condition is saved would miss exactly the
		// edit that has no condition in it.
		"cycle_warnings": DetectFlowConditionCycles(requestFlowGraph(steps)),
		"branch_note":    requestFlowBranchNote(steps),
		// The loop protection this flow would be judged against, on the READ as well as on the
		// preview. A client that can only learn the caps by running a preview will print its own
		// constants until somebody presses preview, and a cap printed from a constant while the
		// server enforces another is a promise the screen cannot keep.
		"caps": ResolveFlowRunCaps(FlowRunCapRequest{}, previewEngagementConfig(flow.ScopeTargetID)),
	})
}

// PreviewRequestFlow handles GET /request-flow-builder/flow/{flow_id}/preview.
//
// The dry run, and the default way to look at a flow before sending it: which steps would go out, to
// which hosts, with which verbs, and which would be refused and why.
//
// GET on purpose, and the replay is POST. The method itself then carries the distinction the safety
// rules ask for: looking is safe and repeatable, sending is a second deliberate action.
func PreviewRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	flow, err := getRequestFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}
	steps, err := getRequestFlowSteps(flowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the steps")
		return
	}

	rails, _ := LoadFlowSendRails(flow.ScopeTargetID)
	rows := requestFlowPreview(steps, flow.BaseURL, rails)

	willSend := 0
	for _, row := range rows {
		if row.Enabled && row.Refusal == "" {
			willSend++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"flow":  flow,
		"steps": rows,
		// The three numbers a dry run exists to answer: how many requests, where to, and what will
		// not be sent. Named request_count rather than step_count because a disabled or refused step
		// is a step that produces no traffic, and the operator is deciding about traffic.
		//
		// ON A BRANCHING FLOW THESE ARE THE STRAIGHT-LINE NUMBERS AND NOTHING ELSE. Which steps run
		// depends on responses that have not happened, so a preview cannot know the path; branch_note
		// says so rather than letting request_count read as a promise. A number that is presented as
		// a total and is really an upper bound on one possible path is how an operator plans a run
		// against a rate cap and then exceeds it.
		"request_count":  willSend,
		"skipped_count":  len(rows) - willSend,
		"hosts":          sortedRequestFlowHosts(rows),
		"scope_boundary": rails.Scope.Describe(),
		"branch_note":    requestFlowBranchNote(steps),
		"cycle_warnings": DetectFlowConditionCycles(requestFlowGraph(steps)),
		"caps":           ResolveFlowRunCaps(FlowRunCapRequest{}, previewEngagementConfig(flow.ScopeTargetID)),
	})
}

// requestFlowBranchNote says, in one sentence, that this flow's step count is not its request count.
// Empty when the flow is a straight line, because a note that is always there is a note nobody reads.
func requestFlowBranchNote(steps []RequestFlowStep) string {
	branching := 0
	for _, s := range steps {
		if len(s.Conditions) > 0 {
			branching++
		}
	}
	if branching == 0 {
		return ""
	}
	return fmt.Sprintf("%d of %d step(s) branch on their response, so which steps actually run "+
		"depends on what the target answers. The counts above are for the straight-line path and a "+
		"run may send fewer, or, where a step is jumped back to, more.", branching, len(steps))
}

// previewEngagementConfig resolves the engagement config for display, falling back to the resolved
// defaults when it cannot be read. A preview that cannot show the caps is still a useful preview; a
// RUN that cannot read the config sends nothing, which is the asymmetry that matters.
func previewEngagementConfig(scopeTargetID string) ResolvedEngagementConfig {
	engagement, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Engagement config unreadable for preview of %s: %v", scopeTargetID, err)
		return ResolveEngagementFrom(nil, EngagementGlobals{})
	}
	return engagement
}

// requestFlowPreview works out, without sending anything, what a replay would do.
func requestFlowPreview(steps []RequestFlowStep, baseURL string, rails flowSendRails) []RequestFlowStepPreview {
	out := make([]RequestFlowStepPreview, 0, len(steps))
	for _, s := range steps {
		host, refusal := requestFlowScopeRefusal(s.RawRequest, baseURL, rails)
		row := RequestFlowStepPreview{
			StepID:        s.ID,
			StepOrder:     s.StepOrder,
			Name:          s.Name,
			Method:        requestFlowMethodOf(s.RawRequest),
			Host:          host,
			Target:        resolveBaseURL(s.RawRequest, baseURL),
			Enabled:       s.Enabled,
			InScope:       refusal == "",
			StateChanging: requestFlowIsStateChanging(s.RawRequest),
			Placeholders:  authFlowVarNames(s.RawRequest),
			Conditions:    len(s.Conditions),
			Refusal:       refusal,
		}
		if !s.Enabled && row.Refusal == "" {
			row.Refusal = "not sent: this step is turned off"
		}
		out = append(out, row)
	}
	return out
}

// ReplayRequestFlow handles POST /request-flow-builder/flow/{flow_id}/replay.
//
// The run follows the steps' CONDITIONS. A flow with no conditions on any step walks 1..n and stops,
// which is byte for byte what it did before branching existed, so this is not a behaviour change for
// any flow already saved.
//
// The response is a superset of the old one: flow, steps, refused_hosts and scope_boundary are still
// there and still mean the same thing. What is added is the part a branching run cannot be
// understood without - the execution trace, the outcome, and the caps it was judged against.
func ReplayRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	flow, err := getRequestFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}
	steps, err := getRequestFlowSteps(flowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the steps")
		return
	}
	if len(steps) == 0 {
		writeJSONError(w, http.StatusBadRequest, "flow_empty", "This flow has no steps yet.")
		return
	}

	// The caps the operator may ask for. An empty body is the normal case and means the defaults,
	// so a decode failure is not fatal - but a body that IS sent and cannot be read is, because
	// silently running with defaults after the operator lowered a cap is the wrong direction to fail.
	var payload struct {
		FlowRunCapRequest
	}
	if r.Body != nil {
		if derr := json.NewDecoder(r.Body).Decode(&payload); derr != nil && derr != io.EOF {
			writeJSONError(w, http.StatusBadRequest, "invalid_body",
				"Invalid request body: "+derr.Error())
			return
		}
	}

	// THE ENGAGEMENT CONFIG, AND WHY A FAILURE HERE STOPS THE RUN.
	//
	// This is a sender, so it resolves the per-target engagement config: the programme's identifying
	// header, its User-Agent, its rate limit and its request timeout. Sending a programme's traffic
	// without the header their brief calls mandatory is how a research run gets read by a SOC as an
	// attack, so a config that cannot be read means nothing is sent at all.
	engagement, err := ResolveEngagementConfig(flow.ScopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "engagement_unreadable",
			"This target's engagement config could not be read, so nothing was sent: "+err.Error())
		return
	}
	caps := ResolveFlowRunCaps(payload.FlowRunCapRequest, engagement)

	// ONE SENDER PER TARGET. Every cap above is per-run, including the pacer, so two replays each
	// holding perfectly to 2 rps put 4 rps on the programme. See flowTargetGate.go.
	release, holder, ok := flowTargets.acquire(flow.ScopeTargetID, flowTargetHolder{
		Kind: "built", RunID: uuid.New().String(), FlowID: flow.ID, Label: flow.Name,
	})
	if !ok {
		writeJSONError(w, http.StatusConflict, "target_busy",
			flowTargetBusyMessage(holder, caps.RPS))
		return
	}
	defer release()

	// FAILS CLOSED, and BEFORE anything is sent. The deny list and the exclusion rules are the
	// operator's own "never send here"; losing either to a transient database error and sending
	// anyway is the failure this whole file's rails exist to prevent.
	rails, err := LoadFlowSendRails(flow.ScopeTargetID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Rails unreadable for %s: %v", flow.ScopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "rails_unreadable", err.Error())
		return
	}

	// One shared cookie jar across the whole flow, so Set-Cookie from earlier steps is sent on later
	// ones. This is the reason a flow is a flow and not a list of requests, and it survives a jump:
	// a step reached by goto sees the session the steps before it established.
	jar, _ := cookiejar.New(nil)
	result := runRequestFlowConditional(flow, steps, rails, engagement, caps, jar, liveFlowRunDeps())
	saveRequestFlowRun(result)

	updated, _ := getRequestFlowSteps(flowID)
	// The run-time detail is not persisted on the step, so fold the LAST execution of each step back
	// onto the row being returned: without it the caller cannot tell a step that filled in a token
	// from one that did not. The other executions are in the trace, which is where a step that ran
	// three times is actually legible.
	last := map[string]FlowExecutionTrace{}
	for _, entry := range result.Trace {
		last[entry.StepID] = entry
	}
	for i := range updated {
		if entry, ok := last[updated[i].ID]; ok {
			updated[i].Captured = entry.Captured
			updated[i].Substituted = entry.Substituted
			updated[i].Skipped = entry.Skipped
		} else {
			// Never reached. Not an error and not a failure: a branch simply did not go this way, and
			// saying so is the difference between "this step failed" and "this step was not on the path".
			updated[i].Skipped = true
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"flow":           flow,
		"steps":          updated,
		"refused_hosts":  rails.Scope.Refused(),
		"scope_boundary": rails.Scope.Describe(),
		"run":            result,
		// Lifted out of run/ as well, because these three are what the operator reads first and a
		// client should not have to know the shape of a run to show them.
		"outcome":     result.Outcome,
		"stop_reason": result.StopReason,
		"stop_detail": result.StopDetail,
	})
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

// CreateRequestFlowFromDetectedFlow handles POST /request-flow-builder/{scope_target_id}/from-flow.
//
// This is the point of the whole feature: the operator ran detection, found the flow, and now wants
// to change one request in it. Rather than re-deriving what a flow is, it asks the passive detector
// (segmentCaptureFlows, the same code the diagram is drawn from) which captures belong to this flow
// and in what order, then asks the capture bridge for each one's bytes.
func CreateRequestFlowFromDetectedFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var payload struct {
		FlowID string `json:"flow_id"`
		Name   string `json:"name"`
		// Bring in the subresources the diagram hides, same escape hatch as show_all.
		IncludeAll bool `json:"include_all"`
		// An explicit selection, which wins over the noise filter.
		CaptureIDs []string `json:"capture_ids"`
		// Off by default and named for what it does. With it false, every seeded POST, PUT, PATCH and
		// DELETE arrives disabled, because a captured body carries a real identifier.
		ArmWriteSteps bool `json:"arm_write_steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	sessionID, tabID, rootCaptureID, err := DecodeFlowID(payload.FlowID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_flow_id", err.Error())
		return
	}

	// The whole tab, because a flow is defined by its boundaries and the boundaries are the
	// neighbouring navigations. Pinned to the scope target from the path AND to the root capture's
	// own target, so a flow can never be assembled from two targets' rows.
	sqlText := fmt.Sprintf(`
		SELECT id, session_id, tab_id, COALESCE(method,''), COALESCE(url,''),
		       COALESCE(status_code,0), COALESCE(resource_type,''), COALESCE(initiator,''),
		       COALESCE(mime_type,''), timestamp, COALESCE(duration_ms,0),
		       COALESCE(octet_length(response_body),0),
		       (COALESCE(post_data,'') <> '') AS has_body,
		       COALESCE(redirect_chain,'[]'::jsonb),
		       TRUE AS matched
		FROM manual_crawl_captures
		WHERE session_id = $1 AND tab_id IS NOT DISTINCT FROM $2
		  AND scope_target_id = $3
		  AND scope_target_id = (SELECT scope_target_id FROM manual_crawl_captures WHERE id = $4)
		ORDER BY timestamp ASC
		LIMIT %d`, flowScanCeiling)

	captures, err := queryFlowCaptures(sqlText, []interface{}{sessionID, tabID, scopeTargetID, rootCaptureID})
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to load detected flow %s: %v", payload.FlowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the flow")
		return
	}

	var found *captureFlow
	for _, f := range segmentCaptureFlows(captures) {
		if len(f.Captures) > 0 && f.Captures[0].ID == rootCaptureID {
			flow := f
			found = &flow
			break
		}
	}
	if found == nil {
		// Reachable without anything being broken: a capture that rooted a flow yesterday stops
		// rooting one when a redirect that lands on it arrives.
		writeJSONError(w, http.StatusNotFound, "flow_not_found",
			"No flow starts at that request. It may have been re-segmented as new captures arrived; "+
				"reload the flow list.")
		return
	}

	only := map[string]bool{}
	for _, id := range payload.CaptureIDs {
		if id = strings.TrimSpace(id); id != "" {
			only[id] = true
		}
	}

	// Bytes for exactly the captures this flow contains. Fetched in one round trip and joined in
	// memory, because the ORDER has already been decided by the detector and re-deriving it from a
	// second query's sort would be a second opinion about the same thing.
	wanted := make([]string, 0, len(found.Captures))
	for _, c := range found.Captures {
		wanted = append(wanted, c.ID)
	}
	detail, err := loadRequestFlowSeedCaptures(scopeTargetID, wanted)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to load capture bytes: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the requests")
		return
	}

	seeded := seedStepsFromFlow(*found, detail, payload.IncludeAll, only, payload.ArmWriteSteps)
	if len(seeded) == 0 {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_seed",
			"None of that flow's requests could be turned into steps. If you selected specific "+
				"requests, check they are still in this flow.")
		return
	}

	summary := summarizeFlow(*found)
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = summary.Label
	}
	description := fmt.Sprintf("Built from the detected flow %s on %s",
		summary.Label, time.Now().Format("2006-01-02 15:04"))

	baseURL := ""
	if summary.Host != "" {
		if u, perr := url.Parse(found.Captures[0].URL); perr == nil && u.Host != "" {
			baseURL = u.Scheme + "://" + u.Host
		}
	}

	writeSeededRequestFlow(w, scopeTargetID, name, description, baseURL, "detected_flow",
		payload.FlowID, seeded, payload.ArmWriteSteps)
}

// CreateRequestFlowFromCaptures handles POST /request-flow-builder/{scope_target_id}/from-captures:
// a flow from an explicit list of capture ids, in the order they were recorded.
func CreateRequestFlowFromCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var payload struct {
		Name               string   `json:"name"`
		CaptureIDs         []string `json:"capture_ids"`
		ArmWriteSteps bool     `json:"arm_write_steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if len(payload.CaptureIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "capture_ids_required", "capture_ids is required")
		return
	}

	ordered, detail, err := loadOrderedRequestFlowSeedCaptures(scopeTargetID, payload.CaptureIDs)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to load captures: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the requests")
		return
	}
	if len(ordered) == 0 {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_seed",
			"None of those captures exist for this target.")
		return
	}

	seeded := make([]requestFlowSeededStep, 0, len(ordered))
	baseURL := ""
	for _, id := range ordered {
		d := detail[id]
		if baseURL == "" {
			if u, perr := url.Parse(d.URL); perr == nil && u.Host != "" {
				baseURL = u.Scheme + "://" + u.Host
			}
		}
		seeded = append(seeded, requestFlowSeedStep(d, payload.ArmWriteSteps))
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = "Built from " + fmt.Sprint(len(seeded)) + " recorded request(s)"
	}
	description := fmt.Sprintf("Built from %d recorded request(s) on %s",
		len(seeded), time.Now().Format("2006-01-02 15:04"))

	writeSeededRequestFlow(w, scopeTargetID, name, description, baseURL, "captures", "",
		seeded, payload.ArmWriteSteps)
}

// writeSeededRequestFlow inserts a flow and its steps, and reports how many arrived disarmed.
//
// The disabled count is in the RESPONSE and not only in the rows, because "I imported the login flow
// and it did nothing" is what happens when the safety default is silent. The operator is told the
// number and the reason at the moment it applies.
func writeSeededRequestFlow(w http.ResponseWriter, scopeTargetID, name, description, baseURL,
	source, seededFrom string, seeded []requestFlowSeededStep, allowStateChanging bool) {

	flow, err := insertRequestFlow(scopeTargetID, name, description, baseURL, source, seededFrom)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to create seeded flow: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create the flow")
		return
	}

	disabled := 0
	for i, step := range seeded {
		var captureID interface{}
		if step.SourceCaptureID != "" {
			captureID = step.SourceCaptureID
		}
		if _, err := dbPool.Exec(context.Background(), `
			INSERT INTO request_flow_steps
			  (id, request_flow_id, step_order, name, raw_request, source_capture_id, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			uuid.New().String(), flow.ID, i+1, step.Name, step.RawRequest, captureID, step.Enabled); err != nil {
			log.Printf("[REQUEST-FLOW] Failed to insert seeded step %d: %v", i+1, err)
			continue
		}
		if !step.Enabled {
			disabled++
		}
	}

	flow, _ = getRequestFlow(flow.ID)
	steps, _ := getRequestFlowSteps(flow.ID)
	rails, _ := LoadFlowSendRails(scopeTargetID)

	note := ""
	if disabled > 0 {
		note = fmt.Sprintf("%d of %d step(s) arrived turned OFF because they are POST, PUT, PATCH or "+
			"DELETE and carry the body that was recorded. Replaying a captured body sends the real "+
			"identifier it contains, which on some endpoints means the application texts or emails a "+
			"real person. Read each one and turn on the ones you mean to send.", disabled, len(seeded))
	} else if allowStateChanging {
		note = "arm_write_steps was set, so every seeded step is armed, including the ones that " +
			"carry recorded request bodies. Check what those bodies contain before replaying."
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"flow":           flow,
		"steps":          steps,
		"disabled_count": disabled,
		"note":           note,
		"scope_boundary": rails.Scope.Describe(),
		"preview":        requestFlowPreview(steps, flow.BaseURL, rails),
	})
}

// ---------------------------------------------------------------------------
// Step endpoints
// ---------------------------------------------------------------------------

// AddRequestFlowStep handles POST /request-flow-builder/flow/{flow_id}/steps.
//
// Two ways in: raw_request for bytes typed or pasted, or capture_id to seed from a recorded request
// through the same BuildRawHTTPRequest the repeater loads. The second is the common one, and it is
// why a step can be added without leaving the flow to go and copy something.
func AddRequestFlowStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	flow, err := getRequestFlow(flowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "No request flow with that id")
		return
	}

	var payload struct {
		Name        string               `json:"name"`
		RawRequest  string               `json:"raw_request"`
		CaptureID   string               `json:"capture_id"`
		Extractions []AuthFlowExtraction `json:"extractions"`
		// Ordered, first match wins. Validated here rather than at replay time, because a condition
		// that cannot work is far cheaper to explain while the operator is still looking at it.
		Conditions []FlowCondition `json:"conditions"`
		// Omitted means: armed for a hand-typed step (the operator wrote the bytes), disarmed for a
		// state-changing step seeded from a capture (the recorder wrote the bytes).
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	raw := payload.RawRequest
	name := payload.Name
	sourceCapture := ""
	seeded := false

	if strings.TrimSpace(payload.CaptureID) != "" {
		if _, uerr := uuid.Parse(payload.CaptureID); uerr != nil {
			writeJSONError(w, http.StatusBadRequest, "capture_id_invalid", "capture_id must be a UUID")
			return
		}
		detail, derr := loadRequestFlowSeedCaptures(flow.ScopeTargetID, []string{payload.CaptureID})
		if derr != nil {
			log.Printf("[REQUEST-FLOW] Failed to load capture %s: %v", payload.CaptureID, derr)
			writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the capture")
			return
		}
		d, ok := detail[payload.CaptureID]
		if !ok {
			writeJSONError(w, http.StatusNotFound, "capture_not_found",
				"No capture with that id for this target")
			return
		}
		// Verbatim, not normalized. See requestFlowSeedStep.
		raw = BuildRawHTTPRequest(d.Method, d.URL, d.Headers, d.Body)
		if strings.TrimSpace(name) == "" {
			name = requestFlowSeedName(d.Method, d.URL)
		}
		sourceCapture = d.ID
		seeded = true
	} else {
		if strings.TrimSpace(raw) == "" {
			writeJSONError(w, http.StatusBadRequest, "raw_request_required",
				"Give raw_request, or capture_id to start from a recorded request.")
			return
		}
		// A hand-typed request is normalized: a paste that lost its blank line or its Content-Length
		// would otherwise be stored, sent with an empty body, and answered 400 by the target, and the
		// operator would debug the target instead of the paste.
		raw = normalizeRawRequest(raw)
	}

	if problem := rawRequestProblem(raw); problem != "" {
		writeJSONError(w, http.StatusBadRequest, "raw_request_invalid", problem)
		return
	}
	if problem := validateExtractionSet(payload.Extractions); problem != "" {
		writeJSONError(w, http.StatusBadRequest, "extraction_invalid", problem)
		return
	}

	// Goto targets are resolved against the steps that already exist PLUS this one, so a step may
	// legitimately jump to itself (a bounded retry loop) at the moment it is created.
	existing, _ := getRequestFlowSteps(flowID)
	graph := append(requestFlowGraph(existing), FlowGraphStep{Name: name, Enabled: true,
		Conditions: payload.Conditions})
	if problem := ValidateFlowConditions(payload.Conditions, graph); problem != "" {
		writeJSONError(w, http.StatusBadRequest, "condition_invalid", problem)
		return
	}

	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	} else if seeded {
		enabled = requestFlowSeedEnabled(raw, false)
	}

	extractionsJSON, _ := json.Marshal(orEmptyExtractions(payload.Extractions))
	conditionsJSON, _ := json.Marshal(orEmptyConditions(payload.Conditions))
	var captureID interface{}
	if sourceCapture != "" {
		captureID = sourceCapture
	}

	// Order is chosen and claimed in ONE statement. Reading MAX and then inserting lets two concurrent
	// appends pick the same number; here the unique index would reject the second, but the append
	// would fail for a reason nobody could explain rather than simply taking the next number.
	stepID := uuid.New().String()
	var order int
	if err := dbPool.QueryRow(context.Background(), `
		INSERT INTO request_flow_steps
		  (id, request_flow_id, step_order, name, raw_request, source_capture_id, enabled, extractions,
		   conditions)
		SELECT $1, $2, COALESCE(MAX(step_order),0)+1, $3, $4, $5, $6, $7, $8
		FROM request_flow_steps WHERE request_flow_id = $2
		RETURNING step_order`,
		stepID, flowID, name, raw, captureID, enabled, extractionsJSON, conditionsJSON).Scan(&order); err != nil {
		log.Printf("[REQUEST-FLOW] Failed to insert step: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to add the step")
		return
	}
	touchRequestFlow(flowID)

	step, err := getRequestFlowStepByID(stepID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to read back the step")
		return
	}

	// Never replayed on add. AddAuthFlowStep sends the step as soon as it is saved, which is right for
	// an auth flow the operator is wiring up against their own account and wrong here: a step seeded
	// from a capture would fire a recorded body at the target the moment it was added, before anybody
	// had read it.
	note := ""
	if seeded && !enabled {
		note = "Added turned OFF: this is a " + requestFlowMethodOf(raw) + " carrying the body that " +
			"was recorded. Read it before turning it on."
	}

	// Cycles are WARNED about at the moment they are created, not refused, and not left to be
	// discovered when the flow fires at a live target. A bounded retry loop is legitimate; an
	// unnoticed one is a denial of service with the operator's name on it.
	after, _ := getRequestFlowSteps(flowID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"step":           step,
		"note":           note,
		"cycle_warnings": DetectFlowConditionCycles(requestFlowGraph(after)),
	})
}

// orEmptyConditions keeps a NULL out of the column, so every read is a list and no caller has to
// decide what a missing conditions field means.
func orEmptyConditions(conds []FlowCondition) []FlowCondition {
	if conds == nil {
		return []FlowCondition{}
	}
	return conds
}

// UpdateRequestFlowStep handles PUT /request-flow-builder/steps/{step_id}: edit the bytes.
//
// Every field is a pointer and every column is COALESCEd, so omitting one leaves it alone. This is
// the endpoint the operator uses most, one field at a time, which is exactly the shape that turns a
// non-pointer payload into a wipe.
func UpdateRequestFlowStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stepID := mux.Vars(r)["step_id"]
	if _, err := uuid.Parse(stepID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "step_id_required", "step_id must be a UUID")
		return
	}

	var payload struct {
		Name       *string `json:"name"`
		RawRequest *string `json:"raw_request"`
		Enabled    *bool   `json:"enabled"`
		// Omitted leaves the rules alone; [] clears them.
		Extractions *[]AuthFlowExtraction `json:"extractions"`
		// Same pointer rule: omitted leaves the branching alone, [] makes the step linear again.
		Conditions *[]FlowCondition `json:"conditions"`
		// Preserve the bytes exactly, for a deliberate Content-Length / Transfer-Encoding
		// disagreement. Same reasoning as the repeater's raw mode: "helpfully" repairing a smuggling
		// probe turns it into an ordinary POST and the operator concludes the target is not
		// vulnerable when they never sent the test.
		RawMode bool `json:"raw_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if payload.RawRequest != nil {
		raw := *payload.RawRequest
		if !payload.RawMode {
			raw = normalizeRawRequest(raw)
		}
		if problem := rawRequestProblem(raw); problem != "" {
			writeJSONError(w, http.StatusBadRequest, "raw_request_invalid", problem)
			return
		}
		payload.RawRequest = &raw
	}

	var extractionsJSON []byte
	if payload.Extractions != nil {
		if problem := validateExtractionSet(*payload.Extractions); problem != "" {
			writeJSONError(w, http.StatusBadRequest, "extraction_invalid", problem)
			return
		}
		extractionsJSON, _ = json.Marshal(orEmptyExtractions(*payload.Extractions))
	}

	var conditionsJSON []byte
	if payload.Conditions != nil {
		before, err := getRequestFlowStepByID(stepID)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
			return
		}
		// Validated against the flow AS IT WILL BE: this step's new conditions, every other step's
		// current name and id. A goto is checked against the destinations that will actually exist.
		siblings, _ := getRequestFlowSteps(before.RequestFlowID)
		for i := range siblings {
			if siblings[i].ID == stepID {
				siblings[i].Conditions = *payload.Conditions
				if payload.Name != nil {
					siblings[i].Name = *payload.Name
				}
			}
		}
		if problem := ValidateFlowConditions(*payload.Conditions, requestFlowGraph(siblings)); problem != "" {
			writeJSONError(w, http.StatusBadRequest, "condition_invalid", problem)
			return
		}
		conditionsJSON, _ = json.Marshal(orEmptyConditions(*payload.Conditions))
	}

	tag, err := dbPool.Exec(context.Background(), `
		UPDATE request_flow_steps SET
		  name = COALESCE($1, name),
		  raw_request = COALESCE($2, raw_request),
		  enabled = COALESCE($3, enabled),
		  extractions = COALESCE($4, extractions),
		  conditions = COALESCE($5, conditions),
		  updated_at = NOW()
		WHERE id = $6`, payload.Name, payload.RawRequest, payload.Enabled, extractionsJSON,
		conditionsJSON, stepID)
	if err != nil {
		log.Printf("[REQUEST-FLOW] Failed to update step %s: %v", stepID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update the step")
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}

	step, err := getRequestFlowStepByID(stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}
	touchRequestFlow(step.RequestFlowID)

	if payload.Conditions != nil {
		after, _ := getRequestFlowSteps(step.RequestFlowID)
		step.CycleWarnings = DetectFlowConditionCycles(requestFlowGraph(after))
	}
	json.NewEncoder(w).Encode(step)
}

// DeleteRequestFlowStep handles DELETE /request-flow-builder/steps/{step_id}.
//
// The remaining steps are CLOSED UP into 1..n rather than left with a gap. A gap is harmless to the
// replay, which orders rather than counts, but it makes step_order stop meaning position, and the
// reorder endpoint takes positions.
func DeleteRequestFlowStep(w http.ResponseWriter, r *http.Request) {
	stepID := mux.Vars(r)["step_id"]

	var flowID string
	if err := dbPool.QueryRow(context.Background(),
		`DELETE FROM request_flow_steps WHERE id = $1 RETURNING request_flow_id::text`,
		stepID).Scan(&flowID); err != nil {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}

	remaining, err := getRequestFlowStepIDs(flowID)
	if err == nil {
		if werr := requestFlowWriteOrder(flowID, remaining); werr != nil {
			log.Printf("[REQUEST-FLOW] Failed to close up order after delete: %v", werr)
		}
	}
	touchRequestFlow(flowID)
	w.WriteHeader(http.StatusNoContent)
}

// ReorderRequestFlowSteps handles PUT /request-flow-builder/flow/{flow_id}/steps/order.
func ReorderRequestFlowSteps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	var payload struct {
		StepIDs []string `json:"step_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	current, err := getRequestFlowStepIDs(flowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the steps")
		return
	}
	if len(current) == 0 {
		writeJSONError(w, http.StatusNotFound, "flow_not_found", "That flow has no steps")
		return
	}

	ordered, err := resolveStepOrder(current, payload.StepIDs)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_order", err.Error())
		return
	}
	if err := requestFlowWriteOrder(flowID, ordered); err != nil {
		log.Printf("[REQUEST-FLOW] Failed to reorder flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to reorder the steps")
		return
	}
	touchRequestFlow(flowID)

	steps, _ := getRequestFlowSteps(flowID)
	json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
}

// MoveRequestFlowStep handles POST /request-flow-builder/steps/{step_id}/move.
func MoveRequestFlowStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stepID := mux.Vars(r)["step_id"]
	var payload struct {
		ToPosition int `json:"to_position"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	step, err := getRequestFlowStepByID(stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}
	current, err := getRequestFlowStepIDs(step.RequestFlowID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the steps")
		return
	}

	ordered, err := moveStepOrder(current, stepID, payload.ToPosition)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_order", err.Error())
		return
	}
	if err := requestFlowWriteOrder(step.RequestFlowID, ordered); err != nil {
		log.Printf("[REQUEST-FLOW] Failed to move step %s: %v", stepID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to move the step")
		return
	}
	touchRequestFlow(step.RequestFlowID)

	steps, _ := getRequestFlowSteps(step.RequestFlowID)
	json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
}

// ReplayRequestFlowStep handles POST /request-flow-builder/steps/{step_id}/replay.
//
// A disabled step is refused rather than quietly sent. The operator turning a step off is the safety
// mechanism for seeded state-changing requests, and an endpoint that ignores it is a hole in it.
func ReplayRequestFlowStep(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stepID := mux.Vars(r)["step_id"]
	step, err := getRequestFlowStepByID(stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}
	if !step.Enabled {
		writeJSONError(w, http.StatusBadRequest, "step_disabled",
			"This step is turned off, so it was not sent. Turn it on if you mean to send it.")
		return
	}

	replayErr := replayRequestFlowStepByID(stepID)
	if replayErr != nil {
		log.Printf("[REQUEST-FLOW] Failed to replay step %s: %v", stepID, replayErr)
	}
	updated, err := getRequestFlowStepByID(stepID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "step_not_found", "No step with that id")
		return
	}

	payload := map[string]interface{}{"step": updated}
	if replayErr != nil {
		// When the replay itself failed the row still holds the PREVIOUS run's response. Returning it
		// with no marker shows the operator a stale success for a request that had just gone wrong.
		payload["replay_error"] = replayErr.Error()
		payload["replay_note"] = "The replay did not complete. The response shown is from the previous run."
	}
	json.NewEncoder(w).Encode(payload)
}

// ---------------------------------------------------------------------------
// The database layer, which decides nothing
// ---------------------------------------------------------------------------

func insertRequestFlow(scopeTargetID, name, description, baseURL, source, seededFrom string) (RequestFlow, error) {
	id := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO request_flows
		  (id, scope_target_id, name, description, base_url, source, seeded_from_flow_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, scopeTargetID, strings.TrimSpace(name), description, baseURL, source, seededFrom); err != nil {
		return RequestFlow{}, err
	}
	return getRequestFlow(id)
}

func getRequestFlow(flowID string) (RequestFlow, error) {
	var f RequestFlow
	err := dbPool.QueryRow(context.Background(), `
		SELECT f.id::text, f.scope_target_id::text, f.name, f.description, f.base_url, f.source,
		       f.seeded_from_flow_id, f.created_at, f.updated_at,
		       (SELECT COUNT(*) FROM request_flow_steps s WHERE s.request_flow_id = f.id),
		       (SELECT COUNT(*) FROM request_flow_steps s WHERE s.request_flow_id = f.id AND s.enabled)
		FROM request_flows f WHERE f.id = $1`, flowID).
		Scan(&f.ID, &f.ScopeTargetID, &f.Name, &f.Description, &f.BaseURL, &f.Source,
			&f.SeededFromFlowID, &f.CreatedAt, &f.UpdatedAt, &f.StepCount, &f.EnabledCount)
	return f, err
}

// touchRequestFlow moves the parent's updated_at, which is what the list sorts by. Without it a flow
// the operator has been editing all afternoon sits at the bottom of their own list.
func touchRequestFlow(flowID string) {
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE request_flows SET updated_at = NOW() WHERE id = $1`, flowID); err != nil {
		log.Printf("[REQUEST-FLOW] Failed to touch flow %s: %v", flowID, err)
	}
}

const requestFlowStepCols = `id::text, request_flow_id::text, step_order, name, raw_request,
	COALESCE(source_capture_id::text,''), enabled, response_status, response_headers,
	COALESCE(response_body,''), response_time_ms, COALESCE(error,''), created_at, updated_at,
	COALESCE(extractions,'[]'::jsonb), COALESCE(conditions,'[]'::jsonb)`

func scanRequestFlowStep(row interface{ Scan(...interface{}) error }) (RequestFlowStep, error) {
	var s RequestFlowStep
	var headersJSON, extractionsJSON, conditionsJSON []byte
	if err := row.Scan(&s.ID, &s.RequestFlowID, &s.StepOrder, &s.Name, &s.RawRequest,
		&s.SourceCaptureID, &s.Enabled, &s.ResponseStatus, &headersJSON, &s.ResponseBody,
		&s.ResponseTimeMs, &s.Error, &s.CreatedAt, &s.UpdatedAt, &extractionsJSON,
		&conditionsJSON); err != nil {
		return s, err
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.ResponseHeaders)
	}
	if len(extractionsJSON) > 0 {
		_ = json.Unmarshal(extractionsJSON, &s.Extractions)
	}
	if len(conditionsJSON) > 0 {
		_ = json.Unmarshal(conditionsJSON, &s.Conditions)
	}
	if s.Conditions == nil {
		s.Conditions = []FlowCondition{}
	}
	return s, nil
}

func getRequestFlowStepByID(stepID string) (RequestFlowStep, error) {
	return scanRequestFlowStep(dbPool.QueryRow(context.Background(),
		`SELECT `+requestFlowStepCols+` FROM request_flow_steps WHERE id = $1`, stepID))
}

func getRequestFlowSteps(flowID string) ([]RequestFlowStep, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+requestFlowStepCols+` FROM request_flow_steps
		 WHERE request_flow_id = $1 ORDER BY step_order ASC`, flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	steps := []RequestFlowStep{}
	for rows.Next() {
		s, err := scanRequestFlowStep(rows)
		if err != nil {
			log.Printf("[REQUEST-FLOW] Failed to scan step: %v", err)
			continue
		}
		steps = append(steps, s)
	}
	return steps, rows.Err()
}

func getPriorRequestFlowSteps(flowID string, beforeOrder int) ([]RequestFlowStep, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+requestFlowStepCols+` FROM request_flow_steps
		 WHERE request_flow_id = $1 AND step_order < $2 ORDER BY step_order ASC`, flowID, beforeOrder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	steps := []RequestFlowStep{}
	for rows.Next() {
		if s, err := scanRequestFlowStep(rows); err == nil {
			steps = append(steps, s)
		}
	}
	return steps, rows.Err()
}

func getRequestFlowStepIDs(flowID string) ([]string, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT id::text FROM request_flow_steps WHERE request_flow_id = $1 ORDER BY step_order ASC`,
		flowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// requestFlowWriteOrder assigns 1..n to the given ids, in the given order, in one transaction.
//
// Two phases, and the first is not optional. step_order carries a UNIQUE index on
// (request_flow_id, step_order), which is what makes order a fact rather than a tie-break, and a
// permutation written straight over the top of itself collides the moment two steps swap. So every
// row is first parked in negative space, which is disjoint from every value about to be written, and
// then given its final number. Both statements run in one transaction, so a failure halfway leaves
// the original order rather than a half-permuted one.
func requestFlowWriteOrder(flowID string, ordered []string) error {
	ctx := context.Background()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// -step_order - 1 rather than -step_order, so a row that somehow holds 0 parks at -1 instead of
	// staying at 0 and slipping past the stranded check below. The mapping is injective, so the
	// parked values stay unique and the index holds through the first statement too.
	if _, err := tx.Exec(ctx,
		`UPDATE request_flow_steps SET step_order = -step_order - 1 WHERE request_flow_id = $1`,
		flowID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE request_flow_steps s
		SET step_order = t.ord, updated_at = NOW()
		FROM unnest($2::uuid[]) WITH ORDINALITY AS t(id, ord)
		WHERE s.id = t.id AND s.request_flow_id = $1`, flowID, ordered); err != nil {
		return err
	}

	// Nothing may be left parked. A row still holding a negative number means the id list did not
	// cover the flow, and committing would leave a step whose position is meaningless.
	var stranded int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_flow_steps WHERE request_flow_id = $1 AND step_order < 0`,
		flowID).Scan(&stranded); err != nil {
		return err
	}
	if stranded > 0 {
		return fmt.Errorf("reorder would have left %d step(s) without a position", stranded)
	}

	return tx.Commit(ctx)
}

func updateRequestFlowStepResponse(stepID string, status int, headers map[string][]string,
	body string, ms float64, errStr string) error {

	headersJSON, _ := json.Marshal(headers)
	var statusVal interface{}
	if status > 0 {
		statusVal = status
	}
	_, err := dbPool.Exec(context.Background(), `
		UPDATE request_flow_steps SET response_status = $1, response_headers = $2, response_body = $3,
		  response_time_ms = $4, error = $5, updated_at = NOW() WHERE id = $6`,
		statusVal, headersJSON, sanitizeForTextColumn(body), ms, errStr, stepID)
	return err
}

// loadRequestFlowSeedCaptures fetches the bytes for a set of captures, keyed by id.
//
// Scoped to the target. A capture id is only ever handed out by an endpoint that already checked the
// target, but a seed that trusted the id alone would let a flow be assembled from another
// engagement's traffic, and the cost of the extra predicate is nothing.
func loadRequestFlowSeedCaptures(scopeTargetID string, ids []string) (map[string]requestFlowSeedCapture, error) {
	out := map[string]requestFlowSeedCapture{}
	if len(ids) == 0 {
		return out, nil
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, COALESCE(method,''), COALESCE(url,''), headers, COALESCE(post_data,'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND id = ANY($2::uuid[])`, scopeTargetID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var d requestFlowSeedCapture
		var headersJSON []byte
		if err := rows.Scan(&d.ID, &d.Method, &d.URL, &headersJSON, &d.Body); err != nil {
			log.Printf("[REQUEST-FLOW] Failed to scan capture: %v", err)
			continue
		}
		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &d.Headers)
		}
		out[d.ID] = d
	}
	return out, rows.Err()
}

// loadOrderedRequestFlowSeedCaptures also returns the ids in RECORDED order.
//
// Not in the order they arrived in the payload: a flow's meaning is its sequence, and a client that
// posts a set of ticked checkboxes has no reason to have them in timeline order. Ordering by
// timestamp with the id as tie-break matches how segmentCaptureFlows orders the same rows, so a
// hand-picked flow and a detected one cannot disagree about which request came first.
func loadOrderedRequestFlowSeedCaptures(scopeTargetID string, ids []string) ([]string, map[string]requestFlowSeedCapture, error) {
	detail, err := loadRequestFlowSeedCaptures(scopeTargetID, ids)
	if err != nil {
		return nil, nil, err
	}
	if len(detail) == 0 {
		return nil, detail, nil
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND id = ANY($2::uuid[])
		ORDER BY timestamp ASC, id ASC`, scopeTargetID, ids)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	ordered := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ordered = append(ordered, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Defensive: a row the ORDER query returned but the detail query did not cannot happen with the
	// same predicate, and a step with no bytes is worse than a missing one.
	kept := make([]string, 0, len(ordered))
	for _, id := range ordered {
		if _, ok := detail[id]; ok {
			kept = append(kept, id)
		}
	}
	return kept, detail, nil
}

// sortedRequestFlowHosts lists the hosts that would actually RECEIVE traffic.
//
// Steps that would be refused or are turned off are excluded, and that is the whole point: a field
// called "hosts" on a dry run is read as "these are the machines about to be contacted", so listing
// a host the run is going to refuse would say the opposite of what is true. The refused ones are
// still visible per step, with the reason attached.
func sortedRequestFlowHosts(previews []RequestFlowStepPreview) []string {
	seen := map[string]bool{}
	hosts := []string{}
	for _, p := range previews {
		if p.Host == "" || !p.Enabled || p.Refusal != "" || seen[p.Host] {
			continue
		}
		seen[p.Host] = true
		hosts = append(hosts, p.Host)
	}
	sort.Strings(hosts)
	return hosts
}
