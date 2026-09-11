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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Running a DETECTED flow: the button the Request Flows modal was missing.
//
// replayRequestFlows.go reconstructs a flow from manual_crawl_captures and draws it. The modal then
// lets the operator open any node and edit its bytes. Until this file there was nowhere for those
// bytes to go: the diagram was a reading of history with no way to make history happen again, which
// is the whole reason an operator opens it.
//
// ============================================================================
// WHY THIS IS LINEAR, AND WHERE CONDITIONS LIVE
// ============================================================================
//
// A detected flow is DERIVED. segmentCaptureFlows recomputes it on every request; there are no step
// rows, no ids that survive re-segmentation, and therefore nowhere to hang "if the status is 302 go
// to step 4". So this runner does the one thing the data supports: it takes the flow's nodes in
// captured order and sends them, in sequence, through one shared cookie jar.
//
// Branching belongs to the Request Flow Builder, which has real ordered step rows in its own tables.
// The path from here to there already exists (CreateRequestFlowFromDetectedFlow), and the answer for
// an operator who wants a condition is "Edit as flow", not a condition bolted onto a graph that is
// recomputed from scratch every time it is read.
//
// ============================================================================
// THE RAILS
// ============================================================================
//
// This sends real traffic, carrying the operator's recorded session, to a live bug bounty target.
// Every rail below exists because of that:
//
//	DRY RUN IS THE DEFAULT.   dry_run is a POINTER and an omitted one means TRUE. A caller that
//	                          forgets the field gets a plan, not traffic. Sending requires
//	                          dry_run:false, typed on purpose.
//	THE GRAPH'S OWN FILTER.   Only the significant nodes are sent, the same isSignificantFlowCapture
//	                          the diagram is drawn with. The operator chose this flow by looking at a
//	                          picture that had already hidden 90% of it as images and stylesheets; a
//	                          run that re-sends 37 hidden subresources to replay one form submit is
//	                          load nobody asked for against a diagram nobody was shown.
//	THE WHOLE FLOW RUNS.      Every verb in the flow is sent, POST included, because replaying a flow
//	                          while omitting its POST is a run that did not test the flow. There is
//	                          no verb filter here and there is not meant to be one.
//	SCOPE, AND THE DENY LIST. Hosts marked in_scope=false are refused FIRST and unconditionally, then
//	                          the boundary, then the flow exclusion rules - the same order and the
//	                          same three readers active detection uses, because a rule that only some
//	                          senders honour is not a rule.
//	ENGAGEMENT CONFIG.        ResolveEngagementConfig for the programme's header, its User-Agent, its
//	                          rate cap and its timeout, and a failure to READ it stops the run. A run
//	                          that proceeds without it sends traffic to a programme without the header
//	                          their brief calls mandatory and reports success.
//	EVERY SKIP IS REPORTED.   With the reason, per step, in the dry run and in the result. "Flow
//	                          ended" with no reason is how an operator concludes the target is broken
//	                          when it was their own filter.
//
// ============================================================================
// LOOP PROTECTION, IN A RUNNER THAT CANNOT LOOP
// ============================================================================
//
// This runner is linear, so it cannot loop today. The budget below is still counted in EXECUTIONS
// rather than definitions, and the per-step cap is still enforced, because that is the only shape
// that stays correct if anything ever gives this loop a backwards edge. A budget that counts
// definitions is a budget a four-step flow can spin inside forever.
//
// A run that hits a cap STOPS and names the cap it hit, in words, in stopped_by and stopped_detail.

// ---------------------------------------------------------------------------
// The caps. Not configurable off.
// ---------------------------------------------------------------------------

const (
	// The maximum number of step EXECUTIONS in one run. Counted as requests actually sent, not as
	// nodes in the flow: a flow that could re-enter a step is a handful of definitions and an
	// unbounded number of executions, and the second is what costs the target.
	//
	// 50 is chosen against the corpus: the median significant-node count of a navigation-rooted flow
	// is in single digits, and the flows above 50 are the 2,700-request burst sessions that nobody
	// means to replay in full.
	detectedFlowDefaultStepBudget = 50

	// The hard ceiling. A caller may lower the budget and may not raise it past this, whatever it
	// asks for. 300 sequential requests at the default 1 rps is already five minutes of traffic.
	detectedFlowMaxStepBudget = 300

	// How many times one node may execute in one run. This runner is linear, so the honest value is
	// one, and the check exists so that a future backwards edge trips a named cap instead of
	// spinning inside a budget that still has room.
	detectedFlowPerStepExecutions = 1

	// This runner does not retry. A retry cap belongs with the conditions that make retries
	// expressible, which is the builder. Stated as a constant so that adding retries here without
	// bounding them is a visibly wrong edit rather than an omission.
	detectedFlowMaxRetries = 0

	// Read from the wire, and kept in memory. Runs live in this process, so the second number is a
	// memory budget rather than a fidelity choice: the full body of any one step is a click away in
	// the repeater, which reads it from the database.
	detectedFlowMaxReadBody   = 2 * 1024 * 1024
	detectedFlowMaxStoredBody = 64 * 1024
	// What the progress endpoint returns per step when bodies were not asked for, so a poll every
	// second does not carry megabytes.
	detectedFlowBodyPreview = 2048

	// How many finished runs stay readable, and for how long. A detected flow has no tables, so a run
	// of it has nowhere to persist; these two numbers are what makes that bounded rather than a leak.
	detectedFlowRunRetention = 8
	detectedFlowRunTTL       = 30 * time.Minute
)

// Run statuses.
const (
	detectedFlowRunPlanned   = "planned"
	detectedFlowRunRunning   = "running"
	detectedFlowRunCompleted = "completed"
	detectedFlowRunStopped   = "stopped"
	detectedFlowRunCancelled = "cancelled"
)

// Why a step was not sent. Codes, so a client can group them; every one is accompanied by a sentence
// on the step itself, because "12 steps were skipped" is not something an operator can act on.
const (
	detectedFlowSkipSubresource    = "subresource"
	detectedFlowSkipNotReplayable  = "not_replayable"
	detectedFlowSkipNoBytes        = "no_bytes"
	detectedFlowSkipNoHost         = "no_host"
	detectedFlowSkipHostExcluded   = "host_excluded"
	detectedFlowSkipOutOfScope     = "out_of_scope"
	detectedFlowSkipExclusion      = "exclusion"
	detectedFlowSkipOverBudget     = "over_budget"
	detectedFlowSkipNotReachedStop = "not_reached"
)

// Why a run stopped early. Each maps to a sentence in detectedFlowStopSentence, and each names the
// cap in words.
const (
	detectedFlowStopStepBudget = "max_executed_steps"
	detectedFlowStopPerStepCap = "per_step_execution_cap"
	detectedFlowStopEngagement = "engagement_request_budget"
	detectedFlowStopOnError    = "stop_on_error"
	detectedFlowStopCancelled  = "cancelled"
)

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

// DetectedFlowRunOptions is the request body of POST /replay-request/flow/{flow_id}/run.
type DetectedFlowRunOptions struct {
	// The operator's edits, keyed by capture id, exactly the ids the graph's nodes carry. These are
	// the bytes that get sent. An override for a capture this flow does not contain is REPORTED, not
	// ignored: an edit the operator made and the runner dropped is worse than no edit box.
	Overrides map[string]string `json:"overrides"`

	// A POINTER, and an omitted one means TRUE. Dry run is the default so that a caller which forgets
	// the field gets a plan rather than traffic; sending is the deliberate dry_run:false.
	DryRun *bool `json:"dry_run"`

	// Stop the run at the first step that errors. Off by default: a flow where step two 500s is a
	// flow whose step three answer is exactly the thing worth seeing.
	StopOnError bool `json:"stop_on_error"`

	// Send the subresources the diagram hides. Same escape hatch as show_all on the graph.
	IncludeAll bool `json:"include_all"`

	// Lower the execution budget for this run. Cannot raise it past detectedFlowMaxStepBudget, and a
	// zero or absent value means the default.
	MaxSteps int `json:"max_steps"`
}

// DetectedFlowRunStep is one node of the flow and what the run did, or would do, with it.
//
// Every node of the flow gets exactly one of these, including the ones that will not be sent. A list
// that contains only the steps that ran cannot answer "where did the other eleven go".
type DetectedFlowRunStep struct {
	Order     int    `json:"order"` // 1-based position in the flow, as captured
	CaptureID string `json:"capture_id"`
	Method    string `json:"method"`
	// URL is what will actually be requested, derived from the bytes being sent rather than from the
	// capture row, so an override that rewrote the Host header shows the host it rewrote it to.
	URL            string `json:"url"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	ResourceType   string `json:"resource_type"`
	CapturedStatus int    `json:"captured_status"`
	IsRoot         bool   `json:"is_root"`

	// The exact bytes. On a dry run this IS the answer: what would be sent, in order.
	RawRequest string `json:"raw_request"`
	RawBytes   int    `json:"raw_bytes"`
	Overridden bool   `json:"overridden"`

	// Whether these bytes carry a Cookie or Authorization header. Reported rather than stripped; see
	// the comment on planDetectedFlowRun.
	CarriesCredentials bool `json:"carries_credentials"`

	WillSend   bool   `json:"will_send"`
	SkipReason string `json:"skip_reason,omitempty"`
	SkipDetail string `json:"skip_detail,omitempty"`
	// The exclusion rule that refused it, when SkipReason is "exclusion".
	SkipPattern string `json:"skip_pattern,omitempty"`

	// Filled by a real run.
	Executed        bool                `json:"executed,omitempty"`
	Status          int                 `json:"status,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
	ResponseBytes   int                 `json:"response_bytes,omitempty"`
	BodyTruncated   bool                `json:"response_truncated,omitempty"`
	DurationMs      float64             `json:"duration_ms,omitempty"`
	Error           string              `json:"error,omitempty"`
	// What the engagement config changed about this request before it went out, in words. Empty when
	// it changed nothing.
	EngagementNotes []string `json:"engagement_notes,omitempty"`
}

// DetectedFlowRunPlan is what a dry run returns and what a real run executes. One shape for both, so
// what the operator approved is what goes out.
type DetectedFlowRunPlan struct {
	FlowID        string `json:"flow_id"`
	ScopeTargetID string `json:"scope_target_id"`
	Label         string `json:"label"`

	// Every node, in captured order. will_send says which of them produce traffic.
	Steps []DetectedFlowRunStep `json:"steps"`

	// The three numbers a dry run exists to answer: how many requests, where to, and what will not be
	// sent. RequestCount counts REQUESTS, not steps, because a skipped step is a step that costs the
	// target nothing and the operator is deciding about traffic.
	RequestCount int      `json:"request_count"`
	SkippedCount int      `json:"skipped_count"`
	NodeCount    int      `json:"node_count"`
	Hosts        []string `json:"hosts"`

	// How many of the requests about to go out carry the operator's recorded session.
	CredentialCount int `json:"credential_count"`

	StepBudget   int     `json:"step_budget"`
	BudgetSource string  `json:"budget_source"`
	RPS          float64 `json:"rps"`
	TimeoutS     int     `json:"timeout_s"`
	// Wall-clock cost at the paced rate, so "run" is a decision with a number attached.
	EstimatedSeconds int `json:"estimated_seconds"`

	ScopeBoundary     string   `json:"scope_boundary"`
	DeniedHosts       []string `json:"denied_hosts"`
	ExclusionPatterns []string `json:"exclusion_patterns"`

	// The programme's rules and where each field came from, so the plan can say "sending
	// X-HackerOne-DailyPay-Research, set for this target" rather than leaving the operator to trust
	// that it happened.
	Engagement *ResolvedEngagementConfig `json:"engagement,omitempty"`

	IncludeAll  bool `json:"include_all"`
	StopOnError bool `json:"stop_on_error"`

	// Capture ids the caller sent an override for that are not in this flow. Never silently dropped.
	UnusedOverrides []string `json:"unused_overrides,omitempty"`

	// Set when the plan is legal but produces no traffic, or when something about it needs saying
	// before the operator presses run.
	Warning string   `json:"warning,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// DetectedFlowRunReport is a run in progress or finished.
type DetectedFlowRunReport struct {
	RunID         string               `json:"run_id"`
	FlowID        string               `json:"flow_id"`
	ScopeTargetID string               `json:"scope_target_id"`
	DryRun        bool                 `json:"dry_run"`
	Status        string               `json:"status"`
	Plan          *DetectedFlowRunPlan `json:"plan"`

	// The live copy. Starts as the plan's steps and gains responses as the run proceeds.
	Steps []DetectedFlowRunStep `json:"steps"`

	Executed int `json:"executed"`
	Failed   int `json:"failed"`

	// The cap or the reason the run stopped before its last step, and the sentence that names it.
	// Empty on a run that finished its plan.
	StoppedBy     string `json:"stopped_by,omitempty"`
	StoppedDetail string `json:"stopped_detail,omitempty"`

	RefusedHosts map[string]int `json:"refused_hosts,omitempty"`

	StartedAt  time.Time  `json:"started_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ---------------------------------------------------------------------------
// The pure core
//
// Everything from here to the next banner is a function over plain values with no database and no
// network. These are the decisions worth arguing about - which requests get re-sent to a live target
// and which do not - and a decision that can only be exercised against a live corpus is a decision
// nobody will ever check. detectedFlowRun_test.go exercises every one of them against structs.
// ---------------------------------------------------------------------------

// detectedFlowNode is one capture, joined to its bytes, before any run decision is made about it.
type detectedFlowNode struct {
	CaptureID      string
	Method         string
	URL            string
	ResourceType   string
	CapturedStatus int
	IsRoot         bool
	// Whether the graph's default filter would draw this node. Precomputed with the same
	// isSignificantFlowCapture the diagram uses, so the run and the picture agree.
	Significant bool
	// The bytes as captured, from BuildRawHTTPRequest. Empty when the capture's row could not be
	// loaded, which is a skip and not a silently empty request.
	RawRequest string
}

// buildDetectedFlowNodes joins a detected flow to the bytes of its captures.
//
// The ORDER is the detector's, untouched: this is the sequence the browser produced and the sequence
// the diagram is laid out in. Re-deriving it here from a second sort would be a second opinion about
// the same thing.
func buildDetectedFlowNodes(flow captureFlow, detail map[string]requestFlowSeedCapture) []detectedFlowNode {
	nodes := make([]detectedFlowNode, 0, len(flow.Captures))
	for i, c := range flow.Captures {
		node := detectedFlowNode{
			CaptureID:      c.ID,
			Method:         strings.ToUpper(strings.TrimSpace(c.Method)),
			URL:            c.URL,
			ResourceType:   c.ResourceType,
			CapturedStatus: c.StatusCode,
			IsRoot:         i == 0,
			// The root is always drawn, whatever its type, so a burst rooted on a script still has an
			// anchor. renderFlowGraph does the same, and the run must select what the picture showed.
			Significant: i == 0 || isSignificantFlowCapture(c),
		}
		if d, ok := detail[c.ID]; ok {
			// BuildRawHTTPRequest's output is used VERBATIM and deliberately not passed through
			// normalizeRawRequest, for the reason requestFlowSeedStep gives: the normalizer rewrites
			// every CRLF in the whole string, body included, and recomputes Content-Length from the
			// shortened bytes. On a multipart body that rewrites every boundary and the request stops
			// being the request that was captured.
			node.RawRequest = BuildRawHTTPRequest(d.Method, d.URL, d.Headers, d.Body)
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// detectedFlowRequestTarget reads the request-target off a raw request without parsing the whole
// thing, so it works on bytes the operator is midway through editing.
func detectedFlowRequestTarget(raw string) string {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// detectedFlowStepTarget works out the absolute URL these bytes would actually be sent to.
//
// Judged on the BYTES, never on the capture row. An operator who edited the Host header has changed
// which server this request reaches, and a scope check against the URL the browser originally
// recorded would wave that straight through.
//
// capturedURL is the fallback origin only: resolveBaseURL treats the request's own Host header as
// authoritative and consults the fallback solely to keep the scheme and port of the same host, so a
// flow captured over http://localhost:8080 is not silently upgraded to https.
func detectedFlowStepTarget(rawRequest, capturedURL string) (absolute, host string) {
	fallback := ""
	if u, err := url.Parse(strings.TrimSpace(capturedURL)); err == nil && u.Host != "" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}
		fallback = scheme + "://" + u.Host
	}

	base := resolveBaseURL(rawRequest, fallback)
	if base == "" {
		return "", ""
	}

	target := detectedFlowRequestTarget(rawRequest)
	if strings.Contains(target, "://") {
		// Absolute-form request line. It names its own origin, which is the one that would be dialled.
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.String(), strings.ToLower(u.Hostname())
		}
	}

	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Host == "" {
		return "", ""
	}
	if target == "" || !strings.HasPrefix(target, "/") {
		target = "/"
	}
	return strings.TrimRight(base, "/") + target, strings.ToLower(baseURL.Hostname())
}

// detectedFlowIsReplayable reports whether these bytes describe something an HTTP/1.1 sender can
// send at all.
//
// websocket is in flowSignificantResourceTypes because a 101 upgrade is a first-class security
// surface worth SEEING in the diagram. It is not something this runner can re-send: the upgrade is a
// handshake and what follows it is frames, not a request. Replaying the GET half of it against a
// live target produces a meaningless 400 and a step the operator has to work out for themselves.
func detectedFlowIsReplayable(node detectedFlowNode) (bool, string) {
	if strings.EqualFold(strings.TrimSpace(node.ResourceType), "websocket") {
		return false, "not sent: this is a WebSocket upgrade. The handshake and the frames after it " +
			"are not an HTTP request this runner can re-send; use a WebSocket client for it."
	}
	scheme := ""
	if u, err := url.Parse(strings.TrimSpace(node.URL)); err == nil {
		scheme = strings.ToLower(u.Scheme)
	}
	switch scheme {
	case "", "http", "https":
		return true, ""
	}
	return false, fmt.Sprintf("not sent: %s:// is not a scheme this runner speaks. Only http and "+
		"https requests can be replayed.", scheme)
}

// detectedFlowCarriesCredentials reports whether these bytes carry the operator's session.
//
// Reported, NOT stripped, and that is a deliberate choice worth its own paragraph.
//
// A detected flow is a recording of the operator's own browser, and the Cookie header is most of what
// made the flow work. Stripping it would turn every authenticated flow into a chain of redirects to
// /login that completes without error and proves nothing: the run would report twelve green steps and
// the operator would go looking for what changed on the target. That is the "200 means nothing" trap,
// arrived at by a safety measure.
//
// So the bytes go out as they are - they are the request the operator is looking at - and the plan
// says, before anything is sent, how many of them carry a session. engagement send_cookies is
// surfaced next to that count rather than used as a switch here, because it is the acknowledgement
// that this class of sender acts as the authenticated user, not a filter on which bytes are real.
func detectedFlowCarriesCredentials(raw string) bool {
	head, _, _ := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	for _, line := range strings.Split(head, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "cookie:") || strings.HasPrefix(lower, "authorization:") {
			// A header present but empty carries nothing.
			_, value, _ := strings.Cut(line, ":")
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

// resolveDetectedFlowBudget settles the execution budget and says which rule set it.
//
// Three inputs, and the LOWEST wins: what the caller asked for, this runner's ceiling, and the
// programme's own max_requests_per_run. The source is returned because a run that stops at 45 steps
// needs to be able to say whether that was the framework or the brief, and those call for different
// actions from the operator.
func resolveDetectedFlowBudget(requested, engagementMax int) (int, string) {
	budget := detectedFlowDefaultStepBudget
	source := "default"

	if requested > 0 && requested < budget {
		budget, source = requested, "requested"
	} else if requested > budget {
		// Raising it is allowed up to the hard ceiling and no further. A caller cannot configure this
		// cap off, which is the whole point of it being a cap.
		budget, source = requested, "requested"
		if budget > detectedFlowMaxStepBudget {
			budget, source = detectedFlowMaxStepBudget, "ceiling"
		}
	}

	if engagementMax > 0 && engagementMax < budget {
		budget, source = engagementMax, "engagement"
	}
	if budget < 1 {
		budget, source = 1, "ceiling"
	}
	return budget, source
}

// detectedFlowPaceInterval is the gap between two requests at the engagement's rate cap.
//
// Applied across the WHOLE run rather than per host. A flow that crosses three hosts is still one
// operator sending one sequence, and pacing per host would let a three-host flow send at three times
// the rate the brief allows.
func detectedFlowPaceInterval(rps float64) time.Duration {
	if rps <= 0 {
		return time.Second
	}
	return time.Duration(float64(time.Second) / rps)
}

// detectedFlowStopSentence names the cap that stopped a run, in words.
//
// "Flow ended" with no reason is how an operator concludes the target is broken when it was their own
// budget. Every one of these says which cap, what its value was, and what to do about it.
func detectedFlowStopSentence(code string, value int) string {
	switch code {
	case detectedFlowStopStepBudget:
		return fmt.Sprintf("Stopped: the run hit the MAX EXECUTED STEPS budget of %d. That counts "+
			"requests actually sent, not steps in the flow. Raise max_steps (ceiling %d) or run the "+
			"rest of the flow separately.", value, detectedFlowMaxStepBudget)
	case detectedFlowStopPerStepCap:
		return fmt.Sprintf("Stopped: the run hit the PER-STEP EXECUTION CAP of %d. One step was about "+
			"to be sent more than %d time(s) in a single run, which a linear runner must never do.",
			detectedFlowPerStepExecutions, detectedFlowPerStepExecutions)
	case detectedFlowStopEngagement:
		return fmt.Sprintf("Stopped: the run hit this target's ENGAGEMENT REQUEST BUDGET of %d "+
			"requests per run. That is the programme's own cap, set in the engagement config, not the "+
			"framework's.", value)
	case detectedFlowStopOnError:
		return "Stopped: stop_on_error was set and a step failed. The steps after it were not sent."
	case detectedFlowStopCancelled:
		return "Stopped: the run was cancelled. The steps it had already sent are kept."
	}
	return ""
}

// detectedFlowPlanInput is everything planDetectedFlowRun needs, as values. The database reads that
// produce it are in the handler, and NOTHING is decided there.
type detectedFlowPlanInput struct {
	FlowID        string
	ScopeTargetID string
	Label         string
	Nodes         []detectedFlowNode
	Options       DetectedFlowRunOptions
	Scope         *ScanScope
	Denied        map[string]bool
	Exclusions    []FlowExclusion
	Engagement    ResolvedEngagementConfig
}

// planDetectedFlowRun works out, without sending anything, exactly what the run would do.
//
// This is the dry run, and the real run executes this same plan, so the two cannot disagree about
// which requests go out. Two code paths here would be two chances for the preview to be wrong, which
// is the failure that makes a dry run worthless.
//
// The refusal order matters and mirrors active detection: the operator's explicit "never send here"
// is checked BEFORE the boundary, because a deny that a boundary can override is not a deny.
func planDetectedFlowRun(in detectedFlowPlanInput) *DetectedFlowRunPlan {
	budget, budgetSource := resolveDetectedFlowBudget(in.Options.MaxSteps, in.Engagement.MaxRequestsPerRun)

	plan := &DetectedFlowRunPlan{
		FlowID:            in.FlowID,
		ScopeTargetID:     in.ScopeTargetID,
		Label:             in.Label,
		Steps:             make([]DetectedFlowRunStep, 0, len(in.Nodes)),
		NodeCount:         len(in.Nodes),
		Hosts:             []string{},
		StepBudget:        budget,
		BudgetSource:      budgetSource,
		RPS:               in.Engagement.MaxRPS,
		TimeoutS:          in.Engagement.RequestTimeoutS,
		ScopeBoundary:     in.Scope.Describe(),
		DeniedHosts:       sortedDetectedFlowHostSet(in.Denied),
		ExclusionPatterns: SortedFlowExclusionPatterns(in.Exclusions),
		IncludeAll:        in.Options.IncludeAll,
		StopOnError:       in.Options.StopOnError,
		Engagement:        &in.Engagement,
	}

	// Which overrides were actually used. An override for a capture this flow does not contain is
	// reported rather than dropped: the operator edited something and the runner is about to not send
	// it, and finding that out afterwards is worse than not having offered the edit box.
	used := map[string]bool{}

	willSend := 0
	hosts := map[string]bool{}
	for i, node := range in.Nodes {
		raw := node.RawRequest
		overridden := false
		if edited, ok := in.Options.Overrides[node.CaptureID]; ok {
			used[node.CaptureID] = true
			raw = edited
			overridden = true
		}

		step := DetectedFlowRunStep{
			Order:          i + 1,
			CaptureID:      node.CaptureID,
			ResourceType:   node.ResourceType,
			CapturedStatus: node.CapturedStatus,
			IsRoot:         node.IsRoot,
			RawRequest:     raw,
			RawBytes:       len(raw),
			Overridden:     overridden,
		}

		// Method, URL and host all come from the BYTES BEING SENT, not from the capture row. An
		// operator who edited the Host header must meet the scope check for the host they typed, and
		// the plan must report the verb they actually typed rather than the one that was recorded.
		step.Method = requestFlowMethodOf(raw)
		if step.Method == "" {
			step.Method = node.Method
		}
		step.URL, step.Host = detectedFlowStepTarget(raw, node.URL)
		if step.URL == "" {
			step.URL = node.URL
		}
		step.Path = flowURLPath(step.URL)
		step.CarriesCredentials = detectedFlowCarriesCredentials(raw)

		reason, detail, pattern := detectedFlowStepRefusal(node, step, in, overridden)
		if reason == "" && willSend >= budget {
			// Marked at plan time as well as enforced in the loop, so the dry run tells the operator
			// that steps 51 and up will not go out BEFORE they press run rather than after.
			reason = detectedFlowSkipOverBudget
			detail = detectedFlowStopSentence(detectedFlowStopStepBudget, budget)
			if budgetSource == "engagement" {
				detail = detectedFlowStopSentence(detectedFlowStopEngagement, budget)
			}
		}

		if reason == "" {
			step.WillSend = true
			willSend++
			if step.Host != "" {
				hosts[step.Host] = true
			}
			if step.CarriesCredentials {
				plan.CredentialCount++
			}
		} else {
			step.SkipReason = reason
			step.SkipDetail = detail
			step.SkipPattern = pattern
			// A skipped step keeps its identity, its reason and its SIZE, and drops its bytes.
			//
			// The runner never needs them - it will not send this step - and a burst-rooted flow is up
			// to 2,700 nodes of which the default filter hides 85%. Serialising the whole request for
			// every one of them turns a dry run into a multi-megabyte response, and turns each poll of
			// a run into the same. The bytes of any capture are one double-click away in the repeater,
			// which is where the operator reads them anyway.
			step.RawRequest = ""
		}

		plan.Steps = append(plan.Steps, step)
	}

	plan.RequestCount = willSend
	plan.SkippedCount = len(plan.Steps) - willSend
	for h := range hosts {
		plan.Hosts = append(plan.Hosts, h)
	}
	sort.Strings(plan.Hosts)
	plan.EstimatedSeconds = int((time.Duration(willSend) * detectedFlowPaceInterval(plan.RPS)) / time.Second)

	for id := range in.Options.Overrides {
		if !used[id] {
			plan.UnusedOverrides = append(plan.UnusedOverrides, id)
		}
	}
	sort.Strings(plan.UnusedOverrides)

	plan.Notes = detectedFlowPlanNotes(plan, in)
	plan.Warning = detectedFlowPlanWarning(plan)
	return plan
}

// detectedFlowStepRefusal is the one place a step is judged, so the dry run and the send cannot
// disagree about which steps are allowed. An empty reason means it will be sent.
func detectedFlowStepRefusal(node detectedFlowNode, step DetectedFlowRunStep,
	in detectedFlowPlanInput, overridden bool) (reason, detail, pattern string) {

	// SELECTION, first, because it is not a refusal: these are the requests the diagram did not show.
	//
	// An OVERRIDDEN node is always in, whatever its resource type. Editing a request's bytes is the
	// operator naming it, the same way an explicit capture_ids selection wins over the noise filter in
	// seedStepsFromFlow. Dropping an edited stylesheet because stylesheets are noise would ignore the
	// one thing the operator did by hand.
	if !node.Significant && !in.Options.IncludeAll && !overridden {
		return detectedFlowSkipSubresource, fmt.Sprintf(
			"not sent: %s is a subresource the flow diagram hides by default. Set include_all to "+
				"send the whole flow, or edit this request to include just this one.",
			strings.TrimSpace(node.ResourceType)), ""
	}

	if ok, why := detectedFlowIsReplayable(node); !ok {
		return detectedFlowSkipNotReplayable, why, ""
	}

	if strings.TrimSpace(step.RawRequest) == "" {
		return detectedFlowSkipNoBytes, "not sent: this capture's request could not be rebuilt, so " +
			"there are no bytes to send. It may have been pruned from the capture table.", ""
	}

	if step.Host == "" {
		return detectedFlowSkipNoHost, "not sent: these bytes have no Host header and no usable URL, " +
			"so there is no way to tell which server to send them to.", ""
	}

	// The operator's own explicit "never send here", BEFORE the boundary. A host marked in_scope=false
	// that also sits inside the target's registrable domain is still admitted by ScanScope.Allows, so
	// this check is not redundant with the next one. See ExcludedScopeHosts.
	if IsDeniedFlowHost(in.Denied, step.Host) {
		return detectedFlowSkipHostExcluded, fmt.Sprintf(
			"not sent: %s is marked out of scope for this target.", step.Host), ""
	}

	if !in.Scope.Allows(step.Host) {
		return detectedFlowSkipOutOfScope, fmt.Sprintf(
			"not sent: %s is outside this target's boundary (%s). Add the host in the scope settings "+
				"if the engagement covers it.", step.Host, in.Scope.Describe()), ""
	}

	if d := FirstFlowExclusionMatch(in.Exclusions, step.URL); d.Excluded {
		why := d.Reason
		if strings.TrimSpace(why) == "" {
			why = "no reason was recorded on the rule"
		}
		return detectedFlowSkipExclusion, fmt.Sprintf(
			"not sent: an exclusion rule covers this URL (%s). Reason: %s", d.Pattern, why), d.Pattern
	}

	// Nothing below this line judges the verb. A POST, a PUT, a PATCH, a DELETE or a verb nobody has
	// heard of is sent exactly like a GET is: the operator recorded this flow and asked for it back.
	// The four checks above are the ones that matter, and they are about WHOSE data the request
	// touches, not which verb it uses.
	return "", "", ""
}

// detectedFlowPlanNotes says out loud the things about this run that are true and surprising.
func detectedFlowPlanNotes(plan *DetectedFlowRunPlan, in detectedFlowPlanInput) []string {
	notes := []string{}

	if plan.CredentialCount > 0 {
		note := fmt.Sprintf("%d of the %d requests carry a Cookie or Authorization header from the "+
			"recording, so the run acts as the session you captured with.",
			plan.CredentialCount, plan.RequestCount)
		if !in.Engagement.SendCookies {
			note += " send_cookies is off in this target's engagement config; the captured bytes are " +
				"sent as they are, because stripping the session would make every step redirect to a " +
				"login page and complete without proving anything."
		}
		notes = append(notes, note)
	}

	// Redirects are NOT followed, and that is not a limitation. A detected flow already contains the
	// redirect destination as its own node, because the browser requested it and the recorder stored
	// it. Following the 302 as well would send that destination twice.
	if in.Engagement.FollowRedirects {
		notes = append(notes, "Redirects are not followed. The flow already contains the destination "+
			"of each redirect as its own step, so following them would send it twice.")
	}

	if name := strings.TrimSpace(in.Engagement.CustomHeaderName); name != "" && in.Engagement.CustomHeaderValue != "" {
		notes = append(notes, fmt.Sprintf("Sending %s on every request (%s).", name,
			in.Engagement.Source["custom_header_name"]))
	}

	switch source := in.Engagement.Source["custom_user_agent"]; source {
	case EngagementFromTarget, EngagementFromGlobal:
		notes = append(notes, fmt.Sprintf("The User-Agent is set by this engagement config (%s), so "+
			"it replaces the one in the recording.", source))
	default:
		notes = append(notes, "No User-Agent is configured for this target, so each request keeps the "+
			"one it was recorded with.")
	}

	if plan.RequestCount > 0 {
		notes = append(notes, fmt.Sprintf("Paced at %.2f requests per second (%s), which is about %d "+
			"seconds for %d requests.", plan.RPS, in.Engagement.Source["max_rps"],
			plan.EstimatedSeconds, plan.RequestCount))
	}

	return notes
}

// detectedFlowPlanWarning explains an empty plan, in the terms of whatever actually emptied it.
//
// Sending an operator to re-read their exclusion list for something the subresource filter did is how
// a correct message becomes a wrong one.
func detectedFlowPlanWarning(plan *DetectedFlowRunPlan) string {
	if plan.RequestCount > 0 {
		return ""
	}
	counts := map[string]int{}
	for _, s := range plan.Steps {
		if s.SkipReason != "" {
			counts[s.SkipReason]++
		}
	}
	if len(plan.Steps) == 0 {
		return "Nothing would be sent: this flow has no requests in it."
	}

	parts := make([]string, 0, len(counts))
	for _, reason := range []string{
		detectedFlowSkipSubresource, detectedFlowSkipOutOfScope,
		detectedFlowSkipHostExcluded, detectedFlowSkipExclusion, detectedFlowSkipNotReplayable,
		detectedFlowSkipNoBytes, detectedFlowSkipNoHost, detectedFlowSkipOverBudget,
	} {
		if counts[reason] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[reason], reason))
		}
	}

	msg := "Nothing would be sent. Every step was skipped: " + strings.Join(parts, ", ") + "."
	if counts[detectedFlowSkipSubresource] > 0 {
		msg += " This flow is all subresources; include_all would send them."
	}
	return msg
}

// withoutSteps is the plan as a SUMMARY, for a response whose top-level steps array is the list.
//
// One contract on both endpoints: `steps` is always the ordered list of every node and what happened
// to it, and `plan` is always the counts, the boundary and the rules it ran under. Serialising the
// steps twice on a fifty-step flow doubles a payload that is polled every second, and gives a client
// two places to read the same thing from, which is how the two end up disagreeing.
func (p *DetectedFlowRunPlan) withoutSteps() *DetectedFlowRunPlan {
	if p == nil {
		return nil
	}
	out := *p
	out.Steps = nil
	return &out
}

func sortedDetectedFlowHostSet(hosts map[string]bool) []string {
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// applyEngagementToRequest puts the programme's rules on one outgoing request and reports, in words,
// what it changed.
//
// THE USER-AGENT RULE, which is the only judgement call here.
//
// ResolveEngagementConfig always produces an EffectiveUserAgent: with nothing configured anywhere it
// is the framework's own "ars0n-framework/2.0". Setting that unconditionally would mean every replay
// of a recorded request goes out with a User-Agent the recording never had, on every target, by
// default - and plenty of applications serve different content, or a WAF block, on a non-browser UA.
// The operator would be debugging a difference the runner introduced.
//
// So the provenance decides, which is exactly what Source exists for: when a User-Agent was actually
// CONFIGURED, for the target or globally, the programme's requirement wins and it replaces the
// recorded one. When the only thing on offer is the framework default, the recorded User-Agent is
// kept, because that is the request the operator is replaying. Either way the choice is reported on
// the step rather than being silent.
func applyEngagementToRequest(req *http.Request, engagement ResolvedEngagementConfig) []string {
	notes := []string{}

	for name, value := range engagement.HeaderMap() {
		// Set, not Add: the programme's identifying header must win over a header of the same name
		// that happened to be in the recording, and two copies of it is not what the brief asked for.
		req.Header.Set(name, value)
		notes = append(notes, "set "+name+" (engagement config)")
	}

	recorded := req.Header.Get("User-Agent")
	source := engagement.Source["custom_user_agent"]
	configured := source == EngagementFromTarget || source == EngagementFromGlobal

	if engagement.UserAgentMode == "append" && strings.TrimSpace(engagement.CustomUserAgent) != "" {
		// APPEND means custom_user_agent is a TAG glued onto a base. For a replay the honest base is
		// the User-Agent the request was recorded with, not the global one EffectiveUserAgent chose,
		// because the whole point of this runner is to re-send what was recorded.
		tag := strings.TrimSpace(engagement.CustomUserAgent)
		if recorded != "" {
			if !strings.Contains(recorded, tag) {
				req.Header.Set("User-Agent", recorded+" "+tag)
				notes = append(notes, "appended "+tag+" to the recorded User-Agent")
			}
		} else {
			req.Header.Set("User-Agent", engagement.EffectiveUserAgent)
			notes = append(notes, "set the User-Agent to "+engagement.EffectiveUserAgent)
		}
		return notes
	}

	if configured || recorded == "" {
		if req.Header.Get("User-Agent") != engagement.EffectiveUserAgent {
			req.Header.Set("User-Agent", engagement.EffectiveUserAgent)
			notes = append(notes, "replaced the User-Agent with "+engagement.EffectiveUserAgent)
		}
		return notes
	}

	// Nothing configured: the recording's own User-Agent survives.
	return notes
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

// detectedFlowRunMu guards the mutable half of a run: the per-step results, the counters and the
// status. The runner writes them from its own goroutine while the progress endpoint reads them from a
// request handler, which without this is a data race and, on a 64KB body, a torn read.
//
// SINGLE WRITER. Exactly one goroutine ever writes a given run, so the runner locks only when it
// WRITES and may read its own state freely; every reader takes the read lock. One package-level lock
// rather than one per run, because a run is a handful of microseconds of writes and a struct
// containing a mutex cannot be copied for a response without go vet objecting.
var detectedFlowRunMu sync.RWMutex

// detectedFlowWrite is the only way a run's mutable state changes.
func detectedFlowWrite(f func()) {
	detectedFlowRunMu.Lock()
	defer detectedFlowRunMu.Unlock()
	f()
}

// detectedFlowResponse is what one send produced.
type detectedFlowResponse struct {
	Status     int
	Headers    map[string][]string
	Body       string
	Bytes      int
	Truncated  bool
	DurationMs float64
	Notes      []string
}

// detectedFlowSender is the transport, as a parameter, so the loop below - which is where every cap
// is enforced - can be tested without a network. The production implementation is
// sendDetectedFlowRequest, wrapped by detectedFlowLiveSender.
//
// It takes the STEP rather than the bytes because the step carries the capture id, and the capture id
// is how the sender finds the origin the request was recorded against.
type detectedFlowSender func(ctx context.Context, step *DetectedFlowRunStep, jar http.CookieJar) (detectedFlowResponse, error)

// runDetectedFlowSteps is the whole run: the sequence, the caps, and the reason it stopped.
//
// ONE COOKIE JAR across every step. That is what makes a flow a flow rather than a list of requests:
// the Set-Cookie from step one is on step two, which is the entire mechanism a login, a CSRF token or
// a shopping basket depends on.
//
// EXECUTIONS, NOT DEFINITIONS. The budget counts requests actually sent and the per-step counter
// counts how many times each node was entered. Today the two are the same because the loop is linear;
// they are written separately so that they still hold if this ever gains a backwards edge.
func runDetectedFlowSteps(ctx context.Context, run *DetectedFlowRunReport, jar http.CookieJar,
	send detectedFlowSender, pace func(context.Context) bool, scope *ScanScope) {

	budget := run.Plan.StepBudget
	executions := map[string]int{}
	sentAny := false

	for i := range run.Steps {
		step := &run.Steps[i]
		if !step.WillSend {
			// Already has its reason from the plan. Not counted as an execution, because it costs the
			// target nothing.
			continue
		}

		if ctx.Err() != nil {
			run.stopRemaining(i, detectedFlowStopCancelled,
				detectedFlowStopSentence(detectedFlowStopCancelled, 0), scope)
			return
		}

		if run.Executed >= budget {
			code := detectedFlowStopStepBudget
			if run.Plan.BudgetSource == "engagement" {
				code = detectedFlowStopEngagement
			}
			run.stopRemaining(i, code, detectedFlowStopSentence(code, budget), scope)
			return
		}

		if executions[step.CaptureID] >= detectedFlowPerStepExecutions {
			run.stopRemaining(i, detectedFlowStopPerStepCap,
				detectedFlowStopSentence(detectedFlowStopPerStepCap, detectedFlowPerStepExecutions), scope)
			return
		}

		// The engagement rate limit applies to every request this runner sends. Paced BEFORE the send
		// rather than after, and skipped before the first one so a one-step flow is not made to wait
		// for a rate it is in no danger of exceeding.
		if sentAny && !pace(ctx) {
			run.stopRemaining(i, detectedFlowStopCancelled,
				detectedFlowStopSentence(detectedFlowStopCancelled, 0), scope)
			return
		}

		executions[step.CaptureID]++
		sentAny = true
		// Counted BEFORE the send, so a request in flight is already against the budget. Counting it
		// afterwards would let a cancelled or crashed run under-report what it put on the wire, and
		// what reached the target is the number that matters.
		detectedFlowWrite(func() {
			run.Executed++
			step.Executed = true
			run.UpdatedAt = time.Now().UTC()
		})

		resp, err := send(ctx, step, jar)

		detectedFlowWrite(func() {
			step.Status = resp.Status
			step.ResponseHeaders = resp.Headers
			step.ResponseBody = resp.Body
			step.ResponseBytes = resp.Bytes
			step.BodyTruncated = resp.Truncated
			step.DurationMs = resp.DurationMs
			if len(resp.Notes) > 0 {
				step.EngagementNotes = resp.Notes
			}
			if err != nil {
				step.Error = err.Error()
				run.Failed++
			}
			run.UpdatedAt = time.Now().UTC()
		})

		if err != nil && run.Plan.StopOnError {
			// The step that failed keeps its result; the ones after it are marked not-reached so the
			// operator can tell "did not run" from "ran and returned nothing".
			run.stopRemaining(i+1, detectedFlowStopOnError,
				detectedFlowStopSentence(detectedFlowStopOnError, 0), scope)
			return
		}
	}

	detectedFlowWrite(func() {
		run.Status = detectedFlowRunCompleted
		run.finish(scope)
	})
}

// stopRemaining ends a run at index `from` and says why, on the run AND on every step that will now
// never be sent. A step with no verdict is a step the operator has to guess about: "did not run" and
// "ran and returned nothing" are different findings.
func (run *DetectedFlowRunReport) stopRemaining(from int, code, detail string, scope *ScanScope) {
	detectedFlowWrite(func() {
		run.StoppedBy = code
		run.StoppedDetail = detail
		run.Status = detectedFlowRunStopped
		if code == detectedFlowStopCancelled {
			run.Status = detectedFlowRunCancelled
		}
		for i := from; i < len(run.Steps); i++ {
			step := &run.Steps[i]
			if !step.WillSend || step.Executed {
				continue
			}
			step.WillSend = false
			step.SkipReason = detectedFlowSkipNotReachedStop
			step.SkipDetail = detail
		}
		run.finish(scope)
	})
}

// finish stamps a run as over. Called with detectedFlowRunMu held.
func (run *DetectedFlowRunReport) finish(scope *ScanScope) {
	now := time.Now().UTC()
	run.UpdatedAt = now
	if run.FinishedAt == nil {
		run.FinishedAt = &now
	}
	if scope != nil {
		if refused := scope.Refused(); len(refused) > 0 {
			run.RefusedHosts = refused
		}
	}
}

// sendDetectedFlowRequest is the transport: raw bytes in, response out, with the programme's rules
// applied.
//
// Modelled on sendRawRequest, which it deliberately does not call, for two reasons. sendRawRequest
// hardcodes a 30 second timeout and knows nothing about an engagement config, so a target capped at
// 10 seconds by its brief would be given three times that; and it takes no context, so a cancelled
// run would go on sending until its last request returned.
//
// REDIRECTS ARE NOT FOLLOWED. A detected flow already contains the destination of every redirect as
// its own node, because the browser requested it and the recorder stored it. Following the 302 here
// would send that destination twice: once as a hop and once as the step it already is.
func sendDetectedFlowRequest(ctx context.Context, raw, capturedURL string, jar http.CookieJar,
	engagement ResolvedEngagementConfig) (detectedFlowResponse, error) {

	out := detectedFlowResponse{}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return out, fmt.Errorf("these bytes are not a request an HTTP client can send: %w", err)
	}

	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	absolute, _ := detectedFlowStepTarget(raw, capturedURL)
	target, perr := url.Parse(absolute)
	if perr != nil || target.Host == "" {
		return out, fmt.Errorf("could not work out which server to send this to (%q)", absolute)
	}

	hostHeader := req.Host // the Host header as written, preserved on the wire
	req.URL = target
	req.RequestURI = ""
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	if hostHeader != "" {
		req.Host = hostHeader
	} else {
		req.Host = target.Host
	}

	out.Notes = applyEngagementToRequest(req, engagement)

	timeout := time.Duration(engagement.RequestTimeoutS) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(engagementDefaultTimeoutS) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// Matches the repeater and the auth-flow replay: these are replays of traffic the operator
			// already recorded against this host, often a staging origin with its own certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	start := time.Now()
	resp, err := client.Do(req.WithContext(ctx))
	out.DurationMs = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	read, _ := io.ReadAll(io.LimitReader(resp.Body, detectedFlowMaxReadBody))
	out.Status = resp.StatusCode
	out.Headers = resp.Header
	out.Bytes = len(read)
	stored := sanitizeForTextColumn(string(read))
	if len(stored) > detectedFlowMaxStoredBody {
		stored = stored[:detectedFlowMaxStoredBody]
		out.Truncated = true
	}
	out.Body = stored
	return out, nil
}

// ---------------------------------------------------------------------------
// Where a run lives
//
// A detected flow is derived and has no tables, so a run of one has nowhere to persist. Runs are held
// in this process, bounded by count and by age. That is a deliberate limit, not an oversight: the
// evidence worth keeping from a run is the response, and the operator promotes a flow they care about
// into the builder ("Edit as flow"), which does have tables.
// ---------------------------------------------------------------------------

type detectedFlowRunRegistry struct {
	mu     sync.Mutex
	runs   map[string]*DetectedFlowRunReport
	cancel map[string]context.CancelFunc
	// flow id -> the run currently in flight for it. One run per flow at a time: two runs of the same
	// flow share nothing except the target, and the target is what they would be doubling up on.
	active map[string]string
	order  []string
}

var detectedFlowRuns = &detectedFlowRunRegistry{
	runs:   map[string]*DetectedFlowRunReport{},
	cancel: map[string]context.CancelFunc{},
	active: map[string]string{},
}

func (r *detectedFlowRunRegistry) start(run *DetectedFlowRunReport, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs[run.RunID] = run
	r.cancel[run.RunID] = cancel
	r.active[run.FlowID] = run.RunID
	r.order = append(r.order, run.RunID)
	r.evictLocked()
}

func (r *detectedFlowRunRegistry) done(runID, flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cancel, runID)
	if r.active[flowID] == runID {
		delete(r.active, flowID)
	}
}

// activeRun reports the run already in flight for this flow, if there is one.
func (r *detectedFlowRunRegistry) activeRun(flowID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	runID, ok := r.active[flowID]
	if !ok {
		return ""
	}
	if run, exists := r.runs[runID]; exists && detectedFlowIsFinished(run) {
		return ""
	}
	return runID
}

// identity returns a run's immutable half: the fields fixed when it was created, which the runner
// never writes and a reader therefore needs no lock for.
func (r *detectedFlowRunRegistry) identity(runID string) (flowID string, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[runID]
	if !ok {
		return "", false
	}
	return run.FlowID, true
}

// detectedFlowIsFinished reads the one mutable field the registry needs, under the run lock.
func detectedFlowIsFinished(run *DetectedFlowRunReport) bool {
	detectedFlowRunMu.RLock()
	defer detectedFlowRunMu.RUnlock()
	return run.FinishedAt != nil
}

func detectedFlowFinishedBefore(run *DetectedFlowRunReport, cutoff time.Time) bool {
	detectedFlowRunMu.RLock()
	defer detectedFlowRunMu.RUnlock()
	return run.FinishedAt != nil && run.FinishedAt.Before(cutoff)
}

func (r *detectedFlowRunRegistry) requestCancel(runID string) bool {
	r.mu.Lock()
	cancel, ok := r.cancel[runID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	return true
}

// evictLocked keeps the registry bounded by age first and count second. Anything still running is
// kept whatever its age: evicting a run in flight would leave the operator polling a 404 for
// something that is still sending.
func (r *detectedFlowRunRegistry) evictLocked() {
	cutoff := time.Now().UTC().Add(-detectedFlowRunTTL)
	kept := r.order[:0]
	for _, id := range r.order {
		run, ok := r.runs[id]
		if !ok {
			continue
		}
		if detectedFlowFinishedBefore(run, cutoff) {
			delete(r.runs, id)
			continue
		}
		kept = append(kept, id)
	}
	r.order = kept

	for len(r.order) > detectedFlowRunRetention {
		oldest := r.order[0]
		if run, ok := r.runs[oldest]; ok && !detectedFlowIsFinished(run) {
			// Still running. Leave it and stop pruning rather than reordering: the queue is in start
			// order and the next one along is not older.
			break
		}
		delete(r.runs, oldest)
		r.order = r.order[1:]
	}
}

// snapshot copies a run for a response. The runner mutates its steps in place from another goroutine,
// so serialising the live struct is a data race and, on a 64KB body, a torn read.
//
// Two locks: the registry's own, which protects the map, and the run lock, which protects what the
// runner is writing into the struct the map points at. Taken in that order everywhere, and the runner
// never reaches for the registry while holding the run lock.
func (r *detectedFlowRunRegistry) snapshot(runID string, bodies bool) *DetectedFlowRunReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[runID]
	if !ok {
		return nil
	}

	detectedFlowRunMu.RLock()
	defer detectedFlowRunMu.RUnlock()

	out := *run
	out.Plan = run.Plan.withoutSteps()
	out.Steps = make([]DetectedFlowRunStep, len(run.Steps))
	copy(out.Steps, run.Steps)
	if !bodies {
		// A progress poll every second must not carry megabytes. The bytes and the truncation flag
		// stay, so the preview never reads as the whole body.
		for i := range out.Steps {
			if len(out.Steps[i].ResponseBody) > detectedFlowBodyPreview {
				out.Steps[i].ResponseBody = out.Steps[i].ResponseBody[:detectedFlowBodyPreview]
				out.Steps[i].BodyTruncated = true
			}
		}
	}
	return &out
}

// ---------------------------------------------------------------------------
// POST /replay-request/flow/{flow_id}/run
// ---------------------------------------------------------------------------

// RunDetectedFlow plans a run of a detected flow, and executes it when dry_run is explicitly false.
//
// The dry run and the real run share one planner, so what the operator approved is what goes out.
func RunDetectedFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	if _, _, _, err := DecodeFlowID(flowID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_flow_id", err.Error())
		return
	}

	var opts DetectedFlowRunOptions
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&opts); err != nil && err != io.EOF {
			writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
			return
		}
	}

	// THE DEFAULT. An omitted dry_run is a dry run. A caller that forgets the field gets a plan, never
	// traffic.
	dryRun := true
	if opts.DryRun != nil {
		dryRun = *opts.DryRun
	}

	// An empty override is refused rather than quietly replaced by the original bytes. An operator who
	// blanked a request meant something by it, and sending the recording instead would be the runner
	// substituting its own idea of the request for theirs.
	for id, raw := range opts.Overrides {
		if strings.TrimSpace(raw) == "" {
			writeJSONError(w, http.StatusBadRequest, "empty_override", fmt.Sprintf(
				"The override for capture %s is empty. An empty request is not a request; remove the "+
					"override to send the recorded bytes, or write the ones you want sent.", id))
			return
		}
	}

	flow, scopeTargetID, err := loadDetectedFlowForRun(flowID)
	if err != nil {
		if err == errDetectedFlowNotFound {
			writeJSONError(w, http.StatusNotFound, "flow_not_found",
				"No flow starts at that request. It may have been re-segmented as new captures "+
					"arrived; reload the flow list.")
			return
		}
		log.Printf("[FLOW-RUN] Failed to load flow %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The flow could not be loaded: "+err.Error())
		return
	}

	// FAIL CLOSED ON ALL THREE. The engagement config, the deny list and the exclusion rules are the
	// programme's rules and the operator's own "never send here". A run that proceeds without being
	// able to read them sends traffic to a programme without the header their brief calls mandatory,
	// to a host somebody ticked off, and reports success. The DRY RUN fails the same way: a preview
	// built without the rules would show a plan the real run cannot honour.
	engagement, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "engagement_unreadable",
			"This target's engagement config could not be read, so no run may start: "+err.Error())
		return
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "scope_unreadable",
			"The excluded-host list could not be read, so no run may start: "+err.Error())
		return
	}
	exclusions, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "exclusions_unreadable",
			"The exclusion list could not be read, so no run may start: "+err.Error())
		return
	}

	ids := make([]string, 0, len(flow.Captures))
	for _, c := range flow.Captures {
		ids = append(ids, c.ID)
	}
	// Scoped to the target, so a flow can never be assembled from another engagement's traffic.
	detail, err := loadRequestFlowSeedCaptures(scopeTargetID, ids)
	if err != nil {
		log.Printf("[FLOW-RUN] Failed to load capture bytes for %s: %v", flowID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The flow's requests could not be loaded: "+err.Error())
		return
	}

	scope := LoadScanScope(scopeTargetID)
	summary := summarizeFlow(flow)
	plan := planDetectedFlowRun(detectedFlowPlanInput{
		FlowID:        flowID,
		ScopeTargetID: scopeTargetID,
		Label:         summary.Label,
		Nodes:         buildDetectedFlowNodes(flow, detail),
		Options:       opts,
		Scope:         scope,
		Denied:        denied,
		Exclusions:    exclusions,
		Engagement:    engagement,
	})

	if dryRun {
		// THE DRY RUN, and the shape both endpoints answer in: `steps` is what would be sent, in
		// order, with every skipped one carrying its reason; `plan` is the counts and the rules. No
		// run id, because nothing was started and there is nothing to poll.
		now := time.Now().UTC()
		json.NewEncoder(w).Encode(DetectedFlowRunReport{
			FlowID:        flowID,
			ScopeTargetID: scopeTargetID,
			DryRun:        true,
			Status:        detectedFlowRunPlanned,
			Plan:          plan.withoutSteps(),
			Steps:         plan.Steps,
			StartedAt:     now,
			UpdatedAt:     now,
		})
		return
	}

	if plan.RequestCount == 0 {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_send", plan.Warning)
		return
	}
	if existing := detectedFlowRuns.activeRun(flowID); existing != "" {
		writeJSONError(w, http.StatusConflict, "already_running", fmt.Sprintf(
			"Run %s is already in flight for this flow. Wait for it or cancel it; two runs of the "+
				"same flow would double the traffic at the target and share nothing else.", existing))
		return
	}

	runID := uuid.New().String()

	// ONE SENDER PER TARGET. The check above is per FLOW, which lets two DIFFERENT flows on the same
	// target start together and double the traffic at exactly the thing its own comment says they
	// would be doubling up on. This gate is keyed on the target, which is what the engagement's rate
	// limit belongs to. See flowTargetGate.go.
	releaseTarget, holder, ok := flowTargets.acquire(scopeTargetID, flowTargetHolder{
		Kind: "detected", RunID: runID, FlowID: flowID, Label: summary.Label,
	})
	if !ok {
		writeJSONError(w, http.StatusConflict, "target_busy",
			flowTargetBusyMessage(holder, engagement.MaxRPS))
		return
	}

	now := time.Now().UTC()
	run := &DetectedFlowRunReport{
		RunID:         runID,
		FlowID:        flowID,
		ScopeTargetID: scopeTargetID,
		DryRun:        false,
		Status:        detectedFlowRunRunning,
		Plan:          plan,
		Steps:         append([]DetectedFlowRunStep(nil), plan.Steps...),
		StartedAt:     now,
		UpdatedAt:     now,
	}

	ctx, cancel := context.WithCancel(context.Background())
	detectedFlowRuns.start(run, cancel)

	// The capture URL each step's bytes came from, so the sender can keep the recorded scheme and port
	// for a host the Host header names without a scheme.
	capturedURLs := map[string]string{}
	for _, c := range flow.Captures {
		capturedURLs[c.ID] = c.URL
	}

	go func() {
		defer cancel()
		// Released when the SENDING stops, not when the handler returns: this run is asynchronous, and
		// a gate released at the response would be no gate at all.
		defer releaseTarget()
		defer detectedFlowRuns.done(runID, flowID)

		jar, jerr := cookiejar.New(nil)
		if jerr != nil {
			log.Printf("[FLOW-RUN] Cookie jar failed for run %s: %v", runID, jerr)
		}

		runDetectedFlowSteps(ctx, run, jar,
			detectedFlowLiveSender(capturedURLs, engagement),
			detectedFlowPacer(detectedFlowPaceInterval(engagement.MaxRPS)),
			scope)

		log.Printf("[FLOW-RUN] Run %s %s: %d sent, %d failed%s", runID, run.Status,
			run.Executed, run.Failed, detectedFlowStopSuffix(run))
	}()

	// The same shape the poll answers in, so the client renders the run with one code path from the
	// moment it starts, plus the URL to poll.
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(struct {
		DetectedFlowRunReport
		Poll string `json:"poll"`
	}{
		DetectedFlowRunReport: DetectedFlowRunReport{
			RunID:         runID,
			FlowID:        flowID,
			ScopeTargetID: scopeTargetID,
			DryRun:        false,
			Status:        detectedFlowRunRunning,
			Plan:          plan.withoutSteps(),
			Steps:         plan.Steps,
			StartedAt:     now,
			UpdatedAt:     now,
		},
		Poll: fmt.Sprintf("/replay-request/flow/%s/run/%s", flowID, runID),
	})
}

func detectedFlowStopSuffix(run *DetectedFlowRunReport) string {
	if run.StoppedBy == "" {
		return ""
	}
	return " (stopped by " + run.StoppedBy + ")"
}

// detectedFlowLiveSender is the production transport, bound to the URLs the steps were captured
// against so each request keeps the scheme and port of the origin it was recorded on.
func detectedFlowLiveSender(capturedURLs map[string]string, engagement ResolvedEngagementConfig) detectedFlowSender {
	return func(ctx context.Context, step *DetectedFlowRunStep, jar http.CookieJar) (detectedFlowResponse, error) {
		return sendDetectedFlowRequest(ctx, step.RawRequest, capturedURLs[step.CaptureID], jar, engagement)
	}
}

// detectedFlowPacer is the engagement rate limit, as the gap the runner waits before each send. It
// returns false when the run was cancelled while waiting, so a cancel does not have to survive a
// whole interval before it is noticed.
func detectedFlowPacer(interval time.Duration) func(context.Context) bool {
	return func(ctx context.Context) bool {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		select {
		case <-timer.C:
			return true
		case <-ctx.Done():
			return false
		}
	}
}

// ---------------------------------------------------------------------------
// GET /replay-request/flow/{flow_id}/run/{run_id}
// ---------------------------------------------------------------------------

// GetDetectedFlowRun returns progress and results.
//
// Bodies are omitted by default and returned in full with ?bodies=1, because this endpoint is polled
// while the run is in flight and fifty 64KB bodies on every poll is a megabyte a second for nothing.
func GetDetectedFlowRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	flowID := mux.Vars(r)["flow_id"]
	runID := mux.Vars(r)["run_id"]

	run := detectedFlowRuns.snapshot(runID, flowParseBool(r.URL.Query().Get("bodies")))
	if run == nil {
		writeJSONError(w, http.StatusNotFound, "run_not_found",
			"No run with that id. Runs of a detected flow are held in memory and are kept for "+
				"30 minutes; the api restarting or eight later runs will retire one. Promote the flow "+
				"to the builder if you need its results to persist.")
		return
	}
	// A run id from a different flow is not this flow's run, whatever the path says.
	if run.FlowID != flowID {
		writeJSONError(w, http.StatusNotFound, "run_not_found", "That run belongs to a different flow.")
		return
	}

	json.NewEncoder(w).Encode(run)
}

// ---------------------------------------------------------------------------
// POST /replay-request/flow/{flow_id}/run/{run_id}/cancel
// ---------------------------------------------------------------------------

// CancelDetectedFlowRun stops a run in flight.
//
// A cancelled run KEEPS what it already sent. The operator who pressed cancel usually did so having
// seen something worth looking at, and discarding the run would discard that with it.
func CancelDetectedFlowRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	runID := mux.Vars(r)["run_id"]
	flowID, found := detectedFlowRuns.identity(runID)
	if !found || flowID != mux.Vars(r)["flow_id"] {
		writeJSONError(w, http.StatusNotFound, "run_not_found", "No run with that id for this flow.")
		return
	}
	if !detectedFlowRuns.requestCancel(runID) {
		status := ""
		if snap := detectedFlowRuns.snapshot(runID, false); snap != nil {
			status = snap.Status
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"run_id": runID, "status": status,
			"message": "That run has already finished; nothing was cancelled.",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id":  runID,
		"status":  "cancelling",
		"message": "Cancelling. The steps already sent are kept.",
	})
}

// ---------------------------------------------------------------------------
// The database layer, which decides nothing
// ---------------------------------------------------------------------------

var errDetectedFlowNotFound = fmt.Errorf("no flow starts at that capture")

// loadDetectedFlowForRun re-derives one detected flow, and the target it belongs to.
//
// The WHOLE TAB is loaded, because a flow is defined by its boundaries and the boundaries are the
// neighbouring navigations. Loading only this flow's rows would need the segmentation that loading
// them is for. The scope target comes from the root capture's own row and every other row is pinned
// to it, so a flow can never be assembled from two targets' traffic.
func loadDetectedFlowForRun(flowID string) (captureFlow, string, error) {
	sessionID, tabID, rootCaptureID, err := DecodeFlowID(flowID)
	if err != nil {
		return captureFlow{}, "", err
	}

	var scopeTargetID string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id::text FROM manual_crawl_captures WHERE id = $1`,
		rootCaptureID).Scan(&scopeTargetID); err != nil {
		return captureFlow{}, "", errDetectedFlowNotFound
	}

	sqlText := fmt.Sprintf(`
		SELECT id, session_id, tab_id, COALESCE(method,''), COALESCE(url,''),
		       COALESCE(status_code,0), COALESCE(resource_type,''), COALESCE(initiator,''),
		       COALESCE(mime_type,''), timestamp, COALESCE(duration_ms,0),
		       COALESCE(octet_length(response_body),0),
		       (COALESCE(post_data,'') <> '') AS has_body,
		       COALESCE(redirect_chain,'[]'::jsonb),
		       TRUE AS matched
		FROM manual_crawl_captures
		WHERE session_id = $1 AND tab_id IS NOT DISTINCT FROM $2 AND scope_target_id = $3
		ORDER BY timestamp ASC
		LIMIT %d`, flowScanCeiling)

	captures, err := queryFlowCaptures(sqlText, []interface{}{sessionID, tabID, scopeTargetID})
	if err != nil {
		return captureFlow{}, "", err
	}

	for _, f := range segmentCaptureFlows(captures) {
		if len(f.Captures) > 0 && f.Captures[0].ID == rootCaptureID {
			return f, scopeTargetID, nil
		}
	}
	return captureFlow{}, "", errDetectedFlowNotFound
}
