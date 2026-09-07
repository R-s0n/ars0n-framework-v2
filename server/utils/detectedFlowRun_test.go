package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Running a detected flow sends real traffic, carrying the operator's recorded session, at a live bug
// bounty target. Every decision about WHICH of a flow's requests goes out is made by a pure function,
// and every one of them is exercised here against structs rather than against a live 6,000-row
// capture table - because a rule that can only be checked by pointing the runner at somebody's
// production is a rule nobody will ever check again.
//
// The tests fall into four groups:
//
//	selection   which nodes are sent, and every reason one is not
//	overrides   the operator's edited bytes, which must be the bytes that go out
//	caps        the execution budget, counted in executions, and the sentence that names it
//	engagement  the programme's header, User-Agent, rate and timeout

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const dfrRecordedUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

// dfrScope builds a boundary without touching the database. The maps are initialised by hand because
// a zero-value ScanScope has nil ones and Refuse would panic on the first out-of-scope host.
func dfrScope(hosts ...string) *ScanScope {
	s := &ScanScope{
		domains: map[string]bool{},
		extra:   map[string]bool{},
		refused: map[string]int{},
	}
	s.Allow(hosts...)
	return s
}

// dfrEngagement is the framework's own defaults: nothing configured for the target and nothing
// global, which is the state most installs are in.
func dfrEngagement() ResolvedEngagementConfig {
	return ResolveEngagementFrom(nil, EngagementGlobals{})
}

func dfrNode(id, method, rawURL, resourceType string) detectedFlowNode {
	return detectedFlowNode{
		CaptureID:      id,
		Method:         method,
		URL:            rawURL,
		ResourceType:   resourceType,
		CapturedStatus: 200,
		Significant:    flowSignificantResourceTypes[strings.ToLower(resourceType)],
		RawRequest: BuildRawHTTPRequest(method, rawURL,
			map[string]interface{}{"User-Agent": dfrRecordedUA, "Accept": "*/*"}, ""),
	}
}

func dfrRoot(id, method, rawURL string) detectedFlowNode {
	n := dfrNode(id, method, rawURL, "document")
	n.IsRoot = true
	n.Significant = true
	return n
}

func dfrWithBody(n detectedFlowNode, body string) detectedFlowNode {
	n.RawRequest = BuildRawHTTPRequest(n.Method, n.URL,
		map[string]interface{}{"User-Agent": dfrRecordedUA, "Content-Type": "application/json"}, body)
	return n
}

func dfrWithCookie(n detectedFlowNode, cookie string) detectedFlowNode {
	n.RawRequest = BuildRawHTTPRequest(n.Method, n.URL,
		map[string]interface{}{"User-Agent": dfrRecordedUA, "Cookie": cookie}, "")
	return n
}

// dfrPlan runs the planner with the framework defaults and an allow-list of one domain.
func dfrPlan(nodes []detectedFlowNode, opts DetectedFlowRunOptions) *DetectedFlowRunPlan {
	return planDetectedFlowRun(detectedFlowPlanInput{
		FlowID:        "11111111-1111-1111-1111-111111111111~7~22222222-2222-2222-2222-222222222222",
		ScopeTargetID: "33333333-3333-3333-3333-333333333333",
		Label:         "GET /dashboard",
		Nodes:         nodes,
		Options:       opts,
		Scope:         dfrScope("example.com"),
		Denied:        map[string]bool{},
		Exclusions:    nil,
		Engagement:    dfrEngagement(),
	})
}

// dfrStep finds one step of a plan by capture id.
func dfrStep(t *testing.T, plan *DetectedFlowRunPlan, captureID string) DetectedFlowRunStep {
	t.Helper()
	for _, s := range plan.Steps {
		if s.CaptureID == captureID {
			return s
		}
	}
	t.Fatalf("no step for capture %s; the plan must contain EVERY node of the flow, "+
		"including the ones it will not send", captureID)
	return DetectedFlowRunStep{}
}

// dfrSent lists the capture ids that would actually produce traffic, in order.
func dfrSent(plan *DetectedFlowRunPlan) []string {
	out := []string{}
	for _, s := range plan.Steps {
		if s.WillSend {
			out = append(out, s.CaptureID)
		}
	}
	return out
}

func dfrSameIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// dfrReport wraps a plan in a run the loop can execute.
func dfrReport(plan *DetectedFlowRunPlan) *DetectedFlowRunReport {
	return &DetectedFlowRunReport{
		RunID:  "run",
		FlowID: plan.FlowID,
		Status: detectedFlowRunRunning,
		Plan:   plan,
		Steps:  append([]DetectedFlowRunStep(nil), plan.Steps...),
	}
}

// dfrNoPace is the rate limiter with the waiting removed, so a test of the loop is not a test of
// time.Sleep.
func dfrNoPace(context.Context) bool { return true }

// dfrRecordingSender answers every request 200 and remembers the order it was asked in.
func dfrRecordingSender(sent *[]string) detectedFlowSender {
	return func(_ context.Context, step *DetectedFlowRunStep, _ http.CookieJar) (detectedFlowResponse, error) {
		*sent = append(*sent, step.CaptureID)
		return detectedFlowResponse{Status: 200, Body: "ok", Bytes: 2, DurationMs: 1}, nil
	}
}

// ---------------------------------------------------------------------------
// Selection: which of a flow's requests are sent at all
// ---------------------------------------------------------------------------

// The default is the graph's own filter. The operator chose this flow by looking at a diagram that
// had already hidden 90% of it, and a run that re-sends 37 stylesheets to replay one form submit is
// load nobody asked for against a picture nobody was shown.
func TestDetectedFlowRunSendsOnlyTheNodesTheGraphShows(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/dashboard"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
		dfrNode("img", "GET", "https://app.example.com/logo.png", "image"),
		dfrNode("xhr", "GET", "https://app.example.com/api/tickets", "xhr"),
		dfrNode("js", "GET", "https://app.example.com/app.js", "script"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	if want := []string{"root", "xhr"}; !dfrSameIDs(dfrSent(plan), want) {
		t.Fatalf("the default must send the significant nodes only, got %v want %v", dfrSent(plan), want)
	}
	if plan.RequestCount != 2 || plan.SkippedCount != 3 || plan.NodeCount != 5 {
		t.Errorf("the counts must describe requests, skips and the whole flow, got %d/%d/%d",
			plan.RequestCount, plan.SkippedCount, plan.NodeCount)
	}
	for _, id := range []string{"css", "img", "js"} {
		step := dfrStep(t, plan, id)
		if step.SkipReason != detectedFlowSkipSubresource {
			t.Errorf("%s must be skipped as a subresource, got %q", id, step.SkipReason)
		}
		if !strings.Contains(step.SkipDetail, "include_all") {
			t.Errorf("a hidden subresource must be told how to include it, got %q", step.SkipDetail)
		}
	}
}

func TestDetectedFlowRunIncludeAllSendsTheHiddenOnes(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/dashboard"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
		dfrNode("xhr", "GET", "https://app.example.com/api/tickets", "xhr"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{IncludeAll: true})

	if want := []string{"root", "css", "xhr"}; !dfrSameIDs(dfrSent(plan), want) {
		t.Fatalf("include_all must send the whole flow, got %v", dfrSent(plan))
	}
}

// A burst-rooted flow can be rooted on a script. renderFlowGraph always draws the root, so the run
// must always send it: a flow whose anchor is missing is not the flow the operator looked at.
func TestDetectedFlowRunRootIsAlwaysSent(t *testing.T) {
	root := dfrNode("root", "GET", "https://app.example.com/bundle.js", "script")
	root.IsRoot = true
	root.Significant = true // buildDetectedFlowNodes sets this for index 0 whatever the type

	plan := dfrPlan([]detectedFlowNode{root}, DetectedFlowRunOptions{})

	if !dfrStep(t, plan, "root").WillSend {
		t.Fatal("the root of a flow must always be sent, whatever its resource type")
	}
}

// buildDetectedFlowNodes must agree with the diagram about what is significant, because the run and
// the picture are meant to be the same set of requests.
func TestDetectedFlowRunNodeSelectionMatchesTheGraphFilter(t *testing.T) {
	base := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	flow := captureFlow{
		RootKind: flowRootNavigation,
		Captures: []FlowCapture{
			{ID: "root", Method: "GET", URL: "https://app.example.com/x", ResourceType: "document", Timestamp: base},
			{ID: "css", Method: "GET", URL: "https://app.example.com/a.css", ResourceType: "stylesheet", Timestamp: base.Add(time.Second)},
			{ID: "post", Method: "POST", URL: "https://app.example.com/api", ResourceType: "image", HasBody: true, Timestamp: base.Add(2 * time.Second)},
			{ID: "ping", Method: "POST", URL: "https://app.example.com/p", ResourceType: "ping", HasBody: true, Timestamp: base.Add(3 * time.Second)},
		},
	}

	nodes := buildDetectedFlowNodes(flow, map[string]requestFlowSeedCapture{
		"root": {ID: "root", Method: "GET", URL: "https://app.example.com/x"},
	})

	if len(nodes) != 4 {
		t.Fatalf("every capture must become a node, got %d", len(nodes))
	}
	for _, n := range nodes {
		want := n.CaptureID == "root" || n.CaptureID == "post"
		if n.Significant != want {
			t.Errorf("%s significance %v, want %v: the run must select exactly what the graph draws "+
				"(a bodied image is in, a telemetry ping with a body is not)", n.CaptureID, n.Significant, want)
		}
	}
	if nodes[0].RawRequest == "" {
		t.Error("a node whose capture bytes loaded must carry them")
	}
	if nodes[1].RawRequest != "" {
		t.Error("a node whose bytes could not be loaded must be left empty rather than invented")
	}
}

// A capture whose bytes could not be rebuilt is skipped and said so. An empty request sent as a step
// is worse than a missing one, because it produces a response the operator will try to read.
func TestDetectedFlowRunSkipsNodesWithNoBytes(t *testing.T) {
	broken := dfrNode("gone", "GET", "https://app.example.com/api", "xhr")
	broken.RawRequest = ""

	plan := dfrPlan([]detectedFlowNode{dfrRoot("root", "GET", "https://app.example.com/x"), broken},
		DetectedFlowRunOptions{})

	step := dfrStep(t, plan, "gone")
	if step.SkipReason != detectedFlowSkipNoBytes || step.WillSend {
		t.Fatalf("a capture with no bytes must be skipped, got %q/%v", step.SkipReason, step.WillSend)
	}
}

// websocket is significant in the diagram because a 101 upgrade is a security surface worth SEEING.
// It is not something an HTTP/1.1 sender can replay, and pretending otherwise produces a 400 the
// operator then has to explain to themselves.
func TestDetectedFlowRunSkipsWebSocketNodes(t *testing.T) {
	ws := dfrNode("ws", "GET", "wss://app.example.com/socket", "websocket")
	ws.Significant = true

	plan := dfrPlan([]detectedFlowNode{dfrRoot("root", "GET", "https://app.example.com/x"), ws},
		DetectedFlowRunOptions{IncludeAll: true})

	step := dfrStep(t, plan, "ws")
	if step.SkipReason != detectedFlowSkipNotReplayable {
		t.Fatalf("a websocket upgrade cannot be replayed as an HTTP request, got %q", step.SkipReason)
	}
	if !strings.Contains(step.SkipDetail, "WebSocket") {
		t.Errorf("the reason must name what it is, got %q", step.SkipDetail)
	}
}

// ---------------------------------------------------------------------------
// State-changing steps
// ---------------------------------------------------------------------------

// The whole flow runs by default, POST and DELETE included. Replaying a captured flow while
// silently omitting its POST produces a run that did not test the flow.
func TestDetectedFlowRunSendsStateChangingStepsByDefault(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/new"),
		dfrWithBody(dfrNode("post", "POST", "https://app.example.com/api/claims", "xhr"), `{"phone":"+15551234567"}`),
		dfrWithBody(dfrNode("del", "DELETE", "https://app.example.com/api/claims/1", "xhr"), ""),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	for _, id := range []string{"post", "del"} {
		step := dfrStep(t, plan, id)
		if !step.WillSend {
			t.Fatalf("%s must be sent by default, got skip %q: %s", id, step.SkipReason, step.SkipDetail)
		}
		// Still REPORTED, so the operator can see what the run contains before pressing it.
		if !step.StateChanging {
			t.Errorf("%s must still be flagged state_changing so the plan shows what it will do", id)
		}
	}
	if plan.RequestCount != 3 {
		t.Fatalf("all three steps should be sent, got %d", plan.RequestCount)
	}
	if plan.SkipStateChanging {
		t.Error("skip_state_changing must default to false")
	}
}

// The option still works when the operator wants to narrow a run to its reads.
func TestDetectedFlowRunSkipStateChangingIsOptIn(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/new"),
		dfrWithBody(dfrNode("post", "POST", "https://app.example.com/api/claims", "xhr"), `{"a":1}`),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{SkipStateChanging: true})

	step := dfrStep(t, plan, "post")
	if step.WillSend {
		t.Fatal("skip_state_changing must skip the POST")
	}
	if step.SkipReason != detectedFlowSkipStateChanging {
		t.Errorf("skip reason %q, want %q", step.SkipReason, detectedFlowSkipStateChanging)
	}
	if !dfrStep(t, plan, "root").WillSend {
		t.Error("the GET must still be sent")
	}
}

// A flow emptied by skip_state_changing must blame skip_state_changing. Sending an operator to
// re-read their exclusion list for something their own option did is how a correct message becomes
// a wrong one.
func TestDetectedFlowRunEmptyPlanExplainsItself(t *testing.T) {
	root := dfrWithBody(dfrNode("root", "POST", "https://app.example.com/submit", "document"), "x=1")
	root.IsRoot = true
	root.Significant = true

	plan := dfrPlan([]detectedFlowNode{root}, DetectedFlowRunOptions{SkipStateChanging: true})

	if plan.RequestCount != 0 {
		t.Fatalf("nothing should be sendable here, got %d", plan.RequestCount)
	}
	if !strings.Contains(plan.Warning, "skip_state_changing") {
		t.Errorf("the warning must name the rule that emptied the plan, got %q", plan.Warning)
	}
}

// ---------------------------------------------------------------------------
// Scope, the deny list and the exclusion rules
// ---------------------------------------------------------------------------

func TestDetectedFlowRunRefusesOutOfScope(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("cdn", "GET", "https://cdn.thirdparty.net/api/track", "xhr"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	step := dfrStep(t, plan, "cdn")
	if step.WillSend || step.SkipReason != detectedFlowSkipOutOfScope {
		t.Fatalf("an out-of-scope host must never be sent to, got %v/%q", step.WillSend, step.SkipReason)
	}
	if !strings.Contains(step.SkipDetail, "cdn.thirdparty.net") {
		t.Errorf("the refusal must name the host, got %q", step.SkipDetail)
	}
	for _, h := range plan.Hosts {
		if h == "cdn.thirdparty.net" {
			t.Error("the hosts list is read as 'these machines are about to be contacted', so a " +
				"refused host must not appear in it")
		}
	}
}

// A host marked in_scope=false that ALSO sits inside the target's registrable domain is still
// admitted by ScanScope.Allows. The deny list is therefore checked first and unconditionally, which
// is the same order active detection uses and the reason both checks exist.
func TestDetectedFlowRunDeniedHostBeatsScope(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("an", "GET", "https://analytics.example.com/api/e", "xhr"),
	}

	plan := planDetectedFlowRun(detectedFlowPlanInput{
		FlowID: "f", Nodes: nodes, Options: DetectedFlowRunOptions{},
		Scope:      dfrScope("example.com"),
		Denied:     map[string]bool{"analytics.example.com": true},
		Engagement: dfrEngagement(),
	})

	step := dfrStep(t, plan, "an")
	if step.SkipReason != detectedFlowSkipHostExcluded {
		t.Fatalf("a host the operator marked out of scope must be refused BEFORE the boundary is "+
			"consulted, because the boundary would admit it; got %q", step.SkipReason)
	}
	if len(plan.DeniedHosts) != 1 || plan.DeniedHosts[0] != "analytics.example.com" {
		t.Errorf("the plan must show the deny list it is running under, got %v", plan.DeniedHosts)
	}
}

// The exclusion list is where "do not touch this, it texts customers" lives. A sender that does not
// read it walks straight through the one rail that exists for that.
func TestDetectedFlowRunHonoursExclusionRules(t *testing.T) {
	rules := []FlowExclusion{{
		ID: "e1", Pattern: "app.example.com/api/otp*", Reason: "dispatches a one-time code to a real customer",
	}}
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("otp", "GET", "https://app.example.com/api/otp/resend", "xhr"),
	}

	plan := planDetectedFlowRun(detectedFlowPlanInput{
		FlowID: "f", Nodes: nodes, Options: DetectedFlowRunOptions{},
		Scope: dfrScope("example.com"), Denied: map[string]bool{},
		Exclusions: rules, Engagement: dfrEngagement(),
	})

	step := dfrStep(t, plan, "otp")
	if step.WillSend || step.SkipReason != detectedFlowSkipExclusion {
		t.Fatalf("an excluded URL must never be sent, got %v/%q", step.WillSend, step.SkipReason)
	}
	if step.SkipPattern != rules[0].Pattern || !strings.Contains(step.SkipDetail, "one-time code") {
		t.Errorf("the rule AND its reason must travel with the refusal, got %q / %q",
			step.SkipPattern, step.SkipDetail)
	}
	if len(plan.ExclusionPatterns) != 1 {
		t.Errorf("the plan must list the rules in force, not only the ones that fired, got %v",
			plan.ExclusionPatterns)
	}
}

// Whatever refused a step, the step must carry a sentence. "12 skipped" is not something an operator
// can act on, and a step with no verdict is one they have to guess about.
func TestDetectedFlowRunEverySkippedStepSaysWhy(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
		dfrNode("cdn", "GET", "https://cdn.thirdparty.net/x", "xhr"),
		dfrWithBody(dfrNode("post", "POST", "https://app.example.com/api", "xhr"), "a=1"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	for _, step := range plan.Steps {
		if step.WillSend {
			continue
		}
		if step.SkipReason == "" || strings.TrimSpace(step.SkipDetail) == "" {
			t.Errorf("step %d (%s) was skipped with reason %q and detail %q; every skip needs both",
				step.Order, step.CaptureID, step.SkipReason, step.SkipDetail)
		}
	}
}

// A burst-rooted flow is up to 2,700 nodes of which the default filter hides 85%. The dry run must
// not serialise the whole request for every one of them, and the poll of a live run must not do it
// once a second. The size survives so the operator can tell there were bytes.
func TestDetectedFlowRunSkippedStepsDoNotCarryTheirBytes(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	skipped := dfrStep(t, plan, "css")
	if skipped.RawRequest != "" {
		t.Errorf("a step that will not be sent must not carry its bytes, got %d of them",
			len(skipped.RawRequest))
	}
	if skipped.RawBytes == 0 {
		t.Error("the size must survive, or the operator cannot tell an empty capture from a dropped one")
	}
	if sent := dfrStep(t, plan, "root"); sent.RawRequest == "" {
		t.Error("a step that WILL be sent must carry the exact bytes that go out; the runner sends them")
	}
}

func TestDetectedFlowRunHostsListOnlyWhatWillBeContacted(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("api", "GET", "https://api.example.com/v1/me", "xhr"),
		dfrNode("cdn", "GET", "https://cdn.thirdparty.net/x", "xhr"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	if len(plan.Hosts) != 2 || plan.Hosts[0] != "api.example.com" || plan.Hosts[1] != "app.example.com" {
		t.Fatalf("hosts must be the ones about to receive traffic, sorted, got %v", plan.Hosts)
	}
}

// ---------------------------------------------------------------------------
// Overrides: the operator's edited bytes
// ---------------------------------------------------------------------------

// The modal already lets any request be edited. An edit the operator made and the runner ignored is
// worse than no edit box, so this is the test that matters most in the file.
func TestDetectedFlowRunOverrideIsWhatGetsSent(t *testing.T) {
	edited := "GET /api/tickets?id=999 HTTP/1.1\r\nHost: app.example.com\r\nX-Edited: yes\r\n\r\n"
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("xhr", "GET", "https://app.example.com/api/tickets", "xhr"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{Overrides: map[string]string{"xhr": edited}})

	step := dfrStep(t, plan, "xhr")
	if step.RawRequest != edited {
		t.Fatalf("the edited bytes must be the bytes that go out, byte for byte.\n got: %q\nwant: %q",
			step.RawRequest, edited)
	}
	if !step.Overridden {
		t.Error("an overridden step must say so, or the operator cannot tell what they are looking at")
	}
	if step.URL != "https://app.example.com/api/tickets?id=999" {
		t.Errorf("the URL shown must be the one the edited bytes would request, got %q", step.URL)
	}
	if len(plan.UnusedOverrides) != 0 {
		t.Errorf("an override that was used is not unused, got %v", plan.UnusedOverrides)
	}
}

// Editing a request is the operator naming it, exactly as an explicit capture_ids selection wins over
// the noise filter when seeding the builder. Dropping an edited stylesheet because stylesheets are
// noise would ignore the one thing they did by hand.
func TestDetectedFlowRunOverrideForcesAHiddenNodeIn(t *testing.T) {
	edited := "GET /a.css HTTP/1.1\r\nHost: app.example.com\r\nRange: bytes=0-1\r\n\r\n"
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{Overrides: map[string]string{"css": edited}})

	step := dfrStep(t, plan, "css")
	if !step.WillSend {
		t.Fatalf("an edited request must be sent even though its resource type is hidden by default, "+
			"got skip %q", step.SkipReason)
	}
}

// Every judgement is made on the BYTES, never on the capture row. A GET edited into a POST is sent
// as a POST, and a Host header edited to another server must meet the boundary.
func TestDetectedFlowRunOverrideIsJudgedNotTheCapture(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}

	overrides := map[string]string{
		"a": "POST /api/a HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 3\r\n\r\nx=1",
		"b": "GET /api/b HTTP/1.1\r\nHost: evil.thirdparty.net\r\n\r\n",
	}
	plan := dfrPlan(nodes, DetectedFlowRunOptions{Overrides: overrides})

	// The verb comes from the edited bytes, and the edit is honoured: the operator typed a POST.
	a := dfrStep(t, plan, "a")
	if a.Method != "POST" {
		t.Errorf("the method judged must be the one the edited bytes name, got %q", a.Method)
	}
	if !a.StateChanging {
		t.Error("an edited POST must still be REPORTED as state changing so the plan shows it")
	}
	if !a.WillSend {
		t.Errorf("an edited POST is what the operator typed and must be sent, got skip %q", a.SkipReason)
	}

	// And skip_state_changing is still judged on the bytes rather than the capture's original GET.
	narrowed := dfrPlan(nodes, DetectedFlowRunOptions{
		Overrides: overrides, SkipStateChanging: true,
	})
	if s := dfrStep(t, narrowed, "a"); s.WillSend || s.SkipReason != detectedFlowSkipStateChanging {
		t.Errorf("skip_state_changing must judge the edited POST, got %v/%q", s.WillSend, s.SkipReason)
	}

	b := dfrStep(t, plan, "b")
	if b.Host != "evil.thirdparty.net" {
		t.Errorf("the host judged must be the one the edited bytes name, got %q", b.Host)
	}
	if b.WillSend || b.SkipReason != detectedFlowSkipOutOfScope {
		t.Fatalf("an edit that points a request at another server must be refused by scope, got %v/%q",
			b.WillSend, b.SkipReason)
	}
}

func TestDetectedFlowRunReportsUnusedOverrides(t *testing.T) {
	nodes := []detectedFlowNode{dfrRoot("root", "GET", "https://app.example.com/x")}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{Overrides: map[string]string{
		"not-in-this-flow": "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
	}})

	if len(plan.UnusedOverrides) != 1 || plan.UnusedOverrides[0] != "not-in-this-flow" {
		t.Fatalf("an override for a capture this flow does not contain must be reported rather than "+
			"silently dropped, got %v", plan.UnusedOverrides)
	}
}

// ---------------------------------------------------------------------------
// The caps
// ---------------------------------------------------------------------------

func TestDetectedFlowRunBudgetTakesTheLowest(t *testing.T) {
	cases := []struct {
		requested, engagement, want int
		source                      string
	}{
		{0, 0, detectedFlowDefaultStepBudget, "default"},
		{0, 250, detectedFlowDefaultStepBudget, "default"},
		{10, 250, 10, "requested"},
		{0, 20, 20, "engagement"},
		{100, 30, 30, "engagement"},
		{100, 0, 100, "requested"},
	}
	for _, c := range cases {
		got, source := resolveDetectedFlowBudget(c.requested, c.engagement)
		if got != c.want || source != c.source {
			t.Errorf("resolveDetectedFlowBudget(%d, %d) = %d/%q, want %d/%q",
				c.requested, c.engagement, got, source, c.want, c.source)
		}
	}
}

// The ceiling is not configurable off. A caller that asks for five thousand gets three hundred.
func TestDetectedFlowRunBudgetCannotBeRaisedPastTheCeiling(t *testing.T) {
	got, source := resolveDetectedFlowBudget(5000, 0)
	if got != detectedFlowMaxStepBudget || source != "ceiling" {
		t.Fatalf("the hard ceiling must win over anything the caller asks for, got %d/%q", got, source)
	}
}

// The plan says up front which steps the budget will cut, so the operator learns it before pressing
// run rather than from a run that stopped two thirds of the way through.
func TestDetectedFlowRunPlanMarksOverBudgetSteps(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{MaxSteps: 2})

	if plan.RequestCount != 2 {
		t.Fatalf("a budget of 2 must plan 2 requests, got %d", plan.RequestCount)
	}
	step := dfrStep(t, plan, "b")
	if step.SkipReason != detectedFlowSkipOverBudget {
		t.Fatalf("the third step must be marked over budget, got %q", step.SkipReason)
	}
	if !strings.Contains(step.SkipDetail, "MAX EXECUTED STEPS") {
		t.Errorf("the reason must name the cap in words, got %q", step.SkipDetail)
	}
}

// Every stop code must produce a sentence that names the cap. A run that ends with no reason is how
// an operator concludes the target is broken when it was their own budget.
func TestDetectedFlowRunEveryStopCodeHasASentence(t *testing.T) {
	for _, code := range []string{
		detectedFlowStopStepBudget, detectedFlowStopPerStepCap, detectedFlowStopEngagement,
		detectedFlowStopOnError, detectedFlowStopCancelled,
	} {
		sentence := detectedFlowStopSentence(code, 50)
		if strings.TrimSpace(sentence) == "" {
			t.Errorf("stop code %q has no sentence; 'flow ended' with no reason is the failure this "+
				"whole mechanism exists to avoid", code)
		}
		if !strings.HasPrefix(sentence, "Stopped:") {
			t.Errorf("stop code %q must say it stopped, got %q", code, sentence)
		}
	}
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

func TestDetectedFlowRunSendsInCapturedOrder(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))

	sent := []string{}
	runDetectedFlowSteps(context.Background(), run, nil, dfrRecordingSender(&sent), dfrNoPace, nil)

	if !dfrSameIDs(sent, []string{"root", "a", "b"}) {
		t.Fatalf("a detected flow runs in captured order, got %v", sent)
	}
	if run.Status != detectedFlowRunCompleted || run.Executed != 3 || run.Failed != 0 {
		t.Errorf("a clean run must complete, got %s %d/%d", run.Status, run.Executed, run.Failed)
	}
	if run.StoppedBy != "" {
		t.Errorf("a run that finished its plan was not stopped, got %q", run.StoppedBy)
	}
	if run.FinishedAt == nil {
		t.Error("a finished run must be marked finished, or it is polled forever")
	}
}

// A skipped step costs the target nothing, so it must not consume the budget either.
func TestDetectedFlowRunSkippedStepsAreNotExecuted(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("css", "GET", "https://app.example.com/a.css", "stylesheet"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
	}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))

	sent := []string{}
	runDetectedFlowSteps(context.Background(), run, nil, dfrRecordingSender(&sent), dfrNoPace, nil)

	if !dfrSameIDs(sent, []string{"root", "a"}) {
		t.Fatalf("a skipped step must not be sent, got %v", sent)
	}
	if run.Executed != 2 {
		t.Errorf("executions count requests actually sent, got %d", run.Executed)
	}
	for _, s := range run.Steps {
		if s.CaptureID == "css" && s.Executed {
			t.Error("a skipped step must never be marked executed")
		}
	}
}

// The budget counts EXECUTIONS. A run that hits it stops and names it.
func TestDetectedFlowRunStopsAtTheStepBudgetAndNamesIt(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}
	plan := dfrPlan(nodes, DetectedFlowRunOptions{})
	// Force the loop to be the thing that stops it, not the planner: every step is armed and the
	// budget is lowered underneath. This is the check that still holds if the loop ever gains a
	// backwards edge and the plan's count stops predicting the executions.
	plan.StepBudget = 2
	run := dfrReport(plan)

	sent := []string{}
	runDetectedFlowSteps(context.Background(), run, nil, dfrRecordingSender(&sent), dfrNoPace, nil)

	if len(sent) != 2 {
		t.Fatalf("the budget must stop the run at 2 executions, got %v", sent)
	}
	if run.StoppedBy != detectedFlowStopStepBudget {
		t.Fatalf("the run must say which cap stopped it, got %q", run.StoppedBy)
	}
	if !strings.Contains(run.StoppedDetail, "MAX EXECUTED STEPS") {
		t.Errorf("the detail must name the cap in words, got %q", run.StoppedDetail)
	}
	if run.Status != detectedFlowRunStopped {
		t.Errorf("a capped run is stopped, not completed, got %q", run.Status)
	}
	// The steps that never ran must say so rather than looking like they returned nothing.
	last := run.Steps[len(run.Steps)-1]
	if last.SkipReason != detectedFlowSkipNotReachedStop || last.SkipDetail == "" {
		t.Errorf("a step the run never reached must say why, got %q/%q", last.SkipReason, last.SkipDetail)
	}
}

// When the programme's own budget is the lower one, the run must blame the programme and not the
// framework: those call for different actions from the operator.
func TestDetectedFlowRunNamesTheEngagementBudgetWhenThatIsTheCap(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
	}
	engagement := dfrEngagement()
	engagement.MaxRequestsPerRun = 1

	plan := planDetectedFlowRun(detectedFlowPlanInput{
		FlowID: "f", Nodes: nodes, Options: DetectedFlowRunOptions{},
		Scope: dfrScope("example.com"), Denied: map[string]bool{}, Engagement: engagement,
	})
	if plan.BudgetSource != "engagement" || plan.StepBudget != 1 {
		t.Fatalf("the programme's cap must win when it is lower, got %d/%q", plan.StepBudget, plan.BudgetSource)
	}

	run := dfrReport(plan)
	// Arm the second step so the loop, not the plan, is what refuses it.
	run.Steps[1].WillSend = true
	run.Steps[1].SkipReason = ""

	sent := []string{}
	runDetectedFlowSteps(context.Background(), run, nil, dfrRecordingSender(&sent), dfrNoPace, nil)

	if run.StoppedBy != detectedFlowStopEngagement {
		t.Fatalf("the run must name the engagement budget, got %q", run.StoppedBy)
	}
	if !strings.Contains(run.StoppedDetail, "ENGAGEMENT REQUEST BUDGET") {
		t.Errorf("the detail must name the programme's cap, got %q", run.StoppedDetail)
	}
}

// The per-step cap is the guard that survives a future backwards edge: a step must never be entered
// twice in one run, even inside a budget that still has room.
func TestDetectedFlowRunPerStepExecutionCap(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
	}
	plan := dfrPlan(nodes, DetectedFlowRunOptions{})
	run := dfrReport(plan)
	// A flow that re-enters a step: three definitions, the same node twice. The budget has room, so
	// only the per-step cap can stop this.
	run.Steps = append(run.Steps, run.Steps[1])

	sent := []string{}
	runDetectedFlowSteps(context.Background(), run, nil, dfrRecordingSender(&sent), dfrNoPace, nil)

	if len(sent) != 2 {
		t.Fatalf("one node must not execute twice in a run, got %v", sent)
	}
	if run.StoppedBy != detectedFlowStopPerStepCap {
		t.Fatalf("re-entering a step must trip the per-step cap by name, got %q", run.StoppedBy)
	}
	if run.Executed >= run.Plan.StepBudget {
		t.Error("this must be the per-step cap firing with budget left over, not the budget")
	}
}

func TestDetectedFlowRunStopOnError(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{StopOnError: true}))

	sent := []string{}
	sender := func(_ context.Context, step *DetectedFlowRunStep, _ http.CookieJar) (detectedFlowResponse, error) {
		sent = append(sent, step.CaptureID)
		if step.CaptureID == "a" {
			return detectedFlowResponse{DurationMs: 5}, errors.New("connection refused")
		}
		return detectedFlowResponse{Status: 200}, nil
	}

	runDetectedFlowSteps(context.Background(), run, nil, sender, dfrNoPace, nil)

	if !dfrSameIDs(sent, []string{"root", "a"}) {
		t.Fatalf("stop_on_error must stop after the step that failed, got %v", sent)
	}
	if run.StoppedBy != detectedFlowStopOnError || run.Failed != 1 {
		t.Errorf("the run must say why it stopped and count the failure, got %q/%d", run.StoppedBy, run.Failed)
	}
	// The failed step keeps its own result; only the ones after it are not-reached.
	if run.Steps[1].Error == "" || !run.Steps[1].Executed {
		t.Error("the step that failed must keep its error and stay marked executed")
	}
	if run.Steps[2].SkipReason != detectedFlowSkipNotReachedStop {
		t.Errorf("the step after the failure must say it was never sent, got %q", run.Steps[2].SkipReason)
	}
}

// The default. A flow where step two 500s is a flow whose step three answer is exactly what is worth
// seeing, so an error must not end the run unless the operator asked for that.
func TestDetectedFlowRunContinuesPastAnErrorByDefault(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))

	sent := []string{}
	sender := func(_ context.Context, step *DetectedFlowRunStep, _ http.CookieJar) (detectedFlowResponse, error) {
		sent = append(sent, step.CaptureID)
		if step.CaptureID == "a" {
			return detectedFlowResponse{}, errors.New("timeout")
		}
		return detectedFlowResponse{Status: 200}, nil
	}

	runDetectedFlowSteps(context.Background(), run, nil, sender, dfrNoPace, nil)

	if len(sent) != 3 || run.Status != detectedFlowRunCompleted {
		t.Fatalf("an error must not end the run by default, got %v / %s", sent, run.Status)
	}
	if run.Failed != 1 {
		t.Errorf("the failure must still be counted, got %d", run.Failed)
	}
}

// A cancelled run KEEPS what it already sent. The operator who pressed cancel usually did so having
// seen something worth looking at.
func TestDetectedFlowRunCancelKeepsWhatItSent(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"),
		dfrNode("b", "GET", "https://app.example.com/api/b", "xhr"),
	}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))

	ctx, cancel := context.WithCancel(context.Background())
	sent := []string{}
	sender := func(_ context.Context, step *DetectedFlowRunStep, _ http.CookieJar) (detectedFlowResponse, error) {
		sent = append(sent, step.CaptureID)
		cancel() // the operator pressed cancel while step one was in flight
		return detectedFlowResponse{Status: 200, Body: "kept"}, nil
	}

	runDetectedFlowSteps(ctx, run, nil, sender, dfrNoPace, nil)

	if len(sent) != 1 {
		t.Fatalf("a cancelled run must stop sending, got %v", sent)
	}
	if run.Status != detectedFlowRunCancelled || run.StoppedBy != detectedFlowStopCancelled {
		t.Fatalf("a cancelled run must say so, got %s/%q", run.Status, run.StoppedBy)
	}
	if run.Steps[0].ResponseBody != "kept" || !run.Steps[0].Executed {
		t.Error("cancelling must not discard the responses already collected")
	}
}

// ---------------------------------------------------------------------------
// The engagement config
// ---------------------------------------------------------------------------

func dfrRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("fixture is not a readable request: %v", err)
	}
	return req
}

// With nothing configured anywhere, EffectiveUserAgent is the framework's own string. Setting it
// would send every replay with a User-Agent the recording never had, and plenty of applications serve
// different content - or a WAF block - to a non-browser UA. The operator would be debugging a
// difference the runner introduced.
func TestDetectedFlowRunKeepsTheRecordedUserAgentWhenNoneIsConfigured(t *testing.T) {
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: "+dfrRecordedUA+"\r\n\r\n")

	notes := applyEngagementToRequest(req, dfrEngagement())

	if got := req.Header.Get("User-Agent"); got != dfrRecordedUA {
		t.Fatalf("a replay must keep the User-Agent it was recorded with when nobody configured one, got %q", got)
	}
	for _, n := range notes {
		if strings.Contains(n, "User-Agent") {
			t.Errorf("nothing was changed, so nothing should be reported, got %q", n)
		}
	}
}

// When the programme demands a User-Agent it wins, because that is the brief.
func TestDetectedFlowRunReplacesTheUserAgentWhenTheProgrammeSetsOne(t *testing.T) {
	ua := "dailypay-research/1.0 (rs0n2)"
	engagement := ResolveEngagementFrom(&EngagementOverrides{CustomUserAgent: &ua}, EngagementGlobals{})
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: "+dfrRecordedUA+"\r\n\r\n")

	notes := applyEngagementToRequest(req, engagement)

	if got := req.Header.Get("User-Agent"); got != ua {
		t.Fatalf("a configured User-Agent must reach the wire, got %q", got)
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), ua) {
		t.Errorf("replacing the User-Agent must be reported, got %v", notes)
	}
}

// APPEND means the configured value is a TAG. For a replay the honest base is the User-Agent the
// request was recorded with, not the global one the resolver picked, because re-sending what was
// recorded is the entire point of this runner.
func TestDetectedFlowRunAppendsTheTagToTheRecordedUserAgent(t *testing.T) {
	tag := "<H1-rs0n2>"
	mode := "append"
	engagement := ResolveEngagementFrom(
		&EngagementOverrides{CustomUserAgent: &tag, UserAgentMode: &mode}, EngagementGlobals{})
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: "+dfrRecordedUA+"\r\n\r\n")

	applyEngagementToRequest(req, engagement)

	want := dfrRecordedUA + " " + tag
	if got := req.Header.Get("User-Agent"); got != want {
		t.Fatalf("append must glue the tag onto the RECORDED User-Agent, got %q want %q", got, want)
	}
}

func TestDetectedFlowRunSendsTheProgrammeHeader(t *testing.T) {
	name, value := "X-HackerOne-DailyPay-Research", "rs0n2"
	engagement := ResolveEngagementFrom(
		&EngagementOverrides{CustomHeaderName: &name, CustomHeaderValue: &value}, EngagementGlobals{})
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\n\r\n")

	applyEngagementToRequest(req, engagement)

	if got := req.Header.Get(name); got != value {
		t.Fatalf("the programme's mandatory header must be on every request, got %q", got)
	}
}

// Set, not Add. Two copies of the identifying header is not what the brief asked for, and the
// engagement config is the one that is current.
func TestDetectedFlowRunProgrammeHeaderWinsOverARecordedOne(t *testing.T) {
	name, value := "X-Research", "current"
	engagement := ResolveEngagementFrom(
		&EngagementOverrides{CustomHeaderName: &name, CustomHeaderValue: &value}, EngagementGlobals{})
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\nX-Research: stale\r\n\r\n")

	applyEngagementToRequest(req, engagement)

	if got := req.Header.Values(name); len(got) != 1 || got[0] != value {
		t.Fatalf("the engagement header must replace a recorded one of the same name, got %v", got)
	}
}

// HeaderMap refuses the credential-bearing names even when the stored row carries one, and this
// sender applies its output with Set. A Cookie smuggled through the engagement config would overwrite
// the operator's real session with somebody's typo.
func TestDetectedFlowRunNeverTakesACredentialFromTheEngagementConfig(t *testing.T) {
	name, value := "Cookie", "session=attacker"
	engagement := ResolveEngagementFrom(
		&EngagementOverrides{CustomHeaderName: &name, CustomHeaderValue: &value}, EngagementGlobals{})
	req := dfrRequest(t, "GET /x HTTP/1.1\r\nHost: app.example.com\r\nCookie: real=1\r\n\r\n")

	applyEngagementToRequest(req, engagement)

	if got := req.Header.Get("Cookie"); got != "real=1" {
		t.Fatalf("an engagement config must never be able to set a credential header, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Credentials, reported rather than stripped
// ---------------------------------------------------------------------------

func TestDetectedFlowRunCredentialCountIsReported(t *testing.T) {
	nodes := []detectedFlowNode{
		dfrRoot("root", "GET", "https://app.example.com/x"),
		dfrWithCookie(dfrNode("a", "GET", "https://app.example.com/api/a", "xhr"), "session=abc"),
	}

	plan := dfrPlan(nodes, DetectedFlowRunOptions{})

	if plan.CredentialCount != 1 {
		t.Fatalf("the plan must say how many requests carry the recorded session, got %d", plan.CredentialCount)
	}
	if !dfrStep(t, plan, "a").CarriesCredentials {
		t.Error("the step carrying the cookie must be the one flagged")
	}
	joined := strings.Join(plan.Notes, " ")
	if !strings.Contains(joined, "Cookie") {
		t.Errorf("the operator must be told the run acts as their session, got %v", plan.Notes)
	}
	// And the bytes are untouched: stripping the session would make every step redirect to a login
	// page and complete without proving anything.
	if !strings.Contains(dfrStep(t, plan, "a").RawRequest, "session=abc") {
		t.Error("the recorded session must be sent as captured, not stripped")
	}
}

func TestDetectedFlowRunCredentialDetectionIgnoresAnEmptyHeader(t *testing.T) {
	if detectedFlowCarriesCredentials("GET / HTTP/1.1\r\nHost: a\r\nCookie: \r\n\r\n") {
		t.Error("a Cookie header with no value carries nothing")
	}
	if !detectedFlowCarriesCredentials("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer x\r\n\r\n") {
		t.Error("a bearer token is a credential")
	}
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

// A flow captured against http://localhost:8080 must not be silently upgraded to https, which is what
// resolveBaseURL does for a host it has no recorded origin for.
func TestDetectedFlowRunTargetKeepsTheRecordedSchemeAndPort(t *testing.T) {
	raw := "GET /api/x?a=1 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"

	absolute, host := detectedFlowStepTarget(raw, "http://localhost:8080/api/x")

	if absolute != "http://localhost:8080/api/x?a=1" {
		t.Fatalf("the recorded scheme and port must survive, got %q", absolute)
	}
	if host != "localhost" {
		t.Errorf("the host is compared against the boundary without its port, got %q", host)
	}
}

func TestDetectedFlowRunTargetFollowsAnEditedHostHeader(t *testing.T) {
	raw := "GET /api/x HTTP/1.1\r\nHost: other.example.com\r\n\r\n"

	absolute, host := detectedFlowStepTarget(raw, "https://app.example.com/api/x")

	if host != "other.example.com" {
		t.Fatalf("the host judged must be the one the bytes name, got %q", host)
	}
	if !strings.HasPrefix(absolute, "https://other.example.com/") {
		t.Errorf("the URL must follow the edited Host header, got %q", absolute)
	}
}

func TestDetectedFlowRunTargetHasNoHostToGuessAt(t *testing.T) {
	absolute, host := detectedFlowStepTarget("GET /api/x HTTP/1.1\r\n\r\n", "")

	if absolute != "" || host != "" {
		t.Fatalf("a request with no Host and no recorded origin must resolve to nothing rather than "+
			"a guess, got %q/%q", absolute, host)
	}
}

// ---------------------------------------------------------------------------
// The rails, asserted against the source
//
// These three are behaviour a unit test cannot reach without a database and a live target, and each
// one is the difference between a run that is safe and a run that looks safe.
// ---------------------------------------------------------------------------

func dfrSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("detectedFlowRun.go")
	if err != nil {
		t.Fatalf("could not read the runner: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	return code.String()
}

// An omitted dry_run is a DRY RUN. dry_run is a pointer for exactly this reason: with a plain bool a
// client that forgets the field is indistinguishable from one that asked to send, and the difference
// is whether traffic reaches somebody's production.
func TestDetectedFlowRunDryRunIsTheDefault(t *testing.T) {
	var opts DetectedFlowRunOptions
	if err := json.Unmarshal([]byte(`{"stop_on_error":true}`), &opts); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if opts.DryRun != nil {
		t.Fatal("dry_run must be a pointer so that omitted and false are different things")
	}

	body := dfrSource(t)
	start := strings.Index(body, "func RunDetectedFlow(")
	if start < 0 {
		t.Fatal("RunDetectedFlow not found")
	}
	handler := body[start:]
	if !strings.Contains(handler, "dryRun := true") {
		t.Error("the handler must default dry_run to TRUE. A caller that forgets the field gets a " +
			"plan, never traffic")
	}
	assignAt := strings.Index(handler, "dryRun := true")
	overrideAt := strings.Index(handler, "dryRun = *opts.DryRun")
	if overrideAt < 0 || overrideAt < assignAt {
		t.Error("the default must be set first and only then overridden by an explicit dry_run")
	}
}

// FAIL CLOSED. A run that could not read the programme's rules must not start. Sending traffic to
// DailyPay without the header their brief calls mandatory, because a query failed, is how a research
// run gets read by a SOC as an attack.
func TestDetectedFlowRunResolvesEngagementConfigAndFailsClosed(t *testing.T) {
	body := dfrSource(t)

	if !strings.Contains(body, "ResolveEngagementConfig(scopeTargetID)") {
		t.Error("the run must resolve the engagement config rather than assuming defaults")
	}
	if !strings.Contains(body, "engagement.HeaderMap()") {
		t.Error("the run must send the programme's header")
	}
	if !strings.Contains(body, "engagement.EffectiveUserAgent") {
		t.Error("the run must be able to send the programme's User-Agent")
	}
	if !strings.Contains(body, "ExcludedScopeHosts(scopeTargetID)") {
		t.Error("the run must read the deny list; a host the operator ticked off must never be sent to")
	}
	if !strings.Contains(body, "LoadFlowExclusions(scopeTargetID)") {
		t.Error("the run must read the exclusion list, which is where 'this endpoint texts a " +
			"customer' is recorded")
	}
	if !strings.Contains(body, "engagement_unreadable") ||
		!strings.Contains(body, "scope_unreadable") ||
		!strings.Contains(body, "exclusions_unreadable") {
		t.Error("each of the three reads must have its own refusal: an unreadable rule set must stop " +
			"the run rather than degrading into an empty one")
	}
	if !strings.Contains(body, "engagement.RequestTimeoutS") {
		t.Error("the timeout must come from the engagement config, not a hardcoded 30 seconds")
	}
	if !strings.Contains(body, "detectedFlowPaceInterval(engagement.MaxRPS)") {
		t.Error("the rate limit must come from the engagement config and apply to every request")
	}
}

// Redirects must not be followed. A detected flow already contains the destination of every redirect
// as its own node, so following one sends that destination twice.
func TestDetectedFlowRunDoesNotFollowRedirects(t *testing.T) {
	body := dfrSource(t)
	if !strings.Contains(body, "http.ErrUseLastResponse") {
		t.Error("the sender must capture 3xx rather than following it")
	}
}

// This runner does not retry, and a retry that arrives here without a cap is the thing that turns a
// failing step into a loop against a live target. The constant is zero and the loop must contain no
// retry machinery; adding one means adding a cap and a delay in the same edit.
func TestDetectedFlowRunHasNoUnboundedRetry(t *testing.T) {
	if detectedFlowMaxRetries != 0 {
		t.Fatalf("this runner declares %d retries but implements none; a retry needs a cap AND a "+
			"delay between attempts before it exists at all", detectedFlowMaxRetries)
	}
	if detectedFlowPerStepExecutions != 1 {
		t.Errorf("a linear runner enters each step exactly once; %d would mean a step can repeat "+
			"without a condition to bound it", detectedFlowPerStepExecutions)
	}

	body := dfrSource(t)
	start := strings.Index(body, "func runDetectedFlowSteps(")
	if start < 0 {
		t.Fatal("runDetectedFlowSteps not found")
	}
	loop := body[start:]
	if end := strings.Index(loop[1:], "\nfunc "); end > 0 {
		loop = loop[:end]
	}
	// One `for` in the whole runner: the pass over the steps. A second one is either a retry or a
	// backwards edge, and both need a cap that this test would then be the wrong shape for.
	if n := strings.Count(loop, "for "); n != 1 {
		t.Errorf("the runner contains %d loops; a linear runner has exactly one, and anything that "+
			"can re-enter a step must arrive with its own named cap", n)
	}
}

// ---------------------------------------------------------------------------
// Reading a run while it is running
// ---------------------------------------------------------------------------

// The runner writes the steps from its own goroutine while the progress endpoint reads them. A
// snapshot that shared the slice would serialise a step mid-write.
func TestDetectedFlowRunSnapshotDoesNotShareStepsWithTheRun(t *testing.T) {
	nodes := []detectedFlowNode{dfrRoot("root", "GET", "https://app.example.com/x")}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))
	run.RunID = "snapshot-test"

	reg := &detectedFlowRunRegistry{
		runs:   map[string]*DetectedFlowRunReport{run.RunID: run},
		cancel: map[string]context.CancelFunc{},
		active: map[string]string{},
		order:  []string{run.RunID},
	}

	snap := reg.snapshot(run.RunID, true)
	if snap == nil {
		t.Fatal("the run must be readable")
	}
	snap.Steps[0].ResponseBody = "mutated by the reader"
	if run.Steps[0].ResponseBody != "" {
		t.Fatal("a snapshot must copy the steps, not alias them")
	}
	if snap.Plan != nil && len(snap.Plan.Steps) != 0 {
		t.Error("the plan travels as a summary; the top-level steps array is the one list, so a " +
			"fifty-step flow is not serialised twice on every poll")
	}
}

// A poll every second must not carry megabytes, and the preview must never read as the whole body.
func TestDetectedFlowRunSnapshotTruncatesBodiesUnlessAsked(t *testing.T) {
	nodes := []detectedFlowNode{dfrRoot("root", "GET", "https://app.example.com/x")}
	run := dfrReport(dfrPlan(nodes, DetectedFlowRunOptions{}))
	run.RunID = "bodies-test"
	run.Steps[0].ResponseBody = strings.Repeat("a", detectedFlowBodyPreview*3)
	run.Steps[0].ResponseBytes = detectedFlowBodyPreview * 3

	reg := &detectedFlowRunRegistry{
		runs:   map[string]*DetectedFlowRunReport{run.RunID: run},
		cancel: map[string]context.CancelFunc{},
		active: map[string]string{},
		order:  []string{run.RunID},
	}

	small := reg.snapshot(run.RunID, false)
	if len(small.Steps[0].ResponseBody) != detectedFlowBodyPreview {
		t.Fatalf("a poll without bodies=1 must return a preview, got %d bytes",
			len(small.Steps[0].ResponseBody))
	}
	if !small.Steps[0].BodyTruncated {
		t.Error("a preview must be flagged as truncated, or it reads as the whole body")
	}
	if small.Steps[0].ResponseBytes != detectedFlowBodyPreview*3 {
		t.Error("the real size must survive truncation, or the operator cannot tell what they are missing")
	}

	full := reg.snapshot(run.RunID, true)
	if len(full.Steps[0].ResponseBody) != detectedFlowBodyPreview*3 {
		t.Fatalf("bodies=1 must return the whole stored body, got %d bytes",
			len(full.Steps[0].ResponseBody))
	}
}

// ---------------------------------------------------------------------------
// Pacing
// ---------------------------------------------------------------------------

func TestDetectedFlowRunPaceIntervalHonoursTheProgrammeRate(t *testing.T) {
	// Assurant: 45 requests per minute is 0.75 rps.
	if got := detectedFlowPaceInterval(0.75); got < 1300*time.Millisecond {
		t.Errorf("0.75 rps is a gap of about 1.33s, got %v", got)
	}
	if got := detectedFlowPaceInterval(0); got != time.Second {
		t.Errorf("an unset rate must fall back to one request per second, got %v", got)
	}
}
