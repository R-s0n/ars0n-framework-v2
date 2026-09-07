package utils

import (
	"testing"
	"time"
)

// The flow builder is the part of this feature worth arguing about, and it is exercised here rather
// than against the live table on purpose: every judgement it makes is a judgement about data shapes
// that took a 6,000-row corpus to discover, and a rule that can only be checked by running a crawl
// is a rule nobody will ever check again.
//
// Each test below is one of those shapes, taken from the real corpus where possible. The redirect
// tests in particular are the observed `POST /dashboard/tickets/new` -> 302 -> `GET
// /dashboard/tickets` pair, which is the case the whole view exists for.

var flowTestBase = time.Date(2026, 9, 3, 0, 50, 0, 0, time.UTC)

func flowAt(seconds float64) time.Time {
	return flowTestBase.Add(time.Duration(seconds * float64(time.Second)))
}

func flowIntPtr(v int) *int { return &v }

// cap builds a capture with the fields flow reconstruction reads. Session and tab default to one
// session and one tab, because almost every test is about ordering inside a single tab.
func flowCap(id, method, url, resourceType string, at time.Time) FlowCapture {
	return FlowCapture{
		ID:           id,
		SessionID:    "11111111-1111-1111-1111-111111111111",
		TabID:        flowIntPtr(7),
		Method:       method,
		URL:          url,
		StatusCode:   200,
		ResourceType: resourceType,
		Timestamp:    at,
		Matched:      true,
	}
}

func withInitiator(c FlowCapture, initiator string) FlowCapture {
	c.Initiator = initiator
	return c
}

func withChain(c FlowCapture, hops ...FlowRedirectHop) FlowCapture {
	c.RedirectChain = hops
	return c
}

func withStatus(c FlowCapture, status int) FlowCapture {
	c.StatusCode = status
	return c
}

func withBody(c FlowCapture) FlowCapture {
	c.HasBody = true
	return c
}

// flowRootIDs names each flow by the capture that rooted it, which is how the flow id is derived.
func flowRootIDs(flows []captureFlow) []string {
	ids := make([]string, 0, len(flows))
	for _, f := range flows {
		if len(f.Captures) == 0 {
			ids = append(ids, "(empty)")
			continue
		}
		ids = append(ids, f.Captures[0].ID)
	}
	return ids
}

func flowMemberIDs(f captureFlow) []string {
	ids := make([]string, 0, len(f.Captures))
	for _, c := range f.Captures {
		ids = append(ids, c.ID)
	}
	return ids
}

func edgeKind(t *testing.T, edges []FlowEdge, from, to string) string {
	t.Helper()
	for _, e := range edges {
		if e.From == from && e.To == to {
			return e.Kind
		}
	}
	return ""
}

func nodeByID(nodes []FlowNode, id string) *FlowNode {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------

func TestReplayRequestFlowSegmentsOnNavigation(t *testing.T) {
	captures := []FlowCapture{
		flowCap("nav-1", "GET", "https://app.test/login", "main_frame", flowAt(0)),
		withInitiator(flowCap("css-1", "GET", "https://app.test/a.css", "stylesheet", flowAt(0.2)), "parser"),
		withInitiator(flowCap("xhr-1", "GET", "https://app.test/api/me", "xhr", flowAt(0.5)), "script"),
		flowCap("nav-2", "GET", "https://app.test/dashboard", "main_frame", flowAt(9)),
		withInitiator(flowCap("xhr-2", "GET", "https://app.test/api/widgets", "xhr", flowAt(9.4)), "script"),
	}

	flows := segmentCaptureFlows(captures)
	if got := flowRootIDs(flows); len(got) != 2 || got[0] != "nav-1" || got[1] != "nav-2" {
		t.Fatalf("expected two navigation-rooted flows [nav-1 nav-2], got %v", got)
	}
	if got := flowMemberIDs(flows[0]); len(got) != 3 {
		t.Fatalf("first flow should hold the navigation and everything before the next one, got %v", got)
	}
	if got := flowMemberIDs(flows[1]); len(got) != 2 {
		t.Fatalf("second flow should hold the navigation and what followed it, got %v", got)
	}
	for _, f := range flows {
		if f.RootKind != flowRootNavigation {
			t.Fatalf("expected root_kind=%q, got %q", flowRootNavigation, f.RootKind)
		}
	}

	// A different tab is a different flow even when the requests interleave in time.
	other := flowCap("nav-3", "GET", "https://app.test/login", "main_frame", flowAt(0.1))
	other.TabID = flowIntPtr(8)
	flows = segmentCaptureFlows(append(captures, other))
	if len(flows) != 3 {
		t.Fatalf("a second tab must not merge into the first tab's flows, got %d flows", len(flows))
	}
}

func TestReplayRequestFlowRedirectEdges(t *testing.T) {
	// The shape observed in the corpus: both legs of the redirect carry the WHOLE chain.
	hop := FlowRedirectHop{
		From:       "https://app.test/tickets/new",
		Location:   "https://app.test/tickets",
		StatusCode: 302,
	}
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/tickets/new", "main_frame", flowAt(0)),
		withChain(withBody(flowCap("post", "POST", "https://app.test/tickets/new", "main_frame", flowAt(1))), hop),
		withChain(flowCap("landing", "GET", "https://app.test/tickets", "document", flowAt(3)), hop),
	}

	flows := segmentCaptureFlows(captures)
	// The POST is a main_frame and roots its own flow; the landing page is a redirect destination
	// and must NOT root a third one.
	if got := flowRootIDs(flows); len(got) != 2 || got[0] != "nav" || got[1] != "post" {
		t.Fatalf("expected flows rooted at [nav post], got %v", got)
	}
	postFlow := flows[1]
	if got := flowMemberIDs(postFlow); len(got) != 2 || got[1] != "landing" {
		t.Fatalf("the redirect destination must join the flow that redirected to it, got %v", got)
	}

	nodes, edges, hidden := renderFlowGraph(postFlow, deriveFlowLinks(postFlow), false)
	if hidden != 0 {
		t.Fatalf("nothing in this flow is a subresource, expected 0 hidden, got %d", hidden)
	}
	if kind := edgeKind(t, edges, "post", "landing"); kind != flowEdgeRedirect {
		t.Fatalf("expected a redirect edge post->landing, got %q (edges: %+v)", kind, edges)
	}
	if n := nodeByID(nodes, "landing"); n == nil || n.Depth != 1 {
		t.Fatalf("the redirect destination should sit one level below the root, got %+v", n)
	}
	if n := nodeByID(nodes, "post"); n == nil || !n.IsRoot || n.Depth != 0 {
		t.Fatalf("the POST roots this flow, got %+v", n)
	}

	summary := summarizeFlow(postFlow)
	if !summary.HasRedirects || !summary.HasBody {
		t.Fatalf("a POST that redirected should report has_redirects and has_body, got %+v", summary)
	}
	if summary.Label != "POST /tickets/new" {
		t.Fatalf("expected the label to name the navigation that rooted the flow, got %q", summary.Label)
	}
	if summary.Host != "app.test" {
		t.Fatalf("expected host app.test, got %q", summary.Host)
	}
}

// A self-redirect (from == location) is written by the recorder on 2 of the 56 chain-carrying rows
// in the live corpus. It describes no edge and must not become a self-loop.
func TestReplayRequestFlowSelfRedirectDrawsNoEdge(t *testing.T) {
	hop := FlowRedirectHop{
		From:       "https://app.test/settings#prefs",
		Location:   "https://app.test/settings#prefs",
		StatusCode: 302,
	}
	captures := []FlowCapture{
		withChain(flowCap("nav", "POST", "https://app.test/settings#prefs", "main_frame", flowAt(0)), hop),
		withInitiator(flowCap("xhr", "GET", "https://app.test/api/prefs", "xhr", flowAt(1)), "script"),
	}
	flow := segmentCaptureFlows(captures)[0]
	_, edges, _ := renderFlowGraph(flow, deriveFlowLinks(flow), false)
	for _, e := range edges {
		if e.From == e.To {
			t.Fatalf("a self-redirect produced a self-loop: %+v", e)
		}
		if e.Kind == flowEdgeRedirect {
			t.Fatalf("from == location describes no redirect, got %+v", e)
		}
	}
}

func TestReplayRequestFlowParserAttachesToNavigation(t *testing.T) {
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/login", "main_frame", flowAt(0)),
		withInitiator(flowCap("js", "GET", "https://app.test/app.js", "script", flowAt(0.1)), "parser"),
		withInitiator(flowCap("xhr", "GET", "https://app.test/api/me", "xhr", flowAt(0.6)), "script"),
		flowCap("img", "GET", "https://app.test/logo.png", "image", flowAt(0.7)),
	}
	flow := segmentCaptureFlows(captures)[0]
	links := deriveFlowLinks(flow)

	for i, id := range []string{"nav", "js", "xhr", "img"} {
		if i == 0 {
			if links[i].parent != -1 {
				t.Fatalf("the root must have no parent, got %+v", links[i])
			}
			continue
		}
		if links[i].parent != 0 {
			t.Fatalf("%s should hang off the navigation, got parent index %d", id, links[i].parent)
		}
	}
	// The recorder stores only the initiator TYPE, so parser and script both land on the navigation,
	// but an edge with no recorded initiator at all is labelled differently so the operator can see
	// which claim is which.
	if links[1].kind != flowEdgeInitiator || links[2].kind != flowEdgeInitiator {
		t.Fatalf("parser and script edges should be labelled %q, got %q and %q",
			flowEdgeInitiator, links[1].kind, links[2].kind)
	}
	if links[3].kind != flowEdgeSequence {
		t.Fatalf("a capture with no initiator should fall back to %q, got %q",
			flowEdgeSequence, links[3].kind)
	}
}

func TestReplayRequestFlowPreflightPairsWithFollower(t *testing.T) {
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/app", "main_frame", flowAt(0)),
		withInitiator(flowCap("pre", "OPTIONS", "https://api.test/v1/orders", "preflight", flowAt(1)), "preflight"),
		withInitiator(flowCap("real", "POST", "https://api.test/v1/orders", "xhr", flowAt(1.2)), "script"),
		// A second, later request to the same URL must not steal the pairing from the first.
		withInitiator(flowCap("later", "POST", "https://api.test/v1/orders", "xhr", flowAt(4)), "script"),
	}
	flow := segmentCaptureFlows(captures)[0]
	nodes, edges, _ := renderFlowGraph(flow, deriveFlowLinks(flow), false)

	if kind := edgeKind(t, edges, "pre", "real"); kind != flowEdgePreflight {
		t.Fatalf("expected a preflight edge pre->real, got %q (edges: %+v)", kind, edges)
	}
	if kind := edgeKind(t, edges, "pre", "later"); kind != "" {
		t.Fatalf("the preflight should pair with the request that followed it, not with every "+
			"later request to the same URL (edges: %+v)", edges)
	}
	if kind := edgeKind(t, edges, "nav", "later"); kind != flowEdgeInitiator {
		t.Fatalf("the unpaired later request should attach to the navigation, got %q", kind)
	}
	if n := nodeByID(nodes, "real"); n == nil || n.Depth != 2 {
		t.Fatalf("the preflighted request sits below the preflight, expected depth 2, got %+v", n)
	}
}

func TestReplayRequestFlowNoiseFilterReparents(t *testing.T) {
	// A stylesheet is hidden by default and it redirects to another stylesheet, which is the shape
	// observed on the live corpus. The destination inherits a VISIBLE ancestor rather than an edge
	// pointing at a node that is not in the payload.
	hop := FlowRedirectHop{
		From:       "https://cdn.test/a.css",
		Location:   "https://cdn.test/a.b.css",
		StatusCode: 307,
	}
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/", "main_frame", flowAt(0)),
		withInitiator(flowCap("css", "GET", "https://cdn.test/a.css", "stylesheet", flowAt(0.2)), "parser"),
		withInitiator(flowCap("font", "GET", "https://cdn.test/f.woff2", "font", flowAt(0.3)), "parser"),
		withChain(withInitiator(flowCap("cssdst", "GET", "https://cdn.test/a.b.css", "stylesheet", flowAt(0.4)), "parser"), hop),
		withInitiator(flowCap("xhr", "GET", "https://app.test/api/me", "xhr", flowAt(0.6)), "script"),
	}
	flow := segmentCaptureFlows(captures)[0]
	links := deriveFlowLinks(flow)

	// The redirect source is a plain stylesheet with no chain of its own, so it is hidden; its
	// destination carries the chain and is therefore kept.
	nodes, edges, hidden := renderFlowGraph(flow, links, false)
	if hidden != 2 {
		t.Fatalf("expected the plain stylesheet and the font to be hidden, got hidden=%d nodes=%d",
			hidden, len(nodes))
	}
	present := map[string]bool{}
	for _, n := range nodes {
		present[n.ID] = true
	}
	for _, id := range []string{"nav", "cssdst", "xhr"} {
		if !present[id] {
			t.Fatalf("%s should have survived the default filter, nodes: %v", id, present)
		}
	}
	// THE invariant: no edge may name a node that is not in the payload.
	for _, e := range edges {
		if !present[e.From] || !present[e.To] {
			t.Fatalf("dangling edge %+v references a filtered node (nodes: %v)", e, present)
		}
	}
	if kind := edgeKind(t, edges, "nav", "cssdst"); kind != flowEdgeSequence {
		t.Fatalf("a child reparented past its hidden parent must not keep claiming a redirect, got %q", kind)
	}
	if n := nodeByID(nodes, "cssdst"); n == nil || n.Depth != 1 {
		t.Fatalf("depth must be recomputed on the visible tree, got %+v", n)
	}

	// show_all restores the real relationship.
	nodes, edges, hidden = renderFlowGraph(flow, links, true)
	if hidden != 0 || len(nodes) != 5 {
		t.Fatalf("show_all should return every node, got %d nodes and hidden=%d", len(nodes), hidden)
	}
	if kind := edgeKind(t, edges, "css", "cssdst"); kind != flowEdgeRedirect {
		t.Fatalf("with nothing hidden the redirect edge should be intact, got %q (edges: %+v)", kind, edges)
	}

	// The summary's counts always describe the DEFAULT filter, so the list view and the detail view
	// agree about the same flow whatever show_all was set to.
	summary := summarizeFlow(flow)
	if summary.RequestCount != 5 || summary.ShownCount != 3 || summary.HiddenCount != 2 {
		t.Fatalf("expected 5 requests, 3 shown, 2 hidden, got %+v", summary)
	}
}

// A POST of anything survives the filter, because a POST is the request the operator came for even
// when the browser labelled it a subresource.
func TestReplayRequestFlowNoiseFilterKeepsBodiesAndRedirects(t *testing.T) {
	cases := []struct {
		name    string
		capture FlowCapture
		want    bool
	}{
		{"image with a body", withBody(flowCap("a", "POST", "https://app.test/i.png", "image", flowAt(1))), true},
		{"3xx beacon", withStatus(flowCap("b", "GET", "https://app.test/p", "beacon", flowAt(1)), 302), true},
		{"plain image", flowCap("c", "GET", "https://app.test/i.png", "image", flowAt(1)), false},
		{"stylesheet", flowCap("d", "GET", "https://app.test/a.css", "stylesheet", flowAt(1)), false},
		{"xhr", flowCap("e", "GET", "https://app.test/api", "xhr", flowAt(1)), true},
		{"websocket", flowCap("f", "WEBSOCKET", "wss://app.test/s", "websocket", flowAt(1)), true},
	}
	for _, tc := range cases {
		if got := isSignificantFlowCapture(tc.capture); got != tc.want {
			t.Errorf("%s: expected significant=%v, got %v", tc.name, tc.want, got)
		}
	}
}

// redirect_chain is written by a browser extension and is the only column here whose shape nothing
// enforces. A chain that loops must terminate and must not produce a cyclic graph, because a cycle
// makes any depth-first renderer hang and makes "depth" meaningless.
func TestReplayRequestFlowCyclicRedirectChain(t *testing.T) {
	a := "https://app.test/a"
	b := "https://app.test/b"
	c := "https://app.test/c"
	loop := []FlowRedirectHop{
		{From: a, Location: b, StatusCode: 302},
		{From: b, Location: c, StatusCode: 302},
		{From: c, Location: a, StatusCode: 302}, // closes the loop back onto the root
	}
	captures := []FlowCapture{
		withChain(flowCap("A", "GET", a, "main_frame", flowAt(0)), loop...),
		withChain(flowCap("B", "GET", b, "document", flowAt(1)), loop...),
		withChain(flowCap("C", "GET", c, "document", flowAt(2)), loop...),
	}

	done := make(chan struct{})
	var nodes []FlowNode
	var edges []FlowEdge
	go func() {
		defer close(done)
		flow := segmentCaptureFlows(captures)[0]
		nodes, edges = func() ([]FlowNode, []FlowEdge) {
			n, e, _ := renderFlowGraph(flow, deriveFlowLinks(flow), true)
			return n, e
		}()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a cyclic redirect_chain hung flow reconstruction")
	}

	if len(nodes) != 3 {
		t.Fatalf("expected all three captures as nodes, got %d", len(nodes))
	}
	// Exactly one parent per node and the root keeps none, so the result is a tree by construction.
	// Walking every node to the root proves it: a cycle would not terminate.
	parentOf := map[string]string{}
	for _, e := range edges {
		if prev, dup := parentOf[e.To]; dup {
			t.Fatalf("%s was given two parents, %s and %s", e.To, prev, e.From)
		}
		parentOf[e.To] = e.From
	}
	if _, rooted := parentOf["A"]; rooted {
		t.Fatalf("the closing hop gave the root a parent: %v", parentOf)
	}
	for _, n := range nodes {
		steps := 0
		for at := n.ID; ; {
			parent, ok := parentOf[at]
			if !ok {
				break
			}
			at = parent
			steps++
			if steps > len(nodes) {
				t.Fatalf("walking up from %s never reached the root: %v", n.ID, parentOf)
			}
		}
	}
	if kind := edgeKind(t, edges, "A", "B"); kind != flowEdgeRedirect {
		t.Fatalf("the two sound hops should still be redirect edges, got %q", kind)
	}
	if kind := edgeKind(t, edges, "B", "C"); kind != flowEdgeRedirect {
		t.Fatalf("the two sound hops should still be redirect edges, got %q", kind)
	}
}

// A hop that points at itself through one intermediate, where the destination was recorded FIRST.
// Preferring the earlier timestamp as the parent is what keeps this from inverting.
func TestReplayRequestFlowRedirectIgnoresEarlierDestination(t *testing.T) {
	hop := FlowRedirectHop{
		From:       "https://app.test/b",
		Location:   "https://app.test/a",
		StatusCode: 302,
	}
	captures := []FlowCapture{
		flowCap("early-a", "GET", "https://app.test/a", "main_frame", flowAt(0)),
		withChain(flowCap("b", "GET", "https://app.test/b", "xhr", flowAt(5)), hop),
	}
	flow := segmentCaptureFlows(captures)[0]
	_, edges, _ := renderFlowGraph(flow, deriveFlowLinks(flow), true)
	if kind := edgeKind(t, edges, "b", "early-a"); kind != "" {
		t.Fatalf("a destination recorded before its cause is a different visit, got edge kind %q", kind)
	}
}

// The one shape with no navigation to root anything: 1,133 requests in a single tab on the live
// corpus. One flow of 1,133 nodes is not a diagram, so the fallback cuts at an idle gap and says so.
func TestReplayRequestFlowTabWithNoNavigation(t *testing.T) {
	captures := []FlowCapture{
		withInitiator(flowCap("p1", "GET", "https://app.test/api/poll", "xhr", flowAt(0)), "script"),
		withInitiator(flowCap("p2", "GET", "https://app.test/api/poll", "xhr", flowAt(1)), "script"),
		withInitiator(flowCap("p3", "GET", "https://app.test/api/notify", "xhr", flowAt(2.5)), "script"),
		// Longer than the idle gap: the operator did something else.
		withInitiator(flowCap("q1", "POST", "https://app.test/api/save", "xhr", flowAt(30)), "script"),
		withInitiator(flowCap("q2", "GET", "https://app.test/api/poll", "xhr", flowAt(30.5)), "script"),
	}

	flows := segmentCaptureFlows(captures)
	if got := flowRootIDs(flows); len(got) != 2 || got[0] != "p1" || got[1] != "q1" {
		t.Fatalf("expected two burst flows rooted at [p1 q1], got %v", got)
	}
	for _, f := range flows {
		if f.RootKind != flowRootBurst {
			t.Fatalf("a flow with no navigation must be reported as a burst, got %q", f.RootKind)
		}
	}
	if got := flowMemberIDs(flows[0]); len(got) != 3 {
		t.Fatalf("the first burst should hold the three requests before the gap, got %v", got)
	}

	// It still produces a usable graph: a root, edges to everything else, no orphans.
	flow := flows[0]
	nodes, edges, hidden := renderFlowGraph(flow, deriveFlowLinks(flow), false)
	if len(nodes) != 3 || hidden != 0 {
		t.Fatalf("expected three visible nodes, got %d (hidden %d)", len(nodes), hidden)
	}
	if len(edges) != 2 {
		t.Fatalf("every non-root node needs an edge or it renders as an orphan, got %+v", edges)
	}
	if n := nodeByID(nodes, "p1"); n == nil || !n.IsRoot {
		t.Fatalf("the first request of a burst roots it, got %+v", n)
	}
	if summary := summarizeFlow(flow); summary.Label != "GET /api/poll" {
		t.Fatalf("a burst is still labelled by the request that rooted it, got %q", summary.Label)
	}
}

// A gap inside a NAVIGATION-rooted flow must not split it. A page that sat quiet and then fired an
// XHR is exactly the sequence worth looking at, and cutting it in half would hide the connection.
func TestReplayRequestFlowIdleGapDoesNotSplitNavigation(t *testing.T) {
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/app", "main_frame", flowAt(0)),
		withInitiator(flowCap("late", "POST", "https://app.test/api/save", "xhr", flowAt(120)), "script"),
	}
	flows := segmentCaptureFlows(captures)
	if len(flows) != 1 || len(flows[0].Captures) != 2 {
		t.Fatalf("a navigation-rooted flow holds everything until the next navigation, got %v",
			flowRootIDs(flows))
	}
}

func TestReplayRequestFlowSummaryCounts(t *testing.T) {
	captures := []FlowCapture{
		flowCap("nav", "GET", "https://app.test/app", "main_frame", flowAt(0)),
		withStatus(withInitiator(flowCap("x1", "GET", "https://app.test/api/a", "xhr", flowAt(1)), "script"), 404),
		withStatus(withInitiator(flowCap("x2", "GET", "https://app.test/api/b", "xhr", flowAt(2)), "script"), 500),
		// No status at all: a connection failure is a result, not a 2xx.
		withStatus(withInitiator(flowCap("x3", "GET", "https://app.test/api/c", "xhr", flowAt(3)), "script"), 0),
		withInitiator(flowCap("img", "GET", "https://app.test/i.png", "image", flowAt(4)), "parser"),
	}
	captures[4].DurationMs = 1500

	flow := segmentCaptureFlows(captures)[0]
	summary := summarizeFlow(flow)

	if summary.RequestCount != 5 || summary.ShownCount != 4 || summary.HiddenCount != 1 {
		t.Fatalf("expected 5 requests, 4 shown, 1 hidden, got %+v", summary)
	}
	// Every request in the flow is counted, hidden ones included: "did anything in here 4xx" is a
	// question about the flow, not about what the diagram chose to draw. The navigation and the
	// hidden image are the two 2xx.
	want := map[string]int{"2xx": 2, "4xx": 1, "5xx": 1, "err": 1}
	if len(summary.StatusSummary) != len(want) {
		t.Fatalf("unexpected status buckets: %v", summary.StatusSummary)
	}
	for bucket, count := range want {
		if summary.StatusSummary[bucket] != count {
			t.Fatalf("expected %s=%d, got status_summary %v", bucket, count, summary.StatusSummary)
		}
	}
	// The flow ends when its last request FINISHED. timestamp is the start, so the trailing
	// duration counts: 4s to the last request plus its own 1.5s.
	if summary.DurationMs != 5500 {
		t.Fatalf("expected the flow to run to the end of its last request (5500ms), got %d",
			summary.DurationMs)
	}
	if summary.HasRedirects || summary.HasBody {
		t.Fatalf("nothing here redirected or carried a body, got %+v", summary)
	}
}

func TestReplayRequestFlowIDRoundTrip(t *testing.T) {
	session := "22222222-2222-2222-2222-222222222222"
	root := "33333333-3333-3333-3333-333333333333"

	for _, tab := range []*int{flowIntPtr(536846617), flowIntPtr(-1), nil} {
		id := EncodeFlowID(session, tab, root)
		gotSession, gotTab, gotRoot, err := DecodeFlowID(id)
		if err != nil {
			t.Fatalf("round trip of %q failed: %v", id, err)
		}
		if gotSession != session || gotRoot != root {
			t.Fatalf("round trip lost the ids: %q / %q", gotSession, gotRoot)
		}
		switch {
		case tab == nil && gotTab != nil:
			t.Fatalf("a NULL tab came back as %d", *gotTab)
		case tab != nil && (gotTab == nil || *gotTab != *tab):
			t.Fatalf("tab %d came back as %v", *tab, gotTab)
		}
	}

	// The id is derived from the session, tab and root capture, so it is stable across two
	// reconstructions of the same corpus rather than being an array index.
	captures := []FlowCapture{
		flowCap("11111111-1111-1111-1111-111111111112", "GET", "https://app.test/a", "main_frame", flowAt(0)),
		flowCap("11111111-1111-1111-1111-111111111113", "GET", "https://app.test/b", "main_frame", flowAt(1)),
	}
	first := summarizeFlow(segmentCaptureFlows(captures)[1]).ID
	reordered := []FlowCapture{captures[1], captures[0]}
	second := summarizeFlow(segmentCaptureFlows(reordered)[1]).ID
	if first != second {
		t.Fatalf("the flow id must not depend on input order: %q vs %q", first, second)
	}

	for _, bad := range []string{"", "nope", session + "~7", session + "~x~" + root, "x~7~" + root} {
		if _, _, _, err := DecodeFlowID(bad); err == nil {
			t.Fatalf("expected %q to be rejected as a flow id", bad)
		}
	}
}

// The fragment is never sent to a server, and the recorder writes it into both `url` and the
// redirect hops. Leaving it in makes one request look like two.
func TestReplayRequestFlowURLNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://App.Test/Path?a=B#frag", "https://app.test/Path?a=B"},
		{"https://app.test/Path?a=B", "https://app.test/Path?a=B"},
		{"not a url#frag", "not a url"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := normalizeFlowURL(tc.in); got != tc.want {
			t.Errorf("normalizeFlowURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := flowURLPath("https://app.test"); got != "/" {
		t.Errorf("a URL with no path is the root, got %q", got)
	}
	if got := flowURLHost("https://App.Test:8443/x"); got != "app.test" {
		t.Errorf("the host is lower-cased and the port dropped, got %q", got)
	}
}
