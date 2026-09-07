package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Request Flow: the second half of the repeater.
//
// A single request is the wrong unit for most of the interesting work. A form submit is a POST, a
// 302, a GET of the page it landed on and the six XHRs that page fires; an OAuth handshake is four
// redirects across three hosts. The repeater can already replay any one of those, but until you can
// SEE which ones belong together you cannot tell which one to replay.
//
// So this reconstructs flows from manual_crawl_captures and returns them as a graph. Nothing here
// re-runs anything and nothing here writes: it is a second reading of rows the crawl already stored,
// and every node carries the capture id the repeater loads, so a double-click in the diagram is the
// same /replay-request/capture/{id}/raw the list view already uses.
//
// Two things govern the whole file.
//
// First, the SEGMENTATION and EDGE DERIVATION are pure functions over a slice of structs. They hold
// every judgement call worth arguing about, and a judgement call that can only be exercised against
// a 6,000-row live table is a judgement call nobody will ever check. The database layer below them
// does nothing but fill those structs in.
//
// Second, the graph must never claim more than the data supports. The recorder stores the initiator
// TYPE and not the initiator URL, so "some script asked for this" is the most that can honestly be
// said about 1,400 of the rows; the code says exactly that and no more, and every edge carries the
// reason it was drawn so the operator can weigh it.

const (
	// A flow ends at the next navigation in the same tab. A tab that never navigated has no such
	// boundary, so its requests are cut into bursts at an idle gap instead. Measured against the
	// live corpus: on the one nav-less session (1,133 requests) 90% of consecutive gaps are under
	// 4.4s, so 5s separates "this page is still settling" from "the operator did something else".
	//
	// Applied ONLY to burst-rooted flows. A navigation-rooted flow keeps everything until the next
	// navigation even across a long pause, because that is what "belongs to this page" means.
	flowIdleGapSeconds = 5

	// How long after a redirecting request its destination may still be treated as the SAME flow.
	//
	// This is not cosmetic. The most valuable flow in the corpus is `POST /dashboard/tickets/new`
	// 302 -> `GET /dashboard/tickets`, and the destination is recorded with resource_type=document,
	// which is a navigation. Segmenting naively puts the POST and the page it produced in two
	// different flows and destroys the exact thing the operator came here to see. A navigation that
	// is the redirect target of something already in the current flow therefore CONTINUES it.
	//
	// The window stops that rule from absorbing an unrelated navigation to a URL some request
	// happened to redirect to ten minutes earlier. The observed follow took 2.1s.
	flowRedirectFollowSeconds = 15

	// Ceilings, not page sizes. The largest corpus seen is ~6,000 rows for a whole target.
	flowScanCeiling   = 50000
	flowsDefaultLimit = 200
	flowsMaxLimit     = 2000
)

// Resource types that root a flow. `document` is here as well as `main_frame` because the two
// capture sources name the same event differently: webRequest reports main_frame, the debugger
// reports Document. There is no frame id in the schema to tell a top-level document from an iframe
// one, so an iframe navigation would also root a flow. That is the conservative direction: an extra
// flow is visible and dismissable, a swallowed one is not.
var flowNavigationResourceTypes = map[string]bool{
	"main_frame": true,
	"document":   true,
}

// What survives the default noise filter.
//
// The corpus is roughly 90% subresources (1,147 script, 918 stylesheet, 754 ping, 628 image, 595
// beacon, 201 font). Drawing them produces a diagram nobody can read, so the default keeps the
// request types that carry application behaviour and hides the rest, with a count so the operator
// knows the graph is filtered.
//
// websocket is in this list although it is not a navigation or an XHR: 101 upgrades are a first-
// class security surface, there are 23 of them table-wide, and hiding them by default in a tool
// whose job is finding flaws would be the same silent omission this filter exists to avoid.
var flowSignificantResourceTypes = map[string]bool{
	"main_frame":     true,
	"document":       true,
	"xhr":            true,
	"xmlhttprequest": true,
	"fetch":          true,
	"preflight":      true,
	"websocket":      true,
}

// Fire-and-forget telemetry, which a request body does NOT rescue from the filter.
//
// "Anything with a body" is otherwise the right rule, because a POST is what the operator came for.
// It stops being right for these two: navigator.sendBeacon and <a ping> are POSTs by construction,
// and on the live corpus 1,326 of the 1,349 ping and beacon rows carry a body. Counting them as
// interesting halved what the default view hides, and put 1,326 analytics pings into the diagrams
// this filter exists to keep readable. With them excluded the default hides 89% on bbyc (18 of 169
// shown) and 85% on privatealps (398 of 2,723), which is the intended shape: a flow diagram is
// worth reading precisely because it is not the whole capture log.
//
// They are hidden, not dropped: they are in the hidden count and one toggle away, which is the
// difference between a filtered graph and a graph that lies about what was there.
var flowTelemetryResourceTypes = map[string]bool{
	"ping":   true,
	"beacon": true,
}

// ---------------------------------------------------------------------------
// The row, and the shapes returned
// ---------------------------------------------------------------------------

// FlowRedirectHop is one entry of the redirect_chain column. Both capture sources write the same
// three keys (see extension/lib/captureStages.js and extension/lib/deepcapture.js), and both write
// the WHOLE chain onto every leg of it, which is what makes the hops resolvable to captures.
type FlowRedirectHop struct {
	From       string `json:"from"`
	Location   string `json:"location"`
	StatusCode int    `json:"statusCode"`
}

// FlowCapture is the projection of manual_crawl_captures that flow reconstruction needs. Bodies are
// absent on purpose: a flow view is for choosing, and the chosen request is fetched whole by the
// existing /raw endpoint.
type FlowCapture struct {
	ID            string
	SessionID     string
	TabID         *int
	Method        string
	URL           string
	StatusCode    int
	ResourceType  string
	Initiator     string
	MimeType      string
	Timestamp     time.Time
	DurationMs    int
	Size          int
	HasBody       bool
	RedirectChain []FlowRedirectHop
	// Whether this row satisfied the operator's search. A flow is shown when ANY of its requests
	// matched, so the filter has to travel with the row rather than removing it: filtering to
	// "method = POST" should show the whole flow that POST belongs to, not an orphaned node.
	Matched bool
}

// FlowNode is one request in the returned graph.
type FlowNode struct {
	ID           string    `json:"id"`
	Method       string    `json:"method"`
	URL          string    `json:"url"`
	Path         string    `json:"path"`
	Host         string    `json:"host"`
	StatusCode   int       `json:"status_code"`
	ResourceType string    `json:"resource_type"`
	Initiator    string    `json:"initiator"`
	MimeType     string    `json:"mime_type"`
	Timestamp    time.Time `json:"timestamp"`
	DurationMs   int       `json:"duration_ms"`
	Size         int       `json:"size"`
	HasBody      bool      `json:"has_body"`
	// Distance from the root along the edges IN THIS RESPONSE, so the renderer can lay the graph out
	// without doing any graph work of its own. Recomputed after filtering, because a depth measured
	// on nodes that are not in the payload is a depth the renderer cannot use.
	Depth  int  `json:"depth"`
	IsRoot bool `json:"is_root"`
}

// FlowEdge carries WHY it was drawn, because the four reasons are not equally trustworthy and the
// operator is entitled to know which one they are looking at.
//
//	redirect   the redirect_chain says so. Explicit, recorded by the browser.
//	preflight  a CORS preflight and the request it cleared, paired on identical URL.
//	initiator  the recorder said a parser or a script caused this. The TYPE is known, the specific
//	           caller is not, so the edge lands on the navigation.
//	sequence   nothing better was known; it happened inside this flow, after the root.
type FlowEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// FlowSummary describes one flow without its graph.
//
// ShownCount and HiddenCount ALWAYS describe the default filter, on both endpoints, so the same
// flow reports the same numbers in the list and in the detail view. What a particular detail
// response actually hid is the separate top-level hidden_count on that response.
type FlowSummary struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	TabID         *int      `json:"tab_id"`
	RootCaptureID string    `json:"root_capture_id"`
	Label         string    `json:"label"`
	Host          string    `json:"host"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	DurationMs    int       `json:"duration_ms"`
	RequestCount  int       `json:"request_count"`
	ShownCount    int       `json:"shown_count"`
	HiddenCount   int       `json:"hidden_count"`
	// Keyed "1xx".."5xx", plus "err" for a request that never got a status at all (a connection
	// failure is a result, and folding it into 2xx would be a lie). Counts EVERY request in the
	// flow, not just the shown ones, because "did anything in here 4xx" is the question being asked.
	StatusSummary map[string]int `json:"status_summary"`
	HasRedirects  bool           `json:"has_redirects"`
	HasBody       bool           `json:"has_body"`
	// "navigation" when a main_frame/document request rooted this flow, "burst" when the tab never
	// navigated and the flow was cut at an idle gap instead. Surfaced rather than hidden: a burst is
	// a heuristic and the operator should be able to see which flows rest on one.
	RootKind string `json:"root_kind"`
}

// captureFlow is one reconstructed flow before it is turned into a graph. Captures are in timeline
// order and Captures[0] is the root.
type captureFlow struct {
	Captures []FlowCapture
	RootKind string
}

const (
	flowRootNavigation = "navigation"
	flowRootBurst      = "burst"
)

// ---------------------------------------------------------------------------
// Segmentation: which requests belong to the same flow
// ---------------------------------------------------------------------------

// segmentCaptureFlows cuts a slice of captures into navigation-rooted flows.
//
// Within one (session, tab), ordered by timestamp, a main_frame or document request starts a new
// flow and everything after it belongs to that flow until the next one. Two rules bend that:
//
//   - A navigation that is the redirect DESTINATION of something already in the current flow does
//     not start a new flow, it joins the one that redirected to it. Without this the single most
//     valuable pattern in the corpus, a form POST and the page its 302 produced, is split in half.
//   - A tab that never navigates has no boundaries at all, and one flow of 1,133 requests is not a
//     diagram. Those are cut at an idle gap instead and labelled as bursts.
//
// Ordering is by (session, tab, timestamp, id). The id breaks ties because two captures can share a
// millisecond, and a flow that reshuffles between two identical requests reads as data changing
// underneath you.
func segmentCaptureFlows(captures []FlowCapture) []captureFlow {
	ordered := make([]FlowCapture, len(captures))
	copy(ordered, captures)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].SessionID != ordered[j].SessionID {
			return ordered[i].SessionID < ordered[j].SessionID
		}
		ti, tj := flowTabKey(ordered[i].TabID), flowTabKey(ordered[j].TabID)
		if ti != tj {
			return ti < tj
		}
		if !ordered[i].Timestamp.Equal(ordered[j].Timestamp) {
			return ordered[i].Timestamp.Before(ordered[j].Timestamp)
		}
		return ordered[i].ID < ordered[j].ID
	})

	// Pointers, not values. Appending to a []captureFlow reallocates its backing array and would
	// leave a held &flows[n-1] writing into the old one, silently losing every capture appended
	// after the growth.
	flows := []*captureFlow{}

	var current *captureFlow
	var currentSession string
	var currentTab string
	// Redirect destinations seen so far in the current flow, and when the request that produced
	// them ran, so the follow window can be applied.
	redirectTargets := map[string]time.Time{}
	var lastTimestamp time.Time

	start := func(c FlowCapture, kind string) {
		current = &captureFlow{Captures: []FlowCapture{c}, RootKind: kind}
		flows = append(flows, current)
		redirectTargets = map[string]time.Time{}
		noteFlowRedirectTargets(redirectTargets, c)
		lastTimestamp = c.Timestamp
	}

	for _, c := range ordered {
		session := c.SessionID
		tab := flowTabKey(c.TabID)
		isNav := flowNavigationResourceTypes[strings.ToLower(strings.TrimSpace(c.ResourceType))]

		if current == nil || session != currentSession || tab != currentTab {
			currentSession, currentTab = session, tab
			kind := flowRootBurst
			if isNav {
				kind = flowRootNavigation
			}
			start(c, kind)
			continue
		}

		continuesRedirect := flowContinuesRedirect(redirectTargets, c)

		switch {
		case isNav && !continuesRedirect:
			start(c, flowRootNavigation)
			continue
		// The idle gap only applies where there is no navigation to define the boundary. Splitting a
		// navigation-rooted flow on a pause would break up a page that legitimately sat quiet and
		// then fired an XHR, which is precisely the sequence worth looking at.
		case current.RootKind == flowRootBurst && !continuesRedirect &&
			c.Timestamp.Sub(lastTimestamp) > flowIdleGapSeconds*time.Second:
			start(c, flowRootBurst)
			continue
		}

		current.Captures = append(current.Captures, c)
		noteFlowRedirectTargets(redirectTargets, c)
		lastTimestamp = c.Timestamp
	}

	result := make([]captureFlow, 0, len(flows))
	for _, f := range flows {
		result = append(result, *f)
	}
	return result
}

// flowTabKey renders a nullable tab id as a sortable, comparable string. Every row in the live
// corpus has a tab, but the column is nullable and a NULL tab is still a tab's worth of traffic.
func flowTabKey(tabID *int) string {
	if tabID == nil {
		return "n"
	}
	return strconv.Itoa(*tabID)
}

func noteFlowRedirectTargets(targets map[string]time.Time, c FlowCapture) {
	for _, hop := range c.RedirectChain {
		location := normalizeFlowURL(hop.Location)
		if location == "" {
			continue
		}
		// Keep the latest, so the follow window is measured from the most recent request that could
		// have produced this destination.
		if prev, ok := targets[location]; !ok || c.Timestamp.After(prev) {
			targets[location] = c.Timestamp
		}
	}
}

func flowContinuesRedirect(targets map[string]time.Time, c FlowCapture) bool {
	at, ok := targets[normalizeFlowURL(c.URL)]
	if !ok {
		return false
	}
	delta := c.Timestamp.Sub(at)
	return delta >= 0 && delta <= flowRedirectFollowSeconds*time.Second
}

// normalizeFlowURL puts two URLs in a form where "is this the same request" can be answered.
//
// The fragment is dropped because it is never sent to a server and because the recorder writes it
// into both `url` and the redirect hops, so leaving it in makes /settings and /settings#preferences
// two different requests when the wire saw one. Scheme and host are lower-cased; the path and query
// are not, because they are case-sensitive on the wire and folding them would merge distinct
// endpoints.
func normalizeFlowURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		// Unparseable is still comparable to itself, which is all this needs to be.
		if cut, _, found := strings.Cut(trimmed, "#"); found {
			return cut
		}
		return trimmed
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String()
}

func flowURLHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	// Hostname() drops the port, matching the capture_host() SQL function every other feature splits
	// traffic with.
	return strings.ToLower(parsed.Hostname())
}

func flowURLPath(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

// ---------------------------------------------------------------------------
// Edges: which request caused which
// ---------------------------------------------------------------------------

// flowLink is the parent assigned to one node, or parent < 0 for the root and for anything that has
// not been claimed yet.
type flowLink struct {
	parent int
	kind   string
}

const (
	flowEdgeRedirect  = "redirect"
	flowEdgePreflight = "preflight"
	flowEdgeInitiator = "initiator"
	flowEdgeSequence  = "sequence"
)

// deriveFlowLinks assigns every capture in a flow exactly one parent, producing a tree rooted at
// index 0. A tree rather than a general graph because the renderer lays out by depth, and because
// every parent below rests on a different amount of evidence: with one parent per node the operator
// is shown the STRONGEST claim the data supports rather than a pile of maybes.
//
// Priority, highest first:
//
//  1. redirect. The browser recorded the hop. Nothing here is inferred.
//  2. preflight. A CORS preflight and the request to the same URL that follows it. Chrome always
//     emits them in that order, so the pairing is safe.
//  3. initiator / sequence. Attached to the flow root. See attachRemainingToRoot for why nothing
//     more specific is claimed.
//
// A node keeps the first parent it is given, so a weaker rule can never overwrite a stronger one.
func deriveFlowLinks(flow captureFlow) []flowLink {
	n := len(flow.Captures)
	links := make([]flowLink, n)
	for i := range links {
		links[i].parent = -1
	}
	if n == 0 {
		return links
	}

	byURL := map[string][]int{}
	for i, c := range flow.Captures {
		key := normalizeFlowURL(c.URL)
		if key != "" {
			byURL[key] = append(byURL[key], i)
		}
	}

	linkFlowRedirects(flow, links, byURL)
	linkFlowPreflights(flow, links, byURL)
	attachRemainingToRoot(flow, links)
	return links
}

// linkFlowRedirects turns redirect_chain into edges between captures.
//
// Both capture sources write the WHOLE chain onto every leg of a redirect, so the same (from,
// location) pair usually arrives twice, once from the request that was redirected and once from the
// request it became. Collecting the pairs first and resolving each once is what makes that
// duplication harmless instead of order-dependent.
//
// A hop whose destination was never captured draws nothing. Every node in this graph is a real row
// the repeater can load, and a synthetic node with no capture id would be a node the operator can
// see and cannot open.
func linkFlowRedirects(flow captureFlow, links []flowLink, byURL map[string][]int) {
	type redirectPair struct{ from, location string }

	seen := map[redirectPair]bool{}
	pairs := []redirectPair{}
	for _, c := range flow.Captures {
		for _, hop := range c.RedirectChain {
			pair := redirectPair{from: normalizeFlowURL(hop.From), location: normalizeFlowURL(hop.Location)}
			if pair.from == "" || pair.location == "" || pair.from == pair.location {
				// from == location is a self-redirect: 12 of the 57 redirect_chain hops on the live
				// corpus, where the recorder wrote the same URL into both keys. It describes no edge
				// and drawing it would put a self-loop in the graph.
				//
				// This is why a flow can be badged as having redirects and still draw none. The
				// marquee case is one of them: POST /dashboard/tickets/71571 302s to its own GET and
				// both keys record the same URL, so the edge degrades to initiator while the
				// grouping stays correct. The real fix is upstream in the extension, which writes
				// the post-redirect URL into `from` on some paths; the chart tells the operator
				// rather than leaving an unexplained gap.
				continue
			}
			if seen[pair] {
				continue
			}
			seen[pair] = true
			pairs = append(pairs, pair)
		}
	}

	for _, pair := range pairs {
		src := firstFlowIndex(byURL[pair.from])
		if src < 0 {
			continue
		}
		dst := firstFlowIndexAfter(byURL[pair.location], flow, src)
		if dst < 0 || dst == src || dst == 0 {
			// dst == 0 would give the root a parent, which is what a root is defined by not having.
			continue
		}
		if links[dst].parent >= 0 {
			continue
		}
		if flowWouldCycle(links, dst, src) {
			// redirect_chain is external data. A chain that loops must not become a cyclic graph, so
			// the edge that would close the loop is the one dropped, and the earlier-timestamped
			// parent already assigned is the one kept.
			continue
		}
		links[dst] = flowLink{parent: src, kind: flowEdgeRedirect}
	}
}

// firstFlowIndex prefers the earliest occurrence, which given the flow's ordering is the earliest
// timestamp. When a URL was requested three times, the first one is the one that redirected.
func firstFlowIndex(indices []int) int {
	if len(indices) == 0 {
		return -1
	}
	best := indices[0]
	for _, i := range indices[1:] {
		if i < best {
			best = i
		}
	}
	return best
}

// firstFlowIndexAfter picks the earliest candidate that did not happen before its cause. A redirect
// destination recorded BEFORE the request that redirected to it is a different visit to the same
// URL, not this one.
func firstFlowIndexAfter(indices []int, flow captureFlow, src int) int {
	best := -1
	for _, i := range indices {
		if i == src || i < src {
			continue
		}
		if flow.Captures[i].Timestamp.Before(flow.Captures[src].Timestamp) {
			continue
		}
		if best < 0 || i < best {
			best = i
		}
	}
	return best
}

// linkFlowPreflights pairs an OPTIONS with the request it cleared.
//
// The recorder marks the preflight itself, on both sources: resource_type is "preflight" and
// initiator is "preflight" on the same row (241 of each in the corpus). The request it was for is
// the next one to the same URL that is not itself a preflight. The preflight is made the PARENT
// because that is the order the browser sent them in, and because a preflight with nothing hanging
// off it is a preflight the operator will wonder about.
func linkFlowPreflights(flow captureFlow, links []flowLink, byURL map[string][]int) {
	for i, c := range flow.Captures {
		if !isFlowPreflight(c) {
			continue
		}
		target := -1
		for _, j := range byURL[normalizeFlowURL(c.URL)] {
			if j <= i || isFlowPreflight(flow.Captures[j]) {
				continue
			}
			if target < 0 || j < target {
				target = j
			}
		}
		if target <= 0 || links[target].parent >= 0 || flowWouldCycle(links, target, i) {
			continue
		}
		links[target] = flowLink{parent: i, kind: flowEdgePreflight}
	}
}

func isFlowPreflight(c FlowCapture) bool {
	return strings.EqualFold(strings.TrimSpace(c.ResourceType), "preflight") ||
		strings.EqualFold(strings.TrimSpace(c.Initiator), "preflight") ||
		strings.EqualFold(strings.TrimSpace(c.Method), "OPTIONS")
}

// attachRemainingToRoot hangs everything still unclaimed off the navigation that rooted the flow.
//
// This is deliberately NOT a chain of c[i-1] -> c[i]. A sequence chain asserts "A caused B" when all
// that is known is "B came after A", and it turns a page that fired 200 requests into a 200-deep
// ladder that no layout can render and no operator can read.
//
// initiator=parser is exact: the HTML parser found the tag, so the document IS the parent.
// initiator=script is the honest limit of this schema. The recorder stores the initiator TYPE and
// not the initiator URL (extension/lib/deepcapture.js keeps params.initiator.type only), so which
// script made the call cannot be recovered. Attaching it to the navigation is the strongest claim
// the data supports; the edge is labelled "initiator" so the operator can see it rests on that and
// not on a recorded relationship.
func attachRemainingToRoot(flow captureFlow, links []flowLink) {
	for i := 1; i < len(flow.Captures); i++ {
		if links[i].parent >= 0 {
			continue
		}
		kind := flowEdgeSequence
		if strings.TrimSpace(flow.Captures[i].Initiator) != "" {
			kind = flowEdgeInitiator
		}
		links[i] = flowLink{parent: 0, kind: kind}
	}
}

// flowWouldCycle reports whether making parent the parent of child closes a loop.
//
// Walks up from the proposed parent looking for the child. The iteration cap is not decoration: the
// links array is built from external data, and a guard that can itself spin forever is not a guard.
func flowWouldCycle(links []flowLink, child, parent int) bool {
	if child == parent {
		return true
	}
	steps := 0
	for at := parent; at >= 0; at = links[at].parent {
		if at == child {
			return true
		}
		steps++
		if steps > len(links) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Filtering and rendering the graph
// ---------------------------------------------------------------------------

// isSignificantFlowCapture decides what survives the default noise filter.
//
// Resource type is the main test, but three things get in regardless of type, because each of them
// is the reason an operator opened this view:
//
//	a request body      a POST of a stylesheet is still a POST, telemetry excepted
//	a 3xx status        a redirect is the shape of the flow
//	a redirect_chain    the settled status on a followed redirect is 200, not 3xx, so the status
//	                    test alone misses every redirect the browser followed for you. Verified on
//	                    the corpus: all 56 chain-carrying rows are recorded with their final status.
func isSignificantFlowCapture(c FlowCapture) bool {
	resourceType := strings.ToLower(strings.TrimSpace(c.ResourceType))
	if flowSignificantResourceTypes[resourceType] {
		return true
	}
	if c.HasBody && !flowTelemetryResourceTypes[resourceType] {
		return true
	}
	if c.StatusCode >= 300 && c.StatusCode < 400 {
		return true
	}
	return len(c.RedirectChain) > 0
}

// renderFlowGraph turns a flow and its links into the nodes and edges the client draws.
//
// showAll=false applies the noise filter. The root is always kept: a flow whose root was filtered
// out has nothing to hang anything off and nothing to name it with.
//
// The reparenting rule is the load-bearing part. When a parent is hidden its children are moved to
// the nearest VISIBLE ancestor, never left pointing at a node that is not in the payload. A dangling
// edge crashes or silently drops nodes in any renderer, and a silently dropped node is the failure
// this whole filtered view is meant to be honest about. Because the root is always visible, the walk
// always terminates.
//
// A substituted parent downgrades the edge to "sequence". Keeping the original kind would have the
// payload claim a redirect between two requests that never redirected to one another.
func renderFlowGraph(flow captureFlow, links []flowLink, showAll bool) ([]FlowNode, []FlowEdge, int) {
	n := len(flow.Captures)
	nodes := []FlowNode{}
	edges := []FlowEdge{}
	if n == 0 {
		return nodes, edges, 0
	}

	visible := make([]bool, n)
	for i, c := range flow.Captures {
		visible[i] = showAll || i == 0 || isSignificantFlowCapture(c)
	}

	hidden := 0
	for _, v := range visible {
		if !v {
			hidden++
		}
	}

	// Depth on the VISIBLE tree, computed top-down. The captures are in timeline order and a parent
	// is always assigned to an earlier index than its child (redirect and preflight both resolve
	// forwards, and everything else attaches to index 0), so one forward pass is enough.
	depth := make([]int, n)

	for i := 0; i < n; i++ {
		if !visible[i] {
			continue
		}
		c := flow.Captures[i]
		node := FlowNode{
			ID:           c.ID,
			Method:       strings.ToUpper(c.Method),
			URL:          c.URL,
			Path:         flowURLPath(c.URL),
			Host:         flowURLHost(c.URL),
			StatusCode:   c.StatusCode,
			ResourceType: c.ResourceType,
			Initiator:    c.Initiator,
			MimeType:     c.MimeType,
			Timestamp:    c.Timestamp,
			DurationMs:   c.DurationMs,
			Size:         c.Size,
			HasBody:      c.HasBody,
			IsRoot:       i == 0,
		}

		if i > 0 {
			parent := links[i].parent
			kind := links[i].kind
			steps := 0
			for parent > 0 && !visible[parent] {
				kind = flowEdgeSequence
				parent = links[parent].parent
				steps++
				if steps > n {
					// Cannot happen with an acyclic links array, and this is the one place a bad one
					// would hang the request rather than merely draw a wrong edge.
					parent = 0
					break
				}
			}
			if parent < 0 {
				parent = 0
			}
			if parent != i {
				edges = append(edges, FlowEdge{
					From: flow.Captures[parent].ID,
					To:   c.ID,
					Kind: kind,
				})
				depth[i] = depth[parent] + 1
			}
		}

		node.Depth = depth[i]
		nodes = append(nodes, node)
	}

	return nodes, edges, hidden
}

// ---------------------------------------------------------------------------
// Summaries and identity
// ---------------------------------------------------------------------------

// summarizeFlow describes a flow without building its graph. ShownCount and HiddenCount are always
// measured with the DEFAULT filter, so the list and the detail view agree about the same flow.
func summarizeFlow(flow captureFlow) FlowSummary {
	if len(flow.Captures) == 0 {
		return FlowSummary{StatusSummary: map[string]int{}}
	}

	root := flow.Captures[0]
	summary := FlowSummary{
		ID:            EncodeFlowID(root.SessionID, root.TabID, root.ID),
		SessionID:     root.SessionID,
		TabID:         root.TabID,
		RootCaptureID: root.ID,
		Label:         strings.ToUpper(strings.TrimSpace(root.Method)) + " " + flowURLPath(root.URL),
		Host:          flowURLHost(root.URL),
		StartedAt:     root.Timestamp,
		EndedAt:       root.Timestamp,
		RequestCount:  len(flow.Captures),
		StatusSummary: map[string]int{},
		RootKind:      flow.RootKind,
	}

	for _, c := range flow.Captures {
		if c.Timestamp.Before(summary.StartedAt) {
			summary.StartedAt = c.Timestamp
		}
		// timestamp is when the request STARTED (extension/background.js stamps it at
		// onBeforeRequest and derives durationMs from it), so the flow ends when its last request
		// finished, not when the last one began.
		end := c.Timestamp.Add(time.Duration(c.DurationMs) * time.Millisecond)
		if end.After(summary.EndedAt) {
			summary.EndedAt = end
		}
		summary.StatusSummary[flowStatusBucket(c.StatusCode)]++
		if c.HasBody {
			summary.HasBody = true
		}
		if len(c.RedirectChain) > 0 || (c.StatusCode >= 300 && c.StatusCode < 400) {
			summary.HasRedirects = true
		}
		if isSignificantFlowCapture(c) {
			summary.ShownCount++
		}
	}

	// The root is shown whatever its type, so a burst rooted on a script still has an anchor.
	if !isSignificantFlowCapture(root) {
		summary.ShownCount++
	}
	summary.HiddenCount = summary.RequestCount - summary.ShownCount
	summary.DurationMs = int(summary.EndedAt.Sub(summary.StartedAt) / time.Millisecond)
	if summary.DurationMs < 0 {
		summary.DurationMs = 0
	}
	return summary
}

func flowStatusBucket(status int) string {
	if status < 100 || status > 599 {
		return "err"
	}
	return strconv.Itoa(status/100) + "xx"
}

// The flow id has to survive a round trip through a URL and has to be reconstructible without a
// lookup table, because flows are derived on every request and nothing about them is stored. Session
// and tab locate the segment to rebuild, and the root capture id names the flow inside it. Derived
// from those three rather than from an array index, so it stays the same flow when new captures
// arrive and the list re-orders.
//
// '~' is the separator: RFC 3986 unreserved, so it needs no escaping, and it appears in neither a
// UUID nor an integer.
const flowIDSeparator = "~"

func EncodeFlowID(sessionID string, tabID *int, rootCaptureID string) string {
	return sessionID + flowIDSeparator + flowTabKey(tabID) + flowIDSeparator + rootCaptureID
}

func DecodeFlowID(id string) (sessionID string, tabID *int, rootCaptureID string, err error) {
	parts := strings.Split(strings.TrimSpace(id), flowIDSeparator)
	if len(parts) != 3 {
		return "", nil, "", fmt.Errorf("a flow id is <session>~<tab>~<root capture>, got %q", id)
	}
	if _, uerr := uuid.Parse(parts[0]); uerr != nil {
		return "", nil, "", fmt.Errorf("the session part of the flow id is not a UUID: %q", parts[0])
	}
	if _, uerr := uuid.Parse(parts[2]); uerr != nil {
		return "", nil, "", fmt.Errorf("the root capture part of the flow id is not a UUID: %q", parts[2])
	}
	if parts[1] != "n" {
		tab, cerr := strconv.Atoi(parts[1])
		if cerr != nil {
			return "", nil, "", fmt.Errorf("the tab part of the flow id is not a number: %q", parts[1])
		}
		tabID = &tab
	}
	return parts[0], tabID, parts[2], nil
}

// ---------------------------------------------------------------------------
// GET /replay-request/{scope_target_id}/flows
// ---------------------------------------------------------------------------

type replayFlowsResponse struct {
	Flows     []FlowSummary `json:"flows"`
	Total     int           `json:"total"`
	Limit     int           `json:"limit"`
	Truncated bool          `json:"truncated"`
	Query     string        `json:"query"`
	// Present only when the query itself is the problem, matching the captures endpoint: the rest of
	// the payload is still filled in so a client that renders the shape unconditionally survives.
	Error         string `json:"error,omitempty"`
	ErrorPosition int    `json:"error_position,omitempty"`
	// detection_source keyed by flow id: "passive", "active" or "both". Derived by
	// FlowDetectionSources in flowDetectionActive.go and carried as a SIDECAR MAP rather than a field
	// on FlowSummary, so this file - the passive detector - never has to know an active one exists.
	// Absent entirely on an install that has never run active detection; the client reads a missing
	// entry as "not reported" and shows no badge, which is not the same as "passive".
	DetectionSources map[string]string `json:"detection_sources,omitempty"`
}

// GetReplayRequestFlows handles GET /replay-request/{scope_target_id}/flows.
//
// The search is the same language as the capture list, compiled by the same BuildCaptureFilter, so
// `method = POST` or `host ~ assurant` mean here exactly what they mean there. The difference is
// what a match selects: a flow is returned when ANY of its requests matched, because narrowing to a
// POST and being handed that POST alone would be the flow view failing at the one thing it is for.
func GetReplayRequestFlows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required",
			"scope_target_id must be a UUID")
		return
	}

	query := r.URL.Query().Get("q")
	limit := replayParseInt(r.URL.Query().Get("limit"), flowsDefaultLimit)
	if limit <= 0 {
		limit = flowsDefaultLimit
	}
	if limit > flowsMaxLimit {
		limit = flowsMaxLimit
	}

	// $1 is the scope target, so the filter's own placeholders start at $2.
	filter, filterArgs, err := BuildCaptureFilter(query, 2)
	if err != nil {
		var parseErr *CaptureQueryError
		payload := replayFlowsResponse{
			Flows: []FlowSummary{},
			Limit: limit,
			Query: query,
			Error: err.Error(),
		}
		if errors.As(err, &parseErr) {
			payload.ErrorPosition = parseErr.Position
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(payload)
		return
	}

	args := make([]interface{}, 0, len(filterArgs)+1)
	args = append(args, scopeTargetID)
	args = append(args, filterArgs...)

	// The filter travels as a SELECTED COLUMN rather than a WHERE clause. Removing the non-matching
	// rows would remove the context that makes the matching one a flow: the redirect it came from
	// and the navigation it belongs to are exactly the rows a narrow query excludes.
	//
	// COALESCE around it because the filter is allowed to be NULL. resp.body and size are
	// deliberately NULL for a capture whose body was never recorded, so `size < 5000` is UNKNOWN
	// rather than false on those rows; COALESCE to false reproduces what WHERE would have done.
	sqlText := fmt.Sprintf(`
		SELECT id, session_id, tab_id, COALESCE(method,''), COALESCE(url,''),
		       COALESCE(status_code,0), COALESCE(resource_type,''), COALESCE(initiator,''),
		       COALESCE(mime_type,''), timestamp, COALESCE(duration_ms,0),
		       COALESCE(octet_length(response_body),0),
		       (COALESCE(post_data,'') <> '') AS has_body,
		       COALESCE(redirect_chain,'[]'::jsonb),
		       COALESCE((%s), false) AS matched
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC
		LIMIT %d`, filter, flowScanCeiling)

	captures, err := queryFlowCaptures(sqlText, args)
	if err != nil {
		log.Printf("[REPLAY-FLOWS] Flow search failed (q=%q): %v", query, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The flow search could not be run: "+err.Error())
		return
	}

	summaries := []FlowSummary{}
	for _, flow := range segmentCaptureFlows(captures) {
		if !flowHasMatch(flow) {
			continue
		}
		summaries = append(summaries, summarizeFlow(flow))
	}

	// Newest first, tie-broken on the root capture id so two flows that started in the same
	// millisecond do not swap places between two identical requests.
	sort.SliceStable(summaries, func(i, j int) bool {
		if !summaries[i].StartedAt.Equal(summaries[j].StartedAt) {
			return summaries[i].StartedAt.After(summaries[j].StartedAt)
		}
		return summaries[i].RootCaptureID < summaries[j].RootCaptureID
	})

	total := len(summaries)
	page := summaries
	if len(page) > limit {
		page = page[:limit]
	}

	json.NewEncoder(w).Encode(replayFlowsResponse{
		Flows:            page,
		Total:            total,
		Limit:            limit,
		Truncated:        total > len(page),
		Query:            query,
		DetectionSources: FlowDetectionSources(scopeTargetID),
	})
}

func flowHasMatch(flow captureFlow) bool {
	for _, c := range flow.Captures {
		if c.Matched {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GET /replay-request/flow/{flow_id}
// ---------------------------------------------------------------------------

type replayFlowResponse struct {
	Flow  FlowSummary `json:"flow"`
	Nodes []FlowNode  `json:"nodes"`
	Edges []FlowEdge  `json:"edges"`
	// What THIS response hid. The flow summary's own shown/hidden counts always describe the default
	// filter, so they stay comparable with the list view whatever show_all was set to here.
	HiddenCount int  `json:"hidden_count"`
	ShowAll     bool `json:"show_all"`
}

// GetReplayRequestFlow handles GET /replay-request/flow/{flow_id}.
//
// There is no search parameter here on purpose. A flow shown with some of its requests removed by a
// filter is not the flow, and the whole point of the graph is that it is complete.
func GetReplayRequestFlow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionID, tabID, rootCaptureID, err := DecodeFlowID(mux.Vars(r)["flow_id"])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_flow_id", err.Error())
		return
	}

	showAll := flowParseBool(r.URL.Query().Get("show_all"))

	// The whole tab, because a flow is defined by its boundaries and the boundaries are the
	// neighbouring navigations. Loading only this flow's rows would need the segmentation that
	// loading them is for.
	//
	// IS NOT DISTINCT FROM, not =, so a NULL tab matches a NULL tab. With = it matches nothing and
	// the flow 404s.
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
		  AND scope_target_id = (SELECT scope_target_id FROM manual_crawl_captures WHERE id = $3)
		ORDER BY timestamp ASC
		LIMIT %d`, flowScanCeiling)

	// Pinning to the root capture's own scope target keeps this endpoint symmetric with the list
	// endpoint, which validates a scope_target_id from the path. A flow id carries no target, so
	// without this the detail route is keyed on session and tab alone. Session ids are UUIDs minted
	// per crawl and the ids only ever come from the scoped list, so this is not reachable through
	// the UI; it is here so that a flow can never be assembled from two targets' rows, whatever
	// calls it.
	captures, err := queryFlowCaptures(sqlText, []interface{}{sessionID, tabID, rootCaptureID})
	if err != nil {
		log.Printf("[REPLAY-FLOWS] Failed to load flow %s: %v", rootCaptureID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load the flow")
		return
	}

	for _, flow := range segmentCaptureFlows(captures) {
		if len(flow.Captures) == 0 || flow.Captures[0].ID != rootCaptureID {
			continue
		}
		nodes, edges, hidden := renderFlowGraph(flow, deriveFlowLinks(flow), showAll)
		json.NewEncoder(w).Encode(replayFlowResponse{
			Flow:        summarizeFlow(flow),
			Nodes:       nodes,
			Edges:       edges,
			HiddenCount: hidden,
			ShowAll:     showAll,
		})
		return
	}

	// Reachable without anything being broken: a capture that rooted a flow yesterday stops rooting
	// one when a redirect that lands on it arrives, and a bookmarked flow id then names nothing.
	writeJSONError(w, http.StatusNotFound, "flow_not_found",
		"No flow starts at that request. It may have been re-segmented as new captures arrived; "+
			"reload the flow list.")
}

func flowParseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// The database layer, which decides nothing
// ---------------------------------------------------------------------------

// queryFlowCaptures runs a statement shaped like the two above and fills in FlowCaptures. Both
// endpoints share it so their column lists cannot drift apart.
func queryFlowCaptures(sqlText string, args []interface{}) ([]FlowCapture, error) {
	rows, err := dbPool.Query(context.Background(), sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	captures := []FlowCapture{}
	malformedChains := 0
	for rows.Next() {
		var c FlowCapture
		var tabID *int
		var chainJSON []byte
		if err := rows.Scan(&c.ID, &c.SessionID, &tabID, &c.Method, &c.URL, &c.StatusCode,
			&c.ResourceType, &c.Initiator, &c.MimeType, &c.Timestamp, &c.DurationMs,
			&c.Size, &c.HasBody, &chainJSON, &c.Matched); err != nil {
			log.Printf("[REPLAY-FLOWS] Failed to scan capture row: %v", err)
			continue
		}
		c.TabID = tabID
		if len(chainJSON) > 0 {
			// redirect_chain is written by a browser extension and is the only column here whose
			// shape is not enforced by the schema. A row whose chain will not parse loses its
			// redirect edges and keeps everything else, rather than failing the whole request.
			if uerr := json.Unmarshal(chainJSON, &c.RedirectChain); uerr != nil {
				c.RedirectChain = nil
				malformedChains++
			}
		}
		captures = append(captures, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if malformedChains > 0 {
		log.Printf("[REPLAY-FLOWS] %d capture(s) had an unparseable redirect_chain; "+
			"their redirect edges are missing", malformedChains)
	}
	return captures, nil
}
