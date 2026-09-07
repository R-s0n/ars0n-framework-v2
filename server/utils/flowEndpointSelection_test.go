package utils

import (
	"os"
	"strings"
	"testing"
)

// Endpoint selection decides which endpoints an unattended scanner sends real traffic to. Every test
// here is written against pure functions for the same reason the rest of the active-detection tests
// are: a rule that can only be exercised by pointing the scanner at somebody's production is a rule
// nobody will ever check.

func selCandidate(url, method, source string) flowDetectionCandidate {
	return flowDetectionCandidate{URL: url, Method: method, Source: source}
}

func selKey(t *testing.T, url, method string) string {
	t.Helper()
	k, ok := FlowEndpointKey(url, method)
	if !ok {
		t.Fatalf("%s %s should have produced a key", method, url)
	}
	return k
}

func selRow(rows []FlowEndpointRow, url string) *FlowEndpointRow {
	for i := range rows {
		if rows[i].URL == url {
			return &rows[i]
		}
	}
	return nil
}

func selList(t *testing.T, cands []flowDetectionCandidate, deselected map[string]bool,
	rules []FlowExclusion, denied map[string]bool, scope *ScanScope,
) ([]FlowEndpointRow, FlowEndpointSummary) {
	t.Helper()
	return BuildFlowEndpointList(cands, nil, deselected, rules, denied, scope, FlowEndpointFilter{})
}

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

// The key has to survive a re-crawl, which means it has to be immune to the half-dozen ways the six
// discovery sources spell the same URL. It is derived through CanonicalizeEndpoint precisely so that
// this list stays in step with the endpoint list rather than drifting from it.
func TestEndpointSelectionKeyIsStableAcrossSpellings(t *testing.T) {
	base := selKey(t, "https://app.example.com/account/profile", "GET")

	same := []struct{ url, method string }{
		{"https://app.example.com/account/profile/", "GET"},    // trailing slash
		{"https://app.example.com//account//profile", "GET"},   // duplicate slashes
		{"https://app.example.com/account/./profile", "GET"},   // dot segment
		{"https://app.example.com/x/../account/profile", ""},   // dot-dot, and an empty method is GET
		{"http://app.example.com/account/profile", "get"},      // scheme and case of the verb
		{"https://APP.example.com:443/account/profile", "GET"}, // host case and the default port
		// The query string is not part of the key, because detection strips it before sending. Fifty
		// rows of /search?q=<fifty things> are ONE request and must be one selectable row.
		{"https://app.example.com/account/profile?utm_source=x&id=7", "GET"},
	}
	for _, s := range same {
		if got := selKey(t, s.url, s.method); got != base {
			t.Errorf("%s %s produced %q, want the same key as the canonical form %q",
				s.method, s.url, got, base)
		}
	}

	different := []struct{ url, method string }{
		{"https://app.example.com/account/Profile", "GET"}, // case IS identity: the proxy/origin bypass
		{"https://app.example.com/account/profiles", "GET"},
		{"https://app.example.com/account/profile", "POST"},
		{"https://api.example.com/account/profile", "GET"},
		{"https://app.example.com:8443/account/profile", "GET"}, // a non-default port is another service
	}
	for _, d := range different {
		if got := selKey(t, d.url, d.method); got == base {
			t.Errorf("%s %s must not collapse into the key for the canonical form", d.method, d.url)
		}
	}

	// Readable, so a deselection can be recognised in a log line and found with a SQL LIKE.
	if !strings.HasPrefix(base, "GET|app.example.com|/account/profile") {
		t.Errorf("the key must stay readable, got %q", base)
	}
}

func TestEndpointSelectionKeyRefusesUnusableRows(t *testing.T) {
	for _, bad := range []string{"", "   ", "mailto:someone@example.com", "javascript:alert(1)",
		"data:text/html,x", "not a url at all"} {
		if _, ok := FlowEndpointKey(bad, "GET"); ok {
			t.Errorf("%q must not produce a selection key", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// The default
// ---------------------------------------------------------------------------

// THE DEFAULT IS SELECTED. With no rows in flow_endpoint_deselections, every endpoint is in.
func TestEndpointSelectionDefaultsToSelectedWhenNoRowExists(t *testing.T) {
	scope := flowDetectScope("example.com")
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
		selCandidate("https://api.example.com/v1/orders", "GET", "attack_vector"),
	}

	rows, summary := selList(t, cands, nil, nil, nil, scope)

	if summary.Total != 3 || summary.Selected != 3 || summary.Deselected != 0 || summary.Sendable != 3 {
		t.Fatalf("an unconfigured target must have everything selected, got %+v", summary)
	}
	for _, r := range rows {
		if !r.Selected || !r.Sendable {
			t.Errorf("%s must default to selected and sendable, got selected=%v sendable=%v (%s)",
				r.URL, r.Selected, r.Sendable, r.NotSentReason)
		}
	}
}

// Deselect, then reselect, and the endpoint is back exactly as it was. The reselect is a DELETE of
// the deselection row, not a second flag, so there is no state left over to go stale.
func TestEndpointSelectionDeselectThenReselect(t *testing.T) {
	scope := flowDetectScope("example.com")
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
	}
	key := selKey(t, "https://app.example.com/a", "GET")

	rows, summary := selList(t, cands, map[string]bool{key: true}, nil, nil, scope)
	if summary.Selected != 1 || summary.Deselected != 1 || summary.Sendable != 1 {
		t.Fatalf("one deselection should leave one selected, got %+v", summary)
	}
	a := selRow(rows, "https://app.example.com/a")
	if a == nil || a.Selected || a.NotSentReason != "deselected" {
		t.Fatalf("the deselected endpoint must say so, got %+v", a)
	}

	// Reselecting is removing the row.
	rows, summary = selList(t, cands, map[string]bool{}, nil, nil, scope)
	if summary.Selected != 2 || summary.Deselected != 0 || summary.Sendable != 2 {
		t.Fatalf("reselecting must restore the default, got %+v", summary)
	}
	if a = selRow(rows, "https://app.example.com/a"); a == nil || !a.Selected || a.NotSentReason != "" {
		t.Fatalf("the reselected endpoint must be clean, got %+v", a)
	}
}

// THE WHOLE POINT OF THE MODEL, AND THE REASON THE TABLE STORES THE NEGATIVE.
//
// The operator configures against a corpus, deselects some of it, and then crawls again. The
// endpoints that did not exist when they configured must arrive SELECTED. If this test ever fails,
// somebody has changed the table to store selections and the framework has quietly stopped scanning
// every endpoint discovered after the operator last opened this screen - with nothing on the screen
// to say so, and the run still reporting "completed".
func TestEndpointSelectionNewlyDiscoveredEndpointIsSelectedAfterOthersWereDeselected(t *testing.T) {
	scope := flowDetectScope("example.com")

	before := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
	}
	deselected := map[string]bool{
		selKey(t, "https://app.example.com/a", "GET"): true,
		selKey(t, "https://app.example.com/b", "GET"): true,
	}

	_, summary := selList(t, before, deselected, nil, nil, scope)
	if summary.Sendable != 0 {
		t.Fatalf("both endpoints were deselected, so nothing should be sendable, got %+v", summary)
	}

	// The crawl runs again and finds three more. The deselection set is UNCHANGED.
	after := append(append([]flowDetectionCandidate{}, before...),
		selCandidate("https://app.example.com/c", "GET", "consolidated"),
		selCandidate("https://app.example.com/d", "GET", "consolidated"),
		selCandidate("https://api.example.com/v2/new", "GET", "consolidated"),
	)

	rows, summary := selList(t, after, deselected, nil, nil, scope)
	if summary.Total != 5 || summary.Deselected != 2 || summary.Selected != 3 || summary.Sendable != 3 {
		t.Fatalf("newly discovered endpoints must arrive selected, got %+v", summary)
	}
	for _, url := range []string{
		"https://app.example.com/c", "https://app.example.com/d", "https://api.example.com/v2/new",
	} {
		r := selRow(rows, url)
		if r == nil || !r.Selected || !r.Sendable {
			t.Errorf("%s was discovered after the operator configured and must be selected, got %+v", url, r)
		}
	}
}

// ---------------------------------------------------------------------------
// Bulk set
// ---------------------------------------------------------------------------

// The bulk key normaliser is what makes select-all one call rather than a thousand, and the dedupe is
// load-bearing rather than cosmetic: the INSERT branch feeds unnest() into ON CONFLICT DO NOTHING,
// and Postgres refuses a statement that would touch the same row twice. A duplicate key in the list
// would fail the whole call and deselect nothing.
func TestEndpointSelectionBulkKeysAreDedupedAndOrdered(t *testing.T) {
	got := normalizeFlowSelectionKeys([]string{
		"GET|app.example.com|/a",
		"  GET|app.example.com|/b  ",
		"GET|app.example.com|/a",
		"",
		"   ",
		"GET|app.example.com|/c",
		"GET|app.example.com|/b",
	})
	want := []string{
		"GET|app.example.com|/a",
		"GET|app.example.com|/b",
		"GET|app.example.com|/c",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (order must be preserved)", got, want)
		}
	}
	if len(normalizeFlowSelectionKeys(nil)) != 0 {
		t.Error("an empty list must stay empty rather than becoming a statement")
	}
}

// A bulk deselect of fifty rows that all collapse to one endpoint is one key, not fifty. This is the
// query-stripping key doing its job at the point it matters most.
func TestEndpointSelectionCollapsesQueryVariantsToOneKey(t *testing.T) {
	keys := map[string]bool{}
	for _, q := range []string{"?q=alpha", "?q=beta", "?q=gamma&page=2", ""} {
		keys[selKey(t, "https://app.example.com/search"+q, "GET")] = true
	}
	if len(keys) != 1 {
		t.Fatalf("every query variant of /search is one request and must be one key, got %d: %v",
			len(keys), keys)
	}
}

// ---------------------------------------------------------------------------
// Selection against the rails
// ---------------------------------------------------------------------------

// Selected and sendable are separate, and a selected endpoint an exclusion refuses is still refused.
// Re-selecting must never be able to overturn a rule whose reason is "this endpoint texts customers".
func TestEndpointSelectionCannotOverturnAnExclusion(t *testing.T) {
	scope := flowDetectScope("example.com")
	rules := []FlowExclusion{{
		Pattern: "/account/verify",
		Reason:  "dispatches a one-time code to the account owner",
	}}
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/account/verify", "GET", "consolidated"),
		selCandidate("https://app.example.com/account/profile", "GET", "consolidated"),
	}

	rows, summary := selList(t, cands, nil, rules, nil, scope)

	verify := selRow(rows, "https://app.example.com/account/verify")
	if verify == nil {
		t.Fatal("the excluded endpoint must still be listed, so the operator can see why it is refused")
	}
	if !verify.Selected {
		t.Error("the operator did not deselect it; selection is their choice and the exclusion is a rail")
	}
	if verify.Sendable {
		t.Fatal("an excluded endpoint must never be sendable, whatever its selection says")
	}
	if verify.NotSentReason != "exclusion" || verify.Pattern != "/account/verify" ||
		verify.Detail != "dispatches a one-time code to the account owner" {
		t.Errorf("the rule and its reason must reach the screen, got %+v", verify)
	}
	if summary.Excluded != 1 || summary.Sendable != 1 {
		t.Errorf("counts must separate excluded from sendable, got %+v", summary)
	}
}

// An out-of-scope host is listed and refused, and a host the operator marked in_scope=false is
// refused for its own reason rather than being folded into the boundary.
func TestEndpointSelectionReportsScopeRefusalsSeparately(t *testing.T) {
	scope := flowDetectScope("example.com")
	denied := map[string]bool{"analytics.example.com": true}
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://analytics.example.com/collect", "GET", "consolidated"),
		selCandidate("https://somebody-else.com/x", "GET", "consolidated"),
	}

	rows, summary := selList(t, cands, nil, nil, denied, scope)

	if r := selRow(rows, "https://analytics.example.com/collect"); r == nil ||
		r.NotSentReason != "host_excluded" || r.Sendable {
		t.Errorf("an in_scope=false host must be refused on its own terms, got %+v", r)
	}
	if r := selRow(rows, "https://somebody-else.com/x"); r == nil ||
		r.NotSentReason != "out_of_scope" || r.Sendable {
		t.Errorf("a host outside the boundary must be refused, got %+v", r)
	}
	if summary.OutOfScope != 2 || summary.Sendable != 1 {
		t.Errorf("got %+v", summary)
	}
}

// THE ARITHMETIC ON SCREEN. Deselected, excluded, out-of-scope and sendable partition the corpus, so
// the four add up to the total and an operator can reconcile what they are looking at. Selected is
// deliberately not one of the four: it overlaps them, because an endpoint can be selected and still
// refused by a rail.
func TestEndpointSelectionSummaryPartitionsTheCorpus(t *testing.T) {
	scope := flowDetectScope("example.com")
	denied := map[string]bool{"analytics.example.com": true}
	rules := []FlowExclusion{{Pattern: "/account/verify", Reason: "texts the customer"}}
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
		selCandidate("https://app.example.com/account/verify", "GET", "consolidated"),
		selCandidate("https://analytics.example.com/collect", "GET", "consolidated"),
		selCandidate("https://somebody-else.com/x", "GET", "consolidated"),
	}
	deselected := map[string]bool{selKey(t, "https://app.example.com/b", "GET"): true}

	_, s := selList(t, cands, deselected, rules, denied, scope)

	if s.Total != 5 {
		t.Fatalf("total should be 5, got %d", s.Total)
	}
	if s.Deselected+s.Excluded+s.OutOfScope+s.Sendable != s.Total {
		t.Fatalf("the four buckets must partition the corpus: %+v", s)
	}
	if s.Selected != s.Total-s.Deselected {
		t.Fatalf("selected is total minus deselected, got %+v", s)
	}
	if s.Deselected != 1 || s.Excluded != 1 || s.OutOfScope != 2 || s.Sendable != 1 {
		t.Fatalf("got %+v", s)
	}
}

// A deselection is reported ahead of the rails, so each endpoint carries exactly one reason and the
// arithmetic above holds. The operator's own choice is the most direct explanation of why something
// is not being sent.
func TestEndpointSelectionDeselectionIsReportedAheadOfTheRails(t *testing.T) {
	scope := flowDetectScope("example.com")
	rules := []FlowExclusion{{Pattern: "/account/verify", Reason: "texts the customer"}}
	url := "https://app.example.com/account/verify"
	cands := []flowDetectionCandidate{selCandidate(url, "GET", "consolidated")}
	deselected := map[string]bool{selKey(t, url, "GET"): true}

	rows, s := selList(t, cands, deselected, rules, nil, scope)
	if r := selRow(rows, url); r == nil || r.NotSentReason != "deselected" {
		t.Errorf("a deselected endpoint reports as deselected, got %+v", r)
	}
	if s.Deselected != 1 || s.Excluded != 0 {
		t.Errorf("one endpoint must be counted once, got %+v", s)
	}
}

// One endpoint found by both tables is one row, carrying both sources, not two rows the operator has
// to deselect twice.
func TestEndpointSelectionMergesSourcesIntoOneRow(t *testing.T) {
	scope := flowDetectScope("example.com")
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/a/", "GET", "attack_vector"),
	}
	rows, s := selList(t, cands, nil, nil, nil, scope)
	if s.Total != 1 || len(rows) != 1 {
		t.Fatalf("the same endpoint from two tables is one row, got %d", s.Total)
	}
	if len(rows[0].Sources) != 2 ||
		!flowListContains(rows[0].Sources, "consolidated") ||
		!flowListContains(rows[0].Sources, "attack_vector") {
		t.Errorf("both sources must be recorded, got %v", rows[0].Sources)
	}
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

// Substring filtering, and it is a substring filter on purpose. BuildCaptureFilter compiles to SQL
// against manual_crawl_captures' own columns; this list is assembled in Go from two other tables, so
// there is no table for that predicate to run against and a second in-memory evaluator would answer
// the same query differently from the SQL one.
func TestEndpointSelectionFilters(t *testing.T) {
	scope := flowDetectScope("example.com")
	rules := []FlowExclusion{{Pattern: "/account/verify", Reason: "texts the customer"}}
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/account/profile", "GET", "consolidated"),
		selCandidate("https://app.example.com/account/verify", "GET", "consolidated"),
		selCandidate("https://api.example.com/v1/orders", "POST", "attack_vector"),
	}
	deselected := map[string]bool{selKey(t, "https://api.example.com/v1/orders", "POST"): true}

	// wantReturned is the size of this page; wantMatched is how many rows the filter selected before
	// pagination. THEY ARE ASSERTED SEPARATELY on purpose. Collapsing them is how a field named like a
	// total ends up reporting a page size - a defect this codebase has already shipped four times, on
	// four different screens.
	check := func(f FlowEndpointFilter, wantReturned, wantMatched int, label string) {
		t.Helper()
		rows, s := BuildFlowEndpointList(cands, nil, deselected, rules, nil, scope, f)
		if len(rows) != wantReturned {
			t.Errorf("%s returned %d rows, want %d", label, len(rows), wantReturned)
		}
		if s.Total != 3 {
			t.Errorf("%s: total must stay the corpus total, not the page, got %d", label, s.Total)
		}
		if s.Matched != wantMatched {
			t.Errorf("%s: matched must count the filter, got %d want %d", label, s.Matched, wantMatched)
		}
		if s.Returned != len(rows) {
			t.Errorf("%s: returned must count this page, got %+v", label, s)
		}
	}

	check(FlowEndpointFilter{Query: "account"}, 2, 2, "q=account")
	check(FlowEndpointFilter{Query: "API.EXAMPLE"}, 1, 1, "case-insensitive host")
	check(FlowEndpointFilter{Query: "post"}, 1, 1, "method")
	check(FlowEndpointFilter{Source: "attack_vector"}, 1, 1, "source")
	check(FlowEndpointFilter{State: "deselected"}, 1, 1, "state=deselected")
	check(FlowEndpointFilter{State: "selected"}, 2, 2, "state=selected")
	check(FlowEndpointFilter{State: "excluded"}, 1, 1, "state=excluded")
	check(FlowEndpointFilter{State: "sendable"}, 1, 1, "state=sendable")
	check(FlowEndpointFilter{State: "not_sendable"}, 2, 2, "state=not_sendable")
	check(FlowEndpointFilter{Limit: 2}, 2, 3, "limit")
	check(FlowEndpointFilter{Offset: 2}, 1, 3, "offset")
	check(FlowEndpointFilter{Offset: 99}, 0, 3, "offset past the end")
}

// ---------------------------------------------------------------------------
// The planner honouring the selection
// ---------------------------------------------------------------------------

// A deselected endpoint is not planned, and it is reported as skipped WITH the reason, so the dry
// run's arithmetic reads total minus deselected minus excluded equals sent.
func TestFlowDetectionPlannerHonoursDeselection(t *testing.T) {
	scope := flowDetectScope("example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{})
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
		selCandidate("https://app.example.com/c", "GET", "consolidated"),
	}
	deselected := map[string]bool{selKey(t, "https://app.example.com/b", "GET"): true}

	kept, skips := PartitionFlowCandidatesBySelection(cands, deselected, cfg.IncludeQuery)
	if len(kept) != 2 {
		t.Fatalf("the deselected endpoint must not reach the planner, got %d kept", len(kept))
	}
	if len(skips) != 1 || skips[0].Reason != "deselected" ||
		skips[0].URL != "https://app.example.com/b" || skips[0].Method != "GET" {
		t.Fatalf("the deselection must be reported with a reason, got %+v", skips)
	}
	if skips[0].Detail == "" {
		t.Error("a skip with no detail is a skip the operator cannot act on")
	}

	plan := buildFlowDetectionPlan(kept, cfg, nil, nil, scope)
	if plan.RequestCount != 2 {
		t.Fatalf("two endpoints should be planned, got %d", plan.RequestCount)
	}
	if flowDetectTargeted(plan, "https://app.example.com/b") {
		t.Error("a deselected endpoint must never be a target")
	}
}

// THE BUDGET ORDERING. Deselection runs BEFORE the plan is built, not after, so a deselected
// endpoint cannot consume a slot in the run's request budget and push a wanted one into over_budget.
// Getting this backwards produces a run that sends its whole budget at endpoints the operator took
// out while the ones they left in are reported as "budget reached".
func TestFlowDetectionPlannerAppliesDeselectionBeforeTheBudgetCut(t *testing.T) {
	scope := flowDetectScope("example.com")
	cfg := flowDetectCfg(t, FlowDetectionConfig{MaxRequests: 2})

	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/aaa", "GET", "consolidated"),
		selCandidate("https://app.example.com/bbb", "GET", "consolidated"),
		selCandidate("https://app.example.com/ccc", "GET", "consolidated"),
		selCandidate("https://app.example.com/ddd", "GET", "consolidated"),
	}
	// The first two alphabetically are the ones the operator does NOT want.
	deselected := map[string]bool{
		selKey(t, "https://app.example.com/aaa", "GET"): true,
		selKey(t, "https://app.example.com/bbb", "GET"): true,
	}

	kept, _ := PartitionFlowCandidatesBySelection(cands, deselected, cfg.IncludeQuery)
	plan := buildFlowDetectionPlan(kept, cfg, nil, nil, scope)

	if plan.RequestCount != 2 {
		t.Fatalf("the budget of 2 should be filled with the two selected endpoints, got %d", plan.RequestCount)
	}
	for _, want := range []string{"https://app.example.com/ccc", "https://app.example.com/ddd"} {
		if !flowDetectTargeted(plan, want) {
			t.Errorf("%s was selected and within budget, so it must be a target", want)
		}
	}
	if s := flowDetectSkipFor(plan, "https://app.example.com/ccc"); s != nil && s.Reason == "over_budget" {
		t.Error("a selected endpoint must not be pushed out of the budget by a deselected one")
	}
}

// Every query variant of a deselected endpoint is one skip line, not fifty, matching the way the
// planner deduplicates its targets.
func TestFlowDetectionPlannerReportsOneDeselectionPerEndpoint(t *testing.T) {
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/search?q=alpha", "GET", "consolidated"),
		selCandidate("https://app.example.com/search?q=beta", "GET", "consolidated"),
		selCandidate("https://app.example.com/search?q=gamma", "GET", "consolidated"),
	}
	deselected := map[string]bool{selKey(t, "https://app.example.com/search", "GET"): true}

	kept, skips := PartitionFlowCandidatesBySelection(cands, deselected, false)
	if len(kept) != 0 {
		t.Fatalf("every variant of a deselected endpoint is deselected, got %d kept", len(kept))
	}
	if len(skips) != 1 {
		t.Fatalf("fifty query variants are one request and must be one skip line, got %d", len(skips))
	}
	if skips[0].URL != "https://app.example.com/search" {
		t.Errorf("the skip must show the URL that would have been sent, got %q", skips[0].URL)
	}
}

// A candidate whose URL cannot produce a key is KEPT rather than silently dropped, so the planner can
// report it as unusable_url where the operator can see it. A selection filter that swallows rows it
// does not understand is a filter that hides corpus corruption.
func TestFlowDetectionPlannerKeepsUnkeyableCandidates(t *testing.T) {
	cands := []flowDetectionCandidate{
		selCandidate("mailto:someone@example.com", "GET", "consolidated"),
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
	}
	deselected := map[string]bool{selKey(t, "https://app.example.com/a", "GET"): true}

	kept, skips := PartitionFlowCandidatesBySelection(cands, deselected, false)
	if len(kept) != 1 || kept[0].URL != "mailto:someone@example.com" {
		t.Fatalf("the unkeyable row must reach the planner, got %+v", kept)
	}
	if len(skips) != 1 {
		t.Fatalf("only the deselected row is a deselection skip, got %+v", skips)
	}
}

// With nothing deselected, the candidate list must pass through untouched. A pre-pass that reorders
// or drops rows on the common path would change what every unconfigured target scans.
func TestFlowDetectionPlannerPassesThroughWhenNothingIsDeselected(t *testing.T) {
	cands := []flowDetectionCandidate{
		selCandidate("https://app.example.com/a", "GET", "consolidated"),
		selCandidate("https://app.example.com/b", "GET", "consolidated"),
	}
	for _, d := range []map[string]bool{nil, {}} {
		kept, skips := PartitionFlowCandidatesBySelection(cands, d, false)
		if len(kept) != 2 || len(skips) != 0 {
			t.Fatalf("an unconfigured target must be untouched, got %d kept / %d skipped", len(kept), len(skips))
		}
		if kept[0].URL != cands[0].URL || kept[1].URL != cands[1].URL {
			t.Error("order must be preserved")
		}
	}
}

// ---------------------------------------------------------------------------
// Asserted against the source
// ---------------------------------------------------------------------------

// The planner must consult the selection BEFORE it builds the plan. This is asserted against the
// source because the consequence - a budget spent on deselected endpoints - only shows up on a live
// target with more endpoints than budget, which is where it is most expensive to discover.
func TestFlowDetectionPlanConsultsSelectionBeforeBuildingThePlan(t *testing.T) {
	raw, err := os.ReadFile("flowDetectionActive.go")
	if err != nil {
		t.Fatalf("could not read the planner: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, "func PlanFlowDetection(")
	if start < 0 {
		t.Fatal("PlanFlowDetection not found")
	}
	body := src[start:]
	partitionAt := strings.Index(body, "PartitionFlowCandidatesBySelection(")
	buildAt := strings.Index(body, "buildFlowDetectionPlan(")
	if partitionAt < 0 {
		t.Fatal("PlanFlowDetection must apply the operator's endpoint selection")
	}
	if buildAt < 0 || partitionAt > buildAt {
		t.Error("the selection must be applied before the plan is built, or deselected endpoints " +
			"consume the run's request budget and the selected ones are cut as over_budget")
	}
	if !strings.Contains(body, "LoadFlowEndpointDeselections(") {
		t.Error("the selection must be read from the database, not assumed empty")
	}
	// Fail closed. A selection that could not be read must stop the run, exactly as the exclusion
	// list does, rather than degrading into "everything is selected".
	if !strings.Contains(body, "the endpoint selection could not be read, so no run may start") {
		t.Error("a failed read of the selection must refuse the run rather than defaulting")
	}
}
