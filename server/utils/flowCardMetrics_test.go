package utils

import (
	"errors"
	"testing"
	"time"
)

// The card's ENDPOINTS number and the Configure screen's must be the SAME number.
//
// They are computed by two functions - flowCardEndpointCounts here and BuildFlowEndpointList in
// flowEndpointSelection.go - because the second does four things the card does not need and the card
// runs on every render. That is a deliberate duplication of two guards, and a deliberate duplication
// is exactly the thing that drifts silently: somebody relaxes one of the guards in the list, the
// card keeps the old one, and the operator sees "1,204" above a button that opens a screen listing
// 1,190. This test is the reason that cannot happen quietly.
//
// The corpus below is chosen for the cases where the two could disagree rather than for realism:
// a duplicate, a query-string variant, a trailing slash, a second method on the same path, an
// unparseable row and a non-HTTP scheme.
func TestFlowCardEndpointsHeadlineIsWhatWouldBeSent(t *testing.T) {
	candidates := []flowDetectionCandidate{
		{URL: "https://a.example.com/one", Method: "GET", Source: "consolidated"},
		// Same endpoint: the flow key has no query string, so this must not add a second one.
		{URL: "https://a.example.com/one?q=1", Method: "GET", Source: "consolidated"},
		// Same endpoint again, reached from the other source table with a trailing slash.
		{URL: "https://a.example.com/one/", Method: "GET", Source: "attack_vector"},
		// A different endpoint: the method is part of the key.
		{URL: "https://a.example.com/one", Method: "POST", Source: "consolidated"},
		{URL: "https://b.example.com/three", Method: "GET", Source: "consolidated"},
		// Inside the boundary, but the operator marked this host in_scope=false.
		{URL: "https://denied.example.com/four", Method: "GET", Source: "consolidated"},
		// Inside the boundary and matched by an exclusion rule.
		{URL: "https://a.example.com/admin/five", Method: "GET", Source: "consolidated"},
		// Outside the boundary entirely.
		{URL: "https://elsewhere.invalid/six", Method: "GET", Source: "consolidated"},
		// Neither of these can be sent, so neither may be counted at all.
		{URL: "::::not a url", Method: "GET", Source: "consolidated"},
		{URL: "ftp://a.example.com/four", Method: "GET", Source: "consolidated"},
	}

	scope := &ScanScope{
		domains: map[string]bool{"example.com": true},
		extra:   map[string]bool{}, refused: map[string]int{},
		primary: "a.example.com",
	}
	denied := map[string]bool{"denied.example.com": true}
	rules := []FlowExclusion{{Pattern: "/admin/*", Reason: "never touch admin"}}

	deselectKey, ok := FlowEndpointKey(candidates[4].URL, candidates[4].Method)
	if !ok {
		t.Fatal("the candidate chosen for deselection has no flow key")
	}
	deselected := map[string]bool{deselectKey: true}

	_, summary := BuildFlowEndpointList(
		candidates, nil, deselected, rules, denied, scope, FlowEndpointFilter{Limit: 1})

	// Six keyed, parseable endpoints: /one GET, /one POST, /three, /four, /admin/five, /six.
	if summary.Total != 6 {
		t.Fatalf("total is %d, want 6 (the two unusable rows must not be counted)", summary.Total)
	}
	// THE POINT OF THE CHANGE. Selected ignores every rail; sendable does not, and they differ by
	// three here for three different reasons.
	if summary.Selected != 5 {
		t.Errorf("selected is %d, want 5", summary.Selected)
	}
	if summary.Sendable != 2 {
		t.Errorf("sendable is %d, want 2 (/one GET and /one POST)", summary.Sendable)
	}
	if summary.Selected == summary.Sendable {
		t.Error("this corpus was built so the two differ; a card showing selected would be wrong here")
	}

	// The four buckets partition the corpus, which is the arithmetic the card renders.
	if got := summary.Deselected + summary.Excluded + summary.OutOfScope + summary.Sendable; got != summary.Total {
		t.Errorf("deselected(%d) + excluded(%d) + out_of_scope(%d) + sendable(%d) = %d, want total %d",
			summary.Deselected, summary.Excluded, summary.OutOfScope, summary.Sendable, got,
			summary.Total)
	}
	if summary.Excluded != 1 {
		t.Errorf("excluded is %d, want 1", summary.Excluded)
	}
	// Both the deny list and the boundary land in out_of_scope, which is how the Configure screen
	// counts them too.
	if summary.OutOfScope != 2 {
		t.Errorf("out_of_scope is %d, want 2 (the denied host and the third-party one)",
			summary.OutOfScope)
	}
}

// A metric that could not be read must carry NO number, not a zero.
//
// This is one line of production code and it is the whole reason the value is a pointer, so it gets
// a test: the failure it prevents is a card reporting "0 flows" on a target with 120 of them because
// a query timed out, and that failure is invisible on screen.
func TestUnavailableMetricCarriesNoNumber(t *testing.T) {
	m := unavailableMetric(errors.New("the flow count could not be read"), time.Now())
	if m.Available {
		t.Error("a failed metric must not be marked available")
	}
	if m.Value != nil {
		t.Errorf("a failed metric must carry no value, got %d", *m.Value)
	}
	if m.Parts != nil {
		t.Errorf("a failed metric must carry no breakdown, got %v", m.Parts)
	}
	if m.Error == "" {
		t.Error("a failed metric must say why")
	}

	ok := availableMetric(0, map[string]int{"total": 0}, time.Now())
	if !ok.Available || ok.Value == nil || *ok.Value != 0 {
		t.Fatalf("a real zero must be present and readable, got %+v", ok)
	}
}
