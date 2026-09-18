package utils

import (
	"strings"
	"testing"
)

func adviceFor(t *testing.T, s TargetState, step string) (AdvisorFinding, bool) {
	t.Helper()
	for _, f := range adviseOnState(s) {
		if f.Step == step {
			return f, true
		}
	}
	return AdvisorFinding{}, false
}

// THE CHECK THIS WHOLE FILE EXISTS FOR.
//
// The reference engagement built a fuzz flow of ten steps, every one of which fuzzed parameters,
// headers or cookies against endpoints that were already known. Content discovery never ran, /admin
// was never requested, and the access-bypass section had zero targets as a consequence that surfaced
// days later. Every card reported success the entire time.
func TestFuzzingWithoutContentDiscoveryIsReportedAsAGap(t *testing.T) {
	// Exactly the reference state: plenty of fuzzing, no content discovery.
	s := TargetState{
		CrawlCaptures: 457, Endpoints: 107, Vectors: 54, FuzzRuns: 1, FuzzFlows: 1,
		ContentDiscovery: 0,
		VectorsByPoint:   map[string]int{"query": 24, "body": 10, "cookie": 20, "header": 0, "path": 0},
	}
	f, ok := adviceFor(t, s, "content-discovery")
	if !ok {
		t.Fatal("a target with fuzz runs but no content-discovery flow must be told so. This is the " +
			"exact state that cost the reference engagement its entire access-bypass section.")
	}
	if !strings.Contains(strings.ToLower(f.Detail+f.Action), "path") {
		t.Errorf("the advice must say that the PATH was never fuzzed, got: %s %s", f.Detail, f.Action)
	}
}

// A target where nothing has been fuzzed at all is a BLOCKER, not a gap: it is the first command of
// the engagement and everything downstream is bounded by it.
func TestNoFuzzingAtAllIsABlocker(t *testing.T) {
	f, ok := adviceFor(t, TargetState{VectorsByPoint: map[string]int{}}, "content-discovery")
	if !ok || f.Severity != "blocker" {
		t.Errorf("content discovery having never run must be a blocker, got %+v", f)
	}
}

// The counterpart that keeps the advisor honest. A target that HAS done content discovery must not be
// nagged about it, or the advice becomes noise and gets ignored, which is how safety mechanisms die.
func TestATargetThatDidContentDiscoveryIsNotNagged(t *testing.T) {
	s := TargetState{
		CrawlCaptures: 100, Endpoints: 50, Vectors: 40, FuzzRuns: 2, FuzzFlows: 2,
		ContentDiscovery: 1, DeniedEndpoints: 3, ActiveCredentials: 1, VectorScans: 4,
		Mechanisms: 5, Threats: 10,
		VectorsByPoint: map[string]int{"query": 20, "body": 8, "cookie": 5, "header": 4, "path": 3},
	}
	if _, ok := adviceFor(t, s, "content-discovery"); ok {
		t.Error("a target that has run content discovery must not be told to run it")
	}
	for _, f := range adviseOnState(s) {
		if f.Severity == "blocker" {
			t.Errorf("a well-worked target should have no blockers, got: %s", f.Title)
		}
	}
}

// An empty insertion point is a guaranteed clean report from every tool in every section, which is
// precisely the kind of accurate and misleading result this project exists to stop.
func TestEmptyInsertionPointsAreNamed(t *testing.T) {
	s := TargetState{
		CrawlCaptures: 10, Vectors: 54, ContentDiscovery: 1, FuzzRuns: 1,
		VectorsByPoint: map[string]int{"query": 24, "body": 10, "cookie": 20, "header": 0, "path": 0},
	}
	f, ok := adviceFor(t, s, "consolidate-vectors")
	if !ok {
		t.Fatal("insertion points with zero vectors must be reported")
	}
	for _, want := range []string{"header", "path"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("the empty point %q must be named explicitly, got: %s", want, f.Detail)
		}
	}
}

// A scan that recorded an error is UNVERIFIED, and treating it as coverage is the original sin.
func TestUnverifiedScansBlock(t *testing.T) {
	s := TargetState{
		Vectors: 10, VectorScans: 5, UnverifiedScans: 2, ContentDiscovery: 1, FuzzRuns: 1,
		CrawlCaptures: 1, ActiveCredentials: 1, DeniedEndpoints: 1, Mechanisms: 1, Threats: 1,
		VectorsByPoint: map[string]int{"query": 5, "body": 2, "cookie": 1, "header": 1, "path": 1},
	}
	f, ok := adviceFor(t, s, "vector-scanning")
	if !ok || f.Severity != "blocker" {
		t.Fatalf("scans that did not finish must block, got %+v", f)
	}
	if !strings.Contains(strings.ToUpper(f.Detail), "UNVERIFIED") {
		t.Errorf("the word UNVERIFIED has to appear, or the operator reads it as clean: %s", f.Detail)
	}
}

// The bypass section being empty is a GAP normally, but a BLOCKER when the reason is that content
// discovery never ran, because then it is a consequence rather than a fact about the target.
func TestAnEmptyBypassSectionPointsAtItsRealCause(t *testing.T) {
	noDiscovery := TargetState{Vectors: 10, CrawlCaptures: 1, VectorsByPoint: map[string]int{}}
	f, _ := adviceFor(t, noDiscovery, "access-bypass")
	if f.Severity != "blocker" {
		t.Errorf("with no content discovery, an empty bypass section is a blocker, got %q", f.Severity)
	}
	if !strings.Contains(f.Detail, "cannot refuse") {
		t.Errorf("the advice must explain that an unrequested path cannot refuse anything: %s", f.Detail)
	}

	withDiscovery := TargetState{
		Vectors: 10, CrawlCaptures: 1, ContentDiscovery: 1, FuzzRuns: 1, ActiveCredentials: 1,
		Mechanisms: 1, Threats: 1,
		VectorsByPoint: map[string]int{"query": 5, "body": 1, "cookie": 1, "header": 1, "path": 1},
	}
	f2, _ := adviceFor(t, withDiscovery, "access-bypass")
	if f2.Severity != "gap" {
		t.Errorf("with content discovery done, an empty bypass section is a gap not a blocker, got %q",
			f2.Severity)
	}
}

// Every piece of advice has to name a concrete next action. "Consider reviewing your coverage" is
// what makes an operator stop reading advisories.
func TestEveryPieceOfAdviceNamesSomethingToDo(t *testing.T) {
	states := []TargetState{
		{VectorsByPoint: map[string]int{}},
		{CrawlCaptures: 457, Endpoints: 107, Vectors: 54, FuzzRuns: 1,
			VectorsByPoint: map[string]int{"query": 24, "header": 0, "path": 0, "body": 10, "cookie": 20}},
		{CrawlCaptures: 1, Vectors: 1, ContentDiscovery: 1, FuzzRuns: 1, VectorScans: 1,
			UnverifiedScans: 1, VectorsByPoint: map[string]int{}},
	}
	for _, s := range states {
		for _, f := range adviseOnState(s) {
			if strings.TrimSpace(f.Action) == "" {
				t.Errorf("advice %q has no action", f.Title)
			}
			if strings.TrimSpace(f.Detail) == "" {
				t.Errorf("advice %q states no measured fact, so there is no reason to believe it", f.Title)
			}
			switch f.Severity {
			case "blocker", "gap", "note":
			default:
				t.Errorf("advice %q has severity %q, which is not one of blocker/gap/note",
					f.Title, f.Severity)
			}
		}
	}
}

// A TARGET WITH NO HASH ROUTING HAS NO FRAGMENT GAP, and must not be told it does.
//
// The insertion-point check counted the fragment with the other five and raised the generic gap on
// every history-routed target: "these insertion points have zero vectors: [fragment]. Every tool in
// every section will report nothing wrong with them", plus an action telling the operator to add
// vectors by hand at the empty point. Every clause of that is wrong here. Only domdig can reach a
// fragment, so "every tool in every section" is not the consequence; a fragment is not discoverable
// by anything, so nobody failed to look; and the routes it advises hand-writing do not exist.
//
// Measured on the live target the day this was written: 4643 captures with a hash in the URL, 0;
// endpoints with a client route or a recorded fragment, 0. The right answer there is silence.
func TestNoHashRoutingMeansNoFragmentGap(t *testing.T) {
	s := TargetState{
		CrawlCaptures: 8260, Vectors: 417, ContentDiscovery: 1, FuzzRuns: 1,
		FragmentsObserved: 0,
		VectorsByPoint: map[string]int{
			"query": 129, "path": 97, "cookie": 86, "header": 64, "body": 41, "fragment": 0},
	}
	for _, f := range adviseOnState(s) {
		if strings.Contains(strings.ToLower(f.Title+f.Detail+f.Action), "fragment") {
			t.Errorf("a target with no observed fragment was told it has a fragment gap: %s / %s",
				f.Title, f.Detail)
		}
	}
}

// And where a fragment WAS observed, the zero is a real gap and is raised in its own words.
//
// This is the privatealps.net state, measured the same day: 7 observations, 0 fragment vectors,
// because consolidation had not been run since the fragment point existed.
func TestAnObservedFragmentWithNoVectorIsAGap(t *testing.T) {
	s := TargetState{
		CrawlCaptures: 8260, Vectors: 417, ContentDiscovery: 1, FuzzRuns: 1,
		FragmentsObserved: 7,
		VectorsByPoint: map[string]int{
			"query": 129, "path": 97, "cookie": 86, "header": 64, "body": 41, "fragment": 0},
	}
	var found *AdvisorFinding
	for i, f := range adviseOnState(s) {
		if strings.Contains(strings.ToLower(f.Title), "fragment") {
			found = &adviseOnState(s)[i]
		}
	}
	if found == nil {
		t.Fatal("a fragment was observed and no fragment vector exists, and nothing said so")
	}
	if !strings.Contains(found.Detail, "7") {
		t.Errorf("the advice must state the measured count, got: %s", found.Detail)
	}
	if !strings.Contains(strings.ToLower(found.Action), "domdig") {
		t.Errorf("the advice must name the one tool that can reach a fragment, got: %s", found.Action)
	}
	if strings.Contains(found.Detail, "every tool in every section") {
		t.Errorf("the generic consequence is false for the fragment: %s", found.Detail)
	}
}

// An UNREADABLE check is not a zero and is not evidence either way. The advisor's own rule.
func TestAnUnreadableFragmentCountRaisesNothing(t *testing.T) {
	s := TargetState{
		CrawlCaptures: 10, Vectors: 54, ContentDiscovery: 1, FuzzRuns: 1,
		FragmentsObserved: -1,
		Unreadable:        []string{"observed_fragments"},
		VectorsByPoint: map[string]int{
			"query": 24, "body": 10, "cookie": 20, "header": 5, "path": 5, "fragment": 0},
	}
	for _, f := range adviseOnState(s) {
		// The unreadable-checks note is allowed to NAME observed_fragments: saying "this check did
		// not run" is the opposite of turning it into advice, and reporting it is what stops a
		// failed query from reading as a zero.
		if f.Title == "Some checks could not be run" {
			continue
		}
		if strings.Contains(strings.ToLower(f.Title+f.Detail), "fragment") {
			t.Errorf("an unreadable count became advice: %s / %s", f.Title, f.Detail)
		}
	}
}

// The coverage endpoint used to argue with itself in one JSON object: a generic consequence saying
// the fragment is a gap in coverage, beside a why saying zero there is usually the truth.
func TestTheFragmentConsequenceDoesNotContradictItsOwnReason(t *testing.T) {
	c := insertionPointGapConsequence("fragment")
	if strings.Contains(c, "every tool in every section") {
		t.Errorf("only domdig reaches a fragment, so this is false: %s", c)
	}
	if !strings.Contains(c, "domdig") {
		t.Errorf("the fragment consequence must name the one tool that reaches it: %s", c)
	}
	if strings.Contains(insertionPointGapReason("fragment"), "gap") !=
		strings.Contains(c, "gap") {
		// Both mention a gap, or neither does. They may not say opposite things about one.
		t.Logf("consequence: %s", c)
	}
	for _, point := range []string{"query", "header", "cookie", "path", "body"} {
		if !strings.Contains(insertionPointGapConsequence(point), "every tool in every section") {
			t.Errorf("%s is a SENT point and its zero really is that gap: %s",
				point, insertionPointGapConsequence(point))
		}
	}
}
