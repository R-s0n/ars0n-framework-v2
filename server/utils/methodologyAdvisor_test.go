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
