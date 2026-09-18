package triage

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/internal/triagecap"
)

// Tests for the triage layer's shared vocabulary and core types.
//
// Four of these are not really unit tests. They are the isolation law and the not-knowing-is-not-
// clean rule written down in a form the build enforces, and each of them exists because the
// corresponding bug has already shipped in this codebase:
//
//   - TestOnlySlotsForReadsTheParametersColumn: the path insertion point probed nothing on 51
//     vectors and recorded them tested, because a loop read attack_vectors.parameters and that
//     column is empty for every path vector.
//   - TestNoUnknownStateCanBeReportedClean and TestStateVocabularyIsExhaustive: a check that never
//     ran, re-classified as clean on the next refactor.
//   - TestPlanCtxExposesPerturbedResponsesOnlyThroughOwn: a class reaching a verdict from another
//     class's response.
//   - TestPayloadWireDefaultsToUnprovenSurvival: Go's http.Cookie silently drops the exact
//     characters a SQL injection probe is made of.

// ---------------------------------------------------------------------------------------------
// The state vocabulary
// ---------------------------------------------------------------------------------------------

// An unknown state must never be presentable as clean, by any route a caller has.
//
// The route matters as much as the answer. There is exactly one predicate, CountsAsClean, and it
// is derived from the same rule rows as IsUnknown, so the two cannot drift apart the way a
// hand-written switch in a renderer drifts from a hand-written switch in an exporter.
func TestNoUnknownStateCanBeReportedClean(t *testing.T) {
	for _, r := range StateRules() {
		if !r.Unknown {
			continue
		}
		if r.State.CountsAsClean() {
			t.Errorf("%s is an unknown state and CountsAsClean said true", r.State)
		}
		if r.State == StateClean {
			t.Errorf("%s is marked unknown and is also the clean state, which cannot both be true", r.State)
		}
		if !r.RequiresReason {
			t.Errorf("%s is unknown but does not require a reason, and an unknown with no reason is how a check that never ran becomes a clean", r.State)
		}
		if r.RequiresOrdinals {
			t.Errorf("%s is unknown but requires probe ordinals, which claims a measurement happened", r.State)
		}
	}

	// The states that are not in the vocabulary at all, including the zero value. Fail closed.
	for _, s := range []TriageState{"", "CLEAN", "clean ", "ok", "pass", "not_vulnerable"} {
		if !s.IsUnknown() {
			t.Errorf("unrecognised state %q read as known, so it could be rendered as something other than unknown", s)
		}
		if s.CountsAsClean() {
			t.Errorf("unrecognised state %q counted as clean", s)
		}
		if s.Kind() != StateKindUnknown {
			t.Errorf("unrecognised state %q has kind %q, want %q", s, s.Kind(), StateKindUnknown)
		}
	}

	// And the one state that may say clean, says clean.
	if !StateClean.CountsAsClean() {
		t.Fatal("StateClean does not count as clean, so nothing can ever be reported tested")
	}
	if StateNotExploitable.CountsAsClean() {
		t.Error("not_exploitable counted as clean: it is a negative, but it is a DIFFERENT negative and the operator needs to see which defence was named")
	}
}

// The vocabulary is exhaustive: every TriageState constant declared in the source has a rule row,
// and every rule row names a declared constant.
//
// This is the test that makes adding a state a decision rather than an accident. A new constant
// with no rule row would fall through to the fail-closed unknown branch and read as unknown
// forever with nobody noticing it had never been classified.
func TestStateVocabularyIsExhaustive(t *testing.T) {
	declared := constantsOfType(t, "TriageState")
	if len(declared) == 0 {
		t.Fatal("parsed zero TriageState constants out of the package source, so this test is checking nothing")
	}

	inTable := map[TriageState]bool{}
	for _, r := range StateRules() {
		if inTable[r.State] {
			t.Errorf("%s has two rule rows", r.State)
		}
		inTable[r.State] = true
	}

	for name, val := range declared {
		if !inTable[TriageState(val)] {
			t.Errorf("constant %s = %q is declared but has no row in triageStateRules: classify it as positive, negative, structural or unknown before using it", name, val)
		}
	}
	for s := range inTable {
		found := false
		for _, val := range declared {
			if val == string(s) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("triageStateRules has a row for %q with no matching TriageState constant", s)
		}
	}

	// Golden counts. Changing the vocabulary changes these numbers, which is the point: the
	// diff shows a human made the call rather than a constant drifting in unremarked.
	got := map[StateKind]int{}
	unknown := 0
	for _, r := range StateRules() {
		got[r.Kind]++
		if r.Unknown {
			unknown++
		}
	}
	want := map[StateKind]int{
		StateKindPositive:   5, // finding, suspicious, borderline, masked_only, reordered
		StateKindNegative:   2, // clean, not_exploitable
		StateKindStructural: 1, // not_applicable
		StateKindUnknown:    5, // cannot_determine, not_reachable, not_planned, not_run, not_probed
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("state kind counts = %v, want %v", got, want)
	}
	if unknown != 6 {
		t.Errorf("%d states read as unknown, want 6 (the five unknowns plus not_applicable, which is structural and yet unknown to every aggregate)", unknown)
	}
	if len(StateRules()) != 13 {
		t.Errorf("%d states in the vocabulary, want 13", len(StateRules()))
	}
}

// A clean with no probe record is a class claiming it tested something when nothing was sent, and
// it fails the run rather than logging a warning. A warning in a log is how this shipped the first
// time.
func TestVerdictValidationRejectsACleanWithNoProbeRecord(t *testing.T) {
	cases := []struct {
		name    string
		v       ClassVerdict
		wantErr string
	}{
		{
			name:    "clean with zero ordinals",
			v:       ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: StateClean},
			wantErr: "zero probe ordinals",
		},
		{
			name:    "finding with zero ordinals",
			v:       ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: StateFinding, Grade: GradeHigh},
			wantErr: "zero probe ordinals",
		},
		{
			name:    "cannot_determine with no reason",
			v:       ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: StateCannotDetermine},
			wantErr: "no reason",
		},
		{
			name:    "unknown state carrying a grade",
			v:       ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: StateNotRun, Reason: "slot_budget", Grade: GradeLow},
			wantErr: "only a fired oracle carries a grade",
		},
		{
			name:    "a state nobody declared",
			v:       ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: "probably_fine"},
			wantErr: "unrecognised state",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.v.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %+v", tc.v)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	ok := ClassVerdict{Class: ClassSQL, SlotKey: "query:sort", State: StateClean, Ordinals: []uint64{68}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a clean carrying its probe ordinals was rejected: %v", err)
	}
}

// A vector half tested and half unmeasured is partially tested, with the untested half named. It
// is never a green tick. CATALOGUE 4.5 rule 1.
func TestOneUnknownSlotStopsTheWholeVectorReadingAsClean(t *testing.T) {
	clean := ClassVerdict{Class: ClassSQL, SlotKey: "query:a", State: StateClean, Ordinals: []uint64{68}}
	unknown := ClassVerdict{Class: ClassSQL, SlotKey: "path:2:*", State: StateCannotDetermine, Reason: "canary_resource"}

	all := SummariseVerdicts([]ClassVerdict{clean, clean, clean, unknown})
	if all.RendersAsClean() {
		t.Error("three clean slots and one cannot_determine aggregated to clean")
	}
	if all.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", all.Unknown)
	}
	if len(all.Untested) != 1 || !strings.Contains(all.Untested[0], "canary_resource") {
		t.Errorf("Untested = %v, want the unmeasured slot named with its reason", all.Untested)
	}

	if (Coverage{}).RendersAsClean() {
		t.Error("an empty verdict set rendered as clean, so a class that emitted nothing reads as having tested everything")
	}

	onlyClean := SummariseVerdicts([]ClassVerdict{clean, clean})
	if !onlyClean.RendersAsClean() {
		t.Error("two valid cleans did not render as clean, so nothing can ever be reported tested")
	}

	malformed := SummariseVerdicts([]ClassVerdict{{Class: ClassSQL, SlotKey: "query:a", State: StateClean}})
	if malformed.RendersAsClean() {
		t.Error("a clean that failed Validate still rendered as clean")
	}
	if len(malformed.Malformed) != 1 {
		t.Errorf("Malformed = %v, want the invalid verdict recorded rather than dropped", malformed.Malformed)
	}
}

// ---------------------------------------------------------------------------------------------
// The isolation law as a type
// ---------------------------------------------------------------------------------------------

// A classifier that reaches for another class's response gets nothing, every time.
//
// THE SHAPE OF THIS TEST CHANGED WITH THE PACKAGE MOVE, AND SO DID WHAT IT PROVES. The CATALOGUE
// assumed a package boundary would do this with unexported fields, the layer lived in package
// utils with 300 other files, so there was no boundary and the check was an explicit owner
// comparison inside p.Obs(as ClassID). That accessor had a hole a reviewer proved: p.Obs(p.Owner())
// returned a foreign response with a nil error, because both sides read the same vault entry.
//
// There is now no accessor that takes an owner. The only route to a response is OwnFor, which
// filters, and OwnedResponses.At, which re-checks against the vault entry. So the assertion is no
// longer "a foreign read is refused"; it is "a foreign read cannot be expressed, and the filter
// that stands in for it yields an empty set". The compile-fail fixture in classes/leak_test.go is
// the other half: it proves the expressions do not build.
func TestAClassCannotReadAnotherClassesResponse(t *testing.T) {
	obs := Observation{ObsID: "o1", Kind: ObsProbe, Class: ClassSQL, ProbeOrdinal: 68}
	v := NewPerturbedVault(testCap, "7f3q")
	defer v.Release(testCap)
	p, err := v.Mint(testCap, obs, ClassSQL, "SQL-E1", 68, testMarker(t, "7f3q", 68))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	mine := OwnFor(testCap, []Perturbed{p}, ClassSQL)
	if mine.Len() != 1 {
		t.Fatalf("the owner was handed %d of its own responses, want 1", mine.Len())
	}
	if _, got, err := mine.At(0); err != nil || got.ObsID != "o1" {
		t.Fatalf("the owner could not read its own response: %q %v", got.ObsID, err)
	}

	for _, foreign := range []ClassID{ClassSSTI, ClassNoSQL, ClassXPath, ClassPPServer} {
		theirs := OwnFor(testCap, []Perturbed{p}, foreign)
		if theirs.Len() != 0 {
			t.Errorf("class %s was handed %d of class SQL's responses", foreign, theirs.Len())
		}
		if _, got, err := theirs.At(0); err == nil {
			t.Errorf("class %s read observation %q out of an empty set", foreign, got.ObsID)
		}
	}

	// The set's class is authoritative even if the handles in it are not its own. This cannot be
	// built by a classifier, because the field is unexported; it is built here to prove the read
	// itself fails closed rather than relying on OwnFor's loop being the only guard.
	smuggled := OwnedResponses{class: ClassSSTI, held: []Perturbed{p}}
	if _, got, err := smuggled.At(0); !errors.Is(err, ErrForeignObservation) || got.ObsID != "" {
		t.Errorf("a set labelled SSTI handed over SQL's observation %q, err = %v", got.ObsID, err)
	}

	// A zero-value Perturbed is not a measured response and must not read as one.
	if _, got, err := (OwnedResponses{class: ClassSQL, held: []Perturbed{{}}}).At(0); !errors.Is(err, ErrUnmintedPerturbed) || got.ObsID != "" {
		t.Errorf("a zero-value Perturbed handed back observation %q (err %v), so an unsent probe would score as a silent response", got.ObsID, err)
	}
}

// The runner's filter is the load-bearing line of the whole system, so it gets its own test: hand
// it every class's responses and it returns exactly one class's.
func TestOwnForStripsEveryForeignResponse(t *testing.T) {
	v := NewPerturbedVault(testCap, "7f3q")
	defer v.Release(testCap)
	var all []Perturbed
	for _, id := range AllClassIDs() {
		ord := uint64(id) + ClassStripeModulus // the second ordinal in this class's stripe
		p, err := v.Mint(testCap, Observation{Kind: ObsProbe, Class: id, ProbeOrdinal: ord}, id,
			ProbeID(id.String()+"-1"), ord, testMarker(t, "7f3q", ord))
		if err != nil {
			t.Fatalf("Mint for %s: %v", id, err)
		}
		all = append(all, p)
	}

	for _, id := range AllClassIDs() {
		own := OwnFor(testCap, all, id)
		if own.Len() != 1 {
			t.Fatalf("class %s was handed %d responses out of %d, want exactly its own 1", id, own.Len(), len(all))
		}
		if own.Class() != id {
			t.Errorf("class %s was handed a set labelled %s", id, own.Class())
		}
		h, o, err := own.At(0)
		if err != nil {
			t.Errorf("class %s could not read the response it was handed: %v", id, err)
		}
		if h.Owner() != id || o.Class != id {
			t.Errorf("class %s was handed class %s's response (observation stamped %s)", id, h.Owner(), o.Class)
		}
	}
}

// triageTypeReach is the result of walking a type graph for responses.
type triageTypeReach struct {
	// Holders are the paths at which one of the two SANCTIONED holders sits: a Perturbed, which
	// hands its response only to its owner, or a Replay, which NewReplay refuses to build from a
	// perturbed observation. Reaching one of these is fine; WHERE they are is asserted.
	Holders []string
	// Raw are the paths at which a response can arrive with no holder in front of it: a bare
	// Observation, an interface that could hold one, or a func that could return one. Every entry
	// here is a hole in the isolation law.
	Raw []string
}

// triageWalkForResponses finds EVERY path by which an Observation can reach a caller.
//
// WHY THE OLD WALKER WAS BLIND, MEASURED. The previous version compared each type against
// reflect.TypeOf(Perturbed{}) and nothing else, so it looked for the holder and never for the
// thing the holder exists to protect. Four field shapes were added to PlanCtx and it passed all
// four:
//
//	AuditAllResponses []Observation
//	AuditAny          map[string]any
//	AuditPtr          *Observation
//	AuditNested       struct{ Deep []*Observation }
//
// A raw Observation IS the whole response: status, every header, the body, the marker and the
// payload. Handing one to a classifier that did not send it is the isolation law broken in the
// most complete way available, and the guard that existed to stop it could not see it.
//
// So this walker looks for the OBSERVATION, through every kind of indirection Go has: pointers,
// slices, arrays, channels, map keys, map values, struct fields including unexported ones,
// function parameters and results, and interfaces. An interface field is recorded unconditionally,
// because any value at all can travel through one and a walker cannot see what a map[string]any
// will hold at runtime. Fail closed: if the shape cannot be proved safe, it is reported.
func triageWalkForResponses(root reflect.Type, name string) triageTypeReach {
	obs := reflect.TypeOf(Observation{})
	perturbed := reflect.TypeOf(Perturbed{})
	replay := reflect.TypeOf(Replay{})

	var got triageTypeReach
	seen := map[reflect.Type]bool{}

	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		switch rt {
		case perturbed:
			got.Holders = append(got.Holders, path+" (Perturbed)")
			return
		case replay:
			got.Holders = append(got.Holders, path+" (Replay)")
			return
		case obs:
			got.Raw = append(got.Raw, path+" (Observation)")
			return
		}
		switch rt.Kind() {
		case reflect.Interface:
			// Unbounded. An Observation fits through here and nothing in the type says it cannot.
			got.Raw = append(got.Raw, path+" (interface "+rt.String()+")")
		case reflect.Ptr:
			walk(rt.Elem(), path+"*")
		case reflect.Slice, reflect.Array:
			walk(rt.Elem(), path+"[]")
		case reflect.Chan:
			walk(rt.Elem(), path+"<-")
		case reflect.Map:
			walk(rt.Key(), path+"{key}")
			walk(rt.Elem(), path+"[]")
		case reflect.Func:
			for i := 0; i < rt.NumIn(); i++ {
				walk(rt.In(i), path+"(in"+strconv.Itoa(i)+")")
			}
			for i := 0; i < rt.NumOut(); i++ {
				walk(rt.Out(i), path+"(out"+strconv.Itoa(i)+")")
			}
		case reflect.Struct:
			if seen[rt] {
				return
			}
			seen[rt] = true
			for i := 0; i < rt.NumField(); i++ {
				walk(rt.Field(i).Type, path+"."+rt.Field(i).Name)
			}
		}
	}
	walk(root, name)
	sort.Strings(got.Holders)
	sort.Strings(got.Raw)
	return got
}

// The walker itself is tested, because a guard nobody checks is the thing it is guarding against.
//
// Each of these is a field shape that reaches an Observation. All of them were invisible to the
// previous walker; all of them must be visible to this one.
func TestTheResponseWalkerSeesEveryIndirection(t *testing.T) {
	type deep struct{ Deep []*Observation }
	cases := []struct {
		name string
		typ  reflect.Type
	}{
		{"slice of observations", reflect.TypeOf(struct{ A []Observation }{})},
		{"array of observations", reflect.TypeOf(struct{ A [2]Observation }{})},
		{"pointer to observation", reflect.TypeOf(struct{ A *Observation }{})},
		{"map value", reflect.TypeOf(struct{ A map[string]Observation }{})},
		{"map key", reflect.TypeOf(struct{ A map[*Observation]string }{})},
		{"empty interface", reflect.TypeOf(struct{ A map[string]any }{})},
		{"bare interface field", reflect.TypeOf(struct{ A interface{ Delivered() bool } }{})},
		{"channel", reflect.TypeOf(struct{ A chan Observation }{})},
		{"func result", reflect.TypeOf(struct{ A func() Observation }{})},
		{"func parameter", reflect.TypeOf(struct{ A func(Observation) }{})},
		{"nested struct", reflect.TypeOf(struct{ Inner deep }{})},
		{"slice of nested structs", reflect.TypeOf(struct{ Inner []deep }{})},
	}
	for _, c := range cases {
		got := triageWalkForResponses(c.typ, "X")
		if len(got.Raw) == 0 {
			t.Errorf("%s: the walker found no route to an Observation, so a PlanCtx field of that shape would pass the guard and hand every class every response", c.name)
		}
	}

	// And the shape that is CORRECT must not be reported, or the guard fires on everything and
	// gets deleted by the next person who touches it.
	ok := triageWalkForResponses(reflect.TypeOf(struct {
		Own   []Perturbed
		Route Replay
		N     int
		S     []string
	}{}), "X")
	if len(ok.Raw) != 0 {
		t.Errorf("the walker reported %v on a struct that only holds the two sanctioned holders", ok.Raw)
	}
	want := []string{"X.Own[] (Perturbed)", "X.Route (Replay)"}
	if !reflect.DeepEqual(ok.Holders, want) {
		t.Errorf("holders = %v, want %v", ok.Holders, want)
	}
}

// PlanCtx must have no field through which a response can arrive except the two sanctioned
// holders, at the two sanctioned places.
//
// Walked by reflection rather than read by eye, so that a future agent adding a convenient
// AllResponses, LastProbe or Audit field fails the build instead of quietly reopening the hole.
func TestPlanCtxExposesPerturbedResponsesOnlyThroughOwn(t *testing.T) {
	plan := triageWalkForResponses(reflect.TypeOf(PlanCtx{}), "PlanCtx")
	if len(plan.Raw) != 0 {
		t.Errorf("a response is reachable from PlanCtx with no owner check in front of it, at %v. A raw Observation is the whole response: body, marker and payload. Every one of those paths hands one class's response to every class", plan.Raw)
	}
	// Own.held rather than Own: Own is now an OwnedResponses, a struct binding the handles to the
	// class they belong to, and the handles sit in its UNEXPORTED held field. The walker still
	// reaches it, which is the point of walking by reflection rather than by eye, and what it
	// finds there is still a Perturbed and never a raw Observation.
	wantHolders := []string{"PlanCtx.Own.held[] (Perturbed)", "PlanCtx.Route (Replay)"}
	if !reflect.DeepEqual(plan.Holders, wantHolders) {
		t.Errorf("response holders on PlanCtx are at %v, want exactly %v", plan.Holders, wantHolders)
	}

	// ClassifyCtx embeds PlanCtx and adds only the post-baseline and this class's own callbacks.
	classify := triageWalkForResponses(reflect.TypeOf(ClassifyCtx{}), "ClassifyCtx")
	if len(classify.Raw) != 0 {
		t.Errorf("a response is reachable from ClassifyCtx with no owner check in front of it, at %v", classify.Raw)
	}
	wantHolders = []string{
		"ClassifyCtx.PlanCtx.Own.held[] (Perturbed)",
		"ClassifyCtx.PlanCtx.Route (Replay)",
		"ClassifyCtx.PostBaseline (Replay)",
	}
	if !reflect.DeepEqual(classify.Holders, wantHolders) {
		t.Errorf("response holders on ClassifyCtx are at %v, want exactly %v", classify.Holders, wantHolders)
	}
}

// Replay is the one shared channel, so it is the one hole worth closing at construction: a
// perturbed response wrapped as a control would be read by every class.
func TestNewReplayRefusesAResponseThatCarriedAPayload(t *testing.T) {
	for _, k := range []ObsKind{ObsProbe, ObsDecodeControl, ObsPctControl} {
		if _, err := NewReplay(testCap, Observation{Kind: k}); err == nil {
			t.Errorf("NewReplay accepted a %s observation, which carried a payload and would then be shared with every class", k)
		}
	}
	if _, err := NewReplay(testCap, Observation{Kind: ObsBaseline, Class: ClassSQL}); err == nil {
		t.Error("NewReplay accepted an observation stamped with a class")
	}
	if _, err := NewReplay(testCap, Observation{Kind: ObsBaseline, ProbeOrdinal: 68}); err == nil {
		t.Error("NewReplay accepted an observation carrying a probe ordinal")
	}

	r, err := NewReplay(testCap, Observation{ObsID: "b1", Kind: ObsBaseline})
	if err != nil {
		t.Fatalf("NewReplay rejected a genuine baseline: %v", err)
	}
	if !r.Resolved() || r.Obs().ObsID != "b1" {
		t.Error("a genuine baseline did not come back resolved")
	}
	if (Replay{}).Resolved() {
		t.Error("a zero-value Replay reported resolved, so a route control that was never sent would read as one that was")
	}

	// The decode and pct controls modify the value, so they are perturbed and owned. That is
	// ruling R6a, and it is the whole reason those two stopped being shared gates.
	if !ObsDecodeControl.CarriesPayload() || !ObsPctControl.CarriesPayload() {
		t.Error("the decode or pct control is not treated as carrying a payload, which makes it a shared gate probe again")
	}
	if ObsBaseline.CarriesPayload() || ObsRouteControl.CarriesPayload() || ObsPreludeControl.CarriesPayload() {
		t.Error("an unperturbed control was treated as carrying a payload, which would stop the controls being shareable at all")
	}
}

// A marker from another class's ordinal stripe is a hit for nobody. Ruling R12.
func TestAForeignMarkerMatchesNobody(t *testing.T) {
	// Ordinal 68 is in stripe 68 mod 64 == 4, which is SQL.
	m := testMarker(t, "7f3q", 68)
	owner, ok := m.ClassID()
	if !ok || owner != ClassSQL {
		t.Fatalf("marker %q attributed to %s (ok=%v), want SQL", m, owner, ok)
	}
	matched := 0
	for _, id := range AllClassIDs() {
		if m.BelongsTo(id) {
			matched++
			if id != ClassSQL {
				t.Errorf("class %s claimed a marker from SQL's stripe", id)
			}
		}
	}
	if matched != 1 {
		t.Errorf("%d classes claimed one marker, want exactly 1", matched)
	}

	// A malformed marker belongs to nobody at all, rather than to whichever class looks first.
	for _, bad := range []Marker{"", "zqj", "ZQJ7F3Q000A1KX9M", "abc7f3q000a1kx9m", "zqj7f3q000a1kx9m!"} {
		if _, ok := bad.ClassID(); ok {
			t.Errorf("malformed marker %q was attributed to a class", bad)
		}
		for _, id := range AllClassIDs() {
			if bad.BelongsTo(id) {
				t.Errorf("class %s claimed malformed marker %q", id, bad)
			}
		}
	}

	// The verifier has landed, so the method is the verifier rather than a stub. A minted marker
	// reads Valid and anything that is not marker-shaped reads Corrupted; the one answer the
	// method must never give now is Unchecked, because CATALOGUE 4.2 caps a hit whose marker
	// cannot be verified at suspicious and every hit in the system used to sit under that cap.
	if got := m.Integrity(); got != MarkerValid {
		t.Errorf("Marker.Integrity() = %q on a minted marker, want %q", got, MarkerValid)
	}
	if got := Marker("not a marker").Integrity(); got != MarkerCorrupted {
		t.Errorf("Marker.Integrity() = %q on a non-marker, want %q; unchecked would let it grade higher", got, MarkerCorrupted)
	}
}

// Minting is where a runner bug becomes loud instead of becoming an unattributable response.
func TestPerturbedRefusesAnOrdinalOutsideItsClassStripe(t *testing.T) {
	obs := Observation{Kind: ObsProbe}
	v := NewPerturbedVault(testCap, "7f3q")
	defer v.Release(testCap)

	if _, err := v.Mint(testCap, obs, ClassSQL, "SQL-E1", 69, ""); err == nil {
		t.Error("ordinal 69 (stripe 5) was accepted for class SQL (stripe 4)")
	}
	if _, err := v.Mint(testCap, obs, ClassID(200), "X-1", 200, ""); err == nil {
		t.Error("an unregistered class id was accepted")
	}
	// A marker from the wrong stripe is refused even when the ordinal is right, because the
	// marker is what the response will be searched for.
	if _, err := v.Mint(testCap, obs, ClassSQL, "SQL-E1", 68, testMarker(t, "7f3q", 69)); err == nil {
		t.Error("a marker from class 5's stripe was accepted on a class SQL probe")
	}
	if _, err := v.Mint(testCap, obs, ClassSQL, "SQL-E1", 68, testMarker(t, "7f3q", 68)); err != nil {
		t.Errorf("a correctly striped probe was refused: %v", err)
	}

	// AND WITHOUT THE CAPABILITY NOTHING IS MINTED AT ALL, which is the half that closes the
	// write side. A class that could mint could name any owner and get a handle into that owner's
	// partition, which undoes the partitioning entirely.
	var noCap triagecap.Runner
	if noCap.Held() {
		t.Fatal("a zero-value capability reported as held, so every gate in this package is open")
	}
	if _, err := v.Mint(noCap, obs, ClassSQL, "SQL-E1", 68, ""); !errors.Is(err, ErrNotTheRunner) {
		t.Errorf("minting with a zero capability returned err = %v, want ErrNotTheRunner", err)
	}
	if got := NewPerturbedVault(noCap, "7f3q"); got != nil {
		t.Error("a zero capability opened a vault")
	}
	if own := OwnFor(noCap, []Perturbed{}, ClassSQL); own.Class() != ClassNone {
		t.Errorf("OwnFor with a zero capability returned a set labelled %s, want none", own.Class())
	}
	if _, err := NewReplay(noCap, Observation{Kind: ObsBaseline}); !errors.Is(err, ErrNotTheRunner) {
		t.Errorf("NewReplay with a zero capability returned err = %v, want ErrNotTheRunner", err)
	}
	if _, err := MintMarkerAt(noCap, "7f3q", ClassSQL, 4); !errors.Is(err, ErrNotTheRunner) {
		t.Errorf("MintMarkerAt with a zero capability returned err = %v, want ErrNotTheRunner", err)
	}
	if _, err := NewRunID(noCap); !errors.Is(err, ErrNotTheRunner) {
		t.Errorf("NewRunID with a zero capability returned err = %v, want ErrNotTheRunner", err)
	}
}

// Every class id must be strictly less than the stripe modulus, or two classes share a stripe and
// R12's arithmetic attributes markers to the wrong one.
func TestClassIDsFitTheOrdinalStripe(t *testing.T) {
	seen := map[uint64]ClassID{}
	for _, id := range AllClassIDs() {
		if uint64(id) >= ClassStripeModulus {
			t.Errorf("class %s has id %d, which is not less than the stripe modulus %d", id, id, ClassStripeModulus)
		}
		stripe := uint64(id) % ClassStripeModulus
		if prev, dup := seen[stripe]; dup {
			t.Errorf("classes %s and %s share ordinal stripe %d", prev, id, stripe)
		}
		seen[stripe] = id
		if id == ClassNone {
			t.Error("ClassNone is in the register, but stripe 0 must stay reserved for baselines and shared controls")
		}
	}
}

// ---------------------------------------------------------------------------------------------
// Wire bytes, because the encoder lies
// ---------------------------------------------------------------------------------------------

// The zero value of a payload's wire record must read as "we do not know whether the bytes went
// out", never as "they did".
//
// Measured on this machine, and this is the whole reason the field exists:
//
//	(&http.Cookie{Name:"s", Value:`1' OR 1=1; DROP`}).String() -> `s="1' OR 1=1 DROP"`
//	(&http.Cookie{Name:"s", Value:`a"b\c`}).String()           -> `s=abc`
//
// The semicolon, the double quote and the backslash are gone, with only a line on the stdlib
// logger. Those are the SQL injection probe characters, and 75 of the 218 vectors in the measured
// corpus are cookie vectors. Without a stored wire form, a mangled probe and a defended
// application are indistinguishable after the fact, and the second reading is the one that gets
// written down as clean.
func TestPayloadWireDefaultsToUnprovenSurvival(t *testing.T) {
	var zero PayloadWire
	if zero.Survived != WireSurvivalUnknown {
		t.Errorf("zero PayloadWire.Survived = %q, want the unknown value", zero.Survived)
	}
	if zero.Survived.Proven() {
		t.Error("an unmeasured payload reported as proven to have reached the wire")
	}
	for _, s := range []WireSurvival{WireSurvivalAltered, WireSurvivalDropped, WireSurvivalRefused} {
		if s.Proven() {
			t.Errorf("%q reported as proven", s)
		}
	}
	for _, s := range []WireSurvival{WireSurvivalIntact, WireSurvivalEncoded} {
		if !s.Proven() {
			t.Errorf("%q did not report as proven, so no probe could ever be scored", s)
		}
	}

	// The record has to be able to answer "what did we ask for" and "what went out" separately,
	// or the question cannot be asked after the fact at all.
	obs := Observation{Payload: PayloadWire{
		Logical:       []byte(`1' OR 1=1; DROP`),
		Wire:          []byte(`sid="1' OR 1=1 DROP"`),
		Container:     []byte(`Cookie: sid="1' OR 1=1 DROP"`),
		ContainerName: "Cookie",
		Survived:      WireSurvivalAltered,
		AlteredBy:     "net/http.Cookie sanitizer",
	}}
	if strings.Contains(string(obs.Payload.Wire), ";") {
		t.Fatal("the fixture is wrong: the sanitizer drops the semicolon")
	}
	if obs.Payload.Survived.Proven() {
		t.Error("a payload the sanitizer altered reported as proven to have reached the wire")
	}
}

// A transport refusal is could-not-send, not a quiet response. A NUL byte in a header value is
// rejected with "net/http: invalid header field value" before anything leaves the machine, which
// is exactly the loud failure a probe should record rather than scoring an empty response.
func TestATransportRefusalIsNotADeliveredRequest(t *testing.T) {
	if !(Observation{}).Delivered() {
		t.Error("an observation with no transport error read as undelivered")
	}
	for _, e := range []TransportErrKind{TransportDNS, TransportConnect, TransportTLS, TransportTimeout, TransportReset, TransportProto, TransportInvalidHeader} {
		if (Observation{TransportErr: e}).Delivered() {
			t.Errorf("a %q failure read as delivered, so a request that never went out would be scored as a silent response", e)
		}
	}
}

// Unknowns are distinguishable from measurements everywhere the zero value would otherwise lie.
func TestUnmeasuredConstraintsDoNotReadAsMeasured(t *testing.T) {
	c := NewSlotConstraints()
	if c.DecodeDepth != -1 {
		t.Errorf("NewSlotConstraints().DecodeDepth = %d, want -1: 0 means measured and not decoding, which is a claim", c.DecodeDepth)
	}
	if !PreludeUnknown.Failed() {
		t.Error("an unmeasured prelude read as usable; on a synchronizer-token app that makes every probe fail validation identically, which reads as a stable endpoint with no differential")
	}
	if !PreludeViewstateBound.Failed() || !PreludeTokenUnobtainable.Failed() {
		t.Error("a failed prelude state read as usable")
	}
	if PreludeTokenObtained.Failed() || PreludeTokenNotRequired.Failed() {
		t.Error("a usable prelude state read as failed, so no mutating vector could ever be probed")
	}
	if (AssetCorpus{}).Complete() {
		t.Error("an uncounted asset corpus read as complete")
	}
	if (AssetCorpus{ScannedN: 50, AvailableM: 0}).Complete() {
		t.Error("a corpus that scanned 50 files with no count of what was available read as complete: that is the LinkFinder cap reporting a number that looks like a total")
	}
	if !(AssetCorpus{ScannedN: 0, AvailableM: 0, Counted: true}).Complete() {
		t.Error("a host that genuinely serves no JS read as incomplete, which would cap every DOM class forever")
	}
	if (AssetCorpus{ScannedN: 50, AvailableM: 120, Counted: true}).Complete() {
		t.Error("50 of 120 files read as complete")
	}
	if (BaselineModel{}).Stable {
		t.Error("a baseline model with no samples read as stable, so an endpoint nobody measured would be differenced against nothing")
	}
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

// testMarker builds a well-formed marker for a given ordinal. The checksum is a placeholder
// because no verifier exists yet; Marker.Integrity reports Unchecked and the test above asserts
// that stays true until someone writes one.
func testMarker(t *testing.T, runID string, ordinal uint64) Marker {
	t.Helper()
	if len(runID) != MarkerRunIDLen {
		t.Fatalf("run id %q is %d chars, want %d", runID, len(runID), MarkerRunIDLen)
	}
	ord := strconv.FormatUint(ordinal, 36)
	if len(ord) > MarkerOrdinalLen {
		t.Fatalf("ordinal %d does not fit in %d base36 chars", ordinal, MarkerOrdinalLen)
	}
	ord = strings.Repeat("0", MarkerOrdinalLen-len(ord)) + ord
	// The checksum is COMPUTED, not a fixed literal. A fixture with a made-up checksum was
	// harmless only while Marker.Integrity() was a stub; now that the verifier is wired, every
	// marker this helper builds would read corrupted and no test could tell a real corruption
	// from the fixture.
	prefix := DefaultMarkerAnchor + runID + ord
	sum, err := MarkerChecksumFor(prefix)
	if err != nil {
		t.Fatalf("checksum for %q: %v", prefix, err)
	}
	m := Marker(prefix + sum)
	if !m.WellFormed() {
		t.Fatalf("built a malformed marker %q", m)
	}
	if got := m.Integrity(); got != MarkerValid {
		t.Fatalf("built marker %q reads %q", m, got)
	}
	return m
}

// packageDir returns the directory holding this package's source.
func packageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(self)
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// constantsOfType parses the package's non-test source and returns every constant declared with
// the named type, as name to string value.
//
// Reading the source rather than a hand-kept list is the only way this can be exhaustive: a list
// is exactly the thing that goes stale when someone adds a constant.
func constantsOfType(t *testing.T, typeName string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, packageDir(t), func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	out := map[string]string{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, s := range gd.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						continue
					}
					id, ok := vs.Type.(*ast.Ident)
					if !ok || id.Name != typeName {
						continue
					}
					for i, n := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("unquote %s: %v", lit.Value, err)
						}
						out[n.Name] = v
					}
				}
			}
		}
	}
	return out
}
