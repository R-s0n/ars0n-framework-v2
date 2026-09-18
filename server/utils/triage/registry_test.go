package triage

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Tests for the classifier contract and the registry.
//
// CheckPayloadIsolation is the isolation law in executable form, so it gets tested the way a
// detector gets tested: against a registry that satisfies it AND against registries that break it
// in each of the four ways. A check that has only ever been run against clean input has not been
// shown to fire, and a detector that has never been shown firing is not a detector.

// fakeClass is a classifier that exists only to feed the isolation checks. It reaches everything
// unconditionally so ValidateClassifier's reason requirement does not get in the way of the
// payload tests, which are what these fixtures are for.
type fakeClass struct {
	id     ClassID
	probes []ProbeSpec
	reach  map[SlotKind]Reachability
	plan   []ProbeRequest
}

func (f fakeClass) ID() ClassID         { return f.id }
func (f fakeClass) Probes() []ProbeSpec { return f.probes }
func (f fakeClass) Plan(PlanCtx) []ProbeRequest {
	return f.plan
}
func (f fakeClass) Classify(ClassifyCtx) []ClassVerdict { return nil }

func (f fakeClass) Reaches(k SlotKind, _ MediaType) Reachability {
	if f.reach != nil {
		return f.reach[k]
	}
	return Reachability{Reach: ReachAlways}
}

// triageTestProbe is shorthand for a declared payload aimed at every insertion point.
func triageTestProbe(id ProbeID, class ClassID, logical string) ProbeSpec {
	return ProbeSpec{
		ID: id, Class: class, Logical: []byte(logical),
		Points: AllSlotKinds(), Tier: TierFull, Risk: RiskR1,
	}
}

func fixtureRegistry(cs ...fakeClass) map[ClassID]Classifier {
	reg := map[ClassID]Classifier{}
	for _, c := range cs {
		reg[c.id] = c
	}
	return reg
}

// The law: no two classes may declare the same payload bytes. Run over whatever is registered.
//
// With no classifiers written yet this is vacuous, so the test says so out loud rather than
// reporting a pass that means nothing, and the fixture tests below are what actually prove the
// check fires.
func TestRegisteredPayloadsArePairwiseDisjointAcrossClasses(t *testing.T) {
	rep := CheckPayloadIsolation(RegisteredClassifiers())
	if !rep.OK() {
		for _, v := range rep.Violations {
			t.Errorf("ISOLATION: %s", v)
		}
	}
	t.Logf("isolation check ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
	if rep.ProbesChecked == 0 {
		t.Log("no classifiers are registered yet, so this run of the law is vacuous; the fixture tests in this file are what prove the check fires")
	}
}

// Two classes shipping byte-equal payloads is the violation the whole design exists to stop.
//
// It matters that the markers differ. A marker is minted per probe, so without normalisation
// every payload is trivially unique and the check would never fire on anything real.
func TestTheIsolationCheckFiresOnAPayloadTwoClassesShare(t *testing.T) {
	sqlMarker := markerFor(t, ClassSQL)
	nosqlMarker := markerFor(t, ClassNoSQL)

	reg := fixtureRegistry(
		fakeClass{id: ClassSQL, probes: []ProbeSpec{triageTestProbe("SQL-E1", ClassSQL, "'||"+sqlMarker+"||'")}},
		fakeClass{id: ClassNoSQL, probes: []ProbeSpec{triageTestProbe("NOSQL-E1", ClassNoSQL, "'||"+nosqlMarker+"||'")}},
	)
	rep := CheckPayloadIsolation(reg)
	if rep.OK() {
		t.Fatal("two classes declared the same payload, differing only in their markers, and the check passed")
	}
	if got := kindsOf(rep); !sawViolation(got, IsoDuplicatePayload) {
		t.Errorf("violations = %v, want a %s", got, IsoDuplicatePayload)
	}

	// The same payload declared twice by ONE class is not a violation: a class may reuse its own
	// bytes across insertion points, and forbidding that would push classes into inventing
	// gratuitously different payloads for no measurement reason.
	same := fixtureRegistry(fakeClass{id: ClassSQL, probes: []ProbeSpec{
		triageTestProbe("SQL-E1", ClassSQL, "'||"+sqlMarker+"||'"),
		triageTestProbe("SQL-E2", ClassSQL, "'||"+sqlMarker+"||'"),
	}})
	if rep := CheckPayloadIsolation(same); !rep.OK() {
		t.Errorf("one class reusing its own payload was reported as a violation: %v", rep.Violations)
	}
}

// Containment across classes is not forbidden. Silent containment is. A hit on the shorter
// payload, inside a response the longer one caused, is attributable to neither class unless
// someone wrote down that it can happen.
func TestUndeclaredCrossClassContainmentIsRefused(t *testing.T) {
	// The two payloads carry DIFFERENT markers, and the containment only shows up after the
	// markers are normalised away. That is the case the check has to catch: on the wire the bytes
	// differ, and they still test the same thing.
	entity := func(m string) string { return "<!ENTITY " + m + " SYSTEM 'file:///etc/passwd'>" }
	short := entity(markerFor(t, ClassXXE))
	long := "<?xml version='1.0'?><!DOCTYPE d [" + entity(markerFor(t, ClassDeser)) + "]><d/>"

	reg := fixtureRegistry(
		fakeClass{id: ClassXXE, probes: []ProbeSpec{triageTestProbe("XXE-X1", ClassXXE, short)}},
		fakeClass{id: ClassDeser, probes: []ProbeSpec{triageTestProbe("DESER-D1", ClassDeser, long)}},
	)
	rep := CheckPayloadIsolation(reg)
	if !sawViolation(kindsOf(rep), IsoUndeclaredContainment) {
		t.Fatalf("a containment well over the 24-byte floor passed unannotated across two classes; violations = %v", rep.Violations)
	}

	// With the annotation it is allowed, because now the ambiguity is written down where a reader
	// of the catalogue row will see it.
	annotated := fakeClass{id: ClassDeser, probes: []ProbeSpec{func() ProbeSpec {
		p := triageTestProbe("DESER-D1", ClassDeser, long)
		p.Embeds = []ProbeID{"XXE-X1"}
		return p
	}()}}
	rep = CheckPayloadIsolation(fixtureRegistry(
		fakeClass{id: ClassXXE, probes: []ProbeSpec{triageTestProbe("XXE-X1", ClassXXE, short)}},
		annotated,
	))
	if sawViolation(kindsOf(rep), IsoUndeclaredContainment) {
		t.Errorf("an annotated containment was still refused: %v", rep.Violations)
	}

	// Under the floor it is not reported at all: a shared handful of bytes such as a quote and a
	// brace is not an attribution risk, and flagging it would make the check noise.
	tiny := fixtureRegistry(
		fakeClass{id: ClassSQL, probes: []ProbeSpec{triageTestProbe("SQL-E1", ClassSQL, "'")}},
		fakeClass{id: ClassLDAP, probes: []ProbeSpec{triageTestProbe("LDAP-E1", ClassLDAP, "x')(|(cn=*")}},
	)
	if sawViolation(kindsOf(CheckPayloadIsolation(tiny)), IsoUndeclaredContainment) {
		t.Error("a one-byte containment was reported, which would make the check unusable")
	}
}

// Ruling R12, the defect that caused it: four of one class's binary constants decoded to another
// class's marker, so a Java endpoint echoing a deserialization probe's payload handed the other
// class's marker search a hit, and a prototype pollution finding could come out of a
// deserialization probe's response.
func TestAPayloadCarryingAnotherClassesMarkerIsRefused(t *testing.T) {
	foreign := markerFor(t, ClassPPServer)
	reg := fixtureRegistry(fakeClass{id: ClassDeser, probes: []ProbeSpec{
		triageTestProbe("DESER-J1", ClassDeser, "ClassNotFoundException: "+foreign),
	}})
	rep := CheckPayloadIsolation(reg)
	if !sawViolation(kindsOf(rep), IsoForeignMarker) {
		t.Fatalf("a payload embedding class PP-SERVER's marker was accepted from class DESER; violations = %v", rep.Violations)
	}
	if !strings.Contains(rep.Violations[0].Detail, "PP-SERVER") {
		t.Errorf("the violation does not name the class the marker belongs to: %s", rep.Violations[0].Detail)
	}

	// The marker with its first byte uppercased is the same marker. DESER's payloads use that
	// form deliberately, and a case-sensitive normaliser would let a real collision through.
	upper := strings.ToUpper(foreign[:1]) + foreign[1:]
	rep = CheckPayloadIsolation(fixtureRegistry(fakeClass{id: ClassDeser, probes: []ProbeSpec{
		triageTestProbe("DESER-J2", ClassDeser, "ClassNotFoundException: "+upper),
	}}))
	if !sawViolation(kindsOf(rep), IsoForeignMarker) {
		t.Errorf("the uppercased form of a foreign marker slipped past the check; violations = %v", rep.Violations)
	}

	// A class carrying its OWN marker is the normal case and must not be flagged.
	own := markerFor(t, ClassDeser)
	if rep := CheckPayloadIsolation(fixtureRegistry(fakeClass{id: ClassDeser, probes: []ProbeSpec{
		triageTestProbe("DESER-J3", ClassDeser, "ClassNotFoundException: "+own),
	}})); sawViolation(kindsOf(rep), IsoForeignMarker) {
		t.Errorf("a class was flagged for carrying its own marker: %v", rep.Violations)
	}
}

// What the isolation check does NOT cover is named in its output, so a green test is never read
// as covering it. Changing this list is a decision, and the diff is where it gets made.
func TestIsolationGapsAreDeclaredRatherThanSilent(t *testing.T) {
	rep := CheckPayloadIsolation(RegisteredClassifiers())
	want := []string{
		"I1a: the dot-dot and XML-ness family rules of ruling R7 are not encoded yet",
		"I1d-encoded: markers embedded as base64, hex or length-prefixed binary are not extracted yet",
	}
	got := append([]string(nil), rep.ChecksNotImplemented...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("declared isolation gaps = %v, want %v. If a gap has been closed, remove it here and from isolationChecksNotImplemented together", got, want)
	}
	if len(rep.ChecksRun) != 4 {
		t.Errorf("%d checks reported as run, want 4", len(rep.ChecksRun))
	}
}

// Registration refuses everything that would make a class unattributable, and it panics rather
// than returning an error because it runs from init() where an error has nowhere to go and a
// half-registered registry silently drops a whole attack class.
func TestRegistrationRefusesAnUnattributableClass(t *testing.T) {
	registeredAtStart := len(RegisteredClassifiers())
	cases := []struct {
		name string
		run  func()
		want string
	}{
		{
			name: "an id nobody put in the register",
			run:  func() { RegisterClassifier(fakeClass{id: ClassID(99)}) },
			want: "not in the register",
		},
		{
			name: "a probe stamped with another class",
			run: func() {
				RegisterClassifier(fakeClass{id: ClassSQL, probes: []ProbeSpec{triageTestProbe("SQL-E1", ClassNoSQL, "x")}})
			},
			want: "declares class",
		},
		{
			name: "a never with no reason",
			run: func() {
				RegisterClassifier(fakeClass{id: ClassCSVI, reach: map[SlotKind]Reachability{
					KindQuery: {Reach: ReachAlways},
				}})
			},
			want: "with no reason",
		},
		{
			name: "a probe aimed where the class does not reach",
			run: func() {
				RegisterClassifier(fakeClass{
					id: ClassCSVI,
					reach: map[SlotKind]Reachability{
						KindQuery:    {Reach: ReachAlways},
						KindBody:     {Reach: ReachNever, Reason: "not written into a record"},
						KindHeader:   {Reach: ReachNever, Reason: "not written into a record"},
						KindCookie:   {Reach: ReachNever, Reason: "a cookie is not written into a record an export re-serves"},
						KindPath:     {Reach: ReachNever, Reason: "a route segment is not written into a record"},
						KindFragment: {Reach: ReachNever, Reason: "never reaches the server"},
					},
					probes: []ProbeSpec{{ID: "CSVI-W1", Class: ClassCSVI, Logical: []byte("=1+1"), Points: []SlotKind{KindCookie}}},
				})
			},
			want: "none of which this class reaches",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("RegisterClassifier accepted %s", tc.name)
				}
				if msg, _ := r.(string); !strings.Contains(msg, tc.want) {
					t.Errorf("panic %q does not mention %q", r, tc.want)
				}
			}()
			tc.run()
		})
	}

	// Nothing above may have left a class in the real registry. Compared against a count taken
	// at the start rather than against zero, because real classes will register from init() as
	// soon as the first one lands.
	if n := len(RegisteredClassifiers()); n != registeredAtStart {
		t.Errorf("the registry went from %d classifiers to %d, so a refused class was registered anyway", registeredAtStart, n)
	}
}

// A payload conjured at run time would never have been seen by the isolation check, so the law
// would hold over the declared set and say nothing about what went on the wire.
func TestAClassCannotPlanAProbeItNeverDeclared(t *testing.T) {
	c := fakeClass{id: ClassSQL, probes: []ProbeSpec{triageTestProbe("SQL-E1", ClassSQL, "'")}}

	if err := PlannedProbesAreDeclared(c, []ProbeRequest{{Spec: "SQL-E1", Slot: "query:sort"}}); err != nil {
		t.Errorf("a declared probe was rejected: %v", err)
	}
	err := PlannedProbesAreDeclared(c, []ProbeRequest{
		{Spec: "SQL-E1", Slot: "query:sort"},
		{Spec: "SQL-IMPROVISED", Slot: "query:sort"},
	})
	if err == nil {
		t.Fatal("an undeclared probe was accepted, so it would reach the wire without ever being isolation-checked")
	}
	if !strings.Contains(err.Error(), "SQL-IMPROVISED") {
		t.Errorf("error %q does not name the undeclared probe", err)
	}
}

// A probe with no bytes sends nothing, and a class that scores it produces a clean it never
// earned. Controls are exempt: a control whose whole point is the unperturbed value has none.
func TestAnEmptyNonControlPayloadIsRefused(t *testing.T) {
	reg := fixtureRegistry(fakeClass{id: ClassSQL, probes: []ProbeSpec{
		{ID: "SQL-EMPTY", Class: ClassSQL, Points: AllSlotKinds()},
	}})
	if !sawViolation(kindsOf(CheckPayloadIsolation(reg)), IsoEmptyPayload) {
		t.Error("a non-control probe with no payload bytes was accepted")
	}

	ctrl := fixtureRegistry(fakeClass{id: ClassSQL, probes: []ProbeSpec{
		{ID: "SQL-NC1", Class: ClassSQL, Points: AllSlotKinds(), IsControl: true},
	}})
	if sawViolation(kindsOf(CheckPayloadIsolation(ctrl)), IsoEmptyPayload) {
		t.Error("a negative control with no payload was refused")
	}
}

// NormaliseMarkers collapses the per-probe token so two payloads can be compared for what they
// actually test.
func TestMarkerNormalisationCollapsesEveryMarkerForm(t *testing.T) {
	m := markerFor(t, ClassSQL)
	cases := []string{
		"'||" + m + "||'",
		"'||" + strings.ToUpper(m[:1]) + m[1:] + "||'",
		"'||" + strings.ToUpper(m) + "||'",
	}
	want := "'||" + MarkerPlaceholder + "||'"
	for _, in := range cases {
		if got := string(NormaliseMarkers([]byte(in))); got != want {
			t.Errorf("NormaliseMarkers(%q) = %q, want %q", in, got, want)
		}
	}
	// Something that merely starts with the anchor is not a marker and must survive intact, or
	// the normaliser would erase application content and make two different payloads look equal.
	if got := string(NormaliseMarkers([]byte("zqj"))); got != "zqj" {
		t.Errorf("NormaliseMarkers(%q) = %q, want it untouched", "zqj", got)
	}
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

// markerFor builds a well-formed marker in the given class's ordinal stripe.
func markerFor(t *testing.T, c ClassID) string {
	t.Helper()
	return string(testMarker(t, "7f3q", uint64(c)+ClassStripeModulus*3))
}

func kindsOf(r IsolationReport) []IsolationViolationKind {
	out := make([]IsolationViolationKind, 0, len(r.Violations))
	for _, v := range r.Violations {
		out = append(out, v.Kind)
	}
	return out
}

func sawViolation(ks []IsolationViolationKind, want IsolationViolationKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}

// A CLASSIFIER MAY NOT HOLD A RESPONSE, AND REGISTRATION IS WHERE THAT IS ENFORCED.
//
// This closes the last reachable path the value walk in utils/triageadversary found by reasoning
// rather than by measurement. RegisteredClassifiers and ClassifierFor are exported, so every
// registered classifier VALUE is reachable from every other class, and reflect reads through
// unexported fields. Today that is harmless, because every classifier is a stateless struct with
// no fields at all. It stops being harmless the first time one caches its own observations in a
// field: a reflect walk from the registry then hands them to everybody, and the vault's
// partitioning is bypassed without anybody touching the vault.
//
// The check runs at registration rather than in a test, so a class written in six months fails
// loudly on the developer's machine rather than in whichever CI run somebody happens to read.
func TestAClassifierThatCachesResponsesIsRefusedAtRegistration(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Classifier
		want string
	}{
		{"caches observations", statefulClass{}, "Seen"},
		{"holds a handle", handleHoldingClass{}, "Last"},
		{"holds an owned set", setHoldingClass{}, "Mine"},
		{"holds an interface it could put anything in", anyHoldingClass{}, "Scratch"},
		{"holds one two structs down", nestedHoldingClass{}, "Inner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			where, bad := classifierCarriesAResponse(reflect.TypeOf(tc.c), tc.c.ID().String(), map[reflect.Type]bool{})
			if !bad {
				t.Fatalf("a classifier declaring %s was accepted, so it could cache its own responses in a field that every other class can reflect into", tc.name)
			}
			if !strings.Contains(where, tc.want) {
				t.Errorf("the refusal points at %q, which does not name the field %q", where, tc.want)
			}
			t.Logf("refused at %s", where)
		})
	}

	// And the shapes that are FINE are fine, or every real classifier fails to register. A class
	// with configuration, counters or a compiled pattern is not the shape this exists to catch.
	for _, tc := range []struct {
		name string
		c    Classifier
	}{
		{"stateless", cleanClass{}},
		{"scalars and a pattern", configuredClass{}},
	} {
		if where, bad := classifierCarriesAResponse(reflect.TypeOf(tc.c), tc.c.ID().String(), map[reflect.Type]bool{}); bad {
			t.Errorf("a %s classifier was refused at %s. A guard that fires on correct code is a guard the next person deletes", tc.name, where)
		}
	}

	// The real registry passes, which is the point of running it here rather than only in the
	// classifier package.
	for id, c := range RegisteredClassifiers() {
		if where, bad := classifierCarriesAResponse(reflect.TypeOf(c), id.String(), map[reflect.Type]bool{}); bad {
			t.Errorf("registered classifier %s holds a response at %s", id, where)
		}
	}
}

type registryProbeBase struct{}

func (registryProbeBase) ID() ClassID { return ClassSQL }
func (registryProbeBase) Probes() []ProbeSpec {
	return []ProbeSpec{{ID: "RP-1", Class: ClassSQL, Logical: []byte("rp"), Points: []SlotKind{KindQuery}}}
}
func (registryProbeBase) Reaches(SlotKind, MediaType) Reachability {
	return Reachability{Reach: ReachAlways}
}
func (registryProbeBase) Plan(PlanCtx) []ProbeRequest         { return nil }
func (registryProbeBase) Classify(ClassifyCtx) []ClassVerdict { return nil }

type cleanClass struct{ registryProbeBase }

type configuredClass struct {
	registryProbeBase
	Rounds  int
	Name    string
	Pattern *regexp.Regexp
}

type statefulClass struct {
	registryProbeBase
	Seen []Observation
}

type handleHoldingClass struct {
	registryProbeBase
	Last Perturbed
}

type setHoldingClass struct {
	registryProbeBase
	Mine OwnedResponses
}

type anyHoldingClass struct {
	registryProbeBase
	Scratch map[string]any
}

type nestedHoldingClass struct {
	registryProbeBase
	Inner struct{ Deep []*Observation }
}
