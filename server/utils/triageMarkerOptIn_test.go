package utils

import (
	"bytes"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// MARKER INJECTION IS OPT-IN, AND THE DEFAULT IS THE POINT.
//
// MarkerPos is DESCRIPTIVE: it records where the marker sits in a payload that spells one. It was
// briefly read as an INSTRUCTION, and the runner injected a marker into any payload declaring a
// MarkerPos and spelling no token. That rescued two inert classes and damaged three working ones,
// each found by measuring the oracle rather than by review:
//
//	ELI-EL6  "bare, NO MARKER": the prefix made the value <marker>1*(...), a parse error.
//	LFI-L7   depends on the plaintext marker being ABSENT (only its base64 is sent). Injecting it
//	         gave suspicious on 31 echo routes, a FINDING at high on a clean control, and
//	         downgraded the real /lfi positive.
//	SSTI     the polyglot came back rewritten on 26 routes: the marker changed the bytes whose
//	         survival the probe measures.
//
// Blast radius: lfi declares MarkerPos 31 times and spells a token 0 times, traversal 22 and 0,
// sql 8 and 0, rfi 8 and 0.
func TestAClassThatDidNotOptInGetsNoInjectedMarker(t *testing.T) {
	mk := triageTestMarker(t, triage.ClassLFI, 14)
	// The LFI-L7 shape: declares a position, spells no token, and its whole oracle rests on the
	// plaintext marker NOT being in the request.
	bare := []byte("data:text/plain;base64,ZXhhbXBsZQ==")
	spec := triage.ProbeSpec{ID: "LFI-L7-shape", Class: triage.ClassLFI,
		Logical: bare, MarkerPos: triage.MarkerInline}

	got, why := triageRenderPayload(spec, triage.ProbeRequest{}, triage.Slot{}, mk)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if bytes.Contains(got, []byte(mk)) {
		t.Fatalf("a class that did not opt in had a marker injected: %q.\nLFI-L7's oracle is that the plaintext marker was NEVER in the request, so this turns a near-zero-false-positive probe into a weaker one while keeping its grading", got)
	}
	if !bytes.Equal(got, bare) {
		t.Fatalf("the payload was altered: got %q want %q", got, bare)
	}
}

// ELI IS ONE OF THE THREE CLASSES THAT OPTED IN, and it is the one that is inert without this.
func TestTheClassThatOptedInStillGetsItsMarker(t *testing.T) {
	if !triageRunnerPlacesMarkers(triage.ClassELI) {
		t.Fatal("ELI no longer opts in to runner-placed markers, which makes the class inert: every landing site reads Unattributed and it fires on nothing. Measured on the oracle, the opt-in is the difference between 0/0/0/62 and 2/1/27/28")
	}
	mk := triageTestMarker(t, triage.ClassELI, 2)
	spec := triage.ProbeSpec{ID: "ELI-shape", Class: triage.ClassELI,
		Logical: []byte("1*((1).valueOf('1900000000')+1900000000)"), MarkerPos: triage.MarkerPrefix}

	got, why := triageRenderPayload(spec, triage.ProbeRequest{}, triage.Slot{}, mk)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if !bytes.HasPrefix(got, []byte(mk)) {
		t.Fatalf("ELI opted in and got no prefix marker: %q", got)
	}
}

// AND THE PER-PROBE OPT-OUT STILL WINS INSIDE AN OPTED-IN CLASS.
func TestTheBareProbeOptOutBeatsTheClassOptIn(t *testing.T) {
	mk := triageTestMarker(t, triage.ClassELI, 2)
	spec := triage.ProbeSpec{ID: "ELI-EL6", Class: triage.ClassELI,
		Logical: []byte("1*((1).valueOf('1900000000')+1900000000)"), MarkerPos: triage.MarkerPrefix}
	req := triage.ProbeRequest{Variant: map[string]string{"marker_placement": "omitted"}}

	got, why := triageRenderPayload(spec, req, triage.Slot{}, mk)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if bytes.Contains(got, []byte(mk)) {
		t.Fatalf("ELI-EL6 is the bare-expression probe and was given a marker anyway: %q. A 16-byte prefix makes this a parse error in every dialect, so the sink is never tested", got)
	}
}

// NO CLASS HAS QUIETLY OPTED IN.
//
// THREE have, deliberately, and each is named here with its reason so a fourth cannot appear by
// accident. This test has already earned itself once: it caught NOSQL opting in during the same
// session it was written.
//
//	ELI    payloads are expressions whose grammar a spelled token would disturb. Without the
//	       opt-in the class is inert: measured 0/0/0/62 against 2/1/27/28 with it.
//	NOSQL  declares MarkerPos 34 times and spells a token 4 times; its payloads are JSON operator
//	       documents. Without the opt-in it produced 816 probe_not_observed verdicts on a live run.
//	SSTI   its probe table is written for PREFIX placement and it spells no token of its own.
//	       Without the opt-in the census probe reaches the wire carrying no marker, and the
//	       reflection search looks for bytes nobody sent: census_marker_not_sent on 63 slots.
//
// Everything else must stay OUT, because injecting a marker into a payload that did not ask for
// one broke LFI-L7 (its oracle is that the plaintext marker is ABSENT from the request), SSTI's
// polyglot (it measures whether its own bytes come back unrewritten) and ELI-EL6 (bare by design).
//
// THE NAME SAID TWO AND THE TABLE HELD THREE, and three is correct.
//
// THAT IS NOT A TYPO, IT IS AN INVITATION. A guard test whose name contradicts its own table is
// one careless edit away from somebody "fixing" the table to match the name, and deleting SSTI
// from it silently reopens the marker-placement regression that damaged five classes. The count
// is asserted below, in its own statement, so the name, the table and the number can no longer
// disagree in silence: change the set and this test tells you to change the name too.
func TestOnlyTheThreeDeclaredClassesAskTheRunnerToPlaceMarkers(t *testing.T) {
	allowed := map[triage.ClassID]string{
		triage.ClassELI:   "expression grammar, inert without it",
		triage.ClassNoSQL: "JSON operator documents, 816 unobserved probes without it",
		triage.ClassSSTI:  "probe table written for prefix placement; census_marker_not_sent on 63 slots without it",
	}

	// THE COUNT IS PINNED SEPARATELY FROM THE TABLE. Asserting len(allowed) against a literal is
	// the one check a careless edit cannot satisfy by editing the table alone.
	const declared = 3
	if len(allowed) != declared {
		t.Fatalf("the allowed map holds %d classes and this test is named for %d. Changing the set of "+
			"classes that get runner-placed markers is a real decision with a measured history; rename the "+
			"test, update this constant and write the new class's reason into the comment above",
			len(allowed), declared)
	}

	optedIn := 0
	for _, id := range triage.AllClassIDs() {
		if triageRunnerPlacesMarkers(id) {
			optedIn++
		}
	}
	if optedIn != declared {
		t.Errorf("%d classes opt in to runner-placed markers and exactly %d are declared here. The count is "+
			"asserted on its own so a class cannot join or leave the set by editing the table", optedIn, declared)
	}

	for _, id := range triage.AllClassIDs() {
		if !triageRunnerPlacesMarkers(id) {
			continue
		}
		if _, ok := allowed[id]; !ok {
			t.Errorf("class %s opted in to runner-placed markers. That is a real decision with a history: as a default it broke LFI-L7, SSTI's polyglot and ELI-EL6. If it is deliberate, add it to the allowed map above WITH ITS REASON", id)
		}
	}
	for id, why := range allowed {
		if !triageRunnerPlacesMarkers(id) {
			t.Errorf("class %s stopped opting in (%s), which makes it blind rather than merely different", id, why)
		}
	}
}
