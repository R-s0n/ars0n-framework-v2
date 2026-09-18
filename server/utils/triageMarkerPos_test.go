package utils

import (
	"bytes"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// MarkerPos WAS DEAD METADATA, AND IT BLINDED WHOLE CLASSES.
//
// triageRenderPayload substituted a marker a payload SPELLS: the placeholder, a marker-shaped
// literal, ${m}, <m>. A class that declared a BARE payload plus MarkerPos, which is what the
// field is for, got no marker on the wire. The runner stamped MarkerPos onto the Observation and
// never used it to place anything.
//
// Measured before this fix: CSTI sent q=%7B%7B7919%2A6271%7D%7D with no marker, every landing
// site was Unattributed, and the class fell through to decode_depth_unknown. It could not have
// fired on any input on any target. Across the ten classifiers, lfi declares MarkerPos 31 times
// and spells a placeholder 0 times; traversal 22 and 0; sql 8 and 0; rfi 8 and 0.
func TestMarkerPosPlacesAMarkerOnAPayloadThatSpellsNone(t *testing.T) {
	mk := triageTestMarker(t, triage.ClassCSTI, 10)
	bare := []byte("{{7919*6271}}")

	cases := []struct {
		name string
		pos  triage.MarkerPos
		want func(got []byte) bool
		why  string
	}{
		{"prefix", triage.MarkerPrefix,
			func(g []byte) bool { return bytes.HasPrefix(g, []byte(mk)) },
			"a prefix marker must lead the payload, because that is where the classes look for it"},
		{"suffix", triage.MarkerSuffix,
			func(g []byte) bool { return bytes.HasSuffix(g, []byte(mk)) },
			"a suffix marker must trail the payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := triage.ProbeSpec{ID: "T-1", Class: triage.ClassCSTI, Logical: bare, MarkerPos: tc.pos}
			got, why := triageRenderPayload(spec, triage.ProbeRequest{}, triage.Slot{}, mk)
			if why != "" {
				t.Fatalf("render refused: %s", why)
			}
			if !bytes.Contains(got, []byte(mk)) {
				t.Fatalf("THE DEAD-METADATA BUG: MarkerPos %q placed no marker at all. Wire bytes %q carry nothing to attribute a reflection to, so every landing site reads Unattributed and the class can never fire", tc.pos, got)
			}
			if !tc.want(got) {
				t.Fatalf("%s: got %q", tc.why, got)
			}
			// The payload's own grammar must survive intact beside the marker.
			if !bytes.Contains(got, bare) {
				t.Fatalf("the payload's own bytes were damaged placing the marker: %q", got)
			}
		})
	}
}

// THE GUARD: a class that spells its own marker has chosen where it goes.
//
// Placing a second one would corrupt a payload whose grammar depends on its exact bytes. SSTI's
// ${1721*913} and CMDI's ${IFS} are payloads, not tokens, and a runner that rewrote them would
// turn the two classes with the cheapest true positives into two that never send anything.
func TestAPayloadThatSpellsItsOwnMarkerIsNotGivenASecond(t *testing.T) {
	mk := triageTestMarker(t, triage.ClassCSTI, 10)
	spec := triage.ProbeSpec{ID: "T-2", Class: triage.ClassCSTI,
		Logical: []byte(triage.MarkerPlaceholder + "{{7919*6271}}"), MarkerPos: triage.MarkerPrefix}

	got, why := triageRenderPayload(spec, triage.ProbeRequest{}, triage.Slot{}, mk)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if n := bytes.Count(got, []byte(mk)); n != 1 {
		t.Fatalf("the payload spelled its own marker and got %d copies: %q. A duplicate marker makes the class's own attribution rule ambiguous", n, got)
	}
}

// AN EMPTY MarkerPos STILL MEANS NO MARKER, and several probes need exactly that.
//
// A marker prefixed onto {"$eq":"alice"} makes invalid JSON and produces the 400 that NOSQL
// exists to tell apart from a genuine engine error. Nine of its probes carry no marker on purpose.
func TestAnEmptyMarkerPosLeavesThePayloadBare(t *testing.T) {
	mk := triageTestMarker(t, triage.ClassNoSQL, 5)
	bare := []byte(`{"$eq":"alice"}`)
	spec := triage.ProbeSpec{ID: "T-3", Class: triage.ClassNoSQL, Logical: bare}

	got, why := triageRenderPayload(spec, triage.ProbeRequest{}, triage.Slot{}, mk)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if bytes.Contains(got, []byte(mk)) {
		t.Fatalf("a probe that declared no MarkerPos was given a marker anyway: %q. That turns a deliberate bare payload into invalid JSON and manufactures the exact 400 this class must distinguish from an engine error", got)
	}
	if !bytes.Equal(got, bare) {
		t.Fatalf("a bare payload was altered: got %q want %q", got, bare)
	}
}
