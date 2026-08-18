package utils

import "testing"

// The calibration answers "is the saved session being honoured". It used to answer it with the
// scope target's base URL, which on a static shell or CDN index returns identical bytes signed in
// or out, so a live session measured as dead and the operator was sent to fix a working credential.
//
// credsVerdict mirrors the decision made in the calibration block. nil means the question could not
// be answered, which is deliberately distinct from answering no.
func credsVerdict(differs, discriminatingProbe, isSPAShell bool) *bool {
	yes, no := true, false
	switch {
	case differs:
		return &yes
	case discriminatingProbe || !isSPAShell:
		return &no
	default:
		return nil
	}
}

func name(v *bool) string {
	if v == nil {
		return "undetermined"
	}
	if *v {
		return "honoured"
	}
	return "not_honoured"
}

// The defect: base URL on an SPA shell always matched, and the match was reported as a dead session.
func TestUndeterminedWhenTheOnlyProbeCannotDiscriminate(t *testing.T) {
	got := credsVerdict(false, false, true)
	if got != nil {
		t.Errorf("base URL on an SPA shell reported %q; the probe cannot vary by credential there, "+
			"so the only honest answer is undetermined", name(got))
	}
}

// A probe that already refuses anonymous callers gives a real answer either way.
func TestDiscriminatingProbeGivesARealAnswer(t *testing.T) {
	if got := credsVerdict(true, true, true); got == nil || !*got {
		t.Errorf("arms differed on a discriminating probe, got %q, want honoured", name(got))
	}
	if got := credsVerdict(false, true, true); got == nil || *got {
		t.Errorf("arms matched on a discriminating probe, got %q, want not_honoured", name(got))
	}
}

// The true negative has to survive: on a target whose root does vary by path, a match is evidence.
func TestMatchOnANonShellTargetIsStillNotHonoured(t *testing.T) {
	if got := credsVerdict(false, false, false); got == nil || *got {
		t.Errorf("got %q, want not_honoured", name(got))
	}
}

// Differing arms always mean honoured, whatever the probe was.
func TestDifferingArmsAreAlwaysHonoured(t *testing.T) {
	for _, disc := range []bool{true, false} {
		for _, spa := range []bool{true, false} {
			if got := credsVerdict(true, disc, spa); got == nil || !*got {
				t.Errorf("differs with discriminating=%v spa=%v gave %q", disc, spa, name(got))
			}
		}
	}
}
