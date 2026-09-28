package triageclasses

import (
	"strconv"

	"ars0n-framework-v2-server/utils/triage"
)

// pxControlRefusesEveryone is the 4xx half of the body-surface precondition, and it is a DIFFERENT
// RULE from the 5xx half rather than the same rule with a wider band.
//
// WHERE IT BELONGS AND WHY IT IS NOT THERE. pxBodySurfaceUnreadable in deser.go is the shared
// precondition every pxReadsBody class asks, and its control arm is a bare status >= 500 copied
// from ORM-LEAK's junk_sensitive. This function is the missing arm and it should be folded into
// that one, so that DESER, ORM-LEAK and every later adopter get it from the same place. It is a
// separate function in a separate file for a working-tree reason and not a design one: deser.go
// was being edited by another hand while this round ran, and a second writer to one file is how
// somebody's work disappears. The fold-in is a report item, not a decision left open.
//
// THE RULE, AND WHY IT NEEDS TWO WITNESSES WHERE THE 5xx ARM NEEDS ONE.
//
// A 5xx IS THE APPLICATION SAYING IT BROKE. The unperturbed control carries none of our bytes, so
// an endpoint that answers 5xx to it never got as far as reading anything we sent, and the page it
// serves is the failure's whatever we send. One witness is enough.
//
// A 4xx SAYS NOTHING OF THE KIND. A 404 to the observed value is an ordinary, deliberate answer,
// and an endpoint that 404s its own value and answers a payload that reached a sink has handed the
// class a real body to read. Refusing on the status alone would delete those true negatives. So
// this arm also requires that NOTHING THIS CLASS SENT MOVED THE ENDPOINT: the body searched is
// then, measurably, the page this endpoint hands a request it is refusing, identically, including
// to a request carrying nothing of ours.
//
// WHY IT IS WORTH AN ARM AT ALL. The operator's live estate answers 401 to 88% of probes. The
// credential-carrying case is caught by the auth gate. A vector with NO credential against an
// endpoint that refuses everyone falls through both, and lands on a clean.
//
// WHAT IT DOES NOT SAY, AND THE DIFFERENCE IS DELIBERATELY NOT MEASURED HERE: why the endpoint
// refuses. A 404 to everything and a 401 to everything are different facts about a target and this
// witness distinguishes neither. Neither has to be distinguished for this decision, because what
// makes the negative unreadable is only that the refusal is the same for us as for a request
// carrying none of our bytes. A class that wants to act on WHICH refusal it was needs its own
// witness for that and must not read one into this sentence.
func pxControlRefusesEveryone(honest []faOwnObs, control triage.Observation, haveControl bool) (string, bool) {
	if !haveControl || control.Status < 400 || control.Status >= 500 {
		return "", false
	}
	s := pxRouteSensitivity(honest, control, haveControl)
	if s.Delivered == 0 || s.Moved > 0 || s.Flat < pxDifferentialWitnessFloor {
		return "", false
	}
	why := "control_refuses_everyone: the unperturbed route control carries none of our bytes and it " +
		"answered " + strconv.Itoa(control.Status) + ", and " + strconv.Itoa(s.Flat) + " of this " +
		"class's " + pxCount(s.Delivered, "delivered probes") + " came back INDISTINGUISHABLE from " +
		"it, not one of them moving it"
	if s.Unknown > 0 {
		why += " (" + pxCount(s.Unknown, "further probe(s)") + " could not be compared at all)"
	}
	return why + ". A 4xx IS NOT A CRASH AND THIS RULE NEEDS BOTH HALVES FOR THAT REASON: a 404 to " +
		"the observed value is an ordinary answer and would leave a real body to read the moment one " +
		"payload moved the endpoint. Together the two halves say something narrower and firmer than " +
		"the 5xx arm: every body this class searched is the page this endpoint hands a request it is " +
		"refusing, so the silence is the refusal's and not the application's answer about our value. " +
		"WHAT THIS DOES NOT SAY: why it refuses. A 404 and a 401 are different facts, this witness " +
		"distinguishes neither, and neither is needed here", true
}
