package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"
)

// The tests that matter here are the refusals. A settings screen that accepts a payload it cannot
// send, or a payload that collides with a shipped one, is a screen that produces a clean verdict
// for a test that never ran, and that is the single failure this whole layer exists to prevent.

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

func triageProblemCodes(ps []TriageFieldProblem) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return out
}

func hasProblem(t *testing.T, ps []TriageFieldProblem, code string) TriageFieldProblem {
	t.Helper()
	for _, p := range ps {
		if p.Code == code {
			return p
		}
	}
	t.Fatalf("expected a problem with code %q, got %v", code, triageProblemCodes(ps))
	return TriageFieldProblem{}
}

func refuseProblem(t *testing.T, ps []TriageFieldProblem, code string) {
	t.Helper()
	for _, p := range ps {
		if p.Code == code {
			t.Fatalf("did not expect a problem with code %q: %s", code, p.Message)
		}
	}
}

// aShippedPayload returns one real probe from the registry, so the collision tests are run against
// what actually ships rather than against a string written here that could drift from it.
func aShippedPayload(t *testing.T) (classKey string, classID triage.ClassID, probeID triage.ProbeID, logical []byte) {
	t.Helper()
	reg := triage.RegisteredClassifiers()
	for _, id := range sortedTriageClassIDs(reg) {
		for _, p := range reg[id].Probes() {
			if len(p.Logical) == 0 || p.IsControl {
				continue
			}
			return TriageClassKey(id), id, p.ID, append([]byte(nil), p.Logical...)
		}
	}
	t.Fatal("the registry declares no non-control probe with bytes, so there is nothing to collide with")
	return "", 0, "", nil
}

// aDifferentRegisteredClass returns a registered class key that is not the one given.
func aDifferentRegisteredClass(t *testing.T, notThis triage.ClassID) string {
	t.Helper()
	for _, c := range TriageClassVocabulary() {
		if triage.ClassID(c.ID) == notThis {
			continue
		}
		if triageContainsString(c.Points, string(triage.KindQuery)) {
			return c.Key
		}
	}
	t.Fatalf("the registry has no second class to test cross-class isolation against")
	return ""
}

// settingsWith returns the defaults carrying exactly these custom payloads.
func settingsWith(payloads ...TriageCustomPayload) TriageInvestigateSettings {
	s := TriageSettingsDefaults()
	s.CustomPayloads = payloads
	return s
}

func aValidPayload() TriageCustomPayload {
	return TriageCustomPayload{
		ID:        "cp-1",
		Class:     "sql",
		Label:     "operator payload",
		Payload:   "opx-custom-probe-alpha-1",
		Points:    []string{"query"},
		Detection: TriageDetection{Mode: TriageDetectInherit},
		Enabled:   true,
	}
}

// ---------------------------------------------------------------------------------------------
// the vocabulary comes from the registry
// ---------------------------------------------------------------------------------------------

func TestTriageClassVocabularyIsTheRegistryAndNotAList(t *testing.T) {
	reg := triage.RegisteredClassifiers()
	vocab := TriageClassVocabulary()
	// Every registered class except the reserved placeholders, which are registered so the
	// boundary is exercised and are not attack classes anybody can buy coverage from.
	want := 0
	for id := range reg {
		if !TriageClassIsReserved(id) {
			want++
		}
	}
	if len(vocab) != want {
		t.Fatalf("vocabulary has %d classes, registry has %d of which %d are offerable; the list is not derived from the registry",
			len(vocab), len(reg), want)
	}
	seen := map[string]bool{}
	for _, c := range vocab {
		id := triage.ClassID(c.ID)
		if _, ok := reg[id]; !ok {
			t.Fatalf("vocabulary offers class %s (%d) which is not registered, so nothing would run it", c.Key, c.ID)
		}
		if c.ProbeCount == 0 {
			t.Fatalf("class %s reports zero probes", c.Key)
		}
		if len(c.Points) == 0 && len(c.Unreachable) == 0 {
			t.Fatalf("class %s names neither a reachable point nor a reason it reaches none", c.Key)
		}
		// Every point the class does not reach carries the class's own reason. A class absent from
		// a point with no reason reads as an oversight and is the same pixel as one ruled out.
		for kind, why := range c.Unreachable {
			if strings.TrimSpace(why) == "" {
				t.Fatalf("class %s does not reach %s and gives no reason", c.Key, kind)
			}
		}
		if seen[c.Key] {
			t.Fatalf("duplicate class key %q", c.Key)
		}
		seen[c.Key] = true
	}
	if !seen["sql"] {
		t.Fatalf("the SQL class is registered but is not in the vocabulary: %v", seen)
	}
}

// THE PLACEHOLDER IS NOT AN ATTACK CLASS AND IS NOT OFFERED AS ONE.
//
// triageclasses/example.go plans nothing, sends nothing and can only ever emit not_planned. It
// shipped in the class list as "example | EXAMPLE | probes 1", enabled by default, and the screen
// read "11 of 11 classes enabled". Every part of that sentence was a coverage claim.
func TestTriageReservedPlaceholderIsNotOfferedAsAnAttackClass(t *testing.T) {
	if !TriageClassIsReserved(triage.ClassExample) {
		t.Fatal("ClassExample is the reserved placeholder id and must be treated as reserved")
	}
	// It is still registered. Filtering it from the vocabulary must not have removed it from the
	// registry, because the isolation law runs over its payload and the runner still emits its
	// not_planned rows, and both of those are the point of registering it.
	if _, ok := triage.RegisteredClassifiers()[triage.ClassExample]; !ok {
		t.Fatal("the placeholder is no longer registered, so the registration boundary is no longer exercised")
	}

	key := TriageClassKey(triage.ClassExample)
	for _, c := range TriageClassVocabulary() {
		if c.Key == key || triage.ClassID(c.ID) == triage.ClassExample {
			t.Fatalf("the reserved placeholder is offered as an attack class: %+v", c)
		}
	}
	if _, offered := TriageSettingsDefaults().Classes[key]; offered {
		t.Fatalf("the reserved placeholder is enabled by default under key %q", key)
	}
	for _, k := range ValidateTriageSettings(TriageSettingsDefaults()).EnabledClasses {
		if k == key {
			t.Fatal("the reserved placeholder is counted among the classes that would run")
		}
	}
}

// A document stored while the placeholder was offered is REPORTED, the same way a retired class
// is, rather than dropped behind the operator's back.
func TestTriageStoredPlaceholderKeyIsReportedNotSilentlyDropped(t *testing.T) {
	key := TriageClassKey(triage.ClassExample)
	in := TriageInvestigateSettings{
		Classes: map[string]TriageClassSetting{key: {Enabled: true, Tier: "full", MaxRisk: "R2"}},
	}
	out, reported := NormaliseTriageSettings(in)
	if _, still := out.Classes[key]; still {
		t.Fatal("the placeholder survived normalisation into the effective settings")
	}
	if !triageContainsString(reported, key) {
		t.Fatalf("the placeholder was dropped without being named; reported %v", reported)
	}
}

func TestTriageDefaultsValidateClean(t *testing.T) {
	v := ValidateTriageSettings(TriageSettingsDefaults())
	if !v.OK {
		t.Fatalf("the shipped defaults do not validate: %v", v.Errors)
	}
	if len(v.EnabledClasses) != len(TriageClassVocabulary()) {
		t.Fatalf("defaults enable %d of %d registered classes", len(v.EnabledClasses), len(TriageClassVocabulary()))
	}
	// The isolation law's own gap list travels with the answer. A check that has not been written
	// is not a check that passed, and the screen has to be able to say so.
	if len(v.IsolationChecksNotRun) == 0 {
		t.Fatal("the validation reports no unimplemented isolation checks, but the registry declares some")
	}
	if len(v.RegistryViolations) != 0 {
		t.Fatalf("the shipped registry breaks its own isolation law: %v", v.RegistryViolations)
	}
}

func TestTriageDefaultsTierIsARealTierForEveryClass(t *testing.T) {
	def := TriageSettingsDefaults()
	for _, c := range TriageClassVocabulary() {
		cs := def.Classes[c.Key]
		if len(c.Tiers) > 0 && !triageContainsString(c.Tiers, cs.Tier) {
			t.Fatalf("class %s defaults to tier %q but declares probes only at %v", c.Key, cs.Tier, c.Tiers)
		}
		if cs.MaxRisk == string(triage.RiskR3) {
			t.Fatalf("class %s defaults to R3, which the registry says is opt-in per run", c.Key)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// the risk ceiling is the class's own, not the global vocabulary
// ---------------------------------------------------------------------------------------------

// aClassWithRiskCount returns a registered class declaring exactly n distinct risk tiers.
func aClassWithRiskCount(t *testing.T, n int) TriageClassInfo {
	t.Helper()
	for _, c := range TriageClassVocabulary() {
		if len(c.Risks) == n {
			return c
		}
	}
	t.Fatalf("no registered class declares exactly %d risk tiers, so this test cannot run against the real registry", n)
	return TriageClassInfo{}
}

// "Up to R2" on a class whose every probe is R0 is not a deeper run. It reads as one.
func TestTriageDefaultRiskCeilingIsTheClassesOwnAndNotABlanketR2(t *testing.T) {
	def := TriageSettingsDefaults()
	narrowed := 0
	for _, c := range TriageClassVocabulary() {
		got := def.Classes[c.Key].MaxRisk
		if len(c.Risks) == 0 {
			continue
		}
		if !triageContainsString(c.Risks, got) {
			t.Fatalf("class %s defaults to a ceiling of %s, which is not one of the risk tiers it declares (%v)",
				c.Key, got, c.Risks)
		}
		for _, r := range c.Risks {
			if triage.RiskTier(r) == triage.RiskR3 {
				continue
			}
			if triageRiskCeilingRank(r) > triageRiskCeilingRank(got) {
				t.Fatalf("class %s defaults to %s but declares a probe at %s, so the default refuses a probe it should not",
					c.Key, got, r)
			}
		}
		if triageRiskCeilingRank(got) < triageRiskCeilingRank(string(triage.RiskR2)) {
			narrowed++
		}
	}
	// The measured registry has five such classes: nosql, lfi and rfi at R0, ssti and xss-r at
	// R1. Zero would mean the default was still the blanket.
	if narrowed == 0 {
		t.Fatal("no class defaults below R2, so the ceiling is still a blanket rather than the class's own")
	}
}

func TestTriageCeilingBelowSomeOfAClassesProbesIsSaidOutLoud(t *testing.T) {
	c := aClassWithRiskCount(t, 2)
	s := TriageSettingsDefaults()
	cs := s.Classes[c.Key]
	cs.Enabled = true
	cs.MaxRisk = c.Risks[0] // the lowest tier it declares, so the higher one is refused
	s.Classes[c.Key] = cs

	v := ValidateTriageSettings(s)
	if !v.OK {
		t.Fatalf("a ceiling below some probes is allowed, it is just partial: %v", v.Errors)
	}
	p := hasProblem(t, v.Warnings, "risk_ceiling_refuses_some_probes")
	if p.Field != "classes."+c.Key+".max_risk" {
		t.Fatalf("the warning is not addressed at the control that caused it: %q", p.Field)
	}
	if !strings.Contains(p.Message, c.Risks[1]) {
		t.Fatalf("the warning does not name the tier being refused: %q", p.Message)
	}
	// It must not read as clean, and the message has to say which way it goes.
	if !strings.Contains(p.Message, "never as clean") {
		t.Fatalf("the warning does not say the refused probes are unknown rather than clean: %q", p.Message)
	}
}

func TestTriageCeilingBelowEveryProbeSaysTheClassWouldSendNothing(t *testing.T) {
	c := aClassWithRiskCount(t, 1)
	if triage.RiskTier(c.Risks[0]) == triage.RiskR0 {
		// R0 is the floor, so nothing can sit below it. Find one that is not.
		for _, o := range TriageClassVocabulary() {
			if len(o.Risks) == 1 && triage.RiskTier(o.Risks[0]) != triage.RiskR0 {
				c = o
				break
			}
		}
	}
	if triage.RiskTier(c.Risks[0]) == triage.RiskR0 {
		t.Fatal("every single-risk class sits at R0, so no ceiling can exclude all of its probes")
	}

	s := TriageSettingsDefaults()
	cs := s.Classes[c.Key]
	cs.Enabled = true
	cs.MaxRisk = string(triage.RiskR0)
	s.Classes[c.Key] = cs

	p := hasProblem(t, ValidateTriageSettings(s).Warnings, "risk_ceiling_refuses_every_probe")
	if !strings.Contains(p.Message, "would send nothing") {
		t.Fatalf("a class that is on and can send nothing must say so: %q", p.Message)
	}
}

// A ceiling ABOVE everything the class declares refuses nothing, so it is not an alert. It is
// also what keeps a deeper probe added tomorrow from being silently excluded, which is why the
// stored value is never clamped down to fit.
func TestTriageCeilingAboveEveryProbeIsNeitherWarnedAboutNorClamped(t *testing.T) {
	c := aClassWithRiskCount(t, 1)
	s := TriageSettingsDefaults()
	cs := s.Classes[c.Key]
	cs.Enabled = true
	cs.MaxRisk = string(triage.RiskR3)
	s.Classes[c.Key] = cs

	v := ValidateTriageSettings(s)
	refuseProblem(t, v.Warnings, "risk_ceiling_refuses_some_probes")
	refuseProblem(t, v.Warnings, "risk_ceiling_refuses_every_probe")

	out, _ := NormaliseTriageSettings(s)
	if out.Classes[c.Key].MaxRisk != string(triage.RiskR3) {
		t.Fatalf("normalisation clamped the ceiling from R3 to %q, which would narrow the run on the day the class gains a deeper probe",
			out.Classes[c.Key].MaxRisk)
	}
}

func TestTriageCeilingOnADisabledClassIsNotAnAlert(t *testing.T) {
	c := aClassWithRiskCount(t, 2)
	s := TriageSettingsDefaults()
	s.Classes[c.Key] = TriageClassSetting{Enabled: false, Tier: c.Tiers[0], MaxRisk: c.Risks[0]}
	v := ValidateTriageSettings(s)
	refuseProblem(t, v.Warnings, "risk_ceiling_refuses_some_probes")
	refuseProblem(t, v.Warnings, "risk_ceiling_refuses_every_probe")
}

// ---------------------------------------------------------------------------------------------
// a valid payload is accepted
// ---------------------------------------------------------------------------------------------

func TestTriageValidPayloadIsAccepted(t *testing.T) {
	v := ValidateTriageSettings(settingsWith(aValidPayload()))
	if !v.OK {
		t.Fatalf("a unique, deliverable payload was refused: %v", v.Errors)
	}
	if len(v.Payloads) != 1 || !v.Payloads[0].OK {
		t.Fatalf("payload check did not pass: %+v", v.Payloads)
	}
	if len(v.Payloads[0].Delivery) != 1 || !v.Payloads[0].Delivery[0].Proven {
		t.Fatalf("expected one proven delivery row, got %+v", v.Payloads[0].Delivery)
	}
	if v.Payloads[0].ProbeID != "custom/sql/cp-1" {
		t.Fatalf("probe id %q is not namespaced to the class and payload", v.Payloads[0].ProbeID)
	}
}

func TestTriageBase64PayloadCarriesBytesAStringLiteralCannot(t *testing.T) {
	p := aValidPayload()
	p.Encoding = "base64"
	p.Payload = "wKsAvw==" // 0xc0 0xab 0x00 0xbf: overlong UTF-8 and a NUL
	v := ValidateTriageSettings(settingsWith(p))
	if v.Payloads[0].LogicalLen != 4 {
		t.Fatalf("base64 payload decoded to %d bytes, want 4", v.Payloads[0].LogicalLen)
	}
	refuseProblem(t, v.Errors, "payload_not_decodable")
}

func TestTriageBadBase64IsRefused(t *testing.T) {
	p := aValidPayload()
	p.Encoding = "base64"
	p.Payload = "not base64 at all!!"
	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "payload_not_decodable")
}

// ---------------------------------------------------------------------------------------------
// the isolation law
// ---------------------------------------------------------------------------------------------

func TestTriageCustomPayloadColludingWithAShippedProbeIsRefused(t *testing.T) {
	classKey, _, probeID, logical := aShippedPayload(t)

	p := aValidPayload()
	p.Class = classKey
	p.Payload = string(logical)
	p.Points = []string{"query"}

	v := ValidateTriageSettings(settingsWith(p))
	if v.OK {
		t.Fatal("a payload byte-equal to a shipped probe was accepted, so a block on either would record the other clean")
	}
	got := hasProblem(t, v.Errors, "payload_collision")
	if !strings.Contains(got.Message, string(probeID)) {
		t.Fatalf("the collision message does not name what was collided with: %q", got.Message)
	}
	if v.Payloads[0].OK {
		t.Fatal("the per-payload check says OK while the document carries a collision error")
	}
}

func TestTriageCrossClassCollisionAlsoTripsTheRegistryIsolationLaw(t *testing.T) {
	_, ownerID, _, logical := aShippedPayload(t)
	other := aDifferentRegisteredClass(t, ownerID)

	p := aValidPayload()
	p.Class = other
	p.Payload = string(logical)

	v := ValidateTriageSettings(settingsWith(p))
	if v.OK {
		t.Fatal("a payload byte-equal to another class's shipped probe was accepted")
	}
	codes := strings.Join(triageProblemCodes(v.Errors), ",")
	if !strings.Contains(codes, string(triage.IsoDuplicatePayload)) {
		t.Fatalf("CheckPayloadIsolation did not report the cross-class duplicate; codes were %s", codes)
	}
}

func TestTriageTwoCustomPayloadsWithTheSameBytesAreRefused(t *testing.T) {
	a := aValidPayload()
	b := aValidPayload()
	b.ID = "cp-2"
	b.Class = "xss-r"

	v := ValidateTriageSettings(settingsWith(a, b))
	if v.OK {
		t.Fatal("two custom payloads with identical bytes were accepted")
	}
	got := hasProblem(t, v.Errors, "payload_collision")
	if !strings.Contains(got.Message, "cp-1") {
		t.Fatalf("the collision message does not name the other custom payload: %q", got.Message)
	}
}

func TestTriageDuplicatePayloadIDIsRefused(t *testing.T) {
	a := aValidPayload()
	b := aValidPayload()
	b.Payload = "opx-custom-probe-beta-2"
	v := ValidateTriageSettings(settingsWith(a, b))
	hasProblem(t, v.Errors, "duplicate_id")
}

func TestTriageEmptyPayloadIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Payload = ""
	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "payload_empty")
}

// ---------------------------------------------------------------------------------------------
// deliverability, through the real encoder
// ---------------------------------------------------------------------------------------------

func TestTriageCookiePayloadWithASemicolonIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Points = []string{"cookie"}
	p.Payload = "opx-custom-probe-gamma;DROP"

	v := ValidateTriageSettings(settingsWith(p))
	if v.OK {
		t.Fatal("a cookie payload carrying a semicolon was accepted; RFC 6265 splits the value and the application reads a shorter string")
	}
	hasProblem(t, v.Errors, "not_intact_on_the_wire")

	row := v.Payloads[0].Delivery[0]
	if !row.Delivered {
		t.Fatalf("expected the bytes to be delivered and the value altered, got %+v", row)
	}
	if row.Proven {
		t.Fatalf("a semicolon-split cookie value must not read as proven: %+v", row)
	}
}

func TestTriageHeaderPayloadWithCRLFIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Points = []string{"header"}
	p.Payload = "opx-custom-probe-delta\r\nX-Injected: 1"

	v := ValidateTriageSettings(settingsWith(p))
	if v.OK {
		t.Fatal("a header payload carrying CR LF was accepted; no conforming client can send it")
	}
	hasProblem(t, v.Errors, "not_deliverable")

	row := v.Payloads[0].Delivery[0]
	if row.Delivered || row.Reason != string(ReasonValueCRLF) {
		t.Fatalf("expected a CRLF refusal from the encoder, got %+v", row)
	}
}

func TestTriageBodyPayloadIsCheckedAgainstJSONAndForm(t *testing.T) {
	p := aValidPayload()
	p.Points = []string{"body"}
	p.Payload = `opx-custom-probe-epsilon"&x=1`

	v := ValidateTriageSettings(settingsWith(p))
	media := map[string]bool{}
	for _, d := range v.Payloads[0].Delivery {
		media[d.Media] = true
	}
	if !media["json"] || !media["form"] {
		t.Fatalf("a body payload has to be checked against both media, got %+v", v.Payloads[0].Delivery)
	}
}

func TestTriageFragmentIsNotAnOfferedInsertionPoint(t *testing.T) {
	if triageContainsString(triageSettableSlotKinds(), string(triage.KindFragment)) {
		t.Fatal("the fragment is offered as an insertion point, but no HTTP probe reaches it")
	}
	p := aValidPayload()
	p.Points = []string{"fragment"}
	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "point_unreachable")
}

func TestTriagePayloadWithNoPointIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Points = nil
	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "points_required")
}

func TestTriagePointTheClassDoesNotReachIsRefusedWithTheClassReason(t *testing.T) {
	// Find a real class/point pair the registry rules out, so the test is about the registry and
	// not about a pair written here.
	var key, point, why string
	for _, c := range TriageClassVocabulary() {
		for _, k := range triageSettableSlotKinds() {
			if r, never := c.Unreachable[k]; never {
				key, point, why = c.Key, k, r
				break
			}
		}
		if key != "" {
			break
		}
	}
	if key == "" {
		t.Skip("no registered class rules out a settable insertion point")
	}

	p := aValidPayload()
	p.Class = key
	p.Points = []string{point}
	v := ValidateTriageSettings(settingsWith(p))
	got := hasProblem(t, v.Errors, "class_does_not_reach_point")
	if !strings.Contains(got.Message, why) {
		t.Fatalf("the refusal does not carry the class's own reason %q: %q", why, got.Message)
	}
}

// ---------------------------------------------------------------------------------------------
// the detection rule
// ---------------------------------------------------------------------------------------------

func TestTriagePayloadWithNoDetectionRuleIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Detection = TriageDetection{}
	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "detection_mode_required")
}

func TestTriageDetectionRulesAreValidatedPerMode(t *testing.T) {
	cases := []struct {
		name string
		d    TriageDetection
		code string
	}{
		{"regex with no pattern", TriageDetection{Mode: TriageDetectBodyRegex}, "pattern_required"},
		{"regex that does not compile", TriageDetection{Mode: TriageDetectBodyRegex, Pattern: "("}, "pattern_not_compilable"},
		{"contains with no pattern", TriageDetection{Mode: TriageDetectBodyContains}, "pattern_required"},
		{"status with no statuses", TriageDetection{Mode: TriageDetectStatusIn}, "statuses_required"},
		{"status out of range", TriageDetection{Mode: TriageDetectStatusIn, Statuses: []int{42}}, "status_out_of_range"},
		{"delay of zero", TriageDetection{Mode: TriageDetectTimeDelay}, "delay_required"},
		{"a mode nobody implements", TriageDetection{Mode: "vibes"}, "unknown_detection_mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := aValidPayload()
			p.Detection = tc.d
			hasProblem(t, ValidateTriageSettings(settingsWith(p)).Errors, tc.code)
		})
	}

	for _, mode := range []string{TriageDetectInherit, TriageDetectReflect} {
		p := aValidPayload()
		p.Detection = TriageDetection{Mode: mode}
		if v := ValidateTriageSettings(settingsWith(p)); !v.OK {
			t.Fatalf("detection mode %q was refused: %v", mode, v.Errors)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// classes, pacing, out of band
// ---------------------------------------------------------------------------------------------

func TestTriagePayloadOnAnUnregisteredClassIsRefused(t *testing.T) {
	p := aValidPayload()
	p.Class = "ssrf" // in the register, not registered: nothing would run it
	v := ValidateTriageSettings(settingsWith(p))
	got := hasProblem(t, v.Errors, "unregistered_class")
	if !strings.Contains(got.Message, "sql") {
		t.Fatalf("the refusal does not list what IS registered: %q", got.Message)
	}
}

func TestTriageZeroProbeBudgetIsRefusedRatherThanSilentlyTestingNothing(t *testing.T) {
	s := TriageSettingsDefaults()
	s.Pacing.PerSlotProbes = 0
	s.Pacing.PerRunProbes = 0
	v := ValidateTriageSettings(s)
	if v.OK {
		t.Fatal("a zero probe budget was accepted; every slot would report exhausted and nothing would be tested")
	}
	if n := len(v.Errors); n < 2 {
		t.Fatalf("expected both budgets refused, got %v", triageProblemCodes(v.Errors))
	}
	hasProblem(t, v.Errors, "budget_not_positive")
}

func TestTriagePacingRefusals(t *testing.T) {
	s := TriageSettingsDefaults()
	s.Pacing.RequestsPerSecond = 0
	s.Pacing.Concurrency = 0
	s.Pacing.MutatingAllowance = -1
	v := ValidateTriageSettings(s)
	hasProblem(t, v.Errors, "rate_not_positive")
	hasProblem(t, v.Errors, "concurrency_not_positive")
	hasProblem(t, v.Errors, "allowance_negative")
}

func TestTriageNoCollaboratorIsAWarningNotACleanSilence(t *testing.T) {
	v := ValidateTriageSettings(TriageSettingsDefaults())
	hasProblem(t, v.Warnings, "no_collaborator")
}

func TestTriageOOBModeNeedsTheOperatorsOwnBase(t *testing.T) {
	s := TriageSettingsDefaults()
	s.OOB.Mode = string(triage.OOBWildcardDNS)
	v := ValidateTriageSettings(s)
	hasProblem(t, v.Errors, "collaborator_base_required")

	s.OOB.Base = "oob.example.invalid"
	if v := ValidateTriageSettings(s); !v.OK {
		t.Fatalf("a configured collaborator was refused: %v", v.Errors)
	}

	s.OOB.Mode = "telepathy"
	hasProblem(t, ValidateTriageSettings(s).Errors, "unknown_oob_mode")
}

func TestTriageUnknownClassKeyAndTierAreRefused(t *testing.T) {
	s := TriageSettingsDefaults()
	s.Classes["hologram"] = TriageClassSetting{Enabled: true, Tier: "full", MaxRisk: "R1"}
	s.Classes["sql"] = TriageClassSetting{Enabled: true, Tier: "deep", MaxRisk: "R9"}
	v := ValidateTriageSettings(s)
	hasProblem(t, v.Errors, "unknown_class")
	hasProblem(t, v.Errors, "unknown_tier")
	hasProblem(t, v.Errors, "unknown_risk_tier")
}

func TestTriageNoClassEnabledIsSaidOutLoud(t *testing.T) {
	s := TriageSettingsDefaults()
	for k, cs := range s.Classes {
		cs.Enabled = false
		s.Classes[k] = cs
	}
	v := ValidateTriageSettings(s)
	if !v.OK {
		t.Fatalf("turning every class off is allowed, it is just useless: %v", v.Errors)
	}
	hasProblem(t, v.Warnings, "no_class_enabled")
	if len(v.EnabledClasses) != 0 {
		t.Fatalf("enabled classes should be empty, got %v", v.EnabledClasses)
	}
}

// ---------------------------------------------------------------------------------------------
// normalisation
// ---------------------------------------------------------------------------------------------

func TestTriageNormaliseFillsDefaultsAndReportsRetiredClasses(t *testing.T) {
	in := TriageInvestigateSettings{
		Classes: map[string]TriageClassSetting{
			"sql":     {Enabled: false},
			"ldap":    {Enabled: true}, // in the register, never registered
			"unicorn": {Enabled: true},
		},
	}
	out, retired := NormaliseTriageSettings(in)

	if len(retired) != 2 || retired[0] != "ldap" || retired[1] != "unicorn" {
		t.Fatalf("keys nothing can run must be reported, not silently dropped; got %v", retired)
	}
	if _, still := out.Classes["ldap"]; still {
		t.Fatal("a class nothing registers must not survive into the effective settings")
	}
	if out.Classes["sql"].Enabled {
		t.Fatal("normalisation turned a deliberately disabled class back on")
	}
	if out.Classes["sql"].Tier == "" || out.Classes["sql"].MaxRisk == "" {
		t.Fatalf("normalisation left the tier or risk blank: %+v", out.Classes["sql"])
	}
	if len(out.Classes) != len(TriageClassVocabulary()) {
		t.Fatalf("normalisation produced %d classes, registry has %d", len(out.Classes), len(TriageClassVocabulary()))
	}
	if out.Pacing.PerRunProbes == 0 || out.Tier == "" {
		t.Fatalf("normalisation left a zero where a default belongs: %+v", out)
	}
	if out.CustomPayloads == nil {
		t.Fatal("custom payloads must normalise to an empty list, never null")
	}
	if v := ValidateTriageSettings(out); !v.OK {
		t.Fatalf("a normalised document does not validate: %v", v.Errors)
	}
}

func TestTriageVocabularyServesEveryDeliveryReasonTheEncoderCanReturn(t *testing.T) {
	vocab := TriageSettingsVocabulary()
	reasons, ok := vocab["delivery_reasons"].([]DeliveryReason)
	if !ok || len(reasons) == 0 {
		t.Fatalf("the vocabulary does not carry the delivery reasons: %T", vocab["delivery_reasons"])
	}
	// None of these may render as clean, so the screen has to be handed all of them rather than
	// mapping the ones it happens to have seen.
	if len(reasons) != len(DeliveryReasons()) {
		t.Fatalf("the vocabulary carries %d of %d delivery reasons", len(reasons), len(DeliveryReasons()))
	}
}

// ---------------------------------------------------------------------------------------------
// D2f. THE SAVE-TIME CHECK HAS TO CHECK WHAT GOES ON THE WIRE
//
// The delivery check existed to catch, at save time, the refusal the operator would otherwise
// discover as a silent clean hours later. It checked the LOGICAL payload: the bytes the operator
// typed. The runner does not send those bytes. It sends them with a 16-byte run marker placed per
// MarkerPos, with the owning class's token grammar applied, and it refuses a payload that still
// carries an unsubstituted token. Every one of those differences is a way for a payload to pass
// the check and then never reach the application, and a probe that was never sent is a slot that
// reads as tested.
//
// MEASURED ON THE OPERATOR'S OWN RUN a218419a: 384 of class NOSQL's 965 fidelity rows came back
// json_node_payload_is_not_valid_json, every one of them a shipped probe whose bytes are valid
// JSON and whose wire form, with a marker glued on, is not. The four probes are NSQ-OP0, NSQ-F2,
// NSQ-F3 and NSQ-T3, and two of them are the class's tier-1 arithmetic oracle. The same arithmetic
// kills an operator payload, and until these tests the save-time check said yes to it.
// ---------------------------------------------------------------------------------------------

// aJSONNodePayload is the exact shape the live run refused: bytes that are a valid JSON value on
// their own, delivered by replacing a JSON node, which is the only encoder that can put an
// operator object into a filter document.
func aJSONNodePayload() TriageCustomPayload {
	return TriageCustomPayload{
		ID:        "cp-node",
		Class:     "nosql",
		Label:     "an operator object at a JSON node",
		Payload:   `{"$ne":"opx-custom-node-omega"}`,
		Points:    []string{"body"},
		Encoder:   string(triage.EncodeJSONNodeReplace),
		Detection: TriageDetection{Mode: TriageDetectInherit},
		Enabled:   true,
	}
}

func triageDeliveryRow(t *testing.T, c TriagePayloadCheck, point, media string) TriagePayloadDelivery {
	t.Helper()
	for _, d := range c.Delivery {
		if d.Point == point && d.Media == media {
			return d
		}
	}
	t.Fatalf("no delivery row for point %q media %q in %+v", point, media, c.Delivery)
	return TriagePayloadDelivery{}
}

// THE MARKER IS DROPPED, NOT PLACED, AND THE OPERATOR HAS TO BE TOLD.
//
// triageRenderPayloadInto refuses to turn a JSON value into something json_node_replace would
// reject, so for this payload it leaves the marker off and reports MarkerPos empty. That is the
// right trade and it is completely invisible from the modal: the payload is saved asking for a
// prefix marker and goes out with none, so nothing it provokes can be attributed to it.
func TestTriageAPayloadWhoseMarkerWillBeDroppedSaysSo(t *testing.T) {
	v := ValidateTriageSettings(settingsWith(aJSONNodePayload()))
	if !v.OK {
		t.Fatalf("a deliverable JSON operator object was refused: %v", v.Errors)
	}
	row := triageDeliveryRow(t, v.Payloads[0], "body", "json")
	if !row.Proven {
		t.Fatalf("the JSON node row is not proven: %+v", row)
	}
	if row.MarkerOnWire {
		t.Fatalf("the row claims a marker will be on the wire, but %d bytes glued to these bytes "+
			"stop them being a JSON value and the renderer leaves the marker off: %+v",
			triage.MarkerLen, row)
	}
	if row.WireLen != v.Payloads[0].LogicalLen {
		t.Errorf("wire_len %d against logical_len %d: nothing is added to a payload whose marker "+
			"was dropped", row.WireLen, v.Payloads[0].LogicalLen)
	}
	hasProblem(t, v.Warnings, "marker_dropped_on_the_wire")
}

// AND THE COMBINATION THAT COULD ONLY EVER READ AS A CLEAN IS REFUSED. An oracle that judges a
// hit by finding the marker in the response, on a payload sent with no marker in it, is silent on
// every target there has ever been, and triageCustomVerdict records silence as clean.
func TestTriageReflectOnAPayloadThatLosesItsMarkerIsRefused(t *testing.T) {
	p := aJSONNodePayload()
	p.Detection = TriageDetection{Mode: TriageDetectReflect}

	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "reflect_marker_dropped_on_the_wire")
}

// THE CHECK ENCODES THE WIRE FORM, NOT THE TYPED BYTES. Where the marker IS placed, it is placed
// before the encoder sees the payload, so a cookie payload is checked at its real length and with
// the marker's own bytes in it.
func TestTriageTheEncoderIsHandedTheMarkedBytes(t *testing.T) {
	p := aValidPayload()
	p.Points = []string{"cookie"}

	v := ValidateTriageSettings(settingsWith(p))
	row := triageDeliveryRow(t, v.Payloads[0], "cookie", "")
	if !row.MarkerOnWire {
		t.Fatalf("a prefix-marked payload on a cookie reports no marker on the wire: %+v", row)
	}
	if want := len(p.Payload) + triage.MarkerLen; row.WireLen != want {
		t.Fatalf("wire_len is %d, want %d: the encoder was handed the typed bytes and not what "+
			"goes out", row.WireLen, want)
	}
}

func TestTriageWireLengthIsReportedAndItIncludesTheMarker(t *testing.T) {
	v := ValidateTriageSettings(settingsWith(aValidPayload()))
	c := v.Payloads[0]
	if c.LogicalLen != len(aValidPayload().Payload) {
		t.Fatalf("logical_len is %d, want %d", c.LogicalLen, len(aValidPayload().Payload))
	}
	if want := c.LogicalLen + triage.MarkerLen; c.WireLen != want {
		t.Fatalf("wire_len is %d, want %d: the operator reads this number to decide whether a "+
			"payload fits a field, and the marker is part of what has to fit", c.WireLen, want)
	}
}

// A BARE PAYLOAD HAS TO BE AUTHORABLE, because the alternative is a payload that can never be
// delivered. triageCustomMarkerOmitted in the runner already honours "omitted" and "none"; this
// file was the half that refused to let the operator spell it.
func TestTriageABarePayloadIsAuthorableAndGoesOutUnchanged(t *testing.T) {
	p := aJSONNodePayload()
	p.MarkerPos = "none"

	v := ValidateTriageSettings(settingsWith(p))
	if !v.OK {
		t.Fatalf("a bare JSON operator object was refused: %v", v.Errors)
	}
	row := triageDeliveryRow(t, v.Payloads[0], "body", "json")
	if !row.Proven {
		t.Fatalf("the bare payload is not proven at a JSON node: %+v", row)
	}
	if v.Payloads[0].WireLen != v.Payloads[0].LogicalLen {
		t.Fatalf("a bare payload's wire is %d bytes against %d logical: nothing may be added to it",
			v.Payloads[0].WireLen, v.Payloads[0].LogicalLen)
	}
	if row.MarkerOnWire {
		t.Fatal("a payload saved as bare reports a marker on the wire")
	}
	// The operator asked for this one, so it is not news and must not be warned about.
	refuseProblem(t, v.Warnings, "marker_dropped_on_the_wire")
}

func TestTriageBareIsOfferedInTheVocabularySoTheModalCanRenderIt(t *testing.T) {
	positions, ok := TriageSettingsVocabulary()["marker_positions"].([]string)
	if !ok {
		t.Fatalf("marker_positions is %T", TriageSettingsVocabulary()["marker_positions"])
	}
	if !triageContainsString(positions, "none") {
		t.Fatalf("the modal is offered %v, so an operator cannot author a payload whose grammar "+
			"cannot carry a marker, and every such payload is refused on the wire", positions)
	}
}

// A BARE PAYLOAD CANNOT BE JUDGED BY REFLECTION. There is no marker to come back.
func TestTriageReflectDetectionOnABarePayloadIsRefused(t *testing.T) {
	p := aJSONNodePayload()
	p.MarkerPos = "none"
	p.Detection = TriageDetection{Mode: TriageDetectReflect}

	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "reflect_needs_a_marker")
}

// THE CLASS'S OWN TOKEN GRAMMAR IS APPLIED TO AN OPERATOR PAYLOAD AT SEND TIME, and a token the
// per-instance variant cannot fill refuses the probe. That refusal belongs at save time.
func TestTriagePayloadCarryingAnUnfillableClassTokenIsRefusedAtSaveTime(t *testing.T) {
	p := aValidPayload()
	p.Class = "nosql"
	p.ID = "cp-token"
	p.Points = []string{"query"}
	p.Payload = `{"$lt":"<v>"}`

	v := ValidateTriageSettings(settingsWith(p))
	hasProblem(t, v.Errors, "payload_token_unresolved")
}

// ONE MEDIUM REFUSING IS NOT THE PAYLOAD BEING UNDELIVERABLE. A JSON-node payload reaches a JSON
// body and cannot reach a form body; refusing the SAVE loses the JSON coverage too, and the form
// slots record a named not_reachable rather than a clean. Coverage is the expensive side.
func TestTriageAMediumThatCannotCarryThePayloadIsAWarningNotARefusal(t *testing.T) {
	p := aJSONNodePayload()
	p.MarkerPos = "none"

	v := ValidateTriageSettings(settingsWith(p))
	if !v.OK {
		t.Fatalf("a payload deliverable into a JSON body was refused because a form body cannot "+
			"carry it: %v", v.Errors)
	}
	form := triageDeliveryRow(t, v.Payloads[0], "body", "form")
	if form.Proven {
		t.Fatal("the form row claims to be proven, but json_node_replace cannot render into a form body")
	}
	hasProblem(t, v.Warnings, "not_deliverable_at_one_medium")
}

// ---------------------------------------------------------------------------------------------
// THE PUT THAT SAID saved:true AND SAVED NOTHING THE CALLER SENT
// ---------------------------------------------------------------------------------------------

// MEASURED, on the live estate, twice in a row against the same endpoint:
//
//	PUT .../settings  {"per_run_probes": 25000, ...}            -> {"saved": true}, per_run_probes 4000
//	PUT .../settings  {"settings": {"per_run_probes": 25000}}   -> {"saved": true}, per_run_probes 25000
//
// The handler decoded into struct{ Settings TriageInvestigateSettings `json:"settings"` }. A body
// that IS the settings object carries no "settings" key, so every field of that struct stayed at
// its zero value, NormaliseTriageSettings filled the zeroes with defaults, the defaults validated
// clean, and the row was overwritten with them. The caller was told saved:true and the operator's
// budget went back to 4000.
//
// That is silent data loss on a write endpoint, reachable by anything driving the API directly,
// the MCP layer included. A write endpoint that cannot tell "the caller sent nothing" from "the
// caller sent the defaults" has no business returning saved:true for either.
//
// THE FIX IS NOT "ALSO ACCEPT THE BARE SHAPE AND MOVE ON". It is that a body matching NEITHER
// shape is refused, loudly, instead of decoding to zero. Accepting the bare shape is the
// convenience; refusing the unrecognised one is the safety, and it is the half that was missing.
func TestABareSettingsBodyIsSavedRatherThanSilentlyReplacedWithDefaults(t *testing.T) {
	bare := []byte(`{"tier":"full","pacing":{"per_run_probes":25000,"concurrency":2}}`)
	got, err := DecodeTriageSettingsBody(bare)
	if err != nil {
		t.Fatalf("a body that IS the settings object was refused: %v", err)
	}
	if got.Pacing.PerRunProbes != 25000 {
		t.Errorf("per_run_probes came back %d, want 25000. This is the measured defect: the bare body decoded to the zero struct and the defaults were written over the operator's value.",
			got.Pacing.PerRunProbes)
	}
	if got.Tier != "full" {
		t.Errorf("tier came back %q, want \"full\"", got.Tier)
	}
}

func TestTheWrappedSettingsBodyStillDecodesUnchanged(t *testing.T) {
	wrapped := []byte(`{"settings":{"tier":"full","pacing":{"per_run_probes":25000}}}`)
	got, err := DecodeTriageSettingsBody(wrapped)
	if err != nil {
		t.Fatalf("the shape the form sends was refused: %v", err)
	}
	if got.Pacing.PerRunProbes != 25000 || got.Tier != "full" {
		t.Errorf("the wrapped body lost its values: tier %q, per_run_probes %d", got.Tier, got.Pacing.PerRunProbes)
	}
}

// A BODY THAT IS NEITHER SHAPE MUST BE REFUSED, NOT DEFAULTED. This is the case that produced the
// 4000 above, and under the old handler it returned no error at all.
func TestASettingsBodyThatCarriesNoSettingsFieldIsRefusedRatherThanDefaulted(t *testing.T) {
	for _, body := range []string{
		`{"per_run_probes":25000}`,
		`{"setings":{"tier":"full"}}`,
		`{}`,
		`{"nothing":"recognised","here":1}`,
	} {
		got, err := DecodeTriageSettingsBody([]byte(body))
		if err == nil {
			t.Errorf("body %s was accepted and decoded to %+v. Nothing in it names a settings field, so accepting it writes the defaults over whatever was stored and reports success.",
				body, got)
			continue
		}
		if !strings.Contains(err.Error(), "settings") {
			t.Errorf("body %s was refused with %q, which does not tell the caller what shape was wanted", body, err)
		}
	}
}

// The two shapes at once is ambiguous and there is no right answer to pick, so it is refused
// rather than silently resolved in favour of one of them.
func TestASettingsBodyThatIsBothShapesAtOnceIsRefused(t *testing.T) {
	both := []byte(`{"settings":{"tier":"full"},"tier":"reduced"}`)
	if _, err := DecodeTriageSettingsBody(both); err == nil {
		t.Error("a body carrying both a settings wrapper and top-level settings fields was accepted; one of the two was silently discarded")
	}
}

func TestANonObjectSettingsBodyIsRefused(t *testing.T) {
	for _, body := range []string{``, `   `, `[]`, `"settings"`, `null`, `{`} {
		if _, err := DecodeTriageSettingsBody([]byte(body)); err == nil {
			t.Errorf("body %q was accepted as a settings document", body)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// AUTOMATIC SESSION RENEWAL
// ---------------------------------------------------------------------------------------------
//
// The measurement that produced this section: the bearer on the estate this layer was built
// against is a fifteen minute JWT, six distinct values arrived in ten minutes of browsing, and a
// full triage run takes twenty nine. Same endpoint, same minute, the value frozen in
// attack_vectors.raw_request returned 401 while the one in manual_crawl_captures returned 200.
//
// The tests below are mostly REFUSALS, for the same reason the payload tests above are. A
// renewal switch the operator can turn on for a session the framework has never actually renewed
// is a scan that dies at minute fifteen while the screen says renewal is on, and every class that
// had not run yet reports something other than what the target would have said.

// The field has to be RECOGNISED by the strict decoder, or a body that names only the renewal
// settings is refused as naming no settings field at all. The list is read off the struct, so
// this passes the day the field exists and not the day somebody remembers a list.
func TestASettingsBodyNamingOnlyTheRenewalFieldIsRecognised(t *testing.T) {
	body := []byte(`{"session_renewal":{"enabled":false,"token_id":"","interval_seconds":0}}`)
	if _, err := DecodeTriageSettingsBody(body); err != nil {
		t.Fatalf("a body naming session_renewal was refused: %v\n"+
			"The renewal settings cannot be written by anything driving this API directly, and the strict decoder is the reason: session_renewal is not one of the fields it reads off the document.", err)
	}
	if !triageContainsString(triageSettingsFieldNames(), "session_renewal") {
		t.Fatalf("session_renewal is not a field of the settings document; the fields are %v", triageSettingsFieldNames())
	}
}

// ---------------------------------------------------------------------------------------------
// helpers for the renewal gate
// ---------------------------------------------------------------------------------------------

// renewalNow is a fixed clock. Every duration below is stated against it, so a test that reads
// "proven 20 minutes ago" says so in the arithmetic rather than in a comment.
var renewalNow = time.Date(2026, 9, 20, 12, 30, 0, 0, time.UTC)

// aProfiledCredential is a credential with a MEASURED fifteen minute lifetime and a live expiry:
// the shape the estate this layer was built against actually serves.
func aProfiledCredential(refresh RefreshCapability) SessionTokenProfile {
	return SessionTokenProfile{
		TokenID:          "tok-1",
		Name:             "app bearer",
		Carrier:          CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "},
		Fingerprint:      "aaaa1111",
		Kind:             CredentialKindJWT,
		TTL:              15 * time.Minute,
		TTLKnown:         true,
		TTLProvenance:    ProvParsed,
		TTLEvidence:      "exp minus iat",
		ExpiresAt:        renewalNow.Add(9 * time.Minute),
		ExpiryKnown:      true,
		ExpiryProvenance: ProvParsed,
		ExpiryStyle:      ExpiryStyleAbsolute,
		Refresh:          refresh,
		Attributes:       map[string]string{},
		ProfiledAt:       renewalNow,
	}
}

// aProvenCredential is the whole input for a credential whose refresh WAS performed and returned
// a different credential, provenAgo ago.
func aProvenCredential(provenAgo time.Duration) TriageRenewalCredential {
	return TriageRenewalCredential{
		TokenID:  "tok-1",
		Name:     "app bearer",
		IsActive: true,
		Profile: aProfiledCredential(RefreshCapability{
			Status:      RefreshProven,
			Mechanism:   RefreshMechanismAuthFlow,
			MintHost:    "login.example.test",
			MintInScope: true,
			ProvenAt:    renewalNow.Add(-provenAgo),
		}),
		ProvenAt:              renewalNow.Add(-provenAgo),
		ProofDetail:           "a refresh was performed and a different credential came back: aaaa0000 became aaaa1111",
		ProofAfterFingerprint: "aaaa1111",
		LastRefreshAt:         renewalNow.Add(-provenAgo),
		LastRefreshStatus:     "success",
	}
}

// renewalPacing is a run of 4000 probes at 3.33 per second, which is the shipped default and an
// estimated run of just over twenty minutes.
func renewalPacing() TriagePacing { return TriageSettingsDefaults().Pacing }

func gateFor(creds ...TriageRenewalCredential) TriageRenewalGate {
	return EvaluateTriageRenewalGate(creds, renewalPacing(), renewalNow)
}

func theOnlyOption(t *testing.T, g TriageRenewalGate) TriageRenewalOption {
	t.Helper()
	if len(g.Options) != 1 {
		t.Fatalf("expected exactly one credential option, got %d", len(g.Options))
	}
	return g.Options[0]
}

// ---------------------------------------------------------------------------------------------
// THE HARD RULE: the control is not offerable until a refresh has actually been performed
// ---------------------------------------------------------------------------------------------

// A refresh_token field, a recorded auth flow and a mint endpoint in the corpus are all
// RefreshAvailable. Every one of them is "the mechanism exists"; not one of them is "we renewed
// this session". Offering the switch on any of them is the vulnerable-IF with the IF unproven.
func TestRenewalIsNotOfferableWhenARefreshMechanismMerelyExists(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer", IsActive: true,
		Profile: aProfiledCredential(RefreshCapability{
			Status: RefreshAvailable, Mechanism: RefreshMechanismOAuthRefresh,
			MintHost: "login.example.test", MintInScope: true,
			Evidence: []string{"3 captured response(s) carry a refresh_token field"},
		}),
	}
	g := gateFor(c)
	if g.Offerable {
		t.Fatal("the renewal control was offered for a session nobody has ever refreshed. A refresh_token field is the grant existing; it is not evidence that spending it returns a working credential.")
	}
	o := theOnlyOption(t, g)
	if o.Usable {
		t.Fatal("the credential was marked usable on an available-but-unexercised mechanism")
	}
	if o.Code != TriageRenewalNeverProven {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalNeverProven)
	}
	// The advice has to name a control that RECORDS A PROOF. The Session Manager's Refresh button
	// is not one: it records kind=refresh status=refreshed, and the proof is read from
	// status=success.
	for _, want := range []string{"NEVER been exercised", "the proof button on this screen"} {
		if !strings.Contains(o.Reason, want) {
			t.Errorf("the refusal does not say %q, so it does not tell the operator what would lift it: %s", want, o.Reason)
		}
	}
}

// And the positive case, which must be reachable or the feature is a permanently greyed switch.
func TestRenewalIsOfferableOnceARefreshWasPerformedAndADifferentCredentialCameBack(t *testing.T) {
	g := gateFor(aProvenCredential(2 * time.Minute))
	if !g.Offerable {
		t.Fatalf("a proven refresh did not make the control offerable: %s", g.Reason)
	}
	o := theOnlyOption(t, g)
	if !o.Usable || o.Code != TriageRenewalProven {
		t.Fatalf("usable=%v code=%q, want true and %q: %s", o.Usable, o.Code, TriageRenewalProven, o.Reason)
	}
	if !strings.Contains(o.Reason, "DIFFERENT working credential") {
		t.Errorf("the reason does not say what was proven: %s", o.Reason)
	}
}

// A mechanism outside the engagement is a DIFFERENT answer from unrefreshable, and the advice is
// different too: the operator can log in by hand.
func TestAMintOutsideScopeIsReportedAsThatAndNotAsUnrefreshable(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "sso bearer",
		Profile: aProfiledCredential(RefreshCapability{
			Status: RefreshMintOutOfScope, Mechanism: RefreshMechanismOAuthRefresh,
			MintHost: "sso.vendor.test", MintInScope: false,
		}),
	}
	o := theOnlyOption(t, gateFor(c))
	if o.Code != TriageRenewalMintOutOfScope {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalMintOutOfScope)
	}
	if !strings.Contains(o.Reason, "sso.vendor.test") || !strings.Contains(o.Reason, "by hand") {
		t.Errorf("the refusal names neither the host nor the way round it: %s", o.Reason)
	}
}

func TestNoMechanismAtAllSaysSoRatherThanGoingSilent(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "opaque sid",
		Profile: aProfiledCredential(RefreshCapability{Status: RefreshNotObserved}),
	}
	g := gateFor(c)
	o := theOnlyOption(t, g)
	if o.Code != TriageRenewalNoMechanism {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalNoMechanism)
	}
	if strings.TrimSpace(o.Reason) == "" || strings.TrimSpace(g.Reason) == "" {
		t.Fatal("the control was withheld with no sentence saying why")
	}
}

func TestNoCredentialOnTheTargetSaysAddOne(t *testing.T) {
	g := gateFor()
	if g.Offerable || g.Code != TriageRenewalNoCredential {
		t.Fatalf("offerable=%v code=%q", g.Offerable, g.Code)
	}
	if !strings.Contains(g.Reason, "Session Manager") {
		t.Errorf("the refusal does not say where to add one: %s", g.Reason)
	}
}

func TestACredentialWithNoValueIsNotRenewable(t *testing.T) {
	p := aProfiledCredential(RefreshCapability{Status: RefreshProven})
	p.Fingerprint = ""
	c := TriageRenewalCredential{TokenID: "tok-1", Name: "empty", Profile: p, ProvenAt: renewalNow.Add(-time.Minute)}
	o := theOnlyOption(t, gateFor(c))
	if o.Usable || o.Code != TriageRenewalNoValue {
		t.Fatalf("usable=%v code=%q, want false and %q", o.Usable, o.Code, TriageRenewalNoValue)
	}
}

// Measured as non-expiring is not "renewal is broken", it is "renewal is pointless", and saying
// the first about the second sends the operator looking for a fault that is not there.
func TestANonExpiringCredentialSaysRenewalWouldChangeNothing(t *testing.T) {
	p := aProfiledCredential(RefreshCapability{Status: RefreshProven})
	p.ExpiryStyle = ExpiryStyleNonExpiring
	c := TriageRenewalCredential{TokenID: "tok-1", Name: "api key", Profile: p, ProvenAt: renewalNow.Add(-time.Minute)}
	o := theOnlyOption(t, gateFor(c))
	if o.Code != TriageRenewalNotNeeded {
		t.Fatalf("code = %q, want %q: %s", o.Code, TriageRenewalNotNeeded, o.Reason)
	}
}

// A refresh_status column that says proven with no event behind it must not arm anything. The
// column is written by DetectRefreshCapability from an event; a row edited by hand is not a proof.
func TestAProvenStatusWithNoEventBehindItIsNotAProof(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer",
		Profile: aProfiledCredential(RefreshCapability{Status: RefreshProven}),
		// ProvenAt deliberately zero: the status claims a proof the events table does not hold.
	}
	o := theOnlyOption(t, gateFor(c))
	if o.Usable {
		t.Fatal("a proven status with no successful refresh event behind it armed the control")
	}
	if o.Code != TriageRenewalNeverProven {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalNeverProven)
	}
}

// ---------------------------------------------------------------------------------------------
// A STALE PROOF IS NOT A PROOF
// ---------------------------------------------------------------------------------------------

// Proven on Monday, failing ever since. DetectRefreshCapability selects the most recent SUCCESS
// and never looks at what came after it, so the profile still reads proven; the gate must not.
func TestAProofThatHasBrokenSinceTakesTheControlAway(t *testing.T) {
	c := aProvenCredential(4 * time.Minute)
	c.LastRefreshAt = renewalNow.Add(-90 * time.Second)
	c.LastRefreshStatus = "replay_failed"
	c.LastRefreshDetail = "the linked auth flow returned 401 at step 2"

	g := gateFor(c)
	if g.Offerable {
		t.Fatal("renewal stayed offerable after the refresh that proved it had failed since. A proof that has stopped working describes the past, and leaving the control on it is the stale proof this gate exists to refuse.")
	}
	o := theOnlyOption(t, g)
	if o.Code != TriageRenewalProofBroken {
		t.Fatalf("code = %q, want %q: %s", o.Code, TriageRenewalProofBroken, o.Reason)
	}
	for _, want := range []string{"replay_failed", "step 2", "until a refresh succeeds again"} {
		if !strings.Contains(o.Reason, want) {
			t.Errorf("the refusal does not carry %q: %s", want, o.Reason)
		}
	}
}

// The same proof with the failure BEFORE it is not broken: a flow that failed and was then fixed
// and proven is exactly the sequence this feature wants to reward.
func TestAFailureBEFORETheProofDoesNotBreakIt(t *testing.T) {
	c := aProvenCredential(2 * time.Minute)
	c.LastRefreshAt = c.ProvenAt // the proof is the most recent event
	c.LastRefreshStatus = "success"
	if !gateFor(c).Offerable {
		t.Fatal("a proof that is the most recent refresh event was treated as broken")
	}
}

// A status nobody here has seen is not evidence a refresh worked, so it counts as a failure and is
// quoted verbatim. Waving it through on a default would be the fail-open this codebase keeps
// finding in its own runners.
func TestAnUnrecognisedRefreshStatusCountsAsAFailure(t *testing.T) {
	c := aProvenCredential(3 * time.Minute)
	c.LastRefreshAt = renewalNow.Add(-time.Minute)
	c.LastRefreshStatus = "some_status_added_later"
	o := theOnlyOption(t, gateFor(c))
	if o.Usable {
		t.Fatal("a refresh event with a status this gate does not recognise was treated as a success")
	}
	if !strings.Contains(o.Reason, "some_status_added_later") {
		t.Errorf("the refusal does not quote the status it did not recognise: %s", o.Reason)
	}
}

// A real refresh that stored a new value records status refreshed, not success. It is not a proof
// (nothing compared the two credentials) but it is emphatically not a failure either.
func TestARefreshedEventIsNeitherAProofNorAFailure(t *testing.T) {
	c := aProvenCredential(3 * time.Minute)
	c.LastRefreshAt = renewalNow.Add(-time.Minute)
	c.LastRefreshStatus = "refreshed"
	if !gateFor(c).Offerable {
		t.Fatal("a later successful refresh that did not record a proof was read as a failure, which would take the control away from a session that is being renewed successfully")
	}
}

// The age test. A proof is the statement that a mechanism minted a working credential at T; once
// that credential is dead, nothing about the mint has been observed in the present.
func TestAProofOlderThanTheCredentialItMintedIsStale(t *testing.T) {
	g := gateFor(aProvenCredential(20 * time.Minute)) // the measured lifetime is 15 minutes
	if g.Offerable {
		t.Fatal("a proof older than the whole lifetime of the credential it produced still armed renewal")
	}
	o := theOnlyOption(t, g)
	if o.Code != TriageRenewalProofStale {
		t.Fatalf("code = %q, want %q: %s", o.Code, TriageRenewalProofStale, o.Reason)
	}
	if o.ProofWindowSeconds != 900 {
		t.Fatalf("the proof window is %ds, want the measured 900s lifetime", o.ProofWindowSeconds)
	}
	if !strings.Contains(o.Reason, "20m") || !strings.Contains(o.ProofWindowBasis, "15m") {
		t.Errorf("the refusal does not show the arithmetic: age in %q, window in %q", o.Reason, o.ProofWindowBasis)
	}
}

func TestAProofInsideTheWindowIsNotStale(t *testing.T) {
	if !gateFor(aProvenCredential(14 * time.Minute)).Offerable {
		t.Fatal("a proof younger than the measured lifetime was called stale")
	}
}

// Where only a floor was observed, the proof is held to the floor: a lower bound, so the window
// is the tightest the evidence supports and it errs towards asking for a new proof.
func TestWithOnlyAFloorTheProofIsHeldToTheFloor(t *testing.T) {
	c := aProvenCredential(6 * time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL, p.TTLProvenance, p.TTLEvidence = false, 0, ProvUnknown, ""
	p.ExpiryKnown = false
	p.TTLFloorKnown, p.TTLFloor = true, 5*time.Minute
	// The provenance the corpus path always writes. A floor with no provenance is refused by
	// TriageRenewalIntervalFor and triageProofWindowFor, so a fixture that leaves it empty is
	// testing a row nothing in production writes.
	p.TTLFloorProvenance = ProvObserved
	p.ObservedEvidence = "samples=51 requests=3701"
	c.Profile = p

	o := theOnlyOption(t, gateFor(c))
	if o.ProofWindowSeconds != 300 {
		t.Fatalf("the proof window is %ds, want the 300s observed floor", o.ProofWindowSeconds)
	}
	if o.Usable {
		t.Fatalf("a proof older than the observed floor was accepted: %s", o.Reason)
	}
	if !strings.Contains(o.ProofWindowBasis, "lower bound") {
		t.Errorf("the window does not say the span it used is a lower bound and not a lifetime: %s", o.ProofWindowBasis)
	}
}

// With NOTHING measured there is no clock of the credential's own, and the proof is instead
// required to cover the run it is authorising. The run length is derived from this document's own
// pacing, so it is not a number invented here.
func TestWithNothingMeasuredTheProofIsHeldToTheEstimatedRunLength(t *testing.T) {
	c := aProvenCredential(30 * time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL = false, 0
	p.ExpiryKnown = false
	p.TTLFloorKnown = false
	c.Profile = p

	g := gateFor(c)
	pacing := renewalPacing()
	runEstimate, _ := TriageEstimatedRunDuration(pacing)
	runSecs := int64(runEstimate / time.Second)
	o := theOnlyOption(t, g)
	if o.ProofWindowSeconds != runSecs {
		t.Fatalf("the proof window is %ds, want the estimated run of %ds", o.ProofWindowSeconds, runSecs)
	}
	if g.RunEstimateSeconds != runSecs {
		t.Fatalf("the gate reports a run estimate of %ds, want %ds", g.RunEstimateSeconds, runSecs)
	}
	if o.Usable {
		t.Fatalf("a 30 minute old proof was accepted against a %ds run window", runSecs)
	}
}

// ---------------------------------------------------------------------------------------------
// THE INTERVAL COMES FROM THE MEASUREMENT
// ---------------------------------------------------------------------------------------------

func TestTheIntervalIsHalfTheMeasuredLifetimeAndSaysWhichLifetime(t *testing.T) {
	o := theOnlyOption(t, gateFor(aProvenCredential(time.Minute)))
	if !o.IntervalKnown || o.IntervalSeconds != 450 {
		t.Fatalf("interval = %ds (known=%v), want 450s, half of the measured 900s", o.IntervalSeconds, o.IntervalKnown)
	}
	for _, want := range []string{"half of the measured", "15m", "parsed", "exp minus iat", "retry window"} {
		if !strings.Contains(o.IntervalBasis, want) {
			t.Errorf("the basis does not carry %q, so the operator cannot audit the number: %s", want, o.IntervalBasis)
		}
	}
}

// An unmeasured lifetime yields NO interval. The alternative, a default, is a schedule that
// under-runs or over-runs with nothing on the screen saying which.
func TestAnUnmeasuredLifetimeYieldsNoIntervalRatherThanADefault(t *testing.T) {
	c := aProvenCredential(time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL = false, 0
	p.TTLFloorKnown = false
	c.Profile = p

	o := theOnlyOption(t, gateFor(c))
	if o.IntervalKnown || o.IntervalSeconds != 0 {
		t.Fatalf("an interval of %ds was produced for a credential whose lifetime was never measured", o.IntervalSeconds)
	}
	if !strings.Contains(o.IntervalBasis, "no interval can be derived from a measurement") {
		t.Errorf("the basis does not say the lifetime was never measured: %s", o.IntervalBasis)
	}
	if !triageAnyContains(o.Warnings, "never been measured") {
		t.Errorf("no warning says the lifetime is unmeasured at the point of configuration: %v", o.Warnings)
	}
}

// exp minus nbf is an UPPER bound, because an issuer may backdate nbf for clock skew. An interval
// derived from an upper bound can fire after the credential is already dead, and that is the one
// direction that matters, so it is said out loud.
func TestAnUpperBoundLifetimeIsFlaggedWhereTheIntervalIsChosen(t *testing.T) {
	c := aProvenCredential(time.Minute)
	p := c.Profile
	p.TTLEvidence = "exp minus nbf; the token carries no iat, and nbf is an upper bound on the lifetime because an issuer may backdate it for clock skew"
	c.Profile = p

	o := theOnlyOption(t, gateFor(c))
	if !o.TTLIsUpperBound {
		t.Fatal("a lifetime the profiler itself called an upper bound was not flagged as one")
	}
	if !strings.Contains(o.IntervalBasis, "UPPER BOUND") {
		t.Errorf("the interval basis does not say it rests on an upper bound: %s", o.IntervalBasis)
	}
	if !triageAnyContains(o.Warnings, "fire after the credential is already dead") {
		t.Errorf("no warning says what an upper bound costs: %v", o.Warnings)
	}
}

// A floor may drive the interval, because half a lower bound renews EARLY. It may never be called
// a TTL while doing so: on the live corpus the observed median was wrong by eighty times.
func TestAFloorMayDriveTheIntervalButIsNeverCalledALifetime(t *testing.T) {
	c := aProvenCredential(time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL = false, 0
	p.TTLFloorKnown, p.TTLFloor = true, 14*time.Minute
	p.TTLFloorProvenance = ProvObserved
	p.ObservedEvidence = "samples=51 requests=3701"
	c.Profile = p

	o := theOnlyOption(t, gateFor(c))
	if !o.IntervalKnown || o.IntervalSeconds != 420 {
		t.Fatalf("interval = %ds (known=%v), want 420s, half of the 14m observed floor", o.IntervalSeconds, o.IntervalKnown)
	}
	if o.TTLKnown {
		t.Fatal("the floor was reported as a measured lifetime")
	}
	if !strings.Contains(o.IntervalBasis, "LOWER BOUND") || !strings.Contains(o.IntervalBasis, "not a TTL") {
		t.Errorf("the basis lets a floor read as a lifetime: %s", o.IntervalBasis)
	}
}

func TestTheEstimatedRunLengthIsTheRunsOwnBudgetAtItsOwnRate(t *testing.T) {
	d, basis := TriageEstimatedRunDuration(TriagePacing{RequestsPerSecond: 4, PerRunProbes: 1200})
	if d != 300*time.Second {
		t.Fatalf("estimate = %v, want 300s (1200 probes at 4 per second)", d)
	}
	for _, want := range []string{"estimated", "1200 probes", "4.00 per second"} {
		if !strings.Contains(basis, want) {
			t.Errorf("the basis does not show the arithmetic (%q): %s", want, basis)
		}
	}
	if _, basis := TriageEstimatedRunDuration(TriagePacing{}); !strings.Contains(basis, "cannot be estimated") {
		t.Errorf("an unpaced run produced an estimate instead of saying it could not: %s", basis)
	}
}

// The measurement the whole feature exists for: a 15 minute credential against a 20 minute run.
func TestTheGateSaysWhetherTheCredentialWouldHaveSurvivedTheRunUnrenewed(t *testing.T) {
	o := theOnlyOption(t, gateFor(aProvenCredential(time.Minute)))
	if !o.SurvivesKnown {
		t.Fatalf("survival was unknown for a credential with a measured expiry: %s", o.SurvivesWhy)
	}
	if o.SurvivesRun {
		t.Fatalf("a credential with 9 minutes left was said to survive a 20 minute run: %s", o.SurvivesWhy)
	}
}

// ---------------------------------------------------------------------------------------------
// THE SETTINGS DOCUMENT: persisted, strictly decoded, and refused when the gate refuses
// ---------------------------------------------------------------------------------------------

func TestRenewalIsOffByDefaultAndTheDefaultsStillValidateClean(t *testing.T) {
	d := TriageSettingsDefaults()
	if d.SessionRenewal.Enabled {
		t.Fatal("automatic session renewal is on by default, which turns a promise about a session nobody has renewed into the default state of every target")
	}
	if v := ValidateTriageSettings(d); !v.OK {
		t.Fatalf("the defaults no longer validate: %v", triageProblemCodes(v.Errors))
	}
}

// An unevaluated gate is the fail-closed case: a caller that could not evaluate the gate cannot
// have shown a refresh was ever performed.
func TestEnablingRenewalAgainstAnUnevaluatedGateIsRefused(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}
	v := ValidateTriageSettings(s) // no gate at all
	if v.OK {
		t.Fatal("renewal was accepted with no refresh gate evaluated. Not knowing is not clean: an unevaluated gate has proven nothing.")
	}
	hasProblem(t, v.Errors, "renewal_gate_not_evaluated")
}

func TestEnablingRenewalOnACredentialTheGateRefusesIsRefused(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer",
		Profile: aProfiledCredential(RefreshCapability{Status: RefreshAvailable, Mechanism: RefreshMechanismOAuthRefresh}),
	}
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}

	v := ValidateTriageSettingsWithRenewal(s, gateFor(c))
	if v.OK {
		t.Fatal("the settings document stored renewal on for a session the framework has never refreshed")
	}
	p := hasProblem(t, v.Errors, "renewal_"+TriageRenewalNeverProven)
	if !strings.Contains(p.Message, "the proof button on this screen") {
		t.Errorf("the refusal does not say what would lift it: %s", p.Message)
	}
	if p.Field != "session_renewal.enabled" {
		t.Errorf("the problem is addressed at %q, so the form cannot put it next to the switch", p.Field)
	}
}

func TestEnablingRenewalOnAProvenCredentialIsAccepted(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(aProvenCredential(time.Minute)))
	if !v.OK {
		t.Fatalf("a proven refresh was still refused: %v", v.Errors)
	}
}

func TestRenewalWithNoCredentialNamedIsRefusedRatherThanGuessed(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(aProvenCredential(time.Minute)))
	if v.OK {
		t.Fatal("renewal with no credential named was accepted, so the runner would have to guess which of a target's credentials to renew")
	}
	hasProblem(t, v.Errors, "renewal_no_credential_named")
}

func TestRenewalNamingADeletedCredentialIsRefused(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-gone"}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(aProvenCredential(time.Minute)))
	if v.OK {
		t.Fatal("renewal naming a credential the target no longer has was accepted")
	}
	hasProblem(t, v.Errors, "renewal_credential_unknown")
}

func TestAnIntervalThatFiresAfterTheCredentialIsDeadIsRefused(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1", IntervalSeconds: 900}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(aProvenCredential(time.Minute)))
	if v.OK {
		t.Fatal("an interval equal to the measured lifetime was accepted, so the first renewal fires after the credential has already expired")
	}
	p := hasProblem(t, v.Errors, "renewal_interval_exceeds_lifetime")
	if !strings.Contains(p.Message, "450") {
		t.Errorf("the refusal does not offer the derived interval: %s", p.Message)
	}
}

func TestAnIntervalWithNothingToDeriveItFromIsRefusedRatherThanDefaulted(t *testing.T) {
	c := aProvenCredential(time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL, p.TTLFloorKnown = false, 0, false
	p.ExpiresAt, p.ExpiryKnown = renewalNow.Add(time.Hour), true // proof still fresh via the run window
	c.Profile = p

	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1", IntervalSeconds: 0}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(c))
	if v.OK {
		t.Fatal("renewal was enabled with no interval and nothing to derive one from, so the schedule is whatever the runner decides and the operator cannot see it")
	}
	pr := hasProblem(t, v.Errors, "renewal_interval_not_derivable")
	if !strings.Contains(pr.Message, "your figure") {
		t.Errorf("the refusal does not say that a typed interval would be labelled as the operator's: %s", pr.Message)
	}
}

func TestANegativeIntervalIsRefusedEvenWhileRenewalIsOff(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: false, IntervalSeconds: -1}
	if ValidateTriageSettings(s).OK {
		t.Fatal("a negative renewal interval was stored because the switch happened to be off")
	}
}

// The strict decoder must accept a renewal-only body and must still refuse one that names nothing.
func TestTheRenewalFieldRoundTripsThroughTheStrictDecoder(t *testing.T) {
	body := []byte(`{"settings":{"session_renewal":{"enabled":true,"token_id":"tok-1","interval_seconds":300}}}`)
	got, err := DecodeTriageSettingsBody(body)
	if err != nil {
		t.Fatalf("the wrapped shape was refused: %v", err)
	}
	if !got.SessionRenewal.Enabled || got.SessionRenewal.TokenID != "tok-1" || got.SessionRenewal.IntervalSeconds != 300 {
		t.Fatalf("the renewal settings did not survive the decode: %+v", got.SessionRenewal)
	}
	normalised, _ := NormaliseTriageSettings(got)
	if normalised.SessionRenewal != got.SessionRenewal {
		t.Fatalf("normalisation changed the renewal settings from %+v to %+v", got.SessionRenewal, normalised.SessionRenewal)
	}
	if _, err := DecodeTriageSettingsBody([]byte(`{"sesion_renewal":{"enabled":true}}`)); err == nil {
		t.Fatal("a body whose only key is a typo of session_renewal was accepted, which writes the defaults over the stored document and reports success")
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT THE RUNNER IS ALLOWED TO DO WITH A STORED SETTING
// ---------------------------------------------------------------------------------------------

// The stored document is not permission. This is the test that makes "the control must go back to
// unavailable rather than staying on" true at run time and not only on the screen.
func TestTheRunnerHelperIsFailClosedWhenTheProofGoesStale(t *testing.T) {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}

	on, interval, why := TriageRenewalEffective(s, gateFor(aProvenCredential(time.Minute)), renewalNow)
	if !on || interval != 450*time.Second {
		t.Fatalf("a proven, fresh credential did not renew: on=%v interval=%v why=%s", on, interval, why)
	}

	// Same stored document, same token, a proof that has since aged out.
	on, _, why = TriageRenewalEffective(s, gateFor(aProvenCredential(20*time.Minute)), renewalNow)
	if on {
		t.Fatal("the runner kept renewing on a document saved when the proof was current, after the proof aged out. A setting that was true once and stays true forever is exactly the stale proof this gate refuses.")
	}
	if !strings.Contains(why, "no longer permitted") {
		t.Errorf("the runner cannot say why it stopped renewing: %s", why)
	}
}

func TestTheRunnerHelperSaysWhyOnEveryPath(t *testing.T) {
	proven := gateFor(aProvenCredential(time.Minute))
	cases := []struct {
		name string
		s    TriageInvestigateSettings
		gate TriageRenewalGate
		want string
	}{
		{"off", TriageSettingsDefaults(), proven, "switched off"},
		{"no gate", settingsRenewing("tok-1", 0), TriageRenewalGate{}, "not evaluated"},
		{"no token", settingsRenewing("", 0), proven, "names no credential"},
		{"gone", settingsRenewing("tok-gone", 0), proven, "no longer has"},
		{"operator interval", settingsRenewing("tok-1", 120), proven, "the interval you set"},
	}
	for _, tc := range cases {
		_, _, why := TriageRenewalEffective(tc.s, tc.gate, renewalNow)
		if !strings.Contains(why, tc.want) {
			t.Errorf("%s: why = %q, want it to contain %q", tc.name, why, tc.want)
		}
	}
}

func settingsRenewing(tokenID string, interval int) TriageInvestigateSettings {
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: tokenID, IntervalSeconds: interval}
	return s
}

// ---------------------------------------------------------------------------------------------
// NEVER LOG A CREDENTIAL
// ---------------------------------------------------------------------------------------------

// Everything the gate serves crosses the wire to a browser and is printed into reasons. Not one
// byte of a credential may be in any of it.
func TestNothingTheRenewalGateProducesCarriesACredentialValue(t *testing.T) {
	secret := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{
		"sub": "user-9", "exp": renewalNow.Add(9 * time.Minute).Unix(), "iat": renewalNow.Add(-6 * time.Minute).Unix(),
	})
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer", IsActive: true,
		Profile: ProfileCredential(NewCredential(secret),
			CredentialCarrier{Kind: "header", Name: "Authorization", Prefix: "Bearer "}, renewalNow),
		ProvenAt:              renewalNow.Add(-time.Minute),
		ProofDetail:           "a refresh was performed and a different credential came back: 11112222 became 33334444",
		ProofAfterFingerprint: "33334444",
		LastRefreshAt:         renewalNow.Add(-time.Minute),
		LastRefreshStatus:     "success",
	}
	c.Profile.Refresh = RefreshCapability{Status: RefreshProven, ProvenAt: c.ProvenAt}

	g := gateFor(c)
	blob, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rendered := string(blob) + fmt.Sprintf(" %v %+v", g, g)
	for _, segment := range strings.Split(secret, ".") {
		if len(segment) < 8 {
			continue
		}
		if strings.Contains(rendered, segment) {
			t.Fatalf("a segment of the credential (%d bytes) reached the gate's serialised form or its %%v rendering", len(segment))
		}
	}
	if strings.Contains(rendered, secret) {
		t.Fatal("the whole credential reached the gate output")
	}
}

func triageAnyContains(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// Against a real database
// ---------------------------------------------------------------------------------------------
//
// LoadTriageRenewalCredentials is the half that cannot be tested purely: the proof lives in
// session_token_events and the "broken since" test is a comparison between two rows of it. With
// no TRIAGE_TEST_DATABASE_URL these are recorded as NOT MEASURED and the package fails at the end
// of the run, because a skip is not a pass.

func renewalTestToken(t *testing.T, ctx context.Context, target, value string, expires *time.Time) string {
	t.Helper()
	var id string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens
		  (scope_target_id, name, token_type, header_name, value_prefix, token_value, expires_at, is_active)
		VALUES ($1,'app bearer','header','Authorization','Bearer ',$2,$3,TRUE) RETURNING id::text`,
		target, value, expires).Scan(&id); err != nil {
		t.Fatalf("insert session token: %v", err)
	}
	return id
}

func renewalTestEvent(t *testing.T, ctx context.Context, tokenID, status, detail string, at time.Time, evidence map[string]any) {
	t.Helper()
	blob, _ := json.Marshal(evidence)
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence, created_at)
		VALUES ($1,'refresh',$2,$3,$4,$5)`, tokenID, status, detail, string(blob), at); err != nil {
		t.Fatalf("insert refresh event: %v", err)
	}
}

// The whole chain: a proof in the events table earns the control, and a later failure takes it
// away. Neither fact is in the refresh_status column, which is why the loader reads the events.
func TestAProofAndTheFailureAfterItAreBothReadFromTheEventsTable(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	exp := time.Now().UTC().Add(9 * time.Minute)
	value := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{
		"sub": "user-9", "exp": exp.Unix(), "iat": exp.Add(-15 * time.Minute).Unix(),
	})
	tokenID := renewalTestToken(t, ctx, target, value, &exp)

	fingerprint := NewCredential(value).Fingerprint()
	renewalTestEvent(t, ctx, tokenID, "success", "a refresh was performed and a different credential came back",
		time.Now().UTC().Add(-2*time.Minute), map[string]any{"after_fingerprint": fingerprint})

	creds, err := LoadTriageRenewalCredentials(ctx, target)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("read %d credentials, want 1", len(creds))
	}
	g := EvaluateTriageRenewalGate(creds, renewalPacing(), time.Now().UTC())
	if !g.Offerable {
		t.Fatalf("a proof in the events table did not arm the control: %s", g.Reason)
	}
	if o := g.Options[0]; o.ProofAgeSeconds < 100 || o.ProofAgeSeconds > 200 {
		t.Errorf("the proof age is %ds, want about 120", o.ProofAgeSeconds)
	}

	// Now a failure AFTER it. The refresh_status column still says nothing about this.
	renewalTestEvent(t, ctx, tokenID, "replay_failed", "the linked auth flow returned 401", time.Now().UTC(), nil)
	creds, err = LoadTriageRenewalCredentials(ctx, target)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	g = EvaluateTriageRenewalGate(creds, renewalPacing(), time.Now().UTC())
	if g.Offerable {
		t.Fatal("the control stayed on after a refresh failed following the proof")
	}
	if g.Options[0].Code != TriageRenewalProofBroken {
		t.Fatalf("code = %q, want %q: %s", g.Options[0].Code, TriageRenewalProofBroken, g.Options[0].Reason)
	}
}

// The settings screen must not take a measurement and a write. Reading the gate leaves the row
// exactly as it found it.
func TestReadingTheRenewalGateWritesNothingToTheTokenRow(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	exp := time.Now().UTC().Add(9 * time.Minute)
	value := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{
		"sub": "user-9", "exp": exp.Unix(), "iat": exp.Add(-15 * time.Minute).Unix(),
	})
	tokenID := renewalTestToken(t, ctx, target, value, &exp)

	var beforeUpdated time.Time
	if err := dbPool.QueryRow(ctx, `SELECT updated_at FROM session_tokens WHERE id = $1`, tokenID).Scan(&beforeUpdated); err != nil {
		t.Fatalf("read updated_at: %v", err)
	}
	if _, err := LoadTriageRenewalCredentials(ctx, target); err != nil {
		t.Fatalf("load: %v", err)
	}
	var afterUpdated time.Time
	var profiledAt *time.Time
	if err := dbPool.QueryRow(ctx,
		`SELECT updated_at, profiled_at FROM session_tokens WHERE id = $1`, tokenID).Scan(&afterUpdated, &profiledAt); err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !afterUpdated.Equal(beforeUpdated) {
		t.Fatalf("reading the gate wrote to the token row: updated_at moved from %s to %s", beforeUpdated, afterUpdated)
	}
	if profiledAt != nil {
		t.Fatalf("reading the gate stored a profile (profiled_at = %s); a settings screen is not the place for a measurement and a write", profiledAt)
	}
}

// The credential's own lifetime has to come back even with no stored profile, or the interval
// would be unavailable on every target nobody had opened the Session Manager on.
func TestTheLifetimeIsRecomputedWhenNoProfileWasEverStored(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	exp := time.Now().UTC().Add(9 * time.Minute)
	value := makeJWT(t, map[string]interface{}{"alg": "HS256"}, map[string]interface{}{
		"sub": "user-9", "exp": exp.Unix(), "iat": exp.Add(-15 * time.Minute).Unix(),
	})
	renewalTestToken(t, ctx, target, value, &exp)

	creds, err := LoadTriageRenewalCredentials(ctx, target)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("read %d credentials, want 1", len(creds))
	}
	p := creds[0].Profile
	if !p.TTLKnown || p.TTL != 15*time.Minute {
		t.Fatalf("TTL = %v (known=%v), want the credential's own 15m", p.TTL, p.TTLKnown)
	}
	o := triageRenewalOptionFor(creds[0], 20*time.Minute, time.Now().UTC())
	if !o.IntervalKnown || o.IntervalSeconds != 450 {
		t.Fatalf("interval = %ds (known=%v), want 450", o.IntervalSeconds, o.IntervalKnown)
	}
}

// The save endpoint refuses an interval that is not shorter than the lifetime. A document that
// reached the column another way must be refused at the moment it is USED as well, because the
// two are different moments and only one of them is the run.
func TestTheRunnerHelperAlsoRefusesAnIntervalLongerThanTheLifetime(t *testing.T) {
	s := settingsRenewing("tok-1", 900)
	on, _, why := TriageRenewalEffective(s, gateFor(aProvenCredential(time.Minute)), renewalNow)
	if on {
		t.Fatal("the runner accepted an interval equal to the measured lifetime, so its first renewal fires after the credential has already expired while the run reports that it renews")
	}
	if !strings.Contains(why, "already expired") {
		t.Errorf("the refusal does not say what is wrong with the interval: %s", why)
	}
}

// ---------------------------------------------------------------------------------------------
// A FLOOR MAY ONLY DRIVE A SCHEDULE WHEN IT BELONGS TO ONE CREDENTIAL
// ---------------------------------------------------------------------------------------------

// aFloorOnlyCredential is a proven credential whose lifetime was NEVER measured and which carries
// only a lower bound, with the provenance the caller names. Every floor test below differs from
// the next only in that provenance, which is the whole point: the number is the same and what may
// be built on it is not.
func aFloorOnlyCredential(floor time.Duration, prov Provenance, evidence string) TriageRenewalCredential {
	c := aProvenCredential(time.Minute)
	p := c.Profile
	p.TTLKnown, p.TTL, p.TTLProvenance, p.TTLEvidence = false, 0, ProvUnknown, ""
	p.ExpiryKnown = false
	p.TTLFloorKnown, p.TTLFloor = true, floor
	p.TTLFloorProvenance = prov
	p.TTLFloorEvidence = evidence
	p.ObservedEvidence = "samples=51 requests=3701"
	c.Profile = p
	return c
}

// A PROBED FLOOR IS NOW ONE CREDENTIAL'S OWN SPAN, AND THESE TWO TESTS RECORD THAT IT CHANGED.
//
// THE FACT THEY USED TO ASSERT WAS TRUE WHEN THEY WERE WRITTEN. applyProbeHistory took the span
// from the EARLIEST successful validation to the LATEST, session_token_events carried no
// fingerprint, and POST /session-tokens/{id}/refresh replaces token_value IN PLACE, so two
// validations either side of one refresh were two different credentials. Round 12 measured a value
// stored one hour before carrying a probed floor of 5h59m.
//
// WHAT CHANGED, READ IN applyProbeHistory RATHER THAN ASSUMED HERE. Every validation event is now
// put through attributeProbe against the credential's fingerprint and the anchor
// credentialHeldSince returns. An event that names another credential is excluded, an event
// nothing can tie to this value is dropped and counted in a warning, and where NOTHING can be
// tied there is no floor at all. The 5h58m span that started this became 29m, and the span here
// is one credential's own.
//
// SO THE REFUSAL BECAME THE DEFECT. SessionTokenProfile.FloorBelongsToOneCredential said true and
// this file said false about the same profile, and the operator lost a derivable schedule on every
// probed floor on every target. These now assert the reconciled answer, and the direction that
// still matters is guarded by the test below: a floor nothing can attribute drives nothing.
func TestAProbedFloorDrivesTheIntervalBecauseEveryEventBehindItWasAttributed(t *testing.T) {
	c := aFloorOnlyCredential(5*time.Hour+59*time.Minute, ProvProbed,
		"the framework used this credential successfully at 2026-09-20T06:31:00Z and again at 2026-09-20T12:30:00Z, so it was alive across 5h59m of its own life")

	interval, known, basis := TriageRenewalIntervalFor(c.Profile)
	if !known || interval != 2*time.Hour+59*time.Minute+30*time.Second {
		t.Fatalf("interval = %s (known=%v), want half of the 5h59m probed floor: %s", interval, known, basis)
	}
	if !strings.Contains(basis, "PROBED LOWER BOUND") {
		t.Errorf("the basis does not name the kind of floor it halved: %s", basis)
	}
	if !strings.Contains(basis, "not a TTL") {
		t.Errorf("the basis lets a floor read as a measured lifetime: %s", basis)
	}

	o := theOnlyOption(t, gateFor(c))
	if !o.IntervalKnown || o.IntervalSeconds != 10770 {
		t.Fatalf("the gate offered %ds (known=%v), want 10770s", o.IntervalSeconds, o.IntervalKnown)
	}
}

// The proof window is the other consumer of the same floor, and it takes the same answer. Two
// consumers reading one predicate is the property being protected.
func TestAProbedFloorHoldsTheProofWindowToo(t *testing.T) {
	c := aFloorOnlyCredential(5*time.Hour+59*time.Minute, ProvProbed, "alive across 5h59m of its own life")

	o := theOnlyOption(t, gateFor(c))
	if o.ProofWindowSeconds != 21540 {
		t.Fatalf("the proof window is %ds, want the 21540s probed floor: %s", o.ProofWindowSeconds, o.ProofWindowBasis)
	}
	if !strings.Contains(strings.ToLower(o.ProofWindowBasis), "probed lower bound") {
		t.Errorf("the window basis does not say which clock it used: %s", o.ProofWindowBasis)
	}
}

// A floor with NO recorded provenance is refused, and this is the test that keeps the reconciliation
// above from becoming "any floor will do". floorProvenance() returns unknown for an empty column
// rather than defaulting it to observed, so a row written before the provenance column existed
// carries a number nobody can attribute to either path, and nothing is derived from it.
func TestAFloorWithNoRecordedProvenanceIsNotUsedEither(t *testing.T) {
	c := aFloorOnlyCredential(14*time.Minute, "", "")
	if _, known, basis := TriageRenewalIntervalFor(c.Profile); known {
		t.Fatalf("an interval was derived from a floor with no recorded provenance: %s", basis)
	}
}

// The observed floor is still allowed, because the corpus reading IS one credential's: the
// summariser takes the longest span of a SINGLE VALUE and records the fingerprint that produced
// it. This is the test that stops the refusal above from quietly deleting the feature.
func TestAnObservedFloorStillDrivesTheIntervalBecauseItIsOneValuesOwnSpan(t *testing.T) {
	c := aFloorOnlyCredential(14*time.Minute, ProvObserved, "one value of the sid cookie across 3701 captured requests")
	o := theOnlyOption(t, gateFor(c))
	if !o.IntervalKnown || o.IntervalSeconds != 420 {
		t.Fatalf("interval = %ds (known=%v), want 420s, half of the 14m observed floor", o.IntervalSeconds, o.IntervalKnown)
	}
}

// ---------------------------------------------------------------------------------------------
// NOT LOOKED YET IS NOT THE SAME AS LOOKED AND FOUND NOTHING
// ---------------------------------------------------------------------------------------------

// A credential nobody has characterised used to be told what was looked for and not found, which
// is a search that never ran.
//
// THE SHAPE IS THE ONE LoadTriageRenewalCredentials PRODUCES. Where no stored profile describes
// the value held, it falls back to ProfileCredential, whose own comment says it cannot see a
// refresh mechanism: the returned profile carries the ZERO RefreshCapability, whose Status is the
// empty string. RefreshNotObserved is a different fact, written only by DetectRefreshCapability,
// which has read the flows, the corpus and the token.
func TestACredentialNothingHasProfiledIsNotToldThatASearchFoundNothing(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer",
		Profile: aProfiledCredential(RefreshCapability{}),
	}
	o := theOnlyOption(t, gateFor(c))
	if o.Code != TriageRenewalNotProfiled {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalNotProfiled)
	}
	if strings.Contains(o.Reason, "no auth flow with executable steps") {
		t.Errorf("a credential nobody has looked at is told a search found nothing: %s", o.Reason)
	}
	if !strings.Contains(o.Reason, "Session Manager") {
		t.Errorf("the refusal does not say what would characterise it: %s", o.Reason)
	}
	g := gateFor(c)
	if strings.Contains(g.Reason, "no mint endpoint in the captured corpus") {
		t.Errorf("the target-level sentence claims a corpus search nobody ran: %s", g.Reason)
	}
}

// And the credential that WAS searched still says so, so the fix above cannot be a rename that
// loses the real finding.
func TestACredentialThatWasSearchedStillSaysNothingWasFound(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "opaque sid",
		Profile: aProfiledCredential(RefreshCapability{Status: RefreshNotObserved}),
	}
	o := theOnlyOption(t, gateFor(c))
	if o.Code != TriageRenewalNoMechanism {
		t.Fatalf("code = %q, want %q", o.Code, TriageRenewalNoMechanism)
	}
}

// ---------------------------------------------------------------------------------------------
// THE ADVICE NAMES A CONTROL THAT ACTUALLY RECORDS A PROOF
// ---------------------------------------------------------------------------------------------

// MEASURED: POST /session-tokens/{id}/refresh replays the flow, stores whatever comes back and
// records kind=refresh status=refreshed. The proof is read from kind=refresh status=SUCCESS, which
// only RecordRefreshProof writes, so pressing Refresh in the Session Manager can never lift any of
// these refusals. Round 12 drove it end to end: a different credential came back, was stored, the
// timeline gained refresh/refreshed, and ProvenAt stayed zero.
func TestNoRefusalTellsTheOperatorToPressAButtonThatRecordsNoProof(t *testing.T) {
	stale := aProvenCredential(30 * time.Minute)
	broken := aProvenCredential(10 * time.Minute)
	broken.LastRefreshAt = renewalNow.Add(-time.Minute)
	broken.LastRefreshStatus = "replay_failed"
	never := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer",
		Profile: aProfiledCredential(RefreshCapability{
			Status: RefreshAvailable, Mechanism: RefreshMechanismAuthFlow,
			MintHost: "login.example.test", MintInScope: true,
		}),
	}

	for _, tc := range []struct {
		name string
		cred TriageRenewalCredential
	}{
		{"never proven", never},
		{"proof stale", stale},
		{"proof broken", broken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gateFor(tc.cred)
			o := theOnlyOption(t, g)
			for _, sentence := range []string{o.Reason, g.Reason} {
				if strings.Contains(strings.ToLower(sentence), "refresh once from the session manager") {
					t.Errorf("the operator is sent to a button that records no proof: %s", sentence)
				}
			}
			if !strings.Contains(o.Reason, "proof") {
				t.Errorf("the refusal does not name the proof it wants: %s", o.Reason)
			}
			if !strings.Contains(strings.ToLower(g.Reason), "on this screen") {
				t.Errorf("the target-level advice does not name the control that records the proof: %s", g.Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE SAVE AND THE RUN AGREE ABOUT THE SHORTEST SCHEDULE
// ---------------------------------------------------------------------------------------------

// The driver HOLDS a login flow to triageRenewalMinInterval rather than refusing one below it, so
// the save does the same and says which schedule will actually run. A document the form refused and
// the runner would have executed was a feature the operator simply could not switch on.
func TestAnIntervalBelowTheRenewalFloorIsHeldToItAtTheSaveAsWellAsAtTheRun(t *testing.T) {
	s := settingsRenewing("tok-1", 30)
	v := ValidateTriageSettingsWithRenewal(s, gateFor(aProvenCredential(time.Minute)))
	if !v.OK {
		t.Fatalf("a 30s renewal schedule was refused at the save, and the runner clamps it to the floor and renews, so the two surfaces disagree: %v", triageProblemCodes(v.Errors))
	}
	p := hasProblem(t, v.Warnings, "renewal_interval_clamped_to_floor")
	if !strings.Contains(p.Message, "authentication burst") {
		t.Errorf("the warning does not say why the floor exists: %s", p.Message)
	}
	for _, want := range []string{"30s", "1m", "CLAMPED"} {
		if !strings.Contains(p.Message, want) {
			t.Errorf("the warning does not say %q, so the operator cannot tell the schedule is not the one they set: %s", want, p.Message)
		}
	}

	// And the floor is not a ceiling on the feature: the shipped 15 minute credential derives 450s
	// and saves clean, with no clamp warning at all.
	clean := ValidateTriageSettingsWithRenewal(settingsRenewing("tok-1", 0), gateFor(aProvenCredential(time.Minute)))
	if !clean.OK {
		t.Fatalf("the derived schedule for a fifteen minute credential was refused: %+v", clean.Errors)
	}
	for _, w := range clean.Warnings {
		if w.Code == "renewal_interval_clamped_to_floor" {
			t.Errorf("a schedule well above the floor was reported as clamped: %s", w.Message)
		}
	}
}

// A credential whose measured lifetime is so short that HALF of it is below the floor IS still
// renewable: the derived schedule is held to the floor and the operator is told at the form what
// that costs, rather than being refused the feature on the one application that needs it.
func TestACredentialWhoseDerivedIntervalIsBelowTheFloorIsClampedAtTheSave(t *testing.T) {
	c := aProvenCredential(time.Second)
	p := c.Profile
	p.TTL, p.TTLKnown = 90*time.Second, true
	p.TTLEvidence = "exp minus iat"
	p.ExpiresAt = renewalNow.Add(80 * time.Second)
	c.Profile = p

	g := gateFor(c)
	o := theOnlyOption(t, g)
	if !o.IntervalKnown || o.IntervalSeconds != 45 {
		t.Fatalf("interval = %ds (known=%v), want 45s, half of the measured 90s", o.IntervalSeconds, o.IntervalKnown)
	}
	v := ValidateTriageSettingsWithRenewal(settingsRenewing("tok-1", 0), g)
	if !v.OK {
		t.Fatalf("a derived 45s schedule was refused at the save, and the runner clamps it to the floor and renews: %v", triageProblemCodes(v.Errors))
	}
	prob := hasProblem(t, v.Warnings, "renewal_interval_clamped_to_floor")
	if !strings.Contains(prob.Message, "45s") || !strings.Contains(prob.Message, "1m") {
		t.Errorf("the warning does not carry both figures: %s", prob.Message)
	}
	// The measured lifetime is 90s and the floor is 1m, so NO part of a cycle is spent holding an
	// expired credential and the warning must not invent one.
	if strings.Contains(prob.Message, "DOES NOT LIVE THAT LONG") {
		t.Errorf("a gap was claimed for a credential that outlives the clamped schedule: %s", prob.Message)
	}
}

// ---------------------------------------------------------------------------------------------
// ONE FLOOR, ONE ANSWER, AND NO SENTENCE ABOUT IT THAT NOBODY READ
// ---------------------------------------------------------------------------------------------

// TWO PREDICATES ON THE SAME QUESTION DISAGREED, AND BOTH REACHED THE OPERATOR.
//
// SessionTokenProfile.FloorBelongsToOneCredential (the producer, which is the only thing that
// knows how the floor was got) answered TRUE for a probed floor. triageFloorBelongsToOneCredential
// (this file, the consumer) answered FALSE for the same profile. One of them is wrong on every
// probed floor on every target, and nothing in the tree said which.
//
// This asserts AGREEMENT rather than either answer, so the consumer cannot drift from the producer
// again when applyProbeHistory changes.
func TestTheFloorPredicateAgreesWithTheProfileThatProducedTheFloor(t *testing.T) {
	for _, prov := range []Provenance{ProvObserved, ProvProbed, ProvUnknown, ProvParsed, ProvDeclared, ""} {
		c := aFloorOnlyCredential(14*time.Minute, prov, "a floor of 14m")
		wantOK, wantWhy := c.Profile.FloorBelongsToOneCredential()
		gotOK, gotWhy := triageFloorBelongsToOneCredential(c.Profile)
		if gotOK != wantOK {
			t.Errorf("provenance %q: the profile says belongs=%v (%s) and this file says belongs=%v (%s). "+
				"The same floor cannot be one credential's to the thing that measured it and not to the thing that reads it",
				prov, wantOK, wantWhy, gotOK, gotWhy)
		}
	}
}

// ROUND 13 CHANGED floorProvenance() TO RETURN unknown FOR AN EMPTY COLUMN. The refusal this file
// emits still told the operator the opposite, and it reaches them through IntervalBasis and
// ProofWindowBasis on every credential whose floor predates the provenance column.
func TestNoRefusalClaimsAnEmptyProvenanceIsDefaultedToObserved(t *testing.T) {
	c := aFloorOnlyCredential(14*time.Minute, "", "")

	// The fact, read on the branch that decides it: an empty column reads as unknown.
	if got := c.Profile.floorProvenance(); got != ProvUnknown {
		t.Fatalf("floorProvenance() = %q for an empty column, want %q; re-point this test", got, ProvUnknown)
	}

	o := theOnlyOption(t, gateFor(c))
	for _, s := range []string{o.IntervalBasis, o.ProofWindowBasis, o.Reason} {
		if strings.Contains(strings.ToLower(s), "defaults") && strings.Contains(strings.ToLower(s), "observed") {
			t.Errorf("an operator-facing sentence says the display path defaults an empty provenance "+
				"to observed. floorProvenance() returns %q: %s", ProvUnknown, s)
		}
	}
}

// AND THE SAME SENTENCE, SERVED THROUGH THE VALIDATOR. The floor with no provenance is refused, so
// the refusal text is what the save shows.
func TestTheValidatorDoesNotServeTheDefaultedToObservedSentence(t *testing.T) {
	c := aFloorOnlyCredential(14*time.Minute, "", "")
	s := TriageSettingsDefaults()
	s.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}
	v := ValidateTriageSettingsWithRenewal(s, gateFor(c))
	for _, p := range append(append([]TriageFieldProblem{}, v.Errors...), v.Warnings...) {
		if strings.Contains(strings.ToLower(p.Message), "defaults") && strings.Contains(strings.ToLower(p.Message), "observed") {
			t.Errorf("the save refusal still carries the defaulted-to-observed claim: %s", p.Message)
		}
	}
}

// A PROBED FLOOR IS NOT A CORPUS READING, AND NO SENTENCE MAY CALL IT ONE.
//
// This is the trap in letting the consumer agree with the producer: the interval basis and the
// proof window basis both said "OBSERVED LOWER BOUND" unconditionally, so admitting probed floors
// would have relabelled every one of them as captured traffic. floorPhrase() in the profile is the
// thing that already knows the two apart.
func TestAProbedFloorIsNeverRenderedAsAnObservedOne(t *testing.T) {
	c := aFloorOnlyCredential(105*time.Minute, ProvProbed,
		"the framework used this credential successfully at 2026-09-20T10:45:00Z and again at 2026-09-20T12:30:00Z, so it was alive across 1h45m of its own life")
	o := theOnlyOption(t, gateFor(c))

	if !o.IntervalKnown || o.IntervalSeconds != 3150 {
		t.Fatalf("interval = %ds (known=%v), want 3150s, half of the 1h45m probed floor: %s",
			o.IntervalSeconds, o.IntervalKnown, o.IntervalBasis)
	}
	if !strings.Contains(o.IntervalBasis, "PROBED LOWER BOUND") {
		t.Errorf("the interval basis does not name the floor it used as a probed one: %s", o.IntervalBasis)
	}
	if strings.Contains(strings.ToLower(o.IntervalBasis), "observed lower bound") ||
		strings.Contains(strings.ToLower(o.IntervalBasis), "the corpus") {
		t.Errorf("the interval basis calls a span of the framework's own requests a corpus reading: %s", o.IntervalBasis)
	}
	if o.ProofWindowSeconds != 6300 {
		t.Fatalf("proof window = %ds, want the 6300s probed floor: %s", o.ProofWindowSeconds, o.ProofWindowBasis)
	}
	if strings.Contains(strings.ToLower(o.ProofWindowBasis), "observed lower bound") {
		t.Errorf("the proof window basis calls a probed floor an observed one: %s", o.ProofWindowBasis)
	}
	if !strings.Contains(strings.ToLower(o.ProofWindowBasis), "probed lower bound") {
		t.Errorf("the proof window basis does not say which kind of floor it used: %s", o.ProofWindowBasis)
	}

	set := TriageSettingsDefaults()
	set.SessionRenewal = TriageSessionRenewal{Enabled: true, TokenID: "tok-1"}
	v := ValidateTriageSettingsWithRenewal(set, gateFor(c))
	for _, p := range v.Warnings {
		if strings.Contains(p.Message, "an observed LOWER BOUND") {
			t.Errorf("the save warning calls a probed floor an observed one: %s", p.Message)
		}
	}
}

// The corpus floor still reads as a corpus floor, so the fix above cannot be a rename that loses
// the distinction it exists to draw.
func TestAnObservedFloorIsStillNamedAsOne(t *testing.T) {
	c := aFloorOnlyCredential(14*time.Minute, ProvObserved, "one value of the sid cookie across 3701 captured requests")
	o := theOnlyOption(t, gateFor(c))
	if !strings.Contains(o.IntervalBasis, "OBSERVED LOWER BOUND") {
		t.Errorf("the observed floor lost its name: %s", o.IntervalBasis)
	}
}

// ---------------------------------------------------------------------------------------------
// refresh_not_checked HAS TO BE REACHABLE THROUGH THE PRODUCTION COMPOSITION
// ---------------------------------------------------------------------------------------------

// ROUND 12 REPORTED THIS FIXED AND IT WAS NOT, BECAUSE THE FIX AND ITS TEST BOTH ASSUMED A SHAPE
// NOBODY READ.
//
// The pure test above hands triageRenewalOptionFor a zero RefreshCapability and gets
// refresh_not_checked, which is correct about the function. The production composition never
// produces that shape: LoadTriageRenewalCredentials falls back to ProfileCredential, and
// profileCredentialBytes sets Refresh to RefreshCapability{Status: RefreshNotObserved}. So on a
// real target every uncharacterised credential took the default branch and was told a search over
// the flows, the corpus and the token had been run and had found nothing.
//
// This is the same claim driven through the real loader against a real database, which is the only
// place the defect was visible.
func TestAnUncharacterisedCredentialReachesTheGateAsNotCheckedNotAsNothingFound(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	// An opaque value, so nothing about it can be parsed and no profile row exists for it.
	renewalTestToken(t, ctx, target, "0f4a7c21d8b34e6f95a0c7de118b2f63", nil)

	creds, err := LoadTriageRenewalCredentials(ctx, target)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("read %d credentials, want 1", len(creds))
	}
	if got := creds[0].Profile.Refresh.Status; got != "" {
		t.Errorf("the loader handed the gate refresh status %q for a credential nothing has characterised. "+
			"That status is the answer of a search over the flows, the corpus and the token, and this loader ran none of them", got)
	}

	g := EvaluateTriageRenewalGate(creds, renewalPacing(), time.Now().UTC())
	o := g.Options[0]
	if o.Code != TriageRenewalNotProfiled {
		t.Fatalf("code = %q, want %q: %s", o.Code, TriageRenewalNotProfiled, o.Reason)
	}
	if strings.Contains(o.Reason, "no auth flow with executable steps") {
		t.Errorf("a credential nobody has looked at is told a search found nothing: %s", o.Reason)
	}
	if strings.Contains(g.Reason, "no mint endpoint in the captured corpus") {
		t.Errorf("the target-level sentence claims a corpus search nobody ran: %s", g.Reason)
	}
}

// AND A CREDENTIAL THAT WAS CHARACTERISED KEEPS ITS ANSWER. The clearing above is on the fallback
// path only, so a stored profile that really did look and find nothing still says so.
func TestAStoredNotObservedSurvivesTheLoaderFallback(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	value := "b71e0c3a9f2d4b508c6e1a7d34f90b22"
	tokenID := renewalTestToken(t, ctx, target, value, nil)

	p := ProfileCredential(NewCredential(value), CredentialCarrier{Kind: "header", Name: "Authorization"}, time.Now().UTC())
	p.TokenID, p.ScopeTargetID = tokenID, target
	p.Refresh = RefreshCapability{Status: RefreshNotObserved, Evidence: []string{"no auth flow, no mint endpoint, no refresh grant"}}
	if err := SaveSessionTokenProfile(ctx, p); err != nil {
		t.Fatalf("store profile: %v", err)
	}

	creds, err := LoadTriageRenewalCredentials(ctx, target)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	g := EvaluateTriageRenewalGate(creds, renewalPacing(), time.Now().UTC())
	if g.Options[0].Code != TriageRenewalNoMechanism {
		t.Fatalf("code = %q, want %q: a real search that found nothing was downgraded to not-checked",
			g.Options[0].Code, TriageRenewalNoMechanism)
	}
}

// AND THE NAMED STATE TAKES THE SAME BRANCH AS THE ZERO ONE. profileCredentialBytes should name
// the before-the-search state rather than leave it empty, and the patch that makes it do so must
// not silently move every uncharacterised credential back into no_mechanism_found.
func TestTheNamedNotCharacterisedStateIsAlsoReadAsNotChecked(t *testing.T) {
	c := TriageRenewalCredential{
		TokenID: "tok-1", Name: "app bearer",
		Profile: aProfiledCredential(RefreshCapability{Status: RefreshNotCharacterised}),
	}
	o := theOnlyOption(t, gateFor(c))
	if o.Code != TriageRenewalNotProfiled {
		t.Fatalf("code = %q, want %q: %s", o.Code, TriageRenewalNotProfiled, o.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// ONE FLOOR, ONE ANSWER, ON BOTH SURFACES
// ---------------------------------------------------------------------------------------------
//
// TWO SHIPPED SURFACES ANSWERED THE SAME QUESTION DIFFERENTLY AND THE LOSER WAS THE OPERATOR WHO
// MOST NEEDS THE FEATURE.
//
// TriageSessionRenewalDriver.clampInterval CLAMPS an interval below triageRenewalMinInterval up to
// the floor and renews. triageValidateSessionRenewal HARD-ERRORED on the same figure, so the
// document could never be saved and the driver's clamp was unreachable through the screen. On an
// application whose credential lives 45 seconds the derived schedule is 22s, so renewal could not
// be switched on AT ALL on precisely the application that cannot finish a run without it.
//
// THE FLOOR EXISTS TO STOP A PATHOLOGICAL SCHEDULE, NOT TO DENY THE FEATURE. A renewal is a whole
// recorded login and faster than once a minute it is an authentication burst against the
// engagement, so the floor stays and the schedule is held to it. What the refusal added on top of
// that was taking renewal away entirely, and the measurement in triageRenewalMinInterval is that
// this costs more than the clamp: clamping leaves 15s of every 60s cycle unauthenticated on a 45s
// credential, and refusing leaves every second after the first 45 unauthenticated for the whole
// run.
//
// The remaining objection to a clamp is a run that reports it renews while running a schedule the
// operator did not choose. That is cured by SAYING SO, with both figures and the size of the
// window, which is what triageRenewalClampWhy and triageRenewalClampGap are, and why BOTH surfaces
// now call the same two functions instead of composing their own sentence.

// TestTheSaveAndTheRunGiveTheSameAnswerAboutAnIntervalBelowTheFloor is defect A, measured on the
// application the decision is about.
func TestTheSaveAndTheRunGiveTheSameAnswerAboutAnIntervalBelowTheFloor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings TriageInvestigateSettings
	}{
		{"the interval is derived from a 45s lifetime", settingsRenewingDerived("tok-1")},
		{"the operator typed 30s", settingsRenewing("tok-1", 30)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gateFor(aShortLivedProvenCredential())

			d := newTriageSessionRenewalDriver("target-1", "", tc.settings)
			d.evaluate = func(context.Context, string, TriagePacing) TriageRenewalGate { return g }
			d.perform = func(context.Context, string, string) SessionRefreshProofResult {
				return renewalDriverProof("tok-1")
			}
			d.now = func() time.Time { return renewalNow }
			d.start(context.Background())
			defer d.Stop()

			v := ValidateTriageSettingsWithRenewal(tc.settings, g)

			if !d.On {
				t.Fatalf("the runner refused to renew, so this test is not measuring the contradiction: %s", d.Decision)
			}
			if d.On != v.OK {
				t.Fatalf("THE TWO SURFACES CONTRADICT EACH OTHER. The runner renews this credential every %s "+
					"(clamped up from %s) and the save refuses the same document with %v, so renewal cannot be "+
					"switched on at all on a 45 second application. One floor, two answers, and the operator who "+
					"most needs the feature is the one who cannot have it.",
					d.Interval, d.DerivedInterval, triageProblemCodes(v.Errors))
			}

			// AND THE SAVE SAYS WHAT THE RUN WILL DO. A clamp nobody is told about is the defect the
			// refusal was avoiding; the warning has to carry the floor, the figure that was asked
			// for, and the unauthenticated window of every cycle.
			p := hasProblem(t, v.Warnings, "renewal_interval_clamped_to_floor")
			for _, want := range []string{"CLAMPED", "1m", "45s", "15s"} {
				if !strings.Contains(p.Message, want) {
					t.Errorf("the save does not tell the operator %q, so the schedule that will actually run is invisible at the point they choose it: %s",
						want, p.Message)
				}
			}
			// The two surfaces say it in the SAME WORDS, because they call the same function.
			if !strings.Contains(d.Decision, triageRenewalClampWhy(d.DerivedInterval, triageRenewalMinInterval)) {
				t.Errorf("the run's decision does not carry the shared clamp sentence: %s", d.Decision)
			}
			if !strings.Contains(p.Message, triageRenewalClampWhy(d.DerivedInterval, triageRenewalMinInterval)) {
				t.Errorf("the save's warning does not carry the shared clamp sentence: %s", p.Message)
			}
		})
	}
}

// AND THE CLAMP IS NOT A LICENCE. Everything the floor was never about is still refused: an
// interval no shorter than the credential's own lifetime schedules its first renewal for after it
// is already dead, and that is an error on both surfaces.
func TestTheClampDoesNotWeakenTheRefusalsThatAreNotAboutTheFloor(t *testing.T) {
	g := gateFor(aProvenCredential(time.Minute))
	o := theOnlyOption(t, g)
	if !o.TTLKnown {
		t.Fatal("this test needs a measured lifetime")
	}
	v := ValidateTriageSettingsWithRenewal(settingsRenewing("tok-1", int(o.TTLSeconds)+30), g)
	if v.OK {
		t.Fatal("an interval longer than the credential's measured lifetime was accepted")
	}
	hasProblem(t, v.Errors, "renewal_interval_exceeds_lifetime")

	// A negative interval is still an error: it is not a schedule the floor can hold, it is not a
	// schedule at all.
	if v := ValidateTriageSettingsWithRenewal(settingsRenewing("tok-1", -5), g); v.OK {
		t.Fatal("a negative renewal interval was accepted")
	}
}

// THE CLAMP MUST NOT SWALLOW THE ONE REFUSAL THE RUN STILL MAKES.
//
// TriageRenewalEffective refuses an operator-set interval that is not shorter than the measured
// lifetime, and it tests the figure that was SET, not the clamped one. On a 45 second credential a
// typed 50s interval is BOTH below the 60s floor and no shorter than the lifetime, so had the floor
// been tested first the save would have answered "clamped, fine" about a document the run refuses
// outright. That is the same contradiction this round closed, pointing the other way.
func TestTheClampIsNotTestedBeforeTheRefusalTheRunStillMakes(t *testing.T) {
	g := gateFor(aShortLivedProvenCredential())
	o := theOnlyOption(t, g)
	if !o.TTLKnown || o.TTLSeconds != 45 {
		t.Fatalf("this test needs the 45s application: ttl=%ds known=%v", o.TTLSeconds, o.TTLKnown)
	}
	const typed = 50 // above the 45s lifetime and below the 60s floor, both at once
	if time.Duration(typed)*time.Second >= triageRenewalMinInterval {
		t.Fatalf("this test's arithmetic assumes %ds is below the %s floor", typed, triageRenewalMinInterval)
	}

	settings := settingsRenewing("tok-1", typed)
	on, _, why := TriageRenewalEffective(settings, g, renewalNow)
	if on {
		t.Fatalf("the run accepted an interval no shorter than the measured lifetime, so this test is not measuring the case: %s", why)
	}

	v := ValidateTriageSettingsWithRenewal(settings, g)
	if v.OK {
		t.Fatalf("THE SAVE ACCEPTED A DOCUMENT THE RUN REFUSES: the run says %q and the save recorded only %v. "+
			"A clamp that is tested before this refusal answers 'that is fine' about a schedule that will never run.",
			why, triageProblemCodes(v.Warnings))
	}
	hasProblem(t, v.Errors, "renewal_interval_exceeds_lifetime")
}
