package utils

import (
	"strings"
	"testing"

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
