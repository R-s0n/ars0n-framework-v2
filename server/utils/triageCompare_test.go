package utils

import (
	"ars0n-framework-v2-server/utils/triage"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests for the comparator and the noise model.
//
// THE FIXTURE CORPUS IS THE DELIVERABLE AS MUCH AS THE CODE. Every fixture below is a synthetic
// endpoint whose correct answer is stated in the foundations document or, for the four marked
// LOCAL, argued here. They are not smoke tests: each one is a way this layer has failed or would
// fail, and a comparator that gets the right answer on all of them is a comparator that can be
// pointed at an application nobody has seen.
//
//	T1  a wholly volatile endpoint               -> too_volatile, and NOT clean
//	T2  only a trace id changes                  -> one marking, judgeable, a/b/c answers
//	T3  a real SQL error in an identical page    -> different, and masked_only must NOT fire
//	T4  a WAF block identical for every payload  -> uniform_block, cannot_determine, not a finding
//	T5  two-server alternation                   -> one marking, one distinct normalised body
//	T6  the clock-granularity trap               -> clock_unproven, and a digit-only diff is masked
//	T7  JSON noisy but shape-stable              -> judgeable_shape_only, and the shape still judges
//	T8  an integer cast that eats the tail       -> same, every time
//	T9  always-500                               -> the gate PASSES and a 500 is not a signal
//	T10 always-dberror                           -> the signature is disabled, a new one is not
//	T11 an oversized body                        -> degraded, capped at suspicious, never clean
//	T12 an empty body                            -> unusable, not "identical bodies therefore same"
//	T13 a CSRF-required POST                     -> status_flap, not too_volatile and not clean
//	T14 a reordered result set                   -> reordered, which quick_ratio alone loses
//	T15 LOCAL: JSON with reordered keys          -> reordered on bytes, EMPTY on shape
//	T16 LOCAL: a genuinely identical pair        -> same, and the only fixture that is clean
//	T17 LOCAL: a masked region carrying novel bytes -> masked_only, the over-masking safety valve
//	T18 LOCAL: drift under the probes            -> drifted, and every verdict in the window falls

// ---------------------------------------------------------------------------------------------
// Fixture plumbing
// ---------------------------------------------------------------------------------------------

var cmpEpoch = time.Date(2026, 9, 18, 10, 4, 5, 0, time.UTC)

// cmpGaps is a spacing that honours the baseline spacing rule: a span above 2.2 s with one gap
// above 1.1 s, so a one-second clock on the target ticks inside the window.
var cmpGaps = []time.Duration{
	600 * time.Millisecond,
	1200 * time.Millisecond,
	700 * time.Millisecond,
	800 * time.Millisecond,
}

type cmpEndpoint struct {
	status  int
	media   triage.MediaType
	headers [][2]string
	gaps    []time.Duration
}

func (e cmpEndpoint) samples(bodies ...string) []triage.Observation {
	gaps := e.gaps
	if gaps == nil {
		gaps = cmpGaps
	}
	out := make([]triage.Observation, 0, len(bodies))
	at := cmpEpoch
	for i, b := range bodies {
		if i > 0 {
			at = at.Add(gaps[(i-1)%len(gaps)])
		}
		out = append(out, e.one(b, at))
	}
	return out
}

func (e cmpEndpoint) one(body string, at time.Time) triage.Observation {
	media := e.media
	if media == "" {
		media = "text/html"
	}
	status := e.status
	if status == 0 {
		status = 200
	}
	return triage.Observation{
		ObsID:       fmt.Sprintf("obs-%d", at.UnixNano()),
		Kind:        triage.ObsBaseline,
		ReqMethod:   "GET",
		Status:      status,
		MediaType:   media,
		ContentType: string(media),
		RespHeaders: e.headers,
		Body:        []byte(body),
		BodyLen:     len(body),
		SentAt:      at,
	}
}

func (e cmpEndpoint) probe(body string) triage.Observation {
	o := e.one(body, cmpEpoch.Add(10*time.Second))
	o.Kind = triage.ObsProbe
	// EVERY PROBE FIXTURE MUST DECLARE WHETHER ITS PAYLOAD REACHED THE WIRE, because the
	// comparator refuses to draw a clean from a probe that cannot show it sent anything. See
	// TestAProbeWhosePayloadNeverReachedTheWireIsNeverClean. The payload is one byte so that
	// echo removal, which needs a run of triageEchoMinRun, cannot fire off the back of it and
	// quietly change what the other fixtures measure.
	o.Payload = triage.PayloadWire{
		Logical: []byte("'"), Wire: []byte("'"), Container: []byte("q='"),
		ContainerName: "request-target", Survived: triage.WireSurvivalIntact,
	}
	return o
}

// cmpPage wraps a body in enough stable HTML on both sides for a marking to anchor.
//
// foundations T2 gives a 78-byte document. With DYNAMICITY_BOUNDARY_LENGTH at 20 no block under
// 41 bytes can anchor a marking, and that document's tail is 18 bytes, so on the literal fixture
// the learner produces a prefix-only marking that eats the whole tail. That is a property of the
// sqlmap algorithm the document specifies, not of this implementation, and it would make T3's
// "masked_only must not fire" unsatisfiable for the wrong reason. The fixture body is therefore
// padded to a realistic page size; every stated expectation is preserved.
func cmpPage(head, volatile, tail string) string {
	return "<html><head><title>Orders</title></head><body><h1>Orders</h1>" + head +
		"<!-- trace " + volatile + " -->" +
		`<div class="footer">Copyright 2026 Example Corp. All rights reserved.</div>` + tail +
		"</body></html>"
}

// cmpTraceIDs together cover every hexadecimal digit, so the alphabet the learner records for the
// trace-id region is complete and a later hexadecimal id is not novel. Random ids would make the
// novelty test flaky, and a flaky novelty test is a test that gets deleted.
//
// No id after the first shares its first or its last byte with the first one. That is not
// cosmetic: the matching block between sample 1 and sample j extends as far as the bytes agree,
// so a shared leading byte pushes the block one byte into the id and the pairing learns a marking
// anchored one byte later. The union then holds two markings for one region, which is harmless in
// production and makes an exact-count assertion here meaningless.
var cmpTraceIDs = []string{"0123ab", "4567cd", "89abef", "c0d1e2", "f3a4b5"}

func cmpBaselineFor(t *testing.T, e cmpEndpoint, bodies ...string) TriageBaseline {
	t.Helper()
	return BuildTriageBaseline(e.samples(bodies...), nil)
}

func cmpChannel(res CompareResult, id ChannelID) ChannelResult {
	for _, c := range res.Channels {
		if c.Channel == id {
			return c
		}
	}
	return ChannelResult{Channel: id, Verdict: DiffUnmeasured}
}

func cmpHasToken(tokens []string, want string) bool {
	for _, tok := range tokens {
		if tok == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// The spacing rule
// ---------------------------------------------------------------------------------------------

// A schedule that a one-second clock could sleep through is refused before a request is sent.
//
// This is the whole reason BaselineSchedule is a value rather than a loop in the runner. Five
// back-to-back requests finish in under 300 ms, the second-granularity timestamp in the body shows
// the same value in all five, the learner records it as invariant, and every later probe then
// reads as a differential on the clock.
func TestABaselineScheduleTooTightForASlowClockIsRefused(t *testing.T) {
	backToBack := BaselineSchedule{Samples: 5, Gaps: []time.Duration{
		50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond,
	}}
	err := backToBack.Validate()
	if err == nil {
		t.Fatal("a 200 ms baseline window was accepted, which is the exact measurement this rule exists to prevent")
	}
	if !strings.Contains(err.Error(), "span") {
		t.Errorf("the refusal should name the span; got %v", err)
	}

	wideSpanNoGap := BaselineSchedule{Samples: 5, Gaps: []time.Duration{
		700 * time.Millisecond, 700 * time.Millisecond, 700 * time.Millisecond, 700 * time.Millisecond,
	}}
	if err := wideSpanNoGap.Validate(); err == nil {
		t.Error("a 2.8 s span made of 700 ms gaps was accepted, but no single gap guarantees a one-second tick")
	}

	if err := BaselineScheduleFor(false).Validate(); err != nil {
		t.Errorf("the default schedule must satisfy its own rule: %v", err)
	}
	if err := BaselineScheduleFor(true).Validate(); err != nil {
		t.Errorf("the non-idempotent schedule must satisfy its own rule: %v", err)
	}
	if got := BaselineScheduleFor(true).Samples; got != TriageNonIdempotentSamples {
		t.Errorf("a non-idempotent vector takes %d samples, want %d: five samples of a POST that creates a row creates five rows", got, TriageNonIdempotentSamples)
	}
}

// The spacing actually observed is measured and reported, not assumed from the schedule.
func TestObservedSpacingIsMeasuredFromTheSamplesThemselves(t *testing.T) {
	tight := cmpEndpoint{gaps: []time.Duration{60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond}}
	b := BuildTriageBaseline(tight.samples("a", "a", "a", "a", "a"), nil)
	if b.SpacingHonoured {
		t.Errorf("a 240 ms window was reported as honouring the spacing rule (span %d ms, max gap %d ms)", b.SpanMillis, b.MaxGapMillis)
	}

	wide := cmpBaselineFor(t, cmpEndpoint{}, "a", "a", "a", "a", "a")
	if !wide.SpacingHonoured {
		t.Errorf("the default fixture spacing was reported as not honoured (span %d ms, max gap %d ms)", wide.SpanMillis, wide.MaxGapMillis)
	}
}

// ---------------------------------------------------------------------------------------------
// T1. A wholly volatile endpoint
// ---------------------------------------------------------------------------------------------

// T1: every byte of the body is fresh. The differential oracles must go dark, and they must do it
// by saying too_volatile rather than by saying nothing changed.
//
// The gate gates the DIFFERENTIAL, not the endpoint: a test asserting that nothing runs here would
// be wrong, because deterministic computation, out-of-band callbacks, distinctive content and
// error signatures all still work on a noisy page.
func TestAWhollyVolatileEndpointIsTooVolatileAndNeverClean(t *testing.T) {
	e := cmpEndpoint{media: "text/plain"}
	b := cmpBaselineFor(t, e,
		"9f2b7c1d4e6a8035bb11ce22df33a044ff556677889900aabbccddeeff001122",
		"11223344556677889900aabbccddeeff0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		"cafebabe0badf00ddeadbeef12345678feedface9876543210abcdefabcdef01",
		"0011aa22bb33cc44dd55ee66ff778899aabbccddeeff00112233445566778899",
		"7f6e5d4c3b2a19080706050403020100ffeeddccbbaa99887766554433221100",
	)
	if b.Gate != GateTooVolatile {
		t.Fatalf("gate = %q (%s), want too_volatile; masked_fraction %.3f, r_floor %.4f", b.Gate, b.GateDetail, b.MaskedFraction, b.Model.RFloor)
	}
	// foundations T1 predicts the verdict comes from G3 with masked_fraction at 1.0. It comes
	// from G2 instead, and it has to: no matching block survives the 40-byte boundary filter on a
	// 64-byte random body, so the learner anchors no marking and masked_fraction is 0. G2 is
	// evaluated first and the similarity floor is near zero, so the answer is the same and the
	// stated reason is the honest one.
	if b.MaskedFraction != 0 {
		t.Errorf("masked_fraction = %.3f, want 0: nothing can be anchored on a wholly volatile body", b.MaskedFraction)
	}
	if b.Model.RFloor >= triageGateRFloorMin {
		t.Errorf("r_floor = %.4f, want well below %.2f", b.Model.RFloor, triageGateRFloorMin)
	}
	if b.DistinctNormalised != 5 {
		t.Errorf("%d distinct normalised bodies out of 5, want 5: unbounded variation is the fact that makes masking unworkable here", b.DistinctNormalised)
	}

	res := CompareToBaseline(b, e.probe("bbbbccccddddeeeeffff00001111222233334444555566667777888899990000"))
	if res.Verdict != DiffUnusable {
		t.Errorf("verdict = %q, want unusable", res.Verdict)
	}
	if res.Reason != "too_volatile" {
		t.Errorf("reason = %q, want too_volatile", res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("an endpoint nobody could measure counted as clean")
	}
	if res.State() != triage.StateCannotDetermine {
		t.Errorf("state = %q, want cannot_determine", res.State())
	}
	// The endpoint itself is reachable and answering. Only the differential is closed.
	if !b.Template.Delivered() || b.NoBody {
		t.Error("a too_volatile endpoint was also reported unreachable or bodyless, which would wrongly disable four oracles that need no baseline")
	}
}

// ---------------------------------------------------------------------------------------------
// T2. Only a trace id changes
// ---------------------------------------------------------------------------------------------

func cmpTraceBaseline(t *testing.T) (cmpEndpoint, TriageBaseline) {
	t.Helper()
	e := cmpEndpoint{}
	bodies := make([]string, 0, len(cmpTraceIDs))
	for _, id := range cmpTraceIDs {
		bodies = append(bodies, cmpPage("<p>3 results</p>", id, ""))
	}
	return e, cmpBaselineFor(t, e, bodies...)
}

// T2: the learner finds the one region that varies, from the variation alone, with no pattern list
// anywhere in the code.
func TestATraceIDIsLearnedAsTheOnlyVolatileRegion(t *testing.T) {
	_, b := cmpTraceBaseline(t)
	if b.Gate != GateJudgeable {
		t.Fatalf("gate = %q (%s), want judgeable", b.Gate, b.GateDetail)
	}
	if len(b.Markings) != 1 {
		t.Fatalf("learned %d markings, want exactly 1 (the trace id): %v", len(b.Markings), b.Markings)
	}
	if b.MaskedFraction <= 0 || b.MaskedFraction > 0.15 {
		t.Errorf("masked_fraction = %.3f, want a small non-zero fraction: the trace id is six bytes of a full page", b.MaskedFraction)
	}
	if !b.Model.ClockTick {
		t.Error("the body changed between samples, so the clock was proven to tick and ClockTick must be true")
	}
	if b.DistinctNormalised != 1 {
		t.Errorf("%d distinct normalised bodies, want 1: masking the trace id should collapse all five samples", b.DistinctNormalised)
	}
}

// T2a: a fresh trace id and nothing else is same. The endpoint varies there anyway.
func TestAFreshTraceIDAloneIsSame(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "7a3f0c", "")))
	if res.Verdict != DiffSame {
		t.Fatalf("verdict = %q (%s), want same", res.Verdict, res.Reason)
	}
	if !res.CountsAsClean() {
		t.Error("a measured, judgeable, identical-after-masking comparison did not count as clean, which would make every endpoint unjudgeable")
	}
}

// T2b: a fresh trace id AND a changed result count is different, and the changed bytes are
// reported from outside the masked region.
func TestAChangedResultCountOutsideTheMaskIsDifferent(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	res := CompareToBaseline(b, e.probe(cmpPage("<p>0 results</p>", "7a3f0c", "")))
	if res.Verdict != DiffDifferent {
		t.Fatalf("verdict = %q (%s), want different; r_bag %.4f r_shingle %.4f threshold %.4f", res.Verdict, res.Reason, res.RBag, res.RShingle, res.Threshold)
	}
	if len(res.ChangedRegions) == 0 {
		t.Error("a differential reported no changed region, so the operator is told something changed and not where")
	}
	if res.Verdict == DiffMaskedOnly {
		t.Error("masked_only fired on a change outside every marking, which means the learned marking is too wide")
	}
	if res.CountsAsClean() {
		t.Error("a differential counted as clean")
	}
}

// T2c: the volatile value changing LENGTH is still same. The marking is anchored by the bytes
// around the hole, not by an offset, and this is the case an offset-based region model gets wrong.
func TestAVolatileRegionChangingLengthIsStillSame(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "abc123def456789", "")))
	if res.Verdict != DiffSame {
		t.Fatalf("verdict = %q (%s), want same: the marking is prefix and suffix bounded and therefore length-independent", res.Verdict, res.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// T3. A real SQL error inside an otherwise identical page
// ---------------------------------------------------------------------------------------------

// T3 asserts four things at once, and that is the point. A model that reaches different but also
// fires masked_only has learned a marking that is too wide, and it would go on to swallow this
// error on the next endpoint.
func TestASQLErrorAddedToAnOtherwiseIdenticalPageIsDifferentAndNotMasked(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	errDiv := `<div class="err">org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near</div>`
	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "7a3f0c", errDiv)))

	if res.Verdict != DiffDifferent {
		t.Fatalf("verdict = %q (%s), want different", res.Verdict, res.Reason)
	}
	for _, h := range res.MaskedHits {
		if h.NovelBytes {
			t.Errorf("masked region %d was reported as carrying novel bytes, but the error was added outside every marking: %q", h.Marking, h.Probe)
		}
	}
	probeTokens := TriageStructTokens([]byte(cmpPage("<p>3 results</p>", "7a3f0c", errDiv)))
	if !cmpHasToken(probeTokens, "cls:div.err") {
		t.Errorf("the structural projection did not gain cls:div.err; got %v", probeTokens)
	}
	if cmpHasToken(b.StructTokens, "cls:div.err") {
		t.Error("the baseline structural projection already contained cls:div.err, so the fixture proves nothing")
	}
	if ch := cmpChannel(res, ChanHTMLStruct); ch.Verdict != DiffDifferent {
		t.Errorf("html_structure channel = %q, want different: a results table or an error box appearing is exactly what this projection is for", ch.Verdict)
	}
	// The error signature itself is catalogued elsewhere; what this file owns is that a signature
	// absent from the baseline and present in the probe survives the differencing.
	if got := NovelErrorSigs(nil, []string{"pg.PSQLException"}); len(got) != 1 || got[0] != "pg.PSQLException" {
		t.Errorf("NovelErrorSigs = %v, want [pg.PSQLException]", got)
	}
}

// ---------------------------------------------------------------------------------------------
// T4. A WAF block that answers every payload identically
// ---------------------------------------------------------------------------------------------

const cmpWAFBody = `<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator. Your support ID is: 0</body></html>`

// cmpVault is the one run vault the comparator tests mint into.
//
// It is held here because the package-level minting entry point is gone: a run's responses are now
// reachable only from a value somebody is holding, which is what ended the //go:linkname attack
// that reached every class's body with no handle and no run id. The tests are the runner here, so
// the tests hold the vault.
var cmpVault = triage.NewPerturbedVault(triageRunnerCapability(), "7f3q")

func cmpPerturbed(t *testing.T, owner triage.ClassID, n int, body string, status int) []triage.Perturbed {
	t.Helper()
	out := make([]triage.Perturbed, 0, n)
	for i := 0; i < n; i++ {
		ordinal := uint64(i)*triage.ClassStripeModulus + uint64(owner)
		obs := triage.Observation{
			ObsID:     fmt.Sprintf("probe-%d-%d", owner, i),
			Kind:      triage.ObsProbe,
			Class:     owner,
			Status:    status,
			MediaType: "text/html",
			Body:      []byte(body),
			BodyLen:   len(body),
			Payload:   triage.PayloadWire{Logical: []byte(fmt.Sprintf("payload-%d-%d", owner, i)), Wire: []byte(fmt.Sprintf("payload-%d-%d", owner, i))},
		}
		p, err := cmpVault.Mint(triageRunnerCapability(), obs, owner, triage.ProbeID(fmt.Sprintf("P%d", i)), ordinal, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// T4 is the single most common false-positive generator in the wild: a 403 differs from baseline,
// therefore signal. It is not signal. It is an absence of measurement, and the class must say so.
func TestAUniformWAFBlockIsAnAbsenceOfMeasurementAndNotAFinding(t *testing.T) {
	e, b := cmpTraceBaseline(t)

	two := cmpPerturbed(t, triage.ClassSQL, 2, cmpWAFBody, 403)
	if got, err := DetectUniformBlock(b, triage.OwnFor(triageRunnerCapability(), two, triage.ClassSQL)); err != nil || got.UniformBlock {
		t.Errorf("two identical blocks were called uniform_block (%v, err %v); the rule is three or more of the class's OWN distinct payloads", got, err)
	}

	own := cmpPerturbed(t, triage.ClassSQL, 4, cmpWAFBody, 403)
	got, err := DetectUniformBlock(b, triage.OwnFor(triageRunnerCapability(), own, triage.ClassSQL))
	if err != nil {
		t.Fatalf("DetectUniformBlock: %v", err)
	}
	if !got.UniformBlock || got.Payloads != 4 {
		t.Fatalf("uniform_block = %+v, want four payloads flagged", got)
	}

	// The comparison of any one of those responses on its own still says "different", and that is
	// correct: it is the class's verdict that becomes cannot_determine (blocked), not the
	// comparator's, and the interference check is what makes that call.
	res := CompareToBaseline(b, e.probe(cmpWAFBody))
	if res.Verdict != DiffDifferent {
		t.Errorf("verdict = %q, want different: the block page genuinely differs from the baseline", res.Verdict)
	}
	if got.Reason != "blocked" {
		t.Errorf("interference reason = %q, want blocked", got.Reason)
	}

	// A class may not read another class's probes to reach this, and the type system says so.
	//
	// The assertion changed shape with the API and got stronger. It used to be that LFI passing its
	// own id alongside SQL's handles got an ERROR back from the accessor. There is now no accessor
	// that takes an id: the only way to a response is triage.OwnFor, which FILTERS, so LFI asking
	// for SQL's handles does not get refused, it gets nothing. An empty set cannot produce a
	// UniformBlock, so LFI reaches no verdict from SQL's responses at all.
	foreign := triage.OwnFor(triageRunnerCapability(), own, triage.ClassLFI)
	if foreign.Len() != 0 {
		t.Errorf("LFI was handed %d of SQL's responses", foreign.Len())
	}
	if got, err := DetectUniformBlock(b, foreign); err != nil || got.UniformBlock {
		t.Errorf("LFI reached interference %v (err %v) from SQL's responses", got, err)
	}

	// The cross-class annotation is the one declared exception, and it is an annotation.
	sqlI, _ := DetectUniformBlock(b, triage.OwnFor(triageRunnerCapability(), own, triage.ClassSQL))
	lfiOwn := cmpPerturbed(t, triage.ClassLFI, 3, cmpWAFBody, 403)
	lfiI, err := DetectUniformBlock(b, triage.OwnFor(triageRunnerCapability(), lfiOwn, triage.ClassLFI))
	if err != nil {
		t.Fatalf("DetectUniformBlock LFI: %v", err)
	}
	crossed, classes := CrossClassUniformBlock(map[triage.ClassID]Interference{triage.ClassSQL: sqlI, triage.ClassLFI: lfiI})
	if !crossed || len(classes) != 2 {
		t.Errorf("cross-class annotation = %v %v, want both classes named: a WAF in front of this slot is worth telling the operator", crossed, classes)
	}
}

// ---------------------------------------------------------------------------------------------
// T5. Two-server alternation
// ---------------------------------------------------------------------------------------------

// T5: two samples from a two-server pool either look identical, so you learn nothing and believe
// the page is stable, or look wholly different, so you mask far too much. Three samples let you
// see A, B, A. Both failure modes are asserted here.
func TestATwoServerPoolIsLearnedRatherThanCalledUnstable(t *testing.T) {
	e := cmpEndpoint{}
	page := func(server string) string {
		return cmpPage("<p>3 results</p>", "8f2a1c", "<!-- served-by: "+server+" -->")
	}
	b := cmpBaselineFor(t, e, page("web-01"), page("web-02"), page("web-01"), page("web-02"), page("web-01"))

	if b.Gate != GateJudgeable {
		t.Fatalf("gate = %q (%s), want judgeable: a two-server pool is learnable, not too volatile", b.Gate, b.GateDetail)
	}
	if len(b.Markings) == 0 {
		t.Fatal("zero markings learned: the sampler hit one server and the model believes the page is stable")
	}
	if b.DistinctNormalised != 1 {
		t.Errorf("%d distinct normalised bodies, want 1: masking the served-by comment should collapse both pool members", b.DistinctNormalised)
	}

	res := CompareToBaseline(b, e.probe(page("web-02")))
	if res.Verdict != DiffSame {
		t.Errorf("verdict = %q (%s), want same: landing on the other pool member is not a differential", res.Verdict, res.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// T6. The clock-granularity trap
// ---------------------------------------------------------------------------------------------

// T6: the whole baseline window passed without a single byte changing, so the endpoint never
// proved its clock ticks. A probe whose only difference is a digit run is then indistinguishable
// from the clock finally ticking, and reporting it as different produces a false positive on every
// probe.
func TestAnEndpointThatNeverProvedItsClockTicksDowngradesDigitOnlyDifferences(t *testing.T) {
	body := func(sec string) string {
		return cmpPage("<p><span>Generated 2026-09-18 10:04:"+sec+"</span></p>", "8f2a1c", "")
	}
	e := cmpEndpoint{}
	b := cmpBaselineFor(t, e, body("07"), body("07"), body("07"), body("07"), body("07"))

	if !b.ClockUnproven {
		t.Fatal("no byte changed across the whole baseline window and clock_unproven was not recorded")
	}
	if b.Gate != GateJudgeable {
		t.Fatalf("gate = %q (%s), want judgeable", b.Gate, b.GateDetail)
	}

	res := CompareToBaseline(b, e.probe(body("09")))
	if res.Verdict != DiffMaskedOnly {
		t.Fatalf("verdict = %q (%s), want masked_only", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("masked_only counted as clean")
	}
	if res.State() != triage.StateMaskedOnly {
		t.Errorf("state = %q, want masked_only", res.State())
	}

	// The same fixture sampled back to back also fails the spacing rule, which is the other half
	// of the same trap and is reported separately so the operator can tell them apart.
	tight := cmpEndpoint{gaps: []time.Duration{80 * time.Millisecond, 80 * time.Millisecond, 80 * time.Millisecond, 80 * time.Millisecond}}
	tb := BuildTriageBaseline(tight.samples(body("07"), body("07"), body("07"), body("07"), body("07")), nil)
	if tb.SpacingHonoured {
		t.Errorf("a 320 ms window reported the spacing rule as honoured (span %d ms)", tb.SpanMillis)
	}
}

// ---------------------------------------------------------------------------------------------
// T7. JSON that is noisy on bytes and stable on shape
// ---------------------------------------------------------------------------------------------

func cmpJSONBody(seed int, rows int, total int) string {
	var sb strings.Builder
	sb.WriteString(`{"meta":{"request_id":"`)
	sb.WriteString(cmpHex(seed*7919, 32))
	sb.WriteString(`","total":`)
	fmt.Fprintf(&sb, "%d", total)
	sb.WriteString(`},"results":[`)
	for i := 0; i < rows; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"`)
		sb.WriteString(cmpHex(seed*1000+i, 36))
		sb.WriteString(`","created_at":"`)
		sb.WriteString(cmpHex(seed*31+i, 24))
		sb.WriteString(`","cursor":"`)
		sb.WriteString(cmpHex(seed*97+i*13, 64))
		sb.WriteString(`"}`)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

// cmpHex is a deterministic hexadecimal filler. It is deterministic so the alphabet the learner
// records is stable and the novelty check is not flaky.
func cmpHex(seed, n int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, n)
	x := uint64(seed)*6364136223846793005 + 1442695040888963407
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = digits[(x>>33)&0xf]
	}
	return string(out)
}

// T7: this is the case that decides whether a REST corpus is covered at all. The bytes are
// dominated by ids and cursors, so the byte model says "too noisy to judge" and every class would
// return cannot_determine, while the key set, the type map and the cardinalities are identical
// across every sample.
func TestAByteNoisyJSONEndpointIsStillJudgeableOnItsShape(t *testing.T) {
	e := cmpEndpoint{media: "application/json"}
	b := cmpBaselineFor(t, e,
		cmpJSONBody(1, 30, 30), cmpJSONBody(2, 30, 30), cmpJSONBody(3, 30, 30),
		cmpJSONBody(4, 30, 30), cmpJSONBody(5, 30, 30),
	)
	if b.Gate != GateJudgeableShapeOnly {
		t.Fatalf("gate = %q (%s), want judgeable_shape_only; r_floor %.4f masked %.3f", b.Gate, b.GateDetail, b.Model.RFloor, b.MaskedFraction)
	}
	if b.Model.RFloor >= triageGateRFloorMin {
		t.Errorf("r_floor = %.4f, expected the byte gate to FAIL on this body; the fixture is not noisy enough to prove anything", b.Model.RFloor)
	}
	if !b.Gate.ShapeJudgeable() || b.Gate.BytesJudgeable() {
		t.Error("judgeable_shape_only must open the shape oracles and close the byte ones")
	}
	for _, want := range []string{"/results[]/id", "/results[]/created_at", "/meta/request_id"} {
		if !b.VolatilePointers[want] {
			t.Errorf("%s was not learned volatile; it changes in every sample", want)
		}
	}
	if b.VolatilePointers["/meta/total"] {
		t.Error("/meta/total is constant across every sample and was learned volatile, which would suppress the cleanest oracle a JSON API offers")
	}

	// T7a: the row count collapses. A byte-only model reports unusable here.
	res := CompareToBaseline(b, e.probe(cmpJSONBody(9, 0, 0)))
	if res.Verdict != DiffDifferent {
		t.Fatalf("T7a verdict = %q (%s), want different on the shape", res.Verdict, res.Reason)
	}
	if len(res.Shape.LensChanged) == 0 {
		t.Errorf("T7a reported no cardinality change; shape = %+v", res.Shape)
	}
	if len(res.Shape.ValsChanged) == 0 {
		t.Errorf("T7a reported no scalar change, but /meta/total went 30 to 0; shape = %+v", res.Shape)
	}

	// T7b: fresh ids and nothing else.
	res = CompareToBaseline(b, e.probe(cmpJSONBody(11, 30, 30)))
	if res.Verdict != DiffSame {
		t.Fatalf("T7b verdict = %q (%s), want same; shape = %+v", res.Verdict, res.Reason, res.Shape)
	}
	if len(res.Shape.VolatileHit) == 0 {
		t.Error("T7b changed every volatile pointer and none was recorded in VolatileHit, so the suppression is invisible to the operator")
	}
	if !res.CountsAsClean() {
		t.Error("a shape-judgeable endpoint with an unchanged shape could not produce a clean result, which would make the whole projection pointless")
	}
}

// The lexical token, not the parsed value. sqlmap's jsonMinimize stringifies the parsed scalar, so
// a precision change is invisible and a large integer loses its low digits through float64.
func TestJSONScalarsAreComparedAsLexicalTokens(t *testing.T) {
	e := cmpEndpoint{media: "application/json"}
	const base = `{"alpha":"a-stable-string-value-here","count":100,"big":9007199254740993,"nested":{"flag":true}}`
	b := cmpBaselineFor(t, e, base, base, base, base, base)
	if b.Gate != GateJudgeable {
		t.Fatalf("gate = %q (%s)", b.Gate, b.GateDetail)
	}

	for _, tc := range []struct{ name, body string }{
		{"exponent form of the same value", `{"alpha":"a-stable-string-value-here","count":1e2,"big":9007199254740993,"nested":{"flag":true}}`},
		{"a large integer losing its low digit", `{"alpha":"a-stable-string-value-here","count":100,"big":9007199254740992,"nested":{"flag":true}}`},
	} {
		res := CompareToBaseline(b, e.probe(tc.body))
		if len(res.Shape.ValsChanged) == 0 {
			t.Errorf("%s: the shape diff saw no change, which is the jsonMinimize defect we must not inherit", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// T8. An integer cast that discards the tail
// ---------------------------------------------------------------------------------------------

// T8: the endpoint parses its parameter with Atoi-like leniency, so a value of 1 and a value of 1
// with any trailing text produce byte-identical responses. The correct triage output is "this slot
// is integer-cast", not clean and not "no reflection". The comparator's half of that is to keep
// answering same, honestly, every time.
func TestAnIntegerCastEndpointAnswersSameToEveryAppendedPayload(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	for _, payload := range []string{"1'", "1 OR 1=1", "1{{7*7}}", "1../../etc/passwd"} {
		probe := e.probe(cmpPage("<p>3 results</p>", "7a3f0c", ""))
		probe.Payload = triage.PayloadWire{Logical: []byte(payload), Wire: []byte(payload), Survived: triage.WireSurvivalIntact}
		res := CompareToBaseline(b, probe)
		if res.Verdict != DiffSame {
			t.Errorf("payload %q: verdict = %q (%s), want same", payload, res.Verdict, res.Reason)
		}
	}
	// cast_suspected is a SLOT annotation derived across every class that probed the slot plus the
	// decode control, so it is deliberately not computed here: this file must not own a fact that
	// depends on another class's probes.
}

// ---------------------------------------------------------------------------------------------
// T9. Always-500
// ---------------------------------------------------------------------------------------------

// T9 exists to kill the "5xx means injection" rule, which is the second most common
// false-positive generator. The gate PASSES here, because every sample agrees, and a probe that
// also returns 500 is same.
func TestAnEndpointThatAlwaysReturnsFiveHundredPassesTheGateAndIsNotASignal(t *testing.T) {
	e := cmpEndpoint{status: 500}
	page := `<html><head><title>Server Error</title></head><body><h1>500</h1><p>The server encountered an internal error and could not complete your request.</p></body></html>`
	b := cmpBaselineFor(t, e, page, page, page, page, page)
	if b.Gate != GateJudgeable {
		t.Fatalf("gate = %q (%s), want judgeable: every sample agreed on the status", b.Gate, b.GateDetail)
	}
	res := CompareToBaseline(b, e.probe(page))
	if res.Verdict != DiffSame {
		t.Errorf("verdict = %q (%s), want same: a 500 from an always-500 endpoint is not a signal", res.Verdict, res.Reason)
	}
	if ch := cmpChannel(res, ChanStatus); ch.Verdict != DiffSame {
		t.Errorf("status channel = %q, want same", ch.Verdict)
	}
}

// ---------------------------------------------------------------------------------------------
// T10. Always-dberror
// ---------------------------------------------------------------------------------------------

// T10: the unperturbed response already carries a database exception. A naive matcher fires on
// every probe here and scores 100% on a corpus where every route is vulnerable, which is exactly
// the verification hole the oracle notes describe.
func TestAnErrorSignatureAlreadyInTheBaselineIsDisabledForThatEndpoint(t *testing.T) {
	baseline := []string{"pg.PSQLException"}

	if got := NovelErrorSigs(baseline, []string{"pg.PSQLException"}); len(got) != 0 {
		t.Errorf("NovelErrorSigs = %v, want empty: this signature is in the baseline and cannot be a finding here", got)
	}
	if got := NovelErrorSigs(baseline, []string{"pg.PSQLException", "pg.SyntaxError"}); len(got) != 1 || got[0] != "pg.SyntaxError" {
		t.Errorf("NovelErrorSigs = %v, want [pg.SyntaxError]: a DIFFERENT signature appearing is still a signal", got)
	}
	if got := NovelErrorSigs(nil, nil); len(got) != 0 {
		t.Errorf("NovelErrorSigs = %v, want empty", got)
	}
}

// ---------------------------------------------------------------------------------------------
// T11. An oversized body
// ---------------------------------------------------------------------------------------------

// T11: above the diff limit, or on a truncated body, the comparison is degraded. A degraded
// comparison caps at suspicious and can never produce clean, even when the bytes it could see
// agreed, because the bytes it could not see are the ones that would have carried the signal.
func TestADegradedComparisonCapsAtSuspiciousAndCanNeverBeClean(t *testing.T) {
	e := cmpEndpoint{}
	page := cmpPage("<p>3 results</p>", "8f2a1c", strings.Repeat("<p>filler</p>", 200))
	samples := e.samples(page, page, page, page, page)
	for i := range samples {
		samples[i].BodyTruncated = true
		samples[i].BodyLen = 8 << 20
	}
	b := BuildTriageBaseline(samples, nil)
	if !b.Model.Degraded {
		t.Fatal("a truncated baseline body did not set Degraded")
	}

	probe := e.probe(page)
	probe.BodyTruncated = true
	probe.BodyLen = 8 << 20
	res := CompareToBaseline(b, probe)

	if !res.Degraded {
		t.Fatal("the comparison was not marked degraded")
	}
	if res.MaxState != triage.StateSuspicious {
		t.Errorf("MaxState = %q, want suspicious: a degraded comparison may not produce a finding", res.MaxState)
	}
	if res.CountsAsClean() {
		t.Error("a degraded comparison counted as clean, which is the exact shape of a false negative this layer exists to prevent")
	}
	if res.State() != triage.StateCannotDetermine {
		t.Errorf("state = %q, want cannot_determine on a degraded same", res.State())
	}
}

// ---------------------------------------------------------------------------------------------
// T12. An empty body
// ---------------------------------------------------------------------------------------------

// T12: not "identical bodies, therefore same". There is nothing to compare, so the body channel is
// unusable and a class with no other oracle gets cannot_determine (no_body).
func TestAnEmptyBodyIsUnusableAndNotAgreement(t *testing.T) {
	e := cmpEndpoint{status: 204, media: ""}
	b := cmpBaselineFor(t, e, "", "", "", "", "")
	if !b.NoBody {
		t.Fatal("five empty bodies did not set NoBody")
	}
	res := CompareToBaseline(b, e.probe(""))
	if ch := cmpChannel(res, ChanBody); ch.Verdict != DiffUnusable {
		t.Errorf("body channel = %q, want unusable", ch.Verdict)
	}
	if res.Verdict != DiffUnusable {
		t.Fatalf("verdict = %q (%s), want unusable", res.Verdict, res.Reason)
	}
	if res.Reason != "no_body" {
		t.Errorf("reason = %q, want no_body", res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("two empty bodies counted as clean")
	}
}

// ---------------------------------------------------------------------------------------------
// T13. A CSRF-required POST
// ---------------------------------------------------------------------------------------------

// T13: every sample after the first fails validation. The honest answer is neither too_volatile
// nor clean: the status flapped, so even error-signature detection is off, and the class's actual
// reason comes from the prelude, which lives in part 7 and is owned elsewhere.
func TestAStatusThatFlapsAcrossTheBaselineClosesEvenErrorSignatures(t *testing.T) {
	e := cmpEndpoint{media: "application/json"}
	ok := `{"id":1,"name":"a stable enough object for the ratio"}`
	rejected := `{"error":"invalid authenticity token"}`
	samples := e.samples(ok, rejected, rejected, rejected, rejected)
	for i := range samples {
		samples[i].ReqMethod = "POST"
		if i > 0 {
			samples[i].Status = 422
		}
	}
	b := BuildTriageBaseline(samples, nil)

	if b.Gate != GateStatusFlap {
		t.Fatalf("gate = %q (%s), want status_flap", b.Gate, b.GateDetail)
	}
	if !strings.Contains(b.GateDetail, "200:1") || !strings.Contains(b.GateDetail, "422:4") {
		t.Errorf("gate detail = %q, want the observed status multiset recorded", b.GateDetail)
	}
	res := CompareToBaseline(b, e.probe(rejected))
	if res.Verdict != DiffUnusable || res.Reason != "status_flap" {
		t.Errorf("verdict = %q reason = %q, want unusable/status_flap", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("a flapping endpoint counted as clean")
	}
	if !b.NonIdempotent.Detected || b.NonIdempotent.SamplesAllowed != TriageNonIdempotentSamples {
		t.Errorf("a POST vector was not detected as non-idempotent: %+v", b.NonIdempotent)
	}
}

// ---------------------------------------------------------------------------------------------
// T14 and T15. Reordering
// ---------------------------------------------------------------------------------------------

// T14: the same ten items in reverse order. quick_ratio is a multiset comparison, so it scores
// this 1.0 and reports same, losing a legitimate differential. The shingle metric is what sees it.
func TestAReorderedResultSetIsItsOwnStateAndNotSame(t *testing.T) {
	e := cmpEndpoint{}
	items := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"}
	build := func(order []string) string {
		var sb strings.Builder
		sb.WriteString("<html><head><title>Orders</title></head><body><ul>")
		for _, it := range order {
			sb.WriteString("<li>" + it + "</li>")
		}
		sb.WriteString("</ul></body></html>")
		return sb.String()
	}
	forward := build(items)
	reversed := make([]string, len(items))
	for i, it := range items {
		reversed[len(items)-1-i] = it
	}

	b := cmpBaselineFor(t, e, forward, forward, forward, forward, forward)
	res := CompareToBaseline(b, e.probe(build(reversed)))

	if res.RBag < 1.0 {
		t.Fatalf("r_bag = %.6f, want exactly 1.0: the fixture must be a true anagram or it proves nothing about quick_ratio", res.RBag)
	}
	if res.RShingle >= 1.0 {
		t.Fatalf("r_shingle = %.6f, want below 1.0", res.RShingle)
	}
	if res.Verdict != DiffReordered {
		t.Fatalf("verdict = %q (%s), want reordered", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("reordered counted as clean")
	}
}

// T15 (LOCAL): key order is not part of the JSON shape. Go maps and most serializers do not
// preserve it, so a shape model that sorts nothing reports a differential on every response from a
// perfectly normal server.
func TestReorderedJSONKeysMoveTheBytesAndNotTheShape(t *testing.T) {
	e := cmpEndpoint{media: "application/json"}
	const forward = `{"alpha":"one","bravo":"two","charlie":"three","delta":"four","echo":"five"}`
	const shuffled = `{"echo":"five","charlie":"three","alpha":"one","delta":"four","bravo":"two"}`
	b := cmpBaselineFor(t, e, forward, forward, forward, forward, forward)
	res := CompareToBaseline(b, e.probe(shuffled))

	if !res.Shape.Empty() {
		t.Errorf("the shape diff was not empty for a pure key reordering: %+v", res.Shape)
	}
	if ch := cmpChannel(res, ChanJSONShape); ch.Verdict != DiffSame {
		t.Errorf("json_shape channel = %q, want same", ch.Verdict)
	}
	if res.Verdict != DiffReordered {
		t.Errorf("verdict = %q (%s), want reordered: the bytes did move, and saying so at reduced confidence is honest", res.Verdict, res.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// T16 and T17. Sameness, and the safety valve on masking
// ---------------------------------------------------------------------------------------------

// T16 (LOCAL): the control. If this fixture does not come back clean then every other answer in
// this file is meaningless, because a comparator that never says same is a comparator nobody uses.
func TestAGenuinelyIdenticalPairIsCleanAndIsTheOnlyFixtureThatIs(t *testing.T) {
	e := cmpEndpoint{}
	page := cmpPage("<p>3 results</p>", "8f2a1c", "")
	b := cmpBaselineFor(t, e, page, page, page, page, page)
	res := CompareToBaseline(b, e.probe(page))

	if res.Verdict != DiffSame {
		t.Fatalf("verdict = %q (%s), want same", res.Verdict, res.Reason)
	}
	if !res.CountsAsClean() {
		t.Fatal("an identical pair on a judgeable endpoint did not count as clean")
	}
	if res.State() != triage.StateClean {
		t.Errorf("state = %q, want clean", res.State())
	}
	for _, ch := range res.Channels {
		if ch.Verdict != DiffSame && ch.Verdict != DiffUnusable {
			t.Errorf("channel %s = %q on an identical pair", ch.Channel, ch.Verdict)
		}
	}
}

// T17 (LOCAL): THE SAFETY VALVE. The union masking across all pairings deliberately masks more
// than any single pair would, which trades false positives for false negatives unless a masked
// region that carries something new can still be reported.
//
// The trigger is measured rather than chosen: the probe put bytes into the region that the region
// never held across the whole baseline. A fresh hexadecimal trace id is not novel, because the
// baseline attested every hexadecimal digit. An error string is.
func TestAMaskedRegionCarryingBytesTheBaselineNeverHeldIsMaskedOnlyAndNotClean(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "7a3f0c PSQLERROR", "")))

	if res.Verdict != DiffMaskedOnly {
		t.Fatalf("verdict = %q (%s), want masked_only; masked hits %+v", res.Verdict, res.Reason, res.MaskedHits)
	}
	if res.CountsAsClean() {
		t.Error("masked_only counted as clean, which is the false negative the whole state exists to prevent")
	}
	if len(res.MaskedHits) == 0 {
		t.Fatal("masked_only was reported with no masked hits, so the operator is told nothing about what the mask swallowed")
	}
	h := res.MaskedHits[0]
	if !h.NovelBytes {
		t.Error("the hit was not flagged as carrying novel bytes")
	}
	if h.Probe == "" || h.Baseline == "" {
		t.Errorf("a masked hit must carry the before and the after: %+v", h)
	}
	if res.State() != triage.StateMaskedOnly {
		t.Errorf("state = %q, want masked_only", res.State())
	}
}

// ---------------------------------------------------------------------------------------------
// T18. Drift
// ---------------------------------------------------------------------------------------------

// T18 (LOCAL, foundations 5.9): the closing baseline no longer matches the opening one. The app
// deployed mid-run, the session expired, a rate limiter engaged, the load balancer moved us. Every
// differential taken in that window is cannot_determine (drift). Without the post-baseline the run
// produces a page of confident false positives and, on the next run, a page of confident cleans.
func TestAClosingBaselineThatDisagreesDowngradesEveryVerdictInTheWindow(t *testing.T) {
	e := cmpEndpoint{}
	page := cmpPage("<p>3 results</p>", "8f2a1c", "")
	samples := e.samples(page, page, page, page, page)

	clean := BuildTriageBaseline(samples, nil)
	if clean.Gate != GateJudgeable {
		t.Fatalf("control gate = %q (%s), want judgeable", clean.Gate, clean.GateDetail)
	}

	post := e.one(`<html><head><title>Maintenance</title></head><body><h1>We will be back shortly</h1><p>This service is being upgraded.</p></body></html>`, cmpEpoch.Add(30*time.Second))
	drifted := BuildTriageBaseline(samples, &post)
	if drifted.Gate != GateDrifted {
		t.Fatalf("gate = %q (%s), want drifted", drifted.Gate, drifted.GateDetail)
	}

	res := CompareToBaseline(drifted, e.probe(page))
	if res.Verdict != DiffUnusable || res.Reason != "drift" {
		t.Errorf("verdict = %q reason = %q, want unusable/drift: not clean and not unstable", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("a drifted window counted as clean")
	}

	// A status change in the closing sample counts too, and names itself.
	post502 := e.one(page, cmpEpoch.Add(30*time.Second))
	post502.Status = 502
	if b := BuildTriageBaseline(samples, &post502); b.Gate != GateDrifted || !strings.Contains(b.GateDetail, "502") {
		t.Errorf("gate = %q detail = %q, want drifted naming the post-baseline status", b.Gate, b.GateDetail)
	}

	// The single retry is allowed once and once only, and both measurement sets survive it.
	if !GateNeedsRemeasurement(drifted) {
		t.Error("a failed gate did not ask for its one re-measurement")
	}
	combined := CombineRemeasurement(drifted, clean)
	if combined.Gate != GateJudgeable || combined.Remeasured == nil || combined.Remeasured.Gate != GateDrifted {
		t.Errorf("the retry must keep both sets: gate %q, first %+v", combined.Gate, combined.Remeasured != nil)
	}
	if GateNeedsRemeasurement(combined) {
		t.Error("a baseline that has already been re-measured asked for a second retry")
	}
}

// ---------------------------------------------------------------------------------------------
// Non-idempotent endpoints
// ---------------------------------------------------------------------------------------------

// foundations 5.10. The detection is from the capture and the samples alone, and every rule it
// fires downgrades what the run is allowed to do rather than what it is allowed to claim.
func TestANonIdempotentVectorIsDetectedAndItsSamplingIsCut(t *testing.T) {
	get := DetectNonIdempotent("GET", nil)
	if get.Detected || get.SamplesAllowed != TriageBaselineSamples {
		t.Errorf("a GET was called non-idempotent: %+v", get)
	}

	post := DetectNonIdempotent("POST", nil)
	if !post.Detected || post.SamplesAllowed != TriageNonIdempotentSamples {
		t.Errorf("a POST was not cut to two samples: %+v", post)
	}

	del := DetectNonIdempotent("DELETE", nil)
	if !del.NeverReplay {
		t.Error("a captured DELETE was not flagged NeverReplay; it is never replayed at all")
	}

	// A 201, or a Location on a non-redirect status, means the endpoint wrote something.
	e := cmpEndpoint{status: 201}
	created := DetectNonIdempotent("POST", e.samples("{}", "{}"))
	if !created.CreatesRow || !created.RequiresABA {
		t.Errorf("a 201 did not imply creates_row and the A/B/A requirement: %+v", created)
	}

	// A monotone counter in the response is LEARNED, not masked away: it is the thing that tells
	// us the endpoint writes.
	je := cmpEndpoint{media: "application/json"}
	counting := DetectNonIdempotent("GET", je.samples(
		`{"total":41,"name":"x"}`, `{"total":42,"name":"x"}`, `{"total":43,"name":"x"}`,
		`{"total":44,"name":"x"}`, `{"total":45,"name":"x"}`))
	if !counting.CreatesRow {
		t.Errorf("a strictly rising counter in the response did not imply creates_row: %+v", counting)
	}
}

// A differential on a mutating vector counts only when the two baselines bracketing it agree.
func TestADifferentialOnAMutatingVectorNeedsAgreeingBrackets(t *testing.T) {
	e, b := cmpTraceBaseline(t)

	before := e.one(cmpPage("<p>3 results</p>", "111111", ""), cmpEpoch)
	after := e.one(cmpPage("<p>3 results</p>", "222222", ""), cmpEpoch.Add(20*time.Second))
	if ok, why := CheckBracketingBaselines(b, before, after); !ok {
		t.Errorf("two brackets differing only inside the learned marking were rejected: %s", why)
	}

	moved := e.one(cmpPage("<p>9 results</p>", "222222", ""), cmpEpoch.Add(20*time.Second))
	if ok, _ := CheckBracketingBaselines(b, before, moved); ok {
		t.Error("brackets that disagree outside the mask were accepted, so a differential from that window would mean nothing")
	}

	failed := before
	failed.TransportErr = triage.TransportTimeout
	if ok, why := CheckBracketingBaselines(b, failed, after); ok || why == "" {
		t.Error("a bracket that never arrived was accepted as agreement")
	}
}

// ---------------------------------------------------------------------------------------------
// Header handling
// ---------------------------------------------------------------------------------------------

// A header the learner saw vary is excluded and SAID so; a header the seed list excludes but the
// learner found constant is reported with its value. Nothing vanishes, because a clean result with
// one interesting suppressed header has to be visible.
func TestHeaderExclusionsAreRecordedRatherThanSilent(t *testing.T) {
	page := cmpPage("<p>3 results</p>", "8f2a1c", "")
	e := cmpEndpoint{}
	samples := e.samples(page, page, page, page, page)
	for i := range samples {
		samples[i].RespHeaders = [][2]string{
			{"Date", "Fri, 18 Sep 2026 10:04:05 GMT"},
			{"X-Request-Id", fmt.Sprintf("req-%d", i)},
			{"Server", "nginx"},
			{"X-Powered-By", "Express"},
		}
	}
	b := BuildTriageBaseline(samples, nil)

	if !b.HeaderVolatile["x-request-id"] {
		t.Error("X-Request-Id varied across every sample and was not learned volatile")
	}
	if _, ok := b.SeedSuppressed["date"]; !ok {
		t.Error("Date was constant across the window and seed-excluded, so it must be reported as seed_suppressed with its value")
	}
	if _, ok := b.SeedSuppressed["x-request-id"]; ok {
		t.Error("a header the learner already found volatile was also reported as seed-suppressed, which double counts it")
	}

	probe := e.probe(page)
	probe.RespHeaders = [][2]string{
		{"Date", "Fri, 18 Sep 2026 10:04:09 GMT"},
		{"X-Request-Id", "req-999"},
		{"Server", "nginx"},
		{"X-Powered-By", "Express"},
		{"X-Debug-Token", "abc"},
	}
	res := CompareToBaseline(b, probe)
	ch := cmpChannel(res, ChanHeaders)
	if ch.Verdict != DiffDifferent || !strings.Contains(ch.Detail, "+x-debug-token") {
		t.Errorf("headers channel = %q %q, want different naming the new header: a header appearing is one of the cleanest protocol signals there is", ch.Verdict, ch.Detail)
	}
	if len(ch.Excluded) == 0 {
		t.Error("the headers channel excluded volatile headers and did not say which")
	}
}

// ---------------------------------------------------------------------------------------------
// Marker and echo removal
// ---------------------------------------------------------------------------------------------

// Without echo removal any reflecting parameter makes every probe differ from baseline and the
// whole differential collapses into noise. sqlmap does this with REFLECTED_VALUE_MARKER and it is
// one of the three things worth copying outright.
func TestTheEchoedPayloadAndTheMarkerComeOffBothSidesBeforeComparing(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	payload := "zqj4f3q0004hkx9m-and-a-distinctive-tail"
	probe := e.probe(cmpPage(`<p>3 results</p><p>You searched for: `+payload+`</p>`, "7a3f0c", ""))
	probe.Payload = triage.PayloadWire{Logical: []byte(payload), Wire: []byte(payload), Survived: triage.WireSurvivalIntact}

	res := CompareToBaseline(b, probe)
	if res.RemovedEchoBytes == 0 {
		t.Error("the reflected payload was not removed from either side")
	}
	if res.RemovedMarkerBytes == 0 {
		t.Error("the marker form was not removed; a marker in the body is not a differential, it is the probe looking at itself")
	}
	// What remains is the wrapper the echo sat in, which IS a difference, so the honest answer is
	// still a differential. The assertion that matters is that the payload bytes themselves were
	// not what produced it.
	if res.Verdict == DiffUnmeasured {
		t.Error("the comparison produced no verdict at all")
	}
}

// ---------------------------------------------------------------------------------------------
// The vocabulary guards
// ---------------------------------------------------------------------------------------------

// Every comparison outcome declared in the source has to be classified, or it defaults to
// something. This codebase has shipped the bug where it defaulted to clean.
func TestEveryDiffVerdictIsClassifiedAndNoUnknownOneCanReadAsSame(t *testing.T) {
	declared := constantsOfType(t, "DiffVerdict")
	if len(declared) == 0 {
		t.Fatal("parsed zero DiffVerdict constants out of the package source, so this test is checking nothing")
	}
	known := map[DiffVerdict]bool{
		DiffSame: true, DiffDifferent: true, DiffBorderline: true,
		DiffMaskedOnly: true, DiffReordered: true, DiffUnmeasured: true, DiffUnusable: true,
	}
	for name, val := range declared {
		v := DiffVerdict(val)
		if !known[v] {
			t.Errorf("constant %s = %q is declared but this test does not know it: classify it before using it, because an unclassified verdict falls through to a default and the default has been clean before", name, val)
		}
		if diffRank(v) == 0 && v != DiffUnmeasured {
			t.Errorf("%s has no rank, so it sorts below same when channels are combined", name)
		}
		if v.IsUnknown() && v.CountsAsSame() {
			t.Errorf("%s is unknown and counted as same", name)
		}
		if v.IsUnknown() && !v.TriageState().IsUnknown() {
			t.Errorf("%s is an unknown verdict that maps to the known state %q", name, v.TriageState())
		}
	}
	for _, s := range []DiffVerdict{"", "ok", "SAME", "same ", "no_change"} {
		if !s.IsUnknown() || s.CountsAsSame() {
			t.Errorf("unrecognised verdict %q did not fail closed", s)
		}
	}
	// Only same maps onto the clean state. Everything else is a positive or an unknown.
	for v := range known {
		if v.TriageState() == triage.StateClean && v != DiffSame {
			t.Errorf("%q maps to clean", v)
		}
	}
	if DiffDifferent.TriageState() != triage.StateSuspicious {
		t.Errorf("a differential maps to %q; it must map to suspicious, because only the owning class's own oracle can make it a finding", DiffDifferent.TriageState())
	}
}

// Every gate verdict has to say whether the byte oracles and the shape oracles are open, and an
// unrecognised one has to close both.
func TestEveryGateVerdictDeclaresWhatItOpensAndFailsClosed(t *testing.T) {
	declared := constantsOfType(t, "GateVerdict")
	if len(declared) == 0 {
		t.Fatal("parsed zero GateVerdict constants out of the package source")
	}
	known := map[GateVerdict]bool{
		GateUnmeasured: true, GateJudgeable: true, GateJudgeableShapeOnly: true,
		GateTooVolatile: true, GateStatusFlap: true, GateDrifted: true,
	}
	for name, val := range declared {
		g := GateVerdict(val)
		if !known[g] {
			t.Errorf("constant %s = %q is declared but this test does not know it: a gate verdict nobody classified still answers Reason() with no_baseline, which mislabels the reason the operator is shown", name, val)
		}
		if g.BytesJudgeable() && !g.ShapeJudgeable() {
			t.Errorf("%s opens the byte oracles and closes the shape ones, which cannot be right", name)
		}
		if !g.ShapeJudgeable() && g.Reason() == "" {
			t.Errorf("%s closes the oracles and names no reason, and an unknown with no reason is how a check that never ran becomes a clean", name)
		}
	}
	for _, g := range []GateVerdict{"", "fine", "judgeable "} {
		if g.BytesJudgeable() || g.ShapeJudgeable() {
			t.Errorf("unrecognised gate verdict %q opened an oracle", g)
		}
		if g.Reason() != "no_baseline" {
			t.Errorf("unrecognised gate verdict %q gave reason %q, want no_baseline", g, g.Reason())
		}
	}
	if GateJudgeableShapeOnly.BytesJudgeable() {
		t.Error("judgeable_shape_only opened the byte oracles, which is the whole thing it exists to close")
	}
}

// A baseline nobody built, and a baseline of one sample, are unknown. Sample 2 is the whole of the
// noise model; without it there is no differential to be had.
func TestABaselineWithoutADifferentialIsUnmeasuredRatherThanStable(t *testing.T) {
	empty := BuildTriageBaseline(nil, nil)
	if empty.Gate != GateUnmeasured || empty.Model.Stable {
		t.Errorf("an empty baseline reported gate %q stable %v", empty.Gate, empty.Model.Stable)
	}
	if empty.GateDetail == "" {
		t.Error("an unmeasured baseline named no reason")
	}

	e := cmpEndpoint{}
	one := BuildTriageBaseline(e.samples(cmpPage("<p>3 results</p>", "8f2a1c", "")), nil)
	if one.Gate != GateUnmeasured || one.GateDetail != "insufficient_baseline_samples" {
		t.Errorf("a one-sample baseline reported gate %q (%s)", one.Gate, one.GateDetail)
	}
	res := CompareToBaseline(one, e.probe("anything at all"))
	if res.CountsAsClean() || res.Verdict != DiffUnusable {
		t.Errorf("a comparison against a one-sample baseline gave %q, clean %v", res.Verdict, res.CountsAsClean())
	}
}

// A transport refusal is could-not-send, never a quiet response. The measured mitigation for the
// cookie-mangling trap depends on this: a NUL byte in a header value is rejected by net/http with
// "invalid header field value", and that must arrive here as an unknown rather than as a defended
// application.
func TestATransportRefusalIsCouldNotSendAndNotAQuietResponse(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	probe := e.probe("")
	probe.TransportErr = triage.TransportInvalidHeader
	probe.TransportMsg = "net/http: invalid header field value"

	res := CompareToBaseline(b, probe)
	if res.Verdict != DiffUnusable {
		t.Fatalf("verdict = %q, want unusable", res.Verdict)
	}
	if !strings.Contains(res.Reason, string(triage.TransportInvalidHeader)) {
		t.Errorf("reason = %q, want it to name the transport error", res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("a request that never reached the application counted as clean")
	}
}

// ---------------------------------------------------------------------------------------------
// The metric itself
// ---------------------------------------------------------------------------------------------

// The threshold is measured per endpoint and is ORDER-INDEPENDENT. sqlmap latches kb.matchRatio
// from whichever response arrived first, so the same probe set in a different order can give a
// different verdict on the same endpoint.
func TestTheThresholdIsMeasuredFromTheBaselineAndNotLatchedFromTheFirstResponse(t *testing.T) {
	e := cmpEndpoint{}
	bodies := []string{
		cmpPage("<p>3 results</p>", cmpTraceIDs[0], ""),
		cmpPage("<p>3 results</p>", cmpTraceIDs[1], ""),
		cmpPage("<p>3 results</p>", cmpTraceIDs[2], ""),
		cmpPage("<p>3 results</p>", cmpTraceIDs[3], ""),
		cmpPage("<p>3 results</p>", cmpTraceIDs[4], ""),
	}
	forward := BuildTriageBaseline(e.samples(bodies...), nil)
	reversed := BuildTriageBaseline(e.samples(bodies[4], bodies[3], bodies[2], bodies[1], bodies[0]), nil)

	if forward.Threshold != reversed.Threshold || forward.Model.RFloor != reversed.Model.RFloor {
		t.Errorf("threshold depended on sample order: %.6f/%.6f versus %.6f/%.6f",
			forward.Threshold, forward.Model.RFloor, reversed.Threshold, reversed.Model.RFloor)
	}
	if forward.Threshold < triageRatioLowerBound || forward.Threshold > triageRatioUpperBound {
		t.Errorf("threshold %.6f escaped the clamp", forward.Threshold)
	}
}

// The bag ratio alone is blind to order and the shingle ratio alone is blind to composition. The
// verdict uses the minimum, so neither blindness survives.
func TestTheTwoRatiosDisagreeOnAnAnagramAndThatIsThePoint(t *testing.T) {
	a := []byte("the quick brown fox jumps over the lazy dog, twice over and once more")
	b := []byte("erom ecno dna revo eciwt ,god yzal eht revo spmuj xof nworb kciuq eht")
	if got := triageBagRatio(a, b); got < 1.0 {
		t.Errorf("bag ratio on an exact anagram = %.6f, want 1.0", got)
	}
	if got := triageShingleRatio(a, b); got >= 1.0 {
		t.Errorf("shingle ratio on a reversal = %.6f, want below 1.0", got)
	}
	if got := triageShingleRatio(a, a); got != 1.0 {
		t.Errorf("shingle ratio against itself = %.6f, want 1.0", got)
	}
	if got := triageBagRatio(nil, nil); got != 1.0 {
		t.Errorf("bag ratio of two empty bodies = %.6f, want 1.0", got)
	}
	if got := triageBagRatio(a, nil); got != 0 {
		t.Errorf("bag ratio against an empty body = %.6f, want 0", got)
	}
}

// NDJSON, a root scalar and a root array are all legal JSON documents, and a content type that
// lies about any of them must not stop the shape model.
func TestTheShapeModelParsesWhatTheContentTypeDenies(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		parsed  bool
		records int
	}{
		{"an object served as text/html", `{"a":1}`, true, 0},
		{"a root array", `[1,2,3]`, true, 0},
		{"a root scalar", `42`, true, 0},
		{"NDJSON", "{\"a\":1}\n{\"a\":2}\n{\"a\":3}", true, 3},
		{"not JSON at all", `<html><body>hello</body></html>`, false, 0},
		{"JSON with a trailing tail", `{"a":1} <html>`, false, 0},
	}
	for _, tc := range cases {
		p := triageProjectJSON([]byte(tc.body))
		if p.Parsed != tc.parsed {
			t.Errorf("%s: parsed = %v, want %v", tc.name, p.Parsed, tc.parsed)
		}
		if p.Records != tc.records {
			t.Errorf("%s: records = %d, want %d", tc.name, p.Records, tc.records)
		}
	}

	// Duplicate keys are legal and parsers keep the last, so the document has lost information and
	// any value-level verdict on it is low confidence.
	dup := triageProjectJSON([]byte(`{"a":1,"a":2}`))
	if !dup.DupKeys {
		t.Error("duplicate keys within one object were not detected")
	}
}

// GraphQL answers 200 for a syntax error and 200 for success, so the status is useless and a byte
// ratio is dominated by the payload. The signal lives entirely in the shape.
func TestGraphQLFactsAreCapturedAsNamedFieldsAndNotJustPointers(t *testing.T) {
	e := cmpEndpoint{media: "application/json"}
	ok := `{"data":{"viewer":{"id":"u-1","name":"a name long enough to matter"}},"errors":null}`
	b := cmpBaselineFor(t, e, ok, ok, ok, ok, ok)

	failed := `{"data":null,"errors":[{"message":"Syntax Error: Expected Name, found <EOF> at 17","extensions":{"code":"GRAPHQL_PARSE_FAILED"}}]}`
	res := CompareToBaseline(b, e.probe(failed))
	if res.Verdict != DiffDifferent {
		t.Fatalf("verdict = %q (%s), want different", res.Verdict, res.Reason)
	}
	if len(res.Shape.GQLChanged) == 0 {
		t.Errorf("no GraphQL fact changed, but /data went null and an error appeared: %+v", res.Shape)
	}

	// The message is CLASSIFIED, not compared raw, because GraphQL messages embed positions.
	one := triageClassifyMessage("Syntax Error: Expected Name, found <EOF> at 17")
	two := triageClassifyMessage("Syntax Error: Expected Name, found <EOF> at 249")
	if one != two {
		t.Errorf("two instances of the same error classified differently: %q versus %q", one, two)
	}
	if triageClassifyMessage("Unknown argument") == one {
		t.Error("two different errors classified the same")
	}
}

// ---------------------------------------------------------------------------------------------
// T19. A payload that never reached the wire
// ---------------------------------------------------------------------------------------------

// T19: Delivered() is a TRANSPORT fact. It answers "the request went out and a response came
// back". It says nothing about whether the bytes the class asked for were still inside that
// request when it left, and those are different questions with different failure modes.
//
// The measured one: Go's net/http Cookie writer silently drops the semicolon, the double quote
// and the backslash from a cookie value. Those are the SQL injection probe characters. A probe
// carrying a quoted tautology in a cookie is delivered perfectly, arrives carrying something
// harmless or nothing at all, produces a response byte-identical to the baseline because no
// payload was ever tested, and the comparator has no difference to report. Recording that as
// clean is the exact false negative WireSurvival was added for: the class never tested anything,
// and the operator never points the scanner here again.
//
// The zero value is UNKNOWN and must be treated as unknown, not as intact, because a probe that
// never measured its own survival is indistinguishable from one that was mangled.
func TestAProbeWhosePayloadNeverReachedTheWireIsNeverClean(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	identical := cmpPage("<p>3 results</p>", "7a3f0c", "")

	for _, tc := range []struct {
		name string
		wire triage.PayloadWire
		want string
	}{
		{
			name: "dropped",
			wire: triage.PayloadWire{
				Logical: []byte(`1' OR '1'='1`), Wire: []byte(`1' OR '1'='1`),
				Container: []byte("sid=1 OR 1=1"), ContainerName: "Cookie",
				Survived: triage.WireSurvivalDropped, AlteredBy: "net/http.Cookie sanitizer",
			},
			want: "dropped",
		},
		{
			name: "refused",
			wire: triage.PayloadWire{Logical: []byte("a\x00b"), Survived: triage.WireSurvivalRefused},
			want: "refused",
		},
		{
			name: "altered",
			wire: triage.PayloadWire{
				Logical: []byte(`1';--`), Wire: []byte("1--"),
				Survived: triage.WireSurvivalAltered, AlteredBy: "net/http.Cookie sanitizer",
			},
			want: "altered",
		},
		{
			name: "never measured, the zero value",
			wire: triage.PayloadWire{Logical: []byte(`1' OR '1'='1`)},
			want: "unknown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := e.probe(identical)
			probe.Payload = tc.wire

			res := CompareToBaseline(b, probe)

			if res.Verdict == DiffSame {
				t.Errorf("verdict = same (%s): the response is identical because no payload was ever tested, not because the application defended", res.Reason)
			}
			if res.CountsAsClean() {
				t.Error("a probe whose payload never reached the wire counted as clean, which is the false negative WireSurvival exists to prevent")
			}
			if res.MaxState != triage.StateCannotDetermine {
				t.Errorf("MaxState = %q, want cannot_determine: the owning class may claim nothing from a comparison of a payload that was never sent", res.MaxState)
			}
			if res.State() != triage.StateCannotDetermine {
				t.Errorf("State() = %q, want cannot_determine", res.State())
			}
			if !res.PayloadUnproven {
				t.Error("PayloadUnproven was false")
			}
			if !strings.Contains(res.Reason, tc.want) {
				t.Errorf("reason = %q, want it to name what happened (%q)", res.Reason, tc.want)
			}
		})
	}

	// The control. A payload that IS proven to have reached the wire, verbatim or through a
	// declared reversible encoder, still reads same and still counts as clean. Without this the
	// fix above would be indistinguishable from disabling clean altogether.
	for _, survived := range []triage.WireSurvival{triage.WireSurvivalIntact, triage.WireSurvivalEncoded} {
		probe := e.probe(identical)
		probe.Payload = triage.PayloadWire{Logical: []byte("'"), Wire: []byte("'"), Container: []byte("q='"), Survived: survived}
		res := CompareToBaseline(b, probe)
		if res.Verdict != DiffSame || !res.CountsAsClean() {
			t.Errorf("survived=%q: verdict = %q (%s), clean = %v; a proven payload against a healthy baseline must still be able to read clean",
				survived, res.Verdict, res.Reason, res.CountsAsClean())
		}
		if res.PayloadUnproven {
			t.Errorf("survived=%q was reported unproven", survived)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// T20. The mask has a length ceiling
// ---------------------------------------------------------------------------------------------

// T20: the novelty test that guards a masked region is ALPHABET-ONLY. It asks whether the probe
// put a byte in the hole that the region never held across the baseline. It never asks how many.
//
// A six-byte hexadecimal trace id therefore attests every hexadecimal digit, and from then on
// the region will absorb any quantity of hexadecimal without a word. The consequence is a
// boolean oracle whose rendered output happens to be in-alphabet, a row count inside the masked
// span for instance, disappearing at any size. That is a false negative in the single most
// important SQLi signal, and unlike a missed byte it does not get smaller as the payload grows.
//
// The rule: the probe's content for a region must lie within triageMaskLengthRatio of the length
// range that region was OBSERVED to take. The alphabet is attested by measurement; the capacity
// is not, and capacity is what carries the signal.
func TestAMaskedRegionThatGrowsPastItsAttestedLengthIsNotClean(t *testing.T) {
	e, b := cmpTraceBaseline(t)

	// Every baseline id is six bytes. Twenty-four bytes of in-alphabet hexadecimal is four times
	// the widest thing this region was ever seen to hold, and the alphabet test says nothing.
	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "0123ab0123ab0123ab0123ab", "")))
	if res.Verdict == DiffSame {
		t.Errorf("verdict = same (%s): a six-byte region absorbed twenty-four bytes and the comparator reported no change", res.Reason)
	}
	if res.Verdict != DiffMaskedOnly {
		t.Errorf("verdict = %q (%s), want masked_only: the change is confined to a learned region, so it is reportable at reduced confidence and is not a finding", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("a masked region that quadrupled in size counted as clean")
	}
	var flagged bool
	for _, h := range res.MaskedHits {
		if h.LenUnattested {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("no masked hit was marked LenUnattested: %+v", res.MaskedHits)
	}

	// The two controls the ceiling must not break.
	//
	// A fresh in-alphabet id of the SAME length is fully attested, in alphabet and in capacity,
	// and stays clean. T2c's longer id is 15 bytes against a 6-byte baseline, a ratio of 2.5,
	// which is the widest legitimate re-render in this corpus and is what puts the ceiling at 3.
	for _, id := range []string{"7a3f0c", "abc123def456789"} {
		ctl := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", id, "")))
		if ctl.Verdict != DiffSame || !ctl.CountsAsClean() {
			t.Errorf("id %q (%d bytes): verdict = %q (%s), clean = %v; want same and clean",
				id, len(id), ctl.Verdict, ctl.Reason, ctl.CountsAsClean())
		}
	}
}

// ---------------------------------------------------------------------------------------------
// T21. A masked region going empty
// ---------------------------------------------------------------------------------------------

// T21: novelty is tested on the bytes that are PRESENT. Absence has no bytes, so a region that
// goes empty passes the novelty test trivially, the normalised bodies still agree because the
// mask removed the region on one side and there was nothing to remove on the other, and the
// comparison reads same.
//
// A row count going from 12 to 0 inside a masked span is exactly the boolean signal this layer
// exists to catch, and it is the cleanest one a rendered page ever offers. Disappearance is a
// change.
func TestAMaskedRegionGoingEmptyIsAChange(t *testing.T) {
	e, b := cmpTraceBaseline(t)

	res := CompareToBaseline(b, e.probe(cmpPage("<p>3 results</p>", "", "")))
	if res.Verdict == DiffSame {
		t.Errorf("verdict = same (%s): the masked region vanished and the comparator reported no change", res.Reason)
	}
	if res.Verdict != DiffMaskedOnly {
		t.Errorf("verdict = %q (%s), want masked_only", res.Verdict, res.Reason)
	}
	if res.CountsAsClean() {
		t.Error("a masked region that went empty counted as clean")
	}
	var flagged bool
	for _, h := range res.MaskedHits {
		if h.Probe == "" && h.LenUnattested {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("the emptied region was not flagged: %+v", res.MaskedHits)
	}
}

// ---------------------------------------------------------------------------------------------
// T22. Every unproven survival sets the flag, whichever branch returns first
// ---------------------------------------------------------------------------------------------

// T22: PayloadUnproven must be a property of the PROBE, not of the route the comparator happened
// to take through CompareToBaseline.
//
// The measured defect: a refused payload is refused BY THE TRANSPORT. "net/http: invalid header
// field value" on a NUL byte is raised at send time, so the same probe that records
// WireSurvivalRefused also records TransportInvalidHeader, and the !probe.Delivered() branch at
// the top of the comparator returns before the fidelity block ever runs. The result was verdict
// unusable with reason transport_invalid_header_value and PayloadUnproven FALSE. T19 did not
// catch it because every fixture there is Delivered(): it exercises the fidelity block and not
// the branch that returns ahead of it.
//
// Why a false flag matters more than a right reason: the store's one definition of unproven
// (triageUnprovenFidelity) is survived NOT IN ('intact','encoded'), which counts refused. A
// classifier keying on res.PayloadUnproven therefore disagrees with the store about the very
// same probe. The reason string is the more specific of the two and is kept; the flag is
// additive.
func TestEveryUnprovenSurvivalSetsTheFlagWhicheverBranchReturnsFirst(t *testing.T) {
	e, b := cmpTraceBaseline(t)
	identical := cmpPage("<p>3 results</p>", "7a3f0c", "")

	for _, tc := range []struct {
		name      string
		transport triage.TransportErrKind
		wire      triage.PayloadWire
		wantWhy   string
	}{
		{
			name: "dropped",
			wire: triage.PayloadWire{
				Logical: []byte(`1' OR '1'='1`), Wire: []byte(`1' OR '1'='1`),
				Container: []byte("sid=1 OR 1=1"), ContainerName: "Cookie",
				Survived: triage.WireSurvivalDropped, AlteredBy: "net/http.Cookie sanitizer",
			},
			wantWhy: "dropped",
		},
		{
			name: "altered",
			wire: triage.PayloadWire{
				Logical: []byte(`1';--`), Wire: []byte("1--"),
				Survived: triage.WireSurvivalAltered, AlteredBy: "net/http.Cookie sanitizer",
			},
			wantWhy: "altered",
		},
		{
			// THE ONE THAT WAS FALSE. A refused payload never left, so the transport error is
			// set too and the early return fires.
			name:      "refused, and therefore not delivered",
			transport: triage.TransportInvalidHeader,
			wire: triage.PayloadWire{
				Logical: []byte("a\x00b"), ContainerName: "Cookie",
				Survived: triage.WireSurvivalRefused, AlteredBy: "net/http header writer",
			},
			wantWhy: "refused",
		},
		{
			name:    "never measured, the zero value",
			wire:    triage.PayloadWire{Logical: []byte(`1' OR '1'='1`)},
			wantWhy: "unknown",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := e.probe(identical)
			probe.TransportErr = tc.transport
			probe.Payload = tc.wire

			res := CompareToBaseline(b, probe)

			if !res.PayloadUnproven {
				t.Errorf("PayloadUnproven = false (verdict %q, reason %q): a classifier keying on this flag alone misses %s, and the store counts it as unproven",
					res.Verdict, res.Reason, tc.name)
			}
			if res.PayloadUnprovenWhy == "" {
				t.Error("PayloadUnprovenWhy was empty: an unproven probe with no reason is a cannot_determine with no reason")
			}
			if !strings.Contains(res.PayloadUnprovenWhy, tc.wantWhy) {
				t.Errorf("PayloadUnprovenWhy = %q, want it to name what happened (%q)", res.PayloadUnprovenWhy, tc.wantWhy)
			}
			if res.CountsAsClean() {
				t.Error("an unproven probe counted as clean")
			}
			if res.MaxState != triage.StateCannotDetermine {
				t.Errorf("MaxState = %q, want cannot_determine", res.MaxState)
			}
		})
	}

	// The transport reason is the more specific of the two and survives. Setting the flag must
	// not overwrite it with the generic fidelity wording.
	t.Run("the transport reason is kept", func(t *testing.T) {
		probe := e.probe(identical)
		probe.TransportErr = triage.TransportInvalidHeader
		probe.Payload = triage.PayloadWire{Logical: []byte("a\x00b"), Survived: triage.WireSurvivalRefused}

		res := CompareToBaseline(b, probe)

		if res.Reason != "transport_invalid_header_value" {
			t.Errorf("reason = %q, want transport_invalid_header_value: the transport names the more specific failure and the flag is additive, not a replacement", res.Reason)
		}
		if res.Verdict != DiffUnusable {
			t.Errorf("verdict = %q, want unusable", res.Verdict)
		}
	})

	// THE PREDICATE CONTROL. Without this the fix above is indistinguishable from setting the
	// flag unconditionally, which would end clean for every probe in the suite.
	t.Run("a proven intact payload is still same and still clean", func(t *testing.T) {
		probe := e.probe(identical)
		if probe.Payload.Survived != triage.WireSurvivalIntact {
			t.Fatalf("fixture survival = %q, want intact", probe.Payload.Survived)
		}

		res := CompareToBaseline(b, probe)

		if res.PayloadUnproven {
			t.Errorf("PayloadUnproven = true on an intact payload (%s): the flag is a constant, not a predicate", res.PayloadUnprovenWhy)
		}
		if res.Verdict != DiffSame {
			t.Errorf("verdict = %q (%s), want same", res.Verdict, res.Reason)
		}
		if !res.CountsAsClean() {
			t.Error("a proven payload against a healthy baseline could not read clean")
		}
	})
}
