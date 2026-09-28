package triageclasses

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

const desTestMarker triage.Marker = "zqj0000000000dsr"

// desObs builds one of this class's own observations. The PAYLOAD RECORD IS THE IMPORTANT PART:
// the length oracle compares the number the application named against the length of what was
// actually sent, and it reads that length from PayloadWire rather than from a constant, so a test
// that left the payload record empty would be exercising a path the real runner never takes.
func desObs(id triage.ProbeID, sent, body string) faOwnObs {
	return faOwnObs{
		ProbeID: id, Ordinal: 24, Marker: desTestMarker,
		Obs: triage.Observation{
			Status: 200, Body: []byte(body),
			Payload: triage.PayloadWire{
				Logical:  []byte(sent),
				Wire:     []byte(sent),
				Survived: triage.WireSurvivalIntact,
			},
		},
	}
}

func desLenBody(n int) string {
	return "<b>Warning</b>: unserialize(): Error at offset 0 of " + itoa(n) + " bytes in /var/www/x.php"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestTheDeserClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassDeser)
	if !ok {
		t.Fatal("the deser classifier did not register itself")
	}
	if c.ID() != triage.ClassDeser {
		t.Fatalf("registered under %s but reports %s", triage.ClassDeser, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, v := range triage.CheckPayloadIsolation(triage.RegisteredClassifiers()).Violations {
		t.Errorf("ISOLATION: %s", v)
	}
}

// THE MEASURED LENGTHS. Every number in this test was produced by php:8.3-cli-alpine against the
// exact bytes this class declares, and the declared payloads must keep those lengths or the
// verified measurements stop describing the shipped probes.
func TestTheLengthPayloadsAreTheMeasuredLengths(t *testing.T) {
	for _, c := range []struct {
		text string
		want int
	}{
		{desP2AText, 39},
		{desP2BText, 32},
		{desNC1Text, 35},
	} {
		if len(c.text) != c.want {
			t.Errorf("%q is %d bytes, and the verified php measurement was taken at %d. Either the payload or the measurement is now fiction",
				c.text, len(c.text), c.want)
		}
	}
	if desP2AText == desP2BText || desP2AText == desNC1Text || desP2BText == desNC1Text {
		t.Error("two of the three length arms carry the same bytes, so the pair cannot discriminate")
	}
	// Every byte must be one no encoder in this layer escapes, so the length PHP counts is the
	// length in this file rather than the length after a round trip through a decoder.
	for _, s := range []string{desP2AText, desP2BText, desNC1Text} {
		for i := 0; i < len(s); i++ {
			b := s[i]
			ok := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-'
			if !ok {
				t.Errorf("%q byte %d (%q) is outside [a-z0-9-], so an encoder may rewrite it and the length arithmetic stops being inspectable", s, i, string(b))
			}
		}
	}
}

// THE LENGTH ORACLE, AND ITS FOUR REFUSALS. Only the last row is a finding, and each of the other
// three is a distinct thing this oracle must decline to over-read.
func TestTheLengthOracleIsThePairAndNotTheNumber(t *testing.T) {
	for _, c := range []struct {
		name   string
		obs    []faOwnObs
		want   desLenVerdict
		offset int
		exact  bool
	}{
		{
			name: "three points on one line with no wrapper",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, desLenBody(39)),
				desObs(desP2B, desP2BText, desLenBody(32)),
				desObs(desNC1, desNC1Text, desLenBody(35)),
			},
			want: desLenComputed, offset: 0, exact: true,
		},
		{
			name: "a constant wrapper around the value",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, desLenBody(39+11)),
				desObs(desP2B, desP2BText, desLenBody(32+11)),
			},
			want: desLenComputed, offset: 11, exact: false,
		},
		{
			name: "a static error page naming one number",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, desLenBody(39)),
				desObs(desP2B, desP2BText, desLenBody(39)),
			},
			want: desLenStatic,
		},
		{
			name: "numbers that move but do not track our lengths",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, desLenBody(39)),
				desObs(desP2B, desP2BText, desLenBody(30)),
			},
			want: desLenMismatch,
		},
		{
			name: "only one arm answered",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, desLenBody(39)),
				desObs(desP2B, desP2BText, "<p>nothing here</p>"),
			},
			want: desLenOnePoint, offset: 0, exact: true,
		},
		{
			name: "nothing answered",
			obs: []faOwnObs{
				desObs(desP2A, desP2AText, "<p>hello</p>"),
				desObs(desP2B, desP2BText, "<p>hello</p>"),
			},
			want: desLenAbsent,
		},
	} {
		got := desReadLengths(c.obs)
		if got.verdict != c.want {
			t.Errorf("%s: verdict %q, want %q (points %v)", c.name, got.verdict, c.want, desRenderLengthPoints(got))
			continue
		}
		if c.want == desLenComputed || c.want == desLenOnePoint {
			if got.offset != c.offset || got.exact != c.exact {
				t.Errorf("%s: offset %d exact %v, want %d %v", c.name, got.offset, got.exact, c.offset, c.exact)
			}
		}
	}
}

// The oracle compares against the RECORDED payload and not against the constants in the source.
// A WAF that truncated one payload changes the expected number with it, and a class comparing to
// the literal 39 would read a mangled probe as a miss and eventually as a clean.
func TestTheLengthOracleReadsTheRecordedPayloadAndNotTheConstant(t *testing.T) {
	truncatedA := desObs(desP2A, desP2AText[:20], desLenBody(20))
	truncatedB := desObs(desP2B, desP2BText[:10], desLenBody(10))
	got := desReadLengths([]faOwnObs{truncatedA, truncatedB})
	if got.verdict != desLenComputed {
		t.Errorf("two truncated payloads each naming their TRUNCATED length were not read as a computation: %q. The oracle is reading a constant somewhere", got.verdict)
	}
}

// DES-P1's serialized object declares its own class-name length. The number in the payload is
// arithmetic over the RENDERED name, and the declared bytes carry the eight-character placeholder,
// so the source looks wrong and the wire is right. A change to the prefix without a change to the
// number produces a payload PHP rejects at the length check, which fires the LENGTH oracle instead
// of this one and looks like a working probe.
func TestTheIncompleteClassPayloadDeclaresTheRenderedNameLength(t *testing.T) {
	var p1 string
	for _, p := range (deserClassifier{}).Probes() {
		if p.ID == desP1 {
			p1 = string(p.Logical)
		}
	}
	if p1 == "" {
		t.Fatal("DES-P1 is not declared")
	}
	rendered := strings.Replace(p1, triage.MarkerPlaceholder, string(desTestMarker), 1)
	want := `O:22:"` + desClassPrefix + string(desTestMarker) + `":0:{}`
	if rendered != want {
		t.Fatalf("DES-P1 renders as\n  %s\nwant\n  %s", rendered, want)
	}
	nameLen := len(desClassPrefix) + triage.MarkerLen
	if nameLen != 22 {
		t.Errorf("the rendered class name is %d bytes and the payload declares 22. PHP checks that number and rejects the object, so the probe would test the length oracle instead of this one", nameLen)
	}
}

// THE ANSWER IS NEVER IN THE REQUEST, and each of these was verified against the real runtime
// before it was written down. The test asserts the property the verification established, so a
// future edit to a payload cannot quietly break the rank-1 claim.
func TestNoTransformationOracleCanBeProducedByAnEcho(t *testing.T) {
	probes := map[triage.ProbeID][]byte{}
	for _, p := range (deserClassifier{}).Probes() {
		probes[p.ID] = p.Logical
	}
	for _, c := range []struct {
		id     triage.ProbeID
		answer string
	}{
		{desJ1, desJ1Echo},
		{desJ2, desJ2Echo},
		{desY1, desY1Repr},
		{desY2, desY2Echo},
	} {
		payload := string(probes[c.id])
		if strings.Contains(strings.ToUpper(payload), strings.ToUpper(c.answer)) {
			t.Errorf("%s's answer %q is present in its own payload %q, so a plain echo produces it and the oracle is rank 7 and not rank 1",
				c.id, c.answer, payload)
		}
		// And it must not be there after a base64 decode either, which is the form the runtime
		// actually reads.
		if raw, ok := desDecodeBase64(payload); ok {
			if strings.Contains(strings.ToUpper(string(raw)), strings.ToUpper(c.answer)) {
				t.Errorf("%s's answer %q is present in the DECODED payload, so the runtime is echoing bytes we sent rather than computing anything", c.id, c.answer)
			}
		}
	}
	// __PHP_Incomplete_Class is the same argument for DES-P1.
	if strings.Contains(string(probes[desP1]), "__PHP_Incomplete_Class") {
		t.Error("DES-P1 carries the string its oracle looks for, so an echo would fire it")
	}
}

// The pickle payload really does round-trip to the repr the oracle looks for. The base64 is
// checked for shape here; the semantic round trip was verified on CPython 3.13.12 and its output
// is quoted in the class file.
func TestThePicklePayloadIsWellFormedBase64OfAProtocolFourPickle(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(desY1Text)
	if err != nil {
		t.Fatalf("DES-Y1 is not valid base64: %v", err)
	}
	if len(raw) < 3 || raw[0] != 0x80 || raw[1] != 0x04 {
		t.Fatalf("DES-Y1 does not begin with the pickle PROTO 4 opcode: % x", raw[:3])
	}
	for _, opcode := range []byte{'c', 'R'} { // GLOBAL and REDUCE, the two that execute
		if idx := indexByte(raw, opcode); idx >= 0 && opcode == 'R' {
			t.Errorf("DES-Y1 contains the REDUCE opcode at offset %d, which CALLS something. The payload must build a list of two strings and nothing else", idx)
		}
	}
	for _, half := range []string{"zqdesery", "1pickl3z"} {
		if !strings.Contains(string(raw), half) {
			t.Errorf("the decoded pickle does not carry the half %q the repr is built from", half)
		}
		if strings.Contains(desY1Text, half) {
			t.Errorf("the half %q is visible in the BASE64 TEXT, so the joined repr could be produced by an echo of the request", half)
		}
	}
	if strings.Contains(string(raw), desY1Repr) {
		t.Error("the joined repr is present in the raw pickle, so it is not a value Python had to compute")
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// THE JAVA PAIR, and the same three-way shape as the length pair.
func TestTheJavaArmNeedsBothProbesToNameTheirOwnBytes(t *testing.T) {
	for _, c := range []struct {
		name       string
		obs        []faOwnObs
		wantState  triage.TriageState
		wantFired  bool
		wantDetail string
	}{
		{
			name: "each names its own",
			obs: []faOwnObs{
				desObs(desJ1, desJ1Text, "StreamCorruptedException: invalid stream header: "+desJ1Echo),
				desObs(desJ2, desJ2Text, "StreamCorruptedException: invalid stream header: "+desJ2Echo),
			},
			wantState: triage.StateFinding, wantFired: true,
		},
		{
			name: "a page reciting both header examples",
			obs: []faOwnObs{
				desObs(desJ1, desJ1Text, "examples: "+desJ1Echo+" and "+desJ2Echo),
				desObs(desJ2, desJ2Text, "examples: "+desJ1Echo+" and "+desJ2Echo),
			},
			wantState: triage.StateCannotDetermine, wantFired: true,
		},
		{
			name: "only one answered",
			obs: []faOwnObs{
				desObs(desJ1, desJ1Text, "invalid stream header: "+desJ1Echo),
				desObs(desJ2, desJ2Text, "<p>nothing</p>"),
			},
			wantState: triage.StateSuspicious, wantFired: true,
		},
		{
			name: "neither answered",
			obs: []faOwnObs{
				desObs(desJ1, desJ1Text, "<p>nothing</p>"),
				desObs(desJ2, desJ2Text, "<p>nothing</p>"),
			},
			wantFired: false,
		},
		{
			name: "the exception with no hex at all",
			obs: []faOwnObs{
				desObs(desJ1, desJ1Text, "java.io.StreamCorruptedException"),
				desObs(desJ2, desJ2Text, "java.io.StreamCorruptedException"),
			},
			wantFired: false,
		},
	} {
		state, _, _, _, fired := desJavaArm(c.obs, map[string]any{})
		if fired != c.wantFired {
			t.Errorf("%s: fired=%v want %v", c.name, fired, c.wantFired)
			continue
		}
		if fired && state != c.wantState {
			t.Errorf("%s: state %q want %q", c.name, state, c.wantState)
		}
	}
}

// DES-R0 IS ZERO REQUESTS AND IT IS ALSO WHERE THE FALSE POSITIVES LIVE. The two-character base64
// prefixes are short enough to appear in ordinary text, so every rule requires the DECODE to match
// and the exclusions run first.
func TestTheFormatTableBelievesTheDecodeAndNotThePrefix(t *testing.T) {
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	for _, c := range []struct {
		name string
		slot triage.Slot
		want desFormat
	}{
		{"java serialized", triage.Slot{Value: b64([]byte{0xAC, 0xED, 0x00, 0x05, 0x74, 0x00, 0x02, 0x68, 0x69})}, desFormatJava},
		{"ruby marshal", triage.Slot{Value: b64([]byte{0x04, 0x08, 0x49, 0x22, 0x0a, 0x68, 0x65, 0x6c, 0x6c, 0x6f})}, desFormatRuby},
		{"python pickle", triage.Slot{Value: b64([]byte{0x80, 0x04, 0x95, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})}, desFormatPickle},
		{"php serialized", triage.Slot{Value: `O:8:"stdClass":0:{}`}, desFormatPHP},
		{"php array", triage.Slot{Value: `a:1:{i:0;s:1:"x";}`}, desFormatPHP},
		{"node serialize", triage.Slot{Value: `{"rce":"_$$ND_FUNC$$_function(){}"}`}, desFormatNodeSer},
		{"dotnet binaryformatter", triage.Slot{Value: b64([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00})}, desFormatBinFmt},
		{"view state by name", triage.Slot{Name: "__VIEWSTATE", Value: b64([]byte{0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})}, desFormatViewState},

		{"a jwt", triage.Slot{Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"}, desFormatNone},
		{"a jwt by wrapper", triage.Slot{Value: "anything-at-all-here", Wrapper: triage.WrapJWT}, desFormatNone},
		{"base64 of json", triage.Slot{Value: b64([]byte(`{"user":"alice","role":"viewer"}`))}, desFormatNone},
		{"base64 of ordinary text", triage.Slot{Value: b64([]byte("the quick brown fox jumps over it"))}, desFormatNone},
		{"a uuid", triage.Slot{Value: "550e8400-e29b-41d4-a716-446655440000"}, desFormatNone},
		{"an integer", triage.Slot{Value: "1024"}, desFormatNone},
		{"empty", triage.Slot{Value: ""}, desFormatNone},
		{"prose that starts like base64", triage.Slot{Value: "rObertoIsNotASerializedObject"}, desFormatNone},
	} {
		got, why := desRecognise(c.slot)
		if got != c.want {
			t.Errorf("%s: recognised as %q, want %q (%s)", c.name, got, c.want, why)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s: recognition returned no reason", c.name)
		}
	}
}

// THE CLEAN GATE. Each arm answers for a different runtime and none answers for another, so a
// reduced-tier run that bought only the PHP arm must not produce a green tick over a JVM and a
// Python process nobody looked at.
func TestCleanRequiresEveryArmAndNotOnlyTheCheapOnes(t *testing.T) {
	phpOnly := []faOwnObs{
		desObs(desP2A, desP2AText, "<p>nothing</p>"),
		desObs(desP2B, desP2BText, "<p>nothing</p>"),
		desObs(desNC1, desNC1Text, "<p>nothing</p>"),
	}
	missing := desArmsNotRun(phpOnly)
	if len(missing) == 0 {
		t.Fatal("a run that sent only the PHP arm reported no missing arms, so it would be allowed to say clean about a JVM and a Python process it never touched")
	}
	for _, want := range []string{string(desJ1), string(desJ2), string(desY1)} {
		found := false
		for _, m := range missing {
			if m == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not named among the arms that did not run: %v", want, missing)
		}
	}
	all := append(phpOnly,
		desObs(desJ1, desJ1Text, "<p>nothing</p>"),
		desObs(desJ2, desJ2Text, "<p>nothing</p>"),
		desObs(desY1, desY1Text, "<p>nothing</p>"),
	)
	if n := len(desArmsNotRun(all)); n != 0 {
		t.Errorf("with every arm on the wire, %d were still reported missing: %v", n, desArmsNotRun(all))
	}
}

// THE CONTROL'S SILENCE IS CHECKED FOR FOUR ORACLES AND ITS NUMBER IS READ FOR THE FIFTH, and the
// reason is a measurement: every non-serialized string fires the length oracle on a real sink, so
// a class that used this control to disable that oracle would silence its own best probe wherever
// it works.
func TestTheTransformationControlDoesNotCoverTheLengthOracle(t *testing.T) {
	// A control response carrying its own length must NOT count as a transformation failure.
	lengthOnly := desObs(desNC1, desNC1Text, desLenBody(35))
	if fired, what := desTransformationFired(lengthOnly, ""); fired {
		t.Errorf("the control's own length reading was treated as a transformation control failure (%s). Every non-serialized string produces it on a real unserialize sink, so this would disable the length oracle on every target where it works", what)
	}
	// A control response carrying an actual transformation signature MUST fail the control.
	for _, body := range []string{
		"object(__PHP_Incomplete_Class)#1",
		"invalid stream header: " + desJ1Echo,
		"result: " + desY1Repr,
		desY2Echo,
	} {
		if fired, _ := desTransformationFired(desObs(desNC1, desNC1Text, body), ""); !fired {
			t.Errorf("the control did not fail on a response carrying %q, so a detector matching page text would go unnoticed", body)
		}
	}
}

// A JWT slot is not_applicable at ZERO request cost, which is the exclusion every class is
// required to have. Every payload here would be rejected at the signature check and would measure
// the token library rather than a deserializer.
func TestAJWTSlotCostsNothingAndSaysWhy(t *testing.T) {
	slot := triage.Slot{
		Kind: triage.KindCookie, Key: "cookie:id_token", Name: "id_token",
		Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", ServerReachable: true, SegmentIndex: -1,
	}
	c := deserClassifier{}
	if n := len(c.Plan(triage.PlanCtx{Slot: slot})); n != 0 {
		t.Errorf("planned %d probes into a JWT slot", n)
	}
	vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts", len(vs))
	}
	if vs[0].State != triage.StateNotApplicable {
		t.Errorf("state is %q, want not_applicable", vs[0].State)
	}
	if !strings.Contains(vs[0].Reason, "signed_wrapper") {
		t.Errorf("the reason %q does not name the exclusion", vs[0].Reason)
	}
}

func TestDeserWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello", ServerReachable: true, SegmentIndex: -1}
	for _, v := range (deserClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}) {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("clean with nothing sent: %q", v.Reason)
		}
	}
}

// Round 0 is the whole arm set and the second round is gated on a MEASUREMENT: DES-P1 goes out
// only once the length pair has shown an unserialize sink is actually there.
func TestTheIncompleteClassProbeIsGatedOnTheLengthPair(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello", ServerReachable: true, SegmentIndex: -1}
	if !desUnserializeSinkSeen(triage.PlanCtx{Slot: slot}) {
		// expected: an empty own-set cannot have established anything
	} else {
		t.Error("an empty own-set was read as having established an unserialize sink")
	}
	if n := len(desRound0()); n != 7 {
		t.Errorf("round 0 plans %d probes, want 7 (three PHP-arm strings and four base64 arms)", n)
	}
	for _, id := range desRound0() {
		if id == desP1 {
			t.Error("DES-P1 is in round 0. On a slot with no unserialize sink it is 26 bytes of noise with nothing to answer it, and the whole point of the ladder is that the length pair decides")
		}
	}
}

func TestEveryDeserPayloadIsDeliverableAndTheArithmeticOneCarriesNoMarker(t *testing.T) {
	for _, p := range (deserClassifier{}).Probes() {
		if len(p.Logical) == 0 {
			t.Errorf("probe %s has no bytes", p.ID)
		}
		for i := 0; i < len(p.Logical); i++ {
			if p.Logical[i] < 0x20 || p.Logical[i] > 0x7e {
				t.Errorf("probe %s byte %d is %#x, outside printable ASCII. This class's whole cost argument is that it needs no encoder this layer has not implemented", p.ID, i, p.Logical[i])
			}
		}
	}
	// The three length arms must NOT carry a marker: sixteen extra bytes would be harmless to the
	// arithmetic and would make the source numbers stop describing the wire.
	for _, id := range []triage.ProbeID{desP2A, desP2B, desNC1} {
		for _, p := range (deserClassifier{}).Probes() {
			if p.ID == id && strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
				t.Errorf("%s spells a marker. Its attribution is by probe ordinal, and a marker in it would change the length the application counts", id)
			}
		}
	}
	var c any = deserClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("DESER opted into runner-placed markers, which would add sixteen bytes to every length arm and break the arithmetic on the wire while leaving the source looking right")
	}
}

// A BASELINE CARRYING THE UNSERIALIZE SENTENCE MUST NOT DISABLE THE LENGTH ORACLE, AND IT DID.
//
// MEASURED on the canary oracle's /deser/php, the route written to be this class's positive: the
// route control sends the slot's observed value, that value is not serialized either, so the
// baseline carries "unserialize(): Error at offset 0 of 5 bytes" and desDisabledByBaseline listed
// php_unserialize_length. The class answered cannot_determine (signature_in_baseline) with all
// three arms correctly naming 39, 32 and 35. A tier-1 computation refused as an unusable
// signature, on the only shape where this class is at its strongest.
//
// The point of the rule is a page that recites a FIXED number. desReadLengths already refuses
// that by construction, and this test pins both halves: the baseline no longer disables the
// detector, and three arms naming one number is still not a computation.
func TestABaselineCarryingAnUnserializeErrorDoesNotDisableTheLengthOracle(t *testing.T) {
	baseline := [][]byte{[]byte(desLenBody(5))}
	for _, name := range desDisabledByBaseline(baseline) {
		if name == "php_unserialize_length" {
			t.Fatal("a baseline naming a length disabled the length oracle. Every working unserialize " +
				"sink produces that sentence for its own unperturbed value, so this rule switched the " +
				"class off on exactly the targets it is for")
		}
	}
	// And the static page is still caught, by the rule that is actually about it.
	static := desReadLengths([]faOwnObs{
		desObs(desP2A, desP2AText, desLenBody(39)),
		desObs(desP2B, desP2BText, desLenBody(39)),
		desObs(desNC1, desNC1Text, desLenBody(39)),
	})
	if static.verdict != desLenStatic {
		t.Errorf("three arms naming the same 39 read as %q, want %q: the pair, not the baseline, is "+
			"what catches a page reciting a fixed number", static.verdict, desLenStatic)
	}
	// The three signature detectors that ARE strings stay in the table.
	disabled := strings.Join(desDisabledByBaseline([][]byte{
		[]byte("docs: an unknown class loads as __PHP_Incomplete_Class"),
	}), ",")
	if !strings.Contains(disabled, "php_incomplete_class") {
		t.Errorf("a baseline carrying __PHP_Incomplete_Class did not disable that detector: %q", disabled)
	}
}

func TestTheDeserOracleCasesDeclareAFireRouteAndASilentRoute(t *testing.T) {
	cases := (deserClassifier{}).OracleCases()
	pos, neg, clean, na := 0, 0, 0, 0
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
			if c.WantState.CountsAsClean() {
				clean++
			}
			if c.WantState == triage.StateNotApplicable {
				na++
			}
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %s carries no reason", c.Name)
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("oracle cases: %d positive, %d negative; both must be non-zero", pos, neg)
	}
	if clean == 0 {
		t.Error("no negative case expects clean, so the class has never been shown able to say nothing-found")
	}
	if na == 0 {
		t.Error("no case exercises the zero-cost not_applicable, which every class is required to have")
	}
	t.Logf("%d oracle cases: %d positive, %d negative, %d expecting clean, %d expecting not_applicable", len(cases), pos, neg, clean, na)
}

// ---------------------------------------------------------------------------------------------
// THE TENTH DOOR: SIX SIGNATURES ABSENT FROM ZERO BYTES
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE ORACLE BEFORE THE FIX, exam of 2026-09-19 over 80 routes: this class reported
// CLEAN on /clean/empty204, /clean/nothing and /clean/always500 with the reason
// "no_deserializer_answered: all six arms of this class reached the wire and every one of them
// stayed silent". Every oracle this class has is a string or a number IN A RESPONSE BODY:
// __PHP_Incomplete_Class, an unserialize error naming a length, eight hex characters a JVM
// formatted, CPython's repr of a two-element list. On the first two routes there were no bytes
// for any of them to be absent from, and on the third every response was the same error page the
// benign control also gets, so nothing this class sent reached anything.
//
// desNeg calls desNegative, which is the decision this class takes once all five oracles have
// declined, and it supplies the whole of desCleanRequires so that the OLD path reaches clean
// rather than stopping at only_some_engines_were_tested.

func desNeg(t *testing.T, honest []faOwnObs, control triage.Observation, haveControl bool) triage.ClassVerdict {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassDeser, "query:q", state, reason, oracle, grade, ords, ann, desLabel(ann))
	}
	vs := desNegative(honest, control, haveControl, desFormatNone, ann, []uint64{24}, nil, one)
	if len(vs) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(vs))
	}
	if err := vs[0].Validate(); err != nil {
		t.Fatalf("the verdict this class emitted does not satisfy ClassVerdict.Validate: %v", err)
	}
	return vs[0]
}

// desAllArms answers every probe in desCleanRequires with the same body, so the arms-not-run
// refusal cannot be what produces the verdict under test.
func desAllArms(body string) []faOwnObs {
	var out []faOwnObs
	for _, id := range desCleanRequires() {
		out = append(out, desObs(id, "payload-"+string(id), body))
	}
	return out
}

func TestDeserWillNotReportCleanWhenThereIsNoBodyForASignatureToBeAbsentFrom(t *testing.T) {
	for _, c := range []struct {
		name    string
		control triage.Observation
	}{
		{"a 204 with no body, on the control and on all six arms", triage.Observation{ObsID: "route", Status: 204}},
		{"a 200 with an empty body, on the control and on all six arms", triage.Observation{ObsID: "route", Status: 200}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := desNeg(t, desAllArms(""), c.control, true)
			if v.State.CountsAsClean() {
				t.Errorf("state %s. Six body oracles reported silence out of zero bytes, which is not a "+
					"measurement of anything: %s", v.State, v.Reason)
			}
			if v.State != triage.StateCannotDetermine {
				t.Errorf("state %s, want cannot_determine", v.State)
			}
			if !strings.Contains(v.Reason, "no_body_to_read") {
				t.Errorf("the reason does not name no_body_to_read: %s", v.Reason)
			}
			if !strings.Contains(v.Reason, "6 of this class's own delivered probes") {
				t.Errorf("the reason does not report the count that fired: %s", v.Reason)
			}
		})
	}
}

// /clean/always500: the bodies exist, they are identical, and the UNPERTURBED request gets the
// same one. Whatever this class searched, it was not the application's answer about our value.
func TestDeserWillNotReportCleanWhenTheUnperturbedControlIsItselfFailing(t *testing.T) {
	page := "<!doctype html><title>Error</title><h1>Something went wrong</h1>"
	control := triage.Observation{ObsID: "route", Status: 500, Body: []byte(page), BodyLen: len(page)}
	v := desNeg(t, desAllArms(page), control, true)
	if v.State.CountsAsClean() {
		t.Errorf("state %s. The benign control, which carries none of our bytes, already answered 500 "+
			"with this page, so the pages searched are the failure's and not the application's: %s",
			v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "control_already_failing") {
		t.Errorf("the reason does not name control_already_failing: %s", v.Reason)
	}
}

// THE OTHER HALF, AND IT IS THE REGRESSION THAT MATTERS MOST. /api/items is a JSON API that reads
// its parameters and echoes NOTHING, which is the shape of the operator's real target: it answers
// the same fixed document to every input, and a clean there is CORRECT because these oracles are
// signatures rather than differentials. A guard built on "the endpoint answers the same to
// everything" would have deleted it, which is why the body arm asks about BYTES and about the
// control's status and never about sensitivity.
func TestDeserStillReportsCleanOnAnEchoFreeJSONAPIThatAnswersTheSameToEveryInput(t *testing.T) {
	doc := `{"ok":true,"items":[{"id":1},{"id":2}],"page":2}`
	control := triage.Observation{ObsID: "route", Status: 200, Body: []byte(doc), BodyLen: len(doc)}
	v := desNeg(t, desAllArms(doc), control, true)
	if v.State != triage.StateClean {
		t.Fatalf("state %s on an echo-free JSON API answering 200. Every arm here is a rank-1 oracle "+
			"over a value the runtime would have had to COMPUTE, so silence over a real body is a real "+
			"negative and this class must keep it: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "bytes of response body across") {
		t.Errorf("the clean does not say how many bytes it searched, which is the one number that "+
			"separates it from the vacuous version: %s", v.Reason)
	}
	if got := v.Annotations["bodies_searched"]; got != len(desCleanRequires()) {
		t.Errorf("bodies_searched = %v, want %d", got, len(desCleanRequires()))
	}
}

// ---------------------------------------------------------------------------------------------
// ROUND 5: THE DIFFERENTIAL WITNESS READS TWO CHANNELS AND DECIDES ON ONE
// ---------------------------------------------------------------------------------------------

// pxObs is one delivered own-observation for the witness tests. It sets the normalised body hash
// because faCompare prefers it, which is the only path a real projection takes.
func pxObs(id triage.ProbeID, body string, headers ...[2]string) faOwnObs {
	o := triage.Observation{
		ObsID: "obs-" + string(id), Status: 302,
		Body: []byte(body), BodyLen: len(body),
		RespHeaders: append([][2]string{}, headers...),
	}
	o.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return faOwnObs{ProbeID: id, Ordinal: 7, Obs: o}
}

func pxCtl(body string, headers ...[2]string) triage.Observation {
	o := triage.Observation{
		ObsID: "route", Status: 302,
		Body: []byte(body), BodyLen: len(body),
		RespHeaders: append([][2]string{}, headers...),
	}
	o.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return o
}

// THE DECISION STAYS ON THE BODY CHANNEL AND THIS TEST IS THE REASON WHY, WRITTEN DOWN.
//
// /redirect/local answers twelve identical body bytes to every payload and puts the value in
// Location. Counting that Location as movement was the obvious fix for route_insensitive's false
// sentence, and it is the wrong one: lfiRouteInsensitive reads Moved and Flat off this struct and
// refuses a clean only while Moved == 0. Make Moved count a header and LFI goes straight back to
// reporting clean on /redirect/local, /redirect/fixed, /redirect/loginwrap,
// /redirect/strictvalidator and /redirect/alwaysoffsite, where its four oracles all search a body
// that never changed. A fix that converts a refusal into a clean somewhere else is not a fix.
//
// So Moved, Flat and Unknown keep the faCompare meaning exactly, and what the header channel saw
// is carried beside them for the reason strings to report.
func TestTheDifferentialWitnessDecidesOnTheChannelItsOraclesRead(t *testing.T) {
	const body = "redirecting"
	control := pxCtl(body, [2]string{"Location", "/a?u=control"})
	honest := []faOwnObs{
		pxObs("P1", body, [2]string{"Location", "/a?u=alpha&dup=1"}),
		pxObs("P2", body, [2]string{"Location", "/a?u=alpha-dup-1"}),
		pxObs("P3", body, [2]string{"Location", "/a?u=beta"}),
	}
	s := pxRouteSensitivity(honest, control, true)
	if s.Delivered != 3 || s.Moved != 0 || s.Flat != 3 {
		t.Fatalf("delivered=%d moved=%d flat=%d, want 3/0/3. Moved must stay the faCompare reading, "+
			"because lfiRouteInsensitive refuses its clean on exactly that number",
			s.Delivered, s.Moved, s.Flat)
	}
	if s.HeaderMoved != 3 {
		t.Errorf("HeaderMoved = %d, want 3. Location carries a different value on every probe and the "+
			"witness reported the responses as indistinguishable", s.HeaderMoved)
	}
	if len(s.HeaderNames) != 1 || s.HeaderNames[0] != "location" {
		t.Errorf("HeaderNames = %v, want [location]. A reason string that says the headers moved without "+
			"naming them is an assertion rather than a measurement", s.HeaderNames)
	}
}

// THE VOLATILE LIST, WHICH IS WHAT KEEPS THE SECOND CHANNEL FROM REPORTING A CLOCK.
//
// Date moves every second, Content-Length is derived from a body the first channel already
// compared, and an x-request-id is unique per request by design. None of those is the endpoint
// answering our value. SET-COOKIE IS DELIBERATELY NOT ON THE LIST even though CATALOGUE 3.3's
// seed list has it: /crlf/setcookie puts the slot's value straight into Set-Cookie and is one of
// the four routes this witness exists to see.
func TestTheHeaderWitnessIgnoresClocksAndLengthsAndStillSeesSetCookie(t *testing.T) {
	base := pxCtl("body", [2]string{"Date", "Mon, 01 Jan 2035 00:00:00 GMT"},
		[2]string{"Content-Length", "4"}, [2]string{"X-Request-Id", "aaaa"},
		[2]string{"X-RateLimit-Remaining", "99"}, [2]string{"Set-Cookie", "pref=control; Path=/"})
	sameButNoisy := pxObs("P1", "body", [2]string{"Date", "Tue, 02 Jan 2035 03:04:05 GMT"},
		[2]string{"Content-Length", "4"}, [2]string{"X-Request-Id", "bbbb"},
		[2]string{"X-RateLimit-Remaining", "12"}, [2]string{"Set-Cookie", "pref=control; Path=/"})
	if names := pxHeaderWitness(base, sameButNoisy.Obs); len(names) != 0 {
		t.Errorf("the witness reported %v as movement. Every one of those headers differs for a reason "+
			"that has nothing to do with what we sent", names)
	}

	cookieMoved := pxObs("P2", "body", [2]string{"Date", "Wed, 03 Jan 2035 00:00:00 GMT"},
		[2]string{"Content-Length", "4"}, [2]string{"X-Request-Id", "cccc"},
		[2]string{"X-RateLimit-Remaining", "3"}, [2]string{"Set-Cookie", "pref=hppa&hppdup=hppb; Path=/"})
	names := pxHeaderWitness(base, cookieMoved.Obs)
	if len(names) != 1 || names[0] != "set-cookie" {
		t.Errorf("pxHeaderWitness = %v, want [set-cookie]. /crlf/setcookie writes the slot's value into "+
			"that header and it is one of the four routes this witness was added for", names)
	}
}

// A HEADER PRESENT ON ONE SIDE AND ABSENT ON THE OTHER IS A DIFFERENCE. A response that grew an
// Access-Control-Allow-Origin the control did not have is the endpoint answering differently, and
// a fingerprint comparison that only walked one side would miss it in one direction.
func TestTheHeaderWitnessSeesAHeaderThatOnlyOneSideCarries(t *testing.T) {
	control := pxCtl("body")
	grew := pxObs("P1", "body", [2]string{"Access-Control-Allow-Origin", "https://evil.test"})
	if names := pxHeaderWitness(control, grew.Obs); len(names) != 1 || names[0] != "access-control-allow-origin" {
		t.Errorf("pxHeaderWitness = %v, want [access-control-allow-origin]", names)
	}
	if names := pxHeaderWitness(grew.Obs, control); len(names) != 1 || names[0] != "access-control-allow-origin" {
		t.Errorf("reversed, pxHeaderWitness = %v, want [access-control-allow-origin]", names)
	}
}

// AND IT MEASURES NOTHING WHEN THERE WAS NOTHING TO MEASURE. A witness that called an unobserved
// response "different" would be manufacturing exactly the movement it was added to report
// honestly, and the reason strings downstream would then name headers nobody ever saw.
func TestTheHeaderWitnessReportsNothingWhenOneSideNeverArrived(t *testing.T) {
	control := pxCtl("body", [2]string{"Location", "/a"})
	never := triage.Observation{}
	if names := pxHeaderWitness(control, never); names != nil {
		t.Errorf("pxHeaderWitness against an unobserved response = %v, want nothing", names)
	}
	failed := pxObs("P1", "body", [2]string{"Location", "/b"})
	failed.Obs.TransportErr = triage.TransportTimeout
	if names := pxHeaderWitness(control, failed.Obs); names != nil {
		t.Errorf("pxHeaderWitness against an undelivered response = %v, want nothing", names)
	}
	s := pxRouteSensitivity([]faOwnObs{failed}, control, true)
	if s.Delivered != 0 || s.HeaderMoved != 0 {
		t.Errorf("delivered=%d headerMoved=%d, want 0/0 for a probe that never came back",
			s.Delivered, s.HeaderMoved)
	}
}

// THE REFUSAL'S OWN SENTENCE, ASSERTED HERE RATHER THAN ONLY THROUGH HPP, because
// pxDifferentialSurfaceUnavailable is shared and the next class to declare pxReadsDifference
// inherits every word of it.
func TestRouteInsensitiveSaysWhichChannelItReadAndWhatTheOtherOneSaw(t *testing.T) {
	const body = "redirecting"
	control := pxCtl(body, [2]string{"Location", "/a?u=control"})
	honest := []faOwnObs{
		pxObs("P1", body, [2]string{"Location", "/a?u=alpha"}),
		pxObs("P2", body, [2]string{"Location", "/a?u=beta"}),
	}
	why, absent := pxDifferentialSurfaceUnavailable(honest, control, true)
	if !absent {
		t.Fatalf("the refusal stopped firing on an endpoint whose status and body do not move. "+
			"Widening this decision to the header channel is what returns LFI's five redirect routes "+
			"to clean: %s", why)
	}
	if strings.Contains(why, "INDISTINGUISHABLE") {
		t.Errorf("the reason still calls two responses with different Location headers "+
			"indistinguishable: %s", why)
	}
	if strings.Contains(why, "true of every payload anyone could send") {
		t.Errorf("the reason still generalises from two probes to every payload that exists: %s", why)
	}
	for _, want := range []string{
		"THE SAME STATUS AND THE SAME NORMALISED BODY",
		"NOT INERT, THOUGH: 2 of those probes",
		"location",
	} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason does not contain %q: %s", want, why)
		}
	}
}

// AND WHERE NOTHING MOVED IN EITHER CHANNEL, THE SECOND SENTENCE MUST NOT APPEAR AT ALL. A row
// that always carries a caveat is a row nobody reads, and "0 of those probes came back with a
// different header" is the same overclaim in the opposite direction.
func TestRouteInsensitiveStaysSilentAboutHeadersThatDidNotMove(t *testing.T) {
	control := pxCtl("<!doctype html><h1>Rosewood Gin</h1>", [2]string{"Content-Type", "text/html"})
	honest := []faOwnObs{
		pxObs("P1", "<!doctype html><h1>Rosewood Gin</h1>", [2]string{"Content-Type", "text/html"}),
		pxObs("P2", "<!doctype html><h1>Rosewood Gin</h1>", [2]string{"Content-Type", "text/html"}),
	}
	why, absent := pxDifferentialSurfaceUnavailable(honest, control, true)
	if !absent {
		t.Fatalf("the refusal did not fire on an endpoint that answered everything identically: %s", why)
	}
	if strings.Contains(why, "NOT INERT") {
		t.Errorf("the reason reports header movement on an endpoint whose headers are identical: %s", why)
	}
}

// The nothing-sent ladder asks the planner before it asks the budget. See pxbudgetarm.go for the
// defect; what is asserted here is that THIS class's ladder is wired to THIS class's planner.
//
// desRound0 is unconditional once the eligibility, reachability and signed-wrapper gates have
// passed, and Classify checks those same three before it reaches the ladder, so the count handed
// to the tail is exactly what Plan would have derived. It is never zero, so this class's
// not_planned arm is structurally unreachable and its nothing-sent rows are honestly about the
// cap; the conversion buys the SENTENCE, which no longer dates the cap to before this class
// planned when nothing measured that order.
func TestDeserNothingSentAsksThePlannerBeforeTheBudget(t *testing.T) {
	if len(desRound0()) == 0 {
		t.Fatal("desRound0 is empty, so this class derives nothing for any slot and the comment above is wrong")
	}
	src, err := os.ReadFile(filepath.Join(packageDirOf(t), "deser.go"))
	if err != nil {
		t.Fatalf("read deser.go: %v", err)
	}
	if !strings.Contains(string(src), "pxNothingSentTail(ctx, len(desRound0())") {
		t.Error("desNothingSent does not hand pxNothingSentTail the count desRound0 derives, so the " +
			"ordering and the sentence are being asserted by the class again")
	}
}
