package triageclasses

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

func lfiProbe(t *testing.T, id triage.ProbeID) triage.ProbeSpec {
	t.Helper()
	for _, p := range (lfiClassifier{}).Probes() {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("probe %s is not declared, so it can never be planned", id)
	return triage.ProbeSpec{}
}

func TestTheLFIClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassLFI)
	if !ok {
		t.Fatal("the LFI classifier did not register, so the whole class would be silently missing")
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassLFI {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Logical) == 0 {
			t.Errorf("probe %s has no bytes", p.ID)
		}
	}
}

// THE CLASS BOUNDARY, ASSERTED FROM THE OTHER SIDE. NC-L6 from the catalogue, as an offline
// fixture: not one payload in this class escapes a directory, in any encoding, so a hit here can
// never be a traversal hit wearing the wrong label and a WAF rule for '../' cannot make this
// class silently untestable.
func TestNoLFIPayloadContainsADotDotInAnyEncoding(t *testing.T) {
	for _, p := range (lfiClassifier{}).Probes() {
		decoded := faTestDecodeAll(p.Logical)
		if bytes.Contains(decoded, []byte("..")) {
			t.Errorf("payload %s decodes to %q, which contains a dot-dot. That is TRAVERSAL's question, "+
				"it needs TRAVERSAL's confirmation, and a merged payload can be rejected by a validator "+
				"that either half would pass", p.ID, string(decoded))
		}
	}
}

// The two classes must not ship byte-equal payloads, and the build-time check only catches exact
// equality. This asserts the stronger family property while the payloads are in one place.
func TestTheThreeFileAccessClassesShareNoPayloadWithEachOther(t *testing.T) {
	type owned struct {
		class triage.ClassID
		id    triage.ProbeID
		norm  string
	}
	var all []owned
	for _, c := range []triage.Classifier{traversalClassifier{}, lfiClassifier{}, rfiClassifier{}} {
		for _, p := range c.Probes() {
			all = append(all, owned{c.ID(), p.ID, string(triage.NormaliseMarkers(p.Logical))})
		}
	}
	for i := range all {
		for j := range all {
			if i >= j || all[i].class == all[j].class {
				continue
			}
			if all[i].norm == all[j].norm {
				t.Errorf("ISOLATION: %s (%s) is byte-equal to %s (%s). A block or a rejection of that "+
					"payload could not be attributed to either class", all[i].id, all[i].class, all[j].id, all[j].class)
			}
		}
	}
}

// The negative controls have to be near misses and not random strings, and the two that carry the
// marker's anchor trigram have to be SHORT OF a marker or the attribution machinery mistakes them
// for one.
func TestTheAnchorTrigramControlsAreDeliberatelyThreeCharactersShortOfAMarker(t *testing.T) {
	t.Run("the bogus scheme is not a marker", func(t *testing.T) {
		if m := triage.Marker("zqjnotascheme"); m.WellFormed() {
			t.Fatal("zqjnotascheme parses as a well formed marker, so the attribution machinery would " +
				"treat this control's payload as carrying somebody's marker")
		}
		if got := triage.NormaliseMarkers([]byte("zqjnotascheme://x")); !bytes.Contains(got, []byte("zqjnotascheme")) {
			t.Errorf("the marker normaliser rewrote the control's scheme to %q, which means it reads as a marker", got)
		}
	})
	t.Run("the control's base64 decodes to a near miss and not to this run's marker", func(t *testing.T) {
		p := lfiProbe(t, lfiNC5)
		i := bytes.Index(p.Logical, []byte("base64,"))
		if i < 0 {
			t.Fatal("NC5 is not a base64 data URI any more")
		}
		d, err := base64.StdEncoding.DecodeString(string(p.Logical[i+len("base64,"):]))
		if err != nil {
			t.Fatalf("NC5's base64 does not decode: %v", err)
		}
		if string(d) != "zqjnotmarker" {
			t.Fatalf("NC5 decodes to %q, want zqjnotmarker: the control's job is to fire a detector that "+
				"matches the anchor trigram alone while staying invisible to one that matches this run's sixteen bytes", d)
		}
		if triage.Marker(d).WellFormed() {
			t.Fatal("NC5's plaintext is a well formed marker, which would make the control indistinguishable from a hit")
		}
	})
}

// Delivery limits, from the verified encoder facts.
func TestTheLFIDeliveryLimitsMatchTheVerifiedEncoderFacts(t *testing.T) {
	has := func(p triage.ProbeSpec, k triage.SlotKind) bool {
		for _, pk := range p.Points {
			if pk == k {
				return true
			}
		}
		return false
	}
	for _, k := range []triage.SlotKind{triage.KindHeader, triage.KindCookie} {
		if has(lfiProbe(t, lfiL10), k) {
			t.Errorf("L10 carries a NUL and claims a %s slot, where a NUL cannot be delivered at all", k)
		}
	}
	for _, id := range []triage.ProbeID{lfiL17, lfiL18} {
		p := lfiProbe(t, id)
		if len(p.Points) != 1 || p.Points[0] != triage.KindPath {
			t.Errorf("%s is the no-slash payload for a path segment and must claim nothing else", id)
		}
		if bytes.Contains(p.Logical, []byte("/")) && id == lfiL17 {
			t.Errorf("%s contains a slash, which defeats its entire purpose", id)
		}
	}
	t.Run("the wrapper payload needs an equals sign, which is why the cookie point is comfortable", func(t *testing.T) {
		if !bytes.Contains(lfiProbe(t, lfiL5).Logical, []byte("=")) {
			t.Error("the filter wrapper lost its resource= parameter")
		}
	})
	t.Run("no payload in this class needs a space, which is what makes the cookie point work at all", func(t *testing.T) {
		for _, p := range (lfiClassifier{}).Probes() {
			if bytes.Contains(p.Logical, []byte(" ")) {
				t.Errorf("payload %s contains a space, which is not cookie-octet and would need encoding the class did not plan for", p.ID)
			}
		}
	})
}

// THE DETECTION RULES, WITH THE NAMED FALSE POSITIVES AS FIRST-CLASS ROWS.
func TestTheLFIContentSignaturesFireOnARealReadAndStaySilentOnEveryNamedFalsePositive(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a real passwd read fires", "root:x:0:0:root:/root:/bin/bash\n", true},
		{"a real web.xml read fires",
			`<?xml version="1.0"?><web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"><display-name>app</display-name></web-app>`, true},
		{"a real web.config read fires",
			`<configuration><system.webServer><handlers/></system.webServer></configuration>`, true},
		{"a real spring properties read fires", "server.port=8080\nspring.datasource.url=jdbc:x\n", true},
		{"php source disclosure fires when the decoded run begins with the open tag", "<?php\nnamespace App;\n", true},

		{"FP-L6: the payload echoed back does not fire",
			"<p>cannot open php://filter/convert.base64-encode/resource=/etc/passwd</p>", false},
		{"an XML page that merely mentions web-app does not fire without a corroborating element",
			"<p>configure your &lt;web-app&gt; element</p>", false},
		{"a configuration word in prose does not fire",
			"See the configuration section and system.web notes below.", false},
		{"a php open tag in the MIDDLE of a page does not fire, because the rule is anchored at offset zero",
			"<html><body>example: <?php echo 1; ?></body></html>", false},
		{"an empty body does not fire", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := faMatchSignatures(lfiContent, []byte(tc.body))
			if got := len(p) > 0; got != tc.want {
				t.Errorf("primary signatures fired = %v, want %v", got, tc.want)
			}
		})
	}
}

// The two /proc detectors are STRUCTURAL because the substring versions fire on half the
// internet. These rows are the exact strings that defeat a substring detector.
func TestTheProcDetectorsAreStructuralAndIgnoreDocumentationThatMentionsPATH(t *testing.T) {
	realEnviron := "LANG=en_US.UTF-8\x00PATH=/usr/local/bin:/usr/bin:/bin\x00HOME=/root\x00PWD=/srv\x00"
	realCmdline := "/usr/local/bin/python3\x00/srv/app/main.py\x00"
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a real environ fires", realEnviron, true},
		{"shell documentation mentioning PATH=/usr/bin does NOT fire, because there is no NUL and no structure",
			"Set PATH=/usr/bin before running. Also LANG=en_US and HOME=/root.", false},
		{"a JSON document carrying PATH does NOT fire", `{"env":{"PATH":"/usr/bin","HOME":"/root","LANG":"C"}}`, false},
		{"NUL separated tokens with no PATH among them does NOT fire", "A=1\x00B=2\x00C=3\x00", false},
		{"fewer than three names does NOT fire", "PATH=/usr/bin\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lfiEnvironLooksReal([]byte(tc.body)); got != tc.want {
				t.Errorf("lfiEnvironLooksReal = %v, want %v", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a real cmdline fires", realCmdline, true},
		{"markup with a NUL in it does NOT fire, because a cmdline has no angle bracket",
			"<pre>/usr/bin/x\x00arg</pre>", false},
		{"a relative first token does NOT fire", "python3\x00main.py\x00", false},
		{"no NUL at all does NOT fire", "/usr/local/bin/python3 /srv/app/main.py", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lfiCmdlineLooksReal([]byte(tc.body)); got != tc.want {
				t.Errorf("lfiCmdlineLooksReal = %v, want %v", got, tc.want)
			}
		})
	}
}

// The stream and stack error tables identify the sink, and the engine id they hand back is what
// picks tier 4. Getting it wrong sends a Java probe at a .NET application.
func TestTheStackErrorTableNamesTheEngineItIdentified(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{"java.net.MalformedURLException: unknown protocol: php", "java"},
		{"System.IO.FileNotFoundException: Could not find file 'C:\\app\\x'", "dotnet"},
		{"Error: ENOENT: no such file or directory, open '/srv/x'", "node"},
		{"FileNotFoundError: [Errno 2] No such file or directory: '/srv/x'", "python"},
		{"Errno::EACCES", "ruby"},
		{"open /srv/x: permission denied", "go"},
		{"<b>Warning</b>: include(): failed to open stream: No such file or directory", "php"},
		{"nothing at all here", ""},
	} {
		got := lfiEngine([]faOwnObs{{Obs: triage.Observation{Body: []byte(tc.body)}}})
		if got != tc.want {
			t.Errorf("engine for %q = %q, want %q", tc.body, got, tc.want)
		}
	}
}

// THE LADDER'S ONE LOAD-BEARING PROPERTY: tier 2 is a list and not a consequence of tier 1.
func TestTierTwoIsUnconditionalAndIsNotDerivedFromTierOne(t *testing.T) {
	if len(lfiTier2IDs) == 0 {
		t.Fatal("tier 2 is empty")
	}
	in := map[triage.ProbeID]bool{}
	for _, id := range lfiTier1IDs {
		in[id] = true
	}
	for _, id := range lfiTier2IDs {
		if in[id] {
			t.Errorf("%s is in both tiers, so the counts in the cost model are wrong", id)
		}
	}
	// The wrapper and the data URI are the two payloads that work where an absolute path does
	// not, and they are the reason this tier cannot be gated.
	want := map[triage.ProbeID]bool{lfiL5: false, lfiL7: false}
	for _, id := range lfiTier2IDs {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, present := range want {
		if !present {
			t.Errorf("%s is not in the unconditional tier, and it is one of the two payloads that reach a sink an absolute path cannot", id)
		}
	}
	t.Run("and a path slot that rejects the encoded slash still has something deliverable", func(t *testing.T) {
		if len(lfiPathNoSlashIDs) < 2 {
			t.Fatal("a %2F-rejecting path slot would get nothing, and a class with nothing deliverable that reported clean would be reporting on the transport")
		}
		for _, id := range lfiPathNoSlashIDs {
			p := lfiProbe(t, id)
			if id == lfiL17 || id == lfiL18 {
				if bytes.HasPrefix(p.Logical, []byte("/")) {
					t.Errorf("%s starts with a slash, which is the one byte a path segment cannot carry here", id)
				}
			}
		}
	})
}

// EVERY PATH THROUGH CLASSIFY THAT REACHES NO RESPONSES MUST BE AN UNKNOWN.
func TestLFIClassifyNeverReportsCleanWhenItHasNoResponses(t *testing.T) {
	c := lfiClassifier{}
	base := triage.Slot{Key: "query:file", Kind: triage.KindQuery, Name: "file", ServerReachable: true}
	for _, tc := range []struct {
		name string
		ctx  triage.ClassifyCtx
	}{
		{"nothing resolved at all", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base}}},
		{"the prelude failed", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base, Prelude: triage.PreludeTokenUnobtainable}}},
		{"the budget was exhausted", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: base,
			Budget: triage.TriageBudget{PerSlot: 20, PerRun: 100}}}},
		{"a fragment slot", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "fragment:x", Kind: triage.KindFragment, ServerReachable: true}}}},
		{"a credential slot", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "cookie:session", Kind: triage.KindCookie, ServerReachable: true,
				Constraints: triage.SlotConstraints{IsCredential: true}}}}},
		{"a path slot that rejects the encoded slash", triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
			Slot: triage.Slot{Key: "path:2", Kind: triage.KindPath, ServerReachable: true,
				Constraints: triage.SlotConstraints{PctRejected: true}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := c.Classify(tc.ctx)
			if len(vs) == 0 {
				t.Fatal("no verdict at all, so the slot reads as untouched")
			}
			for _, v := range vs {
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
				if v.State.CountsAsClean() {
					t.Error("reported CLEAN with no probe responses in hand")
				}
				if !v.State.IsUnknown() {
					t.Errorf("state %q is not an unknown", v.State)
				}
				if strings.TrimSpace(v.Reason) == "" {
					t.Error("an unknown with no reason")
				}
			}
		})
	}
}

// The refusals on safety grounds are printed on the verdict, because a payload refused on safety
// is an UNKNOWN and the operator has to be able to see which mechanisms were never tested.
func TestTheSafetyRefusalsAreNamedOnTheVerdictAndNotJustInAComment(t *testing.T) {
	v := lfiClassifier{}.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot: triage.Slot{Key: "query:f", Kind: triage.KindQuery, ServerReachable: true}}})
	list, _ := v[0].Annotations["not_probed_on_safety"].([]string)
	if len(list) == 0 {
		t.Fatal("the verdict does not name the payloads this class refuses to send")
	}
	joined := strings.Join(list, " | ")
	for _, want := range []string{"expect://", "phar://", "php://input", "log"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the refusal list does not mention %q, so an operator cannot tell that mechanism was never tested", want)
		}
	}
}

func TestTheScriptNameComesFromTheVectorsOwnURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://h/app/view.php?f=1", "view.php"},
		{"https://h/app/", "index.php"},
		{"https://h/app/reports", "index.php"},
		{"", "index.php"},
	} {
		if got := lfiScriptName(tc.in); got != tc.want {
			t.Errorf("lfiScriptName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTheLFIOracleSetContainsBothAFiringRouteAndASilentOne(t *testing.T) {
	pos, neg, cleanRoutes := 0, 0, 0
	for _, c := range (lfiClassifier{}).OracleCases() {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %q carries no reason", c.Name)
		}
		if c.WantState.CountsAsClean() {
			cleanRoutes++
		}
	}
	if pos == 0 {
		t.Error("no route on which this class must fire")
	}
	if neg == 0 {
		t.Error("no route on which this class must STAY SILENT")
	}
	if cleanRoutes == 0 {
		t.Error("no route on which a CLEAN is the correct answer, so the class's clean path has never " +
			"been observed producing one honestly and could be unreachable without anybody noticing")
	}
}

// ---------------------------------------------------------------------------------------------
// THE data:// RULE AND THE CONTROL THAT IS SUPPOSED TO HOLD IT DOWN
// ---------------------------------------------------------------------------------------------

// lfiTestL7Obs builds an LFI-L7 response from an endpoint that reflects its parameter, which is
// what /xss, /redirect, /cmdi and /ssti on the oracle all do.
//
// Payload.Wire is PERCENT-ENCODED, because that is what a query, form, cookie or path encoder
// writes: the comma of "base64," goes out as %2C. Payload.Logical is the bytes the class asked
// for. The two differ in exactly the byte the control used to search for.
func lfiTestL7Obs(t *testing.T, marker string, reflects bool) triage.Observation {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(marker))
	logical := "data://text/plain;base64," + b64
	wire := strings.ReplaceAll(strings.ReplaceAll(logical, ":", "%3A"), ",", "%2C")
	wire = strings.ReplaceAll(strings.ReplaceAll(wire, "/", "%2F"), ";", "%3B")
	if bytes.Contains([]byte(wire), []byte("base64,")) {
		t.Fatal("the fixture's wire still carries a literal \"base64,\", so it is not a percent-encoded wire and proves nothing")
	}
	body := "not found\n"
	if reflects {
		body = "<div id=\"out\">" + logical + "</div>\n"
	}
	o := triage.Observation{
		ObsID: "obs-l7", RunID: "lfi0", Status: 200, Kind: triage.ObsProbe,
		Class: triage.ClassLFI, Marker: triage.Marker(marker),
		Body: []byte(body), BodyLen: len(body), ReqWireURL: "/x",
	}
	o.BodySHA256 = sha256.Sum256(o.Body)
	o.Payload = triage.PayloadWire{
		Logical: []byte(logical), Wire: []byte(wire), Survived: triage.WireSurvivalEncoded,
		EncoderChain: []triage.EncoderMode{triage.EncodeQuery},
	}
	return o
}

// THE FALSE POSITIVE THIS TEST EXISTS FOR. An endpoint that echoes its parameter hands back the
// base64 of the marker, faByteForm's base64 search reports the marker present, and the control
// that is supposed to demote that to suspicious searched for the literal string "base64," inside
// the PERCENT-ENCODED wire, where it can never appear. Measured against the oracle: the rule
// fired finding/high/data_scheme_decoded on four of seven slots INCLUDING /xss and /redirect,
// and did not fire on /lfi.
func TestAReflectedPayloadIsNotADecodedOneBecauseTheControlReadsTheWire(t *testing.T) {
	m := "zqjlfi0000014aa1"
	o := lfiTestL7Obs(t, m, true)

	if !lfiBase64Echoed(o, triage.Marker(m)) {
		t.Error("the base64 control did not fire on a response that echoed the payload verbatim. " +
			"It reads the percent-encoded wire, where the comma of \"base64,\" is %2C, so it can " +
			"never find its anchor and can never demote anything")
	}
	got, form := lfiJudgeDataScheme(o, triage.Marker(m))
	if got == lfiDataDecoded {
		t.Errorf("a reflecting endpoint was judged %q (marker form %q), which is graded "+
			"finding/high/data_scheme_decoded. Nothing decoded anything: the base64 we sent came "+
			"straight back", got, form)
	}
	// It is lfiDataEchoed and no longer lfiDataReflected, and the distinction is exam ef8c13ab's
	// defect 3(a): "reflected" used to cover both "only the base64 came back" and "the plaintext
	// AND the base64 came back", and the single verdict text claimed the second on every route
	// that was really the first. Only the bytes we sent came back here, so the rank 1 oracle is
	// silent rather than negative and the ladder below it still gets asked.
	if got != lfiDataEchoed {
		t.Errorf("judgement %q, want %q", got, lfiDataEchoed)
	}
}

// And the rule still has to fire where it belongs: the sixteen PLAINTEXT bytes coming back when
// only their base64 was sent is a stream wrapper decoding a value from this slot.
func TestThePlaintextMarkerComingBackAloneIsStillTheDecodedFinding(t *testing.T) {
	m := "zqjlfi0000014aa1"
	o := lfiTestL7Obs(t, m, false)
	o.Body = []byte("root:x:0:0:" + m + ":/root:/bin/sh\n")
	o.BodyLen = len(o.Body)
	o.BodySHA256 = sha256.Sum256(o.Body)

	if lfiBase64Echoed(o, triage.Marker(m)) {
		t.Fatal("the control fired on a body that carries only the plaintext, which would demote a real finding")
	}
	got, form := lfiJudgeDataScheme(o, triage.Marker(m))
	if got != lfiDataDecoded {
		t.Errorf("judgement %q (form %q), want %q: the plaintext came back and the base64 did not",
			got, form, lfiDataDecoded)
	}
}

// A body with neither form in it is silent, and silence is neither of the other two.
func TestADataSchemeResponseCarryingNoMarkerAtAllIsSilent(t *testing.T) {
	m := "zqjlfi0000014aa1"
	o := lfiTestL7Obs(t, m, false)
	if got, _ := lfiJudgeDataScheme(o, triage.Marker(m)); got != lfiDataSilent {
		t.Errorf("judgement %q, want %q", got, lfiDataSilent)
	}
}

// ------------------------------------------------------------------------------------------------
// EXAM ef8c13ab, DEFECT 3: A CLASS THAT FIRED EVERYWHERE EXCEPT WHERE THE BUG WAS
//
// Two separate faults, measured against the local oracle, and they have opposite signs.
//
// (a) LFI returned suspicious/low (data_both_present) on TWELVE routes, six of them clean
//     controls: /cmdi /ssti /xss /redirect /sqli/mssql /sqli/mysql /csti/angular /xss/encoded
//     /xss/entity /clean/echo /clean/echoparser /clean/echomongo. Every one of those routes
//     reflects its parameter verbatim, so LFI-L7's own base64 came back and NOTHING ELSE DID. The
//     verdict text claims "the marker plaintext AND the literal base64 both came back", which is
//     false on all twelve: only the base64 came back, which is the bytes we sent, which is the one
//     observation that carries no information at all.
//
// (b) LFI returned cannot_determine (blocked) on /lfi ITSELF, its own positive control, where the
//     response is /etc/passwd. Five distinct traversal payloads all return the same 134 bytes,
//     because they all resolve to the SAME FILE, and the uniform-block rule read that identity as
//     a filter answering with one canned page. Identical non-baseline bodies across distinct
//     payloads is the signature of a successful read as much as of a block, and the two are told
//     apart by what is IN the body: a WAF block page does not contain root:x:0:0.
// ------------------------------------------------------------------------------------------------

func lfiTestL7Observation(t *testing.T, marker triage.Marker, bodyFmt string) triage.Observation {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(marker))
	logical := "data://text/plain;base64," + b64
	o := triage.Observation{Body: []byte(strings.ReplaceAll(bodyFmt, "${payload}", logical))}
	o.Payload.Logical = []byte(logical)
	o.Payload.Wire = []byte(logical)
	o.Marker = marker
	return o
}

func TestLFIDoesNotClaimBothPresentWhenOnlyTheBytesItSentCameBack(t *testing.T) {
	marker := triage.Marker("zqjk3m1x7p2w9b4t")
	cases := []struct {
		name string
		body string
	}{
		{"/clean/echo, verbatim text/plain reflection", "echo\n${payload}\n"},
		{"/cmdi, the value inside an emulated ping line", "PING ${payload}: 56 data bytes\nARS0N_CANARY_OK\n"},
		{"/clean/echomongo, the value inside a JSON error", `{"ok":false,"error":"could not parse filter","received":"{\"q\":\"${payload}\"}"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := lfiTestL7Observation(t, marker, tc.body)
			if bytes.Contains(obs.Body, []byte(marker)) {
				t.Fatalf("fixture error: the plaintext marker is in the body, so this is not the "+
					"echo-only case the test is about. body=%q", string(obs.Body))
			}
			judged, form := lfiJudgeDataScheme(obs, marker)
			if judged == lfiDataReflected {
				t.Fatalf("lfiJudgeDataScheme = %s (form %s), which the classifier reports as "+
					"data_both_present suspicious/low. The plaintext marker is NOT in this body: only "+
					"the base64 this probe itself sent came back, so the verdict text is a false "+
					"statement about the measurement and the grade is noise on every reflecting route",
					judged, form)
			}
			if judged != lfiDataEchoed {
				t.Fatalf("lfiJudgeDataScheme = %s (form %s), want %s: the endpoint handed back exactly "+
					"the bytes this probe sent and nothing else", judged, form, lfiDataEchoed)
			}
		})
	}
}

func TestLFIStillFlagsTheCaseWhereThePlaintextAndTheBase64BothCameBack(t *testing.T) {
	marker := triage.Marker("zqjk3m1x7p2w9b4t")
	obs := lfiTestL7Observation(t, marker, "rendered: "+string(marker)+"\nsource: ${payload}\n")
	judged, form := lfiJudgeDataScheme(obs, marker)
	if judged != lfiDataReflected {
		t.Fatalf("lfiJudgeDataScheme = %s (form %s), want %s: both the sixteen plaintext bytes and "+
			"the literal base64 are in this body, which is the display-layer-decoded shape that is "+
			"worth a look", judged, form, lfiDataReflected)
	}
}

func TestLFIStillCallsItDecodedWhenOnlyThePlaintextCameBack(t *testing.T) {
	marker := triage.Marker("zqjk3m1x7p2w9b4t")
	obs := lfiTestL7Observation(t, marker, "included: "+string(marker)+"\n")
	judged, _ := lfiJudgeDataScheme(obs, marker)
	if judged != lfiDataDecoded {
		t.Fatalf("lfiJudgeDataScheme = %s, want %s: sixteen bytes that were never in the request "+
			"came back, which is a stream wrapper decoding and emitting", judged, lfiDataDecoded)
	}
}

func TestLFIDoesNotCallItBlockedWhenTheIdenticalBodyIsTheFileItRead(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/sh\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"canary:x:1000:1000:ARS0N_CANARY_OK:/home/canary:/bin/sh\n")
	baseline := []byte("canary oracle. ARS0N_CANARY_OK\n")
	var honest []faOwnObs
	for i, wire := range []string{"/etc/passwd", "%2Fetc%2Fpasswd", "/etc/./passwd", "/etc//passwd"} {
		o := triage.Observation{Status: 200, Body: passwd, BodySHA256: sha256.Sum256(passwd)}
		o.Payload.Wire = []byte(wire)
		honest = append(honest, faOwnObs{ProbeID: triage.ProbeID("LFI-L" + string(rune('1'+i))), Ordinal: uint64(i + 1), Obs: o})
	}
	if !faUniformBlock(faObsOf(honest), baseline) {
		t.Fatal("fixture error: these four payloads must look uniform to faUniformBlock, or the test " +
			"is not exercising the gate that swallowed the positive control")
	}
	live, _ := faDisabledByBaseline(lfiContent, [][]byte{baseline})
	if !lfiBlockRefutedByContent(honest, [][]byte{baseline}, live) {
		t.Fatal("the uniform-block gate still calls this a filter answering. Four distinct payloads " +
			"returned one identical body and that body IS /etc/passwd: a WAF block page does not " +
			"contain root:x:0:0, so this is the same file arriving through four encodings, which is " +
			"the strongest positive shape this class has. Calling it blocked is how /lfi, the class's " +
			"own positive control, came back cannot_determine")
	}
}

func TestLFIStillCallsItBlockedWhenTheIdenticalBodyIsACannedBlockPage(t *testing.T) {
	block := []byte("<html><head><title>403 Forbidden</title></head><body>Request blocked by policy. Ref 8813-A.</body></html>")
	baseline := []byte("canary oracle. ARS0N_CANARY_OK\n")
	var honest []faOwnObs
	for i, wire := range []string{"/etc/passwd", "%2Fetc%2Fpasswd", "/etc/./passwd"} {
		o := triage.Observation{Status: 403, Body: block, BodySHA256: sha256.Sum256(block)}
		o.Payload.Wire = []byte(wire)
		honest = append(honest, faOwnObs{ProbeID: triage.ProbeID("LFI-L" + string(rune('1'+i))), Ordinal: uint64(i + 1), Obs: o})
	}
	live, _ := faDisabledByBaseline(lfiContent, [][]byte{baseline})
	if lfiBlockRefutedByContent(honest, [][]byte{baseline}, live) {
		t.Fatal("a canned 403 with no file content in it must still read as blocked, or the fix has " +
			"traded one silent failure for another")
	}
}
