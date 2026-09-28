package triageclasses

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
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

// ------------------------------------------------------------------------------------------------
// THE EARLY STOP, AND THE SENTENCE THAT BLAMED THE RUNNER FOR IT
// ------------------------------------------------------------------------------------------------

// lfiTestObs is a response this class could have received. The normalised hash is derived from the
// body so two different bodies never collide, which is what the uniform-block reading turns on.
func lfiTestObs(id string, status int, body string) triage.Observation {
	var norm [32]byte
	for i, b := range []byte(body) {
		norm[i%32] ^= b + byte(i)
	}
	return triage.Observation{
		ObsID: id, RunID: "lfi-stop", Status: status, Kind: triage.ObsProbe,
		Class: triage.ClassLFI, Body: []byte(body), BodyLen: len(body),
		BodySHA256: sha256.Sum256([]byte(body)),
		Proj:       triage.Projections{NormBodySHA256: norm},
		Payload:    triage.PayloadWire{Wire: []byte(id), Survived: triage.WireSurvivalEncoded},
	}
}

func lfiTier1Own(bodies map[triage.ProbeID]string) []faOwnObs {
	var out []faOwnObs
	for _, id := range lfiTier1IDs {
		b, ok := bodies[id]
		if !ok {
			continue
		}
		out = append(out, faOwnObs{ProbeID: id, Obs: lfiTestObs(string(id), 200, b)})
	}
	return out
}

// THE UNIFORM-BLOCK STOP MUST BE MEASURED AGAINST THE BASELINE, WHICH IS THE WHOLE POINT OF THE
// BASELINE.
//
// This is the defect TRAVERSAL found, wrote up above trvUnderStop and fixed, and which this class
// still had: faUniformBlock skips a response only when "len(baseline) > 0 && bytes.Equal(o.Body,
// baseline)", so passing nil makes an endpoint that serves ONE page whatever you send read as
// three distinct payloads producing one identical non-baseline body, which is the signature of a
// filter answering. It is not a filter. It is a route with one page.
//
// MEASURED, canary oracle, the 80-route exam: all 29 LFI not_run cells carried tier2_not_sent,
// /clean/always500 among them, and /clean/always500 returns the same 142 bytes to the baseline and
// to every payload alike. The verdict's OWN block gate, which does pass the baseline, correctly
// did not fire on it; only the planner's copy did.
func TestTheEarlyStopIsMeasuredAgainstTheBaselineAndNotAgainstNothing(t *testing.T) {
	page := "internal server error"
	own := lfiTier1Own(map[triage.ProbeID]string{
		lfiDEC: page, lfiNC1: page, lfiL1: page, lfiL2: page, lfiL16: page,
	})
	if why := lfiStopReason(own, []byte(page)); why != "" {
		t.Errorf("this class stopped its own ladder with %q on an endpoint that answers one identical "+
			"page to the unperturbed control and to every payload alike. Nothing was blocked: every "+
			"response IS the baseline, and tier 2, tier 3 and the blind arm were all suppressed on "+
			"that reading", why)
	}
	// And the positive control: when the three identical bodies are NOT the baseline, that is the
	// shape the gate exists for and it must still fire.
	block := "<html>403 Forbidden: request blocked</html>"
	blocked := lfiTier1Own(map[triage.ProbeID]string{
		lfiDEC: block, lfiNC1: block, lfiL1: block, lfiL2: block, lfiL16: block,
	})
	if why := lfiStopReason(blocked, []byte(page)); why != "uniform_block" {
		t.Errorf("three distinct payloads produced one identical body that is NOT the baseline and "+
			"the gate reported %q. That is a filter answering and the ladder must stop", why)
	}
}

// THE tier2_not_sent SENTENCE MAY NOT BLAME THE RUNNER FOR A DECISION THIS CLASS MADE.
//
// It shipped as "tier 2 (L4, L5, L7, L8) is unconditional by design, because a wrapper works where
// an absolute path does not. Without it this class has tested absolute paths only and must not say
// clean about the rest". True of the DECLARATION in lfiTier2IDs and false of the RUN: Plan round 1
// returns nil whenever lfiStopReason fires, so tier 2 is conditional on the stop in exactly the
// way the sentence denies. An operator reads "unconditional by design" as a runner bug and opens
// triageRun.go, which is the wrong file.
func TestTheTierTwoReasonNamesTheGateThatActuallyFired(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stop   string
		wantIn []string
		notIn  []string
	}{
		{
			name:   "this class chose not to send it",
			stop:   "uniform_block",
			wantIn: []string{"lfiStopReason", "uniform_block", "this class"},
			notIn:  []string{"unconditional by design"},
		},
		{
			name:   "nothing in this class stopped the ladder, so the probes were dropped elsewhere",
			stop:   "",
			wantIn: []string{"no gate in this class", "runner"},
			notIn:  []string{"unconditional by design"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := lfiTier2NotSentReason(tc.stop)
			for _, want := range tc.wantIn {
				if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
					t.Errorf("the reason does not name %q:\n  %s", want, got)
				}
			}
			for _, no := range tc.notIn {
				if strings.Contains(got, no) {
					t.Errorf("the reason still says %q, which is a claim about the declaration and "+
						"not about this run:\n  %s", no, got)
				}
			}
		})
	}
}

// ------------------------------------------------------------------------------------------------
// THE NEGATIVE TAIL: TWO SHAPES THAT WERE MEASURED CLEAN AND HAD NOTHING MEASURED IN THEM
// ------------------------------------------------------------------------------------------------

// lfiFlatOwn is a full ladder in which every response is the SAME response: tier 1, the
// unconditional tier 2 and both errno families, all carrying one identical body.
//
// It is the shape two whole families of oracle route cannot see through, and it is not
// hypothetical: /clean/always500 answers one 142-byte error page to the unperturbed control and
// to every payload alike, and the five fixed-302 routes answer twelve identical bytes to
// everything.
func lfiFlatOwn(status int, body string) []faOwnObs {
	ids := []triage.ProbeID{lfiDEC, lfiNC1, lfiL1, lfiL2, lfiL16, lfiL4, lfiL5, lfiL7, lfiL8,
		lfiL14, lfiL15}
	out := make([]faOwnObs, 0, len(ids))
	for _, id := range ids {
		out = append(out, faOwnObs{ProbeID: id, Obs: lfiTestObs(string(id), status, body)})
	}
	return out
}

func lfiTailOne(state triage.TriageState, reason, oracle string, grade triage.TriageGrade,
	ords []uint64) []triage.ClassVerdict {
	return []triage.ClassVerdict{{
		Class: triage.ClassLFI, SlotKey: "query:file", State: state, Reason: reason,
		Grade: grade, Oracle: oracle, Ordinals: ords,
	}}
}

func lfiTailFactsFor(control triage.Observation) lfiTailFacts {
	return lfiTailFacts{Kind: triage.KindQuery, DecodeDepth: 1, Control: control, HaveControl: true}
}

// A CONTROL THAT IS ALREADY FAILING MAKES EVERY BODY THIS CLASS SEARCHED THE FAILURE'S PAGE.
//
// MEASURED, canary oracle, the 80-route exam. On ONE run, on ONE route, three classes reading the
// same 142 bytes:
//
//	/clean/always500  DESER     cannot_determine  control_already_failing
//	/clean/always500  ORM-LEAK  cannot_determine  junk_sensitive
//	/clean/always500  LFI       clean             "its own oracles stayed silent"
//
// The seven clean preconditions this class listed contained no check that the control itself was
// failing, so the one class of the three that had no such guard reported the green tick.
func TestAnAlreadyFailingControlIsNotAnLFIClean(t *testing.T) {
	page := "<!doctype html><title>Error</title>\n<h1>Something went wrong</h1>\n" +
		"<p>The service could not complete your request. Please try again later.</p>\n"
	control := lfiTestObs("route-control", 500, page)
	v := lfiNegative(lfiFlatOwn(500, page), [][]byte{[]byte(page)}, lfiTailFactsFor(control),
		map[string]any{}, nil, nil, lfiTailOne)
	if len(v) != 1 {
		t.Fatalf("the tail produced %d verdicts, want 1", len(v))
	}
	if v[0].State.CountsAsClean() {
		t.Fatalf("LFI reported %s on an endpoint that answered the SAME %d-byte error page to the "+
			"unperturbed control and to every payload alike. Every oracle in this class reads that "+
			"body, so the pages searched were the failure's and not the application's answer about "+
			"our value: %s", v[0].State, len(page), v[0].Reason)
	}
	if !strings.Contains(v[0].Reason, "control_already_failing") {
		t.Errorf("the refusal does not name control_already_failing, which is what DESER and ORM-LEAK "+
			"call the identical reading on the identical route: %s", v[0].Reason)
	}
}

// AN ENDPOINT THAT ANSWERS EVERY PAYLOAD THE WAY IT ANSWERS A REQUEST CARRYING NONE OF OUR BYTES
// HAS NOT BEEN MEASURED BY THIS CLASS AT ALL.
//
// MEASURED, same exam run: five fixed-302 routes (/redirect/local, /redirect/fixed,
// /redirect/loginwrap, /redirect/strictvalidator, /redirect/alwaysoffsite) answer twelve identical
// body bytes to the control and to every payload. HPP refuses that shape as route_insensitive and
// LFI called it clean. The body is not empty and the status is not 5xx, so neither arm of
// pxReadsBody sees it: this is the class's own value_insensitive, the one NOSQL and TRAVERSAL
// already carry.
func TestARouteThatAnswersEveryPayloadIdenticallyIsNotAnLFIClean(t *testing.T) {
	body := "redirecting"
	control := lfiTestObs("route-control", 302, body)
	v := lfiNegative(lfiFlatOwn(302, body), [][]byte{[]byte(body)}, lfiTailFactsFor(control),
		map[string]any{}, nil, nil, lfiTailOne)
	if len(v) != 1 {
		t.Fatalf("the tail produced %d verdicts, want 1", len(v))
	}
	if v[0].State.CountsAsClean() {
		t.Fatalf("LFI reported %s on a route that returned the unperturbed control's own %d bytes to "+
			"every payload it was sent. No content signature, no marker, no stack error and no errno "+
			"difference can appear in a response that is byte-identical to one carrying none of our "+
			"bytes, so nothing was read here: %s", v[0].State, len(body), v[0].Reason)
	}
	if !strings.Contains(v[0].Reason, "route_insensitive") {
		t.Errorf("the refusal does not name route_insensitive: %s", v[0].Reason)
	}
}

// THE OTHER HALF, AND THE REASON THIS IS NOT A LICENCE TO REFUSE EVERYTHING. An endpoint that
// answers differently to the payloads is one this class CAN read, and its silence there is the
// application's answer and must stay a clean.
func TestARouteThatAnswersDifferentlyStillReachesTheLFIClean(t *testing.T) {
	control := lfiTestObs("route-control", 200, "you asked for readme")
	own := lfiFlatOwn(200, "no such file")
	v := lfiNegative(own, [][]byte{[]byte("you asked for readme")}, lfiTailFactsFor(control),
		map[string]any{}, nil, nil, lfiTailOne)
	if len(v) != 1 {
		t.Fatalf("the tail produced %d verdicts, want 1", len(v))
	}
	if v[0].State != triage.StateClean {
		t.Fatalf("state %s, want clean: this endpoint answered each payload differently, so the "+
			"oracles had something to read and their silence is a measurement: %s", v[0].State, v[0].Reason)
	}
}

// A CONTROL THAT REFUSES EVERYONE IS THE 4xx HALF OF THE SAME FACT, AND THE MECHANISM DID NOT
// COVER IT.
//
// pxBodySurfaceUnreadable is the shared precondition for every class that declares pxReadsBody,
// and its control arm is a bare status >= 500 copied from ORM-LEAK. That leaves the shape the
// operator's live estate is mostly made of: 88% of probes against it come back 401. The
// credential-carrying case is caught by the auth gate; a vector with NO credential against an
// endpoint that refuses everyone fell through both and landed on a clean.
//
// pxControlRefusesEveryone is the missing arm. The second half of this test is the one that
// matters most: an endpoint that refuses the control and ANSWERS a payload has given the class a
// body to read, and the arm must not touch it.
func TestTheBodySurfacePreconditionCoversAControlThatRefusesEveryone(t *testing.T) {
	page := `{"error":"not found"}`
	control := lfiTestObs("route-control", 404, page)

	why, absent := pxControlRefusesEveryone(lfiFlatOwn(404, page), control, true)
	if !absent {
		t.Fatalf("the 4xx arm let through an endpoint that answered 404 with the SAME %d bytes to the "+
			"unperturbed control and to every probe. Every body searched was the page this endpoint "+
			"hands a request it is refusing, so a negative read out of it is the refusal's silence "+
			"and not the application's", len(page))
	}
	if !strings.Contains(why, "control_refuses_everyone") {
		t.Errorf("the refusal does not name control_refuses_everyone: %s", why)
	}
	if !strings.Contains(why, "404") {
		t.Errorf("the refusal does not name the status it measured, so a reader cannot check it: %s", why)
	}

	// THE NARROWNESS, and it is the whole reason this arm is not a bare status test. A 404 to the
	// observed value is an ordinary answer. One payload that moves the endpoint means there was a
	// real body to read, and the class must be allowed to read it.
	answered := lfiFlatOwn(404, page)
	answered[3].Obs = lfiTestObs(string(answered[3].ProbeID), 200, "root:x:0:0:root:/root:/bin/sh")
	if why, absent := pxControlRefusesEveryone(answered, control, true); absent {
		t.Errorf("the arm refused an endpoint that answered one of this class's payloads differently "+
			"from the control. That endpoint handed the oracles a body, and refusing there deletes "+
			"true negatives rather than false ones: %s", why)
	}

	// AND A 5xx CONTROL IS NOT THIS ARM'S BUSINESS: pxBodySurfaceUnreadable already refuses it on
	// one witness, and answering twice in two voices helps nobody.
	if why, absent := pxControlRefusesEveryone(lfiFlatOwn(500, page),
		lfiTestObs("route-control", 500, page), true); absent {
		t.Errorf("the 4xx arm fired on a 5xx control, which the shared precondition already refuses "+
			"for a different and stronger reason: %s", why)
	}
}

// A PRECONDITION LIST MAY NOT PRINT A FACT NOBODY MEASURED.
//
// Every guard added in this round is a statement about the UNPERTURBED ROUTE CONTROL, and on a
// slot where no control resolved not one of them ran: pxBodySurfaceUnreadable skips its control
// arm, and both route arms return false on the spot. A clean that still listed "the control did
// not answer 5xx" would be the stale-fact failure in its purest form, and it would be read by an
// operator as a check that passed.
func TestTheLFICleanDoesNotClaimControlFactsWhenThereWasNoControl(t *testing.T) {
	own := lfiFlatOwn(200, "no such file")
	facts := lfiTailFacts{Kind: triage.KindQuery, DecodeDepth: 1} // HaveControl is false
	var got []triage.ClassVerdict
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade,
		ords []uint64) []triage.ClassVerdict {
		got = []triage.ClassVerdict{{State: state, Reason: reason, Annotations: ann}}
		return got
	}
	v := lfiNegative(own, [][]byte{[]byte("baseline")}, facts, ann, nil, nil, one)
	if v[0].State != triage.StateClean {
		t.Fatalf("state %s, want clean: with no route control the new guards cannot fire, and refusing "+
			"here would delete every clean on a slot whose control did not resolve: %s", v[0].State, v[0].Reason)
	}
	lines, _ := ann["clean_preconditions"].([]string)
	if len(lines) == 0 {
		t.Fatal("the clean carries no preconditions at all")
	}
	joined := strings.Join(lines, " | ")
	if strings.Contains(joined, "did not itself answer 5xx") ||
		strings.Contains(joined, "THE ENDPOINT IS NOT FLAT") ||
		strings.Contains(joined, "NOT REFUSING EVERYONE") {
		t.Errorf("the clean lists a control fact on a slot that had no control, so it asserts three "+
			"checks that did not run: %s", joined)
	}
	if !strings.Contains(joined, "NOT CHECKED on this slot") {
		t.Errorf("the clean does not say which checks were skipped for want of a control: %s", joined)
	}
}

// ---------------------------------------------------------------------------------------------
// ROUND 8: route_insensitive MAY NOT DENY WHAT THE OTHER CHANNEL DID
// ---------------------------------------------------------------------------------------------

// lfiHdrObs is one of this class's own observations with response headers on it, which lfiTestObs
// does not carry. The header channel is the whole subject of the two tests below and it is the
// one thing the existing fixtures cannot express.
func lfiHdrObs(id triage.ProbeID, status int, body string, headers ...[2]string) faOwnObs {
	o := lfiTestObs(string(id), status, body)
	o.RespHeaders = append([][2]string{}, headers...)
	return faOwnObs{ProbeID: id, Ordinal: 11, Obs: o}
}

func lfiHdrCtl(status int, body string, headers ...[2]string) triage.Observation {
	o := lfiTestObs("route-control", status, body)
	o.RespHeaders = append([][2]string{}, headers...)
	return o
}

// THE FOUR ROUTES THIS TEST IS WRITTEN FROM, MEASURED AND NOT RECALLED. /redirect/local answers
// twelve constant body bytes to everything and puts the slot's value straight into Location:
// "Location: hppa&hppdup=hppb" to one probe and "Location: hppa-hppdup-hppb" to the next.
// /redirect/loginwrap, /redirect/strictvalidator and /crlf/setcookie do the same in Location and
// in Set-Cookie. On all four, lfiRouteInsensitive shipped "came back INDISTINGUISHABLE from the
// unperturbed route control" and "That is true of any payload anyone could send", and both
// sentences are false there: the responses are distinguishable, and the endpoint is demonstrably
// reading what we sent.
//
// THE DECISION IS NOT WHAT IS BEING FIXED. Every oracle in this class searches a BODY, so a
// moving Location hands them nothing, and counting it as movement returns LFI to clean on five
// routes whose bodies never change. The sentence is what was bigger than the measurement.
func TestLFIRouteInsensitiveDoesNotCallAMovingHeaderIndistinguishable(t *testing.T) {
	const body = "redirecting"
	control := lfiHdrCtl(302, body, [2]string{"Location", "/go?u=control"})
	honest := []faOwnObs{
		lfiHdrObs(lfiL1, 302, body, [2]string{"Location", "/go?u=alpha"}),
		lfiHdrObs(lfiL2, 302, body, [2]string{"Location", "/go?u=beta"}),
		lfiHdrObs(lfiL4, 302, body, [2]string{"Location", "/go?u=gamma"}),
	}
	why, flat := lfiRouteInsensitive(honest, control, true)
	if !flat {
		t.Fatalf("the refusal stopped firing on an endpoint whose status and body never move. "+
			"Widening THIS decision to the header channel is what returns LFI to clean on "+
			"/redirect/local, /redirect/fixed, /redirect/loginwrap, /redirect/strictvalidator and "+
			"/redirect/alwaysoffsite, where all four of its oracles search a body that never "+
			"changed: %s", why)
	}
	if strings.Contains(why, "INDISTINGUISHABLE") {
		t.Errorf("the reason still calls two responses with different Location headers "+
			"indistinguishable: %s", why)
	}
	if strings.Contains(why, "out. That is true of any payload anyone could send") {
		t.Errorf("the reason still generalises an UNQUALIFIED null result to every payload that "+
			"exists, on an endpoint that answered three probes with three different Locations. The "+
			"generalisation is only true of the channel this class reads and the sentence has to "+
			"say so: %s", why)
	}
	for _, want := range []string{
		"THE SAME STATUS AND THE SAME NORMALISED BODY",
		"ON THAT CHANNEL that is true of any payload anyone could send",
		"3 of those probes",
		"location",
	} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason does not contain %q, so a reader cannot tell which channel was read "+
				"or what the other one saw: %s", want, why)
		}
	}
}

// AND WHERE NOTHING MOVED IN EITHER CHANNEL THE SECOND SENTENCE MUST BE ABSENT. A caveat printed
// on every row is a caveat nobody reads, and "0 probes came back with a different header" is the
// same overclaim pointing the other way.
func TestLFIRouteInsensitiveStaysSilentAboutHeadersThatDidNotMove(t *testing.T) {
	const body = "redirecting"
	control := lfiHdrCtl(302, body, [2]string{"Location", "/account/home"})
	honest := []faOwnObs{
		lfiHdrObs(lfiL1, 302, body, [2]string{"Location", "/account/home"}),
		lfiHdrObs(lfiL2, 302, body, [2]string{"Location", "/account/home"}),
	}
	why, flat := lfiRouteInsensitive(honest, control, true)
	if !flat {
		t.Fatalf("the refusal did not fire on an endpoint that answered everything identically "+
			"in both channels: %s", why)
	}
	if strings.Contains(why, "THE OTHER CHANNEL DID MOVE") {
		t.Errorf("the reason reports header movement on an endpoint whose headers are identical "+
			"to the control's: %s", why)
	}
}

// THE BACKSTOP AT lfi.go IS UNREACHABLE, AND THAT IS A PROPERTY RATHER THAN AN ACCIDENT.
//
// The ladder asks pxNoEvidenceToRead(pxReadsBody, ...) and then pxControlRefusesEveryone. The 4xx
// arm inside pxBodySurfaceUnreadable and pxControlRefusesEveryone are the same four comparisons,
// so the first call answers on every input the second would answer on, and the second line can
// never be the one that returns. The round-7 verifier flagged the comment above it as stale and
// warned that the next round would either redo work already done or delete the reachable copy.
//
// This test is the thing that keeps the answer current. It fails the moment either predicate is
// narrowed, which is exactly when the backstop stops being a backstop and starts being the arm.
func TestTheLFIFourHundredBackstopIsUnreachableBecauseTheSharedArmRunsFirst(t *testing.T) {
	page := `{"error":"not found"}`
	for _, c := range []struct {
		name    string
		status  int
		own     []faOwnObs
		control triage.Observation
	}{
		{"404 reproduced by every probe", 404, lfiFlatOwn(404, page), lfiTestObs("rc", 404, page)},
		{"401 reproduced by every probe", 401, lfiFlatOwn(401, page), lfiTestObs("rc", 401, page)},
		{"403 reproduced by every probe", 403, lfiFlatOwn(403, page), lfiTestObs("rc", 403, page)},
		{"429 reproduced by every probe", 429, lfiFlatOwn(429, page), lfiTestObs("rc", 429, page)},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, backstop := pxControlRefusesEveryone(c.own, c.control, true)
			shared, first := pxNoEvidenceToRead(pxReadsBody, c.own, c.control, true)
			if backstop && !first {
				t.Fatalf("the backstop fired where the shared precondition did not, so lfi.go's " +
					"second 4xx line is LOAD BEARING and the comment calling it a backstop is now " +
					"wrong. Fix the comment, not this test")
			}
			if backstop && !strings.Contains(shared, "control_refuses_everyone") {
				t.Errorf("the shared precondition answered first with something other than the 4xx "+
					"arm, so the two are no longer the same rule: %s", shared)
			}
		})
	}
}

// The nothing-sent ladder asks the planner before it asks the budget. See pxbudgetarm.go.
//
// This class has TWO derived sets and the ladder must read the same branch Plan reads: a path
// slot whose percent handling refuses %2F gets lfiPathNoSlashIDs and everything else gets
// lfiTier1IDs. Both are non-empty, so LFI's not_planned arm is structurally unreachable and its
// nothing-sent rows are honestly about the cap; what the conversion buys is the sentence, which
// no longer dates the cap to before this class planned when nothing measured that order.
func TestLFINothingSentReadsTheSameDerivedSetPlanReads(t *testing.T) {
	if len(lfiTier1IDs) == 0 || len(lfiPathNoSlashIDs) == 0 {
		t.Fatal("one of this class's derived sets is empty, so the comment above is wrong and the " +
			"not_planned arm is reachable after all")
	}
	src, err := os.ReadFile(filepath.Join(packageDirOf(t), "lfi.go"))
	if err != nil {
		t.Fatalf("read lfi.go: %v", err)
	}
	text := string(src)
	// The %2F branch is Plan's, and the ladder now carries the same condition. Two occurrences:
	// one in Plan, one in Classify's nothing-sent ladder.
	if n := strings.Count(text, "ctx.Slot.Kind == triage.KindPath && ctx.Slot.Constraints.PctRejected"); n != 2 {
		t.Errorf("the %%2F branch appears %d time(s) in lfi.go, want 2 (Plan and the nothing-sent "+
			"ladder). If the ladder stops reading the branch Plan reads, it is counting probes this "+
			"class would never have sent on this slot", n)
	}
	if !strings.Contains(text, "pxNothingSentTail(ctx, len(derived)") {
		t.Error("the nothing-sent ladder does not hand pxNothingSentTail the derived count, so the " +
			"ordering and the sentence are being asserted by the class again")
	}
}
