package utils

import (
	"errors"
	"strings"
	"testing"
)

// A control that cannot fail is not a control. These are the four outcomes it has to tell apart.
func TestTheControlOnlyPassesWhenTheToolActuallyFoundSomething(t *testing.T) {
	spec := CanarySpec{Path: "/xss", Param: "q", Why: "the reason"}

	if got := evaluateCanary(spec, false, 0, nil); got.Ran {
		t.Error("a tool with no control defined must not be reported as having run one, or every " +
			"unconfigured tool would read as a failure and the warning would become noise")
	}
	if got := evaluateCanary(spec, true, 1, nil); !got.Passed {
		t.Error("a finding on the oracle is the whole success condition")
	}
	got := evaluateCanary(spec, true, 0, nil)
	if got.Passed {
		t.Fatal("zero findings against a target we KNOW is vulnerable means the tool did not work. " +
			"This is the entire point: it is the case that produced 53 vectors reported clean in " +
			"forty seconds on an application with SQL injection in it.")
	}
	if !strings.Contains(got.Detail, "the reason") {
		t.Errorf("a failed control must explain itself in the operator's terms, got %q", got.Detail)
	}
	if got := evaluateCanary(spec, true, 0, errors.New("boom")); got.Passed ||
		!strings.Contains(got.Detail, "boom") {
		t.Error("a control run that errored is a failed control, and the error is the explanation")
	}
}

// THE FOREIGN KEY TRAP. vector_scan_vectors.vector_id and vector_findings.vector_id both reference
// attack_vectors(id). A canary is synthetic and is in no table, so writing its id to those columns
// fails the insert, the error is only logged, the scan carries on, and the control records nothing at
// all. This area has hit that exact failure three times already.
func TestTheCanaryRecordsAgainstAURLNotAForeignKey(t *testing.T) {
	row := canaryVectorRow("target-1", "dalfox", vectorCanaries["dalfox"])

	if !row.IsGraphQLTarget {
		t.Fatal("the canary must take the URL-identity path, or its verdict row fails the foreign key " +
			"onto attack_vectors and the control silently records nothing")
	}
	identity := identityFor(row.ID, row.IsBypassTarget, row.IsGraphQLTarget, row.IsLeakTarget,
		row.EvidenceURL)
	if identity.VectorID != nil {
		t.Error("the canary id must NEVER land in vector_id: there is no attack_vectors row for it")
	}
	if identity.TargetURL == nil {
		t.Error("with no vector_id the row needs a target_url, or Postgres treats the all-NULL " +
			"identity as distinct every time and duplicates accumulate on each write")
	}
}

// reportPath does `vector.ID[:8]` with no length check, and the scan goroutine has no recover, so a
// short id panics the run and leaves it stuck on 'running' forever with no error and no completed_at.
func TestTheCanaryIDIsLongEnoughForTheReportPathSlice(t *testing.T) {
	for tool := range vectorCanaries {
		row := canaryVectorRow("target-1", tool, vectorCanaries[tool])
		if len(row.ID) < 8 {
			t.Errorf("%s canary id %q is shorter than the 8 characters reportPath slices, which "+
				"panics an unrecovered goroutine and hangs the scan on 'running'", tool, row.ID)
		}
	}
}

// The same input must produce the same id, or every run creates a new identity and the control's
// history is unreadable.
func TestTheCanaryIDIsStableAcrossRuns(t *testing.T) {
	a := canaryVectorRow("target-1", "sqlmap", vectorCanaries["sqlmap"])
	b := canaryVectorRow("target-1", "sqlmap", vectorCanaries["sqlmap"])
	if a.ID != b.ID {
		t.Error("the canary id must be deterministic so its verdict rows line up across runs")
	}
	c := canaryVectorRow("target-1", "ghauri", vectorCanaries["ghauri"])
	if a.ID == c.ID {
		t.Error("two tools must not share a canary id, or their verdicts collide on the unique index " +
			"and the second one is silently dropped by ON CONFLICT DO NOTHING")
	}
}

// THE ELIGIBILITY TRAP. Every tool filters vectors by insertion point, and a canary the tool cannot
// reach is skipped before it is ever sent. It would then record neither a pass nor a failure, which
// is the quietest possible way for a safety mechanism to do nothing.
func TestEveryDeclaredControlUsesAnInsertionPointItsToolCanReach(t *testing.T) {
	for toolKey, spec := range vectorCanaries {
		tool, ok := VectorToolByKey(toolKey)
		if !ok {
			t.Errorf("a control is declared for %q but no such tool is registered, so it can never "+
				"run", toolKey)
			continue
		}
		if !VectorToolCanReach(tool, spec.InsertionPoint) {
			t.Errorf("%s cannot reach the %q insertion point, so its control would be skipped as "+
				"ineligible and prove nothing at all", toolKey, spec.InsertionPoint)
		}
	}
}

// THE THREE TOOLS THAT HAD NO CONTROL AT ALL.
//
// A tool with no entry in vectorCanaries cannot produce a trustworthy zero, and its total failure is
// invisible. domdig is the proof: it has crashed on 100% of its vectors on three separate runs and
// was recorded "clean" every time. On the run that produced this test, 31 of 31 stored traces crashed
// before a payload was sent, not one of the 45 query vectors was ever tested, and the section
// reported no cross-site scripting.
//
// sstimap and tinja were the other two, for a different reason: the oracle had no template injection
// endpoint, so there was nothing for either of them to be tested against.
func TestTheToolsWhoseSilenceProvedNothingNowHaveAControl(t *testing.T) {
	for toolKey, reason := range map[string]string{
		"domdig": "it has crashed pre-payload on every vector of three separate runs and was filed " +
			"clean each time",
		"sstimap": "a template injection scanner with no template injection to find cannot be shown " +
			"to be working",
		"tinja": "a template injection scanner with no template injection to find cannot be shown " +
			"to be working",
		// Regression guards on the ones that already had a control.
		"commix": "its control was declared but did not fire on the first full run",
		"dalfox": "it has silently verified nothing under a setting it accepted",
		"ghauri": "it filed 53 vectors clean in forty seconds on a rejected option",
	} {
		if _, ok := vectorCanaryFor(toolKey); !ok {
			t.Errorf("%s has no positive control, so its zero is unfalsifiable: %s", toolKey, reason)
		}
	}
}

// THE PARAMETER NAME IS PART OF THE CONTROL. Measured against commix 4.2.dev76, controller.py:314:
//
//	if any(x in check_parameter.lower() for x in settings.HTTP_HEADERS)
//
// with HTTP_HEADERS = ["user-agent", "referer", "host"], matched as a SUBSTRING. `-p host` therefore
// does not name a query parameter at all: commix injects into the Host header, the oracle answers 400
// to a Host it does not serve, --batch answers "N" to "ignore HTTP response code '400'?", and the run
// ends with "Skipping further testing on the target URL." That is exactly what the /cmdi control did,
// and it is why the framework stamped the whole scan UNVERIFIED.
func TestNoControlNamesAParameterCommixReadsAsAnHTTPHeader(t *testing.T) {
	for toolKey, spec := range vectorCanaries {
		for _, reserved := range []string{"host", "referer", "user-agent"} {
			if strings.Contains(strings.ToLower(spec.Param), reserved) {
				t.Errorf("%s control injects into a parameter named %q, which contains commix's "+
					"reserved header name %q. commix matches that list as a substring and would test "+
					"the HTTP header instead of the parameter, so the control cannot fire",
					toolKey, spec.Param, reserved)
			}
		}
	}
}

// A control aimed at a path the oracle does not serve gets a 404 for every payload and fails for a
// reason that has nothing to do with the tool, which is the failure mode that makes operators stop
// reading the stamp. These are the endpoints docker/oracle/main.go registers.
func TestEveryControlAimsAtAnEndpointTheOracleActuallyServes(t *testing.T) {
	served := map[string]bool{
		"/xss": true, "/sqli": true, "/redirect": true, "/lfi": true, "/cmdi": true, "/ssti": true,
	}
	for toolKey, spec := range vectorCanaries {
		if !served[spec.Path] {
			t.Errorf("%s control aims at %s, which the canary oracle does not serve. Every payload "+
				"would 404 and the control would report the tool broken", toolKey, spec.Path)
		}
	}
}

// The synthetic row has to survive the ordinary URL rebuild with its parameter physically present.
// Several tools substitute by matching name=value in the URL TEXT, so a parameter that is not in the
// string matches nothing and the tool reports clean without having tested anything.
func TestTheControlURLCarriesItsParameterWithAValue(t *testing.T) {
	for toolKey, spec := range vectorCanaries {
		got := canaryVectorRow("target-1", toolKey, spec).toInput().TargetURL()
		want := "http://" + canaryHost() + spec.Path + "?" + spec.Param + "=1"
		if got != want {
			t.Errorf("%s control URL rebuilt as %q, want %q", toolKey, got, want)
		}
	}
}

// And it has to survive the tool's own composer, because that is where the URL is assembled into the
// argv that is actually executed. The LFI section shipped a defect of exactly this shape: the target
// URL was built wrongly, every payload went somewhere else, and each affected section reported clean.
func TestTheControlURLReachesTheComposedCommandLine(t *testing.T) {
	// The tools whose composer puts a URL in the argv. Two are excluded on purpose and neither is an
	// oversight: nuclei-dast is driven from a raw request file rather than a URL, and SQLiDetector
	// takes -f with a list of URLs written into its container, so neither command line carries one.
	for _, toolKey := range []string{"commix", "sstimap", "tinja", "domdig", "dalfox", "xssfuzz",
		"sqlmap", "ghauri", "lfimap"} {
		spec, ok := vectorCanaryFor(toolKey)
		if !ok {
			t.Errorf("no control defined for %s", toolKey)
			continue
		}
		tool, ok := VectorToolByKey(toolKey)
		if !ok || tool.Compose == nil {
			t.Errorf("%s is not registered with a composer, so its control can never run", toolKey)
			continue
		}
		args, _ := tool.Compose(canaryVectorRow("target-1", toolKey, spec).toInput(),
			map[string]any{}, "/tmp/report")
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, canaryHost()+spec.Path) {
			t.Errorf("%s composed a command line that never mentions %s: %s",
				toolKey, canaryHost()+spec.Path, joined)
		}
		if !strings.Contains(joined, spec.Param) {
			t.Errorf("%s composed a command line that never mentions the parameter %q: %s",
				toolKey, spec.Param, joined)
		}
	}
}

// The insertion point has to be one of the closed five, because normaliseInsertionPoint returns ""
// for anything else and an empty point matches no eligibility rule.
func TestControlInsertionPointsAreRealOnes(t *testing.T) {
	valid := map[string]bool{}
	for _, p := range VectorInsertionPoints {
		valid[p] = true
	}
	for toolKey, spec := range vectorCanaries {
		if !valid[spec.InsertionPoint] {
			t.Errorf("%s control declares insertion point %q, which is not one of %v",
				toolKey, spec.InsertionPoint, VectorInsertionPoints)
		}
		if strings.TrimSpace(spec.Path) == "" || strings.TrimSpace(spec.Param) == "" {
			t.Errorf("%s control has no path or no parameter, so there is nothing to inject into",
				toolKey)
		}
		if strings.TrimSpace(spec.Why) == "" {
			t.Errorf("%s control has no explanation, so a failure would tell the operator nothing "+
				"about what to do next", toolKey)
		}
	}
}

// The failure message is what an operator reads when told their scan does not count. It has to say
// plainly that the result is not clean, rather than burying it in a status field.
func TestTheFailureMessageRefusesToLetTheResultReadAsClean(t *testing.T) {
	msg := canaryFailureMessage("ghauri", vectorCanaries["ghauri"], 53)
	// Case-insensitive: the message opens with "NOT CLEAN" in capitals for emphasis and closes with
	// "should not be read as clean" in prose. Both carry the point and pinning the exact casing would
	// only make the test brittle against a wording change that improves it.
	lower := strings.ToLower(msg)
	for _, want := range []string{"unverified", "not clean", "53"} {
		if !strings.Contains(lower, want) {
			t.Errorf("the failure message must contain %q so the verdict cannot be misread; got: %s",
				want, msg)
		}
	}
}

// The control inherits the operator's TOOL settings but must not inherit their TARGET settings.
//
// Measured on the first end-to-end run: dalfox found the XSS on the oracle, then ran the inherited
// --session-check-url against the real target's /my-account, failed it, and exited 1 under
// --on-session-loss abort. The control reported a broken tool while the tool was working.
func TestTheControlDoesNotInheritTheTargetsSession(t *testing.T) {
	tool, ok := VectorToolByKey("dalfox")
	if !ok {
		t.Skip("dalfox is not registered")
	}
	operator := map[string]any{
		"sessionCheck":    "Log out",
		"sessionCheckUrl": "https://ginandjuice.shop/my-account",
		"cookies":         "session=abc; AWSALB=def",
		"headers":         "X-Real-Target: yes",
		"onSessionLoss":   "abort",
		"proxy":           "http://127.0.0.1:8080",
		// Tool configuration, which MUST survive: a setting that breaks the tool has to break the
		// control too, or the control stops covering the settings that blind a scanner.
		"rateLimit":           3,
		"workers":             4,
		"maxPayloadsPerParam": 200,
	}
	got := canarySettings(tool, operator)

	for _, gone := range []string{"sessionCheck", "sessionCheckUrl", "cookies", "headers",
		"onSessionLoss", "proxy"} {
		if _, present := got[gone]; present {
			t.Errorf("%q binds to the real target and must not reach the control: a cookie from one "+
				"host is meaningless at another, and a session check against a host the control is "+
				"not testing fails for a reason that has nothing to do with the tool", gone)
		}
	}
	for _, kept := range []string{"rateLimit", "workers", "maxPayloadsPerParam"} {
		if _, present := got[kept]; !present {
			t.Errorf("%q configures the TOOL and must be inherited, or the control stops proving the "+
				"tool works under the settings the operator actually chose", kept)
		}
	}
}

// The positive control is not a finding about the target and must never be listed as one.
//
// MEASURED on the Juice Shop corpus: 11 of 61 stored findings were against the oracle container, and
// they arrived in the operator's findings list indistinguishable from real ones, complete with
// reproduction steps telling the operator to open http://oracle:8000 in a browser. sqlmap's entire
// finding list was 3 oracle and 0 target; SQLiDetector's was 2 and 0. "sqlmap: 3 findings" read as
// three SQL injections on the target and was three injections in the framework's own test fixture.
func TestCanaryFindingsAreNotFindingsOnTheTarget(t *testing.T) {
	// canaryHost() carries a PORT ("oracle:8000"). url.Hostname() does not. The first version of
	// findingIsCanary compared those two directly and therefore matched nothing at all.
	host := hostWithoutPort(canaryHost())
	if host == "" {
		t.Fatal("canaryHost() is empty, so nothing can be recognised as the control")
	}
	if strings.Contains(host, ":") {
		t.Fatalf("hostWithoutPort left a port on %q; the comparison will never match a parsed URL", host)
	}

	// The exact URLs that were stored and shown to the operator.
	for _, raw := range []string{
		"http://" + canaryHost() + "/xss?q=1",
		"http://" + canaryHost() + "/sqli?id=1",
		"http://" + host + "/redirect?to=x",
		"HTTP://" + strings.ToUpper(canaryHost()) + "/xss?q=1",
	} {
		if !findingIsCanary(raw) {
			t.Errorf("findingIsCanary(%q) = false; this control hit would be listed as a finding on "+
				"the operator's target", raw)
		}
	}

	// Real target findings must survive untouched. Over-filtering hides real vulnerabilities, which
	// is the worse direction of this fix by a wide margin.
	for _, raw := range []string{
		"http://10.0.0.18:3000/rest/products/search?q=1",
		"https://ginandjuice.shop/catalog?category=Gifts",
		"http://10.0.0.18:3000/encryptionkeys/jwt.pub",
	} {
		if findingIsCanary(raw) {
			t.Errorf("findingIsCanary(%q) = true; a real finding on the target would be hidden", raw)
		}
	}
}

// Matched on the parsed HOST, not as a substring. A framework aimed at estates that run Oracle will
// meet hostnames containing the word, and swallowing a real finding is far worse than showing a
// control.
func TestCanaryMatchIsHostNotSubstring(t *testing.T) {
	for _, raw := range []string{
		"https://oracle-erp.customer.com/login?next=x",
		"https://myoracle.example.net/a?b=1",
		"https://example.com/oracle/admin?id=1",
		"https://example.com/a?host=oracle",
	} {
		if findingIsCanary(raw) {
			t.Errorf("findingIsCanary(%q) = true; that is a real host and its finding would vanish", raw)
		}
	}
	// Unparseable or empty input is not a control. Defaulting to "control" would hide it.
	for _, raw := range []string{"", "   ", "::::not a url"} {
		if findingIsCanary(raw) {
			t.Errorf("findingIsCanary(%q) = true; an unreadable URL must not be treated as the control", raw)
		}
	}
}

// A control that is only mentioned when it fails trains people to read silence as success, which is
// the same reasoning error as reading "0 findings" as "0 vulnerabilities". So it reports either way.
func TestCanaryOutcomeIsReportedWhetherOrNotItFired(t *testing.T) {
	fired := canaryOutcome("dalfox", []map[string]any{{"id": "x"}}, "")
	if fired["fired"] != true || fired["hit_count"] != 1 {
		t.Errorf("a control that fired is not reported as fired: %#v", fired)
	}
	if !strings.Contains(fired["meaning"].(string), "NOT findings on your target") {
		t.Errorf("the passing message does not say these are not target findings: %q", fired["meaning"])
	}

	silent := canaryOutcome("domdig", nil, "")
	if silent["fired"] != false || silent["hit_count"] != 0 {
		t.Errorf("a control that did not fire is not reported as such: %#v", silent)
	}
	if !strings.Contains(silent["meaning"].(string), "unproven") {
		t.Errorf("a silent control must say the zero is unproven, got %q", silent["meaning"])
	}

	unverified := canaryOutcome("ghauri", nil, "UNVERIFIED: the canary did not fire")
	if !strings.Contains(unverified["meaning"].(string), "can be trusted") {
		t.Errorf("an unverified run must say so plainly, got %q", unverified["meaning"])
	}
}
