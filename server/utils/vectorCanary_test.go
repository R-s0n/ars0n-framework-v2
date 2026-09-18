package utils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
	fired := canaryOutcome("dalfox", []map[string]any{{"id": "x"}}, "", false)
	if fired["fired"] != true || fired["hit_count"] != 1 {
		t.Errorf("a control that fired is not reported as fired: %#v", fired)
	}
	if !strings.Contains(fired["meaning"].(string), "NOT findings on your target") {
		t.Errorf("the passing message does not say these are not target findings: %q", fired["meaning"])
	}

	silent := canaryOutcome("domdig", nil, "", false)
	if silent["fired"] != false || silent["hit_count"] != 0 {
		t.Errorf("a control that did not fire is not reported as such: %#v", silent)
	}
	if !strings.Contains(silent["meaning"].(string), "unproven") {
		t.Errorf("a silent control must say the zero is unproven, got %q", silent["meaning"])
	}

	unverified := canaryOutcome("ghauri", nil, "UNVERIFIED: the canary did not fire", false)
	if !strings.Contains(unverified["meaning"].(string), "can be trusted") {
		t.Errorf("an unverified run must say so plainly, got %q", unverified["meaning"])
	}
}

// ---------------------------------------------------------------------------------------------
// REUSING A PASSING CONTROL.
//
// A reused control is only defensible if the things that could make yesterday's pass a lie actually
// invalidate it. Every one of those is tested here by making the change and asserting a MISS, which
// is the only direction of this feature that can hurt anyone: a false miss costs 49 to 129 seconds,
// a false hit certifies a blind scanner.

// fakeOracle stands in for the canary oracle. It answers with the marker header that distinguishes a
// real handler from the index fallthrough, which is what canaryServesSpec checks for.
func fakeOracle(t *testing.T, marker bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if marker {
			w.Header().Set("X-Ars0n-Oracle", "sqli")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// canaryTestbed wires a tool, a live fake oracle, a stubbed container fingerprint and a stopped
// clock, and clears the process-wide evidence so tests cannot leak into one another.
func canaryTestbed(t *testing.T, marker bool) (VectorTool, CanarySpec, *string, *time.Time,
	*httptest.Server) {
	t.Helper()
	tool, ok := VectorToolByKey("sqlmap")
	if !ok {
		t.Skip("sqlmap is not registered")
	}
	spec := vectorCanaries["sqlmap"]

	srv := fakeOracle(t, marker)
	t.Setenv("ARS0N_CANARY_HOST", strings.TrimPrefix(srv.URL, "http://"))

	state := "container-abc|image-1|2026-09-18T10:00:00Z|true"
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	prevState, prevNow := canaryContainerState, canaryNow
	canaryContainerState = func(context.Context, string) (string, bool) {
		if state == "" {
			return "", false
		}
		return state, true
	}
	canaryNow = func() time.Time { return now }

	canaryEvidenceMu.Lock()
	canaryEvidenceByTool = map[string]canaryPass{}
	canaryProbation = map[string]bool{}
	canaryEvidenceMu.Unlock()

	t.Cleanup(func() {
		canaryContainerState, canaryNow = prevState, prevNow
		canaryEvidenceMu.Lock()
		canaryEvidenceByTool = map[string]canaryPass{}
		canaryProbation = map[string]bool{}
		canaryEvidenceMu.Unlock()
	})
	return tool, spec, &state, &now, srv
}

// The baseline both directions are measured against: a fresh pass, nothing changed, reused.
func TestAFreshPassIsReusedWhenNothingHasChanged(t *testing.T) {
	tool, spec, _, now, _ := canaryTestbed(t, true)
	settings := map[string]any{"level": 2}
	section := map[string]any{"listeningWebhookURL": ""}

	if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, section); reused {
		t.Fatal("nothing has been proven yet, so the very first control of a campaign must be run for " +
			"real; a cache that answers before it has been filled is not a cache")
	}

	recordCanaryPass(context.Background(), tool, spec, settings, section)
	*now = now.Add(9 * time.Minute)

	outcome, reused := canaryReusablePass(context.Background(), tool, spec, settings, section)
	if !reused {
		t.Fatal("an unchanged tool, settings, container and oracle nine minutes later is the whole " +
			"case this exists for")
	}
	if !outcome.Ran || !outcome.Passed || !outcome.Reused {
		t.Errorf("a reused pass must still read as a control that ran and passed, and must say it was " +
			"reused; got " + fmt.Sprintf("%#v", outcome))
	}
	if outcome.Age != 9*time.Minute {
		t.Errorf("the age of the evidence is what makes the weaker claim readable, got %v", outcome.Age)
	}
}

// THE INVALIDATIONS. Each one records a pass, changes exactly one thing, and requires a miss.
func TestEveryChangeThatCouldMakeThePassALieInvalidatesIt(t *testing.T) {
	settings := map[string]any{"level": 2, "risk": 1}
	section := map[string]any{"listeningWebhookURL": ""}

	for name, tc := range map[string]struct {
		change      func(t *testing.T, state *string, now *time.Time, srv *httptest.Server)
		askSettings map[string]any
		askSection  map[string]any
		why         string
	}{
		"a tool setting changed": {
			askSettings: map[string]any{"level": 5, "risk": 1},
			why: "the pass was taken under --level 2; it says nothing about what the tool does at " +
				"--level 5, and a setting the tool silently rejects is the defect class this control " +
				"was built for",
		},
		"a section setting changed": {
			askSection: map[string]any{"listeningWebhookURL": "https://hook.example/x"},
			why: "section settings reach the composer, so a change to one can change the command line " +
				"that was proven to work",
		},
		"the container was restarted": {
			change: func(t *testing.T, state *string, _ *time.Time, _ *httptest.Server) {
				*state = "container-abc|image-1|2026-09-18T11:59:00Z|true"
			},
			why: "a restart is a different process with a different filesystem state, and it is the " +
				"invalidation an operator triggers without ever thinking about the canary",
		},
		"the image was rebuilt": {
			change: func(t *testing.T, state *string, _ *time.Time, _ *httptest.Server) {
				*state = "container-def|image-2|2026-09-18T11:59:00Z|true"
			},
			why: "a new image is a new tool version, and a tool version change is exactly what the " +
				"ghauri --delay defect was",
		},
		"the container is not running": {
			change: func(t *testing.T, state *string, _ *time.Time, _ *httptest.Server) {
				*state = ""
			},
			why: "a container that is not running cannot be the thing that passed ten minutes ago in " +
				"any sense worth acting on, and docker inspect failing means we do not know what is " +
				"there at all",
		},
		"the pass has expired": {
			change: func(t *testing.T, _ *string, now *time.Time, _ *httptest.Server) {
				*now = now.Add(canaryEvidenceTTL)
			},
			why: "the TTL is the only guard against a slow degradation that none of the explicit " +
				"invalidations can see, so it has to bite exactly at the boundary",
		},
		"the pass has been spent": {
			change: func(t *testing.T, _ *string, _ *time.Time, _ *httptest.Server) {},
			why: "the use cap is what stops a fast tool getting hundreds of scans out of one control " +
				"inside the TTL",
		},
		"the oracle is down": {
			change: func(t *testing.T, _ *string, _ *time.Time, srv *httptest.Server) {
				srv.Close()
			},
			why: "reuse is a claim about a test rig, and a rig nobody can see is not one to make " +
				"claims about",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tool, spec, state, now, srv := canaryTestbed(t, true)
			recordCanaryPass(context.Background(), tool, spec, settings, section)

			if name == "the pass has been spent" {
				for i := 0; i < canaryEvidenceMaxUses; i++ {
					if _, ok := canaryReusablePass(context.Background(), tool, spec, settings,
						section); !ok {
						t.Fatalf("use %d of %d was refused; the cap must not bite early or the "+
							"saving disappears", i+1, canaryEvidenceMaxUses)
					}
				}
			}
			if tc.change != nil {
				tc.change(t, state, now, srv)
			}
			askSettings, askSection := settings, section
			if tc.askSettings != nil {
				askSettings = tc.askSettings
			}
			if tc.askSection != nil {
				askSection = tc.askSection
			}

			if _, reused := canaryReusablePass(context.Background(), tool, spec, askSettings,
				askSection); reused {
				t.Errorf("the stored pass was reused after %s. %s", name, tc.why)
			}
		})
	}
}

// A STALE ORACLE IS NOT A LIVE ONE. Measured once already: an oracle image that served no /ssti
// answered 200 there out of its index handler, and the control ran against a page with no template
// in it. /health was fine throughout. A reused pass must not inherit that, so the reuse check asks
// for the control's own path and requires the marker header a real handler sets.
func TestAnOracleServingTheIndexPageDoesNotKeepAPassAlive(t *testing.T) {
	tool, spec, _, _, _ := canaryTestbed(t, false)
	settings := map[string]any{"level": 2}

	recordCanaryPass(context.Background(), tool, spec, settings, nil)
	if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, nil); reused {
		t.Error("the oracle answered 200 without the X-Ars0n-Oracle marker, which is what a stale " +
			"image's index fallthrough looks like, and the pass was reused anyway")
	}
}

// A FAILURE ENDS THE REUSE IMMEDIATELY, AND ONE PASS DOES NOT RESTART IT.
//
// The failure drops the evidence whatever key it was taken under: the pass said the tool works and
// the failure says nobody knows what the tool is doing. The probation is the second half: a single
// pass after a failure could be the flap rather than the fix, and caching a flap is how a cache ends
// up certifying a broken tool for the next half hour.
func TestAFailedControlEndsReuseAndTheNextPassIsNotBelievedOnItsOwn(t *testing.T) {
	tool, spec, _, now, _ := canaryTestbed(t, true)
	settings := map[string]any{"level": 2}

	recordCanaryPass(context.Background(), tool, spec, settings, nil)
	recordCanaryFailure(tool.Key)

	if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, nil); reused {
		t.Fatal("a control that has just FAILED left a usable pass behind; that is the cache " +
			"certifying a tool we have direct evidence is not working")
	}

	// First pass after the failure: run for real, believed for this scan, not stored.
	recordCanaryPass(context.Background(), tool, spec, settings, nil)
	if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, nil); reused {
		t.Error("one pass after a failure is not enough to resume reuse; it could be the flap " +
			"rather than the fix")
	}

	// Second consecutive pass: the tool has proven itself twice, reuse resumes.
	recordCanaryPass(context.Background(), tool, spec, settings, nil)
	*now = now.Add(time.Minute)
	if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, nil); !reused {
		t.Error("after two consecutive passes the probation must end, or a tool that failed once " +
			"pays the full control cost for the rest of the campaign")
	}
}

// Two scans of the same tool at once must not both spend the last use, or the cap is advisory.
func TestConcurrentScansCannotOverspendOnePass(t *testing.T) {
	tool, spec, _, _, _ := canaryTestbed(t, true)
	settings := map[string]any{"level": 2}
	recordCanaryPass(context.Background(), tool, spec, settings, nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0
	for i := 0; i < canaryEvidenceMaxUses*3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, reused := canaryReusablePass(context.Background(), tool, spec, settings, nil); reused {
				mu.Lock()
				hits++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if hits > canaryEvidenceMaxUses {
		t.Errorf("one pass was reused %d times against a cap of %d; the cap has to hold under the "+
			"concurrency the runner actually has", hits, canaryEvidenceMaxUses)
	}
}

// The stored scan has to say which claim it is making. A clean result backed by a control from
// twenty minutes ago is a different thing to read than one backed by a control from this run, and
// the operator is the one who decides whether that matters.
func TestTheRecordSaysWhetherTheControlWasFreshOrReused(t *testing.T) {
	fresh := canaryPassReason("sqlmap", CanaryOutcome{Ran: true, Passed: true})
	if !strings.Contains(fresh, "PASSED") || strings.Contains(strings.ToUpper(fresh), "REUSED") {
		t.Errorf("a fresh control must not read as a reused one: %q", fresh)
	}

	reused := canaryPassReason("ghauri", CanaryOutcome{Ran: true, Passed: true, Reused: true,
		Age: 21 * time.Minute})
	for _, want := range []string{"PASSED", "REUSED", "21m", "ghauri"} {
		if !strings.Contains(reused, want) {
			t.Errorf("the reused-control record must contain %q so the weaker claim is legible; "+
				"got %q", want, reused)
		}
	}
	if canaryReusedStatus == "findings" || canaryReusedStatus == "error" {
		t.Error("a reused control produced no findings and is not an error; sharing either status " +
			"puts it in a list the results modal means something else by")
	}
}

// A REUSED PASS MUST NOT RENDER AS "NO CONTROL HIT".
//
// canaryOutcome derived everything from len(hits), and a reused pass runs no tool so it stores no
// findings. Wired without this, a control that PASSED produced the operator-facing warning "No
// control hit was recorded ... a zero against the target is unproven either way", which is the
// fastest way to teach someone to ignore the one warning that matters.
//
// It must also stay DISTINGUISHABLE from a fresh pass. "Verified" and "verified by a result from
// twenty minutes ago" are different claims and the reader is entitled to know which one they have.
func TestAReusedControlReadsAsPassedAndSaysItWasReused(t *testing.T) {
	reused := canaryOutcome("sqlmap", nil, "", true)
	if reused["fired"] != true {
		t.Errorf("a reused pass is not reported as fired: %#v", reused)
	}
	if reused["reused"] != true {
		t.Errorf("a reused pass does not say so: %#v", reused)
	}
	meaning := reused["meaning"].(string)
	if strings.Contains(meaning, "unproven") || strings.Contains(meaning, "No control hit") {
		t.Errorf("a passing control renders as a warning: %q", meaning)
	}
	if !strings.Contains(meaning, "REUSED") {
		t.Errorf("a reused pass is indistinguishable from a fresh one: %q", meaning)
	}

	// And a fresh pass must not claim reuse.
	fresh := canaryOutcome("sqlmap", []map[string]any{{"id": "x"}}, "", false)
	if fresh["reused"] != false || strings.Contains(fresh["meaning"].(string), "REUSED") {
		t.Errorf("a fresh pass claims to be reused: %#v", fresh)
	}
}
