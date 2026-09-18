package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// POSITIVE CONTROLS.
//
// Every scanner in this framework fails open. Handed an option it does not understand, a session that
// has died, or a flag it silently ignores, it exits having sent nothing and the runner writes
// "clean". A clean result and a never-ran result are byte-identical in the results modal, and clean
// is the one an operator acts on.
//
// This is the whole defect class this project spent an engagement discovering one instance at a time:
// ghauri rejecting a fractional --delay and filing 53 vectors clean in forty seconds; Forbidden
// printing a usage banner and exiting ZERO; dalfox aborting on a lost session and recording no XSS on
// an application that documents four; dalfox handed --user-agent and silently verifying nothing.
// Every one of them was found by hand, after the fact, on a target that happened to be known
// vulnerable. On an unknown target every one of them would have been believed.
//
// A canary closes that. Each run also tests a target this framework KNOWS is vulnerable, in the same
// scan, through the same composer, the same argv, the same parser and the same storage path. If the
// tool does not find the thing that is definitely there, the run proved nothing, and its verdict on
// the real target is withheld rather than reported.
//
// WHY IT MUST GO THROUGH THE WHOLE PIPELINE. It would be cheaper to check that the binary answers
// --version. That would have caught almost none of the above. The ghauri defect was in an option
// table, the Forbidden defect was in argv construction, the dalfox defect was in a settings value,
// and one earlier defect was in vectorAPI's NULL handling which hid findings for ten tools after they
// had been found and stored correctly. A control is only worth what it covers, so this one is a real
// vector run end to end and is special-cased nowhere.

// canaryHost is where the oracle lives on the compose network. Overridable so the framework can be
// pointed at a different control target, but it defaults to the service that ships with it.
func canaryHost() string {
	if v := strings.TrimSpace(os.Getenv("ARS0N_CANARY_HOST")); v != "" {
		return v
	}
	return "oracle:8000"
}

// canaryOracleContainer names the container behind canaryHost(), so its identity can go in the
// reuse key. Derived from the host rather than hardcoded, because ARS0N_CANARY_HOST is settable and
// a key that fingerprinted the wrong container would fail closed forever (harmless) or match a
// container nobody is using (not harmless).
func canaryOracleContainer() string {
	host := canaryHost()
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "" || host == "localhost" || host == "127.0.0.1" {
		return ""
	}
	// Compose names it <project>-<service>-1 and the service is what the host resolves to.
	return "ars0n-framework-v2-" + host + "-1"
}

// CanarySpec describes one tool's positive control: where to send it, and what finding proves the
// tool worked.
type CanarySpec struct {
	// Path and Param locate the deliberately vulnerable input on the oracle.
	Path  string
	Param string
	// Method is the verb the vector carries. Most controls are GET.
	Method string
	// InsertionPoint has to be one this tool can actually reach, or the canary is skipped as
	// ineligible and proves nothing. The eligibility rules are per tool and per insertion point, so
	// this is declared rather than assumed.
	InsertionPoint string
	// Why explains, in the operator's terms, what a failure of this control means. It is shown when
	// the control fails, so it is written for the person reading the results modal rather than for the
	// person who wrote the code.
	Why string
}

// vectorCanaryFor returns the positive control for a tool, if one is defined.
//
// DELIBERATELY OPT-IN PER TOOL. A tool with no entry here behaves exactly as it did before: it can
// still report clean without proving anything, and that is a known gap rather than a hidden one. The
// alternative, inventing a control for every tool at once, would mean shipping controls that have
// never been observed to pass, and a control that fails for its own reasons is worse than none: it
// trains the operator to ignore the warning.
func vectorCanaryFor(toolKey string) (CanarySpec, bool) {
	spec, ok := vectorCanaries[toolKey]
	return spec, ok
}

var vectorCanaries = map[string]CanarySpec{
	// Reflected, unencoded, into both an HTML text position and a single-quoted JavaScript string.
	// Verified: dalfox 3.2.1 reports one finding, type V, detection_method dom-verification.
	"dalfox": {
		Path: "/xss", Param: "q", Method: "GET", InsertionPoint: "query",
		Why: "dalfox found no XSS on a page that reflects the parameter unencoded into both an HTML " +
			"position and a JavaScript string. It cannot have been testing anything, so its clean " +
			"result on the real target means nothing. Check the settings for an option it rejected " +
			"or silently ignored, and check that the session is still live.",
	},
	"xssfuzz": {
		Path: "/xss", Param: "q", Method: "GET", InsertionPoint: "query",
		Why: "xssFuzz found no reflection on a page that echoes the parameter back verbatim. Since it " +
			"does a plain substring match, a miss here means no request was sent or no response was " +
			"read, not that the payload was neutralised.",
	},
	// Boolean, error and time differentials all present. Verified by hand against the oracle:
	// AND 1=1 shows the row, AND 1=2 hides it, an odd quote returns 500 with a PSQLException, and an
	// injected sleep really sleeps.
	"sqlmap": {
		Path: "/sqli", Param: "id", Method: "GET", InsertionPoint: "query",
		Why: "sqlmap found no injection on a parameter that is concatenated into a query and returns a " +
			"boolean differential, a database error page and a controllable delay. A miss here means " +
			"the run did not happen: check for a rejected option, and confirm the session cache was " +
			"flushed.",
	},
	"ghauri": {
		Path: "/sqli", Param: "id", Method: "GET", InsertionPoint: "query",
		Why: "ghauri found no injection on a parameter with a boolean differential, an error page and " +
			"a controllable delay. This is the exact shape of the defect that filed 53 vectors clean " +
			"in forty seconds: a rejected --delay value, or a per-host session cache returning an old " +
			"verdict without sending a request.",
	},
	"sqlidetector": {
		Path: "/sqli", Param: "id", Method: "GET", InsertionPoint: "query",
		Why: "SQLiDetector matched no error signature on a parameter that returns a verbatim " +
			"PSQLException on an unbalanced quote. Since signature matching is all it does, a miss " +
			"here means it sent nothing or read nothing.",
	},
	"nuclei-dast": {
		Path: "/redirect", Param: "next", Method: "GET", InsertionPoint: "query",
		Why: "nuclei found no open redirect on an endpoint that sends the caller anywhere it is told " +
			"with no validation. Either the templates did not run or the matcher is not doing what it " +
			"appears to: this is the same section where a matcher once produced 53 fabricated findings.",
	},
	// REcollapse is a DETECTOR now, so it needs a control like any other. It had none while it was a
	// payload generator, which was defensible then and is not any more: it is the tool that actually
	// sends this section's requests, so its silence is the silence that matters.
	//
	// The same oracle endpoint nuclei uses, and it exercises the whole chain rather than the binary:
	// recollapse must emit mutations carrying the token, the framework must build a request with the
	// payload in the right parameter, send it, decline to follow the 30x, and recognise that the
	// Location it came back with names the webhook host. A miss anywhere in that sequence is a miss
	// here.
	"recollapse": {
		Path: "/redirect", Param: "next", Method: "GET", InsertionPoint: "query",
		Why: "the framework's own SSRF probe found no redirect on an endpoint that sends the caller " +
			"anywhere it is told with no validation. That is the whole send-and-match path failing, not " +
			"just recollapse: check that the Listening Webhook URL is a real absolute URL, since the " +
			"open redirect match is what compares the Location header against its host.",
	},
	"lfimap": {
		Path: "/lfi", Param: "file", Method: "GET", InsertionPoint: "query",
		Why: "LFImap found no inclusion on a parameter that returns a passwd-shaped document for a " +
			"traversal payload. A miss here usually means the target URL was assembled wrongly and the " +
			"payloads went somewhere else, which is a defect that has affected every section sharing " +
			"that code path.",
	},
	// PARAMETER NAME "cmd", NOT "host". The control was declared against /cmdi?host= and did not fire
	// on the first full run. Measured, commix 4.2.dev76, controller.py line 314:
	//
	//	if any(x in check_parameter.lower() for x in settings.HTTP_HEADERS)
	//
	// where HTTP_HEADERS is ["user-agent", "referer", "host"], matched as a SUBSTRING. So `-p host`
	// does not name the query parameter at all: commix reads it as the Host header, injects into the
	// Host header, the oracle answers 400 to a Host it does not serve, and --batch answers "N" to
	// "Do you want to ignore HTTP response code '400'?", after which it prints "Skipping further
	// testing on the target URL." The verbatim trace was:
	//
	//	[info] Setting HTTP Header parameter 'host' for tests.
	//	[info] Skipping further testing on the target URL.
	//
	// Any parameter whose NAME contains host, referer or user-agent does this. The oracle already
	// accepts cmd as an alias for the same injectable input, so the control moves rather than the
	// oracle. With it, commix reports the parameter injectable via the classic technique.
	"commix": {
		Path: "/cmdi", Param: "cmd", Method: "GET", InsertionPoint: "query",
		Why: "Commix found no injection on a parameter that honours a shell separator followed by " +
			"sleep or echo. A miss here means no request was sent, or a cached verdict was returned " +
			"from a previous run without one.",
	},
	// domdig drives a real Chromium, so its control has to be something a browser can EXECUTE rather
	// than something that merely appears in the response text. The oracle's /xss reflects into an HTML
	// element position, which is where domdig's `<iMg src=a oNerrOr=window.___xssSink(N)>` and
	// `</scrIpt><scrIpt>...</scrIpt>` payloads fire. Verified: domdig 2.0.0 reports 7 findings, all
	// type domxss and confirmed true, element GET/q.
	//
	// This is the tool the whole exercise was aimed at. It had no control, it has crashed on 100% of
	// its vectors on three separate runs, and it was recorded clean every time: 31 of 31 traces
	// crashed before a payload was sent and not one of 45 query vectors was ever tested.
	//
	// THE CONTROL IS QUERY ONLY, AND THAT IS A REAL GAP, NOT AN OVERSIGHT.
	//
	// domdig is the only tool here that reaches a FRAGMENT, so a fragment run is certified by a
	// control that only ever proved query fuzzing. Pointing this entry at "fragment" would not fix
	// that, it would break the control: a fragment is never sent to the server, and the oracle has no
	// client-side sink to read one. Measured, rebuilt domdig against the live oracle:
	//
	//	node /app/domdig.js -J -q "http://oracle:8000/xss?q=rs0n"   ->  7 findings, all confirmed
	//	node /app/domdig.js -J -q "http://oracle:8000/xss#rs0nFRAG" ->  []
	//
	// A "fragment" control would therefore fail every run and blame domdig for it, which is the one
	// outcome worse than no control. Closing the gap needs an oracle route that reads location.hash
	// into a sink; docker/oracle/main.go has no such route and no reference to location.hash at all.
	// Until it does, this stays at "query". Nothing is currently mis-certified: the database holds
	// 420 vectors and none of them is a fragment.
	"domdig": {
		Path: "/xss", Param: "q", Method: "GET", InsertionPoint: "query",
		Why: "domdig found no XSS on a page that reflects the parameter unencoded into an HTML element " +
			"position, which is exactly where its own img-onerror and script-tag payloads fire in a " +
			"browser. domdig launches Chromium per vector, and its usual failure is a crash before any " +
			"payload is sent, which exits 0 and reads as clean. Open the stored trace for this run: if " +
			"it ends in a browser or protocol error rather than a report, no vector was tested.",
	},
	// Emulated FreeMarker at /ssti. Verified: SSTImap reports "Engine: Freemarker, Technique: rendered"
	// against ?tpl=.
	"sstimap": {
		Path: "/ssti", Param: "tpl", Method: "GET", InsertionPoint: "query",
		Why: "SSTImap identified no engine on a parameter whose value is rendered as a template: " +
			"${(1+2)?c} comes back as 3. Its detection is a string comparison against its own rendered " +
			"probe, so a miss here means no request was sent or no response was read, not that the " +
			"target sanitised anything.",
	},
	// Same endpoint, different mechanism: TInjA fingerprints by sending four polyglots and classifying
	// each response as unmodified, modified or error. Verified: TInjA 1.2.0 reports "Freemarker was
	// identified (certainty: Very High)" and one suspected template injection.
	"tinja": {
		Path: "/ssti", Param: "tpl", Method: "GET", InsertionPoint: "query",
		Why: "TInjA identified no engine on a parameter that renders ${7*7} as 49 and returns a " +
			"FreeMarker parse error for a malformed interpolation. Its whole method is comparing the " +
			"reaction to four polyglots, so a miss means the polyglots did not arrive: check the trace " +
			"for a rejected flag, and check that --reportpath still ends in a slash, because TInjA " +
			"treats it as a prefix and a path without one produces a report file nothing ever reads.",
	},
}

// canarySettings strips the settings that identify the TARGET, keeping the ones that configure the
// TOOL.
//
// This distinction was learned the hard way, on the first end-to-end run. The control inherited the
// operator's dalfox settings wholesale, which included --session-check-url pointing at the real
// target's /my-account and the real target's session cookie. dalfox duly found the XSS on the oracle,
// then ran its session check against a completely different host, failed it, and exited 1 with
// --on-session-loss abort. The control reported a broken tool when the tool was working perfectly.
//
// The rule: anything in the Session group belongs to the target, not to the tool. A cookie issued by
// one host is meaningless at another, and a session-check URL is an assertion about a host the
// control is not testing. Proxy goes too, because it points at the operator's environment rather than
// at either target.
//
// THE COST, STATED PLAINLY. The original design wanted total inheritance so that a setting which
// silently breaks a tool would also break the control. Stripping this group gives some of that up: a
// broken cookie or a malformed session-check regex will no longer be caught here. What remains
// covered is everything in the option table, argv construction, the parser, and the storage path,
// which is where the defects this project actually hit have lived. The alternative, a control that
// fails whenever the real target's session expires, would be a control nobody believes.
func canarySettings(tool VectorTool, settings map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range settings {
		meta, known := tool.Options[key]
		if known && meta.Group == "Session" {
			continue
		}
		if key == "proxy" {
			continue
		}
		out[key] = value
	}
	return out
}

// canaryVectorRow builds the synthetic vector the control runs against.
//
// It is a vectorRow that exists in NO table, following the pattern graphqlRowSource established. The
// identity matters more than it looks: vector_scan_vectors.vector_id and vector_findings.vector_id
// both carry a foreign key onto attack_vectors, so an id that is not a real attack vector fails the
// insert, the error is only logged, the scan carries on, and the control silently records nothing.
// That failure mode has been hit three times in this area already. IsGraphQLTarget is what routes
// this row to the target_url identity instead, which has no foreign key.
func canaryVectorRow(scopeTargetID, toolKey string, spec CanarySpec) vectorRow {
	url := "http://" + canaryHost() + spec.Path + "?" + spec.Param + "=1"
	method := spec.Method
	if method == "" {
		method = "GET"
	}
	row := vectorRow{
		// A full UUID, not a short synthetic string: reportPath slices vector.ID[:8] without checking
		// its length, so anything shorter panics the scan goroutine, which has no recover and would
		// leave the run stuck on 'running' forever with no error and no completed_at.
		ID:             deterministicUUID(scopeTargetID + "|canary|" + toolKey + "|" + url),
		Method:         method,
		InsertionPoint: spec.InsertionPoint,
		Parameters:     []string{spec.Param},
		EvidenceURL:    url,
		// Routes the verdict to the target_url column, which has no foreign key. See the comment above.
		IsGraphQLTarget: true,
	}
	row.Scheme, row.Domain, row.Port, row.Path = splitURLParts(url)
	return row
}

// CanaryOutcome is what the run concluded about its own validity.
type CanaryOutcome struct {
	// Ran is false when no control is defined for this tool, in which case Passed means nothing and
	// the scan keeps its ordinary verdict.
	Ran bool
	// Passed is true when the control produced at least one finding.
	Passed bool
	// Detail is the operator-facing explanation, empty unless the control failed.
	Detail string

	// Reused is true when this pass was NOT re-run: it is a pass from earlier that still speaks for
	// this tool. A reused pass is a weaker claim than a fresh one and is reported as such, because
	// "verified" and "verified by a result from earlier" are different things to know about a clean
	// result. See canaryReusablePass for what has to hold before one is reused at all.
	Reused bool
	// ProvenAt and Age are when the reused pass was actually taken, and how old it was at the moment
	// it was reused. Zero on a fresh pass.
	ProvenAt time.Time
	Age      time.Duration
}

// canaryFailureMessage is what gets written to vector_scans.error, and therefore what the results
// modal shows above the findings. It has to say what happened, what it means, and what to do, in that
// order, because it is read by someone who has just been told their scan does not count.
func canaryFailureMessage(toolKey string, spec CanarySpec, targetVectors int) string {
	return "THIS SCAN IS UNVERIFIED, NOT CLEAN. Before testing the target, " + toolKey +
		" was run against a control this framework knows is vulnerable, at " +
		"http://" + canaryHost() + spec.Path + ", and it found nothing there. " + spec.Why +
		" Until that control passes, the " + strconv.Itoa(targetVectors) +
		" result(s) from this run prove nothing about the target and should not be read as clean."
}

// evaluateCanary decides whether the control passed. Kept separate from the run so the decision is
// testable without a database or a docker daemon.
func evaluateCanary(spec CanarySpec, defined bool, findings int, runErr error) CanaryOutcome {
	if !defined {
		return CanaryOutcome{Ran: false}
	}
	if runErr != nil {
		return CanaryOutcome{Ran: true, Passed: false,
			Detail: "the control run itself failed: " + runErr.Error()}
	}
	if findings > 0 {
		return CanaryOutcome{Ran: true, Passed: true}
	}
	return CanaryOutcome{Ran: true, Passed: false, Detail: spec.Why}
}

// canaryReachable reports whether the oracle answers at all.
//
// Worth checking separately, because "the oracle is down" and "the scanner is broken" produce the
// same zero and deserve different messages. Telling an operator their scanner is broken when the
// control target is simply not running is how a safety mechanism loses its credibility.
func canaryReachable(ctx context.Context) bool {
	return canaryServes(ctx, "/health")
}

// canaryServesSpec reports whether the oracle actually serves the path THIS control needs.
//
// /health is not enough, and the gap is measured. The oracle image running on 2026-08-23 was built
// on 2026-08-21 and served no /ssti at all: unknown paths fell through to its index handler, so
// /ssti answered 200 with the index page. /health answered 200 too. So the control for SSTImap and
// TInjA ran against a page with no template in it, found nothing, and the operator was told THE
// SCANNER had found nothing rather than that the oracle was stale.
//
// That inverts the entire purpose of a positive control. A control exists to answer "does this tool
// work", and a stale oracle turns it into "this tool is broken" for every tool at once.
//
// So the reachability check asks for the control's OWN path and requires the oracle to claim it. The
// oracle marks every handler it really implements with the X-Ars0n-Oracle header; an index fallthrough
// does not carry it, which is what distinguishes "serves /ssti" from "serves something at /ssti".
func canaryServesSpec(ctx context.Context, spec CanarySpec) bool {
	return canaryServes(ctx, spec.Path)
}

func canaryServes(ctx context.Context, path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+canaryHost()+path, nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	// /health predates the marker and is the liveness check rather than a control surface.
	if path == "/health" {
		return true
	}
	return strings.TrimSpace(resp.Header.Get("X-Ars0n-Oracle")) != ""
}

// ---------------------------------------------------------------------------------------------
// REUSING A PASSING CONTROL.
//
// THE COST. The control runs once per SCAN, and the authenticated campaign pattern is one scan per
// vector, because the session is refreshed between vectors. Measured on this estate: 49.7s of
// control per sqlmap scan and 129s per ghauri scan. Over a 140 vector arm that is 1.9 hours and 5.0
// hours respectively spent proving the same local oracle still works, roughly a quarter of the
// campaign's wall clock, and every one of those runs is identical to the one before it.
//
// WHAT A PASS IS EVIDENCE OF. Read the failures this control was built from: ghauri rejecting a
// fractional --delay, Forbidden printing a usage banner, dalfox blinded by --user-agent, commix
// reading -p host as a header, vectorAPI's NULL handling, a stale oracle image serving an index page
// at /ssti. Not one of them is a property of the vector being scanned. Every one is a property of
// THE TOOL, ITS SETTINGS, ITS CONTAINER and THE ORACLE. A pass is therefore evidence about that
// tuple at a point in time, and it stays evidence for as long as the tuple is unchanged.
//
// WHAT IT IS NOT EVIDENCE OF, STATED PLAINLY. It cannot cover a per-run failure: domdig launches a
// fresh Chromium for every vector and can crash on this one having worked on the last. Neither can a
// FRESH control, though. A control is a separate process invocation either way, so even today it is
// a sample rather than a proof, and the instrument that catches a per-run crash is the stored trace
// and its exit detail, not the canary. Reuse lowers the sampling rate; it does not create the gap.
// The TTL and the use cap below exist to keep that sampling rate from reaching zero.
//
// WHY NOT A SETTING. A canary that can be switched off is off when it matters. There is no knob
// here: reuse happens when the evidence is current and identical, and there is no way to ask for a
// reused control, extend its life, or suppress a fresh one. Every gate fails closed, so the only
// direction anything can go wrong in is more control runs, never fewer.

// canaryEvidenceTTL bounds how long a pass speaks for the tool.
//
// 30 minutes is chosen against the measured arm. A ghauri arm runs about 5 hours, so a 30 minute
// life re-proves the tool at least ten times across it: 21 minutes of control instead of 5 hours,
// with the sampling that catches a container that has quietly degraded still happening twice an
// hour. Longer saves almost nothing more, because the saving is already 93% at ten runs, and buys
// real staleness, which is a bad trade for a mechanism whose whole value is that it is believed.
const canaryEvidenceTTL = 30 * time.Minute

// canaryEvidenceMaxUses bounds how many scans one pass can speak for, whatever the clock says.
//
// The TTL alone is not enough because it is blind to throughput. A tool whose vectors take eight
// seconds gets 200 scans out of one control inside the TTL; the cap turns that back into a control
// every 20 vectors. Cheap tools are exactly the ones that can afford to re-prove themselves.
const canaryEvidenceMaxUses = 20

// canaryNow is the clock, replaceable so the expiry tests do not sleep.
var canaryNow = time.Now

// canaryContainerState reports an opaque identity for the tool's running container, replaceable so
// the invalidation tests do not need a docker daemon.
var canaryContainerState = dockerCanaryContainerState

type canaryPass struct {
	key      string
	provenAt time.Time
	uses     int
}

var (
	canaryEvidenceMu sync.Mutex
	// One live pass per tool. A pass under a different key does not sit alongside the current one: it
	// is replaced, so there is never a shelf of old evidence waiting for the settings to be changed
	// back to something it matches.
	canaryEvidenceByTool = map[string]canaryPass{}
	// PROBATION. A tool that has just failed its control has to pass TWICE before its word is reused
	// again, and the first of those passes is not stored. A failure means the tuple is in a state
	// nobody understands; one pass after it could be the flap rather than the fix, and caching a flap
	// is precisely how a cache ends up certifying a broken tool for the next half hour.
	canaryProbation = map[string]bool{}
)

// dockerCanaryContainerState fingerprints the container the tool executes in.
//
// THIS IS THE INVALIDATION THAT MATTERS MOST, because it is the one an operator triggers without
// thinking about the canary at all. A rebuilt image, a compose up, a crashed container that came
// back: every one of them produces a new container id or a new start time, and every one of them can
// change what the tool does. The image id is in here too, so a container recreated from a new build
// of the same tag invalidates even when nothing else moved.
//
// A container that is not running is not reusable either. It cannot have been the thing that passed
// ten minutes ago in any sense worth acting on.
func dockerCanaryContainerState(ctx context.Context, container string) (string, bool) {
	if strings.TrimSpace(container) == "" {
		return "", false
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probe, "docker", "inspect", "-f",
		"{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.Running}}", container).Output()
	if err != nil {
		return "", false
	}
	state := strings.TrimSpace(string(out))
	if !strings.HasSuffix(state, "|true") {
		return "", false
	}
	return state, true
}

// canaryEvidenceKey is everything a pass is conditional on, in one string.
//
// Deliberately NOT keyed on the scope target. canarySettings has already stripped the settings that
// bind to a target, so what is left describes the tool, and a pass under an identical tool
// configuration is the same evidence whichever target prompted it. Keying on the target would
// silently halve the hit rate while protecting against nothing.
//
// A marshalling failure returns not-ok rather than a fallback string, because a key that cannot be
// computed must miss, and a fallback that happens to be equal for two different settings maps is the
// one bug in a cache like this that nobody ever finds.
func canaryEvidenceKey(ctx context.Context, tool VectorTool, spec CanarySpec,
	toolSettings, sectionSettings map[string]any) (string, bool) {

	state, ok := canaryContainerState(ctx, tool.Container)
	if !ok {
		return "", false
	}
	// THE ORACLE'S OWN CONTAINER IS IN THE KEY, and leaving it out was the one gap a review found
	// that could actually certify a broken control.
	//
	// Only the TOOL's container was fingerprinted, and the per-reuse liveness check is
	// canaryServesSpec, which asks for the marker header. An oracle rebuilt so that it still sets
	// that header but no longer carries the injection would keep serving a green reuse for the
	// whole TTL. That is not hypothetical here: this file's own origin story is an oracle image
	// that began serving its index page at /ssti, and it was caught only because that index
	// happened to lack the marker. A rebuild that kept the marker would not have been.
	//
	// Fails closed like every other gate: an oracle container that cannot be inspected yields no
	// key, so the pass is dropped and the control runs fresh.
	oracleState, ok := canaryContainerState(ctx, canaryOracleContainer())
	if !ok {
		return "", false
	}
	settingsJSON, err := json.Marshal(toolSettings)
	if err != nil {
		return "", false
	}
	sectionJSON, err := json.Marshal(sectionSettings)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"tool=" + tool.Key,
		"binary=" + tool.Binary,
		"container=" + tool.Container,
		"state=" + state,
		"oracle=" + canaryHost(),
		"oracle_state=" + oracleState,
		"spec=" + spec.Method + " " + spec.Path + "?" + spec.Param + " @" + spec.InsertionPoint,
		"settings=" + string(settingsJSON),
		"section=" + string(sectionJSON),
	}, "\n")))
	return hex.EncodeToString(sum[:]), true
}

// canaryReusablePass answers whether a stored pass still speaks for this tool right now.
//
// Every gate fails closed: an unreadable container, an unmarshallable setting, an oracle that has
// stopped serving the control's own path, a key that does not match, an expired or spent pass. All
// of them produce a fresh control run, which is exactly the behaviour this framework had before.
//
// THE ORACLE IS RE-CHECKED ON EVERY REUSE, with canaryServesSpec rather than /health, and that is
// not redundant. The measured failure was an oracle image that answered 200 at /ssti out of its
// index handler while serving no template injection at all: /health was fine and the control was
// meaningless. Reusing a pass across an oracle that has since gone stale would inherit that lie
// without even the chance to notice it. The check costs one HTTP request against 49 to 129 seconds.
func canaryReusablePass(ctx context.Context, tool VectorTool, spec CanarySpec,
	toolSettings, sectionSettings map[string]any) (CanaryOutcome, bool) {

	canaryEvidenceMu.Lock()
	pass, held := canaryEvidenceByTool[tool.Key]
	canaryEvidenceMu.Unlock()
	if !held {
		return CanaryOutcome{}, false
	}

	age := canaryNow().Sub(pass.provenAt)
	if age < 0 || age >= canaryEvidenceTTL || pass.uses >= canaryEvidenceMaxUses {
		forgetCanaryPass(tool.Key)
		return CanaryOutcome{}, false
	}
	if !canaryServesSpec(ctx, spec) {
		forgetCanaryPass(tool.Key)
		return CanaryOutcome{}, false
	}
	key, ok := canaryEvidenceKey(ctx, tool, spec, toolSettings, sectionSettings)
	if !ok || key != pass.key {
		forgetCanaryPass(tool.Key)
		return CanaryOutcome{}, false
	}

	// Re-read under the lock before spending a use, so two scans of the same tool running at once
	// cannot both take the last one.
	canaryEvidenceMu.Lock()
	current, still := canaryEvidenceByTool[tool.Key]
	if !still || current.key != key || current.uses >= canaryEvidenceMaxUses {
		canaryEvidenceMu.Unlock()
		return CanaryOutcome{}, false
	}
	current.uses++
	canaryEvidenceByTool[tool.Key] = current
	canaryEvidenceMu.Unlock()

	return CanaryOutcome{Ran: true, Passed: true, Reused: true, ProvenAt: pass.provenAt, Age: age}, true
}

// recordCanaryPass stores a FRESH pass as evidence for the tuple that produced it.
//
// The first pass after a failure is deliberately not stored. See canaryProbation.
func recordCanaryPass(ctx context.Context, tool VectorTool, spec CanarySpec,
	toolSettings, sectionSettings map[string]any) {

	canaryEvidenceMu.Lock()
	onProbation := canaryProbation[tool.Key]
	if onProbation {
		delete(canaryProbation, tool.Key)
	}
	canaryEvidenceMu.Unlock()
	if onProbation {
		return
	}

	key, ok := canaryEvidenceKey(ctx, tool, spec, toolSettings, sectionSettings)
	if !ok {
		return
	}
	canaryEvidenceMu.Lock()
	canaryEvidenceByTool[tool.Key] = canaryPass{key: key, provenAt: canaryNow()}
	canaryEvidenceMu.Unlock()
}

// recordCanaryFailure drops this tool's evidence and puts it on probation.
//
// A failure invalidates the stored pass whatever key it was taken under. The pass said "this tool
// works"; the failure says nobody knows what this tool is doing, and a pass from before the last
// thing anyone observed is not an answer to that.
func recordCanaryFailure(toolKey string) {
	canaryEvidenceMu.Lock()
	delete(canaryEvidenceByTool, toolKey)
	canaryProbation[toolKey] = true
	canaryEvidenceMu.Unlock()
}

func forgetCanaryPass(toolKey string) {
	canaryEvidenceMu.Lock()
	delete(canaryEvidenceByTool, toolKey)
	canaryEvidenceMu.Unlock()
}

// canaryReusedStatus is the verdict status written for a control that was not re-run.
//
// A distinct value rather than "findings", because a reused control produced no findings and writing
// it as one would put a zero-hit row in the column an operator reads as hits. It is also not
// "error", which the results modal lists as untested work to redo.
const canaryReusedStatus = "control-reused"

// canaryPassReason is what the stored scan says about its own control.
//
// "Verified" and "verified by a result from earlier" are different claims, and an operator reading a
// clean result is entitled to know which one they have and how old the evidence is. Hiding the
// difference would be the same defect as reporting an untested vector as clean, one level up.
func canaryPassReason(toolKey string, outcome CanaryOutcome) string {
	if !outcome.Reused {
		return "Positive control PASSED: " + toolKey + " found the known vulnerability on the canary " +
			"oracle, so this run was genuinely testing something."
	}
	return "Positive control PASSED " + canaryAgeLabel(outcome.Age) + " ago and was REUSED, not re-run: " +
		toolKey + " proved itself on the canary oracle under these exact settings in this same " +
		"container instance, the oracle still serves the control endpoint, and nothing has changed since."
}

func canaryAgeLabel(d time.Duration) string {
	if d < time.Minute {
		return strconv.Itoa(int(d.Round(time.Second)/time.Second)) + "s"
	}
	return strconv.Itoa(int(d.Round(time.Minute)/time.Minute)) + "m"
}
