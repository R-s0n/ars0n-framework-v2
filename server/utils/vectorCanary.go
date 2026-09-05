package utils

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
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
