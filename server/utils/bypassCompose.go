package utils

import (
	"strconv"
	"strings"
)

// Building the command lines for the access control bypass section.
//
// Both tools take one URL and try many variations of it. The composing work is almost entirely about
// two things: the false positive controls, because on a real site the default behaviour of either
// tool is to report every variation whose response differs at all and most differences are not
// bypasses; and keeping the scan READ ONLY, because the default behaviour of both tools is to send
// requests that create data in the operator's own application.

// nomore403PayloadDir is where the cloned repository's payload wordlists live in the image.
const nomore403PayloadDir = "/opt/nomore403/payloads"

// ---------------------------------------------------------------------------
// An access control check must not write.
// ---------------------------------------------------------------------------
//
// MEASURED, against a live target the operator owns: a single pass of these two tools produced 24
// findings that were POST -> 201 Created against /api/Users and /api/SecurityAnswers. Every one of
// those 201s is a ROW CREATED in the application by a tool whose entire job is READING whether an
// access control decision can be avoided. 20 of nomore403's 85 findings and 4 of Forbidden's 74 were
// of that shape.
//
// Neither binary has a flag for this. Both were read rather than trusted:
//
//   - nomore403's `verbs` and `verbs-case` techniques send every line of its payloads/httpmethods
//     file, which is CONNECT, COPY, DELETE, GET, HEAD, LABEL, LOCK, MOVE, OPTIONS, PATCH, POST,
//     POUET, PUT, TRACE, TRACK, UNCHECKOUT, UPDATE and VERSION-CONTROL. There is no flag that
//     narrows that list, and -t/--http-method does not apply to it.
//   - nomore403's `method-override` technique sends POST for EVERY request it makes: as
//     ?_method=<verb>, as X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override on a POST, and
//     as a POST body carrying _method. requestMethodOverrideBody hardcodes the POST.
//   - Forbidden's `methods` test sends whatever the endpoint's OPTIONS Allow header advertises,
//     which on an Express application is routinely POST, PUT, PATCH and DELETE.
//   - Forbidden's `method-overrides` test smuggles 45 verbs, DELETE and MKCOL and MOVE among them,
//     and its third record set hardcodes method = "POST" with a body, so -f/--force does not stop it.
//   - Forbidden's `uploads` test sends PUT /pentest.txt with the body "pentest" once per directory
//     in the path. That is not a read at all, it is a file write.
//
// So the control is the framework's, and it is to REFUSE the families rather than to try to tame
// them. Everything below is off unless one switch is on, and that switch is off by default.

// bypassWriteSetting is the ONE switch that lets either tool send a state-changing request. No other
// stored setting can turn writing on: a technique switch, a test switch, a forced HTTP method and an
// operator's own extra header are all filtered against it, so a settings blob that has sat in the
// database since before this existed cannot quietly bring the writes back.
const bypassWriteSetting = "allowStateChangingRequests"

// bypassSafeMethods are the verbs an access control check may use. Defined as an allow list rather
// than a deny list because both tools send verbs nobody has heard of: POUET, ARBITRARY, SPACEJUMP,
// MKREDIRECTREF. What an unknown verb does to an unknown back end is not knowable, so it is refused.
//
// TRACE is here because it is defined to echo the request and change nothing, and it is the whole
// point of the cross site tracing probe.
var bypassSafeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true}

// bypassMethodOverrideHeaders are the header names that smuggle a verb past a router that only
// inspects the request line. A safe method carrying one of these is not a safe request: the front
// end sees GET and the application sees DELETE.
//
// The first three are the names both tools use. The rest are the siblings that the same middleware
// families accept, included so that a header typed into the operator's own extra header field is
// caught by the same rule as the tools' own.
var bypassMethodOverrideHeaders = map[string]bool{
	"x-http-method-override": true,
	"x-http-method":          true,
	"x-method-override":      true,
	"x-method":               true,
	"x-original-method":      true,
	"x-action-override":      true,
}

// nomore403WritingTechniques are the nomore403 techniques whose requests change state, and what each
// one actually sends. Keyed by the flag name the binary accepts.
var nomore403WritingTechniques = map[string]string{
	"verbs": "sends every verb in payloads/httpmethods, which includes POST, PUT, PATCH, DELETE, " +
		"COPY, MOVE, LOCK, UPDATE and UNCHECKOUT",
	"verbs-case": "re-sends those same verbs with the letter case switched, so a router that " +
		"matches on POST still routes pOsT",
	"method-override": "sends POST for every request it makes: as ?_method=, as " +
		"X-HTTP-Method-Override, X-HTTP-Method and X-Method-Override, and as a POST body carrying " +
		"_method=PUT, PATCH or DELETE",

	// Found by MEASURING rather than by reading the technique's name. raw-desync sounds like a
	// framing probe and it is one, but four of its seven raw payloads are POST, three of them with a
	// body, one of which is the form "_=1&_2=2". Against a handler that accepts a form post, that is
	// a submission. It survived the first pass of this fix and showed up as four POSTs in a decoy's
	// request log.
	"raw-desync": "sends four raw POST requests, three of them with a body, to probe how the front " +
		"end and the back end disagree about request framing",
}

// forbiddenWritingTests are the Forbidden test families whose requests change state.
var forbiddenWritingTests = map[string]string{
	"methods": "sends every method the endpoint's own OPTIONS Allow header advertises, which on a " +
		"typical application includes POST, PUT, PATCH and DELETE",
	"method-overrides": "smuggles 45 verbs, DELETE, MOVE and MKCOL among them, through _method " +
		"query parameters, override headers and a request body, and its third record set hardcodes " +
		"POST so forcing a method does not stop it",
	"uploads": "sends PUT /pentest.txt with the body \"pentest\" once for every directory in the " +
		"URL path. This writes a file to the target and is not a read at all",
}

// bypassWritesAllowed reads the one switch.
func bypassWritesAllowed(settings map[string]any) bool {
	return truthySetting(settings[bypassWriteSetting])
}

// bypassMethodIsSafe reports whether a forced HTTP method leaves the scan read only.
func bypassMethodIsSafe(method string) bool {
	return bypassSafeMethods[strings.ToUpper(strings.TrimSpace(method))]
}

// withoutWritingFamilies removes the technique or test names that change state, preserving the
// caller's order so the command line and the warning are both reproducible.
func withoutWritingFamilies(chosen []string, writing map[string]string,
	allowWrites bool) (kept, dropped []string) {

	for _, name := range chosen {
		if !allowWrites && writing[name] != "" {
			dropped = append(dropped, name)
			continue
		}
		kept = append(kept, name)
	}
	return kept, dropped
}

// bypassDroppedText spells out what was removed and why, one clause per family, so the reason is on
// the scan rather than in this file.
func bypassDroppedText(toolName string, dropped []string, writing map[string]string) string {
	parts := make([]string, 0, len(dropped))
	for _, name := range dropped {
		parts = append(parts, name+" ("+writing[name]+")")
	}
	return "This run did NOT use " + strings.Join(dropped, ", ") + ", because those " +
		toolName + " families send state-changing requests and an access control check must not " +
		"write to the target: " + strings.Join(parts, "; ") + ". Turn on \"" +
		bypassWriteWarningLabel + "\" if you have permission to have this scan create, modify and " +
		"delete data in the application you are testing."
}

// bypassWriteWarningLabel is the switch's label, repeated in warnings so an operator reading a scan
// knows exactly which control to look for.
const bypassWriteWarningLabel = "Allow state-changing requests (THIS WRITES TO THE TARGET)"

// bypassWritesEnabledWarning is emitted on every run that has the switch on, because a setting
// stored months ago must not be the only place this is stated.
func bypassWritesEnabledWarning(toolName string) string {
	return "STATE-CHANGING REQUESTS ARE ENABLED for this " + toolName + " run. It will send POST, " +
		"PUT, PATCH, DELETE and method-override requests to the target, and anything the " +
		"application accepts is a row created, changed or removed in it. A 201 Created in these " +
		"results is not a bypass you found, it is a record you made."
}

// bypassSafeExtraHeaders emits the operator's own extra headers, dropping any that would turn a safe
// request into a write.
//
// An operator can type X-HTTP-Method-Override: DELETE into the extra header field, and it would then
// ride on EVERY request either tool sends, including the hundreds of path mutations that have
// nothing to do with verbs. That is a stored setting silently enabling writing, which is the thing
// the switch exists to prevent.
func bypassSafeExtraHeaders(flag string, value any, allowWrites bool, warnings *[]string) []string {
	var args []string
	for _, item := range settingValues(value) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// Split on the colon rather than reusing headerNameOf alone, because the VALUE decides: an
		// override naming GET changes nothing and is kept. Forbidden's own "Content-Type;" form, which
		// expands to an empty header, has no colon and falls straight through.
		name, verb, hasColon := strings.Cut(item, ":")
		if !allowWrites && hasColon &&
			bypassMethodOverrideHeaders[strings.ToLower(strings.TrimSpace(name))] &&
			!bypassMethodIsSafe(verb) {
			*warnings = append(*warnings, "Dropped your \""+item+"\" header. A method override "+
				"header rides on every request the tool sends, so it would turn the whole scan "+
				"into "+strings.ToUpper(strings.TrimSpace(verb))+" traffic against the target. Turn "+
				"on \""+bypassWriteWarningLabel+"\" to send it.")
			continue
		}
		args = append(args, flag, item)
	}
	return args
}

// bypassRefusedForcedMethod is the refusal for a stored forced method that writes.
//
// The whole run is refused rather than the method being quietly swapped for GET. A scan that ran
// something other than what the screen said would be a report an operator cannot reason about, and
// this section has already shipped that defect once.
func bypassRefusedForcedMethod(toolName, setting, method string) string {
	return toolName + " was NOT run: the stored \"" + setting + "\" setting forces the " +
		strings.ToUpper(strings.TrimSpace(method)) + " method, which changes state on the target, " +
		"and an access control check must not write. Clear that setting to scan read only, or turn " +
		"on \"" + bypassWriteWarningLabel + "\" if you have permission to write to this application."
}

// ---------------------------------------------------------------------------
// nomore403
// ---------------------------------------------------------------------------

// ComposeNomore403 builds the nomore403 argv for one target URL.
func ComposeNomore403(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("nomore403")
	var warnings []string
	allowWrites := bypassWritesAllowed(settings)

	args := []string{"-u", v.EvidenceURL}

	var techniques []string
	for _, technique := range nomore403Techniques {
		if truthySetting(settings[technique.Key]) {
			techniques = append(techniques, technique.Flag)
		}
	}
	if len(techniques) == 0 {
		for _, technique := range nomore403Techniques {
			techniques = append(techniques, technique.Flag)
		}
		warnings = append(warnings, "No techniques were selected, so this run used nomore403's whole "+
			"list, minus the families that write.")
	}

	// -k IS ALWAYS EMITTED FROM HERE ON, and that is the fix rather than a tidy-up.
	//
	// Omitting -k does not mean "no techniques", it means nomore403's own default, and its own
	// default is all twenty-three INCLUDING verbs, verbs-case and method-override. Every run that
	// left the techniques unselected therefore sent POST, PUT, PATCH and DELETE at the operator's
	// application, which is exactly how 20 rows were created in it.
	techniques, dropped := withoutWritingFamilies(techniques, nomore403WritingTechniques, allowWrites)
	if len(dropped) > 0 {
		warnings = append(warnings, bypassDroppedText("nomore403", dropped, nomore403WritingTechniques))
	}
	if len(techniques) == 0 {
		warnings = append(warnings, "nomore403 was NOT run: every technique selected for it writes to "+
			"the target ("+strings.Join(dropped, ", ")+"). Select at least one read-only technique, "+
			"or turn on \""+bypassWriteWarningLabel+"\".")
		return nil, warnings
	}
	args = append(args, "-k", strings.Join(techniques, ","))

	if allowWrites {
		warnings = append(warnings, bypassWritesEnabledWarning("nomore403"))
	}

	// The header technique reads payloads/simpleheaders, and that shipped file carries
	// X-HTTP-Method-Override: POST, PUT and PATCH, X-HTTP-Method: POST and X-Method-Override: POST.
	// The request line stays GET, so nothing is written unless the target's own middleware honours
	// those headers, and on a target that does honour them it is a write. The framework cannot edit a
	// file inside the tool's image from here, so this is disclosed rather than fixed.
	if !allowWrites && contains(techniques, "headers") {
		warnings = append(warnings, "One residual write path is NOT closed: nomore403's \"headers\" "+
			"technique reads its shipped payloads/simpleheaders file, which contains five method "+
			"override headers carrying POST, PUT and PATCH. The request line stays GET, so on most "+
			"targets nothing is written, but a router that honours X-HTTP-Method-Override on a GET "+
			"will treat those five as writes. Turn the Header injection technique off if that is not "+
			"acceptable for this target.")
	}

	// A forced method is a stored setting that would make every request a write.
	if method := stringifySetting(settings["httpMethod"]); method != "" && !allowWrites &&
		!bypassMethodIsSafe(method) {
		warnings = append(warnings, bypassRefusedForcedMethod("nomore403", "HTTP method", method))
		return nil, warnings
	}

	// Calibration is what separates a usable report from an unusable one, so turning it off is
	// reported every time rather than being a quiet checkbox.
	if truthySetting(settings["noCalibrate"]) {
		warnings = append(warnings, "Auto-calibration is OFF for this run. Measured against a target "+
			"that answers 200 with a denial page to every variation, this setting took the report from "+
			"thirteen results and no false positives to sixty results including three bypasses that "+
			"did not exist. Every result here needs confirming by hand.")
	}

	// The extra headers are emitted here rather than by composeVectorSettings, because a method
	// override header among them has to be filtered first.
	skip := map[string]bool{"extraHeaders": true}
	args = append(args, bypassSafeExtraHeaders("-H", settings["extraHeaders"], allowWrites, &warnings)...)

	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)

	// Framework owned. -f is emitted explicitly rather than relying on the container's working directory. nomore403's
	// --help says the payload folder defaults to "the same directory as the executable"; the source
	// says otherwise, defaulting to the literal relative path "payloads" resolved against the process
	// CWD. Anything that changes the working directory therefore leaves it with no header, endpath or
	// midpath payloads, and the run completes having tried a fraction of what it reported.
	args = append(args, "-f", nomore403PayloadDir, "--jsonl", "-o", reportPath, "--no-banner")
	return args, warnings
}

// ---------------------------------------------------------------------------
// Forbidden
// ---------------------------------------------------------------------------

// forbiddenDefaultTests is the read-only default. methods, method-overrides and uploads used to be
// in here and are not any more: see forbiddenWritingTests for what each of them sends.
var forbiddenDefaultTests = []string{"path-overrides", "headers", "paths", "encodings"}

// forbiddenRootPath is the accessible path the framework supplies when the operator has not chosen
// one, and it exists to make the path override tests comparable. See ComposeForbidden.
const forbiddenRootPath = "/"

// ComposeForbidden builds the Forbidden argv for one target URL.
//
// Forbidden takes ONE URL: passing a file path produces `ERROR: Inaccessible URL: URL scheme is
// required`, so there is no batching to be had here even though the target list is long.
func ComposeForbidden(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("forbidden")
	var warnings []string
	allowWrites := bypassWritesAllowed(settings)

	args := []string{"-u", v.EvidenceURL}

	var tests []string
	for _, test := range forbiddenTests {
		if truthySetting(settings[test.Key]) {
			tests = append(tests, test.Flag)
		}
	}
	if len(tests) == 0 {
		// -t is REQUIRED and there is no default. Without it Forbidden prints usage and exits, and a
		// run that printed usage is a run that reports a clean target it never touched.
		tests = append(tests, forbiddenDefaultTests...)
		warnings = append(warnings, "No tests were selected. Forbidden requires -t and has no default, "+
			"so this run used the read-only families that need no extra input: path overrides, "+
			"headers, paths and encodings. The tests that need a collaborator URL are a deliberate "+
			"choice, and the tests that write are behind the state-changing switch.")
	}

	tests, dropped := withoutWritingFamilies(tests, forbiddenWritingTests, allowWrites)
	if len(dropped) > 0 {
		warnings = append(warnings, bypassDroppedText("Forbidden", dropped, forbiddenWritingTests))
	}
	if len(tests) == 0 {
		// -t must never be emitted empty: Forbidden answers that with usage text and exit 0, which is
		// indistinguishable from a clean scan of a target it never touched.
		warnings = append(warnings, "Forbidden was NOT run: every test selected for it writes to the "+
			"target ("+strings.Join(dropped, ", ")+"). Select at least one read-only test, or turn on "+
			"\""+bypassWriteWarningLabel+"\".")
		return nil, warnings
	}
	args = append(args, "-t", strings.Join(tests, ","))

	if allowWrites {
		warnings = append(warnings, bypassWritesEnabledWarning("Forbidden"))
	}

	// -f/--force sets the method for the non-specific tests AND for the request that validates the
	// target, so an unsafe value here writes before a single test has run.
	force := stringifySetting(settings["force"])
	if force != "" && !allowWrites && !bypassMethodIsSafe(force) {
		warnings = append(warnings, bypassRefusedForcedMethod("Forbidden", "Force HTTP method", force))
		return nil, warnings
	}

	skip := map[string]bool{"extraHeaders": true, "contentLengths": true}

	// THE ACCESSIBLE PATH, AND WHY IT IS THE SITE ROOT BY DEFAULT.
	//
	// Forbidden's path-overrides family is three record sets, and only one of them requests the URL
	// under test:
	//
	//	PATH-OVERRIDES-1  requests the ACCESSIBLE path from -p, carrying X-Original-URL: /the/target
	//	PATH-OVERRIDES-2  requests the SITE ROOT, carrying the same headers
	//	PATH-OVERRIDES-3  requests the target itself, carrying the same headers
	//
	// The first two are the interesting ones, because the classic X-Original-URL bypass is exactly
	// "ask for something you are allowed to have and let the back end rewrite it". They are also
	// where 28 of Forbidden's 74 findings came from on a measured run, 38%, and all 28 were false: an
	// ordinary /robots.txt (28 bytes, public) and an ordinary homepage (9641 bytes), each reported as
	// a bypass of a completely different endpoint because nothing compared the response against the
	// no-header response of the URL that was actually requested.
	//
	// Forbidden has the control for this and the framework was not using it. -l accepts the literal
	// word "path", meaning "filter out anything the length of the accessible URL's own response". So
	// the accessible path is pinned to the SITE ROOT, which makes record sets 1 and 2 request the
	// same URL, and one filter then covers both. Left at Forbidden's built-in list the filter would
	// cover /robots.txt and leave the fourteen homepage results untouched.
	//
	// The cost is real and is stated: given a single -p, Forbidden EXITS if that path does not answer
	// 2xx, and it exits ZERO having written no report. forbiddenIncomplete turns that into an error
	// on the vector rather than a clean result.
	pathSetting := stringifySetting(settings["path"])
	usesPathOverrides := contains(tests, "path-overrides")
	switch {
	case pathSetting != "":
		if usesPathOverrides {
			warnings = append(warnings, "The accessible path is set to "+pathSetting+" rather than the "+
				"site root. Forbidden filters out results the length of that page, but its second path "+
				"override record set requests the SITE ROOT regardless, and those results are not "+
				"covered by the filter. A 200 in this report whose URL is the bare root is the homepage, "+
				"not a bypass. Clear this setting to have both record sets covered.")
		}
	case usesPathOverrides:
		args = append(args, "-p", forbiddenRootPath)
		skip["path"] = true
		warnings = append(warnings, "The accessible path is the site root. Two of Forbidden's three "+
			"path override record sets request a URL that is NOT the endpoint under test, and pinning "+
			"both to the root lets the -l path filter remove the ordinary response of the URL each of "+
			"them actually requested. If the root does not answer 2xx, Forbidden stops without testing "+
			"anything and this vector is reported as an error rather than as clean.")
	}

	// The soft-403 filter and the accessible-page filter, supplied rather than left to the operator.
	//
	// "initial" is the length of this target's own denial: a variation that comes back the same length
	// as that denial is the denial again, whatever status it carries. "path" is the length of the
	// accessible page: a path override result the same length as it is that page again, which is what
	// turned an untouched /robots.txt into fourteen findings about /admin.
	//
	// The operator's own lengths are ADDED to these rather than replacing them. The two baselines are
	// what make a finding about the URL that was actually requested, which is a correctness property
	// of the section rather than a preference.
	lengths := []string{"initial", "path"}
	var extraLengths []string
	for _, item := range strings.Split(stringifySetting(settings["contentLengths"]), ",") {
		item = strings.TrimSpace(item)
		if item == "" || contains(lengths, item) {
			continue
		}
		lengths = append(lengths, item)
		extraLengths = append(extraLengths, item)
	}
	args = append(args, "-l", strings.Join(lengths, ","))
	if len(extraLengths) > 0 {
		warnings = append(warnings, "Your content lengths ("+strings.Join(extraLengths, ", ")+") were "+
			"added to the two the framework always sends: \"initial\", the length of this target's own "+
			"denial, and \"path\", the length of the accessible page the path override tests request. "+
			"Those two are what stop a result being reported as a bypass of a URL it never touched.")
	} else {
		warnings = append(warnings, "Results whose length matches the original denial response are "+
			"filtered out, which is what stops a page that says \"Access Denied\" under a 200 from "+
			"being reported as a bypass, and so are results the length of the accessible page the path "+
			"override tests request. Add your own content lengths to filter more.")
	}

	if force != "" {
		warnings = append(warnings, "Forcing a method also skips the OPTIONS probe Forbidden uses to "+
			"discover which methods the endpoint allows, so the whole verb axis collapses to the one "+
			"method you forced.")
	}

	args = append(args, bypassSafeExtraHeaders("-H", settings["extraHeaders"], allowWrites, &warnings)...)
	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)

	// The collaborator default is an EXTERNAL third party, so say so rather than quietly sending
	// requests that name somebody else's domain.
	if usesCollaborator(tests) && strings.TrimSpace(stringifySetting(settings["evil"])) == "" {
		warnings = append(warnings, "The host-override, redirect, header and parser tests reference a "+
			"collaborator URL, and none was set, so Forbidden's default of github.com was used. Set "+
			"your own to make callbacks observable, and to stop pointing tests at a third party.")
	}

	args = append(args, "-o", reportPath)
	return args, warnings
}

// forbiddenIncomplete reports that Forbidden gave up before testing anything.
//
// It exits ZERO when it does this, and writes no report, which is byte for byte what a clean scan of
// a target with no bypass looks like. Four of its validation steps end this way, and one of them is
// reachable from a framework default: given a single -p, an accessible path that does not answer 2xx
// stops the whole run.
//
// Only stdout is examined. The report file carries the target's own response bodies, and a target
// that happened to echo one of these sentences back would otherwise mark its own scan as failed.
func forbiddenIncomplete(stdout, report string) string {
	for _, marker := range []string{
		"Inaccessible URL is not valid",
		"Accessible URL is not valid",
		"Accessible URL did not return 2xx HTTP response status code",
		"Evil URL is not valid",
		"Evil URL is being ignored",
	} {
		if strings.Contains(stdout, marker) {
			return marker + ", so Forbidden exited during validation without running a single test. " +
				"It exits 0 and writes no report when it does this, which is indistinguishable from a " +
				"clean scan, so this vector is recorded as UNTESTED."
		}
	}
	if strings.Contains(stdout, "No test records were created") {
		return "Forbidden created no test records, so it sent no requests at all. Check the selected " +
			"test families."
	}
	return ""
}

func usesCollaborator(tests []string) bool {
	for _, test := range tests {
		switch test {
		case "host-overrides", "headers", "bearer-auths", "redirects", "parsers":
			return true
		}
	}
	return false
}

// bypassBaselineLength is the length of the original denial response, used to tell a real bypass
// from the same denial served under a different status.
func bypassBaselineLength(value any) (int, bool) {
	text := strings.TrimSpace(stringifySetting(value))
	if text == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(text)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
