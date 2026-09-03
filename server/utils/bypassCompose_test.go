package utils

import (
	"context"
	neturl "net/url"
	"os"
	"strings"
	"testing"
)

// stubBypassControl replaces the network arm of the negative control with a table of canned
// responses, so the comparison logic is exercised without a target.
//
// EVERY test that reaches a candidate needs one. A parser test with no stub would send real
// requests at whatever hostname the fixture happens to name, which is both wrong and slow.
func stubBypassControl(t *testing.T, answer func(req bypassProbeRequest) bypassProbeResult) {
	t.Helper()
	previous := bypassControlProbe
	bypassControlProbe = func(_ context.Context, req bypassProbeRequest) bypassProbeResult {
		out := answer(req)
		out.Method, out.URL, out.Headers = req.Method, req.URL, req.Headers
		if out.Bytes == 0 {
			out.Bytes = len(out.Body)
		}
		if out.Status == 0 && out.Err == "" {
			out.Status = 200
		}
		return out
	}
	t.Cleanup(func() { bypassControlProbe = previous })
}

// bypassFindingsOfKind picks out one class of finding, because the rejection note now travels
// alongside the real ones and counting rows without reading the kind proves nothing.
func bypassFindingsOfKind(findings []VectorFinding, kind string) []VectorFinding {
	var out []VectorFinding
	for _, f := range findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// The access control bypass section, measured against an nginx lab with a back-end behind it:
//
//	/admin     denied at the proxy, but nginx location matching is CASE SENSITIVE, so /ADMIN reaches
//	           the back-end. A real bypass, and a realistic one.
//	/internal  denied for the exact path only; /internal/ reaches the back-end.
//	/decoy     answers 403 itself, and 200 with an "Access Denied" body to every variation. The
//	           false positive trap, and the reason the parser compares body hashes.

// This section's targets are NOT attack vectors, and they must not be loaded from that table.
//
// Every other section loads attack_vectors wholesale, so putting a few hundred 403 URLs in there
// would quietly turn them into XSS, SQL injection and file inclusion targets as well.
func TestBypassToolsScanTheirOwnTargetList(t *testing.T) {
	for _, key := range []string{"nomore403", "forbidden"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if tool.RowSource == nil {
			t.Errorf("%s must scan the consolidated 4xx list, not the attack vector table", key)
		}
		if tool.ScanUnit != "URL" || tool.DedupeKey == nil {
			t.Errorf("%s unit of work is a URL and the card has to say so", key)
		}
	}
}

// A bypass target's id goes in bypass_target_id, never vector_id.
//
// vector_id has a foreign key onto attack_vectors. Writing a bypass target's id there fails the
// insert, the failure is logged and the scan carries on, and the target is left with no row at all,
// which afterwards reads as a target that was never reached.
func TestBypassTargetsAreRecordedAgainstTheirOwnColumn(t *testing.T) {
	vectorID, bypassID := vectorIdentityColumns("11111111-1111-4111-8111-111111111111", true)
	if vectorID != nil {
		t.Error("a bypass target must not be written to vector_id: the foreign key rejects it")
	}
	if bypassID == nil {
		t.Error("a bypass target must be written to bypass_target_id")
	}

	vectorID, bypassID = vectorIdentityColumns("22222222-2222-4222-8222-222222222222", false)
	if vectorID == nil || bypassID != nil {
		t.Error("an ordinary attack vector still goes to vector_id")
	}

	if v, b := vectorIdentityColumns("", true); v != nil || b != nil {
		t.Error("an empty id must be stored as NULL rather than as an empty string")
	}
}

// The bypass tools take a hand-picked endpoint list on a Targets tab, like every other section that
// scans URLs. The derived list they used to have is gone at the operator's direction.
func TestBypassToolsTakeHandPickedEndpoints(t *testing.T) {
	for _, key := range []string{"nomore403", "forbidden"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if tool.RowSource == nil {
			t.Errorf("%s must take its targets from its own endpoint list", key)
		}
		meta, ok := tool.Options[graphqlEndpointsSetting]
		if !ok {
			t.Fatalf("%s has no endpoints setting, so it can never be given a target", key)
		}
		if meta.Group != "Targets" {
			t.Errorf("%s must put its endpoints on a Targets tab, got %q", key, meta.Group)
		}
		if tool.Groups[0] != "Targets" {
			t.Errorf("%s should open on the tab that decides what gets scanned, got %q", key, tool.Groups[0])
		}
	}
}

// The endpoints worth bypassing are the ones that already denied something, and the picker offers
// those first. 401, 403 and 407 are an access control decision on a resource that exists; 404 and
// 405 are offered but are not what the section is for, and on a real target 404 outnumbered the rest
// five to one.
func TestDeniedStatusSourcesAreHTTPStatusColumns(t *testing.T) {
	if len(deniedStatusSources) < 6 {
		t.Errorf("six tables record an HTTP status alongside a URL, got %d", len(deniedStatusSources))
	}
	for _, source := range deniedStatusSources {
		if source.StatusColumn != "status_code" && source.StatusColumn != "http_status" {
			t.Errorf("%s.%s does not look like an HTTP status column; a scan status column holds "+
				"'running' and would produce an empty list", source.Table, source.StatusColumn)
		}
	}
}

// nomore403's techniques are switches, so only names the binary accepts are ever emitted.
func TestNomore403TechniquesAreSwitches(t *testing.T) {
	tool, _ := VectorToolByKey("nomore403")
	for _, flag := range []string{"-k", "--technique"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("%s must be framework owned", flag)
		}
	}
	if len(nomore403Techniques) != 23 {
		t.Errorf("nomore403 ships 23 techniques in its default list, this has %d", len(nomore403Techniques))
	}
	for _, technique := range nomore403Techniques {
		if _, ok := tool.Options[technique.Key]; !ok {
			t.Errorf("technique %s has no setting, so it can never be turned on", technique.Flag)
		}
	}

	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	args, warnings := ComposeNomore403(v, map[string]any{}, "/tmp/rep")
	// -k is ALWAYS emitted. Omitting it does not mean "no techniques", it means nomore403's own
	// default, which is all twenty-three INCLUDING the three that write to the target.
	if !argsContain(args, "-k") {
		t.Error("-k must always be explicit: omitting it hands the run nomore403's own default, " +
			"which includes verbs, verbs-case and method-override")
	}
	if len(warnings) == 0 {
		t.Error("running everything on the operator's behalf must be reported")
	}

	one, _ := ComposeNomore403(v, map[string]any{"pathCase": true}, "/tmp/rep")
	if got := argValueAfter(one, "-k"); got != "path-case" {
		t.Errorf("a single selected technique must be the only one requested, got %q", got)
	}
}

// Turning calibration off is the difference between a usable report and an unusable one.
//
// Measured against the decoy, which answers 200 with a denial body to every variation: with
// calibration on nomore403 reported 13 results and none of the decoy's; with --no-calibrate it
// reported 60 including three bypasses of it that do not exist.
func TestNomore403WarnsWhenCalibrationIsDisabled(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	_, warnings := ComposeNomore403(v, map[string]any{"noCalibrate": true}, "/tmp/rep")

	var warned bool
	for _, w := range warnings {
		if strings.Contains(w, "Auto-calibration is OFF") {
			warned = true
		}
	}
	if !warned {
		t.Error("disabling calibration must be reported: it took a clean report to three false positives")
	}
}

// Forbidden REQUIRES -t and has no default. Without it, it prints usage and exits, and a run that
// printed usage would be recorded as a clean scan of a target it never touched.
func TestForbiddenAlwaysSuppliesTests(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	args, warnings := ComposeForbidden(v, map[string]any{}, "/tmp/rep")

	tests := argValueAfter(args, "-t")
	if tests == "" {
		t.Fatal("Forbidden requires -t; without it the run prints usage and tests nothing")
	}
	if len(warnings) == 0 {
		t.Error("choosing the test families on the operator's behalf must be reported")
	}

	// And dump mode is owned, because it writes the test list and runs NOTHING.
	tool, _ := VectorToolByKey("forbidden")
	for _, flag := range []string{"-dmp", "--dump"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("%s must be framework owned: it produces a report having sent no requests", flag)
		}
	}
}

// The soft-403 filter is supplied by default, because every target in this section is a URL that
// already returned a denial. A variation whose response is the same length as that denial is the
// denial again, whatever status code it now carries.
func TestForbiddenFiltersTheOriginalDenialByDefault(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	args, warnings := ComposeForbidden(v, map[string]any{}, "/tmp/rep")

	if got := argValueAfter(args, "-l"); !strings.Contains(got, "initial") {
		t.Errorf("the original denial's length must be filtered out by default, got -l %q: %v", got, args)
	}
	var explained bool
	for _, w := range warnings {
		if strings.Contains(w, "Access Denied") {
			explained = true
		}
	}
	if !explained {
		t.Error("the filter must explain what it stops, or an operator will remove it")
	}

	// An operator's own lengths are ADDED to the two baselines rather than replacing them, and are
	// not doubled up: two -l flags would mean the second silently wins.
	own, _ := ComposeForbidden(v, map[string]any{"contentLengths": "1234"}, "/tmp/rep")
	if strings.Count(strings.Join(own, " "), "-l ") > 1 {
		t.Errorf("two -l flags were emitted; the second would win: %v", own)
	}
	got := argValueAfter(own, "-l")
	for _, want := range []string{"initial", "path", "1234"} {
		if !strings.Contains(got, want) {
			t.Errorf("-l %q lost %q: the two baselines are what make a finding about the URL that was "+
				"actually requested, so an operator's own lengths are added to them", got, want)
		}
	}
}

// Several of Forbidden's tests reference an external collaborator, defaulting to github.com. Sending
// requests that name a third party should never be silent.
func TestForbiddenAnnouncesTheDefaultCollaborator(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	_, warnings := ComposeForbidden(v, map[string]any{"redirects": true}, "/tmp/rep")

	var warned bool
	for _, w := range warnings {
		if strings.Contains(w, "github.com") {
			warned = true
		}
	}
	if !warned {
		t.Error("the default collaborator points at a third party and that must be stated")
	}
}

// The parser must read Forbidden's REAL keys.
//
// This shipped broken and cost a whole scan: the status field is called "status", the struct read
// "code" because that is what the documentation calls it, every record scored zero, every record was
// skipped as non-2xx, and a run that produced 1472 results was stored as a clean target. Both values
// also arrive as STRINGS rather than numbers.
func TestForbiddenParserReadsTheRealReportKeys(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://x.example.com/admin", IsBypassTarget: true}

	// The record under test reaches something no other path returns, so it survives its control.
	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		if strings.Contains(req.URL, "%41dmin") {
			return bypassProbeResult{Body: strings.Repeat("the admin panel ", 40)}
		}
		return bypassProbeResult{Body: strings.Repeat("not found shell ", 200)}
	})

	report := `[
	  {"id":"1-ENCODINGS-1","url":"http://x.example.com:80/%41dmin","method":"GET",
	   "command":"curl --path-as-is -iskL 'http://x.example.com/%41dmin'","status":"200","length":"73"},
	  {"id":"2-METHODS-1","url":"http://x.example.com/admin","method":"POST",
	   "command":"curl -X POST","status":"403","length":"19"}
	]`

	findings := parseForbiddenReport("", report, row)
	if len(findings) != 1 {
		t.Fatalf("the 200 is a finding and the 403 is not, got %d", len(findings))
	}
	if findings[0].Method != "GET" {
		t.Errorf("wrong record kept: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "200") || !strings.Contains(findings[0].Evidence, "73b") {
		t.Errorf("the status and length must survive into the evidence: %q", findings[0].Evidence)
	}

	// 1472 records for one URL, almost all the same response reached by a different encoding.
	many := `[`
	for i := 0; i < 50; i++ {
		if i > 0 {
			many += ","
		}
		many += `{"method":"GET","status":"200","length":"73","url":"http://x/a","command":"c"}`
	}
	many += `]`
	if got := parseForbiddenReport("", many, row); len(got) != 1 {
		t.Errorf("fifty identical responses should collapse to one finding, got %d", len(got))
	}
}

// nomore403's parser judges every result against the tool's OWN baseline row, which is the original
// denial. A result with the same body hash is that denial again, whatever status it now carries.
func TestNomore403SuppressesTheOriginalDenialPage(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://x.example.com/decoy", IsBypassTarget: true, BaselineStatus: 403}

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		if strings.Contains(req.URL, "%2564ecoy") {
			return bypassProbeResult{Body: strings.Repeat("the protected page ", 30)}
		}
		return bypassProbeResult{Body: strings.Repeat("catch-all shell ", 200)}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":19,"technique":"default","payload":"http://x/decoy","score":0,"likelihood":"low","body_hash":"aaaa"}`,
		// 200, but byte for byte the same denial page. Not a bypass.
		`{"status_code":200,"content_length":19,"technique":"path-case","payload":"http://x/DECOY","score":100,"likelihood":"high","body_hash":"aaaa"}`,
		// 200 with genuinely different content. This is the one.
		`{"status_code":200,"content_length":37,"technique":"double-encoding","payload":"http://x/%2564ecoy","score":100,"likelihood":"high","body_hash":"bbbb","repro_curl":"curl 'http://x/%2564ecoy'"}`,
		// Refused again.
		`{"status_code":403,"content_length":19,"technique":"verbs","payload":"POST","score":10,"likelihood":"low","body_hash":"cccc"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if len(findings) != 1 {
		t.Fatalf("only the result with different content is a bypass, got %d: %+v", len(findings), findings)
	}
	if findings[0].InjectType != "double-encoding" {
		t.Errorf("the wrong result survived: %+v", findings[0])
	}
	if findings[0].Severity != "high" {
		t.Errorf("a scored-100 result reaching different content is the real thing: %q", findings[0].Severity)
	}
	if !findings[0].IsBypassTarget && false {
		t.Error("unreachable")
	}
}

// A response that is a different status but exactly the same length as the original denial is graded
// down, because that is what a denial page served under 200 looks like.
func TestNomore403GradesSameLengthResponsesDown(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://x.example.com/decoy", IsBypassTarget: true}

	// The control does not reproduce it, so the finding survives to BE graded. The grade is the
	// point of this test and the control does not raise it: same length as the denial page stays
	// suspicious whatever a control says, because the two are measuring different things.
	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		if strings.Contains(req.URL, "decoy") {
			return bypassProbeResult{Body: "nineteen bytes here"}
		}
		return bypassProbeResult{Body: strings.Repeat("catch-all shell ", 200)}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":19,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":200,"content_length":19,"technique":"path-case","score":100,"likelihood":"high","body_hash":"dddd"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "low" {
		t.Errorf("same length as the denial is the denial: severity %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Confidence, "same length") {
		t.Errorf("the report must say why it is doubted: %q", findings[0].Confidence)
	}
}

// A 403 is exactly what somebody else's infrastructure returns to an unexpected request, so the 4xx
// tables fill up with third parties. Measured on a real scope target: the commonest hosts in its 4xx
// set were an unrelated auth provider and a payment site. Scanning those means sending hundreds of
// deliberately malformed requests at a company nobody authorised us to test.
func TestBypassScanStaysInScope(t *testing.T) {
	scope := "mercury-dev.countr.one"

	for _, in := range []string{
		"https://mercury-dev.countr.one/admin",
		"https://global.cdn.mercury-dev.countr.one/admin",
		"https://countr.one/admin",
	} {
		if !bypassHostInScope(in, scope) {
			t.Errorf("%s belongs to the target and must be scanned", in)
		}
	}

	for _, out := range []string{
		"https://dev-partner-auth.one.app/admin",
		"https://www.onepay.com/admin",
	} {
		if bypassHostInScope(out, scope) {
			t.Errorf("%s is a third party and must not be scanned by default", out)
		}
	}

	// With no scope host known, nothing is held back: a target wrongly dropped is a scan that
	// silently misses something, which is worse than one that asks.
	if !bypassHostInScope("https://anything.example.com/x", "") {
		t.Error("with no scope host known the target must still be scanned")
	}
}

// A target that no longer denies anything has nothing to bypass.
//
// The list is built from 4xx responses recorded EARLIER by other tools, and sites change: an endpoint
// is opened up, a login expires, a WAF rule is withdrawn. When the unmodified request already
// succeeds, every variation of it succeeds too, and a status-only comparison reports all of them as
// bypasses of an access control that is not there.
func TestNomore403ReportsAStaleTargetRatherThanBypasses(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://x.example.com/admin", IsBypassTarget: true, BaselineStatus: 403}

	report := strings.Join([]string{
		`{"status_code":200,"content_length":500,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":200,"content_length":500,"technique":"path-case","score":100,"likelihood":"high","body_hash":"bbbb"}`,
		`{"status_code":200,"content_length":512,"technique":"headers","score":100,"likelihood":"high","body_hash":"cccc"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if len(findings) != 1 {
		t.Fatalf("a target that no longer denies anything is one note, not a pile of bypasses, got %d", len(findings))
	}
	if findings[0].Kind != "stale-target" || findings[0].Severity != "info" {
		t.Errorf("this is not a vulnerability: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "403") || !strings.Contains(findings[0].Evidence, "200") {
		t.Errorf("the evidence must contrast what was recorded with what is true now: %q", findings[0].Evidence)
	}
}

// --raw-http is inert and must not be offered as though it enabled something.
//
// Verified in nomore403's source: rawHTTP is declared once and read once, where it appends the string
// "raw-http" to a list of flag names printed in verbose mode. It gates no technique, and
// raw-duplicates, raw-authority and raw-desync are in the default -k set and run either way.
func TestNomore403DoesNotOfferTheInertRawHTTPFlag(t *testing.T) {
	tool, _ := VectorToolByKey("nomore403")
	for key, meta := range tool.Options {
		if meta.Flag == "--raw-http" {
			t.Errorf("%s offers --raw-http, which gates nothing: it would tell an operator they had "+
				"enabled something", key)
		}
	}
	if _, owned := tool.OwnedFlags["--raw-http"]; !owned {
		t.Error("--raw-http must be recorded as owned, with the reason, so it is not re-added later")
	}
}

// The payload directory is passed explicitly.
//
// nomore403's --help says the folder defaults to "the same directory as the executable". Its source
// says otherwise: the default is the literal relative path "payloads", resolved against the process
// working directory. Anything that changes the working directory leaves it with no header, endpath or
// midpath payloads, and the run completes having tried a fraction of what the report implies.
func TestNomore403AlwaysPointsAtItsPayloadDirectory(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	args, _ := ComposeNomore403(v, map[string]any{}, "/tmp/rep")

	if !argsContainPair(args, "-f", nomore403PayloadDir) {
		t.Errorf("the payload directory must be explicit, not inherited from the working directory: %v", args)
	}
}

// An option with no Flag is not a command line argument: it is either a target list the composer
// consumes itself, or a switch that folds into a flag built elsewhere. Forbidden has twenty such
// options, nineteen test families plus its endpoint list.
//
// Emitted anyway they became bare "" argv entries, plus the endpoint list as a stray positional.
// Forbidden rejected the command line, printed usage and exited 0 in a third of a second, and exit 0
// with no report file is indistinguishable from a clean scan. The section reported no bypass on a
// target where X-Original-URL: /admin returns the admin panel to an anonymous caller.
func TestFlaglessSettingsNeverReachTheCommandLine(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/admin",
		EvidenceURL: "https://ginandjuice.shop/admin", InsertionPoint: "path",
	}
	settings := map[string]any{
		"endpoints":     "https://ginandjuice.shop/admin",
		"pathOverrides": true, "methods": true, "headers": true, "encodings": true,
		"paths": true, "parsers": true, "redirects": true, "uploads": true,
		"ignore": "Access denied", "path": "/about", "threads": 3,
	}
	args, _ := ComposeForbidden(v, settings, "/tmp/report.out")

	for i, a := range args {
		if a == "" {
			t.Errorf("argv[%d] is an empty string; the whole command line is rejected: %q", i, args)
		}
	}
	// The endpoint list must not appear as a bare positional either.
	for i := 1; i < len(args); i++ {
		if args[i] == "https://ginandjuice.shop/admin" && args[i-1] != "-u" {
			t.Errorf("the endpoint list leaked in as a positional at argv[%d]: %q", i, args)
		}
	}
	// The switches must still have done their job.
	if !argsContainPair(args, "-t", "methods,path-overrides,headers,paths,encodings,redirects,parsers,uploads") &&
		!argsContain(args, "-t") {
		t.Error("the test families did not fold into -t")
	}
	if !argsContainPair(args, "-i", "Access denied") {
		t.Error("a real flagged option was dropped by the fix")
	}
	if !argsContainPair(args, "-p", "/about") {
		t.Error("the known-accessible path was dropped")
	}
}

// ---------------------------------------------------------------------------
// An access control check must not write to the target.
// ---------------------------------------------------------------------------
//
// MEASURED, one pass of both tools against a live application: 24 of the findings were
// POST -> 201 Created against /api/Users and /api/SecurityAnswers. 20 came from nomore403's verb
// tampering and method override, 4 from Forbidden's method overrides. Every one of those 201s is a
// ROW the scanner created in the operator's own application while claiming to be READING whether an
// access control decision could be avoided.
//
// bypassWriteSetting is spelled out rather than referenced by constant, so this test states the
// contract in the same words a stored settings blob does.
const bypassWriteSwitch = "allowStateChangingRequests"

// Nothing state-changing runs unless it is asked for, and the DEFAULT path is the one that mattered:
// leaving the technique switches alone is what a fresh install does.
func TestBypassToolsSendNoStateChangingRequestsByDefault(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}

	// nomore403. Omitting -k is not "no techniques", it is nomore403's own default of all
	// twenty-three, three of which send POST, PUT, PATCH and DELETE. So -k must be present AND must
	// not name them.
	args, _ := ComposeNomore403(v, map[string]any{}, "/tmp/rep")
	if args == nil {
		t.Fatal("the default nomore403 run must still happen, just without the writing techniques")
	}
	if !argsContain(args, "-k") {
		t.Fatalf("-k was omitted, so nomore403 used its own default of all 23 techniques including "+
			"verbs, verbs-case and method-override: %v", args)
	}
	techniques := strings.Split(argValueAfter(args, "-k"), ",")
	// raw-desync is in this list because it was MEASURED, not because its name suggests it: four of
	// its seven raw payloads are POST and three carry a body. It survived the first pass of this fix.
	for _, writing := range []string{"verbs", "verbs-case", "method-override", "raw-desync"} {
		if containsExactly(techniques, writing) {
			t.Errorf("the default nomore403 run includes %q, which sends POST, PUT, PATCH and DELETE "+
				"at the operator's application", writing)
		}
	}
	if len(techniques) < 15 {
		t.Errorf("only %d techniques survived; dropping the three that write must not gut the scan: %v",
			len(techniques), techniques)
	}

	// Forbidden. methods sends whatever OPTIONS advertises, method-overrides hardcodes a POST body,
	// and uploads sends PUT /pentest.txt into every directory of the path.
	args, _ = ComposeForbidden(v, map[string]any{}, "/tmp/rep")
	if args == nil {
		t.Fatal("the default Forbidden run must still happen, just without the writing tests")
	}
	tests := strings.Split(argValueAfter(args, "-t"), ",")
	if len(tests) == 0 || tests[0] == "" {
		t.Fatal("-t must never be empty: Forbidden answers that with usage text and exit 0")
	}
	for _, writing := range []string{"methods", "method-overrides", "uploads"} {
		if containsExactly(tests, writing) {
			t.Errorf("the default Forbidden run includes %q, which writes to the target", writing)
		}
	}
}

// The switch is the ONLY thing that can turn writing on, it is off by default, and a run that has it
// on says so every time rather than relying on a checkbox nobody has looked at since.
func TestBypassWritingFamiliesNeedTheExplicitSwitch(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}

	// A technique switch on its own is not enough. This is the case that matters most: a settings
	// blob stored before any of this existed already has verbs turned on.
	args, warnings := ComposeNomore403(v, map[string]any{"verbs": true, "methodOverride": true}, "/tmp/rep")
	if args != nil {
		t.Errorf("every selected nomore403 technique writes, so the run must be refused rather than "+
			"quietly sending POST and DELETE: %v", args)
	}
	if !warningMentions(warnings, "NOT run") {
		t.Errorf("a refused run has to say so: %v", warnings)
	}

	args, warnings = ComposeForbidden(v, map[string]any{"uploads": true}, "/tmp/rep")
	if args != nil {
		t.Errorf("uploads sends PUT /pentest.txt, so with nothing else selected the run must be "+
			"refused rather than emitting an empty -t: %v", args)
	}
	if !warningMentions(warnings, "NOT run") {
		t.Errorf("a refused run has to say so: %v", warnings)
	}

	// A writing family beside a safe one is dropped, not silently kept, and the drop is reported.
	args, warnings = ComposeNomore403(v, map[string]any{"verbs": true, "pathCase": true}, "/tmp/rep")
	if got := argValueAfter(args, "-k"); got != "path-case" {
		t.Errorf("verb tampering must be dropped and path-case kept, got -k %q", got)
	}
	if !warningMentions(warnings, "verbs") {
		t.Errorf("dropping a technique the operator selected must be reported: %v", warnings)
	}

	// And with the switch on, they run, loudly.
	args, warnings = ComposeNomore403(v,
		map[string]any{"verbs": true, "methodOverride": true, bypassWriteSwitch: true}, "/tmp/rep")
	if got := argValueAfter(args, "-k"); !strings.Contains(got, "verbs") ||
		!strings.Contains(got, "method-override") {
		t.Errorf("with the switch on the operator's own choice must run, got -k %q", got)
	}
	if !warningMentions(warnings, "STATE-CHANGING REQUESTS ARE ENABLED") {
		t.Errorf("a run that writes must say so every time: %v", warnings)
	}

	args, warnings = ComposeForbidden(v, map[string]any{"uploads": true, bypassWriteSwitch: true}, "/tmp/rep")
	if got := argValueAfter(args, "-t"); !strings.Contains(got, "uploads") {
		t.Errorf("with the switch on the operator's own choice must run, got -t %q", got)
	}
	if !warningMentions(warnings, "STATE-CHANGING REQUESTS ARE ENABLED") {
		t.Errorf("a run that writes must say so every time: %v", warnings)
	}
}

// A forced HTTP method is a stored setting that would make EVERY request a write, including the
// request Forbidden sends to validate the target before a single test has run.
func TestBypassRefusesAStoredForcedWriteMethod(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}

	for _, unsafe := range []string{"POST", "delete", "PUT", "POUET"} {
		if args, warnings := ComposeNomore403(v, map[string]any{"httpMethod": unsafe}, "/tmp/rep"); args != nil {
			t.Errorf("nomore403 forced to %s must be refused: %v", unsafe, args)
		} else if !warningMentions(warnings, "NOT run") {
			t.Errorf("the refusal must name itself: %v", warnings)
		}
		if args, _ := ComposeForbidden(v, map[string]any{"force": unsafe}, "/tmp/rep"); args != nil {
			t.Errorf("Forbidden forced to %s must be refused: %v", unsafe, args)
		}
	}

	// The read-only verbs still work, including the ones the section actually needs.
	for _, safe := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if args, _ := ComposeNomore403(v, map[string]any{"httpMethod": safe}, "/tmp/rep"); args == nil {
			t.Errorf("%s changes nothing and must be allowed", safe)
		}
		if args, _ := ComposeForbidden(v, map[string]any{"force": safe}, "/tmp/rep"); args == nil {
			t.Errorf("%s changes nothing and must be allowed", safe)
		}
	}

	// With the switch on, the operator's choice stands.
	if args, _ := ComposeNomore403(v,
		map[string]any{"httpMethod": "POST", bypassWriteSwitch: true}, "/tmp/rep"); args == nil {
		t.Error("with the switch on a forced POST is the operator's decision to make")
	}
}

// A method override header rides on EVERY request either tool sends, including the hundreds of path
// mutations that have nothing to do with verbs, so one typed into the extra header field turns the
// whole scan into write traffic.
func TestBypassDropsMethodOverrideHeadersFromTheOperatorsOwnList(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}

	for _, header := range []string{
		"X-HTTP-Method-Override: DELETE",
		"x-method-override: PUT",
		"X-HTTP-Method: POST",
	} {
		args, warnings := ComposeNomore403(v, map[string]any{"extraHeaders": header}, "/tmp/rep")
		if argsContainPair(args, "-H", header) {
			t.Errorf("%q would make every request in the scan a write: %v", header, args)
		}
		if !warningMentions(warnings, "Dropped") {
			t.Errorf("dropping the operator's own header must be reported: %v", warnings)
		}
		if args, _ := ComposeForbidden(v, map[string]any{"extraHeaders": header}, "/tmp/rep"); argsContainPair(args, "-H", header) {
			t.Errorf("Forbidden kept %q: %v", header, args)
		}
	}

	// An ordinary header, and an override naming a safe verb, both survive. An auth header is the
	// whole reason the field exists.
	for _, kept := range []string{"Authorization: Bearer ey...", "X-HTTP-Method-Override: GET"} {
		if args, _ := ComposeNomore403(v, map[string]any{"extraHeaders": kept}, "/tmp/rep"); !argsContainPair(args, "-H", kept) {
			t.Errorf("%q changes nothing and must be sent: %v", kept, args)
		}
		if args, _ := ComposeForbidden(v, map[string]any{"extraHeaders": kept}, "/tmp/rep"); !argsContainPair(args, "-H", kept) {
			t.Errorf("Forbidden dropped %q: %v", kept, args)
		}
	}
}

// The extra header field has to EXIST before it can carry anything.
//
// The technique and test switches are merged over the option map, so an option sharing a key with
// one of them is silently replaced. Both tools had an "Extra header" option keyed "headers", and
// both tools also have a "headers" technique or test, so the option was gone: the Config modal never
// drew the field, and a session token stored under that key was read as a bool, found not to be the
// string "true", and dropped without a word. Every scan this section ran was anonymous.
func TestBypassOptionKeysDoNotCollideWithTechniqueKeys(t *testing.T) {
	for _, tc := range []struct {
		key      string
		switches []string
	}{
		{"nomore403", techniqueKeys()},
		{"forbidden", testKeys()},
	} {
		tool, ok := VectorToolByKey(tc.key)
		if !ok {
			t.Fatalf("%s is not registered", tc.key)
		}
		meta, ok := tool.Options["extraHeaders"]
		if !ok || meta.Flag != "-H" {
			t.Errorf("%s has no reachable extra header option, so a bypass scan can never carry a "+
				"session token", tc.key)
		}
		for _, name := range tc.switches {
			if meta, ok := tool.Options[name]; ok && meta.Flag != "" {
				t.Errorf("%s option %q is both a switch and a flagged option; the switch wins the "+
					"merge and the flagged option disappears", tc.key, name)
			}
		}
	}
}

func techniqueKeys() []string {
	out := make([]string, 0, len(nomore403Techniques))
	for _, technique := range nomore403Techniques {
		out = append(out, technique.Key)
	}
	return out
}

func testKeys() []string {
	out := make([]string, 0, len(forbiddenTests))
	for _, test := range forbiddenTests {
		out = append(out, test.Key)
	}
	return out
}

// ---------------------------------------------------------------------------
// A finding must be about the URL that was actually requested.
// ---------------------------------------------------------------------------
//
// MEASURED: 28 of Forbidden's 74 findings, 38%, never touched the endpoint they claim to be about.
// Forbidden's path override family is three record sets and only the third requests the URL under
// test. PATH-OVERRIDES-1 requests the ACCESSIBLE path from -p, PATH-OVERRIDES-2 requests the SITE
// ROOT, and both carry X-Original-URL and its siblings pointed at the endpoint. Fourteen results
// were an ordinary /robots.txt, 28 bytes and entirely public. Fourteen were an ordinary homepage,
// 9641 bytes. All 28 were reported as a bypass of a completely different endpoint.
//
// Forbidden has the control and the framework was not using it: -l accepts the literal word "path",
// meaning "filter out anything the length of the accessible URL's own response". Pinning the
// accessible path to the site root makes record sets 1 and 2 request the same URL, so one filter
// covers both.
func TestForbiddenComparesPathOverrideResultsAgainstTheURLItRequested(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/ftp/package.json.bak"}
	args, _ := ComposeForbidden(v, map[string]any{"pathOverrides": true}, "/tmp/rep")

	lengths := argValueAfter(args, "-l")
	if !strings.Contains(lengths, "path") {
		t.Errorf("-l %q does not filter the accessible page's own response, so its ordinary 200 is "+
			"reported as a bypass of the endpoint under test", lengths)
	}
	if !strings.Contains(lengths, "initial") {
		t.Errorf("-l %q does not filter this target's own denial", lengths)
	}
	if got := argValueAfter(args, "-p"); got != "/" {
		t.Errorf("the accessible path must default to the site root so the -l path filter covers "+
			"BOTH record sets that request a URL other than the endpoint, got -p %q", got)
	}
}

// An operator who names their own accessible path gets it, and gets told what it leaves uncovered:
// the second record set requests the site root whatever -p says.
func TestForbiddenSaysWhatAChosenAccessiblePathLeavesUnfiltered(t *testing.T) {
	v := VectorInput{EvidenceURL: "http://x.example.com/admin"}
	args, warnings := ComposeForbidden(v,
		map[string]any{"pathOverrides": true, "path": "/robots.txt"}, "/tmp/rep")

	if got := argValueAfter(args, "-p"); got != "/robots.txt" {
		t.Errorf("the operator's own accessible path must be used, got %q", got)
	}
	if !strings.Contains(argValueAfter(args, "-l"), "path") {
		t.Error("the accessible page's length must still be filtered")
	}
	if !warningMentions(warnings, "site root") {
		t.Errorf("a chosen path leaves the root record set uncovered and that must be stated: %v", warnings)
	}
}

// Forbidden gives up during validation by printing a red line and returning, and the process still
// exits ZERO having written no report. Exit 0 with no report is byte for byte a clean scan.
//
// This is reachable from a framework default: given a single -p, an accessible path that does not
// answer 2xx stops the whole run before a single test.
func TestForbiddenValidationExitIsNotACleanScan(t *testing.T) {
	tool, ok := VectorToolByKey("forbidden")
	if !ok {
		t.Fatal("forbidden is not registered")
	}
	if tool.Incomplete == nil {
		t.Fatal("Forbidden exits 0 and writes no report when it gives up during validation, which is " +
			"indistinguishable from a clean scan, so it needs an Incomplete check")
	}

	for _, stdout := range []string{
		"Normalized accessible URL: http://x.example.com/\n" +
			"Accessible URL did not return 2xx HTTP response status code, the tool will now exit...\n",
		"Inaccessible URL is not valid, the tool will now exit...\n",
		"Number of created test records: 0\nNo test records were created\n",
	} {
		if why := tool.Incomplete(stdout, ""); why == "" {
			t.Errorf("this run tested nothing and would have been stored as clean: %q", stdout)
		}
	}

	// A run that really worked is not flagged.
	ok2 := "Validating the inaccessible URL using the HTTP GET method...\n" +
		"Ignoring the inaccessible URL response content length: 1934\n" +
		"Number of created test records: 1472\nProgress: 1472/1472\n"
	if why := tool.Incomplete(ok2, `[{"url":"http://x/a","status":"200"}]`); why != "" {
		t.Errorf("a completed run must not be flagged: %q", why)
	}
}

func warningMentions(warnings []string, want string) bool {
	for _, w := range warnings {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}

func containsExactly(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

// The same defect reaches every section, because composeVectorSettings is shared. nomore403 has
// twenty-three flagless technique switches plus its own endpoint list.
func TestNomore403AlsoEmitsNoEmptyArguments(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "ginandjuice.shop", Path: "/admin",
		EvidenceURL: "https://ginandjuice.shop/admin", InsertionPoint: "path",
	}
	args, _ := ComposeNomore403(v, map[string]any{
		"endpoints": "https://ginandjuice.shop/admin",
		"headers":   true, "unicode": true, "midpaths": true, "verbs": true,
		"bypassIp": "127.0.0.1",
	}, "/tmp/report.out")

	for i, a := range args {
		if a == "" {
			t.Errorf("argv[%d] is an empty string: %q", i, args)
		}
	}
	if !argsContainPair(args, "-i", "127.0.0.1") {
		t.Error("a real flagged option was dropped")
	}
}

// =================================================================================================
// THE NEGATIVE CONTROL, and the two reasons 159 findings against OWASP Juice Shop were all false.
//
// Everything below was written against a measured run: seven scanners produced 165 findings, 159 of
// them from these two tools, and an adversarial review reduced the lot to zero. The framework's own
// data said so at the time and nothing acted on it, so each of these tests pins one of the ways a
// non-finding used to become a finding.
// =================================================================================================

// A NON-RESPONSE IS NOT A BYPASS.
//
// Measured: 17 of nomore403's 85 results carried status 0 with a zero-byte body, meaning the request
// never completed. Six were scored 27 by the tool and two were scored 61, so its own score kept
// them. The framework repeated the mistake because it only discarded results at status 400 and
// above, and 0 is not 400.
func TestBypassNeverScoresANonResponseAsABypass(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		t.Errorf("a dead connection must be rejected without spending a request on it: %s", req.URL)
		return bypassProbeResult{}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":0,"content_length":0,"technique":"headers","score":61,"likelihood":"high","body_hash":"","payload":"http://10.0.0.18:3000/ftp/package.json.bak"}`,
		`{"status_code":0,"content_length":0,"technique":"midpaths","score":27,"likelihood":"low","body_hash":"x","payload":"http://10.0.0.18:3000/ftp/package.json.bak"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if got := bypassFindingsOfKind(findings, "access-control-bypass"); len(got) != 0 {
		t.Fatalf("a request that never completed is not access, got %d bypass findings: %+v", len(got), got)
	}

	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 {
		t.Fatalf("the rejections have to be counted and explained, not silently dropped: %+v", findings)
	}
	if !strings.Contains(notes[0].Evidence, "2 "+bypassRejectNoResponse) {
		t.Errorf("both non-responses must be counted by name: %q", notes[0].Evidence)
	}
	// Scoring a non-response is the inverted detector. Say so where an operator will read it.
	if !strings.Contains(notes[0].Evidence, "61") {
		t.Errorf("the tool's own score for a dead connection is worth quoting back: %q", notes[0].Evidence)
	}
}

// AN EMPTY RESPONSE WITHHOLDS NOTHING.
//
// Measured: 18 of nomore403's 85 were OPTIONS answered 204 with a zero-byte body. There is no
// protected content in an empty response, so it cannot demonstrate access to any.
func TestBypassRejectsAnEmptyResponseThatWithheldNothing(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		t.Errorf("an empty 204 must be rejected without spending a request on it: %s", req.URL)
		return bypassProbeResult{}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":204,"content_length":0,"technique":"verbs","payload":"OPTIONS","score":55,"likelihood":"medium","body_hash":"bbbb"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if got := bypassFindingsOfKind(findings, "access-control-bypass"); len(got) != 0 {
		t.Fatalf("an empty 204 contains nothing that was being withheld: %+v", got)
	}
	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 || !strings.Contains(notes[0].Evidence, bypassRejectEmptyBody) {
		t.Fatalf("the empty-body class has to be rejected by name: %+v", findings)
	}
}

// THE CONTROL, against the exact shape that produced 30 of nomore403's dead findings.
//
// Juice Shop answers 200 with the same Angular shell to every path that does not exist, and the
// shell reflects the requested path back, so its LENGTH is a function of the request string. The
// same target file produced seven different response lengths across one run. Nothing about that is
// a bypass, and nothing a report parser can see distinguishes it from one.
func TestBypassRejectsACandidateTheControlReproduces(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	var asked []string
	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		asked = append(asked, req.URL)
		return bypassProbeResult{Body: juiceShopShell(req.URL), ContentType: "text/html"}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":200,"content_length":11390,"technique":"endpaths","score":100,"likelihood":"high",` +
			`"body_hash":"bbbb","payload":"http://10.0.0.18:3000/ftp/package.json.bak..;/",` +
			`"repro_curl":"curl -i -sS -k 'http://10.0.0.18:3000/ftp/package.json.bak..;/'"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if got := bypassFindingsOfKind(findings, "access-control-bypass"); len(got) != 0 {
		t.Fatalf("the catch-all page is not a bypass: %+v", got)
	}

	// The control has to have been aimed at the url the TOOL requested, not at the target url. That
	// distinction is the entire defect.
	sawMutated := false
	for _, u := range asked {
		if strings.Contains(u, "package.json.bak..;") {
			sawMutated = true
		}
	}
	if !sawMutated {
		t.Errorf("the request under test was never re-sent at the url the tool used: %v", asked)
	}
	if len(asked) < 2 {
		t.Errorf("a control must have been sent alongside it: %v", asked)
	}

	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 {
		t.Fatalf("the rejection has to be recorded: %+v", findings)
	}
	if !strings.Contains(notes[0].Evidence, bypassRejectControlSame) {
		t.Errorf("the reason must say the control reproduced it: %q", notes[0].Evidence)
	}
	if !strings.Contains(notes[0].Evidence, bypassControlSibling) {
		t.Errorf("which control killed it must be named: %q", notes[0].Evidence)
	}
}

// The one that must survive: a real bypass on the same target.
//
// /ftp/package.json.bak is 403 at 1934 bytes; /ftp/package.json.bak%2500.md is 200 at 4440 bytes of
// the actual file. The control returns the catch-all shell, so this one is different from what any
// path returns, and it is kept.
func TestBypassKeepsACandidateTheControlDoesNotReproduce(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	realFile := `{"name":"juice-shop","version":"20.2.0","dependencies":{` +
		strings.Repeat(`"pkg":"1.0.0",`, 300) + `"end":"1"}}`

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		if strings.Contains(req.URL, "package.json.bak%2500.md") {
			return bypassProbeResult{Body: realFile, ContentType: "application/json"}
		}
		return bypassProbeResult{Body: juiceShopShell(req.URL), ContentType: "text/html"}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":200,"content_length":4440,"technique":"suffix-tricks","score":100,"likelihood":"high",` +
			`"body_hash":"cccc","payload":"http://10.0.0.18:3000/ftp/package.json.bak%2500.md",` +
			`"repro_curl":"curl -i -sS -k 'http://10.0.0.18:3000/ftp/package.json.bak%2500.md'"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	got := bypassFindingsOfKind(findings, "access-control-bypass")
	if len(got) != 1 {
		t.Fatalf("a poison null byte reaching the real file is the finding this section exists for: %+v", findings)
	}

	// BOTH ARMS ARE STORED. Every one of the 159 dead findings carried raw_response = "" and a
	// request marked "RECONSTRUCTED REQUEST, NOT CAPTURED BYTES". A comparison an operator cannot
	// see is a comparison an operator cannot check.
	if !strings.Contains(got[0].RawResponse, "REQUEST UNDER TEST") ||
		!strings.Contains(got[0].RawResponse, "NEGATIVE CONTROL") {
		t.Errorf("the finding must carry both arms: %q", got[0].RawResponse)
	}
	if !strings.Contains(got[0].RawResponse, "juice-shop") {
		t.Errorf("the protected response has to be the real bytes, not a summary: %q", got[0].RawResponse)
	}
	if !strings.Contains(got[0].RawResponse, "app-root") {
		t.Errorf("the control response has to be stored too: %q", got[0].RawResponse)
	}
	if strings.Contains(got[0].RawRequest, "NOT CAPTURED BYTES") || got[0].RawRequest == "" {
		t.Errorf("these bytes were really sent, so they must not be marked reconstructed: %q", got[0].RawRequest)
	}
	if !strings.Contains(got[0].Confidence, "CONTROLLED") {
		t.Errorf("the verdict must say a control was run: %q", got[0].Confidence)
	}
}

// Forbidden's own worst class: 28 of its 74 results requested a DIFFERENT PUBLIC URL entirely, 14
// of them the bare site root and 14 of them /robots.txt at 28 bytes, each with a rewriting header
// that changed nothing. Stripping the header and asking again is all it takes.
func TestForbiddenRejectsAPublicURLFetchedWithAnInertHeader(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	robots := "User-agent: *\nDisallow: /ftp\n"
	sawHeaderless := false
	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		if len(req.Headers) == 0 {
			sawHeaderless = true
		}
		return bypassProbeResult{Body: robots, ContentType: "text/plain"}
	})

	report := `[{"id":"3-PATH-OVERRIDES-1","url":"http://10.0.0.18:3000/robots.txt","method":"GET",` +
		`"command":"curl -i -sS 'http://10.0.0.18:3000/robots.txt' -H 'X-Original-URL: /ftp/package.json.bak'",` +
		`"status":"200","length":"28"}]`

	findings := parseForbiddenReport("", report, row)
	if got := bypassFindingsOfKind(findings, "access-control-bypass"); len(got) != 0 {
		t.Fatalf("a public file fetched with an inert header is not a bypass: %+v", got)
	}
	if !sawHeaderless {
		t.Error("the control must re-send the same url with the rewriting header removed")
	}
	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 || !strings.Contains(notes[0].Evidence, bypassControlHeaderStripped) {
		t.Fatalf("the header-stripped control has to be named as what killed it: %+v", findings)
	}
	if !strings.Contains(notes[0].Evidence, "X-Original-URL") {
		t.Errorf("the header that did nothing should be named: %q", notes[0].Evidence)
	}
}

// THE ONE THE CONTROL MUST NOT KILL, and the reason the two controls are an either rather than a
// both.
//
// A rewriting header is this bug class at its purest: measured on ginandjuice.shop, GET /about with
// "X-Original-URL: /admin" returns the admin panel to an anonymous caller. The check is applied to
// the request path and the routing decision is made from the header. Sent to a made-up sibling path
// that same header still rewrites to /admin, so a sibling control would come back identical to the
// response under test and throw the finding away. Stripping the header is the control that works.
func TestBypassKeepsARewritingHeaderTheControlDoesNotReproduce(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	adminPanel := "<html><body><h1>Administration</h1>" + strings.Repeat("<tr>user</tr>", 200) + "</body></html>"
	var asked []bypassProbeRequest
	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		asked = append(asked, req)
		// The header rewrites the route WHATEVER path is requested. That is the bug.
		for _, h := range req.Headers {
			if strings.HasPrefix(strings.ToLower(h), "x-original-url:") {
				return bypassProbeResult{Body: adminPanel, ContentType: "text/html"}
			}
		}
		return bypassProbeResult{Body: "User-agent: *\nDisallow: /ftp\n", ContentType: "text/plain"}
	})

	report := `[{"id":"3-PATH-OVERRIDES-1","url":"http://10.0.0.18:3000/robots.txt","method":"GET",` +
		`"command":"curl -i -sS 'http://10.0.0.18:3000/robots.txt' -H 'X-Original-URL: /ftp/package.json.bak'",` +
		`"status":"200","length":"4100"}]`

	findings := parseForbiddenReport("", report, row)
	got := bypassFindingsOfKind(findings, "access-control-bypass")
	if len(got) != 1 {
		t.Fatalf("a rewriting header that returns the protected page IS the finding: %+v", findings)
	}
	if !strings.Contains(got[0].RawResponse, "Administration") {
		t.Errorf("the protected response must be stored: %q", got[0].RawResponse)
	}

	// A sibling control here would rewrite to the same place and wrongly kill it, so it must not run.
	for _, req := range asked {
		if strings.Contains(req.URL, bypassSiblingFiller[:3]) {
			t.Errorf("a header technique must not be judged by a sibling path: %s", req.URL)
		}
	}
}

// The sibling control only works if it is the SAME LENGTH.
//
// Measured on this target, response length is a deterministic function of the requested path
// STRING: 40 characters gave 11336 bytes and 58 gave 11467. A sibling of a different length comes
// back a different size, the comparison calls that a difference, and the catch-all page is reported
// as a bypass all over again.
func TestBypassSiblingURLKeepsTheLengthAndTheEscapes(t *testing.T) {
	for _, in := range []string{
		"http://10.0.0.18:3000/ftp/package.json.bak",
		"http://10.0.0.18:3000/ftp/package.json.bak%2500.md",
		"http://10.0.0.18:3000/rest/admin/application-configuration?a=1",
	} {
		out := bypassSiblingURL(in)
		if out == "" {
			t.Fatalf("no sibling could be built for %q", in)
		}
		if len(out) != len(in) {
			t.Errorf("the sibling must be the same length, %d vs %d: %q -> %q", len(in), len(out), in, out)
		}
		if out == in {
			t.Errorf("the sibling must not be the url under test: %q", out)
		}
	}

	// Nothing to scramble means no sibling, said plainly rather than by inventing one.
	if got := bypassSiblingURL("http://10.0.0.18:3000/"); got != "" {
		t.Errorf("a bare root has no sibling to build: %q", got)
	}
}

// A verb this framework will not send has no control, and a candidate with no control is not
// reported as a bypass. 20 of nomore403's 85 and 4 of Forbidden's 74 were POST answered 201
// Created, which is the application accepting a new request rather than a refused resource being
// reached.
func TestBypassWillNotClaimABypassItCannotControl(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		t.Errorf("no request may be sent for a verb the framework refuses: %s %s", req.Method, req.URL)
		return bypassProbeResult{}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":201,"content_length":40,"technique":"verbs","payload":"POST","score":80,"likelihood":"high","body_hash":"eeee"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	if got := bypassFindingsOfKind(findings, "access-control-bypass"); len(got) != 0 {
		t.Fatalf("a POST answered 201 is not evidence a refused resource was reached: %+v", got)
	}
	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 || !strings.Contains(notes[0].Evidence, bypassHoldUnsafeVerb) {
		t.Fatalf("it must be held for the right reason, not silently dropped: %+v", findings)
	}
}

// The count of what was thrown away, and why, has to be visible. Replacing "159 findings" with an
// unexplained "0 findings" is the same failure wearing a smaller number.
func TestBypassRejectionsAreCountedAndExplained(t *testing.T) {
	row := vectorRow{ID: "t1", InsertionPoint: "path", Method: "GET",
		EvidenceURL: "http://10.0.0.18:3000/ftp/package.json.bak", IsBypassTarget: true, BaselineStatus: 403}

	stubBypassControl(t, func(req bypassProbeRequest) bypassProbeResult {
		return bypassProbeResult{Body: juiceShopShell(req.URL), ContentType: "text/html"}
	})

	report := strings.Join([]string{
		`{"status_code":403,"content_length":1934,"technique":"default","body_hash":"aaaa"}`,
		`{"status_code":0,"content_length":0,"technique":"headers","score":61,"body_hash":"b1"}`,
		`{"status_code":204,"content_length":0,"technique":"verbs-case","payload":"OpTiOnS","score":30,"body_hash":"b2"}`,
		`{"status_code":200,"content_length":11390,"technique":"endpaths","score":100,"likelihood":"high","body_hash":"b3",` +
			`"repro_curl":"curl -i -sS -k 'http://10.0.0.18:3000/ftp/package.json.bak..;/'"}`,
		`{"status_code":201,"content_length":40,"technique":"verbs","payload":"POST","score":80,"body_hash":"b4"}`,
	}, "\n")

	findings := parseNomore403Report("", report, row)
	notes := bypassFindingsOfKind(findings, "bypass-candidates-rejected")
	if len(notes) != 1 {
		t.Fatalf("expected one accounting note, got %+v", findings)
	}
	evidence := notes[0].Evidence
	if !strings.Contains(evidence, "4 candidate bypasses") {
		t.Errorf("the note must say how many candidates there were: %q", evidence)
	}
	if !strings.Contains(evidence, "0 survived") {
		t.Errorf("the note must say how many survived: %q", evidence)
	}
	for _, slug := range []string{
		bypassRejectNoResponse, bypassRejectEmptyBody, bypassRejectControlSame, bypassHoldUnsafeVerb,
	} {
		if !strings.Contains(evidence, slug) {
			t.Errorf("every rejection class has to be named: %q missing from %q", slug, evidence)
		}
	}
	if notes[0].Severity != "info" {
		t.Errorf("the accounting note is not a vulnerability: %q", notes[0].Severity)
	}
}

// juiceShopShell reproduces the measured behaviour of the target: every path that does not exist
// answers 200 with the same Angular shell, and the shell echoes the requested path back, so its
// length varies with the request string rather than with anything on the server.
func juiceShopShell(requestURL string) string {
	path := requestURL
	if parsed, err := neturl.Parse(requestURL); err == nil {
		path = parsed.EscapedPath()
	}
	return "<!DOCTYPE html><html><head><title>OWASP Juice Shop</title></head><body>" +
		"<app-root data-route=\"" + path + "\"></app-root>" +
		strings.Repeat("<!-- angular runtime -->", 400) +
		"</body></html>"
}

// A scan must never take the API process down with it.
//
// MEASURED, and it was one ordering mistake away from happening on the first real bypass scan:
// bypassAcquireHost was called before bypassScanClient(), and only bypassScanClient() initialises
// bypassBudget inside its sync.Once, so the first live control dereferenced a nil *HostBudget:
//
//	utils.(*HostBudget).Acquire(0x0, ...)  paceBudget.go:129
//	utils.bypassAcquireHost(...)           bypassControl.go
//	panic: runtime error: invalid memory address or nil pointer dereference
//
// runVectorScan is launched as a bare `go runVectorScan(...)`, so that panic would have killed the
// whole api process, every other running scan, and every request in flight. Five other long runners
// in this package already had a recover; the vector path had none.
//
// The ordering is fixed. This asserts the GUARD, so the next mistake costs one scan rather than the
// service, and so the crashed scan is recorded UNTESTED rather than left running forever.
func TestAPanickingVectorScanDoesNotTakeTheProcessDown(t *testing.T) {
	// The guard is a deferred recover at the top of runVectorScan. Assert it is present and that it
	// records the scan as failed, by reading the source: calling runVectorScan needs a live dbPool.
	src, err := os.ReadFile("vectorScan.go")
	if err != nil {
		t.Fatalf("cannot read vectorScan.go: %v", err)
	}
	body := string(src)

	fn := strings.Index(body, "func runVectorScan(")
	if fn < 0 {
		t.Fatal("runVectorScan is gone; this guard needs re-pointing")
	}
	// Look only at the head of the function, where a deferred recover has to be to cover it all.
	head := body[fn:min(fn+2500, len(body))]

	if !strings.Contains(head, "recover()") {
		t.Error("runVectorScan has no deferred recover. It runs as a bare goroutine, so any panic " +
			"inside it kills the api process rather than the scan")
	}
	if !strings.Contains(head, "defer func()") {
		t.Error("the recover is not in a deferred function, so it cannot catch anything")
	}
	// A crashed scan must not be left at "running" with no process behind it.
	if !strings.Contains(head, "UNTESTED") {
		t.Error("a crashed scan is not recorded as UNTESTED, so its unreached vectors read as clean")
	}
	if !strings.Contains(head, "status = 'error'") {
		t.Error("a crashed scan is not moved to a terminal status, so it sits at 'running' forever")
	}
}

// The negative control must not be able to leave the engagement.
//
// Every other ScanClient in this package is built .WithScope(scope). This one was not, so the
// control followed whatever hostname the TOOL wrote into its report. That is the exact shape of this
// section's failure: Forbidden requested the bare site root and /robots.txt instead of the endpoint
// it claimed, and its path is operator-configurable.
func TestTheBypassControlRefusesAnOutOfScopeHost(t *testing.T) {
	src, err := os.ReadFile("bypassControl.go")
	if err != nil {
		t.Fatalf("cannot read bypassControl.go: %v", err)
	}
	body := string(src)

	probe := strings.Index(body, "func liveBypassControlProbe(")
	if probe < 0 {
		t.Fatal("liveBypassControlProbe is gone; this guard needs re-pointing")
	}
	send := strings.Index(body[probe:], "client.Do(ctx")
	if send < 0 {
		t.Fatal("the control no longer sends through client.Do; re-point this guard")
	}
	before := body[probe : probe+send]

	for _, want := range []string{"LoadScanScope", "Allows(", "Refuse("} {
		if !strings.Contains(before, want) {
			t.Errorf("the control sends a request without calling %s first, so it can reach a host "+
				"outside the engagement", want)
		}
	}
	// And the client must be taken BEFORE the budget is acquired, or bypassBudget is nil.
	clientAt := strings.Index(before, "bypassScanClient()")
	acquireAt := strings.Index(before, "bypassAcquireHost(")
	if clientAt < 0 || acquireAt < 0 {
		t.Fatal("cannot find the client and budget calls to check their order")
	}
	if acquireAt < clientAt {
		t.Error("bypassAcquireHost runs before bypassScanClient(), so bypassBudget is nil and the " +
			"first live control panics")
	}
}
