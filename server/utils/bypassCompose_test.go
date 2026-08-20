package utils

import (
	"strings"
	"testing"
)

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
	if argsContain(args, "-k") {
		t.Error("with nothing selected -k must be omitted so nomore403 uses its own full default")
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

	if !argsContainPair(args, "-l", "initial") {
		t.Errorf("the original denial's length must be filtered out by default: %v", args)
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

	// An operator's own choice wins, and is not doubled up.
	own, _ := ComposeForbidden(v, map[string]any{"contentLengths": "1234"}, "/tmp/rep")
	if strings.Count(strings.Join(own, " "), "-l ") > 1 {
		t.Errorf("two -l flags were emitted; the second would win: %v", own)
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
