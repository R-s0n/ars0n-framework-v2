package utils

import (
	"strconv"
	"strings"
	"testing"
)

// The Miscellaneous section: Upload_Bypass, jwt_tool and pphack.
//
// Each of the three had a way of finishing with exit code 0 having proved nothing, and two of them
// had a way of finishing with exit code 0 having proved something FALSE. Everything pinned here was
// measured against a lab with a weak upload filter, a JWT endpoint that honours alg:none, and a page
// that merges the query string into an object:
//
//	Upload_Bypass, unmarked request -> "File uploaded successfully with: X.php" while the server
//	                                   logged filename='pic.jpeg' for every request: nothing was
//	                                   mutated and every finding was invented
//	Upload_Bypass, marked request   -> sent pic.php (rejected), then pic.php3 (accepted and written)
//	Upload_Bypass, no TTY           -> OSError [Errno 25] on the first module's response
//	jwt_tool, default config        -> ProxyError against 127.0.0.1:8080, no request ever sent
//	jwt_tool, -M pb without -t      -> "No target secified (-t), cannot scan offline."
//	jwt_tool, -C without -d/-p/-kf  -> argparse usage error, token untouched
//	jwt_tool, -X a without -t       -> forges tokens locally and confirms nothing
//	pphack -j                       -> {"TargetURL":...,"ScanURL":...,"JSEvaluation":...}

// ---------------------------------------------------------------------------
// Upload_Bypass
// ---------------------------------------------------------------------------

const uploadCapture = "POST /upload HTTP/1.1\r\n" +
	"Host: misclab:5000\r\n" +
	"Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC\r\n" +
	"Content-Length: 187\r\n" +
	"\r\n" +
	"------WebKitFormBoundaryABC\r\n" +
	"Content-Disposition: form-data; name=\"file\"; filename=\"pic.jpeg\"\r\n" +
	"Content-Type: image/jpeg\r\n" +
	"\r\n" +
	"GIF89a hello\r\n" +
	"------WebKitFormBoundaryABC--\r\n"

// THE test for this tool. Upload_Bypass substitutes each technique's payload into three markers in
// the saved request. Given a request without them it substitutes nothing, re-sends the original
// bytes, and compares the response to the success message the operator configured. The operator
// picked that request BECAUSE it uploads successfully, so the comparison always matches and the tool
// reports a bypass for a file it never altered.
//
// Measured: an unmarked run reported "File uploaded successfully with: YdezwsXRpX.php" while the
// server logged filename='pic.jpeg' for every request it received, and the .php file was never on
// disk. A marked run of the same request sent pic.php (rejected by the filter) and then pic.php3
// (accepted, and present on disk afterwards).
func TestUploadRequestIsMarkedOrRefused(t *testing.T) {
	marked, err := MarkUploadRequest(uploadCapture)
	if err != nil {
		t.Fatalf("a normal multipart upload must be markable: %v", err)
	}

	for _, marker := range []string{uploadFilenameMarker, uploadDataMarker, uploadMimetypeMarker} {
		if !strings.Contains(marked, marker) {
			t.Errorf("%s is missing, so Upload_Bypass would substitute nothing there:\n%s",
				marker, marked)
		}
	}
	if strings.Contains(marked, "pic.jpeg") {
		t.Error("the original filename survived, so the tool would keep uploading it")
	}
	if strings.Contains(marked, "GIF89a hello") {
		t.Error("the original file content survived, so no payload can be substituted in")
	}
	if strings.Contains(marked, "image/jpeg") {
		t.Error("the original mimetype survived, so no mimetype can be tried")
	}

	// The markers are shorter than what they replaced. A Content-Length still describing the original
	// body makes the server wait for bytes that never arrive.
	_, body, _ := strings.Cut(marked, "\r\n\r\n")
	if !strings.Contains(marked, "Content-Length: "+strconv.Itoa(len(body))) {
		t.Errorf("Content-Length was not recomputed for the marked body of %d bytes:\n%s",
			len(body), marked)
	}
}

// A request with no file part cannot be mutated, and running anyway is what produces the invented
// findings above. It has to refuse and say so.
func TestUnmarkableUploadRequestIsRefusedRatherThanGuessed(t *testing.T) {
	cases := map[string]string{
		"a plain JSON POST with no file part": "POST /api HTTP/1.1\r\nHost: x.test\r\n" +
			"Content-Type: application/json\r\n\r\n{\"name\":\"bob\"}",
		"a request with no body at all": "GET /x HTTP/1.1\r\nHost: x.test\r\n\r\n",
		"nothing recorded":              "",
	}

	for name, raw := range cases {
		if _, err := MarkUploadRequest(raw); err == nil {
			t.Errorf("%s must be refused, not scanned: an unmarked run reports a bypass for every "+
				"module without altering anything", name)
		}
	}

	// The composer refuses the same request, so no scan is spent on it.
	v := VectorInput{RawRequestOverride: "GET /x HTTP/1.1\r\nHost: x.test\r\n\r\n"}
	args, warnings := ComposeUploadBypass(v, map[string]any{
		"extension": "php", "success": "ok",
	}, "/tmp/rep")
	if args != nil {
		t.Error("a request that cannot be marked must not be scanned")
	}
	if len(warnings) == 0 {
		t.Error("refusing silently is the failure this section exists to avoid")
	}
}

// An operator who marked the request by hand gets it through untouched: their markers may sit in a
// body shape this code would not recognise, such as a base64 blob inside JSON.
func TestHandMarkedUploadRequestIsLeftAlone(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/json\r\n\r\n" +
		"{\"name\":\"*filename*\",\"body\":\"*data*\"}"

	marked, err := MarkUploadRequest(raw)
	if err != nil {
		t.Fatalf("a hand-marked request must be accepted: %v", err)
	}
	if !strings.Contains(marked, "*filename*") || !strings.Contains(marked, "*data*") {
		t.Errorf("the operator's own markers were destroyed:\n%s", marked)
	}
}

// Both of these are required by the tool, and it errors out per target without them.
func TestUploadBypassRefusesWithoutTheArgumentsItRequires(t *testing.T) {
	v := VectorInput{RawRequestOverride: uploadCapture}

	if args, warnings := ComposeUploadBypass(v, map[string]any{"success": "ok"}, "/tmp/rep"); args != nil {
		t.Error("without -E there is no forbidden extension to test for")
	} else if len(warnings) == 0 {
		t.Error("it has to say what is missing")
	}

	if args, warnings := ComposeUploadBypass(v, map[string]any{"extension": "php"}, "/tmp/rep"); args != nil {
		t.Error("without a success indicator it cannot tell an accepted upload from a rejected one")
	} else if len(warnings) == 0 {
		t.Error("it has to say what is missing")
	}
}

// The scheme reaches the tool through the environment because it has no flag for it: lib/config.py
// hard-codes protocol = 'https' and only falls back to HTTP when the TLS handshake raises SSLError.
// A host that also serves HTTPS would be scanned on the wrong service without a word.
func TestUploadBypassCarriesTheTargetScheme(t *testing.T) {
	settings := map[string]any{"extension": "php", "success": "ok"}

	http, _ := ComposeUploadBypass(
		VectorInput{RawRequestOverride: uploadCapture, Scheme: "http"}, settings, "/tmp/rep")
	if len(http) == 0 || http[0] != "UPLOAD_BYPASS_PROTOCOL=http" {
		t.Errorf("an http target must be scanned over http: %v", http)
	}

	https, _ := ComposeUploadBypass(
		VectorInput{RawRequestOverride: uploadCapture, Scheme: "https"}, settings, "/tmp/rep")
	if len(https) == 0 || https[0] != "UPLOAD_BYPASS_PROTOCOL=https" {
		t.Errorf("an https target must be scanned over https: %v", https)
	}

	// The env prefix only works because the tool is invoked through env rather than python directly.
	tool, _ := VectorToolByKey("upload-bypass")
	if tool.Binary != "env" {
		t.Errorf("the scheme is passed as an environment variable, so the binary must be env, not %q",
			tool.Binary)
	}
}

// Uploading a web shell leaves executable code on somebody else's server. It is available, because
// proving impact is the point, but it is never what a run does by default.
func TestUploadBypassUploadsHarmlessFilesUnlessToldOtherwise(t *testing.T) {
	v := VectorInput{RawRequestOverride: uploadCapture}
	base := map[string]any{"extension": "php", "success": "ok"}

	args, warnings := ComposeUploadBypass(v, base, "/tmp/rep")
	if !argsContain(args, "-d") {
		t.Errorf("the default must be the harmless sample files: %v", args)
	}
	if argsContain(args, "-e") {
		t.Error("web shells must never be uploaded without being asked for")
	}

	base["exploit"] = true
	args, warnings = ComposeUploadBypass(v, base, "/tmp/rep")
	if !argsContain(args, "-e") {
		t.Errorf("web shell mode was asked for and must be used: %v", args)
	}
	if !warnsAbout(warnings, "EXECUTABLE") {
		t.Errorf("leaving code on a target has to be said out loud: %v", warnings)
	}
}

// The echoed success message is the trap here. Upload_Bypass prints a "User Options" block before
// every module which repeats the configured message back, so a parser matching "success" anywhere
// invents one finding per module on every run, including runs that found nothing.
func TestUploadBypassEchoIsNotAFinding(t *testing.T) {
	stdout := "\x1b[1mUser Options:\x1b[0m\n" +
		"\U0001F310 Target URL: http://misclab:5000/upload\n" +
		"\U0001F4AC Upload Message: File was uploaded successfully\n" +
		"\U0001F3AE Mode: Detect\n"

	if findings := parseUploadBypassOutput(stdout, "", vectorRow{ID: "v1"}); len(findings) != 0 {
		t.Errorf("the configured message echoed back is not a bypass, got %d findings: %+v",
			len(findings), findings)
	}
}

// The real report, which is what a success actually looks like.
func TestUploadBypassReadsItsReport(t *testing.T) {
	report := "-------------------------------------------------------------------\n" +
		"File uploaded successfully with the extension: b'f08IFtOmKi.php3'\n" +
		"Content-Type: application/x-httpd-php\n" +
		"Upload Location: Not specified\n" +
		"Date & Time: 19.08.2026_15:54:42\n" +
		"Module: polyglot\n"

	findings := parseUploadBypassOutput("", report, vectorRow{ID: "v1", EvidenceURL: "http://x/upload"})
	if len(findings) != 1 {
		t.Fatalf("one accepted file is one finding, got %d", len(findings))
	}
	if findings[0].Payload != "f08IFtOmKi.php3" {
		t.Errorf("the filename that got through is the finding, got %q", findings[0].Payload)
	}
	if findings[0].InjectType != "polyglot" {
		t.Errorf("the technique that worked must be recorded, got %q", findings[0].InjectType)
	}
}

// ---------------------------------------------------------------------------
// jwt_tool
// ---------------------------------------------------------------------------

// The single worst defect in this section. jwt_tool writes its own config on first run pointing at
// Burp's default proxy, which is nothing inside this container, so EVERY run that sends a request
// died on "[ERROR] ProxyError - check proxy is up" with no request ever leaving. Nothing was tested
// and the scan read as clean.
func TestJWTToolAlwaysDisablesTheProxyItConfiguresForItself(t *testing.T) {
	args, _ := ComposeJWTTool(VectorInput{RawRequestOverride: "a.b.c"}, map[string]any{}, "/tmp/rep")
	if !argsContain(args, "-np") {
		t.Fatalf("-np must be on every run or nothing is ever sent: %v", args)
	}

	tool, _ := VectorToolByKey("jwt-tool")
	if _, owned := tool.OwnedFlags["-np"]; !owned {
		t.Error("-np must be framework-owned so it cannot be turned off")
	}
	// -i means "use HTTP for the passed request", NOT "skip TLS verification". Offering it as the
	// latter would quietly downgrade an HTTPS target.
	if _, owned := tool.OwnedFlags["-i"]; !owned {
		t.Error("-i must be owned: it changes the scheme rather than relaxing TLS checks")
	}
	// Both hang a scan forever waiting for input that never comes.
	for _, flag := range []string{"-T", "-I"} {
		if _, owned := tool.OwnedFlags[flag]; !owned {
			t.Errorf("%s is interactive and must be owned", flag)
		}
	}
}

// Measured: with a mode selected and no -t, jwt_tool prints "No target secified (-t), cannot scan
// offline." and stops. The run would look like a scan and be a decode.
func TestJWTScanModesRefuseWithoutSomewhereToSendTokens(t *testing.T) {
	v := VectorInput{RawRequestOverride: "a.b.c"}

	for _, mode := range []string{"playbook", "errorFuzz", "commonClaims", "allTests"} {
		args, warnings := ComposeJWTTool(v, map[string]any{mode: true}, "/tmp/rep")
		if args != nil {
			t.Errorf("%s cannot run without a target URL and must be refused", mode)
		}
		if !warnsAbout(warnings, "target URL") {
			t.Errorf("%s must say a target URL is what is missing: %v", mode, warnings)
		}
	}

	// With a target it runs.
	args, _ := ComposeJWTTool(v, map[string]any{
		"playbook": true, "targetURL": "https://x.test/api", "canaryValue": "Welcome",
	}, "/tmp/rep")
	if !argsContainPair(args, "-M", "pb") {
		t.Errorf("the playbook mode must be passed once it has a target: %v", args)
	}
}

// Measured: -C with none of -d, -p or -kf is an argparse error. jwt_tool prints its usage and exits
// without touching the token.
func TestJWTCrackRefusesWithNothingToTry(t *testing.T) {
	v := VectorInput{RawRequestOverride: "a.b.c"}

	if args, warnings := ComposeJWTTool(v, map[string]any{"crack": true}, "/tmp/rep"); args != nil {
		t.Error("cracking with no wordlist, password or key file is a usage error, not a scan")
	} else if len(warnings) == 0 {
		t.Error("it has to say what is missing")
	}

	args, _ := ComposeJWTTool(v, map[string]any{
		"crack": true, "dictionary": "/wordlists/jwt.txt",
	}, "/tmp/rep")
	if !argsContain(args, "-C") {
		t.Errorf("with a wordlist it must run: %v", args)
	}
}

// An exploit run with no target URL forges tokens locally and never sends one. The forged tokens
// print happily and look exactly like success.
func TestJWTOfflineForgeryIsNotReportedAsABypass(t *testing.T) {
	// Real offline output, from `jwt_tool -X a <token>` with no -t.
	stdout := "Original JWT: eyJ0eXAi.eyJsb2dpbi.sig\n\n" +
		"jwttool_1b8a5714 - EXPLOIT: \"alg\":\"none\" - this is an exploit targeting the debug " +
		"feature that allows a token to have no signature\n" +
		"(This will only be valid on unpatched implementations of JWT.)\n" +
		"[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6InRpY2FycGkifQ.\n"

	row := vectorRow{ID: "v1", RawRequest: sampleJWT}
	for _, f := range parseJWTToolOutput(stdout, "", row) {
		if f.Severity == "critical" || f.Severity == "high" {
			t.Errorf("nothing was sent anywhere, so this cannot be a %s finding: %s",
				f.Severity, f.Evidence)
		}
		if f.Kind != "jwt-observed" {
			t.Errorf("an offline run describes the token, it does not find a bug; got %q", f.Kind)
		}
	}

	// The warning has to say why the run cannot conclude anything.
	_, warnings := ComposeJWTTool(VectorInput{RawRequestOverride: "a.b.c"},
		map[string]any{"algNone": true}, "/tmp/rep")
	if !warnsAbout(warnings, "never sent") {
		t.Errorf("an offline exploit run must say the forgeries go nowhere: %v", warnings)
	}
}

// The confirmed case: the canary line comes first, then the line naming what was sent.
func TestJWTAcceptedForgeryNeedsTheCanary(t *testing.T) {
	confirmed := "[+] FOUND \"Welcome\" in response:\n" +
		"jwttool_49bb89f6db37e98dee6cd9f04fe1d70b Exploit: \"alg\":\"none\" Response Code: 200, 14 bytes\n"

	findings := parseJWTToolOutput(confirmed, "", vectorRow{ID: "v1", RawRequest: sampleJWT})
	if len(findings) != 1 || findings[0].Kind != "jwt-accepted-forgery" {
		t.Fatalf("a canary hit is authentication bypass, got %+v", findings)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("an accepted forgery is critical, got %q", findings[0].Severity)
	}

	// The same run WITHOUT a canary prints only the response line, which is identical whether the
	// forgery was accepted or the endpoint answers 2xx to everything.
	unconfirmed := "jwttool_68e6790b Exploit: \"alg\":\"none\" Response Code: 200, 14 bytes\n" +
		"jwttool_a4fe07ad Exploit: \"alg\":\"None\" Response Code: 200, 14 bytes\n"

	findings = parseJWTToolOutput(unconfirmed, "", vectorRow{ID: "v1", RawRequest: sampleJWT})
	if len(findings) != 1 {
		t.Fatalf("two indistinguishable results are one uncertain finding, got %d: %+v",
			len(findings), findings)
	}
	if findings[0].Kind != "jwt-forgery-not-rejected" {
		t.Errorf("without a canary this is not a confirmed bypass, got %q", findings[0].Kind)
	}
	if findings[0].Severity == "critical" {
		t.Error("an unconfirmed result must not be reported at the same severity as a confirmed one")
	}
	if !strings.Contains(findings[0].Confidence, "canary") {
		t.Error("it has to say what would turn this into a real answer")
	}

	// A rejected forgery is not a finding at all.
	rejected := "jwttool_d7e4b881 Injected kid claim Response Code: 401, 12 bytes\n"
	for _, f := range parseJWTToolOutput(rejected, "", vectorRow{ID: "v1"}) {
		if f.Kind != "jwt-observed" {
			t.Errorf("a 401 means the forgery was refused, got %q", f.Kind)
		}
	}
}

// Measured: "[+] secret is the CORRECT key!". None of the obvious guesses ("cracked", "key found")
// appear anywhere in that line.
func TestJWTCrackedSecretIsRead(t *testing.T) {
	stdout := "[+] secret is the CORRECT key!\n" +
		"You can tamper/fuzz the token contents (-T/-I) and sign it using:\n"

	findings := parseJWTToolOutput(stdout, "", vectorRow{ID: "v1", RawRequest: sampleJWT})
	if len(findings) != 1 || findings[0].Kind != "jwt-weak-secret" {
		t.Fatalf("a recovered signing key is the strongest result this tool produces, got %+v", findings)
	}
	if findings[0].Payload != "secret" {
		t.Errorf("the key itself must be recorded, got %q", findings[0].Payload)
	}
}

// ---------------------------------------------------------------------------
// pphack
// ---------------------------------------------------------------------------

// pphack marshals its own struct without JSON tags, so the keys are Go field names. Guessing
// url/payload/gadget unmarshals to an empty struct and every result is dropped, which turns a
// vulnerable target into a clean one.
func TestPphackReadsItsRealFieldNames(t *testing.T) {
	stdout := `{"TargetURL":"http://misclab:5000/?foo=bar",` +
		`"ScanURL":"http://misclab:5000/?__proto__[xreyrw]=xreyrw",` +
		`"JSEvaluation":"1|2|3"}`

	findings := parsePphackOutput(stdout, "", vectorRow{ID: "v1", InsertionPoint: "query"})
	if len(findings) != 1 {
		t.Fatalf("the measured output line must produce a finding, got %d", len(findings))
	}
	if findings[0].URL != "http://misclab:5000/?foo=bar" {
		t.Errorf("TargetURL is the page, got %q", findings[0].URL)
	}
	if !strings.Contains(findings[0].Payload, "__proto__") {
		t.Errorf("ScanURL is what proved it, got %q", findings[0].Payload)
	}
	if findings[0].InjectType != "1|2|3" {
		t.Errorf("JSEvaluation is what was read back off the prototype, got %q", findings[0].InjectType)
	}
	// A clean run prints its banner and nothing else.
	if len(parsePphackOutput("banner only\n", "", vectorRow{ID: "v1"})) != 0 {
		t.Error("no JSON means nothing was found")
	}
}

// Client-side prototype pollution is polluted through the URL and read by the page's own JavaScript.
// A body never reaches that sink, so scanning one spends requests on something that cannot fire.
func TestPphackTakesGETVectorsOnly(t *testing.T) {
	tool, ok := VectorToolByKey("pphack")
	if !ok {
		t.Fatal("pphack is not registered")
	}
	for _, point := range tool.InsertionPoints {
		if point != "query" && point != "path" {
			t.Errorf("%s does not reach a client-side sink", point)
		}
	}
	for _, point := range []string{"body", "cookie", "header"} {
		if tool.SkipReason(point) == "" {
			t.Errorf("a %s vector must be skipped with a reason, not silently tested", point)
		}
	}
}

// Every tool in the section has to be reachable and belong to it.
func TestMiscSectionIsRegistered(t *testing.T) {
	for _, key := range []string{"upload-bypass", "jwt-tool", "pphack"} {
		tool, ok := VectorToolByKey(key)
		if !ok {
			t.Fatalf("%s is not registered", key)
		}
		if tool.Category != "misc" {
			t.Errorf("%s belongs in misc, not %s", key, tool.Category)
		}
		if tool.Limitation == "" {
			t.Errorf("%s must say what it cannot do", key)
		}
	}

	// The three take three different kinds of target, which is the whole shape of this section.
	upload, _ := VectorToolByKey("upload-bypass")
	if upload.RowSource == nil {
		t.Error("Upload_Bypass takes the requests the operator marked as uploads")
	}
	if _, ok := upload.Options[graphqlEndpointsSetting]; !ok {
		t.Error("Upload_Bypass needs a Targets tab to mark uploads on")
	}
	jwt, _ := VectorToolByKey("jwt-tool")
	if jwt.RowSource == nil {
		t.Error("jwt_tool finds its own tokens rather than being given targets")
	}
	pphack, _ := VectorToolByKey("pphack")
	if pphack.RowSource == nil {
		t.Error("pphack takes the GET attack vectors")
	}

	found := false
	for _, category := range VectorCategories {
		if category.Key == "misc" {
			found = true
		}
	}
	if !found {
		t.Error("the misc category must be listed or the section never renders")
	}
}

const sampleJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7"

func warnsAbout(warnings []string, phrase string) bool {
	for _, w := range warnings {
		if strings.Contains(w, phrase) {
			return true
		}
	}
	return false
}
