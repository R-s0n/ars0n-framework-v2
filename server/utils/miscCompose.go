package utils

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Building the command lines for the Miscellaneous section.

// ComposeUploadBypass builds the command for one marked upload request.
//
// The request is written to a file first, because Upload_Bypass reads a saved proxy request and has
// no way to take one on the command line. Two of its arguments are REQUIRED and the run fails
// without them, so the composer refuses rather than letting the scan error out per target.
func ComposeUploadBypass(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("upload-bypass")
	var warnings []string

	// Checked here as well as at the point the file is written, because a request this function
	// cannot mark is one where every module would report a bypass that never happened. See
	// MarkUploadRequest for what goes wrong without the markers.
	if _, err := MarkUploadRequest(v.RawRequestOverride); err != nil {
		return nil, []string{"This request cannot be tested: " + err.Error()}
	}

	if strings.TrimSpace(stringifySetting(settings["extension"])) == "" {
		return nil, []string{"Upload_Bypass needs the forbidden extension you are trying to smuggle " +
			"past the filter (its -E), for example php. Without it there is nothing to test for."}
	}

	// It accepts exactly one of these three and cannot judge an upload without one.
	success := strings.TrimSpace(stringifySetting(settings["success"]))
	failure := strings.TrimSpace(stringifySetting(settings["failure"]))
	status := strings.TrimSpace(stringifySetting(settings["statusCode"]))
	chosen := 0
	for _, value := range []string{success, failure, status} {
		if value != "" {
			chosen++
		}
	}
	switch {
	case chosen == 0:
		return nil, []string{"Upload_Bypass cannot tell an accepted upload from a rejected one " +
			"without being told how success looks. Set the success message, the failure message or " +
			"the status code that means success."}
	case chosen > 1:
		warnings = append(warnings, "More than one success indicator was set and Upload_Bypass takes "+
			"only one; the run may not use the one you expect.")
	}

	skip := map[string]bool{graphqlEndpointsSetting: true, "detect": true, "exploit": true,
		"antiMalware": true}

	// The scheme travels in the environment because Upload_Bypass has no flag for it: lib/config.py
	// hard-codes protocol = 'https' and format_detector builds its URL as f'{protocol}://{host}{path}'.
	// The image patches that constant to read UPLOAD_BYPASS_PROTOCOL. Passing it per exec rather than
	// editing the file keeps concurrent scans in the shared container from fighting over one global.
	scheme := strings.ToLower(strings.TrimSpace(v.Scheme))
	if scheme != "http" {
		scheme = "https"
	}
	args := []string{"UPLOAD_BYPASS_PROTOCOL=" + scheme, "python",
		"/opt/upload_bypass/upload_bypass.py", "-r", reportPath + ".req"}

	// The mode decides WHAT gets uploaded, and the difference matters more than a flag usually does.
	switch {
	case truthySetting(settings["exploit"]):
		args = append(args, "-e")
		warnings = append(warnings, "Web shell mode is on. A successful bypass here leaves EXECUTABLE "+
			"CODE on the target, which is a change to somebody else's system rather than a test of it. "+
			"Make sure that is within what you are authorised to do, and clean up after yourself.")
	case truthySetting(settings["antiMalware"]):
		args = append(args, "-a")
		warnings = append(warnings, "The EICAR test file is being uploaded, which is designed to trip "+
			"anti-malware. Expect it to be noticed.")
	default:
		args = append(args, "-d")
		warnings = append(warnings, "Harmless sample files are being uploaded, which is the mode meant "+
			"for a real engagement. Turning on web shells uploads executable code instead.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)
	args = append(args, "-o", reportPath)
	return args, warnings
}

// uploadMarkers are the three placeholders Upload_Bypass substitutes into the saved request.
const (
	uploadFilenameMarker = "*filename*"
	uploadDataMarker     = "*data*"
	uploadMimetypeMarker = "*mimetype*"
)

var (
	uploadBoundaryPattern = regexp.MustCompile(`(?i)boundary="?([^";\r\n]+)"?`)
	uploadFilenamePattern = regexp.MustCompile(`(?i)(filename\s*=\s*)("[^"]*"|[^;\r\n]*)`)
	uploadPartTypePattern = regexp.MustCompile(`(?im)^(content-type\s*:\s*)(.*)$`)
	uploadLengthPattern   = regexp.MustCompile(`(?im)^(content-length\s*:\s*)(\d+)\s*$`)
)

// UploadRequestFile renders the raw request Upload_Bypass reads, or "" when it cannot be marked.
func UploadRequestFile(v VectorInput) string {
	marked, err := MarkUploadRequest(v.RawRequestOverride)
	if err != nil {
		return ""
	}
	return marked
}

// MarkUploadRequest rewrites a captured upload into the form Upload_Bypass requires.
//
// This is the difference between the tool working and the tool lying. Its -U instructions say the
// saved request must have the filename replaced with *filename*, the file content with *data* and
// the file's Content-Type with *mimetype*; those are where it substitutes each technique's payload.
//
// Measured on v3.0.9#dev: given an UNMARKED request it substitutes nothing and re-sends the original
// bytes, then compares the response against the success message. The original upload is one the
// operator picked BECAUSE it works, so the response always matches and the tool reports a bypass for
// the first module it tries. Server-side logging during that run showed the same untouched
// filename=pic.jpeg arriving for every request, so every one of those findings was invented. With
// the markers in place the same run sent pic.php (rejected) and then pic.php3 (accepted and written
// to disk), which is a real finding.
//
// Returning an error rather than a best-effort request is deliberate: a run that cannot be marked is
// worse than no run, because it produces confident findings that are all false.
func MarkUploadRequest(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("no request was recorded for it, and Upload_Bypass mutates a saved " +
			"request rather than building one")
	}
	request := normaliseRawRequest(raw)

	split := strings.Index(request, "\r\n\r\n")
	if split < 0 {
		return "", errors.New("the recorded request has no body, so there is no file to mutate")
	}
	head, body := request[:split], request[split+4:]

	// An operator who marked the request by hand gets it through untouched. Their markers may sit in
	// a body shape this function would not recognise, such as a base64 blob inside JSON.
	if strings.Contains(body, uploadFilenameMarker) && strings.Contains(body, uploadDataMarker) {
		return withContentLength(head, body), nil
	}

	boundary := uploadBoundaryPattern.FindStringSubmatch(head)
	if boundary == nil {
		return "", errors.New("it is not a multipart upload, so the file part cannot be found " +
			"automatically. Edit the request and mark the filename with " + uploadFilenameMarker +
			", the file content with " + uploadDataMarker + " and the file's Content-Type with " +
			uploadMimetypeMarker)
	}

	delimiter := "--" + boundary[1]
	segments := strings.Split(body, delimiter)
	marked := false
	for i, segment := range segments {
		if !uploadFilenamePattern.MatchString(segment) {
			continue
		}
		headerEnd := strings.Index(segment, "\r\n\r\n")
		if headerEnd < 0 {
			continue
		}
		partHeaders := segment[:headerEnd]

		partHeaders = uploadFilenamePattern.ReplaceAllString(partHeaders,
			`${1}"`+uploadFilenameMarker+`"`)
		if uploadPartTypePattern.MatchString(partHeaders) {
			partHeaders = uploadPartTypePattern.ReplaceAllString(partHeaders,
				"${1}"+uploadMimetypeMarker)
		} else {
			// The tool needs somewhere to put the mimetype each technique wants to try. A capture
			// that never carried one still has to offer the header.
			partHeaders += "\r\nContent-Type: " + uploadMimetypeMarker
		}

		segments[i] = partHeaders + "\r\n\r\n" + uploadDataMarker + "\r\n"
		marked = true
		break
	}
	if !marked {
		return "", errors.New("no file part was found in the multipart body, so there is nothing to " +
			"mutate. Pick a request that actually uploads a file")
	}

	return withContentLength(head, strings.Join(segments, delimiter)), nil
}

// withContentLength puts the header back in step with the body it describes.
//
// The markers are shorter than the data they replace, and a Content-Length left describing the
// original body makes the server wait for bytes that never arrive.
func withContentLength(head, body string) string {
	if uploadLengthPattern.MatchString(head) {
		head = uploadLengthPattern.ReplaceAllString(head,
			"${1}"+strconv.Itoa(len(body)))
	}
	return head + "\r\n\r\n" + body
}

// normaliseRawRequest gives the request the CRLF line endings a proxy would have written.
//
// The two sources of raw requests in this framework disagree: the manual crawl extension records
// real wire bytes with CRLF, while a request typed into a textarea has LF. Upload_Bypass parses
// headers by splitting on CRLF, so an LF-only request parses as one enormous header line and the
// body is lost.
func normaliseRawRequest(raw string) string {
	unified := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
	return strings.ReplaceAll(unified, "\n", "\r\n")
}

// jwtScanModes are the modes that need somewhere to send a token.
var jwtScanModes = []struct {
	Setting string
	Mode    string
	Label   string
}{
	{"playbook", "pb", "playbook audit"},
	{"errorFuzz", "er", "claim error fuzzing"},
	{"commonClaims", "cc", "common claim fuzzing"},
	{"allTests", "at", "all tests"},
}

// jwtExploits map a switch to jwt_tool's -X letter.
var jwtExploits = []struct {
	Setting string
	Letter  string
	Label   string
}{
	{"algNone", "a", "alg:none"},
	{"nullSignature", "n", "null signature"},
	{"blankPassword", "b", "blank password"},
	{"psychic", "p", "psychic signature"},
	{"spoofJWKS", "s", "JWKS spoofing"},
	{"keyConfusion", "k", "key confusion"},
	{"injectJWKS", "i", "inline JWKS injection"},
}

// ComposeJWTTool builds the command for one token.
func ComposeJWTTool(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("jwt-tool")
	var warnings []string

	token := strings.TrimSpace(v.RawRequestOverride)
	if token == "" {
		return nil, []string{"This target carries no token, so there is nothing to test."}
	}

	// -np on every run, always.
	//
	// jwt_tool writes jwtconf.ini on first use with a proxy of 127.0.0.1:8080, which is Burp's default
	// and is nothing at all inside this container. Measured: every run with a target URL died on
	// "[ERROR] ProxyError - check proxy is up" having sent no request, so no forgery was ever tested
	// and the scan looked clean. There is no flag to POINT the proxy somewhere else, only this one to
	// turn it off, so it is not offered as a choice.
	args := []string{"/opt/jwt_tool/jwt_tool.py", "-np", token}

	targetURL := strings.TrimSpace(stringifySetting(settings["targetURL"]))

	var modes, modeLabels []string
	for _, mode := range jwtScanModes {
		if truthySetting(settings[mode.Setting]) {
			modes = append(modes, mode.Mode)
			modeLabels = append(modeLabels, mode.Label)
		}
	}

	// Measured: with a mode selected and no -t, jwt_tool prints "No target secified (-t), cannot scan
	// offline." and stops. Running anyway would burn a scan slot to produce a decode the operator
	// could have had for free, so it refuses and says what is missing.
	if len(modes) > 0 && targetURL == "" {
		return nil, []string{"The " + strings.Join(modeLabels, ", ") + " mode needs somewhere to send " +
			"the tokens it builds, and no target URL is set. jwt_tool refuses to scan offline. Set a " +
			"target URL that accepts this token, and a canary value that appears only in an " +
			"authenticated response."}
	}
	for _, mode := range modes {
		args = append(args, "-M", mode)
	}

	var exploitLabels []string
	for _, exploit := range jwtExploits {
		if truthySetting(settings[exploit.Setting]) {
			args = append(args, "-X", exploit.Letter)
			exploitLabels = append(exploitLabels, exploit.Label)
		}
	}

	// Measured: -C with no -d, -p or -kf is an argparse error, so jwt_tool prints its usage and exits
	// without touching the token.
	if truthySetting(settings["crack"]) {
		hasKeySource := false
		for _, key := range []string{"dictionary", "password", "keyfile"} {
			if strings.TrimSpace(stringifySetting(settings[key])) != "" {
				hasKeySource = true
			}
		}
		if !hasKeySource {
			return nil, []string{"Cracking needs something to try: a wordlist, a single password or a " +
				"key file. jwt_tool exits with a usage error when -C is given none of them."}
		}
	}

	// What separates a finding from a description.
	switch {
	case targetURL == "" && len(exploitLabels) > 0:
		warnings = append(warnings, "No target URL is set, so the "+strings.Join(exploitLabels, ", ")+
			" forgeries are built but never sent. This run can show you what the token contains and "+
			"which attacks are theoretically available; it cannot tell you whether the server accepts "+
			"any of them, and nothing here should be reported as a vulnerability on its own.")
	case targetURL == "":
		warnings = append(warnings, "No mode, exploit or crack was selected, so this run only decodes "+
			"the token and reports what it says about itself.")
	case strings.TrimSpace(stringifySetting(settings["canaryValue"])) == "":
		warnings = append(warnings, "A target URL is set but no canary value. Measured: without one "+
			"jwt_tool prints the same status-code line whether a forgery was accepted or rejected, so "+
			"findings from this run are downgraded to 'a forged token got a 2xx' rather than "+
			"'the forgery was accepted'. Give it a string that appears only in an authenticated "+
			"response to get a confirmed answer.")
	}

	if truthySetting(settings["spoofJWKS"]) && strings.TrimSpace(stringifySetting(settings["jwksURL"])) == "" {
		warnings = append(warnings, "The JWKS spoofing attack needs a JWKS URL you control, and none "+
			"was set, so that exploit has nowhere to point.")
	}
	if truthySetting(settings["keyConfusion"]) && strings.TrimSpace(stringifySetting(settings["publicKey"])) == "" {
		warnings = append(warnings, "Key confusion needs the server's public key, and none was set. "+
			"jwt_tool will fall back to the key it generated for itself, which the server has never "+
			"seen, so the attack cannot succeed.")
	}

	skip := map[string]bool{}
	for _, mode := range jwtScanModes {
		skip[mode.Setting] = true
	}
	for _, exploit := range jwtExploits {
		skip[exploit.Setting] = true
	}
	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)

	_ = reportPath
	return args, warnings
}

// ComposePphack builds the command for one GET vector.
func ComposePphack(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("pphack")
	var warnings []string

	// -j because the findings are read as JSON, and the JSON goes to stdout rather than to a file.
	args := []string{"-u", v.TargetURL(), "-j"}

	if truthySetting(settings["exploit"]) {
		warnings = append(warnings, "Automatic exploitation is on, so pphack does not stop at proving "+
			"the pollution: it runs the follow-on payload in the page.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	_ = reportPath
	return args, warnings
}

// describeUploadRequest is what the picker shows for a candidate, so an operator choosing between two
// uploads to the same endpoint can tell them apart.
func describeUploadRequest(raw string) string {
	if _, err := MarkUploadRequest(raw); err != nil {
		return "cannot be marked automatically: " + err.Error()
	}
	if match := uploadFilenamePattern.FindStringSubmatch(normaliseRawRequest(raw)); match != nil {
		name := strings.Trim(match[2], `"`)
		if name != "" && name != uploadFilenameMarker {
			return fmt.Sprintf("uploads %s", name)
		}
	}
	return "ready to test"
}
