package utils

import (
	"net/url"
	"strings"
)

// Building the command lines for the local file inclusion section.
//
// LFImap marks WHERE the payload goes with a placeholder, which is what lets it test the exact input
// a vector names rather than whatever it finds. LFIHunt takes a URL list and finds the parameters
// itself, so it runs once per URL.

// lfimapPlaceholder is LFImap's marker, its --placeholder default. The framework places it rather
// than letting LFImap guess, and passes the same word back so the two cannot drift.
const lfimapPlaceholder = "PWN"

// ComposeLFImap builds the LFImap argv for one vector.
//
// The placeholder goes in exactly one place, chosen by the vector's insertion point. Measured
// against a PHP target with a real include(): the query string, the body, a cookie and a header all
// reported the inclusion this way.
//
// CREDENTIALS. This used to read one setting, settings["cookie"], and nothing else. Measured on scan
// 991aaec6 against an application whose Session Manager held two active, honoured tokens: not one of
// 250 LFImap command lines carried a session credential, no trace contained a JWT, and 79 of the runs
// died on the 401 that caused. The framework held the credential the whole time and never handed it
// over. It now goes through cmdiCredentialsFor, the same layering commix and SSTImap use, so there is
// one credential path for the vector tools rather than a second one that can rot on its own.
func ComposeLFImap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("lfimap")
	var warnings []string

	// A PATH vector names no parameter and does not need to: the marker replaces a path segment. Every
	// other point substitutes into a named input, so there the name is required.
	param := markableParam(v)
	if param == "" && v.InsertionPoint != "path" {
		return nil, []string{"This vector names no parameter, so there is nowhere to put the marker."}
	}

	args := []string{"-U", lfimapTargetURL(v, param)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" && v.InsertionPoint != "body" {
		args = append(args, "-M", method)
	}

	// The header this vector marks, excluded from every other source of headers below. Measured, and
	// it is a silent-clean failure rather than a cosmetic one: see lfimapHeaderArgs.
	targetHeader := ""
	if v.InsertionPoint == "header" {
		targetHeader = param
	}

	// The vector's own recorded request, then the credentials the framework holds for this host
	// (Session Manager over manual-crawl capture over saved ffuf config), then the operator's own
	// settings, which win.
	creds := cmdiCredentialsFor(v, settings, targetHeader)
	warnings = append(warnings, cmdiCredentialWarnings("LFImap", creds)...)

	switch v.InsertionPoint {
	case "body":
		args = append(args, "-D", lfimapBody(v, param))
	case "cookie":
		// Every other cookie survives, with the target's replaced by the marker: a scan that drops the
		// session tests a logged-out application.
		args = append(args, "-C", joinCookies(strings.Join(cmdiCookiesExcept(creds, param), "; "),
			param, lfimapPlaceholder))
	case "header":
		args = append(args, "-H", param+": "+lfimapPlaceholder)
	}
	// -C is argparse "store", not "append", so there is exactly one of them and it carries every
	// cookie. A cookie vector already built its own above.
	if v.InsertionPoint != "cookie" && len(creds.Cookies) > 0 {
		args = append(args, "-C", strings.Join(creds.Cookies, "; "))
	}

	headerArgs, headerWarnings := lfimapHeaderArgs(settings, creds, targetHeader)
	args = append(args, headerArgs...)
	warnings = append(warnings, headerWarnings...)

	// "header" is skipped here because lfimapHeaderArgs emits the operator's headers itself, with the
	// name collision above removed. Leaving it to composeVectorSettings put the operator's copy of the
	// marked header AFTER the marker on the command line, where it wins.
	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"cookie": true, "header": true}, &warnings)...)

	// A technique has to be chosen or LFImap tests none of them. Filter and traversal by default:
	// the filter wrapper is the highest-signal PHP check and traversal is the one that applies to a
	// target of any language.
	if !anyTechniqueChosen(settings) {
		args = append(args, "-f", "-t")
		warnings = append(warnings, "No technique was chosen, so this run used the filter wrapper and "+
			"path traversal. The wrappers that reach code execution are a deliberate choice.")
	}

	warnings = append(warnings, lfimapPayloadReach(settings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args, "--placeholder", lfimapPlaceholder, "-nc")
	_ = reportPath
	return args, warnings
}

// lfimapHeaderArgs emits every -H the run needs, with the marked header's name reserved.
//
// THE COLLISION IS A SILENT-CLEAN FAILURE, measured on the wire against a capturing listener. LFImap
// declares -H with action="append" and then folds the list into a dict, so the LAST occurrence of a
// name wins. With
//
//	-H "X-File: PWN" -H "X-File: realvalue"
//
// every request carried X-File: realvalue, the marker was gone, and LFImap fell back to enumerating
// the QUERY STRING: it fuzzed ?x= instead and finished with "Parameters tested: 1, Vulnerabilities
// found: 0". A header vector that was never touched, filed as clean. The composer used to emit the
// marker first and then let composeVectorSettings append the operator's headers, which is exactly
// that order, so an operator whose Headers setting named the header under test lost the vector.
func lfimapHeaderArgs(settings map[string]any, creds cmdiCredentials, targetHeader string) (
	args []string, warnings []string) {

	target := strings.ToLower(strings.TrimSpace(targetHeader))
	seen := map[string]bool{}
	if target != "" {
		seen[target] = true
	}

	// The operator's own headers first, because cmdiCredentialsFor drops their names from creds on
	// the understanding that whoever composes emits them. Dropping them here as well would leave an
	// operator authenticated by a pasted bearer running anonymously while being told otherwise.
	for _, item := range settingValues(settings["header"]) {
		item = strings.TrimSpace(item)
		name := headerNameOf(item)
		if item == "" || name == "" {
			continue
		}
		if name == target {
			warnings = append(warnings, "Dropped your "+strings.TrimSpace(targetHeader)+" header for "+
				"this vector: it is the header under test, and LFImap keeps only the LAST -H of a "+
				"name. Sending both would erase the marker and silently move the scan onto the query "+
				"string, which reports clean for a header nothing ever tested.")
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		args = append(args, "-H", item)
	}

	for _, header := range creds.Headers {
		name := headerNameOf(header)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		args = append(args, "-H", header)
	}
	return args, warnings
}

// lfimapPayloadReach says in numbers what this run can possibly find, so a zero is read correctly.
//
// Every payload LFImap sends names a FIXED OPERATING SYSTEM FILE, and it decides a run succeeded by
// looking for one of the thirty fixed strings in config.KEY_WORDS in the response body: root:x:0:0,
// daemon:x:1:, www-data:x, their base64 and ROT13 forms, and the Windows hosts file's own comments.
// Counted in the shipped tool: the filter technique is eleven php:// payloads, and the traversal
// technique is one request per wordlist line, twenty in short.txt and 1055 in long.txt, EVERY line of
// which contains a path separator and asks for /etc/passwd or Windows\System32\drivers\etc\hosts.
// Neither list contains %2500 at all.
//
// So a file-read bug that returns an APPLICATION file, a backup or a config or a source file, is
// neither requested nor recognised by this tool at any setting. That is not a gap the framework can
// close from the command line: the success test is thirty hard-coded strings inside the tool, so a
// payload that fetched the file would still be reported as nothing found.
func lfimapPayloadReach(settings map[string]any) []string {
	scale := ""
	if !anyTechniqueChosen(settings) {
		scale = " This run sends 31 payloads: 11 php:// wrappers, which a target that is not PHP " +
			"cannot act on at all, and 20 traversal payloads."
	} else if truthySetting(settings["useLong"]) {
		scale = " The long wordlist is 1055 traversal payloads, and every one of them names the same " +
			"two operating system files as the short one."
	}
	return []string{"WHAT A ZERO FROM LFIMAP MEANS: every payload it sends asks for a fixed " +
		"operating system file, and it recognises success by looking for one of 30 fixed strings " +
		"from those files in the response." + scale + " A read of an APPLICATION file, a backup or a " +
		"config or a source file, is neither requested nor recognised, so this result is a zero for " +
		"operating system file reads and says nothing about that class."}
}

// anyTechniqueChosen reports whether the operator picked at least one attack technique.
//
// LFImap has no default: with no technique flag it connects, decides there is nothing to do and
// exits 0. That is the silent-nothing failure for this tool, so the composer supplies a pair rather
// than letting it happen.
func anyTechniqueChosen(settings map[string]any) bool {
	for _, key := range []string{"filter", "input", "dataWrap", "expect", "trunc", "rfi", "cmd",
		"fileWrap", "heuristics", "all"} {
		if truthySetting(settings[key]) {
			return true
		}
	}
	return false
}

// lfimapTargetURL puts the placeholder in the query string or the path, or leaves the URL alone when
// the payload belongs somewhere else.
//
// The path case matters and is easy to get wrong in the direction of reporting clean. LFImap's URL
// substitution is a blind whole-string replace, so the marker works anywhere in the URL including a
// path segment; but with no marker present LFImap falls back to enumerating the QUERY parameters,
// which means a path vector would quietly scan something else and report the path untested.
func lfimapTargetURL(v VectorInput, param string) string {
	base := v.TargetURL()
	if v.InsertionPoint == "path" {
		return markLastPathSegment(base, lfimapPlaceholder, true)
	}
	if v.InsertionPoint != "query" {
		return base
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	// Built by hand rather than through Encode(), so the marker reaches LFImap as the literal PWN
	// rather than as an encoded string it would then not recognise.
	var pairs []string
	for name, values := range parsed.Query() {
		if name == param {
			continue
		}
		for _, value := range values {
			pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(value))
		}
	}
	pairs = append(pairs, url.QueryEscape(param)+"="+lfimapPlaceholder)
	parsed.RawQuery = strings.Join(pairs, "&")
	return parsed.String()
}

// lfimapBody renders the body with the marker in the target parameter and every other field kept.
// Dropping the others would produce a request the endpoint rejects, and a 400 includes nothing.
func lfimapBody(v VectorInput, param string) string {
	var pairs []string
	seen := false
	for _, name := range v.Parameters {
		if name == param {
			pairs = append(pairs, url.QueryEscape(name)+"="+lfimapPlaceholder)
			seen = true
			continue
		}
		pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(v.valueFor(name)))
	}
	if !seen {
		pairs = append(pairs, url.QueryEscape(param)+"="+lfimapPlaceholder)
	}
	return strings.Join(pairs, "&")
}

// ComposeLFIHunt builds the LFIHunt argv.
//
// scanner.py, not LFIHunt.py: the latter is the interactive menu and blocks on input() immediately.
// The scanner takes a file of URLs, which the runner writes, and an output file, which is what the
// findings are read from. Its stdout is progress bars and cannot be parsed.
// It CANNOT be authenticated, and that has to be said rather than left to be discovered. scanner.py
// declares exactly three arguments, -i, -o and -t, and its checkers build their own requests with no
// cookie or header material anywhere. There is no flag to give it a session, so every LFIHunt result
// on this framework is an ANONYMOUS result. On an application whose interesting surface is behind a
// login that makes its zero meaningless, and a zero that looks like the other tools' zeros is the
// shape this project keeps having to dig back out of a finding count.
func ComposeLFIHunt(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("lfihunt")
	var warnings []string

	args := []string{"/opt/LFIHunt/scanner.py", "-i", reportPath + ".urls", "-o", reportPath}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	warnings = append(warnings, lfihuntAnonymousWarning(v)...)
	return args, warnings
}

// lfihuntAnonymousWarning states that this scan ran logged out, and says so more sharply when the
// framework was holding a credential it had no way to pass on.
func lfihuntAnonymousWarning(v VectorInput) []string {
	base := "LFIHunt CANNOT be authenticated: its batch scanner takes only an input file, an output " +
		"file and a thread count, and its checkers carry no cookie or header. This vector was " +
		"therefore tested as an anonymous user."
	if material := cmdiHeldCredentials(v.ScopeTargetID, v.Domain); material != nil {
		return []string{base + " The framework HOLDS credentials for " + v.Domain + " (" +
			authMaterialSource(material) + ") and could not hand them over, so treat this zero as " +
			"unproven and rely on LFImap, which does send them, for the authenticated surface."}
	}
	return []string{base}
}

// LFIHuntURL renders the URL the scanner is given.
//
// Every parameter the vector names is present with a value, because LFIHunt's checkers enumerate the
// QUERY STRING and test what they find: a parameter that is not physically in the URL is a parameter
// they never see, and the scan reports clean without having touched it.
func LFIHuntURL(v VectorInput) string {
	base := v.TargetURL()
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := parsed.Query()
	for _, name := range v.Parameters {
		if q.Get(name) == "" {
			q.Set(name, v.valueFor(name))
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
