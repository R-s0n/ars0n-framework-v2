package utils

import "strings"

// Composing the three XSS scanners. The generic machinery is in vectorCompose.go; what lives here is
// the part that is specific to dalfox, domdig and xssFuzz.

// dalfoxLocationFor maps our insertion point onto dalfox's -p location token.
//
// Verified token by token. query, body, json, multipart and header all work and self-label in the
// output. cookie works but reports location "Header", because a cookie IS a header on the wire.
//
// PATH IS DELIBERATELY ABSENT. There is no path token: `-p name:path` produces zero findings and
// zero errors, exactly like the invalid token `-p name:bogus` does. Path is reachable only through
// dalfox's own path_segment_N discovery, which is why pathNeedsDiscovery exists below.
func dalfoxLocationFor(insertionPoint, contentType string) (string, bool) {
	switch insertionPoint {
	case "query":
		return "query", true
	case "header":
		return "header", true
	case "cookie":
		return "cookie", true
	case "body":
		ct := strings.ToLower(contentType)
		switch {
		case strings.Contains(ct, "json"):
			return "json", true
		case strings.Contains(ct, "multipart"):
			return "multipart", true
		default:
			return "body", true
		}
	}
	return "", false
}

// XSSBlindingSettings are settings that make a whole insertion point untestable while the scan still
// exits 0 and reports nothing. Refused at save time rather than at run time, for the same reason the
// ffuf vocabulary refuses its unsupported options: a setting that is stored and then quietly negates
// the scan is worse than one that is rejected.
//
// Only path is listed. --skip-reflection-header and --skip-reflection-cookie turn off DISCOVERY of
// those inputs, and the runner names its target explicitly with -p, so they cost nothing. Measured:
// a cookie vector with --skip-reflection-cookie set still reported its finding. Path has no explicit
// form, so for path these two flags are the whole mechanism.
func ComposeDalfox(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("dalfox")
	var warnings []string

	args := []string{"scan", v.TargetURL()}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "-X", method)
	}
	// vectorBodyFor, not v.Body. Guarding on a recorded body meant that a body vector whose
	// raw_request was never captured produced `-X POST -p name:body` with no -d, so dalfox posted an
	// empty body, tested nothing, and the vector was recorded clean. All 10 POST vectors on
	// ginandjuice.shop are in exactly that state.
	if v.InsertionPoint == "body" {
		args = append(args, "-d", vectorBodyFor(v))
	}

	// The target header, lower-cased, so it can be removed from the user's -H list regardless of how
	// either was capitalised. Header names are case insensitive and Authorization would otherwise
	// survive a comparison against authorization.
	suppressedHeader := ""
	if v.InsertionPoint == "header" && len(v.Parameters) > 0 {
		suppressedHeader = strings.ToLower(v.Parameters[0])
	}

	if location, ok := dalfoxLocationFor(v.InsertionPoint, v.ContentType); ok {
		for _, name := range v.Parameters {
			args = append(args, "-p", name+":"+location)
		}
		if v.InsertionPoint == "cookie" {
			for _, name := range v.Parameters {
				args = append(args, "--cookies", name+"="+v.valueFor(name))
			}
		}
	} else if v.InsertionPoint == "path" {
		// No -p at all. There is no path token, and an unrecognised one is silently ignored rather
		// than rejected, so naming one here would produce a clean scan of nothing.
		if blinded := VectorBlindedPoints("dalfox", settings); len(blinded["path"]) > 0 {
			warnings = append(warnings, "Path vectors need dalfox's own path segment discovery, which "+
				strings.Join(blinded["path"], " and ")+" turns off. This vector was not scanned.")
			return nil, warnings
		}
	}

	args = append(args, composeVectorSettings(tool, settings, suppressedHeader, nil, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--format", "jsonl",
		"--output", reportPath,
		"--include-all",
		"--no-color",
		"-S",
	)
	return args, warnings
}

// ComposeDomdig builds the domdig argv for one vector. domdig takes one URL and fuzzes its query
// string and hash, so there is nothing per-insertion-point to decide: the eligibility check has
// already ruled out everything it cannot reach.
func ComposeDomdig(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("domdig")
	var warnings []string

	args := []string{"/app/domdig.js"}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	// -J prints findings as JSON on stdout and -q silences the progress chatter that would otherwise
	// be interleaved with it. domdig has no --output, so the report is the captured stdout.
	args = append(args, "-J", "-q", v.TargetURL())
	_ = reportPath
	return args, warnings
}

// ComposeXSSFuzz builds the xssFuzz argv for one vector.
//
// --param is passed explicitly rather than letting xssFuzz discover parameters, because its
// discovery regex is (?<=\?|\&)[^=&]+ over the raw URL and would also pick up parameters this vector
// does not claim. TargetURL has already guaranteed every named parameter is physically present with
// a value, which is what xssFuzz's substitution needs in order to match at all.
func ComposeXSSFuzz(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("xssfuzz")
	var warnings []string

	args := []string{"/app/xssFuzz.py", "-u", v.TargetURL()}
	if len(v.Parameters) > 0 {
		args = append(args, "--param", strings.Join(v.Parameters, ","))
	}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	args = append(args, "-o", reportPath)
	return args, warnings
}
