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
func ComposeLFImap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("lfimap")
	var warnings []string

	// A PATH vector names no parameter and does not need to: the marker replaces a path segment. Every
	// other point substitutes into a named input, so there the name is required.
	param := firstParam(v)
	if param == "" && v.InsertionPoint != "path" {
		return nil, []string{"This vector names no parameter, so there is nowhere to put the marker."}
	}

	args := []string{"-U", lfimapTargetURL(v, param)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" && v.InsertionPoint != "body" {
		args = append(args, "-M", method)
	}

	authCookies := stringifySetting(settings["cookie"])

	switch v.InsertionPoint {
	case "body":
		args = append(args, "-D", lfimapBody(v, param))
	case "cookie":
		// The operator's own cookies survive, with the target's replaced by the marker: a scan that
		// drops the session tests a logged-out application.
		args = append(args, "-C", joinCookies(authCookies, param, lfimapPlaceholder))
	case "header":
		args = append(args, "-H", param+": "+lfimapPlaceholder)
		if authCookies != "" {
			args = append(args, "-C", authCookies)
		}
	default:
		if authCookies != "" {
			args = append(args, "-C", authCookies)
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"cookie": true}, &warnings)...)

	// A technique has to be chosen or LFImap tests none of them. Filter and traversal by default:
	// the filter wrapper is the highest-signal PHP check and traversal is the one that applies to a
	// target of any language.
	if !anyTechniqueChosen(settings) {
		args = append(args, "-f", "-t")
		warnings = append(warnings, "No technique was chosen, so this run used the filter wrapper and "+
			"path traversal. The wrappers that reach code execution are a deliberate choice.")
	}

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args, "--placeholder", lfimapPlaceholder, "-nc")
	_ = reportPath
	return args, warnings
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
func ComposeLFIHunt(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("lfihunt")
	var warnings []string

	args := []string{"/opt/LFIHunt/scanner.py", "-i", reportPath + ".urls", "-o", reportPath}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	return args, warnings
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
