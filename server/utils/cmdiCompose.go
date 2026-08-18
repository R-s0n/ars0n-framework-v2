package utils

import (
	"strings"
)

// Turning one attack vector into a commix, SSTImap or TInjA command line.
//
// The three reach their insertion points by three different mechanisms, and every one of them was
// measured rather than read:
//
//	                commix                    SSTImap              TInjA
//	  query         native                    native (-P Q)        native
//	  body          --data                    -d (-P B)            -d
//	  cookie        --level 2                 -C  (-P C)           NOT REACHABLE
//	  header        user-agent/referer/host   -H  (-P H)           --testheaders <name>
//	  path          INJECT_HERE in the URL    * marker in the URL  NOT REACHABLE
//
// Two of those are silent when wrong. commix below --level 2 never tests a cookie, and TInjA without
// --testheaders never tests a header: both exit 0 having sent nothing at the input the vector names.

// commixMarker is commix's own injection tag, from src/utils/settings.py: INJECT_TAG = "INJECT_HERE".
// It is a literal string, NOT the asterisk sqlmap and SSTImap use, and putting the wrong one in a
// URL produces a scan of the literal text.
const commixMarker = "INJECT_HERE"

// ComposeCommix builds the commix argv for one vector.
func ComposeCommix(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("commix")
	var warnings []string

	args := []string{"/opt/commix/commix.py", "-u", commixTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "--method", method)
	}
	if v.InsertionPoint == "body" {
		args = append(args, "--data", cmdiBodyFor(v))
	}

	// -p keeps commix on the parameter this vector claims. Without it a URL carrying three
	// parameters costs three times as long and can attribute a finding to a vector that never
	// named the parameter that produced it.
	if (v.InsertionPoint == "query" || v.InsertionPoint == "body") && len(v.Parameters) > 0 {
		args = append(args, "-p", strings.Join(v.Parameters, ","))
	}

	authCookies := stringifySetting(settings["cookie"])
	if v.InsertionPoint == "cookie" {
		name := firstParam(v)
		// NOT mergeCookieHeader: that appends sqlmap's * marker, and commix's marker is the literal
		// INJECT_HERE. An asterisk glued to a session value is a changed cookie, which is a different
		// request from the one that was observed.
		args = append(args, "--cookie", joinCookies(authCookies, name, v.valueFor(name)))
		// THE RULE. Measured: with the default level commix never sets the cookie for testing and the
		// run ends reporting nothing; at --level 2 it reports "Cookie parameter 'name' appears to be
		// injectable". Only raised when the operator has not asked for more.
		if levelBelow(settings["level"], 2) {
			args = append(args, "--level", "2")
			warnings = append(warnings, "Raised commix to --level 2 for this cookie vector: below it "+
				"commix does not test cookies at all and the run would report nothing.")
		}
	} else if authCookies != "" {
		args = append(args, "--cookie", authCookies)
	}

	// A header vector only gets here when commixVectorEligible allowed it, which means the header is
	// one of the three commix knows. Level 3 is what turns header testing on.
	if v.InsertionPoint == "header" {
		if levelBelow(settings["level"], 3) {
			args = append(args, "--level", "3")
			warnings = append(warnings, "Raised commix to --level 3 for this header vector: headers "+
				"are not tested below it.")
		}
		name := strings.ToLower(firstParam(v))
		value := v.valueFor(name)
		switch name {
		case "referer":
			args = append(args, "--referer", value)
		case "user-agent":
			args = append(args, "--user-agent", value)
		case "host":
			args = append(args, "--host", value)
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "", map[string]bool{"cookie": true}, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--batch",            // no terminal to answer prompts from
		"--disable-coloring", // escape codes corrupt stored evidence
		// ALWAYS. commix keeps a session per target and consults it on the next run, and the second
		// run of a vector it has already seen reports NOTHING. Measured on a target with a live
		// command injection: without this flag two consecutive runs both report 0 injectable
		// parameters; with it, both report 1. A scan whose results depend on whether the same target
		// was scanned before is worse than a slow one, because the empty result looks like an answer.
		"--flush-session",
		"--output-dir", "/tmp/commix-out",
	)
	return args, warnings
}

// ComposeSSTImap builds the SSTImap argv.
//
// It needs the least help of the three: -P defaults to QBHC, so query, body, headers and cookies are
// all tested with no marker and no level. Only a path vector needs the marker placed.
func ComposeSSTImap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("sstimap")
	var warnings []string

	args := []string{"/opt/SSTImap/sstimap.py", "-u", sstimapTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "-m", method)
	}
	if v.InsertionPoint == "body" {
		args = append(args, "-d", cmdiBodyFor(v))
	}
	if v.InsertionPoint == "cookie" {
		name := firstParam(v)
		args = append(args, "-C", name+"="+v.valueFor(name))
	}
	if v.InsertionPoint == "header" {
		name := firstParam(v)
		args = append(args, "-H", name+": "+v.valueFor(name))
	}
	if cookies := stringifySetting(settings["cookie"]); cookies != "" && v.InsertionPoint != "cookie" {
		for _, pair := range strings.Split(cookies, ";") {
			if pair = strings.TrimSpace(pair); pair != "" {
				args = append(args, "-C", pair)
			}
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "", map[string]bool{"cookie": true}, &warnings)...)
	args = append(args, "--no-color")
	_ = reportPath
	return args, warnings
}

// ComposeTInjA builds the TInjA argv.
//
// --testheaders is the rule here. Measured: with the header named, TInjA identifies Jinja2 at Very
// High certainty; without it the same run sends one polyglot and reports zero suspected injections.
func ComposeTInjA(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("tinja")
	var warnings []string

	args := []string{"url", "-u", v.TargetURL()}

	if v.InsertionPoint == "body" {
		// TInjA switches to POST when -d is given; it has no method flag of its own.
		args = append(args, "-d", cmdiBodyFor(v))
	}
	if v.InsertionPoint == "header" {
		name := firstParam(v)
		args = append(args, "--testheaders", name, "-H", name+": "+v.valueFor(name))
	}
	if cookies := stringifySetting(settings["cookie"]); cookies != "" {
		for _, pair := range strings.Split(cookies, ";") {
			if pair = strings.TrimSpace(pair); pair != "" {
				args = append(args, "-c", pair)
			}
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "", map[string]bool{"cookie": true}, &warnings)...)

	// A DIRECTORY, with the trailing slash. TInjA treats --reportpath as a prefix and appends
	// <timestamp>_Report.jsonl to it, so passing a filename produces report.json2026-..._Report.jsonl
	// and nothing ever appears at the path the runner then tries to read.
	args = append(args, "--reportpath", reportPath+"/")
	return args, warnings
}

// commixTargetURL places commix's INJECT_HERE marker in a path segment.
//
// REPLACING the segment, not appended to it. Measured against a target whose path segment reaches a
// shell: /cmd/path/INJECT_HERE is reported injectable, /cmd/path/worldINJECT_HERE finds nothing at
// all. commix substitutes the whole tag rather than treating it as a suffix, so a marker glued onto
// a value is a marker it never recognises, and the run ends clean.
func commixTargetURL(v VectorInput) string {
	if v.InsertionPoint != "path" {
		return v.TargetURL()
	}
	return markLastPathSegment(v.TargetURL(), commixMarker, true)
}

// sstimapTargetURL places SSTImap's * marker in a path segment.
func sstimapTargetURL(v VectorInput) string {
	if v.InsertionPoint != "path" {
		return v.TargetURL()
	}
	return markLastPathSegment(v.TargetURL(), "*", true)
}

// markLastPathSegment replaces or suffixes the last path segment with a marker.
//
// Edited as TEXT rather than through net/url, for the reason the SQL section found the hard way:
// URL.String() percent-encodes an asterisk to %2A, and a tool looking for a literal marker then
// finds none, falls back to whatever parameters exist, and reports the path clean.
//
// replace says whether the marker stands IN PLACE of the segment (SSTImap's *, which marks where a
// payload goes) or is appended to it (commix's INJECT_HERE, which it substitutes).
func markLastPathSegment(rawURL, marker string, replace bool) string {
	pathPart, queryPart, hasQuery := strings.Cut(rawURL, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return rawURL
	}
	host, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return rawURL
	}

	segments := strings.Split(path, "/")

	// The TEMPLATED segment is the injectable one when there is one. /users/{uuid}/settings has its
	// identifier in the middle, and marking the last segment would test the literal word settings
	// while the thing the vector is actually about goes untouched. Falls back to the last segment
	// when nothing is templated, which is the concrete-identifier case.
	target := -1
	for i, seg := range segments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			target = i
			break
		}
	}
	if target == -1 {
		for i := len(segments) - 1; i >= 0; i-- {
			if segments[i] != "" {
				target = i
				break
			}
		}
	}
	if target >= 0 {
		templated := strings.HasPrefix(segments[target], "{") && strings.HasSuffix(segments[target], "}")
		if replace || templated {
			segments[target] = marker
		} else {
			segments[target] += marker
		}
	}

	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out
}

// cmdiBodyFor returns the body to send, building one from the vector's parameter names when no body
// was recorded. Without it the tool is handed an empty body and tests nothing.
func cmdiBodyFor(v VectorInput) string {
	if strings.TrimSpace(v.Body) != "" {
		return v.Body
	}
	var pairs []string
	for _, name := range v.Parameters {
		pairs = append(pairs, name+"="+v.valueFor(name))
	}
	return strings.Join(pairs, "&")
}

// levelBelow reports whether a stored level setting is absent or lower than the one a vector needs.
// The operator's own higher level is never lowered.
func levelBelow(stored any, need int) bool {
	switch t := stored.(type) {
	case float64:
		return int(t) < need
	case int:
		return t < need
	case string:
		if t == "" {
			return true
		}
		return len(t) == 1 && t[0] < byte('0'+need)
	}
	return true
}


// joinCookies builds a Cookie string from the operator's auth cookies plus the vector's own, with no
// marker of any kind. commix finds a cookie by testing it at --level 2, not by marking it.
func joinCookies(authCookies, targetName, targetValue string) string {
	var kept []string
	for _, pair := range strings.Split(authCookies, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		// The operator's stale copy of the target cookie is dropped, or the request carries the name
		// twice and which one the application reads is not something to leave to chance.
		if strings.EqualFold(strings.TrimSpace(name), targetName) {
			continue
		}
		kept = append(kept, pair)
	}
	if targetName != "" {
		kept = append(kept, targetName+"="+targetValue)
	}
	return strings.Join(kept, "; ")
}
