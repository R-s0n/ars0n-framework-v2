package utils

import (
	"net/url"
	"strconv"
	"strings"
)

// Building the command lines for the request smuggling section.
//
// Both tools take a URL and neither takes a parameter, so composing is mostly about refusing the
// settings that would quietly turn a scan into nothing. That risk is unusually high here: between
// them these two tools have five separate ways to exit 0 having probed nothing at all, and four of
// them are reachable from a settings field.

// ComposeSmugglex builds the smugglex argv for one URL.
func ComposeSmugglex(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("smugglex")
	var warnings []string

	target := smugglingScanURL(v)
	args := []string{target}

	// The checks are assembled from switches rather than passed through, because smugglex accepts an
	// unknown check name in silence: it runs nothing, prints "smuggling found 0 vulnerabilities" and
	// exits 0 in 0.000 seconds. Only names verified to exist against the built binary get emitted.
	var checks []string
	for _, check := range smugglexChecks {
		if truthySetting(settings[check.Key]) {
			checks = append(checks, check.Flag)
		}
	}
	if len(checks) == 0 {
		// Not a default that can be left implicit: an empty -c is one of the silent-nothing cases, and
		// omitting -c entirely runs everything anyway. Stated so the report says what was covered.
		for _, check := range smugglexChecks {
			checks = append(checks, check.Flag)
		}
		warnings = append(warnings, "No checks were selected, so this run used all seven.")
	}
	args = append(args, "-c", strings.Join(checks, ","))

	// h2-downgrade is the only check that needs TLS. It is skipped by smugglex on a cleartext target
	// with a warning of its own, and the run then covers six checks rather than seven; said here so
	// the count in the report is not a surprise.
	if truthySetting(settings["h2Downgrade"]) && !strings.HasPrefix(strings.ToLower(target), "https://") {
		warnings = append(warnings, "The h2-downgrade check speaks real HTTP/2 over TLS and will be "+
			"skipped for this cleartext target, so this run covers the other checks only.")
	}

	// Zero is accepted by smugglex for each of these and destroys the scan without saying so: -t 0
	// makes every check fail instantly with a timeout, and the run reports no vulnerabilities in
	// seven thousandths of a second. Dropped back to the tool's own default instead.
	skip := map[string]bool{}
	for _, key := range []string{"timeout", "concurrency", "baselineCount"} {
		if value, present := settings[key]; present && isZeroNumber(value) {
			skip[key] = true
			warnings = append(warnings, "Ignored "+tool.Options[key].Label+" of 0: smugglex accepts it "+
				"and then reports no findings without having tested anything. The tool default was used.")
		}
	}

	// The five exploitation modules are switches for the same reason the checks are: -e takes a
	// comma-separated list and an unrecognised entry is not an error.
	var exploits []string
	for _, module := range smugglexExploits {
		if truthySetting(settings[module.Key]) {
			exploits = append(exploits, module.Flag)
		}
	}
	if len(exploits) > 0 {
		args = append(args, "-e", strings.Join(exploits, ","))
		warnings = append(warnings, "Exploitation is on ("+strings.Join(exploits, ", ")+"), so this run "+
			"sends smuggled requests intended to reach the back-end rather than only measuring it.")

		// capture is not like the others. It recovers the response to a request it smuggled onto a
		// shared connection, and on a live site the response that comes back can belong to whoever
		// else was using that connection. That is somebody else's data arriving in this report.
		if truthySetting(settings["exploitCapture"]) {
			warnings = append(warnings, "The capture module recovers a smuggled RESPONSE. On a live "+
				"target sharing a front-end with real users, what comes back can be another user's "+
				"traffic, and it will be stored in this scan's evidence. Use it on a target you are "+
				"authorised to disrupt.")
		}
	} else {
		for _, key := range []string{"exploitPorts", "exploitWordlist", "revealEndpoint",
			"revealParam", "smuggleRequest"} {
			skip[key] = true
		}
	}

	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)

	// Framework owned, last so a stored setting cannot displace them. The report is JSON on disk
	// rather than stdout because stdout carries the log lines too, and the runner merges the streams.
	args = append(args, "-o", reportPath, "-f", "json", "--no-color")
	return args, warnings
}

// ComposeHTTP2Smugl builds the http2smugl argv for one URL.
func ComposeHTTP2Smugl(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("http2smugl")
	var warnings []string

	// detect is a subcommand, and the URL is always given in full.
	//
	// The target form matters more than it looks. http2smugl decides how to read a target with a
	// literal test for a slash: no slash means "hostname", so it prepends https:// and appends /;
	// otherwise the string is used verbatim. A bare "example.com/" therefore falls into the verbatim
	// branch with no scheme at all. Passing the whole URL avoids the question.
	args := []string{"detect", smugglTargetURL(v)}

	skip := map[string]bool{}

	// --threads 0 does not error and does not scan: the job channel is created with zero capacity and
	// no workers, so the producer blocks on its first send and the process hangs until it is killed.
	// A hang is worse than a bad result, because the whole section sits at "3 of 40" until the
	// per-tool timeout expires.
	if value, present := settings["threads"]; present && isZeroNumber(value) {
		skip["threads"] = true
		warnings = append(warnings, "Ignored a thread count of 0: http2smugl hangs forever on it "+
			"rather than reporting an error. The tool default of 100 was used.")
	}

	// Without --verbose, a target that times out or resets the connection produces no output at all,
	// on either stream. The run then looks identical to a clean one.
	if !truthySetting(settings["verbose"]) {
		args = append(args, "--verbose")
		warnings = append(warnings, "Verbose logging was turned on for this run: without it http2smugl "+
			"suppresses timeouts and connection resets entirely, and an unreachable target is then "+
			"indistinguishable from a clean one.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", skip, &warnings)...)
	args = append(args, "--csv-log", reportPath)
	return args, warnings
}

// smugglingScanURL renders the URL to scan, AS OBSERVED.
//
// Deliberately not TargetURL(), which substitutes the rs0n canary into every parameter whose value
// was never seen. Neither of these tools reads the query string: they test how the request is
// FRAMED, and forward the query untouched. So a canary buys nothing here and costs something real,
// because changing a parameter value changes which handler runs and what the WAF in front of it
// thinks of the request. The accepted craft is the opposite: keep the attack request as close to a
// normal one as possible, preserving the parameters the endpoint expects.
func smugglingScanURL(v VectorInput) string {
	base := v.baseURL()
	if parsed, err := url.Parse(v.EvidenceURL); err == nil && parsed.RawQuery != "" {
		return base + "?" + parsed.RawQuery
	}
	return base
}

// smugglTargetURL renders the URL http2smugl is given, always with a scheme and always with a path.
func smugglTargetURL(v VectorInput) string {
	target := smugglingScanURL(v)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	// A URL with no path at all lands in http2smugl's verbatim branch without a trailing slash, which
	// its own hostname branch would have added.
	if rest := target[strings.Index(target, "://")+3:]; !strings.Contains(rest, "/") {
		target += "/"
	}
	return target
}

// isZeroNumber reports whether a setting is numerically zero, whatever shape JSON delivered it in.
func isZeroNumber(value any) bool {
	switch t := value.(type) {
	case float64:
		return t == 0
	case int:
		return t == 0
	case string:
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			return false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		return err == nil && parsed == 0
	}
	return false
}
