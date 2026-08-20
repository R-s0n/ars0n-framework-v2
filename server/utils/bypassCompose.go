package utils

import (
	"strconv"
	"strings"
)

// Building the command lines for the access control bypass section.
//
// Both tools take one URL and try many variations of it. The composing work is almost entirely about
// the false positive controls, because on a real site the default behaviour of either tool is to
// report every variation whose response differs at all, and most differences are not bypasses.

// nomore403PayloadDir is where the cloned repository's payload wordlists live in the image.
const nomore403PayloadDir = "/opt/nomore403/payloads"

// ComposeNomore403 builds the nomore403 argv for one target URL.
func ComposeNomore403(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("nomore403")
	var warnings []string

	args := []string{"-u", v.EvidenceURL}

	var techniques []string
	for _, technique := range nomore403Techniques {
		if truthySetting(settings[technique.Key]) {
			techniques = append(techniques, technique.Flag)
		}
	}
	if len(techniques) > 0 {
		args = append(args, "-k", strings.Join(techniques, ","))
	} else {
		// Omitted rather than passed empty: nomore403's own default is all twenty-three, and an empty
		// -k would be a list of nothing.
		warnings = append(warnings, "No techniques were selected, so this run used all twenty-three.")
	}

	// Calibration is what separates a usable report from an unusable one, so turning it off is
	// reported every time rather than being a quiet checkbox.
	if truthySetting(settings["noCalibrate"]) {
		warnings = append(warnings, "Auto-calibration is OFF for this run. Measured against a target "+
			"that answers 200 with a denial page to every variation, this setting took the report from "+
			"thirteen results and no false positives to sixty results including three bypasses that "+
			"did not exist. Every result here needs confirming by hand.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)

	// Framework owned. -f is emitted explicitly rather than relying on the container's working directory. nomore403's
	// --help says the payload folder defaults to "the same directory as the executable"; the source
	// says otherwise, defaulting to the literal relative path "payloads" resolved against the process
	// CWD. Anything that changes the working directory therefore leaves it with no header, endpath or
	// midpath payloads, and the run completes having tried a fraction of what it reported.
	args = append(args, "-f", nomore403PayloadDir, "--jsonl", "-o", reportPath, "--no-banner")
	return args, warnings
}

// ComposeForbidden builds the Forbidden argv for one target URL.
//
// Forbidden takes ONE URL: passing a file path produces `ERROR: Inaccessible URL: URL scheme is
// required`, so there is no batching to be had here even though the target list is long.
func ComposeForbidden(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("forbidden")
	var warnings []string

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
		tests = []string{"methods", "method-overrides", "path-overrides", "headers", "paths", "encodings"}
		warnings = append(warnings, "No tests were selected. Forbidden requires -t and has no default, "+
			"so this run used the six families that need no extra input: methods, method overrides, "+
			"path overrides, headers, paths and encodings. The tests that need a collaborator URL or a "+
			"known-accessible path are a deliberate choice.")
	}
	args = append(args, "-t", strings.Join(tests, ","))

	skip := map[string]bool{}

	// The soft-403 filter, supplied by default rather than left to the operator.
	//
	// The section's whole target list is URLs that returned 401 or 403. A variation that comes back
	// the same length as that original denial is the denial again, whatever status it carries.
	// Forbidden understands the literal word "initial" for exactly this.
	if strings.TrimSpace(stringifySetting(settings["contentLengths"])) == "" {
		args = append(args, "-l", "initial")
		skip["contentLengths"] = true
		warnings = append(warnings, "Results whose length matches the original denial response are "+
			"filtered out, which is what stops a page that says \"Access Denied\" under a 200 from "+
			"being reported as a bypass. Set your own content lengths to change this.")
	}

	if strings.TrimSpace(stringifySetting(settings["force"])) != "" {
		warnings = append(warnings, "Forcing a method also skips the OPTIONS probe Forbidden uses to "+
			"discover which methods the endpoint allows, so the whole verb axis collapses to the one "+
			"method you forced.")
	}

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
