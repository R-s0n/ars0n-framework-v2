package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Building the command lines for the server-side request forgery section.
//
// The chain, and which link each card is:
//
//	REcollapse   mutates the webhook URL into a payload list, which the FRAMEWORK then sends
//	             (redirectProbe.go) at every probeable parameter, each payload carrying a canary
//	Nuclei DAST  runs stock upstream DAST templates, knows nothing about the webhook
//	SSRFmap      weaponises whatever either of them confirmed
//
// The webhook belongs to REcollapse alone, which is why it is a tab on that tool's Config modal
// rather than a section-wide button. Nuclei used to be gated on it too, and that gate meant a target
// with no webhook got nothing from this section at all, including the checks that prove themselves
// from the response and never call anybody.

// ComposeREcollapse builds the recollapse argv.
//
// The seed is the webhook URL with a TOKEN PLACEHOLDER in its path. The placeholder is substituted
// at SEND time, per parameter, in redirectProbe.go: REcollapse generates one list and the prober
// aims it, so a callback names the input that produced it rather than the vector it belonged to.
func ComposeREcollapse(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("recollapse")
	var warnings []string

	webhook := strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"]))
	if webhook == "" {
		return nil, []string{"No listening webhook URL is configured, so there is nothing to build " +
			"payloads out of. Set it on the Webhook tab of this tool's Config."}
	}

	seed := strings.TrimRight(webhook, "/") + "/" + vectorTokenPlaceholder

	args := []string{}
	// replayLimit, probeDelayMs and the three webhook keys all carry no flag, so composeVectorSettings
	// drops them on its own; they are framework settings that govern the send rather than recollapse
	// arguments. Nothing needs to be named here.
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	args = append(args, seed)
	_ = reportPath
	return args, warnings
}

// ComposeNucleiDast builds the nuclei argv for one vector.
//
// ALWAYS through -im jsonl, never -u. Measured: driven by a URL, nuclei fuzzes the query string and
// nothing else, even when the template declares parts: [query, body, header, cookie, path]. Driven
// by a raw request it fuzzes query, body, header AND cookie, which is 60 of the 71 vectors on the
// reference target rather than 39. Path is not fuzzed either way.
//
// No -lfa any more: that flag existed only so nuclei would read the payload file belonging to the
// custom template this section used to ship. Upstream templates carry their own payloads.
func ComposeNucleiDast(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("nuclei-dast")
	var warnings []string

	args := []string{
		"-dast",
		"-im", "jsonl",
		"-l", reportPath + ".in.jsonl",
	}

	// One -t per selected set. These are UPSTREAM templates now, so there is no helper file to read
	// and -lfa is gone with the custom template that needed it.
	for _, path := range nucleiTemplatePaths(settings, &warnings) {
		args = append(args, "-t", path)
	}

	// templates is consumed above rather than skipped-and-forgotten; extraTemplates is emitted by
	// composeVectorSettings itself, since it is a plain repeatable -t.
	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"templates": true}, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args, "-jsonl", "-o", reportPath, "-no-color")
	return args, warnings
}

// nucleiTemplateSets maps a set name to the upstream path holding it.
//
// xinclude is a FILE rather than a directory on purpose: xinclude-injection.yaml lives in
// dast/vulnerabilities/injection/ beside csv-injection, unix-command-injection and
// windows-command-injection, none of which belong in this section. Pointing -t at that directory
// would quietly turn the SSRF scan into a command injection scan.
var nucleiTemplateSets = map[string]string{
	"ssrf":     "/root/nuclei-templates/dast/vulnerabilities/ssrf/",
	"redirect": "/root/nuclei-templates/dast/vulnerabilities/redirect/",
	"rfi":      "/root/nuclei-templates/dast/vulnerabilities/rfi/",
	"xxe":      "/root/nuclei-templates/dast/vulnerabilities/xxe/",
	"xinclude": "/root/nuclei-templates/dast/vulnerabilities/injection/xinclude-injection.yaml",
	"crlf":     "/root/nuclei-templates/dast/vulnerabilities/crlf/",
}

// nucleiDefaultTemplateSets is everything that is a server-side fetch of a supplied URL, plus the
// redirect pair this section keeps. crlf is deliberately absent: header injection is redirect
// adjacent rather than an SSRF, and it is one checkbox away for an operator who wants it.
var nucleiDefaultTemplateSets = []string{"ssrf", "redirect", "rfi", "xxe", "xinclude"}

func nucleiTemplatePaths(settings map[string]any, warnings *[]string) []string {
	chosen := settingValues(settings["templates"])
	if len(chosen) == 0 {
		chosen = nucleiDefaultTemplateSets
	}
	var paths []string
	for _, name := range chosen {
		name = strings.ToLower(strings.TrimSpace(name))
		if path, ok := nucleiTemplateSets[name]; ok {
			paths = append(paths, path)
			continue
		}
		// Reported rather than dropped. A template set that silently vanishes is how an operator comes
		// to believe a class of bug was tested for.
		*warnings = append(*warnings, "Ignored unknown template set "+name+
			". The sets are ssrf, redirect, rfi, xxe, xinclude and crlf.")
	}
	if len(paths) == 0 {
		*warnings = append(*warnings, "No template set resolved, so the defaults were used instead of "+
			"running nuclei with no templates at all, which reports success having tested nothing.")
		for _, name := range nucleiDefaultTemplateSets {
			paths = append(paths, nucleiTemplateSets[name])
		}
	}
	return paths
}

// webhookHost reduces a webhook URL to the host that will appear in a Location header.
func webhookHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// ComposeSSRFmap builds the SSRFmap argv.
func ComposeSSRFmap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("ssrfmap")
	var warnings []string

	param := markableParam(v)
	if param == "" {
		return nil, []string{"SSRFmap needs a parameter name and this vector names none, so there is " +
			"nothing for it to target."}
	}

	args := []string{"/opt/SSRFmap/ssrfmap.py", "-r", reportPath + ".req", "-p", param}

	// portscan unless the operator chose otherwise. Every other module talks to an internal service
	// on someone else's network, and a default that did that would be a default nobody asked for.
	if len(settingValues(settings["modules"])) == 0 || stringifySetting(settings["modules"]) == "" {
		args = append(args, "-m", "portscan")
		warnings = append(warnings, "No modules were chosen, so this run used portscan only. The "+
			"modules that read files or talk to internal databases are a deliberate choice.")
	}

	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	return args, warnings
}

// NucleiBodyRecord builds the proxify-shaped jsonl record nuclei fuzzes from.
//
// The shape is not documented; it came out of the error nuclei prints when the record is wrong:
// `request of type struct { Header map[string]string "json:\"header\""; Body string "json:\"body\"";
// Raw string "json:\"raw\""; Endpoint string "json:\"endpoint\"" }`. A record whose request is a
// plain string is rejected outright, and one shaped like an ordinary HTTP description is accepted
// and then fuzzes nothing.
//
// The RAW REQUEST is what carries the headers and cookies, and it is the reason this section reaches
// four insertion points instead of one.
func NucleiBodyRecord(v VectorInput) (string, error) {
	raw := SSRFmapRawRequest(v)
	target := v.TargetURL()

	contentType := v.ContentType
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	body := ""
	if v.InsertionPoint == "body" {
		body = cmdiBodyFor(v)
	}

	record := map[string]any{
		"url": target,
		"request": map[string]any{
			"raw":      raw,
			"body":     body,
			"header":   map[string]string{"Content-Type": contentType},
			"endpoint": target,
		},
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}

// SSRFmapRawRequest renders the raw request bytes, used both by SSRFmap's -r and by the record above.
//
// The recorded request is preferred when there is one, because it carries the headers and cookies a
// vector is actually about. Rebuilt only when there is nothing recorded.
func SSRFmapRawRequest(v VectorInput) string {
	if strings.TrimSpace(v.RawRequestOverride) != "" {
		return v.RawRequestOverride
	}
	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method == "" {
		method = "GET"
	}
	target := v.TargetURL()
	host, path := target, "/"
	if _, rest, ok := strings.Cut(target, "://"); ok {
		host, _, _ = strings.Cut(rest, "/")
		if _, p, found := strings.Cut(rest, "/"); found {
			path = "/" + p
		}
	}

	if v.InsertionPoint == "body" {
		body := cmdiBodyFor(v)
		contentType := v.ContentType
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
			method, path, host, contentType, len(body), body)
	}
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, host)
}
