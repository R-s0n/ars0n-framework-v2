package utils

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Building the command lines for the open redirect and SSRF section.
//
// The section runs as a chain, and each card is one link:
//
//	REcollapse   mutates the operator's webhook URL into a payload list
//	Nuclei DAST  fires that list at every eligible vector, then asks the webhook who called
//	SSRFmap      pivots whatever the scan confirmed
//
// The webhook is the section's, not a tool's, because the first two both need the same pair and
// entering it twice is how two copies come to disagree.

// redirectMutationsPath is where REcollapse's output is kept for the scanner to pick up.
//
// On the SHARED volume, because the two run in different containers: REcollapse prints to stdout in
// its own, the API writes the list here, and nuclei reads it from its own. Per target rather than
// per scan, since the list is a property of the webhook rather than of one run.
func redirectMutationsPath(scopeTargetID string) string {
	return "/tmp/redirect-mutations-" + strings.ReplaceAll(scopeTargetID, "-", "") + ".txt"
}

// ComposeREcollapse builds the recollapse argv.
//
// The input is the webhook URL with a TOKEN PLACEHOLDER in its path. REcollapse runs once per scan
// and the scanner runs once per vector, so the per-vector marker cannot be baked in here; the
// placeholder is substituted when the payload list is written for a given vector, which is what lets
// a callback name the parameter that produced it.
func ComposeREcollapse(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("recollapse")
	var warnings []string

	webhook := strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"]))
	if webhook == "" {
		return nil, []string{"No listening webhook URL is configured for this section, so there is " +
			"nothing to build payloads out of. Use Configure Webhook."}
	}

	seed := strings.TrimRight(webhook, "/") + "/" + vectorTokenPlaceholder

	args := []string{}
	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"replayLimit": true, "canaryHost": true}, &warnings)...)
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
// -lfa is required because the payload list is a file, and nuclei refuses to read a helper file
// outside its template directory without it: "access to helper file denied", after which the
// template fails to compile and the run reports no templates rather than no findings.
func ComposeNucleiDast(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("nuclei-dast")
	var warnings []string

	if strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"])) == "" {
		return nil, []string{"No listening webhook URL is configured, so the payloads would point at " +
			"nothing and a silent result would mean nothing. Use Configure Webhook."}
	}

	args := []string{
		"-dast",
		"-lfa", // the payload list is a file outside the default template directory
		"-im", "jsonl",
		"-l", reportPath + ".in.jsonl",
		"-t", reportPath + ".tpl/",
	}

	args = append(args, composeVectorSettings(tool, settings, "",
		map[string]bool{"templates": true, "extraTemplates": true}, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args, "-jsonl", "-o", reportPath, "-no-color")
	return args, warnings
}

// NucleiPayloadTemplate is the fuzzing template the scanner runs.
//
// Ours rather than upstream's, and that is a deliberate trade. The upstream DAST templates carry
// their own payloads and cannot be pointed at a webhook, so using them would mean the operator's
// callback URL was never sent. This one is thirty lines, it declares every part nuclei will honour,
// and its matchers cover the SSRF that answers in the response, so a target that returns
// /etc/passwd is caught without any callback at all.
const NucleiPayloadTemplate = `id: framework-redirect-ssrf
info:
  name: Framework open redirect and SSRF sweep
  author: ars0n-framework
  severity: high
  description: |
    Fires the payload list built by REcollapse from the operator's webhook, plus the framework's own
    structural bypass forms, at every fuzzable part of the request. Callbacks are confirmed against
    the webhook afterwards; the matchers below catch the cases that answer in the response instead.
  tags: ssrf,redirect,dast
http:
  - pre-condition:
      - type: dsl
        dsl:
          - "true"
    payloads:
      payload: payloads.txt
    fuzzing:
      - parts: [query, body, header, cookie]
        mode: single
        fuzz:
          - "{{payload}}"
    stop-at-first-match: false
    matchers-condition: or
    matchers:
      - type: regex
        part: body
        name: local-file-read
        regex:
          - 'root:.*?:[0-9]*:[0-9]*:'
          - 'for 16-bit app support'
      - type: regex
        part: body
        name: cloud-metadata
        regex:
          - 'ami-id[\s\S]+placement/'
          - 'instance-id[\s\S]+local-hostname'
          - 'computeMetadata[\s\S]+project-id'
      - type: regex
        part: body
        name: internal-service
        regex:
          - 'SSH-(\d.\d)-OpenSSH'
          - '(DENIED Redis|NOAUTH Authentication|redis_version)'
      - type: word
        part: header
        name: open-redirect
        condition: and
        words:
          - "location: http"
          - "__WEBHOOK_HOST__"
        case-insensitive: true
`

// nucleiWebhookHostPlaceholder is substituted per vector by NucleiPayloadTemplateFor.
const nucleiWebhookHostPlaceholder = "__WEBHOOK_HOST__"

// NucleiPayloadTemplateFor renders the template for ONE vector, pinning the open-redirect matcher to
// the operator's own webhook host.
//
// The matcher used to be the single word "Location: http", which tests that the response redirects
// somewhere, not that the PAYLOAD decided where. Every ordinary absolute redirect matched it, so a
// 53 vector run produced 42 high severity findings with an empty parameter, an empty URL and an
// empty payload: one per vector that happened to redirect at all. That is worse than finding
// nothing, because a real open redirect would have been indistinguishable from the other 41.
//
// Requiring the host we control means a match says the target sent the user somewhere we chose,
// which is what the finding claims.
//
// With no webhook configured the matcher is REMOVED rather than left matching everything. This tool
// is gated on the webhook being set so that should be unreachable, but "unreachable" and "produces
// 42 false highs if reached" is a bad pairing.
func NucleiPayloadTemplateFor(v VectorInput) string {
	host := webhookHost(stringifySetting(v.Section["listeningWebhookURL"]))
	if host == "" {
		return removeOpenRedirectMatcher(NucleiPayloadTemplate)
	}
	return strings.ReplaceAll(NucleiPayloadTemplate, nucleiWebhookHostPlaceholder, host)
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

func removeOpenRedirectMatcher(template string) string {
	idx := strings.Index(template, "        name: open-redirect")
	if idx < 0 {
		return template
	}
	// Trim back to the start of that matcher's list item, so the YAML stays valid.
	idx = strings.LastIndex(template[:idx], "      - type: word")
	if idx < 0 {
		return template
	}
	return template[:idx]
}

// BuildVectorPayloadList renders the payload file for ONE vector.
//
// The token is substituted here, which is the whole attribution mechanism: every payload this vector
// sends carries a marker unique to it, so a hit on the webhook names the vector rather than the
// target in general.
func BuildVectorPayloadList(v VectorInput, mutations string) string {
	webhook := strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"]))
	tokenised := strings.ReplaceAll(mutations, vectorTokenPlaceholder, v.Token)

	seen := map[string]bool{}
	var out []string
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		out = append(out, line)
	}

	for _, line := range strings.Split(tokenised, "\n") {
		add(line)
	}
	// The framework's own structural forms, on top of whatever REcollapse produced. REcollapse
	// mutates bytes; these are shapes, and they are the ones that get past an allowlist.
	tokenWebhook := strings.TrimRight(webhook, "/") + "/" + v.Token
	for _, payload := range FrameworkSSRFPayloads(tokenWebhook, v.Domain) {
		add(payload)
	}
	return strings.Join(out, "\n") + "\n"
}

// ComposeSSRFmap builds the SSRFmap argv.
func ComposeSSRFmap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("ssrfmap")
	var warnings []string

	param := firstParam(v)
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
