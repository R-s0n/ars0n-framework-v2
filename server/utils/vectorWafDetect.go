package utils

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Reading, from the FRAMEWORK'S OWN control request, that the target's edge refused this tool's
// payload CLASS before it ever reached the application.
//
// This is the sibling of vectorRateLimit.go and it closes the same fail-open from the other side. A
// rate limiter answers a scanner's payloads with 429; a signature WAF answers them with a clean 403
// block page. Either way the payload reflects nothing, so the tool finds nothing, exits 0, and the
// runner records the vector CLEAN. vectorRateLimit.go already catches the 429; this catches the 403.
//
// MEASURED on a live estate, 2026-09-30, during a Dalfox/domdig/xssFuzz accuracy test against a
// Cloudflare-fronted target. A benign GET of a search endpoint returned 200 with the real page; the
// SAME request carrying "><script>alert(1)</script> returned 403 and a ~98KB vendor block page,
// edge-terminated (Server-Timing cfOrigin;dur=0), on EVERY host on the domain and independent of
// User-Agent. Dalfox and xssFuzz sent their payloads into that wall on all of their vectors, found
// nothing, exited 0, and the runner recorded every vector clean. domdig only escaped the same fate
// because it happened to CRASH navigating the heavy page, which the crash guard in vectorScan.go
// already promotes to UNTESTED. The Target Behaviour Probe had already classified this exact target
// as enforcing on one payload class with waf_response_mode=block and warned waf_block_signature
// "unusable - an unstable signature would hide real findings": that warning IS this fail-open, and
// nothing was consuming it.
//
// WHY A DIFFERENTIAL AND NOT A VENDOR STRING. The control is benign-vs-payload on the same URL: the
// only difference on the wire is the payload, so a clean rejection the benign request did not draw
// is the target refusing the payload's CONTENT. That reads a Cloudflare managed rule, an app-layer
// input filter and a home-grown deny list all the same, and it needs to, because in every one of
// those cases the payload did not reach the sink and the tool's zero is UNTESTED, not clean. It
// carries no "cloudflare" or brand literal precisely so it does not rot the first time the target
// changes vendor or wording.
//
// ONLY 403 AND 406, NEVER 400 OR 429. 403/406 are the clean-rejection codes a WAF returns when it
// refuses content, and the probe measures the same pair as waf_response_mode=block. 400 is excluded
// on purpose: a 400 is usually the application parsing the input and rejecting its SHAPE, which
// means the input reached the app, the opposite of a wall. 429 is rate limiting and belongs to
// vectorRateLimit.go, which waits out the window rather than calling the vector untested.
//
// ONCE PER HOST PER RUN. The block is an edge/host property, not a per-vector one (the live measure
// found www and the API host blocking identically), so one benign-vs-payload differential per host
// settles it for every vector on that host. The benign arm is REUSED from the "before" budget
// control that the runner already took, so the whole check costs ONE extra request per host.

// wafCanaryPayload is a class-appropriate attack string whose only job is to trip a signature WAF,
// by tool category. It is never expected to reflect or execute: it is a differential control, not an
// exploit. An empty string means "no canary for this class", and the caller then does not probe, so
// a class the WAF was never tested against can never be miscalled untested.
func wafCanaryPayload(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "xss":
		return `"><script>alert(1)</script>`
	case "sqli":
		return `' OR '1'='1' -- -`
	case "lfi":
		return `../../../../../../etc/passwd`
	case "cmdi":
		return `;cat /etc/passwd`
	case "ssti":
		return `${{7*7}}`
	case "redirect":
		return `https://example.org/`
	default:
		return ""
	}
}

// isWAFRefusal reports whether a status is the clean-rejection kind a content WAF returns. 400 is
// deliberately not here (app-layer shape rejection means the input reached the app) and neither is
// 429 (rate limiting, owned by vectorRateLimit.go).
func isWAFRefusal(status int) bool {
	return status == http.StatusForbidden || status == http.StatusNotAcceptable
}

// WAFClassObservation is one host's benign-vs-payload differential, cached for the run.
type WAFClassObservation struct {
	// Probed is true when the differential actually ran. A false Probed is not cached, so a later
	// vector whose benign control passed can still establish the baseline.
	Probed        bool
	Blocked       bool
	BenignStatus  int
	PayloadStatus int
	Reason        string
}

// buildWAFCanaryURL puts the payload into the FIRST query parameter of rawURL (deterministic by
// sorted key), or appends a probe parameter when the URL has none, so the canary exercises the same
// parameter surface the scanner will and differs from the benign control by the payload alone.
func buildWAFCanaryURL(rawURL, payload string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	q := u.Query()
	if len(q) == 0 {
		u.RawQuery = "waf=" + url.QueryEscape(payload)
		return u.String(), true
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	q.Set(keys[0], payload)
	u.RawQuery = q.Encode()
	return u.String(), true
}

// ProbeVectorWAFClass sends the class payload to rawURL through the run's scoped, paced ScanClient
// and decides, against the benign status the caller already observed, whether the host walls the
// payload class. benignStatus comes from the "before" budget control so no second benign request is
// made here. It returns Probed=false (and the caller does not cache it) whenever the differential
// cannot be established this time: no client, no canary for the class, an unparseable URL, a benign
// arm that was itself refused, or a payload request that did not complete.
func ProbeVectorWAFClass(ctx context.Context, client *ScanClient, auth *ScopedAuthContext,
	category, rawURL, host string, benignStatus int) WAFClassObservation {

	obs := WAFClassObservation{BenignStatus: benignStatus}
	payload := wafCanaryPayload(category)
	if client == nil || payload == "" || strings.TrimSpace(rawURL) == "" {
		return obs
	}
	// The benign arm must have PASSED for the differential to mean anything. If the plain control was
	// itself refused, a refused payload proves nothing (the endpoint refuses everything), so leave it
	// unprobed and let a later vector on the host try.
	if benignStatus <= 0 || isWAFRefusal(benignStatus) {
		return obs
	}
	payloadURL, ok := buildWAFCanaryURL(rawURL, payload)
	if !ok {
		return obs
	}

	var material *ScopedAuthMaterial
	if auth != nil && host != "" {
		material, _ = auth.For(host)
	}
	resp := client.Do(ctx, ScanRequest{
		URL:      payloadURL,
		Method:   http.MethodGet,
		Auth:     material,
		ReadBody: false,
	})
	if resp.Err != nil {
		// The payload request did not complete. Not cached, so the host is retried on the next clean
		// vector rather than being called clean by omission.
		return obs
	}

	obs.Probed = true
	obs.PayloadStatus = resp.Status
	if isWAFRefusal(resp.Status) {
		obs.Blocked = true
		obs.Reason = fmt.Sprintf("UNTESTED (WAF): a benign control of this host returned %d, but the "+
			"same request carrying a %s payload returned %d, a clean content rejection the benign "+
			"request did not draw. The tool's payloads were refused before reaching the application, "+
			"so a zero here is WAF-BLOCKED, not clean. The scanner cannot see this because a block "+
			"page reflects no payload. Retest through a channel the edge does not wall (a real browser "+
			"for a reflected or DOM sink, a payload that evades the ruleset, or an in-scope host that "+
			"is not fronted by the WAF).", benignStatus, category, resp.Status)
	}
	return obs
}
