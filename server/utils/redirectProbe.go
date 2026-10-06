package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sending the payloads REcollapse built.
//
// REcollapse has no network code: it prints mutations of a URL and stops. Until this file existed,
// nuclei fired them from a template this project wrote and maintained, which meant the section's own
// scanner was a YAML file wedged into somebody else's fuzzing engine. Two things went wrong with
// that and both were measured:
//
//   - the template's open redirect matcher was the bare word "Location: http", which tests that the
//     response redirects SOMEWHERE rather than that the payload chose where. A 53 vector run produced
//     42 high severity findings, one per vector that happened to redirect at all.
//   - nuclei reports a finding against the template id, so every hit carried the same id, the same
//     name and the same hardcoded severity. A /etc/passwd read and an open redirect were the same row.
//
// Sending the requests here fixes both by construction: the framework knows which payload it put
// where, so a finding names the parameter, the payload and the signal that fired. nuclei goes back
// to running stock upstream templates, which is what it is good at.
//
// THE CANARY IS THE POINT. Every payload carries a token unique to one parameter of one vector in
// one scan, so a callback on the webhook says "the TrackingId cookie on /catalog called out", not
// "something on this host called out". Without it an out-of-band hit names the target and nothing
// else, which is a rumour rather than a finding.

// ssrfProbeTimeout bounds one request. Short on purpose: a payload pointing at an unroutable
// internal address is SUPPOSED to hang, and a scan of several thousand payloads cannot afford the
// default per-request patience.
const ssrfProbeTimeout = 12 * time.Second

// ssrfProbeDefaultDelayMs paces the send. Every payload is one small request, so an unpaced loop is
// the fastest way to look like a denial of service to a target that was willing to be scanned.
const ssrfProbeDefaultDelayMs = 100

// ssrfProbeDefaultLimit caps how many REcollapse MUTATIONS are sent at one parameter.
//
// REcollapse emits tens of thousands from a single seed, and its own option text says sending all of
// them at one parameter is a denial of service rather than a test. The framework's structural forms
// are NOT counted against this limit: there are a couple of dozen of them, they are the ones that
// actually get past an allowlist, and dropping them to make room for byte mutations would trade the
// useful half for the noisy one.
const ssrfProbeDefaultLimit = 250

// ssrfSignal is an in-band proof: something in the response that only a server-side fetch explains.
type ssrfSignal struct {
	name string
	why  string
	re   *regexp.Regexp
}

// ssrfBodySignals are the responses that prove an SSRF WITHOUT any callback.
//
// A target that hands back the content it fetched has proved itself, and these are worth keeping
// separate from the out-of-band half: they are confirmable from the stored response bytes alone,
// where a webhook hit depends on a third-party service still holding the record.
var ssrfBodySignals = []ssrfSignal{
	{
		name: "local-file-read",
		why:  "the response carried the contents of a local file, so the server fetched a file:// URL it was given",
		// [0-9]+ rather than [0-9]*, and the uid/gid pair anchored to a real passwd line shape. With *
		// the digit groups may be EMPTY, so "root:admin::" anywhere in an ordinary page matches and the
		// framework reports a high severity server-side file read on a page that merely mentions root.
		// A signal this expensive to be wrong about has to be spelt strictly.
		re: regexp.MustCompile(`root:[^:\n]*:[0-9]+:[0-9]+:[^:\n]*:|\[fonts\]\s*\r?\n|for 16-bit app support`),
	},
	{
		name: "cloud-metadata",
		why:  "the response carried a cloud instance metadata document, which is only reachable from inside the instance",
		re:   regexp.MustCompile(`ami-id[\s\S]{0,200}placement/|instance-id[\s\S]{0,200}local-hostname|computeMetadata[\s\S]{0,200}project-id|"AccessKeyId"\s*:|"azEnvironment"\s*:`),
	},
	{
		name: "internal-service",
		why:  "the response carried the banner of a service that does not speak HTTP, so the server connected to an internal port",
		re:   regexp.MustCompile(`SSH-\d\.\d-OpenSSH|-ERR wrong number of arguments|NOAUTH Authentication required|redis_version:|MariaDB server version|mysql_native_password`),
	},
}

// ssrfProbeParams picks the parameters worth putting a payload in, and says why when there are none.
//
// The tiers come from paramMarkTier, which is the same ranking every other section uses. Tier 0 is
// an ordinary application input. Tier 1 is a credential: a session cookie, a CSRF token, an
// Authorization header. Tier 2 is an edge value like an AWS load balancer cookie that no application
// code ever reads.
//
// ONLY TIER 0 IS PROBED, and that is a deliberate difference from the tools that mark a single
// parameter. Those pick the best available and test it whatever it is, because testing one parameter
// badly beats testing none. This scan sends thousands of requests in sequence and every later one
// depends on the session surviving, so overwriting the session cookie with a URL does not test the
// session cookie, it ends the scan. A vector whose every parameter is a credential or an edge value
// is reported skipped with that reason rather than scanned into uselessness.
func ssrfProbeParams(v VectorInput) ([]string, string) {
	// A path vector names no parameter: the payload IS a path segment.
	if v.InsertionPoint == "path" {
		return []string{""}, ""
	}

	var probe []string
	var credential, edge []string
	for _, name := range v.Parameters {
		switch paramMarkTier(name) {
		case 0:
			probe = append(probe, name)
		case 1:
			credential = append(credential, name)
		default:
			edge = append(edge, name)
		}
	}
	if len(probe) > 0 {
		return orderURLShapedFirst(probe), ""
	}

	switch {
	case len(credential) > 0 && len(edge) > 0:
		return nil, "Every parameter on this vector is either a credential (" +
			strings.Join(credential, ", ") + ") or an edge value (" + strings.Join(edge, ", ") +
			"). Overwriting a credential with a URL would end the scan rather than test it, and an " +
			"edge value is read by the load balancer and never by the application."
	case len(credential) > 0:
		return nil, "Every parameter on this vector is a credential (" + strings.Join(credential, ", ") +
			"). Overwriting one with a URL logs the scan out, and every request after it measures the " +
			"login wall instead of the application."
	case len(edge) > 0:
		return nil, "Every parameter on this vector is an edge value (" + strings.Join(edge, ", ") +
			"), set and read by the load balancer or CDN. No application code sees it, so a finding is " +
			"impossible while the cost to the run is certain."
	default:
		return nil, "This vector names no parameter to put a payload in."
	}
}

// urlShapedParamNames are the tier-0 parameter names whose VALUE is habitually a whole URL, a host,
// or a path the server then fetches or redirects to. They are where an SSRF or an open redirect
// actually lives, so a scan that legitimately runs for hours or days should put a payload in them
// FIRST and surface a lead early rather than after working through every ordinary input. This is an
// ORDER-ONLY change: every tier-0 parameter is still probed, and the refusal rules are untouched.
//
// Matched as whole lowercased names, NOT substrings, so "username" is not treated as "u" and a long
// opaque field is not promoted just because it contains "url". The set is the one the audit named.
var urlShapedParamNames = map[string]bool{
	"url": true, "uri": true, "link": true, "redirect": true, "redirect_uri": true,
	"callback": true, "webhook": true, "logo": true, "image": true, "image_url": true,
	"img": true, "src": true, "href": true, "avatar": true, "screenshot": true,
	"screenshots": true, "feed": true, "target": true, "host": true, "proxy": true,
	"fetch": true, "remote": true, "domain": true, "site": true, "endpoint": true,
	"upstream": true, "origin": true, "import": true, "next": true, "dest": true,
	"return": true, "forward": true, "goto": true, "continue": true, "cdn": true, "u": true,
}

// orderURLShapedFirst moves the url-shaped parameters to the front of the probe list, keeping the
// relative order WITHIN each group so the result is deterministic.
//
// Determinism is the load-bearing property, not tidiness. collectWebhookFindings rebuilds this exact
// list by calling ssrfProbeParams again and pairs canary index N with parameter N; if this function
// ordered the two parameters of one vector differently on two calls, a callback would be attributed
// to the wrong parameter. A stable partition over the same input is identical on every call. It also
// never changes the SET of params returned, so ssrfProbeParams's refusal logic is unaffected.
func orderURLShapedFirst(params []string) []string {
	if len(params) < 2 {
		return params
	}
	front := make([]string, 0, len(params))
	rest := make([]string, 0, len(params))
	for _, name := range params {
		if urlShapedParamNames[strings.ToLower(strings.TrimSpace(name))] {
			front = append(front, name)
		} else {
			rest = append(rest, name)
		}
	}
	if len(front) == 0 {
		return params
	}
	return append(front, rest...)
}

// ssrfProbeClient is the sender.
//
// REDIRECTS ARE NOT FOLLOWED, and that is the single most important line in this file. The open
// redirect half of this section is decided by reading the Location header of the 30x itself;
// following it replaces that response with whatever the webhook returns, and the finding disappears.
// AND THE 30x MUST SURVIVE THE CLIENT, which is a separate problem from not following it.
// net/http parses the Location header before it consults CheckRedirect, so a Location that
// url.Parse rejects made Client.Do return an error and throw the response away: measured, seven
// of twelve REcollapse-shaped payloads never reached the detector, and the discarded 302 was
// counted as out.Failed++ next to ordinary timeouts. The payloads most likely to work were the
// ones most likely to be discarded. NoFollowClient goes through the transport directly, so there
// is no Location parse to fail and no way for a caller to fall back into the broken path.
func ssrfProbeClient() *NoFollowClient {
	return NewNoFollowClient(&http.Client{
		Timeout: ssrfProbeTimeout,
		Transport: &http.Transport{
			// Scanning targets routinely present an expired, self-signed or hostname-mismatched
			// certificate, and refusing those turns every request into a transport error that reads
			// exactly like "the target is not vulnerable".
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 4,
		},
	})
}

// buildSSRFProbe renders one request: this vector, this parameter, this payload.
//
// Every parameter the vector names KEEPS its observed value except the one under test. A request
// that drops the others is a different request, and an application that needs ?action=view to reach
// the code at all answers the stripped version from a branch nothing interesting lives in.
func buildSSRFProbe(ctx context.Context, v VectorInput, param, payload string,
	creds cmdiCredentials) (*http.Request, error) {

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method == "" {
		method = "GET"
	}

	target := v.TargetURL()
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	contentType := ""

	switch v.InsertionPoint {
	case "query":
		// BUILT BY HAND, not through url.Values.Encode.
		//
		// REcollapse's whole purpose is byte-level mutation, and its default output encoding is
		// already URL-encoded: it emits %00, %0a, %ff and the double-encoded forms deliberately.
		// Encode() would percent-encode those a second time, so %00 goes on the wire as %2500 and the
		// target sees a literal percent-two-five rather than the null byte the mutation was testing.
		// Every mutation that exists to defeat a normalisation quirk would be neutralised in transit,
		// which is the one thing this tool must not do.
		//
		// The other parameters ARE encoded, because those are ordinary observed values.
		var pairs []string
		for _, name := range v.Parameters {
			if name == param {
				continue
			}
			pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(v.valueFor(name)))
		}
		pairs = append(pairs, url.QueryEscape(param)+"="+payload)
		parsed.RawQuery = strings.Join(pairs, "&")

	case "path":
		// A path payload is only meaningful where the segment IS a URL, which is the proxy-style
		// endpoint this reaches. Built textually rather than through url.URL, because setting Path
		// percent-encodes the scheme separator and turns http://host into http:%2F%2Fhost, which the
		// application then never recognises as a URL at all.
		base := strings.TrimRight(parsed.EscapedPath(), "/")
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			base = base[:idx]
		}
		rebuilt := parsed.Scheme + "://" + parsed.Host + base + "/" + payload
		if parsed.RawQuery != "" {
			rebuilt += "?" + parsed.RawQuery
		}
		if parsed, err = url.Parse(rebuilt); err != nil {
			return nil, err
		}

	case "body":
		contentType = v.ContentType
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
		// A multipart body is REBUILT as urlencoded below, because this probe does not construct
		// multipart parts. Sending urlencoded bytes under the recorded multipart/form-data header
		// makes the server reject the request while parsing the boundary, so every payload comes back
		// as the same parse error and the vector reads as not injectable. Declare what is actually
		// on the wire instead.
		if strings.Contains(strings.ToLower(contentType), "multipart/") {
			contentType = "application/x-www-form-urlencoded"
		}
		if strings.Contains(strings.ToLower(contentType), "json") {
			fields := make([]string, 0, len(v.Parameters))
			for _, name := range v.Parameters {
				value := v.valueFor(name)
				if name == param {
					value = payload
				}
				fields = append(fields, strconv.Quote(name)+":"+strconv.Quote(value))
			}
			body = strings.NewReader("{" + strings.Join(fields, ",") + "}")
		} else {
			// Same reasoning as the query string: the payload goes on the wire as REcollapse wrote it.
			var pairs []string
			for _, name := range v.Parameters {
				if name == param {
					continue
				}
				pairs = append(pairs, url.QueryEscape(name)+"="+url.QueryEscape(v.valueFor(name)))
			}
			pairs = append(pairs, url.QueryEscape(param)+"="+payload)
			body = strings.NewReader(strings.Join(pairs, "&"))
		}
		if method == "GET" {
			// A body vector recorded without a verb is a POST. Sending the body on a GET is a request
			// most servers answer from a branch that never reads it.
			method = "POST"
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
		"(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

	// The credentials the framework holds, so the scan tests the authenticated surface rather than
	// the login wall. Layered by cmdiCredentialsFor, which is shared with the injection sections
	// despite its name.
	for _, line := range creds.Headers {
		if name, value, ok := strings.Cut(line, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	if len(creds.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(creds.Cookies, "; "))
	}

	// The payload goes in LAST for a header or cookie vector, so it overwrites whatever the
	// credential layer just set under the same name rather than being overwritten by it.
	switch v.InsertionPoint {
	case "header":
		req.Header.Set(param, payload)
	case "cookie":
		// The jar is rebuilt rather than appended to: a Cookie header carrying the same name twice
		// leaves which one the application reads up to the server, and a scan whose payload may or may
		// not be the value under test is a scan whose clean result means nothing.
		merged := []string{}
		seen := map[string]bool{}
		keep := func(pair string) {
			name, _, ok := strings.Cut(pair, "=")
			key := strings.ToLower(strings.TrimSpace(name))
			if !ok || key == "" || key == strings.ToLower(param) || seen[key] {
				return
			}
			seen[key] = true
			merged = append(merged, pair)
		}
		for _, pair := range creds.Cookies {
			keep(pair)
		}
		// The vector's other cookies at their observed values, so the request is the one the
		// application answered rather than a stripped version of it.
		for _, name := range v.Parameters {
			if !strings.EqualFold(name, param) {
				keep(name + "=" + v.valueFor(name))
			}
		}
		merged = append(merged, param+"="+payload)
		req.Header.Set("Cookie", strings.Join(merged, "; "))
	}

	return req, nil
}

// ssrfProbeOutcome is what one sent payload produced.
type ssrfProbeOutcome struct {
	Signal   string
	Why      string
	Status   int
	Location string
	// Snippet is the matched region with a little context, for the one-line evidence column.
	Snippet string
	// Response is the WHOLE response, status line, headers and body, as it came back. An SSRF is
	// proved by what the server-side fetch returned, and the thing that proves it is routinely far
	// outside a 120 character window: cloud metadata credentials, an /etc/passwd, an internal
	// admin page. The snippet says where to look; this is what gets written up.
	Response string
}

// inspectSSRFResponse decides whether one response proves anything.
//
// Two independent proofs, and they are graded differently on purpose. An open redirect is proved by
// the Location header naming the host WE chose; anything else redirecting anywhere is the ordinary
// behaviour of a web application. A response SSRF is proved by content that only a server-side fetch
// explains.
func inspectSSRFResponse(resp *http.Response, body, webhookHost string) *ssrfProbeOutcome {
	location := resp.Header.Get("Location")
	whole := rawResponseText(resp, body)

	if webhookHost != "" && location != "" {
		if host := redirectTargetHost(location); host != "" && strings.EqualFold(host, webhookHost) {
			return &ssrfProbeOutcome{
				Signal: "open-redirect",
				Why: "the response redirected to the host supplied in the payload, so the target sends " +
					"a user wherever the parameter says",
				Status:   resp.StatusCode,
				Location: location,
				Response: whole,
			}
		}
	}

	for _, signal := range ssrfBodySignals {
		if signal.re.MatchString(body) {
			return &ssrfProbeOutcome{
				Signal:   signal.name,
				Why:      signal.why,
				Status:   resp.StatusCode,
				Location: location,
				Snippet:  ssrfSnippet(body, signal.re),
				Response: whole,
			}
		}
	}
	return nil
}

// redirectTrimBytes are the bytes a browser strips from both ENDS of a URL before parsing it:
// the C0 controls and the space. A Location padded with them is the same Location.
const redirectTrimBytes = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\v\f\r" +
	"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f "

// redirectRemoveBytes are the bytes a browser removes from ANYWHERE in a URL, not just the ends.
//
// WHATWG basic URL parser, step 2: "Remove all ASCII tab or newline from input", where ASCII tab
// or newline is U+0009, U+000A and U+000D. It runs over the whole string. So
// https://evil.exa<TAB>mple/tok navigates to evil.example in every browser, and reading the host
// as "evil.exa\tmple" reports a working redirect as clean.
//
// The set is exactly those three. \v and \f are C0 controls, so they are trimmed at the ends
// above, but they are NOT removed from the middle by any browser and a host containing one does
// not resolve. Widening this set past the three would start manufacturing findings.
//
// WHAT WAS ACTUALLY MEASURED, over a raw listener writing the response byte for byte, read back
// through the framework's own client:
//
//	tab in the host        Location arrives intact as "https://evil.exa\tmple/tok".
//	                       THIS IS THE ONE THAT WAS READING CLEAN AND IS NOW REPORTED.
//	CRLF fold in the host  net/textproto joins the continuation with a SPACE, so the header
//	                       arrives as "https://evil.exa mple/tok". A space is a forbidden host
//	                       code point, so no browser resolves it and NOT matching is correct.
//	bare CR or bare LF     the response never comes back at all: "malformed MIME header: missing
//	                       colon". Unreachable over HTTP/1.1 through net/http.
//
// So over this transport the fix moves exactly the tab case. \n and \r are in the set because
// they are WHATWG's and because a Location also reaches this function from places that are not
// an HTTP/1.1 response header, not because either was observed on the wire here.
const redirectRemoveBytes = "\t\n\r"

// redirectTargetHost reads the host out of a Location header, the way a browser reads it.
//
// A RELATIVE Location has no host and is never a finding: /login is the application deciding where
// its own user goes. Returning empty for it is what stops every ordinary post-then-redirect from
// being reported.
//
// IT DOES NOT GO THROUGH url.Parse, AND THAT IS THE POINT. url.Parse implements RFC 3986; a
// browser implements the WHATWG URL Standard, and the gap between them is exactly where the
// open-redirect payloads live. Two consequences, both measured against the shipped payload list:
//
//   - A Location url.Parse REJECTS used to yield no host at all, so "Go cannot parse this" was
//     being recorded as "the target is not vulnerable". //webhook.example%00/p is a host.
//   - For a special scheme the WHATWG parser treats a backslash as a slash and ignores any number
//     of leading slashes, so http:/host, http:\host, \/\/host and /\/host all navigate to
//     host. FrameworkSSRFPayloads emits four of those forms deliberately, and url.Parse returned
//     an empty Hostname for every one of them: four shipped payloads that could never report a
//     finding no matter how cleanly the target echoed them.
//
// Tolerant is not credulous. The host still has to match the webhook host exactly for a finding,
// so accepting more shapes here widens what can be PROVEN, not what can be claimed.
func redirectTargetHost(location string) string {
	// Leading and trailing C0 controls and spaces are stripped by every browser before parsing,
	// and TAB, LF and CR are then removed from ANYWHERE in what is left. Both steps are WHATWG's,
	// in that order, and the second one is the one that matters: a tab in the middle of the host
	// is the oldest filter bypass there is, and trimming only the ends reports it clean.
	//
	// The trim runs first and only once. redirectTrimBytes is a SUPERSET of redirectRemoveBytes,
	// so after the trim neither end can be a tab, an LF or a CR, and removing the interior ones
	// cannot expose a new trimmable byte at either end. A second trim would be a no-op.
	rest := strings.Trim(location, redirectTrimBytes)
	if strings.ContainsAny(rest, redirectRemoveBytes) {
		rest = strings.Map(func(r rune) rune {
			if strings.ContainsRune(redirectRemoveBytes, r) {
				return -1
			}
			return r
		}, rest)
	}
	if rest == "" {
		return ""
	}

	if i := strings.IndexByte(rest, ':'); i > 0 && redirectIsSchemeToken(rest[:i]) {
		switch strings.ToLower(rest[:i]) {
		case "http", "https":
		default:
			// mailto:, javascript:, data:, file: and the rest are not navigations to a host, and
			// reporting one as an open redirect to that "host" would be a fabricated finding.
			return ""
		}
		rest = rest[i+1:]
		for len(rest) > 0 && (rest[0] == '/' || rest[0] == '\\') {
			rest = rest[1:]
		}
	} else {
		// No scheme. TWO leading slashes (or backslashes, or a mix) is a network-path reference and
		// leaves the site; one is a path on this site and is not a finding.
		n := 0
		for n < len(rest) && (rest[n] == '/' || rest[n] == '\\') {
			n++
		}
		if n < 2 {
			return ""
		}
		rest = rest[n:]
	}

	if j := strings.IndexAny(rest, "/\\?#"); j >= 0 {
		rest = rest[:j]
	}
	// Userinfo. The host is what follows the LAST @, which is the whole point of the
	// http://allowed.example@webhook.example payload: a validator reading the first token and a
	// browser reading the last token disagree about where the user is going.
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.HasPrefix(rest, "[") {
		if k := strings.IndexByte(rest, ']'); k >= 0 {
			rest = rest[:k+1]
		}
	} else if k := strings.LastIndexByte(rest, ':'); k >= 0 && redirectAllDigits(rest[k+1:]) {
		rest = rest[:k]
	}
	return strings.ToLower(rest)
}

// redirectIsSchemeToken reports whether s is a URL scheme per RFC 3986: ALPHA *( ALPHA / DIGIT /
// "+" / "-" / "." ). It is what keeps the colon in //host:8443/p from being read as a scheme.
func redirectIsSchemeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// redirectAllDigits reports whether s is a non-empty run of digits, which is what makes a trailing
// :NNNN a port rather than part of the host.
func redirectAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// rawResponseText renders the response as it came off the wire: status line, headers, blank line,
// body. Stored whole on the finding, because an SSRF proof is the CONTENT the target fetched on our
// behalf, and no amount of summarising it substitutes for the bytes in a report.
func rawResponseText(resp *http.Response, body string) string {
	var b strings.Builder
	b.WriteString(resp.Proto + " " + resp.Status + "\n")
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range resp.Header[name] {
			b.WriteString(name + ": " + value + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(body)
	return b.String()
}

// ssrfSnippet returns the matched region with a little context, for the finding's evidence.
func ssrfSnippet(body string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	start, end := loc[0]-60, loc[1]+60
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// ProbeSSRFVector sends every payload at every probeable parameter of ONE vector.
//
// Returns the in-band findings only. The out-of-band half is collected once at the end of the scan
// by collectWebhookFindings, because a callback can arrive seconds after the response and polling
// the webhook per vector would be both slow and wrong.
//
// The payload list arrives already tokenised for the VECTOR; this function re-tokenises per
// PARAMETER, so a webhook hit names the parameter rather than the vector. That matters on a cookie
// vector carrying five names: without it a callback says one of five things called out.
// ssrfProbeResult is what one vector's probe produced, including the things that are NOT findings.
//
// Sent, failed and refused exist because "no findings" is not a result on its own. A vector where
// every request failed at the transport layer and a vector that was genuinely tested both return
// zero findings, and only one of them is evidence of anything.
type ssrfProbeResult struct {
	Findings []VectorFinding
	Warnings []string
	Sent     int
	Failed   int
	// Untested is non-empty when the run did not finish: the deadline fired, the scan was cancelled,
	// or the target stopped answering. It becomes an ERROR at the call site, so the vector is
	// recorded UNTESTED rather than clean.
	Untested string
}

func ProbeSSRFVector(ctx context.Context, v VectorInput, mutations []string,
	settings map[string]any) ssrfProbeResult {

	out := ssrfProbeResult{}

	params, refusal := ssrfProbeParams(v)
	if len(params) == 0 {
		// NOT a clean result. Nothing was sent, so the caller marks the vector untested with this
		// reason rather than letting it read as "probed and found nothing".
		out.Untested = refusal
		return out
	}

	webhook := strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"]))
	host := webhookHost(webhook)
	if host == "" {
		out.Untested = "The Listening Webhook URL is not a URL with a host in it, so the open redirect " +
			"check has nothing to compare a Location header against and no payload can be attributed. " +
			"Fix it on the Webhook tab; this vector was NOT tested."
		return out
	}

	limit := ssrfProbeDefaultLimit
	if n, err := strconv.Atoi(strings.TrimSpace(stringifySetting(settings["replayLimit"]))); err == nil && n > 0 {
		limit = n
	}
	delay := time.Duration(ssrfProbeDefaultDelayMs) * time.Millisecond
	if n, err := strconv.Atoi(strings.TrimSpace(stringifySetting(settings["probeDelayMs"]))); err == nil && n >= 0 {
		delay = time.Duration(n) * time.Millisecond
	}

	if len(mutations) > limit {
		out.Warnings = append(out.Warnings, "REcollapse produced "+itoa(len(mutations))+" mutations and "+
			"the replay limit is "+itoa(limit)+", so the rest were not sent. Raise Maximum mutations to "+
			"send to cover more, remembering the cost is multiplied by every parameter of every vector.")
		mutations = mutations[:limit]
	}

	client := ssrfProbeClient()
	creds := cmdiCredentialsFor(v, settings, headerNameFor(v))

	for index, param := range params {
		// ALWAYS narrowed, including for a path vector whose parameter name is empty. Using the bare
		// vector token there would make it a strict prefix of every parameter token of the same
		// vector, and the collector matches by substring, so the two could not be told apart.
		//
		// The index must be the position in THIS slice, and the collector must walk the same slice
		// from the same function, or the two disagree about which canary belongs to which parameter.
		token := paramToken(v.Token, index)

		payloads := append([]string{}, FrameworkSSRFPayloads(
			strings.TrimRight(webhook, "/")+"/"+token, v.Domain)...)
		for _, mutation := range mutations {
			payloads = append(payloads, strings.ReplaceAll(mutation, vectorTokenPlaceholder, token))
		}

		// ONE PROOF PER SIGNAL, not one per parameter.
		//
		// Stopping at the first hit was wrong in a way that hid findings rather than duplicating them:
		// the framework's structural forms are sent first and the open-redirect forms come before
		// file:///etc/passwd and the cloud metadata addresses, so a parameter that redirects would
		// report the redirect and never be asked whether the SERVER fetches anything. An open redirect
		// is a medium and a server-side file read is a high, and the medium was masking the high.
		proved := map[string]bool{}

		for _, payload := range payloads {
			if ctx.Err() != nil {
				out.Untested = "The probe stopped after " + itoa(out.Sent) + " requests (" +
					ctx.Err().Error() + "), so the remaining payloads on this vector are UNKNOWN, not clean."
				return out
			}
			if len(proved) == len(ssrfBodySignals)+1 {
				break // every signal this probe can recognise has already been proved here
			}

			req, err := buildSSRFProbe(ctx, v, param, payload, creds)
			if err != nil {
				out.Failed++
				continue
			}
			resp, err := client.Do(req)
			out.Sent++
			if err != nil {
				// Counted, not ignored. Payloads aimed at unroutable addresses time out by design, so a
				// few failures are ordinary; ALL of them failing means the target was never reached and
				// the zero findings mean nothing.
				out.Failed++
				time.Sleep(delay)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
			resp.Body.Close()

			if outcome := inspectSSRFResponse(resp, string(body), host); outcome != nil && !proved[outcome.Signal] {
				proved[outcome.Signal] = true
				out.Findings = append(out.Findings, ssrfFindingFrom(v, param, payload, req, outcome))
			}
			time.Sleep(delay)
		}
	}

	// EVERY REQUEST FAILED. This is the shape that reads exactly like a clean scan and is not one:
	// the host was down, the network was blocked, or the target started refusing the scanner.
	if out.Sent > 0 && out.Failed == out.Sent {
		out.Untested = "All " + itoa(out.Sent) + " requests failed at the transport layer, so this " +
			"vector was never actually tested. The target may be down, blocking the scanner, or " +
			"unreachable from this container."
	}
	return out
}

// headerNameFor is the header a header vector injects into, which the credential layer must not
// also set. Empty for every other insertion point.
func headerNameFor(v VectorInput) string {
	if v.InsertionPoint != "header" {
		return ""
	}
	return markableParam(v)
}

// paramToken narrows a vector token to one parameter, BY INDEX.
//
// An index rather than a hash of the name, because a hash can collide and an index cannot. The first
// version hashed the name into 100,000 buckets, which sounds ample until you notice the collision
// that matters is between two parameters of the SAME vector: both would then carry the same canary,
// and a callback could not say which of them called out. That is the one thing this token exists to
// answer.
//
// The name is not in the token at all, deliberately: a header called X-Forwarded-For would put
// punctuation in it, and a cookie value cannot carry a semicolon.
//
// FIXED WIDTH, and that is not cosmetic either. CheckWebhookResults decides a callback arrived by
// substring-searching the inbox body for each token, so a token that is a PREFIX of another is
// indistinguishable from it. Equal length plus different content means neither can contain the
// other.
func paramToken(vectorToken string, index int) string {
	return vectorToken + "p" + fmt.Sprintf("%03d", index)
}

// ssrfFindingFrom records one proof.
//
// Severity is decided by WHAT WAS PROVED rather than read off a template. An open redirect is a
// medium: it is real, and its impact is phishing and token theft through a trusted domain. A server
// side fetch that hands back a local file or a cloud metadata document is a high, because it reaches
// things the internet is not supposed to.
func ssrfFindingFrom(v VectorInput, param, payload string, req *http.Request,
	outcome *ssrfProbeOutcome) VectorFinding {

	severity := "high"
	kind := "ssrf"
	if outcome.Signal == "open-redirect" {
		severity, kind = "medium", "open-redirect"
	}

	evidence := "Sent " + payload + " in the " + v.InsertionPoint
	if param != "" {
		evidence += " parameter " + param
	}
	evidence += ", and " + outcome.Why + ". The response was " + itoa(outcome.Status)
	if outcome.Location != "" {
		evidence += " to " + outcome.Location
	}
	if outcome.Snippet != "" {
		evidence += ". Matched: " + outcome.Snippet
	}

	return VectorFinding{
		VectorID:        v.VectorID,
		Tool:            "recollapse",
		Kind:            kind,
		Severity:        severity,
		Confidence:      "confirmed in band: " + outcome.Why + ", read from the response itself rather than from a callback",
		InsertionPoint:  v.InsertionPoint,
		Param:           param,
		Payload:         payload,
		Method:          req.Method,
		URL:             req.URL.String(),
		Evidence:        evidence,
		DetectionMethod: "framework SSRF probe (" + outcome.Signal + ")",
		InjectType:      outcome.Signal,
		RawResponse:     outcome.Response,
	}
}
