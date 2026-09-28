package utils

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------
// A RESPONSE THE CLIENT THREW AWAY IS STILL A RESPONSE.
//
// net/http parses the Location header of a 3xx BEFORE it consults CheckRedirect. The relevant
// lines of net/http/client.go, at the top of the redirect loop:
//
//	loc := resp.Header.Get("Location")
//	u, err := req.URL.Parse(loc)
//	if err != nil {
//	        resp.closeBody()
//	        return nil, uerr(fmt.Errorf("failed to parse Location header %q: %v", loc, err))
//	}
//	... only now is c.checkRedirect consulted
//
// So a response whose Location cannot be parsed as a URL makes Client.Do return an ERROR and
// DISCARD the response, even when CheckRedirect is set to http.ErrUseLastResponse. CheckRedirect
// is never called: measured, "CheckRedirect called=FALSE". Transport.RoundTrip returns the same
// 302 intact, which is the proof the response was real and the client threw it away.
//
// AN UNPARSEABLE Location IS EXACTLY WHAT A SUCCESSFUL OPEN-REDIRECT PAYLOAD PRODUCES. Of the
// twelve REcollapse-shaped payloads this framework sends, seven never reached the detector:
// //evil.example%00, http://ev il.example, http://[evil.example, https://evil.example%,
// http://evil.example%zz and the two carrying a raw control byte. Five of those seven are the
// client throwing away a response the transport returned intact, and this fixes them: 10 of 12
// reach the detector now, against 5 of 12 before. The remaining two die in the RESPONSE READER,
// because net/textproto refuses a header line containing NUL or DEL and Transport.RoundTrip
// fails identically; no client-side choice recovers those.
//
// REACHING THE DETECTOR AND BEING REPORTED ARE DIFFERENT NUMBERS, and this one is the first.
// Of the five host-position payloads recovered here, none is reported, and that is correct:
// evil.example%zz fails WHATWG host parsing too, so no browser goes anywhere and a finding would
// be fabricated. The reported count moves on the payloads whose mutation is in the path, query or
// fragment, which is where REcollapse puts most of them.
//
// The payloads most likely to work are the ones most likely to be discarded, which is the worst
// possible correlation, and downstream the discarded response is filed as an ordinary transport
// failure: a scanner that proved an open redirect reports a network problem.
//
// There is no way to keep http.Client.Do and fix this. The parse happens inside an unexported
// loop, before any hook the caller is given, and the response is closed before it returns. The
// only fix is to not enter that loop, which means going through the RoundTripper directly.
//
// NoFollowClient is that. It is a TYPE rather than a helper function on purpose: a helper leaves
// the broken client.Do(req) sitting there compiling, and the whole point is that a caller must
// not be able to opt back into the broken behaviour by accident. NoFollowClient holds its
// *http.Client unexported and offers no way to get it back out, so for these call sites the
// redirect loop is unreachable rather than merely discouraged.
// ---------------------------------------------------------------------------------------------

// NoFollowClient sends one request and returns exactly what came back, redirect or not.
//
// It keeps the Transport, Timeout and Jar of the *http.Client it was built from, so every call
// site's own tuning (TLS verification off for scan targets, compression pinned, per-host idle
// limits, the session jar a replay depends on) is preserved. What it does not keep is the
// redirect loop.
type NoFollowClient struct {
	transport http.RoundTripper
	timeout   time.Duration
	jar       http.CookieJar
}

// NewNoFollowClient adopts a client's configuration. The *http.Client passed in must not be kept
// by the caller: the usual form is to build the literal inline, so no reference to it survives.
//
// CheckRedirect on the adopted client is IGNORED, because it is no longer reachable. That is not
// a silent downgrade of a caller's choice, it is the fix: every adopted client in this codebase
// set it to http.ErrUseLastResponse, and never following is exactly what NoFollowClient does.
func NewNoFollowClient(c *http.Client) *NoFollowClient {
	if c == nil {
		return &NoFollowClient{}
	}
	return &NoFollowClient{transport: c.Transport, timeout: c.Timeout, jar: c.Jar}
}

// Timeout reports the per-request budget, for callers that annotate a result with it.
func (c *NoFollowClient) Timeout() time.Duration { return c.timeout }

// Get is the http.Client.Get shape, for the call sites that used it.
func (c *NoFollowClient) Get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head is the http.Client.Head shape.
func (c *NoFollowClient) Head(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do sends the request through the transport and returns the response.
//
// The pieces of http.Client.Do that matter to these callers are reproduced here and nothing else:
//
//   - Timeout. http.Client.Timeout covers the body read as well as the headers, so it is applied
//     as a context deadline and the cancel is attached to the body's Close rather than fired on
//     return. Firing it on return would kill the body before the caller had read it, which would
//     turn every response into a truncated one: the same disease from the other end.
//   - Jar. Cookies are attached on the way out and stored on the way back, so a session-bearing
//     replay still bears its session. A probe that silently stops sending its cookie measures the
//     login wall and records the application clean.
//   - URL userinfo as an Authorization header. THE TRANSPORT DOES NOT DO THIS; http.Client.send
//     does, at client.go's "if u := req.URL.User; u != nil". Going straight to the RoundTripper
//     without reproducing it drops the credential from every https://user:pass@host/ call site,
//     which is the cookie-jar failure again from the other side: a probe that silently stops
//     authenticating measures the login wall and records the application clean.
//   - The *url.Error wrapping, so an error from this path is the same shape callers already
//     classify, and Timeout() still answers true for a deadline.
//
// Redirects are the piece deliberately not reproduced. The hop itself is the observation.
func (c *NoFollowClient) Do(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("utils: NoFollowClient.Do requires a request with a URL")
	}

	rt := c.transport
	if rt == nil {
		rt = http.DefaultTransport
	}

	if c.jar != nil {
		for _, cookie := range c.jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}

	if u := req.URL.User; u != nil && req.Header.Get("Authorization") == "" {
		// Reproduced from http.Client.send. An explicit Authorization header already on the
		// request always wins, exactly as it does there.
		password, _ := u.Password()
		req = req.Clone(req.Context())
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Authorization", "Basic "+noFollowBasicAuth(u.Username(), password))
	}

	var cancel context.CancelFunc
	if c.timeout > 0 {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(req.Context(), c.timeout)
		req = req.WithContext(ctx)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, &url.Error{Op: noFollowOp(req.Method), URL: noFollowStripPassword(req.URL), Err: err}
	}
	if resp == nil {
		if cancel != nil {
			cancel()
		}
		return nil, &url.Error{
			Op:  noFollowOp(req.Method),
			URL: noFollowStripPassword(req.URL),
			Err: errors.New("the transport returned neither a response nor an error"),
		}
	}

	if c.jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			c.jar.SetCookies(req.URL, cookies)
		}
	}
	if resp.Request == nil {
		resp.Request = req
	}
	if cancel != nil {
		resp.Body = &noFollowBody{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

// noFollowBasicAuth is net/http's unexported basicAuth, which is base64 of "user:pass". The
// result is a credential, so it is never logged, never put in a reason string and never returned
// to a caller that renders one.
func noFollowBasicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// noFollowStripPassword is net/http's unexported stripPassword, reproduced because the errors
// this file builds go straight into log lines and reason strings.
//
// An *url.Error prints its URL. A URL with userinfo carries a LIVE CREDENTIAL, and the call sites
// print the error: endpointInvestigationUtils.go logs "[ERROR] Failed to request %s: %v" and
// investigateUtils.go logs "[WARN] Failed to get HTTP info for %s: %v". Without this, one refused
// connection to a https://user:pass@host/ target writes the password to the server log, and from
// there into anything that quotes the error. The username survives, so the error still says which
// identity failed; the same redaction marker net/http uses is used here so the two paths are
// indistinguishable to anything reading them.
func noFollowStripPassword(u *url.URL) string {
	if u == nil {
		return ""
	}
	if _, set := u.User.Password(); !set {
		return u.String()
	}
	return strings.Replace(u.String(), u.User.String()+"@",
		u.User.Username()+":"+redactedPasswordMarker+"@", 1)
}

func noFollowOp(method string) string {
	if method == "" {
		return "Get"
	}
	return strings.ToUpper(method[:1]) + strings.ToLower(method[1:])
}

// noFollowBody releases the timeout context when the caller is done with the body, which is the
// point at which http.Client would have released it too.
type noFollowBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *noFollowBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// ---------------------------------------------------------------------------------------------
// THE CLIENTS THAT DO FOLLOW
//
// Two call sites genuinely want the chain walked. They are still exposed to the same defect: an
// unparseable Location anywhere in the chain loses the WHOLE page, not just the hop, because
// Client.Do returns an error and no response at all. For those, DoFollowing retries the request
// once without following, so the caller gets the 3xx that broke the chain instead of nothing.
//
// THE RETRY GOES TO THE HOP THAT BROKE, NOT TO THE CALLER'S ORIGINAL URL. Re-sending req.URL
// looks equivalent and is not: on a chain of more than one hop it returns the FIRST 302, whose
// body is empty, and endpointInvestigationUtils.go then computes Title, Forms, APIs, Secrets,
// Misconfigs and AnalyzeEndpoint off that empty body. The row reads "investigated, nothing found"
// with StatusCode 302 and ResponseSize 0 for a page that was never fetched. That is strictly
// worse than the error it replaced, because the error left the row visibly absent. A one-hop
// chain cannot distinguish the two, which is how it shipped.
//
// The retry is a second request, which is why it is not the fix everywhere: the no-follow sites
// pay nothing and must not pay anything. Here it costs one extra GET on a response that was going
// to be discarded, which is the better trade.
// ---------------------------------------------------------------------------------------------

// DoFollowing sends through a redirect-following client and, if the chain died only because a
// Location header would not parse, re-sends once without following and returns that response.
func DoFollowing(c *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := c.Do(req)
	if err == nil || !IsLocationParseError(err) {
		return resp, err
	}
	// THE RETRY IS A SECOND REQUEST, so it is only sent when sending it twice cannot change
	// anything at the target: a safe method, and no body. Both current callers issue plain GETs.
	// Without this guard, adding a body to either one would silently turn a recovery into a
	// duplicate write, and it would only show up as a mystery double record months later.
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "":
	default:
		return nil, err
	}
	if req.Body != nil || req.ContentLength > 0 {
		return nil, err
	}

	target := breakingHopURL(req.URL, err)
	retry, rerr := http.NewRequestWithContext(req.Context(), req.Method, target.String(), nil)
	if rerr != nil {
		return nil, err
	}
	// Clone() of a nil Header is nil, and a request whose Header is nil panics inside the
	// transport. NewRequestWithContext already gave us a usable one, so only replace it.
	if cloned := req.Header.Clone(); cloned != nil {
		retry.Header = cloned
	}
	if sameRedirectHost(req.URL, target) {
		// The Host override only means anything for the URL it was written for.
		retry.Host = req.Host
	} else {
		// The retry is a request this code builds by hand at a host the CALLER never addressed.
		// net/http strips these itself when a redirect crosses to an unrelated host
		// (shouldCopyHeaderOnRedirect), and a hand-built request that does not is a credential
		// sent somewhere it was never meant to go.
		for _, h := range redirectSensitiveHeaders {
			retry.Header.Del(h)
		}
	}
	if resp2, rerr := NewNoFollowClient(c).Do(retry); rerr == nil {
		return resp2, nil
	}
	return nil, err
}

// redirectSensitiveHeaders are the headers net/http refuses to carry across a redirect to an
// unrelated host. The retry has to make the same refusal by hand.
var redirectSensitiveHeaders = []string{
	"Authorization", "Www-Authenticate", "Cookie", "Cookie2", "Proxy-Authorization",
}

// redactedPasswordMarker is what net/http's stripPassword substitutes for a set password when it
// builds the URL on a *url.Error. Anything carrying it is a display string, not a usable URL.
const redactedPasswordMarker = "***"

// breakingHopURL picks the URL to re-send: the hop whose Location would not parse, which net/http
// records on the *url.Error.
//
// client.go's uerr sets URL to stripPassword(resp.Request.URL), and at the Location-parse point
// resp is the response that carried the bad Location, so its Request.URL is exactly the hop that
// broke. Two things make that string untrustworthy on its own:
//
//   - stripPassword rewrites a set password to ***. Re-sending it verbatim would put *** on the
//     wire as the password. Measured: the retry comes back 401 and the caller records "nothing
//     found" for a page the framework is entitled to read. When the redacted URL is on the same
//     host as the original, the real userinfo is restored from it; when it is not, there is no
//     credential to restore and the original URL is the safe answer.
//   - It is a string built for a human. If it will not parse, the original URL is used, which is
//     the old behaviour: never worse than before.
func breakingHopURL(original *url.URL, err error) *url.URL {
	var ue *url.Error
	if !errors.As(err, &ue) || ue.URL == "" {
		return original
	}
	hop, perr := url.Parse(ue.URL)
	if perr != nil || hop.Host == "" {
		return original
	}
	if pw, set := hop.User.Password(); set && pw == redactedPasswordMarker {
		if !sameRedirectHost(original, hop) {
			return original
		}
		hop.User = original.User
	}
	return hop
}

// sameRedirectHost compares hosts the way a credential decision has to: exact, case-insensitive,
// port included, and a missing host on either side is never a match.
func sameRedirectHost(a, b *url.URL) bool {
	if a == nil || b == nil || a.Host == "" || b.Host == "" {
		return false
	}
	return strings.EqualFold(a.Host, b.Host)
}

// GetFollowing is DoFollowing for the callers that used client.Get.
func GetFollowing(c *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return DoFollowing(c, req)
}

// IsLocationParseError reports whether an error is net/http refusing a 3xx whose Location header
// it could not parse. Matched on the message because net/http gives it no sentinel and no type:
// the text is built in one place, client.go's redirect loop, and has been stable since Go 1.0.
//
// This is a string match on a message that EMBEDS THE LOCATION HEADER, which is attacker
// influenced, so the prefix is what is matched and never a bare substring. A Location of
// "https://x.example/failed to parse Location header" must not be able to make some other error
// look like this one.
func IsLocationParseError(err error) bool {
	if err == nil {
		return false
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return strings.HasPrefix(ue.Err.Error(), "failed to parse Location header ")
	}
	return strings.HasPrefix(err.Error(), "failed to parse Location header ")
}

// ---------------------------------------------------------------------------------------------
// WHAT COUNTS AS A HOST FAILURE
//
// HostBudget.Observe(failed=true) drives the collapse detector: ten consecutive failures abort
// the whole run with transport_collapse. The runner used to feed it EVERY error from the send
// path, including errors from requests that never left the process, so the detector was measuring
// this codebase rather than the target.
//
// MEASURED, against the oracle route /hosthdr/location, which answers
// Location: https://<our payload>/account/reset. Every header-slot probe of every registered
// class was sent at it, 348 of them, through the real HostBudget. TWO SEPARATE RUNS, because the
// two numbers below cannot come from one: the first needs the collapse detector disabled to see
// how many responses the client discards, and the second is what the detector then does about it.
//
//	run 1, collapse detector DISABLED, http.Client : 186 of 348 responses discarded (53.4%),
//	                          longest run of consecutive discards 19, against an abort threshold
//	                          of 10.
//	run 2, collapse detector ENABLED, http.Client : ABORTED at probe 11 of 348
//	                          (SSTI/SSTI-BER3) with transport_collapse, so only 11 probes were
//	                          ever sent and 337 of 348 (96.8%) never left the process.
//	either run, NoFollowClient : 348 of 348 sent, 0 discarded, no abort.
//
// So the delivered-probe count is 11 of 348 (3.2%) before and 348 of 348 after; 53.4% is the
// discard rate the detector was reacting to, not a second measurement of the same run.
//
// Every one of the 186 discards was a 302 the target had already delivered in full. The Location
// parse failure was additionally classified reset, because triageClassifyTransportErr
// substring-matches "reset" against an error message that embeds our own payload and this route's
// path ends /account/reset.
//
// The list below is positive identification only. An error this function does not recognise still
// counts against the host, because the collapse detector exists to stop a run that is hammering a
// dead target and a guess in that direction is the dangerous one.
// ---------------------------------------------------------------------------------------------

// triageErrReachedTheWire reports whether a send error is an observation OF THE HOST, and so
// whether it may feed the pacing ladder and the collapse detector.
func triageErrReachedTheWire(err error) bool {
	if err == nil {
		return false
	}
	// The response arrived, in full, and net/http discarded it. The host did nothing wrong; it
	// answered, and answered in the way that proves the finding.
	if IsLocationParseError(err) {
		return false
	}
	// Our own cancellation. The host is not failing because we stopped asking.
	if errors.Is(err, context.Canceled) {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, local := range triageNeverLeftTheProcess {
		if strings.Contains(s, local) {
			return false
		}
	}
	return true
}

// triageNeverLeftTheProcess are the errors raised before a single byte is written: the encoder
// refusing an undeliverable payload, net/http refusing a request it will not build, and the
// transport refusing a header or a URL it will not send. Each is a statement about the probe, not
// about the target.
var triageNeverLeftTheProcess = []string{
	"refusing to send an undeliverable encode",
	"net/http: invalid method",
	"invalid header field name",
	"invalid header field value",
	"unsupported protocol scheme",
	"no host in request url",
	"nil request.url",
	"missing protocol scheme",
	"requires a request with a url",
}

// ---------------------------------------------------------------------------------------------
// THE ONE PLACE AN http.Client IS STILL UNAVOIDABLE
//
// FetchPreludeTokens takes an *http.Client by signature and lives in a file this change does not
// own, so its client cannot become a NoFollowClient here. Leaving it a plain http.Client would
// make it a twelfth site that loses a response whose Location will not parse, which is the whole
// defect being fixed.
//
// LocationNeutralizingTransport is the narrow answer: it moves an unparseable Location out of the
// way BEFORE net/http's redirect loop can choke on it, so the response survives, and preserves
// the original byte-for-byte under a header of its own so nothing is destroyed. It is correct for
// a caller that does not read Location, and it is wrong for one that does. That is why it is named
// after what it does rather than after where it is used, and why the redirect detector does not
// go anywhere near it.
// ---------------------------------------------------------------------------------------------

// PreservedLocationHeader carries the original Location of a response whose Location had to be
// neutralised so net/http would not discard the response.
const PreservedLocationHeader = "X-Ars0n-Unparseable-Location"

// locationNeutralizedValue is what Location is replaced with. It parses, it is relative, and it
// resolves to a path no application serves, so a client that did follow it would go nowhere
// interesting rather than somewhere real.
const locationNeutralizedValue = "/.ars0n-unparseable-location"

// LocationNeutralizingTransport wraps a RoundTripper.
type LocationNeutralizingTransport struct{ Base http.RoundTripper }

func (t LocationNeutralizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode < 300 || resp.StatusCode > 399 {
		return resp, err
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return resp, nil
	}
	if _, perr := url.Parse(loc); perr == nil {
		return resp, nil
	}
	resp.Header.Set(PreservedLocationHeader, loc)
	resp.Header.Set("Location", locationNeutralizedValue)
	return resp, nil
}
