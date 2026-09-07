package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The single door every request issued by Validate, Investigate and active flow detection goes
// through. Scope, pacing and redirect handling are enforced here so no call site has to remember
// them: a rule every call site has to remember is a rule that leaks.
//
// Redirects are never followed. A 302 to /login is the single most useful observation Validate
// makes, and a client that follows it reports 200 and destroys the evidence.

// scanSendableMethods is what this transport will put on the wire. The full set: the operator
// chooses the verb, and a scanner that cannot send a POST cannot reach most of the surface worth
// testing.
//
// Unknown verbs are still refused. That is not a policy, it is a typo check: "GTE" would otherwise
// become a run's worth of 405s recorded as if the endpoints had been tested.
var scanSendableMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
}

// allowedScanMethods is the safe/idempotent subset, per RFC 9110.
//
// THIS IS NOT THE TRANSPORT'S LIMIT. The transport sends scanSendableMethods above. This map is the
// policy that two OTHER subsystems apply to themselves, and both have a specific reason:
//
//	endpointInvestigationUtils.go  downgrades a recorded verb to GET and records VerbNotReplayed.
//	                              It applies captured credentials, and it is the original defect:
//	                              a crawl that captured `DELETE /api/keys/7` sent a real,
//	                              authenticated DELETE. Investigate characterises a verb, it does
//	                              not replay one.
//	bypassControl.go              refuses to judge a candidate whose verb is not safe, because a
//	                              POST answering 2xx means the application accepted a new request,
//	                              not that a refused resource was reached.
//
// Widening this map would silently re-arm both. Detection's verb set is chosen in
// flowDetectionActive.go and enforced by scanSendableMethods; leave this one alone.
var allowedScanMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// ErrMethodNotAllowed is returned rather than silently downgrading to GET. A caller that asked for a
// verb this transport does not know has a bug, and quietly turning it into a GET hides it.
var ErrMethodNotAllowed = fmt.Errorf(
	"scanHTTP: method must be one of GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE")

const (
	scanMaxBodyBytes  = 2 << 20 // 2 MB decoded; enough for any page worth analysing
	scanBodySampleCap = 8 << 10 // what is retained on stored evidence samples
)

// ScanRequest is what a call site may ask for.
type ScanRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	// Body is sent as-is when non-empty, with Content-Length set from its length. Empty means no
	// body and no Content-Length header, so a plain GET stays a plain GET.
	//
	// Set Content-Type in Headers when the body needs one. Nothing here guesses it: a JSON body
	// posted as application/x-www-form-urlencoded gets a 400 that looks like the endpoint rejecting
	// the request rather than the sender mislabelling it.
	Body string
	// Credentials are applied by the caller's ScopedAuthContext, never guessed here.
	Auth *ScopedAuthMaterial
	// Timeout overrides the client default for one request, used when the probe reported a tarpit.
	Timeout time.Duration
	// ReadBody false issues the request and discards the body, for HEAD and for static assets.
	ReadBody bool
}

// ScanResponse is a fully-read, decoupled snapshot. The underlying response is always closed.
type ScanResponse struct {
	URL          string
	FinalURL     string
	Method       string
	Status       int
	Header       http.Header
	Body         string
	BodyBytes    int
	Truncated    bool
	ContentType  string
	Location     string
	ElapsedMS    int64
	Err          error
	AuthApplied  bool
	AuthWithheld string
}

// ScanClient is one client per run. Sharing it keeps connection reuse, the cookie jar, and the
// pacing budget consistent across every request the run makes.
type ScanClient struct {
	http      *http.Client
	budget    *HostBudget
	userAgent string
	// pinnedEncoding keeps byte sizes comparable across the whole run. Comparing a gzipped
	// response against an identity-encoded one is the classic reason a size filter matches nothing.
	pinnedEncoding string
	attribution    string
	// scope is the host boundary. Nil means unrestricted, which is only correct for callers that
	// have no scope target, such as the Routing & WAF Probe measuring its own configured URL.
	scope *ScanScope
}

// WithScope restricts every request this client will issue. Enforced in Do, next to the verb
// allowlist, because a boundary that each call site has to remember is a boundary that leaks: this
// one already leaked twice, in buildQueue and in Tier 1's host probes.
func (c *ScanClient) WithScope(scope *ScanScope) *ScanClient {
	c.scope = scope
	return c
}

// NewScanClient builds the run's client. jar may be nil when session reuse is not wanted.
func NewScanClient(budget *HostBudget, timeout time.Duration, userAgent string, jar http.CookieJar) *ScanClient {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if userAgent == "" {
		userAgent = "ars0n-framework/2.0 (+authorized-testing)"
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Scope targets routinely use self-signed or mismatched certificates in dev environments.
		// Refusing them would make the framework useless on exactly the hosts it is pointed at.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// Compression is handled explicitly so wire sizes stay comparable run-wide.
		DisableCompression: true,
	}
	return &ScanClient{
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			Jar:       jar,
			// Never follow. The hop itself is the observation.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		budget:         budget,
		userAgent:      userAgent,
		pinnedEncoding: "identity",
		attribution:    "X-Ars0n-Framework",
	}
}

// Do issues one request, blocking on the host's rate budget first.
func (c *ScanClient) Do(ctx context.Context, req ScanRequest) ScanResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	out := ScanResponse{URL: req.URL, Method: method}

	if !scanSendableMethods[method] {
		out.Err = ErrMethodNotAllowed
		return out
	}

	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Host == "" {
		out.Err = fmt.Errorf("scanHTTP: unusable URL %q", req.URL)
		return out
	}

	// The host boundary. This is checked before pacing and before the request is built, so an
	// out-of-scope URL costs nothing and, more importantly, reaches nothing.
	if c.scope != nil && !c.scope.Allows(parsed.Hostname()) {
		c.scope.Refuse(parsed.Hostname())
		out.Err = fmt.Errorf("%w: %s", ErrOutOfScope, parsed.Hostname())
		return out
	}

	// Pacing happens before the request is even built, so a blocked budget costs nothing.
	if c.budget != nil {
		if err := c.budget.Wait(ctx, parsed.Hostname()); err != nil {
			out.Err = err
			return out
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = c.http.Timeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A nil body when there is nothing to send, so a GET does not acquire a Content-Length: 0 that
	// the recorded request never had. http.NewRequestWithContext derives ContentLength from a
	// *strings.Reader; it is set again below so the value is explicit rather than inferred, and so a
	// stale Content-Length in req.Headers cannot contradict the bytes actually being written.
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, method, req.URL, bodyReader)
	if err != nil {
		out.Err = err
		return out
	}
	if req.Body != "" {
		httpReq.ContentLength = int64(len(req.Body))
		// GetBody lets the transport rebuild the body if it has to retry the request.
		body := req.Body
		httpReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
	}

	httpReq.Header.Set("User-Agent", c.userAgent)
	httpReq.Header.Set("Accept-Encoding", c.pinnedEncoding)
	httpReq.Header.Set(c.attribution, "endpoint-workflow")
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	if req.Auth != nil {
		out.AuthApplied, out.AuthWithheld = req.Auth.Apply(httpReq)
	}

	started := time.Now()
	resp, err := c.http.Do(httpReq)
	out.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		out.Err = err
		if c.budget != nil {
			c.budget.Observe(parsed.Hostname(), 0, out.ElapsedMS, true)
		}
		return out
	}
	defer resp.Body.Close()

	out.Status = resp.StatusCode
	out.Header = resp.Header.Clone()
	out.ContentType = resp.Header.Get("Content-Type")
	out.Location = resp.Header.Get("Location")
	out.FinalURL = req.URL

	if req.ReadBody && method != http.MethodHead {
		limited := io.LimitReader(resp.Body, scanMaxBodyBytes+1)
		raw, readErr := io.ReadAll(limited)
		if readErr != nil && len(raw) == 0 {
			out.Err = readErr
		}
		if len(raw) > scanMaxBodyBytes {
			out.Truncated = true
			raw = raw[:scanMaxBodyBytes]
		}
		out.Body = string(raw)
		out.BodyBytes = len(raw)
	} else {
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, scanMaxBodyBytes))
		out.BodyBytes = int(n)
	}

	if c.budget != nil {
		c.budget.Observe(parsed.Hostname(), out.Status, out.ElapsedMS, false)
	}
	return out
}

// BodySample returns the capped excerpt stored as evidence. Full bodies are never persisted.
func (r ScanResponse) BodySample() string {
	if len(r.Body) <= scanBodySampleCap {
		return r.Body
	}
	return r.Body[:scanBodySampleCap]
}

// IsRedirect reports a hop worth recording rather than a final answer.
func (r ScanResponse) IsRedirect() bool {
	return r.Status >= 300 && r.Status < 400 && r.Location != ""
}
