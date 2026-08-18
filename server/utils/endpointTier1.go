package utils

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Tier 1: the probes that cost an extra request.
//
// Tier 0 is free because it reads a response that was already fetched. Everything here sends
// something new, so each probe has to earn its request. Three rules keep the budget honest:
//
//   - Per-host work happens once per host, not once per endpoint. Retrieving a source map or
//     robots.txt five thousand times is the same answer five thousand times.
//   - Per-endpoint work runs in Tier 0 score order and stops when the budget runs out, so a
//     truncated run has spent its requests on the endpoints that looked most interesting.
//   - Everything goes through ScanClient, so the verb allowlist, the no-body rule and the measured
//     rate budget apply here exactly as they do everywhere else.
//
// The unauthenticated differential is the reason this tier exists at all. One request per endpoint
// answers the question no amount of passive analysis can: does this endpoint return the same data
// to someone who is not logged in.

type Tier1Config struct {
	// MaxRequests is the ceiling for the whole tier. Zero disables it.
	MaxRequests int
	// RunDifferential is the one probe worth doing on almost every endpoint.
	RunDifferential bool
	RunCORS         bool
	RunMethods      bool
	RunHostProbes   bool
}

// Tier1BudgetFor scales the request budget to the size of the corpus.
//
// A fixed 600 was sized against a small target. On a 2137-endpoint run it meant the unauthenticated
// differential, which is the entire point of this tier, reached about 11% of the corpus, and the
// per-host well-known-file probes consumed 47% of the budget before it. Roughly one request per
// eligible endpoint, floored so a tiny corpus still gets a useful pass and capped so a huge one
// cannot run away.
func Tier1BudgetFor(eligible int) int {
	budget := eligible
	if budget < 600 {
		budget = 600
	}
	if budget > 5000 {
		budget = 5000
	}
	return budget
}

func DefaultTier1Config() Tier1Config {
	return Tier1Config{
		MaxRequests:     600,
		RunDifferential: true,
		RunCORS:         true,
		RunMethods:      true,
		RunHostProbes:   true,
	}
}

type tier1Run struct {
	ctx       context.Context
	client    *ScanClient
	budget    *HostBudget
	auth      *ScopedAuthContext
	cfg       Tier1Config
	scope     *ScanScope
	spent     int
	perHost   map[string]bool
	loginFP   ResponseFingerprint
	haveLogin bool
	// uniformWall is set when the unauthenticated arm returns the login page for the first twenty
	// endpoints without exception. After that the differential is sampled rather than run on
	// everything, because the answer is already known and the requests are better spent elsewhere.
	uniformWall bool
	wallStreak  int
	wallChecked int
	notes       []string
}

// Tier1Target is one endpoint the tier may probe, ordered by its Tier 0 score.
type Tier1Target struct {
	EndpointID  string
	URL         string
	Method      string
	Score       int
	Status      string // the validation verdict
	ContentType string
	Signals     []Signal
	// Authenticated records whether Tier 0 fetched this with credentials. Without that, a
	// differential is meaningless: both arms would be anonymous.
	Authenticated bool
}

// RunTier1 executes the gated probes and returns the signals they produced, keyed by endpoint id,
// plus host-level signals under the key "host:<hostname>".
func RunTier1(ctx context.Context, budget *HostBudget, auth *ScopedAuthContext,
	cfg Tier1Config, targets []Tier1Target, loginFP ResponseFingerprint, haveLogin bool,
	scope *ScanScope,
) (map[string][]Signal, []string) {

	if cfg.MaxRequests <= 0 || len(targets) == 0 {
		return map[string][]Signal{}, nil
	}

	run := &tier1Run{
		ctx:       ctx,
		client:    NewScanClient(budget, 20_000_000_000, "", nil).WithScope(scope),
		budget:    budget,
		auth:      auth,
		cfg:       cfg,
		scope:     scope,
		perHost:   map[string]bool{},
		loginFP:   loginFP,
		haveLogin: haveLogin,
	}

	// Out-of-scope targets are dropped before the budget is spent on them. This is where the
	// robots.txt, security.txt and sitemap.xml probes leaked to 91 unrelated hosts, and they are
	// per-host so a handful of third-party endpoints cost three requests each.
	if scope != nil {
		kept := targets[:0]
		refused := 0
		for _, t := range targets {
			if scope.AllowsURL(t.URL) {
				kept = append(kept, t)
				continue
			}
			scope.Refuse(hostOf(t.URL))
			refused++
		}
		targets = kept
		if refused > 0 {
			run.note(fmt.Sprintf(
				"%d endpoint(s) on %d host(s) outside %s were not probed.",
				refused, len(scope.Refused()), scope.Describe()))
		}
	}
	if len(targets) == 0 {
		return map[string][]Signal{}, run.notes
	}

	// Highest Tier 0 score first, so a truncated run has spent its requests well.
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].Score > targets[j].Score })

	out := map[string][]Signal{}
	appendSig := func(key string, sigs ...Signal) {
		if len(sigs) > 0 {
			out[key] = append(out[key], sigs...)
		}
	}

	for _, t := range targets {
		if run.exhausted() {
			run.note(fmt.Sprintf("Tier 1 stopped after %d requests; %d endpoint(s) were not probed.",
				run.spent, len(targets)-len(out)))
			break
		}
		host := hostOf(t.URL)

		if cfg.RunHostProbes && host != "" && !run.perHost[host] {
			run.perHost[host] = true
			appendSig("host:"+host, run.hostProbes(host, t)...)
		}
		if cfg.RunDifferential {
			appendSig(t.EndpointID, run.differential(t)...)
		}
		if cfg.RunMethods && isAPIShaped(t) {
			appendSig(t.EndpointID, run.methodSurface(t)...)
		}
		if cfg.RunCORS && (isAPIShaped(t) || hasCORSHeaderSignal(t)) {
			appendSig(t.EndpointID, run.corsReflection(t)...)
		}
	}

	return out, run.notes
}

func (r *tier1Run) exhausted() bool {
	return r.spent >= r.cfg.MaxRequests || r.budget.Aborted() != ""
}

func (r *tier1Run) note(s string) { r.notes = append(r.notes, s) }

func (r *tier1Run) get(rawURL string, headers map[string]string, material *ScopedAuthMaterial) ScanResponse {
	r.spent++
	return r.client.Do(r.ctx, ScanRequest{
		URL: rawURL, Method: http.MethodGet, Headers: headers, Auth: material, ReadBody: true,
	})
}

// ---------------------------------------------------------------- T1.1 differential

// differential answers the single most valuable question in the whole workflow: does this endpoint
// hand the same content to somebody who is not logged in.
//
// One request, credentials deliberately withheld. The interesting outcome is not "it was blocked",
// it is "it was not": an endpoint that returns identical bytes with and without a session is either
// public by design or missing an authorization check, and only the operator can tell which.
func (r *tier1Run) differential(t Tier1Target) []Signal {
	if !t.Authenticated || t.Status != validationStatusValid {
		return nil // nothing to compare against
	}
	if r.uniformWall && t.Score < 40 {
		return nil // the answer is already known for this target; save the request
	}
	// Only GET can be sent here, so an endpoint recorded under another verb would be compared on a
	// route that does not exist for GET. Both arms then answer identically because neither found
	// anything, which says nothing about authorization. The recorded verb is carried on the target
	// precisely so this can be checked.
	if m := strings.ToUpper(strings.TrimSpace(t.Method)); m != "" && m != http.MethodGet && m != http.MethodHead {
		return nil
	}
	// A static file is the same for everyone by design. Comparing one against itself and calling the
	// match a possible missing authorization check is noise that crowds out the real findings.
	if staticAssetPath(t.URL, "") {
		return nil
	}

	authed := r.getAuthed(t.URL)
	if authed.Err != nil || authed.Status == 0 {
		return nil
	}
	// Content-Type is only known once something has answered, so the extension check above is
	// repeated here against what the server actually said it served.
	if staticAssetPath(t.URL, authed.ContentType) {
		return nil
	}
	anon := r.get(t.URL, nil, nil)
	if anon.Err != nil {
		return nil
	}

	authedFP := BuildFingerprint(authed)
	anonFP := BuildFingerprint(anon)

	// Track whether every anonymous arm is just the login page. If it is, stop spending requests
	// re-learning it.
	if r.haveLogin && MatchesReference(anonFP, r.loginFP) {
		r.wallStreak++
	} else {
		r.wallStreak = 0
	}
	r.wallChecked++
	if r.wallChecked >= 20 && r.wallStreak >= 20 && !r.uniformWall {
		r.uniformWall = true
		r.note("Every endpoint checked so far returns the login page when unauthenticated, so the " +
			"differential is now sampled rather than run on all of them.")
	}

	// Refusal, absence and a login redirect are answers about access. They have to be decided BEFORE
	// the identical-content case, because two identical 401s are byte-identical and the equivalence
	// test cannot tell them apart from two identical 200s. Ordered the other way round, an endpoint
	// that refused both arms was reported as "the same content with and without credentials, either
	// public by design or missing an authorization check", which is the exact opposite of what it
	// did, and the authz_enforced branch below could never be reached at all.
	sameStatus := anon.Status == authed.Status
	switch {
	case sameStatus && (anon.Status == 401 || anon.Status == 403):
		// Both arms refused. Either the check works, or the credentials never attached. Those two
		// are indistinguishable from here, and saying so is more useful than picking one.
		detail := fmt.Sprintf("Anonymous requests are refused with %d. Working as intended.", anon.Status)
		if authed.AuthApplied {
			detail = fmt.Sprintf("Both the credentialed and the anonymous request were refused with %d. "+
				"The credential was attached, so this is enforcement working, unless the session has "+
				"expired.", anon.Status)
		} else {
			detail = fmt.Sprintf("Both arms were refused with %d, and no credential was attached to the "+
				"authenticated arm (%s). This measures the login wall, not the endpoint.",
				anon.Status, authed.AuthWithheld)
		}
		return []Signal{{
			Family: "authz", Kind: "authz_enforced", Severity: "p3",
			Title:      "Authorization is enforced",
			Detail:     detail,
			Evidence:   fmt.Sprintf("both arms: %d", anon.Status),
			Confidence: "measured",
			DedupeKey:  signalHash("authz_enforced"),
		}}

	case sameStatus && (anon.Status == 404 || anon.Status == 400 || anon.Status == 405 || anon.Status == 501):
		// Neither arm found anything. Identical because the endpoint is not there for this verb, not
		// because it is public. Most often the recorded verb was not GET and the differential can
		// only send GET.
		return nil

	case anon.IsRedirect() && LooksLikeAuthRedirect(anon.Location):
		return []Signal{{
			Family: "authz", Kind: "authz_redirects_to_login", Severity: "p3",
			Title:      "Anonymous requests are redirected to login",
			Detail:     "Working as intended.",
			Confidence: "measured",
			DedupeKey:  signalHash("authz_redirects_to_login"),
		}}

	case sameStatus && ResponsesEquivalent(anonFP, authedFP):
		// The one that matters. Same successful response, same content, no credentials.
		//
		// Both arms truncated at the read cap means the comparison only saw the first N bytes of
		// each, which are identical by construction on any large file. That is not evidence.
		if anon.Truncated && authed.Truncated {
			return []Signal{{
				Family: "authz", Kind: "authz_identical_truncated", Severity: "p3",
				Title: "Identical response with and without authentication, but both were truncated",
				Detail: fmt.Sprintf("Both arms were cut at the %d byte read cap, so only the identical "+
					"prefixes were compared. Whether the full responses differ is not established.",
					scanMaxBodyBytes),
				Evidence:   fmt.Sprintf("both arms: %d, truncated at %d bytes", anon.Status, anon.BodyBytes),
				Confidence: "inferred",
				DedupeKey:  signalHash("authz_identical_truncated|" + t.EndpointID),
			}}
		}
		sev := "p1"
		detail := "This endpoint returned the same content with and without credentials. Either it " +
			"is public by design, or an authorization check is missing."
		if carriesIdentityData(t.Signals) || looksLikePersonalData(anon.Body) {
			sev = "p0"
			detail = "This endpoint returned the same content with and without credentials, and the " +
				"response carries identifiers or personal-looking data. That is a missing " +
				"authorization check unless the data is genuinely public."
		}
		return []Signal{{
			Family: "authz", Kind: "authz_public_identical", Severity: sev,
			Title:      "Identical response with and without authentication",
			Detail:     detail,
			Evidence:   fmt.Sprintf("both arms: %d, %d bytes", anon.Status, anon.BodyBytes),
			Confidence: "measured",
			DedupeKey:  signalHash("authz_public_identical|" + t.EndpointID),
		}}

	case anon.Status == authed.Status && anon.BodyBytes != authed.BodyBytes:
		return []Signal{{
			Family: "authz", Kind: "authz_same_status_different_body", Severity: "p2",
			Title: "Same status code with and without authentication, different body",
			Detail: fmt.Sprintf("Both arms answered %d but the bodies differ (%d vs %d bytes). The "+
				"endpoint is reachable anonymously and decides what to show rather than whether to "+
				"answer, which is where partial disclosure lives.",
				anon.Status, anon.BodyBytes, authed.BodyBytes),
			Confidence: "measured",
			DedupeKey:  signalHash("authz_same_status_diff_body|" + t.EndpointID),
		}}

	case anon.Status == 401 || anon.Status == 403:
		// Only the anonymous arm was refused, so the credential genuinely changed the outcome.
		return []Signal{{
			Family: "authz", Kind: "authz_enforced", Severity: "p3",
			Title:      "Authorization is enforced",
			Detail:     fmt.Sprintf("Anonymous requests are refused with %d. Working as intended.", anon.Status),
			Confidence: "measured",
			DedupeKey:  signalHash("authz_enforced"),
		}}
	}
	return nil
}

// staticAssetPath reports whether a URL is a file served as-is, which is identical with and without
// a session because it is a file, not because a check is missing.
//
// Without this the differential reported every public webpack bundle on a CDN as a potential missing
// authorization check, and the p0 escalation fired on top because minified bundle module ids look
// exactly like small sequential object identifiers.
var staticAssetExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".wasm": true, ".pdf": true, ".zip": true, ".gz": true,
}

func staticAssetPath(rawURL, contentType string) bool {
	if u, err := url.Parse(rawURL); err == nil {
		p := strings.ToLower(u.Path)
		if i := strings.LastIndex(p, "."); i >= 0 && staticAssetExtensions[p[i:]] {
			return true
		}
	}
	ct := strings.ToLower(contentType)
	for _, prefix := range []string{"image/", "font/", "video/", "audio/"} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "application/wasm")
}

func (r *tier1Run) getAuthed(rawURL string) ScanResponse {
	material, _ := r.auth.For(hostOf(rawURL))
	return r.get(rawURL, nil, material)
}

// carriesIdentityData reports whether Tier 0 already found object identifiers here, which is what
// turns "publicly readable" into "publicly readable and enumerable".
func carriesIdentityData(sigs []Signal) bool {
	for _, s := range sigs {
		if s.Family == "identifier" && s.Kind != "identifier_uuid_v4" {
			return true
		}
	}
	return false
}

var personalDataMarkers = []string{`"email"`, `"phone"`, `"first_name"`, `"last_name"`,
	`"address"`, `"ssn"`, `"date_of_birth"`, `"dob"`, `"full_name"`, `"user_id"`, `"account_id"`}

func looksLikePersonalData(body string) bool {
	lower := strings.ToLower(body)
	if len(lower) > 60000 {
		lower = lower[:60000]
	}
	hits := 0
	for _, m := range personalDataMarkers {
		if strings.Contains(lower, m) {
			hits++
		}
	}
	return hits >= 2
}

// ---------------------------------------------------------------- T1.2 method surface

// methodSurface asks the endpoint what it accepts rather than guessing.
//
// OPTIONS is safe and idempotent, and Allow frequently names write verbs no crawler ever saw. A
// PUT or DELETE advertised here is a lead; it is reported, never exercised.
func (r *tier1Run) methodSurface(t Tier1Target) []Signal {
	r.spent++
	material, _ := r.auth.For(hostOf(t.URL))
	resp := r.client.Do(r.ctx, ScanRequest{
		URL: t.URL, Method: http.MethodOptions, Auth: material, ReadBody: false,
	})
	if resp.Err != nil || resp.Status == 0 {
		return nil
	}

	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}
	if allow == "" {
		return nil
	}

	var writeVerbs []string
	for _, v := range strings.Split(strings.ToUpper(allow), ",") {
		v = strings.TrimSpace(v)
		switch v {
		case "PUT", "PATCH", "DELETE", "POST":
			writeVerbs = append(writeVerbs, v)
		}
	}
	if len(writeVerbs) == 0 {
		return nil
	}
	return []Signal{{
		Family: "method", Kind: "method_write_surface", Severity: "p2",
		Title: "Endpoint advertises write methods",
		Detail: fmt.Sprintf("OPTIONS reports Allow: %s. These were never sent by this framework; "+
			"%s are worth testing by hand for authorization.", allow, strings.Join(writeVerbs, ", ")),
		Evidence:   allow,
		Confidence: "measured",
		DedupeKey:  signalHash("method_write_surface|" + allow),
	}}
}

// ---------------------------------------------------------------- T1.3 CORS reflection

const corsProbeOrigin = "https://ars0nprobe.invalid"

// corsReflection sends one request with a foreign Origin and looks at what comes back.
//
// A server that echoes an arbitrary Origin and sets Allow-Credentials lets any website read
// authenticated responses from this endpoint. The probe origin is a .invalid host, which by RFC
// 6761 can never resolve, so nothing is ever sent to a domain somebody could register.
func (r *tier1Run) corsReflection(t Tier1Target) []Signal {
	material, _ := r.auth.For(hostOf(t.URL))
	resp := r.get(t.URL, map[string]string{"Origin": corsProbeOrigin}, material)
	if resp.Err != nil || resp.Status == 0 {
		return nil
	}

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	if allowOrigin == "" {
		return nil
	}

	var out []Signal
	if allowOrigin == corsProbeOrigin {
		sev := "p2"
		detail := "The server echoed an arbitrary Origin back in Access-Control-Allow-Origin, so any " +
			"site can read this response cross-origin."
		if allowCreds {
			sev = "p0"
			detail = "The server echoed an arbitrary Origin AND set Access-Control-Allow-Credentials. " +
				"Any website a logged-in user visits can read this endpoint's authenticated response."
		}
		out = append(out, Signal{
			Family: "cors", Kind: "cors_origin_reflected", Severity: sev,
			Title:      "Access-Control-Allow-Origin reflects the request Origin",
			Detail:     detail,
			Evidence:   "sent Origin: " + corsProbeOrigin + ", received: " + allowOrigin,
			Confidence: "measured",
			DedupeKey:  signalHash("cors_origin_reflected|" + hostOf(t.URL)),
		})

		// Only when it already echoed is a second probe worth the request.
		if !r.exhausted() {
			nullResp := r.get(t.URL, map[string]string{"Origin": "null"}, material)
			if nullResp.Err == nil && nullResp.Header.Get("Access-Control-Allow-Origin") == "null" {
				out = append(out, Signal{
					Family: "cors", Kind: "cors_null_origin", Severity: "p1",
					Title: "Access-Control-Allow-Origin allows the null origin",
					Detail: "A sandboxed iframe or a data: document sends Origin: null, so an attacker " +
						"can reach this endpoint from a context with no origin of its own.",
					Confidence: "measured",
					DedupeKey:  signalHash("cors_null_origin|" + hostOf(t.URL)),
				})
			}
		}
	} else if allowOrigin == "*" && allowCreds {
		out = append(out, Signal{
			Family: "cors", Kind: "cors_wildcard_credentials", Severity: "p1",
			Title:      "Wildcard Access-Control-Allow-Origin with credentials",
			Detail:     "Browsers reject this pair, but it signals the intent that usually shows up as a reflected origin elsewhere on the same host.",
			Confidence: "measured",
			DedupeKey:  signalHash("cors_wildcard_credentials|" + hostOf(t.URL)),
		})
	}
	return out
}

// ---------------------------------------------------------------- T1.4-6 per-host probes

// hostProbes runs the things that are true of a host rather than an endpoint, exactly once each.
func (r *tier1Run) hostProbes(host string, t Tier1Target) []Signal {
	var out []Signal

	base := "https://" + host
	if u, err := url.Parse(t.URL); err == nil {
		base = u.Scheme + "://" + u.Host
	}
	material, _ := r.auth.For(host)

	// Well-known files. Three requests, once per host, and each is a file the site publishes on
	// purpose for anyone to read.
	for path, meta := range map[string]struct{ kind, title, detail, severity string }{
		"/robots.txt": {"robots", "robots.txt lists paths",
			"Disallow entries name paths the operator did not want indexed, which is frequently the admin and export surface.", "p3"},
		"/.well-known/security.txt": {"security_txt", "security.txt published",
			"Names the disclosure contact and policy, which is what a report needs.", "p3"},
		"/sitemap.xml": {"sitemap", "sitemap.xml published",
			"An authoritative list of pages the application wants known, useful for filling gaps a crawler missed.", "p3"},
	} {
		if r.exhausted() {
			break
		}
		resp := r.get(base+path, nil, material)
		if resp.Err != nil || resp.Status < 200 || resp.Status >= 300 || resp.BodyBytes == 0 {
			continue
		}
		// The host belongs in the title, not only in the dedupe key.
		//
		// These are per-host facts and they bypass the corpus rollup, so a run that touched many
		// hosts produced one entry per host with identical text. A live run reported "robots.txt
		// lists paths" forty-one times with nothing on screen to say which host any of them came
		// from, which makes forty-one real findings collectively useless.
		sig := Signal{
			Family: "host", Kind: "host_" + meta.kind, Severity: meta.severity,
			Title: meta.title + " on " + host, Detail: meta.detail,
			Evidence:   host,
			Confidence: "measured",
			DedupeKey:  signalHash("host_" + meta.kind + "|" + host),
		}
		if meta.kind == "robots" {
			if disallowed := robotsDisallowed(resp.Body); len(disallowed) > 0 {
				sig.Severity = "p2"
				sig.Evidence = host + ": " + strings.Join(disallowed, ", ")
				sig.Detail += fmt.Sprintf(" %d Disallow entry(s) found.", len(disallowed))
			}
		}
		out = append(out, sig)
	}

	// Source maps, retrieved once per bundle per host rather than once per endpoint that mentions
	// one. A retrievable map returns the original source, comments included.
	for _, sig := range t.Signals {
		if sig.Kind != "script_sourcemap" || r.exhausted() {
			continue
		}
		mapURL := resolveAgainst(t.URL, sig.Evidence)
		if mapURL == "" {
			continue
		}
		resp := r.get(mapURL, nil, material)
		if resp.Err == nil && resp.Status >= 200 && resp.Status < 300 &&
			strings.Contains(resp.Body[:minInt(400, len(resp.Body))], `"sources"`) {
			out = append(out, Signal{
				Family: "host", Kind: "host_sourcemap_retrievable", Severity: "p1",
				Title: "Source map is publicly retrievable",
				Detail: "The map returns the original, unminified source including comments and code " +
					"paths that are not reachable in the shipped bundle.",
				Evidence:   truncateEvidence(mapURL),
				Confidence: "measured",
				DedupeKey:  signalHash("host_sourcemap|" + mapURL),
			})
		}
		break // one per host is enough to establish whether maps are exposed
	}

	return out
}

func robotsDisallowed(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "disallow:") {
			continue
		}
		path := strings.TrimSpace(line[len("disallow:"):])
		if path != "" && path != "/" {
			out = append(out, path)
		}
		if len(out) >= 15 {
			break
		}
	}
	return out
}

func resolveAgainst(baseURL, ref string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(r)
	// Never leave the origin chasing a source map.
	if resolved.Host != base.Host {
		return ""
	}
	return resolved.String()
}

func isAPIShaped(t Tier1Target) bool {
	if strings.Contains(strings.ToLower(t.ContentType), "json") {
		return true
	}
	lower := strings.ToLower(t.URL)
	for _, hint := range apiPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func hasCORSHeaderSignal(t Tier1Target) bool {
	for _, s := range t.Signals {
		if s.Family == "cors" || s.Kind == "api_cors_wildcard_credentials" {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// LogTier1Summary records what the tier spent, so a partial run is legible.
func LogTier1Summary(sigs map[string][]Signal, notes []string) {
	n := 0
	for _, s := range sigs {
		n += len(s)
	}
	log.Printf("[INVESTIGATE] Tier 1 produced %d signal(s) across %d subject(s)", n, len(sigs))
	for _, note := range notes {
		log.Printf("[INVESTIGATE] Tier 1: %s", note)
	}
}
