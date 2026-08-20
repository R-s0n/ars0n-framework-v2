package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type EndpointInvestigationScan struct {
	ID                 string    `json:"id"`
	ScanID             string    `json:"scan_id"`
	ScopeTargetID      string    `json:"scope_target_id"`
	Status             string    `json:"status"`
	TotalEndpoints     int       `json:"total_endpoints"`
	ProcessedEndpoints int       `json:"processed_endpoints"`
	Result             *string   `json:"result"`
	Error              *string   `json:"error"`
	ExecutionTime      *string   `json:"execution_time"`
	CreatedAt          time.Time `json:"created_at"`
}

type EndpointInvestigationResult struct {
	EndpointID      string           `json:"endpoint_id"`
	URL             string           `json:"url"`
	Method          string           `json:"method"`
	StatusCode      int              `json:"status_code"`
	SecurityHeaders SecurityHeaders  `json:"security_headers"`
	Cookies         []CookieInfo     `json:"cookies"`
	Technologies    []string         `json:"technologies"`
	Forms           []FormInfo       `json:"forms"`
	InputFields     []InputFieldInfo `json:"input_fields"`
	Comments        []string         `json:"comments"`
	APIs            []string         `json:"apis"`
	Secrets         []SecretFinding  `json:"secrets"`
	Misconfigs      []string         `json:"misconfigurations"`
	Redirects       []RedirectInfo   `json:"redirects"`
	ResponseSize    int              `json:"response_size"`
	ResponseTime    int64            `json:"response_time_ms"`
	ContentType     string           `json:"content_type"`
	Server          string           `json:"server"`
	Title           string           `json:"title"`
	CORS            *CORSInfo        `json:"cors"`
	// Whether the probe carried captured credentials, and where they came from. Without this the
	// results are ambiguous: an empty page could be a real empty page or an unauthenticated one.
	Authenticated bool   `json:"authenticated"`
	AuthSource    string `json:"auth_source,omitempty"`
	// Set when the row recorded a write verb. That verb is characterised with GET, never sent, so
	// the result must not read as though the write surface was exercised.
	VerbNotReplayed string `json:"verb_not_replayed,omitempty"`

	// What was actually requested, when that differs from URL because observed parameters were
	// supplied. URL stays the canonical endpoint so the row still lines up with the consolidated
	// list; this says what the application was really asked.
	ProbedURL string `json:"probed_url,omitempty"`

	// The Tier 0 catalogue, plus the score that orders the list. Without the score, five thousand
	// endpoints arrive equally loud and the operator reads the first twenty alphabetically.
	Signals       []Signal               `json:"signals"`
	Frameworks    []FrameworkFingerprint `json:"frameworks"`
	InterestScore int                    `json:"interest_score"`
}

type SecurityHeaders struct {
	StrictTransportSecurity string   `json:"strict_transport_security"`
	ContentSecurityPolicy   string   `json:"content_security_policy"`
	XFrameOptions           string   `json:"x_frame_options"`
	XContentTypeOptions     string   `json:"x_content_type_options"`
	XXSSProtection          string   `json:"x_xss_protection"`
	ReferrerPolicy          string   `json:"referrer_policy"`
	PermissionsPolicy       string   `json:"permissions_policy"`
	Missing                 []string `json:"missing"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httponly"`
	SameSite string `json:"samesite"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
}

type FormInfo struct {
	Action  string   `json:"action"`
	Method  string   `json:"method"`
	Fields  []string `json:"fields"`
	HasFile bool     `json:"has_file"`
}

type InputFieldInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ID   string `json:"id"`
}

type SecretFinding struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type RedirectInfo struct {
	Location   string `json:"location"`
	StatusCode int    `json:"status_code"`
}

type CORSInfo struct {
	AllowOrigin      string   `json:"allow_origin"`
	AllowMethods     string   `json:"allow_methods"`
	AllowHeaders     string   `json:"allow_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	ExposeHeaders    string   `json:"expose_headers"`
	MaxAge           string   `json:"max_age"`
	Misconfigured    bool     `json:"misconfigured"`
	Issues           []string `json:"issues"`
}

// InvestigationEligibility is the single definition of which endpoints get investigated. It is
// Validate's ledger, not the raw endpoint table.
//
// It is a const rather than two copies because the combined run reports this count to the operator
// before phase 2 starts. A summary that says "312 endpoints investigated" while the runner actually
// selected a different set is worse than no summary: it is a number that looks measured.
//
// COALESCE(override_status, validation_status) so an operator override wins over the scan.
// validation_testable IS NULL passes deliberately. Unknown is not the same as ruled out, and a
// target that was never validated ('not_validated') must still be investigable. Restricting this to
// status = 'valid' would empty the phase entirely on a client-routed application, where every HTML
// response is honestly reported as unverified.spa_shell_ambiguous rather than valid.
//
// The destructive exclusion matters as much as the rest: Validate refuses to request those paths
// because a GET on them changes state on the target. GET /logout is the worst case, since it
// destroys the session and every endpoint measured after it comes back as a login wall.
const InvestigationEligibility = `
	scope_target_id = $1
	  AND deleted_at IS NULL
	  AND COALESCE(override_status, validation_status) <> 'ruled_out'
	  AND (validation_testable IS NULL OR validation_testable = TRUE)
	  AND COALESCE(content_class, 'unknown') <> 'static'
	  AND COALESCE(validation_reason_code,'') <> 'skipped.destructive_heuristic'`

// InvestigationHostExpr is the host the request will actually go to. The domain column is derived
// at consolidation time and disagrees with the URL on a small number of malformed rows, so the
// scope filter reads the URL instead.
//
// The trailing split on ':' strips the port. Without it the expression yields
// "host.example:8891" while the boundary holds "host.example", nothing matches, and the
// investigation phase silently finds zero eligible endpoints on any target not using a default
// port. That is a scope filter that excludes the target itself.
const InvestigationHostExpr = `split_part(split_part(split_part(url,'://',2),'/',1),':',1)`

// InvestigationEligibilityIn narrows eligibility to hosts this scan is allowed to contact. Used by
// both the runner and the count that describes it, so the two cannot disagree.
func InvestigationEligibilityIn(scope *ScanScope) string {
	return InvestigationEligibility + "\n  AND " + scope.InScopeHostSQL(InvestigationHostExpr)
}

func RunEndpointInvestigation(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO endpoint_investigation_scans (scan_id, scope_target_id, status) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, scopeTargetID, "pending")
	if err != nil {
		log.Printf("[ERROR] Failed to create endpoint investigation scan record: %v", err)
		http.Error(w, "Failed to create scan record", http.StatusInternalServerError)
		return
	}

	go ExecuteEndpointInvestigation(scanID, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteEndpointInvestigation(scanID, scopeTargetID string) {
	log.Printf("[INFO] Starting endpoint investigation for scope target %s (scan ID: %s)", scopeTargetID, scanID)
	startTime := time.Now()

	// Out-of-scope endpoints never enter the work list. ScanClient refuses them anyway, but Tier 0
	// below still uses a raw http.Client, so leaving them in would send real third-party traffic.
	scope := LoadScanScope(scopeTargetID)
	log.Printf("[INFO] Investigation confined to %s", scope.Describe())

	query := `
		SELECT id, url, method
		FROM consolidated_url_endpoints
		WHERE ` + InvestigationEligibilityIn(scope) + `
		ORDER BY interest_score DESC, is_direct DESC, id`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get endpoints: %v", err)
		UpdateEndpointInvestigationStatus(scanID, "error", 0, 0, "", fmt.Sprintf("Failed to get endpoints: %v", err), time.Since(startTime).String())
		return
	}
	defer rows.Close()

	var endpoints []struct {
		ID     string
		URL    string
		Method string
	}
	for rows.Next() {
		var ep struct {
			ID     string
			URL    string
			Method string
		}
		if err := rows.Scan(&ep.ID, &ep.URL, &ep.Method); err != nil {
			log.Printf("[ERROR] Failed to scan endpoint: %v", err)
			continue
		}
		endpoints = append(endpoints, ep)
	}

	if len(endpoints) == 0 {
		log.Printf("[INFO] No direct endpoints found for scope target %s", scopeTargetID)
		UpdateEndpointInvestigationStatus(scanID, "success", 0, 0, "[]", "", time.Since(startTime).String())
		return
	}

	UpdateEndpointInvestigationStatus(scanID, "running", len(endpoints), 0, "", "", "")

	// Replay the credentials the manual crawl recorded. Without this every endpoint is fetched
	// logged out, so an authenticated application is profiled entirely through its login wall:
	// same title, same headers, same forms, on every single endpoint.
	// The same host-scoped context validation uses, rather than a second implementation. The old one
	// picked a single capture for the whole target by recency alone, with no host match, so on a
	// corpus spanning several hosts whichever request happened to be recorded last decided the
	// credentials for all of them: a CDN cookie could be sent to the API host while the API's own
	// bearer token was never loaded, and every result row was still stamped authenticated. It also
	// could not see the Session Manager at all, so a token the operator had just refreshed was
	// ignored in favour of whatever the crawl happened to catch.
	authCtx := LoadScopedAuthContext(scopeTargetID)
	if authCtx.HasAny() {
		log.Printf("[INFO] Investigating with host-scoped credentials; each endpoint uses the material for its own host")
	} else {
		log.Printf("[INFO] No credentials for this target; investigating unauthenticated")
	}

	// Parameter values the crawl already observed, so reflection can be checked without sending a
	// canary or an extra request.
	observed := loadObservedParams(scopeTargetID)

	// The work list is rewritten to the URL that will actually be requested, so BOTH the Tier 0
	// catalogue and the Tier 1 differential ask a parameterised route with a parameter. The Tier 1
	// authorization comparison is worth nothing when both arms fetch a bare route that answers 400
	// either way. The canonical URL is kept aside so each result still names the endpoint the
	// consolidated list knows.
	observedQuery := loadObservedQueryParams(scopeTargetID)
	canonicalURL := make(map[string]string, len(endpoints))
	parameterised := 0
	for i := range endpoints {
		canonicalURL[endpoints[i].ID] = endpoints[i].URL
		probe := probeURLWithObservedParams(endpoints[i].URL, observedQuery[endpoints[i].ID])
		if probe != endpoints[i].URL {
			parameterised++
			endpoints[i].URL = probe
		}
	}
	if parameterised > 0 {
		log.Printf("[INFO] %d endpoint(s) probed with parameter values the crawl observed", parameterised)
	}

	var results []EndpointInvestigationResult
	perEndpoint := map[string][]Signal{}
	for i, ep := range endpoints {
		log.Printf("[INFO] Investigating endpoint %d/%d: %s", i+1, len(endpoints), ep.URL)

		result := investigateEndpoint(ep.ID, canonicalURL[ep.ID], ep.URL, ep.Method, authCtx, observed[ep.ID], scope)
		results = append(results, result)
		if len(result.Signals) > 0 {
			perEndpoint[ep.ID] = result.Signals
		}

		UpdateEndpointInvestigationStatus(scanID, "running", len(endpoints), i+1, "", "", "")
	}

	// Tier 1: the probes that cost a request. Paced by the same budget the Routing & WAF Probe
	// measured, ordered by what Tier 0 found, and stopped when the budget runs out.
	tier1Signals, tier1Notes := runInvestigationTier1(scopeTargetID, endpoints, results, authCtx, scope)
	LogTier1Summary(tier1Signals, tier1Notes)

	var hostFindings []Signal
	for key, sigs := range tier1Signals {
		if strings.HasPrefix(key, "host:") {
			hostFindings = append(hostFindings, sigs...)
			continue
		}
		for i := range results {
			if results[i].EndpointID == key {
				results[i].Signals = append(results[i].Signals, sigs...)
				perEndpoint[key] = results[i].Signals
			}
		}
	}

	// Anything true of most of the corpus is one fact about the application, not one finding per
	// endpoint. Promoting it leaves each endpoint carrying only what makes it different.
	targetFindings, kept := RollupSignals(perEndpoint)
	targetFindings = append(targetFindings, hostFindings...)
	for i := range results {
		results[i].Signals = kept[results[i].EndpointID]
		results[i].InterestScore = InterestScore(results[i].Signals)
		_, _ = dbPool.Exec(context.Background(),
			`UPDATE consolidated_url_endpoints SET interest_score = $1, investigated_at = NOW()
			 WHERE id = $2`, results[i].InterestScore, results[i].EndpointID)
	}
	if len(targetFindings) > 0 {
		log.Printf("[INFO] %d signal(s) applied to most of the corpus and were rolled up to the target",
			len(targetFindings))
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].InterestScore > results[j].InterestScore
	})

	payload := map[string]interface{}{
		"endpoints":       results,
		"target_findings": targetFindings,
		"tier1_notes":     tier1Notes,
	}
	resultJSON, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal results: %v", err)
		UpdateEndpointInvestigationStatus(scanID, "error", len(endpoints), len(endpoints), "", fmt.Sprintf("Failed to marshal results: %v", err), time.Since(startTime).String())
		return
	}

	UpdateEndpointInvestigationStatus(scanID, "success", len(endpoints), len(endpoints), string(resultJSON), "", time.Since(startTime).String())
	log.Printf("[INFO] Endpoint investigation completed for scope target %s", scopeTargetID)
}

// investigateEndpoint catalogues one endpoint. canonicalURL identifies it and is what the result
// reports; probeURL is what actually gets requested, and differs when observed parameters were
// supplied. Everything on the wire uses probeURL, including the scope check: the canonical URL is a
// label, not a destination.
func investigateEndpoint(endpointID, canonicalURL, probeURL, method string, authCtx *ScopedAuthContext,
	observedParams map[string]string, scope *ScanScope) EndpointInvestigationResult {
	urlStr := probeURL

	// Resolved per endpoint, because credentials are host-bound. Authenticated now means "this
	// request carried a credential", not "the target had one somewhere", which is what made every
	// row read authenticated even when nothing was attached to it.
	material, _ := authCtx.For(hostOf(urlStr))

	probed := ""
	if probeURL != canonicalURL {
		probed = probeURL
	}

	result := EndpointInvestigationResult{
		EndpointID:    endpointID,
		URL:           canonicalURL,
		ProbedURL:     probed,
		Method:        method,
		Authenticated: material != nil,
		AuthSource:    authMaterialSource(material),
		Technologies:  []string{},
		Forms:         []FormInfo{},
		InputFields:   []InputFieldInfo{},
		Comments:      []string{},
		APIs:          []string{},
		Secrets:       []SecretFinding{},
		Misconfigs:    []string{},
		Redirects:     []RedirectInfo{},
		Cookies:       []CookieInfo{},
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			for _, r := range via {
				if r.Response != nil {
					result.Redirects = append(result.Redirects, RedirectInfo{
						Location:   r.Response.Header.Get("Location"),
						StatusCode: r.Response.StatusCode,
					})
				}
			}
			return nil
		},
	}

	// The scope boundary again, because this function predates ScanClient and still builds its own
	// http.Client. Until that is unified, the check has to be repeated here rather than assumed.
	if scope != nil && !scope.AllowsURL(urlStr) {
		scope.Refuse(hostOf(urlStr))
		log.Printf("[INFO] Refusing out-of-scope endpoint %s", urlStr)
		return result
	}

	// Only ever GET, HEAD or OPTIONS.
	//
	// This used to pass the crawl-recorded verb straight through with the captured credentials
	// attached, so investigating a target whose manual crawl captured `DELETE /api/keys/7` sent a
	// real, authenticated DELETE at the target. Same for POST /invoices/{id}/send. A recorded verb
	// is now characterised, never replayed, and the result says so.
	if !allowedScanMethods[strings.ToUpper(method)] {
		result.VerbNotReplayed = method
		method = http.MethodGet
	}

	reqStart := time.Now()
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create request for %s: %v", urlStr, err)
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if applied, _ := material.Apply(req); !applied {
		// Recorded rather than assumed. A row that says authenticated when nothing went on the wire
		// is worse than one that admits it was anonymous.
		result.Authenticated = false
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to request %s: %v", urlStr, err)
		return result
	}
	defer resp.Body.Close()

	result.ResponseTime = time.Since(reqStart).Milliseconds()
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.Server = resp.Header.Get("Server")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read response body for %s: %v", urlStr, err)
		return result
	}

	result.ResponseSize = len(body)
	bodyStr := string(body)

	result.SecurityHeaders = analyzeSecurityHeaders(resp.Header)
	result.Cookies = analyzeCookies(resp.Cookies())
	result.Title = extractTitle(bodyStr)
	result.Forms = extractForms(bodyStr)
	result.InputFields = extractInputFields(bodyStr)
	result.APIs = findAPIEndpoints(bodyStr)
	result.Misconfigs = detectMisconfigurations(resp.Header, bodyStr)
	result.CORS = analyzeCORS(urlStr, resp.Header)

	// The Tier 0 catalogue. Everything here is computed from the response that was already read,
	// so it costs no extra requests and stays inside the measured rate budget.
	result.Signals = AnalyzeEndpoint(SignalInput{
		URL:            urlStr,
		Method:         method,
		Status:         resp.StatusCode,
		Header:         resp.Header,
		Body:           bodyStr,
		ContentType:    result.ContentType,
		Cookies:        resp.Cookies(),
		ObservedParams: observedParams,
		Authenticated:  result.Authenticated,
	})
	result.InterestScore = InterestScore(result.Signals)

	// Fingerprints carry evidence and a confidence now. The previous detector was fourteen
	// substring tests, one of which matched "vue" inside the word "value".
	result.Frameworks = DetectFrameworks(resp.Header, bodyStr, resp.Cookies())
	result.Technologies = nil
	for _, f := range result.Frameworks {
		label := f.Tech
		if f.Version != "" {
			label += " " + f.Version
		}
		result.Technologies = append(result.Technologies, label)
	}

	// Comments and secrets come from the catalogue so there is one implementation of each rather
	// than two that disagree.
	for _, sig := range result.Signals {
		switch sig.Family {
		case "comment":
			result.Comments = append(result.Comments, sig.Evidence)
		case "secret":
			result.Secrets = append(result.Secrets, SecretFinding{Type: sig.Kind, Value: sig.Evidence})
		}
	}

	return result
}

func analyzeSecurityHeaders(headers http.Header) SecurityHeaders {
	sh := SecurityHeaders{
		StrictTransportSecurity: headers.Get("Strict-Transport-Security"),
		ContentSecurityPolicy:   headers.Get("Content-Security-Policy"),
		XFrameOptions:           headers.Get("X-Frame-Options"),
		XContentTypeOptions:     headers.Get("X-Content-Type-Options"),
		XXSSProtection:          headers.Get("X-XSS-Protection"),
		ReferrerPolicy:          headers.Get("Referrer-Policy"),
		PermissionsPolicy:       headers.Get("Permissions-Policy"),
		Missing:                 []string{},
	}

	if sh.StrictTransportSecurity == "" {
		sh.Missing = append(sh.Missing, "Strict-Transport-Security")
	}
	if sh.ContentSecurityPolicy == "" {
		sh.Missing = append(sh.Missing, "Content-Security-Policy")
	}
	if sh.XFrameOptions == "" {
		sh.Missing = append(sh.Missing, "X-Frame-Options")
	}
	if sh.XContentTypeOptions == "" {
		sh.Missing = append(sh.Missing, "X-Content-Type-Options")
	}

	return sh
}

func analyzeCookies(cookies []*http.Cookie) []CookieInfo {
	var result []CookieInfo
	for _, cookie := range cookies {
		sameSite := "None"
		switch cookie.SameSite {
		case http.SameSiteDefaultMode:
			sameSite = "Default"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}

		result = append(result, CookieInfo{
			Name:     cookie.Name,
			Value:    maskSensitiveValue(cookie.Value),
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSite,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
		})
	}
	return result
}

func maskSensitiveValue(value string) string {
	if len(value) > 8 {
		return value[:4] + "..." + value[len(value)-4:]
	}
	return "***"
}

func extractForms(body string) []FormInfo {
	var forms []FormInfo
	formRegex := regexp.MustCompile(`<form[^>]*>[\s\S]*?</form>`)
	matches := formRegex.FindAllString(body, -1)

	for _, formHTML := range matches {
		form := FormInfo{
			Fields: []string{},
		}

		if actionMatch := regexp.MustCompile(`action=["']([^"']*)["']`).FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
		}
		if methodMatch := regexp.MustCompile(`method=["']([^"']*)["']`).FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		} else {
			form.Method = "GET"
		}

		inputRegex := regexp.MustCompile(`<input[^>]*name=["']([^"']*)["'][^>]*>`)
		inputMatches := inputRegex.FindAllStringSubmatch(formHTML, -1)
		for _, match := range inputMatches {
			if len(match) > 1 {
				form.Fields = append(form.Fields, match[1])
			}
		}

		form.HasFile = strings.Contains(formHTML, "type=\"file\"") || strings.Contains(formHTML, "type='file'")

		if len(form.Fields) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

func extractInputFields(body string) []InputFieldInfo {
	var fields []InputFieldInfo
	inputRegex := regexp.MustCompile(`<input[^>]*>`)
	matches := inputRegex.FindAllString(body, -1)

	for _, inputHTML := range matches {
		field := InputFieldInfo{}

		if nameMatch := regexp.MustCompile(`name=["']([^"']*)["']`).FindStringSubmatch(inputHTML); len(nameMatch) > 1 {
			field.Name = nameMatch[1]
		}
		if typeMatch := regexp.MustCompile(`type=["']([^"']*)["']`).FindStringSubmatch(inputHTML); len(typeMatch) > 1 {
			field.Type = typeMatch[1]
		} else {
			field.Type = "text"
		}
		if idMatch := regexp.MustCompile(`id=["']([^"']*)["']`).FindStringSubmatch(inputHTML); len(idMatch) > 1 {
			field.ID = idMatch[1]
		}

		if field.Name != "" || field.ID != "" {
			fields = append(fields, field)
		}
	}

	return fields
}

func findAPIEndpoints(body string) []string {
	var apis []string
	seen := make(map[string]bool)

	apiRegex := regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_\-{}:]+)["']`)
	matches := apiRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			apis = append(apis, match[1])
			seen[match[1]] = true
			if len(apis) >= 50 {
				break
			}
		}
	}

	return apis
}

func detectMisconfigurations(headers http.Header, body string) []string {
	var misconfigs []string

	if headers.Get("Access-Control-Allow-Origin") == "*" && headers.Get("Access-Control-Allow-Credentials") == "true" {
		misconfigs = append(misconfigs, "CORS: Wildcard origin with credentials enabled")
	}

	if headers.Get("X-Frame-Options") == "" && headers.Get("Content-Security-Policy") == "" {
		misconfigs = append(misconfigs, "Missing clickjacking protection")
	}

	if !strings.Contains(strings.ToLower(headers.Get("Content-Type")), "charset") {
		misconfigs = append(misconfigs, "Missing charset in Content-Type")
	}

	serverHeader := headers.Get("Server")
	if regexp.MustCompile(`\d+\.\d+`).MatchString(serverHeader) {
		misconfigs = append(misconfigs, "Server version exposed in headers")
	}

	xPoweredBy := headers.Get("X-Powered-By")
	if xPoweredBy != "" {
		misconfigs = append(misconfigs, fmt.Sprintf("X-Powered-By header exposes technology: %s", xPoweredBy))
	}

	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "stack trace") || strings.Contains(bodyLower, "exception") {
		if strings.Contains(bodyLower, "at line") || strings.Contains(bodyLower, "in file") {
			misconfigs = append(misconfigs, "Stack trace or debug information exposed")
		}
	}

	if strings.Contains(bodyLower, "debug = true") || strings.Contains(bodyLower, "debug mode") {
		misconfigs = append(misconfigs, "Debug mode might be enabled")
	}

	return misconfigs
}

func analyzeCORS(urlStr string, headers http.Header) *CORSInfo {
	allowOrigin := headers.Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		return nil
	}

	cors := &CORSInfo{
		AllowOrigin:      allowOrigin,
		AllowMethods:     headers.Get("Access-Control-Allow-Methods"),
		AllowHeaders:     headers.Get("Access-Control-Allow-Headers"),
		AllowCredentials: headers.Get("Access-Control-Allow-Credentials") == "true",
		ExposeHeaders:    headers.Get("Access-Control-Expose-Headers"),
		MaxAge:           headers.Get("Access-Control-Max-Age"),
		Issues:           []string{},
	}

	if allowOrigin == "*" {
		cors.Misconfigured = true
		if cors.AllowCredentials {
			cors.Issues = append(cors.Issues, "Critical: Wildcard origin with credentials enabled")
		} else {
			cors.Issues = append(cors.Issues, "Warning: Wildcard origin allows any domain")
		}
	}

	if allowOrigin != "*" && strings.Contains(allowOrigin, "null") {
		cors.Misconfigured = true
		cors.Issues = append(cors.Issues, "Allows 'null' origin (exploitable)")
	}

	if cors.AllowMethods != "" && (strings.Contains(cors.AllowMethods, "*") || strings.Contains(strings.ToUpper(cors.AllowMethods), "DELETE")) {
		cors.Issues = append(cors.Issues, "Potentially dangerous methods allowed")
	}

	return cors
}

func UpdateEndpointInvestigationStatus(scanID, status string, totalEndpoints, processedEndpoints int, result, errorMsg, execTime string) {
	query := `UPDATE endpoint_investigation_scans 
	          SET status = $1, total_endpoints = $2, processed_endpoints = $3, result = $4, error = $5, execution_time = $6 
	          WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, totalEndpoints, processedEndpoints, result, errorMsg, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update endpoint investigation scan status: %v", err)
	}
}

func GetEndpointInvestigationStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan EndpointInvestigationScan
	query := `SELECT scan_id, scope_target_id, status, total_endpoints, processed_endpoints, result, error, execution_time, created_at 
	          FROM endpoint_investigation_scans WHERE scan_id = $1`

	var result, errorMsg, execTime *string
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.ScopeTargetID, &scan.Status, &scan.TotalEndpoints, &scan.ProcessedEndpoints,
		&result, &errorMsg, &execTime, &scan.CreatedAt,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to get endpoint investigation scan status: %v", err)
		http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		return
	}

	scan.Result = result
	scan.Error = errorMsg
	scan.ExecutionTime = execTime

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetEndpointInvestigationResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT result FROM endpoint_investigation_scans 
	          WHERE scope_target_id = $1 AND status = 'success' 
	          ORDER BY created_at DESC LIMIT 1`

	var resultJSON *string
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&resultJSON)
	if err != nil {
		log.Printf("[ERROR] Failed to get endpoint investigation results: %v", err)
		http.Error(w, "No investigation results found", http.StatusNotFound)
		return
	}

	if resultJSON == nil {
		http.Error(w, "No investigation results found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(*resultJSON))
}

// loadObservedParams returns, per endpoint id, the parameter values discovery actually saw.
//
// These are what the reflection check looks for in the body that has already been read. Nothing is
// injected and no extra request is sent: this only reports that a value the application was
// genuinely given comes back in its own response, which is the precondition for injection rather
// than evidence of it.
// probeURLWithObservedParams gives a parameterised endpoint a value to answer with.
//
// Consolidation stores /catalog/product?productId=8 as the endpoint /catalog/product with productId
// recorded as a parameter. That is right for identity and wrong for probing: fetched bare the route
// answers 400 with an empty error page, so it yields no forms, no reflections, no framework
// fingerprint and no cookies, and scores 0.
//
// Measured on ginandjuice.shop 2026-08-19: /order/details, /catalog/product and /blog/post all
// scored 0 while third-party JavaScript bundles scored 160, so the three endpoints carrying the
// enumerable identifiers ranked below every copy of React in the corpus. interest_score is what the
// list is ordered by and what a capped run would keep, so the ordering was inverted exactly where it
// mattered.
//
// A URL that already carries a query string is left alone: what the crawl recorded beats anything
// reconstructed from it. The values come from the crawl too, so this sends what the application
// itself sent rather than a guess.
func probeURLWithObservedParams(rawURL string, queryParams map[string]string) string {
	if len(queryParams) == 0 {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery != "" {
		return rawURL
	}

	// Sorted, so one endpoint produces the same request on every run and two scans stay comparable.
	names := make([]string, 0, len(queryParams))
	for name := range queryParams {
		names = append(names, name)
	}
	sort.Strings(names)

	query := parsed.Query()
	for _, name := range names {
		query.Set(name, queryParams[name])
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// loadObservedQueryParams is loadObservedParams narrowed to values that travel in the QUERY STRING.
//
// Separate because the two feed different things. loadObservedParams feeds reflection checking and
// wants every parameter whatever it rode in; this one builds a URL and must not put a body field
// there. /catalog/product/stock records storeId and productId as BODY parameters, and appending
// those to the query would fabricate a request the application never receives.
func loadObservedQueryParams(scopeTargetID string) map[string]map[string]string {
	out := map[string]map[string]string{}

	rows, err := dbPool.Query(context.Background(), `
		SELECT p.endpoint_id, p.param_name, p.example_values
		FROM consolidated_url_parameters p
		JOIN consolidated_url_endpoints e ON e.id = p.endpoint_id
		WHERE e.scope_target_id = $1 AND p.param_type = 'query'`, scopeTargetID)
	if err != nil {
		return out
	}
	defer rows.Close()

	for rows.Next() {
		var endpointID, name string
		var valuesJSON []byte
		if rows.Scan(&endpointID, &name, &valuesJSON) != nil {
			continue
		}
		var values []string
		if json.Unmarshal(valuesJSON, &values) != nil || len(values) == 0 {
			continue
		}
		if strings.TrimSpace(name) == "" || strings.TrimSpace(values[0]) == "" {
			continue
		}
		if out[endpointID] == nil {
			out[endpointID] = map[string]string{}
		}
		out[endpointID][name] = values[0]
	}
	return out
}

func loadObservedParams(scopeTargetID string) map[string]map[string]string {
	out := map[string]map[string]string{}

	rows, err := dbPool.Query(context.Background(), `
		SELECT p.endpoint_id, p.param_name, p.example_values
		FROM consolidated_url_parameters p
		JOIN consolidated_url_endpoints e ON e.id = p.endpoint_id
		WHERE e.scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return out
	}
	defer rows.Close()

	for rows.Next() {
		var endpointID, name string
		var valuesJSON []byte
		if rows.Scan(&endpointID, &name, &valuesJSON) != nil {
			continue
		}
		var values []string
		if json.Unmarshal(valuesJSON, &values) != nil || len(values) == 0 {
			continue
		}
		if out[endpointID] == nil {
			out[endpointID] = map[string]string{}
		}
		out[endpointID][name] = values[0]
	}
	return out
}

// runInvestigationTier1 builds the Tier 1 work list and runs it under the measured rate budget.
//
// Only endpoints Validate called valid are eligible for the differential: comparing an
// authenticated and an anonymous fetch of a catch-all page says nothing about authorization.
func runInvestigationTier1(scopeTargetID string, endpoints []struct {
	ID     string
	URL    string
	Method string
}, results []EndpointInvestigationResult, authCtx *ScopedAuthContext,
	scope *ScanScope) (map[string][]Signal, []string) {

	probe := LoadProbeContext(scopeTargetID)
	rps, concurrency := probe.EffectiveRate()

	_, host, _ := ScopeTargetBase(scopeTargetID)
	budget := NewHostBudget()
	budget.Acquire(host, rps, concurrency, "waf_probe")

	// Validate's verdicts decide who is eligible. Without them everything is 'not_validated',
	// which still qualifies, so a target that was never validated is not silently skipped.
	verdicts := map[string]string{}
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, COALESCE(override_status, validation_status, 'not_validated')
		FROM consolidated_url_endpoints WHERE scope_target_id = $1`, scopeTargetID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, verdict string
			if rows.Scan(&id, &verdict) == nil {
				verdicts[id] = verdict
			}
		}
	}

	byID := map[string]*EndpointInvestigationResult{}
	for i := range results {
		byID[results[i].EndpointID] = &results[i]
	}

	var targets []Tier1Target
	for _, ep := range endpoints {
		res, ok := byID[ep.ID]
		if !ok || res.StatusCode == 0 {
			continue
		}
		verdict := verdicts[ep.ID]
		if verdict == "not_validated" {
			verdict = validationStatusValid // never validated is not evidence against it
		}
		targets = append(targets, Tier1Target{
			EndpointID:    ep.ID,
			URL:           ep.URL,
			Method:        ep.Method,
			Score:         res.InterestScore,
			Status:        verdict,
			ContentType:   res.ContentType,
			Signals:       res.Signals,
			Authenticated: res.Authenticated,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	cfg := DefaultTier1Config()
	cfg.MaxRequests = Tier1BudgetFor(len(targets))

	return RunTier1(ctx, budget, LoadScopedAuthContext(scopeTargetID), cfg,
		targets, ResponseFingerprint{}, false, scope)
}
