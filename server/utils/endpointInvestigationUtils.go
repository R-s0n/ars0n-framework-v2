package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type EndpointInvestigationScan struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	ScopeTargetID string    `json:"scope_target_id"`
	Status        string    `json:"status"`
	TotalEndpoints int      `json:"total_endpoints"`
	ProcessedEndpoints int  `json:"processed_endpoints"`
	Result        *string   `json:"result"`
	Error         *string   `json:"error"`
	ExecutionTime *string   `json:"execution_time"`
	CreatedAt     time.Time `json:"created_at"`
}

type EndpointInvestigationResult struct {
	EndpointID      string                 `json:"endpoint_id"`
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"status_code"`
	SecurityHeaders SecurityHeaders        `json:"security_headers"`
	Cookies         []CookieInfo           `json:"cookies"`
	Technologies    []string               `json:"technologies"`
	Forms           []FormInfo             `json:"forms"`
	InputFields     []InputFieldInfo       `json:"input_fields"`
	Comments        []string               `json:"comments"`
	APIs            []string               `json:"apis"`
	Secrets         []SecretFinding        `json:"secrets"`
	Misconfigs      []string               `json:"misconfigurations"`
	Redirects       []RedirectInfo         `json:"redirects"`
	ResponseSize    int                    `json:"response_size"`
	ResponseTime    int64                  `json:"response_time_ms"`
	ContentType     string                 `json:"content_type"`
	Server          string                 `json:"server"`
	Title           string                 `json:"title"`
	CORS            *CORSInfo              `json:"cors"`
}

type SecurityHeaders struct {
	StrictTransportSecurity string `json:"strict_transport_security"`
	ContentSecurityPolicy   string `json:"content_security_policy"`
	XFrameOptions           string `json:"x_frame_options"`
	XContentTypeOptions     string `json:"x_content_type_options"`
	XXSSProtection          string `json:"x_xss_protection"`
	ReferrerPolicy          string `json:"referrer_policy"`
	PermissionsPolicy       string `json:"permissions_policy"`
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

	query := `SELECT id, url, method FROM consolidated_url_endpoints WHERE scope_target_id = $1 AND is_direct = true`
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

	var results []EndpointInvestigationResult
	for i, ep := range endpoints {
		log.Printf("[INFO] Investigating endpoint %d/%d: %s", i+1, len(endpoints), ep.URL)
		
		result := investigateEndpoint(ep.ID, ep.URL, ep.Method)
		results = append(results, result)
		
		UpdateEndpointInvestigationStatus(scanID, "running", len(endpoints), i+1, "", "", "")
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal results: %v", err)
		UpdateEndpointInvestigationStatus(scanID, "error", len(endpoints), len(endpoints), "", fmt.Sprintf("Failed to marshal results: %v", err), time.Since(startTime).String())
		return
	}

	UpdateEndpointInvestigationStatus(scanID, "success", len(endpoints), len(endpoints), string(resultJSON), "", time.Since(startTime).String())
	log.Printf("[INFO] Endpoint investigation completed for scope target %s", scopeTargetID)
}

func investigateEndpoint(endpointID, urlStr, method string) EndpointInvestigationResult {
	result := EndpointInvestigationResult{
		EndpointID:      endpointID,
		URL:             urlStr,
		Method:          method,
		Technologies:    []string{},
		Forms:           []FormInfo{},
		InputFields:     []InputFieldInfo{},
		Comments:        []string{},
		APIs:            []string{},
		Secrets:         []SecretFinding{},
		Misconfigs:      []string{},
		Redirects:       []RedirectInfo{},
		Cookies:         []CookieInfo{},
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

	reqStart := time.Now()
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create request for %s: %v", urlStr, err)
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
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
	result.Technologies = detectEndpointTechnologies(resp.Header, bodyStr)
	result.Forms = extractForms(bodyStr)
	result.InputFields = extractInputFields(bodyStr)
	result.Comments = extractComments(bodyStr)
	result.APIs = findAPIEndpoints(bodyStr)
	result.Secrets = findSecrets(bodyStr)
	result.Misconfigs = detectMisconfigurations(resp.Header, bodyStr)
	result.CORS = analyzeCORS(urlStr, resp.Header)

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

func detectEndpointTechnologies(headers http.Header, body string) []string {
	var techs []string
	seen := make(map[string]bool)

	addTech := func(tech string) {
		if !seen[tech] {
			techs = append(techs, tech)
			seen[tech] = true
		}
	}

	server := headers.Get("Server")
	if strings.Contains(server, "nginx") {
		addTech("Nginx")
	} else if strings.Contains(server, "Apache") {
		addTech("Apache")
	} else if strings.Contains(server, "IIS") {
		addTech("IIS")
	} else if strings.Contains(server, "cloudflare") {
		addTech("Cloudflare")
	}

	xPoweredBy := headers.Get("X-Powered-By")
	if strings.Contains(xPoweredBy, "PHP") {
		addTech("PHP")
	} else if strings.Contains(xPoweredBy, "ASP.NET") {
		addTech("ASP.NET")
	} else if strings.Contains(xPoweredBy, "Express") {
		addTech("Express.js")
	}

	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wordpress") {
		addTech("WordPress")
	}
	if strings.Contains(bodyLower, "drupal") {
		addTech("Drupal")
	}
	if strings.Contains(bodyLower, "joomla") {
		addTech("Joomla")
	}
	if strings.Contains(bodyLower, "react") || strings.Contains(body, "__NEXT_DATA__") {
		addTech("React")
	}
	if strings.Contains(body, "angular") || strings.Contains(body, "ng-app") {
		addTech("Angular")
	}
	if strings.Contains(body, "vue") || strings.Contains(body, "v-app") {
		addTech("Vue.js")
	}
	if strings.Contains(bodyLower, "jquery") {
		addTech("jQuery")
	}
	if strings.Contains(bodyLower, "bootstrap") {
		addTech("Bootstrap")
	}
	if strings.Contains(bodyLower, "tailwind") {
		addTech("Tailwind CSS")
	}

	return techs
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

func extractComments(body string) []string {
	var comments []string
	commentRegex := regexp.MustCompile(`<!--([\s\S]*?)-->|/\*([\s\S]*?)\*/|//(.*)`)
	matches := commentRegex.FindAllStringSubmatch(body, -1)
	
	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				comment := strings.TrimSpace(match[i])
				if len(comment) > 10 && len(comment) < 200 {
					comments = append(comments, comment)
					if len(comments) >= 20 {
						return comments
					}
				}
			}
		}
	}
	
	return comments
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

func findSecrets(body string) []SecretFinding {
	var secrets []SecretFinding
	
	patterns := map[string]*regexp.Regexp{
		"API Key":        regexp.MustCompile(`(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})`),
		"AWS Key":        regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		"Private Key":    regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		"JWT Token":      regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		"Google API":     regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		"Slack Token":    regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
		"GitHub Token":   regexp.MustCompile(`gh[ps]_[a-zA-Z0-9]{36}`),
		"Bearer Token":   regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`),
	}
	
	for secretType, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 0 {
				value := match[0]
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}
				secrets = append(secrets, SecretFinding{
					Type:  secretType,
					Value: maskSensitiveValue(value),
				})
				if len(secrets) >= 20 {
					return secrets
				}
			}
		}
	}
	
	return secrets
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
