package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type DiscoveredEndpoint struct {
	ID             string
	ScanID         string
	ScanType       string
	ScopeTargetID  string
	URL            string
	Domain         string
	Path           string
	NormalizedPath string
	StatusCode     int
	IsDirect       bool
	Parameters     []EndpointParameter
}

type EndpointParameter struct {
	Type         string
	Name         string
	ExampleValue string
	Position     int
}

func extractDomain(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func stripQueryParams(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return parsedURL.String()
}

func isPathParameter(segment string) bool {
	if segment == "" {
		return false
	}

	if len(segment) >= 8 && isAllDigits(segment) {
		return true
	}

	if len(segment) == 36 && strings.Count(segment, "-") == 4 {
		return true
	}

	if len(segment) == 32 && isAllHex(segment) {
		return true
	}

	if len(segment) >= 20 && isAlphanumeric(segment) {
		digitCount := 0
		for _, char := range segment {
			if char >= '0' && char <= '9' {
				digitCount++
			}
		}
		if float64(digitCount)/float64(len(segment)) > 0.5 {
			return true
		}
	}

	return false
}

func isAllDigits(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func isAllHex(s string) bool {
	for _, char := range s {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func isAlphanumeric(s string) bool {
	for _, char := range s {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
			return false
		}
	}
	return true
}

func normalizePathParameters(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	path := parsedURL.Path
	if path == "" || path == "/" {
		return urlStr
	}

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != "" && isPathParameter(segment) {
			segments[i] = "{id}"
		}
	}

	parsedURL.Path = strings.Join(segments, "/")
	return parsedURL.String()
}

func fetchStatusCode(urlStr string) int {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	send := func(method string) (int, error) {
		req, err := http.NewRequest(method, urlStr, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	status, err := send(http.MethodHead)
	if err != nil {
		return 0
	}

	// Fall back to GET when the server REFUSES the verb, not merely when the request could not be
	// built. The old fallback was on http.NewRequest failing, which for a URL that already parsed
	// never happens, so a target that answers 405 to HEAD had every application route recorded as
	// 405 while its static files recorded 200. Measured on ginandjuice.shop 2026-08-19: /, /about,
	// /login and /catalog/product?productId=N all read 405, which is not the status a GET returns
	// and is not what the operator is being shown the column for.
	if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		if getStatus, getErr := send(http.MethodGet); getErr == nil {
			return getStatus
		}
	}

	return status
}

func enrichURLsWithStatusCodes(urls []string) map[string]int {
	statusCodes := make(map[string]int)

	log.Printf("[INFO] Fetching status codes for %d URLs", len(urls))

	for i, urlStr := range urls {
		if i > 0 && i%10 == 0 {
			log.Printf("[INFO] Progress: %d/%d URLs checked", i, len(urls))
		}

		statusCode := fetchStatusCode(urlStr)
		statusCodes[urlStr] = statusCode

		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("[INFO] Completed fetching status codes for %d URLs", len(urls))
	return statusCodes
}

func formatURLsWithStatusCodes(urls []string, statusCodes map[string]int) (string, string) {
	var urlList []string
	statusCodeMap := make(map[string]interface{})

	for _, urlStr := range urls {
		urlList = append(urlList, urlStr)
		statusCode := statusCodes[urlStr]
		if statusCode > 0 {
			statusCodeMap[urlStr] = statusCode
		} else {
			statusCodeMap[urlStr] = nil
		}
	}

	result := strings.Join(urlList, "\n")
	statusCodeJSON, _ := json.Marshal(statusCodeMap)

	return result, string(statusCodeJSON)
}

func isImageFile(urlStr string) bool {
	imageExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".bmp",
		".webp", ".tiff", ".tif", ".avif", ".apng", ".jfif",
	}

	lowerURL := strings.ToLower(urlStr)
	for _, ext := range imageExtensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
		if strings.Contains(lowerURL, ext+"?") {
			return true
		}
	}
	return false
}

func isStaticAsset(urlStr string) bool {
	staticExtensions := []string{
		".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".map", ".json", ".xml", ".txt",
	}

	lowerURL := strings.ToLower(urlStr)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
		if strings.Contains(lowerURL, ext+"?") {
			return true
		}
	}
	return false
}

func isValidPath(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	path := parsedURL.Path

	if path == "/" {
		return true
	}

	if strings.Contains(path, "http://") || strings.Contains(path, "https://") {
		return false
	}

	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return false
	}

	if len(decodedPath) > 200 {
		return false
	}

	invalidPatterns := []string{
		"\\n", "\n", "\\", "/*", ").*", "&quot", "%5Cn", "%5C",
		"<%", "%>", "<script", "javascript:", "data:", "vbscript:",
		"%22", "%29", "%3C", "%3E", "<0>",
	}
	for _, pattern := range invalidPatterns {
		if strings.Contains(decodedPath, pattern) || strings.Contains(path, pattern) {
			return false
		}
	}

	specialCharCount := 0
	for _, char := range decodedPath {
		if char < 32 || char > 126 {
			specialCharCount++
		}
	}
	if specialCharCount > len(decodedPath)/3 {
		return false
	}

	if len(decodedPath) > 1 && !strings.HasPrefix(decodedPath, "/") {
		return false
	}

	pathSegments := strings.Split(strings.Trim(decodedPath, "/"), "/")

	for _, segment := range pathSegments {
		if segment == "" {
			continue
		}

		if strings.HasPrefix(segment, "[") || strings.HasPrefix(segment, ",") ||
			strings.HasPrefix(segment, ")") || strings.HasSuffix(segment, ",") ||
			strings.HasSuffix(segment, "-") && len(segment) > 1 {
			return false
		}

		if strings.HasPrefix(segment, ".") && len(segment) > 1 {
			restOfSegment := segment[1:]
			if restOfSegment != "env" && restOfSegment != "git" &&
				!strings.HasPrefix(restOfSegment, "well-known") {
				firstChar := rune(restOfSegment[0])
				if firstChar >= 'A' && firstChar <= 'Z' {
					return false
				}
				if len(restOfSegment) <= 4 && (firstChar < 'a' || firstChar > 'z') {
					return false
				}
			}
		}

		containsColon := strings.Contains(segment, ":")
		containsSpace := strings.Contains(segment, " ")
		containsComma := strings.Contains(segment, ",")
		containsPercent := strings.Contains(segment, "%")

		specialCount := 0
		if containsColon {
			specialCount++
		}
		if containsSpace {
			specialCount++
		}
		if containsComma {
			specialCount++
		}
		if containsPercent {
			specialCount++
		}

		if specialCount >= 2 {
			return false
		}
	}

	firstSegment := pathSegments[0]
	if len(pathSegments) == 1 && len(firstSegment) <= 2 && firstSegment != "" {
		if !strings.HasPrefix(firstSegment, ".") {
			isNumber := true
			for _, char := range firstSegment {
				if char < '0' || char > '9' {
					isNumber = false
					break
				}
			}
			if isNumber {
				return false
			}
		}
	}

	validPathChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./~:@!$&'()*+,;="
	validCount := 0
	for _, char := range path {
		if strings.ContainsRune(validPathChars, char) {
			validCount++
		}
	}
	if len(path) > 1 && float64(validCount)/float64(len(path)) < 0.6 {
		return false
	}

	return true
}

func filterURLsByDomain(urls []string, targetDomain string) []string {
	var filtered []string
	for _, urlStr := range urls {
		domain := extractDomain(urlStr)
		if domain == targetDomain {
			filtered = append(filtered, urlStr)
		}
	}
	return filtered
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	frequencies := make(map[rune]int)
	for _, char := range s {
		frequencies[char]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range frequencies {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

func extractQueryParameters(urlStr string) []EndpointParameter {
	var params []EndpointParameter

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		exampleValue := ""
		if len(values) > 0 {
			exampleValue = values[0]
		}
		params = append(params, EndpointParameter{
			Type:         "query",
			Name:         key,
			ExampleValue: exampleValue,
		})
	}

	return params
}

func detectPathParametersByEntropy(urls []string, minGroupSize int) map[int]bool {
	if len(urls) < minGroupSize {
		return nil
	}

	parsedURLs := make([]*url.URL, 0, len(urls))
	for _, urlStr := range urls {
		parsed, err := url.Parse(urlStr)
		if err == nil {
			parsedURLs = append(parsedURLs, parsed)
		}
	}

	if len(parsedURLs) < minGroupSize {
		return nil
	}

	segmentCounts := make(map[int]int)
	maxSegments := 0

	for _, parsed := range parsedURLs {
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		segmentCount := len(segments)
		segmentCounts[segmentCount]++
		if segmentCount > maxSegments {
			maxSegments = segmentCount
		}
	}

	var commonSegmentCount int
	for count, freq := range segmentCounts {
		if freq > len(parsedURLs)/2 {
			commonSegmentCount = count
			break
		}
	}

	if commonSegmentCount == 0 {
		commonSegmentCount = maxSegments
	}

	segmentValues := make(map[int]map[string]int)
	for i := 0; i < commonSegmentCount; i++ {
		segmentValues[i] = make(map[string]int)
	}

	for _, parsed := range parsedURLs {
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for i := 0; i < commonSegmentCount && i < len(segments); i++ {
			segmentValues[i][segments[i]]++
		}
	}

	paramPositions := make(map[int]bool)

	for position, values := range segmentValues {
		uniqueCount := len(values)
		totalCount := 0
		for _, count := range values {
			totalCount += count
		}

		uniqueRatio := float64(uniqueCount) / float64(totalCount)

		if uniqueRatio > 0.7 && uniqueCount >= minGroupSize {

			entropySum := 0.0
			for segment := range values {
				entropySum += calculateEntropy(segment)
			}
			avgEntropy := entropySum / float64(uniqueCount)

			if avgEntropy > 2.0 ||
				(uniqueCount > len(parsedURLs)/2 && avgEntropy > 1.5) ||
				(len(values) > 0 && isPathParameterPattern(values)) {
				paramPositions[position] = true
			}
		}
	}

	return paramPositions
}

func isPathParameterPattern(segments map[string]int) bool {
	for segment := range segments {
		if isPathParameter(segment) {
			return true
		}

		if strings.HasPrefix(segment, "SAP_") ||
			strings.Contains(segment, "-") && len(segment) > 10 ||
			len(segment) > 15 {
			return true
		}
	}
	return false
}

func normalizePathWithDetectedParams(urlStr string, paramPositions map[int]bool) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	segments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

	for position := range paramPositions {
		if position < len(segments) {
			segments[position] = "{id}"
		}
	}

	parsedURL.Path = "/" + strings.Join(segments, "/")
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return parsedURL.String()
}

func processURLsWithParameters(urls []string, targetDomain, scanID, scanType, scopeTargetID string) ([]DiscoveredEndpoint, error) {
	log.Printf("[INFO] Processing %d URLs with parameter detection", len(urls))

	directURLs := make([]string, 0)
	adjacentURLs := make([]string, 0)

	for _, urlStr := range urls {
		domain := extractDomain(urlStr)
		if domain == targetDomain {
			directURLs = append(directURLs, urlStr)
		} else if domain != "" {
			adjacentURLs = append(adjacentURLs, urlStr)
		}
	}

	log.Printf("[INFO] Found %d direct URLs and %d adjacent URLs", len(directURLs), len(adjacentURLs))

	allEndpoints := make([]DiscoveredEndpoint, 0)

	allEndpoints = append(allEndpoints, processURLGroup(directURLs, true, scanID, scanType, scopeTargetID)...)
	allEndpoints = append(allEndpoints, processURLGroup(adjacentURLs, false, scanID, scanType, scopeTargetID)...)

	return allEndpoints, nil
}

func processURLGroup(urls []string, isDirect bool, scanID, scanType, scopeTargetID string) []DiscoveredEndpoint {
	if len(urls) == 0 {
		return nil
	}

	endpoints := make([]DiscoveredEndpoint, 0)
	processedURLs := make(map[string]bool)

	// One loop, because there was never more than one behaviour. This used to group URLs by shape
	// and branch on whether a group held three or more, with the two branches byte-identical: the
	// grouping was computed and thrown away, extractPathParameters was never called from anywhere,
	// and normalized_path was assigned endpoint.Path unconditionally. The Katana results modal
	// showed that value under a "Normalized" heading beside an always-empty parameter list, which
	// reads as "this tool found no path parameters" rather than "this tool never looked".
	//
	// Real path templating is not missing from the framework, it just lives further down: consolidation
	// derives TemplatedPath and TemplateKey in endpointIdentity.go and groups /api/orders/8842719 and
	// /api/orders/8842720 there. Discovery stores what it saw, consolidation decides what it means.
	for _, urlStr := range urls {
		if processedURLs[urlStr] {
			continue
		}
		processedURLs[urlStr] = true

		endpoint := createEndpoint(urlStr, scanID, scanType, scopeTargetID, isDirect)
		endpoint.NormalizedPath = endpoint.Path
		endpoint.Parameters = append(endpoint.Parameters, extractQueryParameters(urlStr)...)
		endpoints = append(endpoints, endpoint)
	}

	log.Printf("[INFO] Fetching status codes for %d endpoints (isDirect=%v)", len(endpoints), isDirect)

	for i := range endpoints {
		endpoints[i].StatusCode = fetchStatusCode(endpoints[i].URL)
		if i > 0 && i%10 == 0 {
			log.Printf("[INFO] Status code progress: %d/%d", i, len(endpoints))
		}
		time.Sleep(100 * time.Millisecond)
	}

	return endpoints
}

func createEndpoint(urlStr, scanID, scanType, scopeTargetID string, isDirect bool) DiscoveredEndpoint {
	return DiscoveredEndpoint{
		ScanID:        scanID,
		ScanType:      scanType,
		ScopeTargetID: scopeTargetID,
		URL:           urlStr,
		Domain:        extractDomain(urlStr),
		Path:          extractPath(urlStr),
		IsDirect:      isDirect,
		Parameters:    make([]EndpointParameter, 0),
	}
}

func extractPath(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "/"
	}
	path := parsedURL.Path
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func storeDiscoveredEndpoints(endpoints []DiscoveredEndpoint) error {
	for _, endpoint := range endpoints {
		endpointID := uuid.New().String()

		query := `INSERT INTO discovered_endpoints 
			(id, scan_id, scan_type, scope_target_id, url, domain, path, normalized_path, status_code, is_direct)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (scan_id, url) DO UPDATE SET
				status_code = EXCLUDED.status_code,
				normalized_path = EXCLUDED.normalized_path
			RETURNING id`

		err := dbPool.QueryRow(
			context.Background(),
			query,
			endpointID,
			endpoint.ScanID,
			endpoint.ScanType,
			endpoint.ScopeTargetID,
			endpoint.URL,
			endpoint.Domain,
			endpoint.Path,
			endpoint.NormalizedPath,
			endpoint.StatusCode,
			endpoint.IsDirect,
		).Scan(&endpointID)

		if err != nil {
			log.Printf("[ERROR] Failed to store endpoint %s: %v", endpoint.URL, err)
			continue
		}

		for _, param := range endpoint.Parameters {
			paramID := uuid.New().String()
			paramQuery := `INSERT INTO endpoint_parameters 
				(id, endpoint_id, param_type, param_name, example_value, position)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (endpoint_id, param_type, param_name, position) DO NOTHING`

			_, err := dbPool.Exec(
				context.Background(),
				paramQuery,
				paramID,
				endpointID,
				param.Type,
				param.Name,
				param.ExampleValue,
				param.Position,
			)

			if err != nil {
				log.Printf("[ERROR] Failed to store parameter %s for endpoint %s: %v", param.Name, endpoint.URL, err)
			}
		}
	}

	log.Printf("[INFO] Successfully stored %d endpoints with parameters", len(endpoints))
	return nil
}

func RunKatanaURLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" {
		http.Error(w, "Invalid request body. `url` is required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, targetURL).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s", targetURL)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO katana_url_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create Katana URL scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseKatanaURLScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// buildKatanaCommand turns the stored config into a command line. Kept separate from the launcher
// so the mapping from setting to flag is one readable block: a rate the probe measured has to end
// up as `-rl` or it did nothing, and that is easy to lose inside a scan function.
func buildKatanaCommand(crawlURL string, cfg KatanaURLConfig, scopeTargetID string) []string {
	cmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-katana-1",
		"katana",
		"-u", crawlURL,
		"-silent",
		"-nc",
	}
	add := func(args ...string) { cmd = append(cmd, args...) }

	if cfg.Depth > 0 {
		add("-d", strconv.Itoa(cfg.Depth))
	}
	if cfg.Parallelism > 0 {
		add("-p", strconv.Itoa(cfg.Parallelism))
	}
	if cfg.Concurrency > 0 {
		add("-c", strconv.Itoa(cfg.Concurrency))
	}
	// Zero means "no cap", which is katana's own default of 150/s. A measured rate lands here.
	if cfg.RateLimit > 0 {
		add("-rl", strconv.Itoa(cfg.RateLimit))
	}
	if cfg.Timeout > 0 {
		add("-timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.Retry > 0 {
		add("-retry", strconv.Itoa(cfg.Retry))
	}
	if cfg.CrawlDurationS > 0 {
		add("-ct", fmt.Sprintf("%ds", cfg.CrawlDurationS))
	}
	if cfg.MaxResponseSize > 0 {
		add("-mrs", strconv.Itoa(cfg.MaxResponseSize))
	}
	if cfg.JSCrawl {
		add("-jc")
	}
	if cfg.JSLuice {
		add("-jsl")
	}
	if cfg.KnownFiles != "" {
		add("-kf", cfg.KnownFiles)
	}
	if cfg.FieldScope != "" {
		add("-fs", cfg.FieldScope)
	}
	if cfg.ExtensionFilter != "" {
		add("-ef", cfg.ExtensionFilter)
	}
	if cfg.IgnoreQueryParams {
		add("-iqp")
	}
	if cfg.AutoFormFill {
		add("-aff")
	}
	if cfg.Headless {
		add("-hl")
	}
	if cfg.XHRExtraction {
		add("-xhr")
	}
	if cfg.Proxy != "" {
		add("-proxy", cfg.Proxy)
	}

	headers := append([]NameVal{}, cfg.Headers...)
	if cfg.UseFFUFAuth {
		authHeaders, cookies := ffufAuthMaterial(scopeTargetID)
		headers = append(headers, authHeaders...)
		if strings.TrimSpace(cookies) != "" {
			headers = append(headers, NameVal{Name: "Cookie", Value: cookies})
		}
	}
	for _, h := range headers {
		if strings.TrimSpace(h.Name) == "" {
			continue
		}
		add("-H", fmt.Sprintf("%s:%s", h.Name, h.Value))
	}

	return cmd
}

func ExecuteAndParseKatanaURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[INFO] Starting Katana URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		log.Printf("[ERROR] Failed to extract domain from target URL: %s", targetURL)
		UpdateKatanaURLScanStatus(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Target domain for filtering: %s", targetDomain)

	cfg := LoadKatanaURLConfig(scopeTargetID)
	crawlURL := targetURL
	if strings.TrimSpace(cfg.BaseURL) != "" {
		// Set by the probe when the configured URL redirects elsewhere: crawling the pre-redirect
		// host means every result belongs to a site the operator is not testing.
		crawlURL = cfg.BaseURL
	}

	dockerCmd := buildKatanaCommand(crawlURL, cfg, scopeTargetID)

	// Bound the crawl so a hung target cannot leave the scan stuck forever.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[ERROR] Katana URL scan timed out after 20m for %s", targetURL)
			UpdateKatanaURLScanStatus(scanID, "error", "", "Katana scan timed out after 20 minutes", strings.Join(dockerCmd, " "), execTime)
			return
		}
		log.Printf("[ERROR] Katana URL scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateKatanaURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs", len(lines))

	var cleanURLs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cleanURLs = append(cleanURLs, line)
	}

	log.Printf("[INFO] Processing %d URLs (no filtering applied)", len(cleanURLs))

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "katana", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to process URLs with parameters: %v", err)
		UpdateKatanaURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[ERROR] Failed to store discovered endpoints: %v", err)
		UpdateKatanaURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	directCount := 0
	adjacentCount := 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			directCount++
		} else {
			adjacentCount++
		}
	}

	resultSummary := fmt.Sprintf("Found %d direct endpoints and %d adjacent endpoints with parameters", directCount, adjacentCount)

	execTime = time.Since(startTime).String()
	log.Printf("[INFO] Katana URL scan completed in %s for %s", execTime, targetURL)

	UpdateKatanaURLScanStatus(scanID, "success", resultSummary, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateKatanaURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE katana_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Katana URL scan status: %v", err)
	}
}

func UpdateKatanaURLScanStatusWithCodes(scanID, status, result, errorMsg, command, execTime, statusCodeJSON string) {
	query := `UPDATE katana_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5, status_code = $6::jsonb WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, statusCodeJSON, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Katana URL scan status: %v", err)
	}
}

func GetKatanaURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code FROM katana_url_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
		StatusCode    *string   `json:"status_code"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to get Katana URL scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetKatanaURLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code
	          FROM katana_url_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Katana URL scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
			StatusCode    *string   `json:"status_code"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
			"status_code":    scan.StatusCode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunLinkFinderURLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" {
		http.Error(w, "Invalid request body. `url` is required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, targetURL).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s", targetURL)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO linkfinder_url_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create LinkFinder URL scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseLinkFinderURLScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

type linkFinderInput struct {
	url      string
	isJSFile bool
}

// linkFinderInputs decides what LinkFinder is actually pointed at.
//
// This is the whole reason this tool has a config. LinkFinder is a regex over a body of text; run
// against a target URL with no -d it fetches one page and scans it, which on a modern SPA means
// scanning an empty shell and never opening a bundle. The `discovered_js` arm feeds it the .js
// URLs the crawlers and the manual crawl already found, which is the job it was built for.
func linkFinderInputs(scanURL, scopeTargetID string, cfg LinkFinderURLConfig) []linkFinderInput {
	var inputs []linkFinderInput

	if cfg.InputSource == "target" || cfg.InputSource == "both" || cfg.InputSource == "" {
		inputs = append(inputs, linkFinderInput{url: scanURL, isJSFile: false})
	}

	if cfg.InputSource == "discovered_js" || cfg.InputSource == "both" {
		limit := cfg.MaxJSFiles
		if limit <= 0 {
			limit = 50
		}
		for _, u := range discoveredJSURLs(scopeTargetID, limit) {
			inputs = append(inputs, linkFinderInput{url: u, isJSFile: true})
		}
	}

	return inputs
}

// discoveredJSURLs collects JavaScript assets that earlier steps already found, from both the
// crawlers' endpoint table and the manual crawl captures. Both are consulted because the manual
// crawl routinely reaches authenticated bundles no unauthenticated crawler will ever see.
func discoveredJSURLs(scopeTargetID string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, limit)

	// pgx panics rather than erroring on a nil pool, which would take the process down instead of
	// producing a scan that reports it found nothing to read.
	if dbPool == nil {
		log.Printf("[WARN] LinkFinder asked for discovered JS before the database was ready")
		return out
	}

	collect := func(query string) {
		rows, err := dbPool.Query(context.Background(), query, scopeTargetID, limit)
		if err != nil {
			log.Printf("[WARN] LinkFinder could not read discovered JS: %v", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var u string
			if rows.Scan(&u) != nil {
				continue
			}
			// Strip the query string so the same bundle under a dozen cache-busting values is
			// fetched once rather than a dozen times.
			base := u
			if i := strings.Index(base, "?"); i >= 0 {
				base = base[:i]
			}
			if seen[base] || len(out) >= limit {
				continue
			}
			seen[base] = true
			out = append(out, base)
		}
	}

	collect(`SELECT url FROM discovered_endpoints
	         WHERE scope_target_id = $1 AND url ~* '\.js($|\?)'
	         ORDER BY created_at DESC LIMIT $2`)
	collect(`SELECT url FROM manual_crawl_captures
	         WHERE scope_target_id = $1 AND url ~* '\.js($|\?)'
	         ORDER BY created_at DESC LIMIT $2`)

	return out
}

func buildLinkFinderCommand(in linkFinderInput, cfg LinkFinderURLConfig, scopeTargetID string) []string {
	cmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-linkfinder-1",
		"python3", "linkfinder.py",
		"-i", in.url,
		"-o", "cli",
	}
	// -d makes LinkFinder walk the page's script tags. It is meaningless against a .js file, which
	// is already the thing being read.
	if cfg.DomainMode && !in.isJSFile {
		cmd = append(cmd, "-d")
	}
	if cfg.Timeout > 0 {
		cmd = append(cmd, "-t", strconv.Itoa(cfg.Timeout))
	}
	if cfg.RegexFilter != "" {
		cmd = append(cmd, "-r", cfg.RegexFilter)
	}

	cookies := cfg.Cookies
	if cfg.UseFFUFAuth && strings.TrimSpace(cookies) == "" {
		// LinkFinder takes cookies but not headers, so a token carried in an Authorization header
		// cannot be passed. Authenticated bundles behind header auth stay out of reach.
		_, ffufCookies := ffufAuthMaterial(scopeTargetID)
		cookies = ffufCookies
	}
	if strings.TrimSpace(cookies) != "" {
		cmd = append(cmd, "-c", cookies)
	}

	return cmd
}

// parseLinkFinderOutput turns cli output into absolute URLs.
//
// Relative hits are resolved against the file they were found in, not against the site root: an
// endpoint written as `v1/users` inside /static/js/app.js means /static/js/v1/users to a browser,
// and resolving it to /v1/users invents an endpoint that does not exist. The previous parser
// dropped every such hit on the floor instead, which is why LinkFinder looked quiet.
func parseLinkFinderOutput(raw, foundIn, scanURL string, cfg LinkFinderURLConfig) []string {
	var out []string

	base, err := url.Parse(foundIn)
	if err != nil {
		base, err = url.Parse(scanURL)
		if err != nil {
			return out
		}
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Running against:") {
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			out = append(out, line)
			continue
		}
		if strings.HasPrefix(line, "//") {
			out = append(out, base.Scheme+":"+line)
			continue
		}
		if strings.HasPrefix(line, "/") {
			out = append(out, strings.TrimSuffix(scanURL, "/")+line)
			continue
		}
		if !cfg.IncludeRelative {
			continue
		}
		// A bare word with no slash and no dot is far more likely to be a regex artefact than a
		// route, so it is not worth turning into a URL.
		if !strings.Contains(line, "/") && !strings.Contains(line, ".") {
			continue
		}
		if ref, err := url.Parse(line); err == nil {
			out = append(out, base.ResolveReference(ref).String())
		}
	}

	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func ExecuteAndParseLinkFinderURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[INFO] Starting LinkFinder URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		log.Printf("[ERROR] Failed to extract domain from target URL: %s", targetURL)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Target domain for filtering: %s", targetDomain)

	cfg := LoadLinkFinderURLConfig(scopeTargetID)
	scanURL := targetURL
	if strings.TrimSpace(cfg.BaseURL) != "" {
		scanURL = cfg.BaseURL
	}

	inputs := linkFinderInputs(scanURL, scopeTargetID, cfg)
	if len(inputs) == 0 {
		UpdateLinkFinderURLScanStatus(scanID, "error", "",
			"No inputs to scan. With inputSource set to discovered_js, run Katana or GoSpider first "+
				"so there are JavaScript files to read.", "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] LinkFinder scanning %d input(s), source=%s", len(inputs), cfg.InputSource)

	var (
		cleanURLs   []string
		lastCmd     []string
		failures    int
		firstStderr string
	)

	// linkFinderOutputFailure recognises the ways linkfinder.py reports a problem while still exiting
	// 0. Deliberately conservative: it matches explicit error text, not merely an empty result, since
	// a bundle with no endpoints in it is a legitimate outcome.
	linkFinderOutputFailure := func(out string) string {
		trimmed := strings.TrimSpace(out)
		lower := strings.ToLower(trimmed)
		for _, marker := range []string{
			"traceback (most recent call last)",
			"invalid input defined or ssl error",
			"urlerror", "httperror", "ssl: certificate_verify_failed",
			"connection refused", "name or service not known",
			"remote end closed connection", "read timed out",
		} {
			if strings.Contains(lower, marker) {
				// One line is enough for the operator to recognise the class of failure.
				first := trimmed
				if i := strings.IndexByte(first, '\n'); i > 0 {
					first = first[:i]
				}
				if len(first) > 200 {
					first = first[:200]
				}
				return first
			}
		}
		return ""
	}

	for i, in := range inputs {
		dockerCmd := buildLinkFinderCommand(in, cfg, scopeTargetID)
		lastCmd = dockerCmd

		// The container fetches over the network, so a hung asset must not hold the scan open.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		cmd := exec.CommandContext(ctx, dockerCmd[0], dockerCmd[1:]...)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		cancel()

		if err != nil {
			// One unreadable bundle must not lose the endpoints from the other forty.
			failures++
			if firstStderr == "" {
				firstStderr = stderr.String()
			}
			log.Printf("[WARN] LinkFinder failed on %s: %v", in.url, err)
			continue
		}

		// linkfinder.py exits 0 whatever happens and writes its fetch errors to stdout, so the exit
		// code alone could never detect a failure: every input could 404 and the scan would report
		// success with zero endpoints and failures==0, making the all-failed guard below unreachable.
		if reason := linkFinderOutputFailure(stdout.String()); reason != "" {
			failures++
			if firstStderr == "" {
				firstStderr = reason
			}
			log.Printf("[WARN] LinkFinder could not read %s: %s", in.url, reason)
			continue
		}

		cleanURLs = append(cleanURLs, parseLinkFinderOutput(stdout.String(), in.url, scanURL, cfg)...)

		// LinkFinder has no pacing of its own, so scanning many bundles is paced here or not at all.
		if cfg.RequestDelayMS > 0 && i < len(inputs)-1 {
			time.Sleep(time.Duration(cfg.RequestDelayMS) * time.Millisecond)
		}
	}

	execTime := time.Since(startTime).String()

	// LinkFinder is invoked once per input, so a single stored command line describes one sixtieth
	// of the scan and names whichever file happened to be last. An operator reading it to reproduce
	// the run would re-run one arbitrary bundle, get a handful of endpoints instead of hundreds, and
	// reasonably conclude the count was fabricated. Record what actually happened.
	provenance := strings.Join(lastCmd, " ")
	if len(inputs) > 1 {
		provenance = fmt.Sprintf("%s   [run once per input over %d inputs, source=%s, %d failed]",
			provenance, len(inputs), cfg.InputSource, failures)
	}

	if len(cleanURLs) == 0 && failures == len(inputs) {
		log.Printf("[ERROR] LinkFinder failed on every input for %s", targetURL)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", firstStderr,
			provenance, execTime)
		return
	}
	if failures > 0 {
		log.Printf("[WARN] LinkFinder: %d of %d inputs failed", failures, len(inputs))
	}

	cleanURLs = dedupeStrings(cleanURLs)
	log.Printf("[INFO] Processing %d URLs from %d input(s)", len(cleanURLs), len(inputs))

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "linkfinder", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to process URLs with parameters: %v", err)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), provenance, time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[ERROR] Failed to store discovered endpoints: %v", err)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), provenance, time.Since(startTime).String())
		return
	}

	directCount := 0
	adjacentCount := 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			directCount++
		} else {
			adjacentCount++
		}
	}

	resultSummary := fmt.Sprintf("Found %d direct endpoints and %d adjacent endpoints with parameters", directCount, adjacentCount)

	execTime = time.Since(startTime).String()
	log.Printf("[INFO] LinkFinder URL scan completed in %s for %s", execTime, targetURL)

	UpdateLinkFinderURLScanStatus(scanID, "success", resultSummary, "", provenance, execTime)
}

func UpdateLinkFinderURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE linkfinder_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update LinkFinder URL scan status: %v", err)
	}
}

func UpdateLinkFinderURLScanStatusWithCodes(scanID, status, result, errorMsg, command, execTime, statusCodeJSON string) {
	query := `UPDATE linkfinder_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5, status_code = $6::jsonb WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, statusCodeJSON, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update LinkFinder URL scan status: %v", err)
	}
}

func GetLinkFinderURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code FROM linkfinder_url_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
		StatusCode    *string   `json:"status_code"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to get LinkFinder URL scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetLinkFinderURLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code
	          FROM linkfinder_url_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get LinkFinder URL scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
			StatusCode    *string   `json:"status_code"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
			"status_code":    scan.StatusCode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunWaybackURLsScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" {
		http.Error(w, "Invalid request body. `url` is required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, targetURL).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s", targetURL)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO waybackurls_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create WaybackURLs scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseWaybackURLsScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseWaybackURLsScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[INFO] Starting WaybackURLs scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		log.Printf("[ERROR] Failed to extract domain from target URL: %s", targetURL)
		UpdateWaybackURLsScanStatus(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Target domain for filtering: %s", targetDomain)

	// The BARE DOMAIN, not targetURL. waybackurls interpolates its argument straight into a CDX
	// query as url=*.<arg>/*, so a scheme-bearing value produces url=*.https://host/*, which is not
	// the host it was meant to ask about. targetDomain was already computed above and then not used.
	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-waybackurls-1",
		"waybackurls",
		targetDomain,
	}

	// Bound the run so a hung provider (or an enormous archive) cannot leave the
	// scan stuck forever.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[ERROR] WaybackURLs scan timed out after 10m for %s", targetURL)
			UpdateWaybackURLsScanStatus(scanID, "error", "", "WaybackURLs scan timed out after 10 minutes", strings.Join(dockerCmd, " "), execTime)
			return
		}
		log.Printf("[ERROR] WaybackURLs scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateWaybackURLsScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs", len(lines))

	var cleanURLs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cleanURLs = append(cleanURLs, line)
	}

	log.Printf("[INFO] Processing %d URLs (no filtering applied)", len(cleanURLs))

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "waybackurls", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to process URLs with parameters: %v", err)
		UpdateWaybackURLsScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[ERROR] Failed to store discovered endpoints: %v", err)
		UpdateWaybackURLsScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	directCount := 0
	adjacentCount := 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			directCount++
		} else {
			adjacentCount++
		}
	}

	resultSummary := fmt.Sprintf("Found %d direct endpoints and %d adjacent endpoints with parameters", directCount, adjacentCount)

	execTime = time.Since(startTime).String()
	log.Printf("[INFO] WaybackURLs scan completed in %s for %s", execTime, targetURL)

	UpdateWaybackURLsScanStatus(scanID, "success", resultSummary, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateWaybackURLsScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE waybackurls_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update WaybackURLs scan status: %v", err)
	}
}

func UpdateWaybackURLsScanStatusWithCodes(scanID, status, result, errorMsg, command, execTime, statusCodeJSON string) {
	query := `UPDATE waybackurls_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5, status_code = $6::jsonb WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, statusCodeJSON, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update WaybackURLs scan status: %v", err)
	}
}

func GetWaybackURLsScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code FROM waybackurls_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
		StatusCode    *string   `json:"status_code"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to get WaybackURLs scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetWaybackURLsScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code
	          FROM waybackurls_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get WaybackURLs scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
			StatusCode    *string   `json:"status_code"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
			"status_code":    scan.StatusCode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunGAUURLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" {
		http.Error(w, "Invalid request body. `url` is required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, targetURL).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s", targetURL)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO gau_url_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create GAU URL scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseGAUURLScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseGAUURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[INFO] Starting GAU URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		log.Printf("[ERROR] Failed to extract domain from target URL: %s", targetURL)
		UpdateGAUURLScanStatus(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Target domain for filtering: %s", targetDomain)

	// Reduce the target URL to a bare host for gau: strip the scheme, any path,
	// and (critically) the trailing port. gau's providers query archives by
	// hostname, so a value like "host.example.com:443" returns nothing.
	domain := strings.TrimPrefix(strings.TrimPrefix(targetURL, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]
	if host, _, ok := strings.Cut(domain, ":"); ok {
		domain = host
	}

	// "wayback" IS included, despite the WaybackURLs scan nominally covering it.
	//
	// That split assumed waybackurls always delivers, and it does not. Measured on
	// ginandjuice.shop 2026-08-19: the CDX API returns 178 URLs for the host and is reachable from
	// the container, while the waybackurls binary emits a single newline and exits 0 with nothing on
	// stderr, reproducibly. The whole run therefore saw 29 archive URLs instead of 187, an 85% loss,
	// and nothing reported a problem because an empty result is a successful scan.
	//
	// Overlapping the two costs a few duplicate URLs, which consolidation folds away anyway. Relying
	// on a single tool for the largest archive costs the archive.
	dockerCmd := []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		domain,
		"--providers", "wayback,commoncrawl,otx,urlscan",
		"--json",
		"--threads", "10",
		"--retries", "3",
		"--timeout", "60",
	}

	// Bound the whole run so a hung provider cannot leave the scan stuck.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[ERROR] GAU URL scan timed out after 10m for %s", targetURL)
			UpdateGAUURLScanStatus(scanID, "error", "", "GAU scan timed out after 10 minutes", strings.Join(dockerCmd, " "), execTime)
			return
		}
		log.Printf("[ERROR] GAU URL scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateGAUURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs", len(lines))

	var cleanURLs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var gauResult map[string]interface{}
		if err := json.Unmarshal([]byte(line), &gauResult); err != nil {
			continue
		}

		if urlStr, ok := gauResult["url"].(string); ok {
			cleanURLs = append(cleanURLs, urlStr)
		}
	}

	log.Printf("[INFO] Processing %d URLs (no filtering applied)", len(cleanURLs))

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "gau", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to process URLs with parameters: %v", err)
		UpdateGAUURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[ERROR] Failed to store discovered endpoints: %v", err)
		UpdateGAUURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	directCount := 0
	adjacentCount := 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			directCount++
		} else {
			adjacentCount++
		}
	}

	resultSummary := fmt.Sprintf("Found %d direct endpoints and %d adjacent endpoints with parameters", directCount, adjacentCount)

	execTime = time.Since(startTime).String()
	log.Printf("[INFO] GAU URL scan completed in %s for %s", execTime, targetURL)

	UpdateGAUURLScanStatus(scanID, "success", resultSummary, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateGAUURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE gau_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GAU URL scan status: %v", err)
	}
}

func UpdateGAUURLScanStatusWithCodes(scanID, status, result, errorMsg, command, execTime, statusCodeJSON string) {
	query := `UPDATE gau_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5, status_code = $6::jsonb WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, statusCodeJSON, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GAU URL scan status: %v", err)
	}
}

func GetGAUURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code FROM gau_url_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
		StatusCode    *string   `json:"status_code"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to get GAU URL scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetGAUURLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code
	          FROM gau_url_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get GAU URL scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
			StatusCode    *string   `json:"status_code"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
			"status_code":    scan.StatusCode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func GetDiscoveredEndpoints(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	isDirect := r.URL.Query().Get("is_direct")
	scanType := r.URL.Query().Get("scan_type")

	baseQuery := `
		SELECT 
			e.id, e.url, e.domain, e.path, e.normalized_path, e.status_code, e.is_direct, e.created_at
		FROM discovered_endpoints e
		WHERE e.scan_id = $1`

	args := []interface{}{scanID}
	argCount := 1

	if isDirect == "true" {
		argCount++
		baseQuery += fmt.Sprintf(" AND e.is_direct = true")
	} else if isDirect == "false" {
		argCount++
		baseQuery += fmt.Sprintf(" AND e.is_direct = false")
	}

	if scanType != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND e.scan_type = $%d", argCount)
		args = append(args, scanType)
	}

	baseQuery += " ORDER BY e.created_at DESC"

	log.Printf("[DEBUG] Querying discovered endpoints with scan_id=%s, scan_type=%s", scanID, scanType)

	rows, err := dbPool.Query(context.Background(), baseQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to get discovered endpoints: %v", err)
		http.Error(w, "Failed to fetch endpoints", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	endpoints := make([]map[string]interface{}, 0)

	for rows.Next() {
		var endpoint struct {
			ID             string    `json:"id"`
			URL            string    `json:"url"`
			Domain         string    `json:"domain"`
			Path           string    `json:"path"`
			NormalizedPath string    `json:"normalized_path"`
			StatusCode     *int      `json:"status_code"`
			IsDirect       bool      `json:"is_direct"`
			CreatedAt      time.Time `json:"created_at"`
		}

		err := rows.Scan(&endpoint.ID, &endpoint.URL, &endpoint.Domain, &endpoint.Path,
			&endpoint.NormalizedPath, &endpoint.StatusCode, &endpoint.IsDirect, &endpoint.CreatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan endpoint row: %v", err)
			continue
		}

		paramQuery := `
			SELECT param_type, param_name, example_value, position
			FROM endpoint_parameters
			WHERE endpoint_id = $1
			ORDER BY position`

		paramRows, err := dbPool.Query(context.Background(), paramQuery, endpoint.ID)
		if err != nil {
			log.Printf("[ERROR] Failed to get parameters for endpoint %s: %v", endpoint.ID, err)
			continue
		}

		var parameters []map[string]interface{}
		for paramRows.Next() {
			var param struct {
				Type         string  `json:"type"`
				Name         string  `json:"name"`
				ExampleValue *string `json:"example_value"`
				Position     int     `json:"position"`
			}

			err := paramRows.Scan(&param.Type, &param.Name, &param.ExampleValue, &param.Position)
			if err != nil {
				log.Printf("[ERROR] Failed to scan parameter row: %v", err)
				continue
			}

			parameters = append(parameters, map[string]interface{}{
				"type":          param.Type,
				"name":          param.Name,
				"example_value": param.ExampleValue,
				"position":      param.Position,
			})
		}
		paramRows.Close()

		endpoints = append(endpoints, map[string]interface{}{
			"id":              endpoint.ID,
			"url":             endpoint.URL,
			"domain":          endpoint.Domain,
			"path":            endpoint.Path,
			"normalized_path": endpoint.NormalizedPath,
			"status_code":     endpoint.StatusCode,
			"is_direct":       endpoint.IsDirect,
			"created_at":      endpoint.CreatedAt,
			"parameters":      parameters,
		})
	}

	log.Printf("[DEBUG] Returning %d discovered endpoints for scan_id=%s, scan_type=%s", len(endpoints), scanID, scanType)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

// RunFFUFURLScan is the RETIRED ffuf runner and now refuses to start.
//
// It is kept as a handler rather than deleted so that anything still pointing here gets an answer
// that says where to go, instead of a 404 that reads like a broken deployment. Its three tables
// (ffuf_url_scans, ffuf_wordlists and the scan half of ffuf_configs) hold no rows, nothing renders
// its results, and the URL workflow's Scan button has driven the fuzz flow for some time. What made
// this worth refusing rather than leaving alone: an agent asked to "run ffuf" through MCP would start
// THIS, watch it report success, and never learn that the live implementation had not run.
//
// ffuf_configs itself is NOT dead and is not touched here: ffufAuthMaterial reads it for the
// crawlers' session material and the WAF probe reads it too, so /ffuf-config stays exactly as it is.
func RunFFUFURLScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "retired",
		"message": "This is the old ffuf runner and it no longer runs. The live implementation is the " +
			"fuzz flow: build steps with POST /fuzz/{scope_target_id}/steps and run them with " +
			"POST /fuzz/{scope_target_id}/run, or use the manage_fuzz MCP tool. Findings land in " +
			"fuzz_findings, which is what the UI and the MCP tools read.",
		"replacement": map[string]string{
			"run":      "POST /fuzz/{scope_target_id}/run",
			"findings": "GET /fuzz/{scope_target_id}/findings",
			"mcp":      "manage_fuzz",
		},
	})
}

// executeLegacyFFUFURLScan is the body of the retired runner, unreferenced and kept only so the
// preflight, phase and diagnosis logic in ffufURLScan.go remains readable next to the code that used
// it. That machinery is worth harvesting into the fuzz flow, which is why it is not deleted.
func executeLegacyFFUFURLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL           string `json:"url" binding:"required"`
		ScopeTargetID string `json:"scope_target_id" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. `url` and `scope_target_id` are required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL
	scopeTargetID := payload.ScopeTargetID

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1 AND id = $2`
	var foundID string
	err := dbPool.QueryRow(context.Background(), query, targetURL, scopeTargetID).Scan(&foundID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s with ID %s", targetURL, scopeTargetID)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO ffuf_url_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create FFUF URL scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseFFUFURLScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// The FFUF runner lives in ffufURLScan.go: it grew a preflight, three fuzz phases and a
// per-scan output file, none of which belong inside this already very long file.

func UpdateFFUFURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE ffuf_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[FFUF-URL] Failed to update FFUF URL scan status: %v", err)
	}
}

func GetFFUFURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM ffuf_url_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt,
	)

	if err != nil {
		log.Printf("[FFUF-URL] Failed to get FFUF URL scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetFFUFURLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
	          FROM ffuf_url_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[FFUF-URL] Failed to get FFUF URL scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
		if err != nil {
			log.Printf("[FFUF-URL] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunGoSpiderURLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL string `json:"url" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" {
		http.Error(w, "Invalid request body. `url` is required.", http.StatusBadRequest)
		return
	}

	targetURL := payload.URL

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, targetURL).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching URL scope target found for %s", targetURL)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO gospider_url_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, targetURL, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create GoSpider URL scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseGoSpiderURLScan(scanID, targetURL, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// buildGoSpiderCommand turns the stored config into a command line.
//
// GoSpider has no rate-limit flag. Its offered rate is concurrency divided by delay, so a measured
// req/s is expressed here as `-k`, and the config modal does that arithmetic where the operator can
// see it rather than hiding it in a translation table.
func buildGoSpiderCommand(crawlURL string, cfg GoSpiderURLConfig, scopeTargetID string) []string {
	cmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-gospider-1",
		"gospider",
		"-s", crawlURL,
		"--json",
	}
	add := func(args ...string) { cmd = append(cmd, args...) }

	if cfg.Depth > 0 {
		add("-d", strconv.Itoa(cfg.Depth))
	}
	if cfg.Concurrent > 0 {
		add("-c", strconv.Itoa(cfg.Concurrent))
	}
	if cfg.Threads > 0 {
		add("-t", strconv.Itoa(cfg.Threads))
	}
	if cfg.DelayS > 0 {
		add("-k", strconv.Itoa(cfg.DelayS))
	}
	if cfg.RandomDelayS > 0 {
		add("-K", strconv.Itoa(cfg.RandomDelayS))
	}
	if cfg.Timeout > 0 {
		add("-m", strconv.Itoa(cfg.Timeout))
	}
	if cfg.Sitemap {
		add("--sitemap")
	}
	if cfg.Robots {
		add("--robots")
	}
	if cfg.OtherSource {
		add("-a")
	}
	if cfg.IncludeSubs {
		add("-w")
	}
	if cfg.IncludeOtherSource {
		add("-r")
	}
	if cfg.NoRedirect {
		add("--no-redirect")
	}
	// GoSpider's --js defaults to true, so turning the switch off in the UI did nothing at all: the
	// flag was never emitted in either state and JavaScript was always parsed. Only the disabling
	// case needs to be sent.
	if !cfg.JS {
		add("--js=false")
	}
	if cfg.Blacklist != "" {
		add("--blacklist", cfg.Blacklist)
	}
	if cfg.Whitelist != "" {
		add("--whitelist", cfg.Whitelist)
	}
	if cfg.WhitelistDomain != "" {
		add("--whitelist-domain", cfg.WhitelistDomain)
	}
	if cfg.UserAgent != "" {
		add("-u", cfg.UserAgent)
	}
	if cfg.Proxy != "" {
		add("-p", cfg.Proxy)
	}

	cookie := cfg.Cookie
	headers := append([]NameVal{}, cfg.Headers...)
	if cfg.UseFFUFAuth {
		authHeaders, cookies := ffufAuthMaterial(scopeTargetID)
		headers = append(headers, authHeaders...)
		if strings.TrimSpace(cookie) == "" {
			cookie = cookies
		}
	}
	if strings.TrimSpace(cookie) != "" {
		add("--cookie", cookie)
	}
	for _, h := range headers {
		if strings.TrimSpace(h.Name) == "" {
			continue
		}
		add("-H", fmt.Sprintf("%s: %s", h.Name, h.Value))
	}

	return cmd
}

func ExecuteAndParseGoSpiderURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[GOSPIDER-URL] Starting GoSpider URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	targetDomain := extractDomain(targetURL)
	if targetDomain == "" {
		log.Printf("[GOSPIDER-URL] Failed to extract domain from target URL: %s", targetURL)
		UpdateGoSpiderURLScanStatus(scanID, "error", "", "Failed to extract domain from target URL", "", time.Since(startTime).String())
		return
	}
	log.Printf("[GOSPIDER-URL] Target domain for filtering: %s", targetDomain)

	cfg := LoadGoSpiderURLConfig(scopeTargetID)
	crawlURL := targetURL
	if strings.TrimSpace(cfg.BaseURL) != "" {
		crawlURL = cfg.BaseURL
	}
	dockerCmd := buildGoSpiderCommand(crawlURL, cfg, scopeTargetID)

	// Bound the crawl so a hung target cannot leave the scan stuck forever.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[GOSPIDER-URL] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[GOSPIDER-URL] GoSpider URL scan timed out after 20m for %s", targetURL)
			UpdateGoSpiderURLScanStatus(scanID, "error", "", "GoSpider scan timed out after 20 minutes", strings.Join(dockerCmd, " "), execTime)
			return
		}
		log.Printf("[GOSPIDER-URL] GoSpider URL scan failed for %s: %v", targetURL, err)
		log.Printf("[GOSPIDER-URL] stderr output: %s", stderr.String())
		UpdateGoSpiderURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[GOSPIDER-URL] Found %d total lines", len(lines))

	var cleanURLs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			if output, ok := result["output"].(string); ok && output != "" {
				cleanURLs = append(cleanURLs, output)
			}
		}
	}

	log.Printf("[GOSPIDER-URL] Processing %d URLs (no filtering applied)", len(cleanURLs))

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "gospider", scopeTargetID)
	if err != nil {
		log.Printf("[GOSPIDER-URL] Failed to process URLs with parameters: %v", err)
		UpdateGoSpiderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[GOSPIDER-URL] Failed to store discovered endpoints: %v", err)
		UpdateGoSpiderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	directCount := 0
	adjacentCount := 0
	for _, ep := range endpoints {
		if ep.IsDirect {
			directCount++
		} else {
			adjacentCount++
		}
	}

	resultSummary := fmt.Sprintf("Found %d direct endpoints and %d adjacent endpoints with parameters", directCount, adjacentCount)

	execTime = time.Since(startTime).String()
	log.Printf("[GOSPIDER-URL] GoSpider URL scan completed in %s for %s", execTime, targetURL)

	UpdateGoSpiderURLScanStatus(scanID, "success", resultSummary, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateGoSpiderURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE gospider_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[GOSPIDER-URL] Failed to update GoSpider URL scan status: %v", err)
	}
}

func GetGoSpiderURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM gospider_url_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt,
	)

	if err != nil {
		log.Printf("[GOSPIDER-URL] Failed to get GoSpider URL scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetGoSpiderURLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
	          FROM gospider_url_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[GOSPIDER-URL] Failed to get GoSpider URL scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan struct {
			ScanID        string    `json:"scan_id"`
			URL           string    `json:"url"`
			Status        string    `json:"status"`
			Result        *string   `json:"result"`
			Error         *string   `json:"error"`
			Command       *string   `json:"command"`
			ExecutionTime *string   `json:"execution_time"`
			CreatedAt     time.Time `json:"created_at"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
		if err != nil {
			log.Printf("[GOSPIDER-URL] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":        scan.ScanID,
			"url":            scan.URL,
			"status":         scan.Status,
			"result":         scan.Result,
			"error":          scan.Error,
			"command":        scan.Command,
			"execution_time": scan.ExecutionTime,
			"created_at":     scan.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
