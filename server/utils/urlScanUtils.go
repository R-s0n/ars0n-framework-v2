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
	"os"
	"os/exec"
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
	
	req, err := http.NewRequest("HEAD", urlStr, nil)
	if err != nil {
		req, err = http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return 0
		}
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	
	return resp.StatusCode
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
		if containsColon { specialCount++ }
		if containsSpace { specialCount++ }
		if containsComma { specialCount++ }
		if containsPercent { specialCount++ }
		
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

func groupSimilarPaths(urls []string) map[string][]string {
	groups := make(map[string][]string)
	
	for _, urlStr := range urls {
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}
		
		pathSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
		
		if len(pathSegments) == 0 {
			continue
		}
		
		basePattern := parsedURL.Hostname()
		for i := range pathSegments {
			basePattern += fmt.Sprintf("/[%d]", i)
		}
		
		groups[basePattern] = append(groups[basePattern], urlStr)
	}
	
	return groups
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

func extractPathParameters(urlStr string, normalizedPath string) []EndpointParameter {
	var params []EndpointParameter
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return params
	}
	
	parsedNormalized, err := url.Parse(normalizedPath)
	if err != nil {
		return params
	}
	
	originalSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	normalizedSegments := strings.Split(strings.Trim(parsedNormalized.Path, "/"), "/")
	
	for i, normalizedSeg := range normalizedSegments {
		if normalizedSeg == "{id}" && i < len(originalSegments) {
			params = append(params, EndpointParameter{
				Type:         "path",
				Name:         fmt.Sprintf("path_param_%d", i),
				ExampleValue: originalSegments[i],
				Position:     i,
			})
		}
	}
	
	return params
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
	
	pathGroups := groupSimilarPaths(urls)
	
	processedURLs := make(map[string]bool)
	
	for _, groupURLs := range pathGroups {
		if len(groupURLs) < 3 {
			for _, urlStr := range groupURLs {
				if processedURLs[urlStr] {
					continue
				}
				processedURLs[urlStr] = true
				
				endpoint := createEndpoint(urlStr, scanID, scanType, scopeTargetID, isDirect)
				endpoint.NormalizedPath = endpoint.Path
				
				queryParams := extractQueryParameters(urlStr)
				endpoint.Parameters = append(endpoint.Parameters, queryParams...)
				
				endpoints = append(endpoints, endpoint)
			}
			continue
		}
		
		paramPositions := detectPathParametersByEntropy(groupURLs, 3)
		
		normalizedGroups := make(map[string][]string)
		
		for _, urlStr := range groupURLs {
			if processedURLs[urlStr] {
				continue
			}
			
			normalizedURL := urlStr
			if len(paramPositions) > 0 {
				normalizedURL = normalizePathWithDetectedParams(urlStr, paramPositions)
			}
			normalizedGroups[normalizedURL] = append(normalizedGroups[normalizedURL], urlStr)
		}
		
		for normalizedURL, originalURLs := range normalizedGroups {
			representativeURL := originalURLs[0]
			processedURLs[representativeURL] = true
			
			endpoint := createEndpoint(representativeURL, scanID, scanType, scopeTargetID, isDirect)
			endpoint.NormalizedPath = extractPath(normalizedURL)
			
			queryParams := extractQueryParameters(representativeURL)
			endpoint.Parameters = append(endpoint.Parameters, queryParams...)
			
			pathParams := extractPathParameters(representativeURL, normalizedURL)
			endpoint.Parameters = append(endpoint.Parameters, pathParams...)
			
			endpoints = append(endpoints, endpoint)
			
			for i := 1; i < len(originalURLs); i++ {
				processedURLs[originalURLs[i]] = true
			}
		}
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
		return ""
	}
	return parsedURL.Path
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

	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-katana-1",
		"katana",
		"-u", targetURL,
		"-d", "5",
		"-jc",
		"-kf", "all",
		"-silent",
		"-nc",
		"-p", "15",
	}

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Katana URL scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateKatanaURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs before filtering", len(lines))

	var cleanURLs []string
	imagesFiltered := 0
	staticFiltered := 0
	invalidPathFiltered := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if isImageFile(line) {
			imagesFiltered++
			continue
		}

		if isStaticAsset(line) {
			staticFiltered++
			continue
		}

		if !isValidPath(line) {
			invalidPathFiltered++
			continue
		}

		cleanURLs = append(cleanURLs, line)
	}

	log.Printf("[INFO] Filtered to %d clean URLs (from %d total): %d images, %d static assets, %d invalid paths",
		len(cleanURLs), len(lines), imagesFiltered, staticFiltered, invalidPathFiltered)

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

	var scans []map[string]interface{}
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

	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-linkfinder-1",
		"python3", "linkfinder.py",
		"-i", targetURL,
		"-o", "cli",
	}

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] LinkFinder URL scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateLinkFinderURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total endpoints/URLs before filtering", len(lines))

	var cleanURLs []string
	imagesFiltered := 0
	staticFiltered := 0
	invalidPathFiltered := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		var fullURL string
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			fullURL = line
		} else if strings.HasPrefix(line, "/") {
			fullURL = strings.TrimSuffix(targetURL, "/") + line
		} else {
			continue
		}

		if isImageFile(fullURL) {
			imagesFiltered++
			continue
		}

		if isStaticAsset(fullURL) {
			staticFiltered++
			continue
		}

		if !isValidPath(fullURL) {
			invalidPathFiltered++
			continue
		}

		cleanURLs = append(cleanURLs, fullURL)
	}

	log.Printf("[INFO] Filtered to %d clean URLs (from %d total): %d images, %d static assets, %d invalid paths",
		len(cleanURLs), len(lines), imagesFiltered, staticFiltered, invalidPathFiltered)

	endpoints, err := processURLsWithParameters(cleanURLs, targetDomain, scanID, "linkfinder", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to process URLs with parameters: %v", err)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to process URLs: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
		return
	}

	err = storeDiscoveredEndpoints(endpoints)
	if err != nil {
		log.Printf("[ERROR] Failed to store discovered endpoints: %v", err)
		UpdateLinkFinderURLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to store endpoints: %v", err), strings.Join(dockerCmd, " "), time.Since(startTime).String())
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

	UpdateLinkFinderURLScanStatus(scanID, "success", resultSummary, "", strings.Join(dockerCmd, " "), execTime)
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

	var scans []map[string]interface{}
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

	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-waybackurls-1",
		"waybackurls",
		targetURL,
	}

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] WaybackURLs scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateWaybackURLsScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs before filtering", len(lines))

	var cleanURLs []string
	imagesFiltered := 0
	staticFiltered := 0
	invalidPathFiltered := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if isImageFile(line) {
			imagesFiltered++
			continue
		}

		if isStaticAsset(line) {
			staticFiltered++
			continue
		}

		if !isValidPath(line) {
			invalidPathFiltered++
			continue
		}

		cleanURLs = append(cleanURLs, line)
	}

	log.Printf("[INFO] Filtered to %d clean URLs (from %d total): %d images, %d static assets, %d invalid paths",
		len(cleanURLs), len(lines), imagesFiltered, staticFiltered, invalidPathFiltered)

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

	var scans []map[string]interface{}
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

	domain := strings.TrimPrefix(strings.TrimPrefix(targetURL, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]

	dockerCmd := []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		domain,
		"--providers", "wayback,commoncrawl,otx",
		"--json",
		"--threads", "10",
	}

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] GAU URL scan failed for %s: %v", targetURL, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateGAUURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	rawResult := stdout.String()
	lines := strings.Split(rawResult, "\n")
	log.Printf("[DEBUG] Found %d total URLs before filtering", len(lines))

	var cleanURLs []string
	imagesFiltered := 0
	staticFiltered := 0
	invalidPathFiltered := 0

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
			if isImageFile(urlStr) {
				imagesFiltered++
				continue
			}

			if isStaticAsset(urlStr) {
				staticFiltered++
				continue
			}

			if !isValidPath(urlStr) {
				invalidPathFiltered++
				continue
			}

			cleanURLs = append(cleanURLs, urlStr)
		}
	}

	log.Printf("[INFO] Filtered to %d clean URLs (from %d total): %d images, %d static assets, %d invalid paths",
		len(cleanURLs), len(lines), imagesFiltered, staticFiltered, invalidPathFiltered)

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

	var scans []map[string]interface{}
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

	rows, err := dbPool.Query(context.Background(), baseQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to get discovered endpoints: %v", err)
		http.Error(w, "Failed to fetch endpoints", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var endpoints []map[string]interface{}

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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

func RunFFUFURLScan(w http.ResponseWriter, r *http.Request) {
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

func ExecuteAndParseFFUFURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[FFUF-URL] Starting FFUF URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	var configJSON []byte
	configQuery := `SELECT config FROM ffuf_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), configQuery, scopeTargetID).Scan(&configJSON)

	wordlistPath := "/wordlists/ffuf-wordlist-5000.txt"
	threads := "40"
	matchCodes := "200-299,301,302,307,401,403,405,500"

	if err == nil {
		var config struct {
			WordlistID       string `json:"wordlistId"`
			Threads          int    `json:"threads"`
			MatchStatusCodes string `json:"matchStatusCodes"`
		}
		if err := json.Unmarshal(configJSON, &config); err == nil {
			if config.Threads > 0 {
				threads = fmt.Sprintf("%d", config.Threads)
			}
			if config.MatchStatusCodes != "" {
				matchCodes = config.MatchStatusCodes
			}
			if config.WordlistID != "" {
				if strings.HasPrefix(config.WordlistID, "builtin-") {
					switch config.WordlistID {
					case "builtin-default":
						possiblePaths := []string{
							"/app/wordlists/ffuf-wordlist-5000.txt",
							"./wordlists/ffuf-wordlist-5000.txt",
							"../wordlists/ffuf-wordlist-5000.txt",
						}
						for _, path := range possiblePaths {
							if _, err := os.Stat(path); err == nil {
								wordlistPath = path
								break
							}
						}
					case "builtin-small":
						possiblePaths := []string{
							"/app/wordlists/ffuf-wordlist-default-small.txt",
							"./wordlists/ffuf-wordlist-default-small.txt",
							"../wordlists/ffuf-wordlist-default-small.txt",
						}
						for _, path := range possiblePaths {
							if _, err := os.Stat(path); err == nil {
								wordlistPath = path
								break
							}
						}
					case "builtin-large":
						possiblePaths := []string{
							"/app/wordlists/ffuf-wordlist-default-long.txt",
							"./wordlists/ffuf-wordlist-default-long.txt",
							"../wordlists/ffuf-wordlist-default-long.txt",
						}
						for _, path := range possiblePaths {
							if _, err := os.Stat(path); err == nil {
								wordlistPath = path
								break
							}
						}
					}
				} else {
					var customPath string
					wordlistQuery := `SELECT path FROM ffuf_wordlists WHERE id = $1`
					if dbPool.QueryRow(context.Background(), wordlistQuery, config.WordlistID).Scan(&customPath) == nil {
						wordlistPath = customPath
					}
				}
			}
		}
	}

	fuzzyURL := targetURL
	if !strings.Contains(fuzzyURL, "FUZZ") {
		fuzzyURL = strings.TrimSuffix(fuzzyURL, "/") + "/FUZZ"
	}

	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-ffuf-1",
		"ffuf",
		"-w", wordlistPath,
		"-u", fuzzyURL,
		"-mc", matchCodes,
		"-o", "/tmp/ffuf-output.json",
		"-of", "json",
		"-ac",
		"-c",
		"-r",
		"-t", threads,
		"-timeout", "30",
	}

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	log.Printf("[FFUF-URL] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[FFUF-URL] FFUF URL scan failed for %s: %v", targetURL, err)
		log.Printf("[FFUF-URL] stderr output: %s", stderr.String())
		UpdateFFUFURLScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	outputCmd := exec.Command("docker", "exec", "ars0n-framework-v2-ffuf-1", "cat", "/tmp/ffuf-output.json")
	resultBytes, err := outputCmd.Output()
	if err != nil {
		log.Printf("[FFUF-URL] Failed to read FFUF results file: %v", err)
		UpdateFFUFURLScanStatus(scanID, "error", "", "Failed to read results file", strings.Join(dockerCmd, " "), execTime)
		return
	}

	var ffufOutput struct {
		Results []struct {
			Input  map[string]string `json:"input"`
			Status int64             `json:"status"`
			Length int64             `json:"length"`
			Words  int64             `json:"words"`
			Lines  int64             `json:"lines"`
		} `json:"results"`
	}

	if err := json.Unmarshal(resultBytes, &ffufOutput); err != nil {
		log.Printf("[FFUF-URL] Failed to parse FFUF results JSON: %v", err)
		UpdateFFUFURLScanStatus(scanID, "error", "", "Failed to parse results JSON", strings.Join(dockerCmd, " "), execTime)
		return
	}

	var endpoints []map[string]interface{}
	for _, result := range ffufOutput.Results {
		endpoint := map[string]interface{}{
			"path":   result.Input["FUZZ"],
			"status": result.Status,
			"size":   result.Length,
			"words":  result.Words,
			"lines":  result.Lines,
		}
		endpoints = append(endpoints, endpoint)
	}

	formattedResults := map[string]interface{}{
		"endpoints": endpoints,
	}
	resultJSON, _ := json.Marshal(formattedResults)

	log.Printf("[FFUF-URL] FFUF URL scan completed in %s for %s", execTime, targetURL)
	log.Printf("[FFUF-URL] Found %d endpoints", len(endpoints))

	UpdateFFUFURLScanStatus(scanID, "success", string(resultJSON), "", strings.Join(dockerCmd, " "), execTime)
}

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

	var scans []map[string]interface{}
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

