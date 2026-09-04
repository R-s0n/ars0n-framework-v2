package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
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

// targetSafeDelay is the gap to leave between requests for a target, taken from the rate the
// operator applied to this target rather than from a constant.
//
// It reads the FFUF config because that is where the Target Behaviour Probe's recommendation ends up
// once an operator accepts it, which makes it the one place on a target that says "this is the rate
// we decided is safe here". Anything else pacing itself independently is, by definition, running at a
// rate nobody chose.
//
// Falls back to the previous 10 per second when nothing is configured, so a target that has never
// been probed behaves exactly as it did before rather than stalling.
func targetSafeDelay(ctx context.Context, scopeTargetID string) time.Duration {
	const fallback = 100 * time.Millisecond

	if strings.TrimSpace(scopeTargetID) == "" {
		return fallback
	}
	var rate float64
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE((config->>'rateLimit')::float8, 0)
		FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&rate)
	if err != nil || rate <= 0 {
		return fallback
	}
	// Clamped so a mistyped or absurd value cannot either hammer a target or stall discovery for
	// hours. One request every two seconds is the slowest this will go on its own.
	if rate > 50 {
		rate = 50
	}
	delay := time.Duration(float64(time.Second) / rate)
	if delay > 2*time.Second {
		delay = 2 * time.Second
	}
	return delay
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

	// PACED AT THE RATE THE OPERATOR ACTUALLY CHOSE, not at a hardcoded one.
	//
	// This used to sleep a flat 100ms, which is 10 requests per second. On a target the probe had
	// measured as safe at 5, that is double the intended rate, and it runs once per discovered
	// endpoint, so the largest single burst of traffic in the whole discovery phase was the one nobody
	// had configured. Worse, it is invisible: the operator sets a rate limit, watches the crawlers
	// honour it, and this loop quietly ignores it.
	ctx := context.Background()
	delay := targetSafeDelay(ctx, scopeTargetID)
	for i := range endpoints {
		endpoints[i].StatusCode = fetchStatusCode(endpoints[i].URL)
		// A 401 or 403 seen here is the framework being refused, which is exactly what the access
		// bypass section needs and exactly what used to be discarded as just another status code.
		RecordDeniedEndpoint(ctx, scopeTargetID, endpoints[i].URL, endpoints[i].StatusCode,
			"endpoint-discovery")
		if i > 0 && i%10 == 0 {
			log.Printf("[INFO] Status code progress: %d/%d", i, len(endpoints))
		}
		time.Sleep(delay)
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

// ---------------------------------------------------------------------------
// Discovery scan outcome guards
//
// Everything below exists to separate "this tool ran and the answer was nothing" from "this tool did
// not run". The vector scanners already draw that line, in vectorScan.go; the discovery scanners did
// not, so every way of failing arrived in the UI as a green "Found 0 direct endpoints".
// ---------------------------------------------------------------------------

// archiveQuery is what a public archive should be asked about a target, or the reason it must not be
// asked at all.
type archiveQuery struct {
	// Host is exactly what to hand the tool: the hostname, with :port appended when the port is not
	// the scheme's default.
	Host string
	// WithSubs reports whether a subdomain wildcard around Host is still a pattern an archive can
	// match. It stops being one as soon as a port is involved.
	WithSubs bool
	// SkipReason is non-empty when querying an archive about this target can only return some other
	// service's data.
	SkipReason string
}

// planArchiveQuery decides what waybackurls and gau should be asked about a target.
//
// Both were being handed a bare hostname with the port thrown away, and both were wrong for the same
// reason: the Wayback CDX index keys on the whole authority, so url=10.0.0.18/* answers about port 80
// and url=10.0.0.18:3000/* answers about port 3000. Verified against the live CDX API on 2026-08-21:
// the first returns crawls of a machine archived in July 2000, the second returns []. Nine of those
// year-2000 paths (/Periodico/crearNoticia.asp, /login.cfm, /Content/Default.asp) were imported into
// discovered_endpoints as endpoints of a Juice Shop on port 3000, recorded at http://10.0.0.18:80/,
// a port nothing on the target listens on.
//
// An IP literal is refused outright rather than merely port-qualified. An archive keys its index on
// the address string, and an address is not a stable identity for a service: whatever the archive
// holds for 10.0.0.18 belongs to whoever had that address when the crawl ran, which for a private
// range is a different network entirely. Crawlers reach sites by following hostnames, so the honest
// expected yield for a bare address is nothing, and the measured yield was another machine's site map.
//
// The subdomain wildcard is dropped as soon as a port is in play. waybackurls interpolates its
// argument as url=*.<arg>/*, and *.host:8080/* is not a pattern the CDX API can match: the wildcard
// belongs in front of a hostname, not in front of a host:port authority.
func planArchiveQuery(targetURL string) archiveQuery {
	raw := strings.TrimSpace(targetURL)
	if raw == "" {
		return archiveQuery{SkipReason: "No target URL to ask an archive about."}
	}
	// url.Parse without a scheme reads "host:3000" as scheme "host", so give it one. The scheme only
	// decides which port counts as default below.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return archiveQuery{SkipReason: fmt.Sprintf("Could not read a host out of %q, so no archive was queried.", targetURL)}
	}

	host := parsed.Hostname()
	if net.ParseIP(host) != nil {
		return archiveQuery{SkipReason: fmt.Sprintf(
			"%s is an IP address, so no public archive was queried. Archives index by address, and an "+
				"address is not a stable identity for a service: asking about 10.0.0.18 on 2026-08-21 "+
				"returned a machine crawled in July 2000, whose paths were then stored as this target's "+
				"endpoints. Crawl this target directly with Katana or GoSpider instead.", host)}
	}

	port := parsed.Port()
	if port == "" || (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		return archiveQuery{Host: host, WithSubs: true}
	}
	return archiveQuery{Host: host + ":" + port}
}

// archiveQueryFloor is the shortest a public-archive lookup can take and still have happened.
//
// Measured against the live Wayback CDX API on 2026-08-21: 3.4s, 4.6s and 32.1s for a query whose
// correct answer is empty, and 14.6s and 20.7s for one with results. The failing scans recorded
// 655ms and 665ms, and reproduced by hand at 451ms with zero bytes on stdout and zero on stderr.
// The cause was NOT a container that could not reach the archive, which is what this comment first
// claimed: wget from inside that container returns real CDX data. web.archive.org answers Go's
// default User-Agent with HTTP 429 in well under a second, and waybackurls discards the resulting
// error and exits 0. 2s sits below every real measurement and comfortably above every failed one,
// and it still earns its place now that archivefetch reports the 429 itself: a future tool that
// fails fast and quietly gets caught by runtime alone.
const archiveQueryFloor = 2 * time.Second

// buildWaybackURLsCommand turns an archive plan into a command line. Kept separate from the launcher
// for the same reason buildKatanaCommand is: the mapping from decision to flag is one readable block,
// and dropping the subdomain wildcard for a port-bearing argument is exactly the kind of detail that
// disappears inside a scan function.
// The tool is archivefetch, not waybackurls, and the container is still named for waybackurls
// because that is what the compose service builds.
//
// waybackurls cannot do this job. It calls http.Get with Go's default client, web.archive.org
// answers "Go-http-client/1.1" with HTTP 429, and waybackurls discards the resulting parse error
// and exits 0 having printed nothing. Measured in that container on 2026-08-21 against
// ginandjuice.shop: the Go default UA gets 429 and 162 bytes, any other UA gets 200 and 9826 bytes,
// and both waybackurls@v0.1.0 and waybackurls@latest print zero bytes and exit 0 while wget against
// the identical CDX URL from the same container returns real data. archivefetch sends a descriptive
// UA, retries a 429, and exits NON-ZERO with a reason when the archive refuses. See
// docker/waybackurls/archivefetch/main.go.
func buildWaybackURLsCommand(plan archiveQuery) []string {
	cmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-waybackurls-1",
		"archivefetch",
	}
	if !plan.WithSubs {
		// A port is in the argument, and the query is url=*.<arg>/*, which for a host:port authority
		// is not a pattern the CDX API can match.
		cmd = append(cmd, "-no-subs")
	}
	return append(cmd, plan.Host)
}

// discoveryRun describes one discovery tool execution in enough detail to decide whether it did the
// work its result line is about to claim.
type discoveryRun struct {
	Tool      string
	Stdout    string
	Stderr    string
	URLsFound int
	Elapsed   time.Duration

	// MinRuntime is the shortest this tool's work could take and still have reached the network.
	// Zero disables the check, for tools whose runtime says nothing useful.
	MinRuntime time.Duration

	// SilenceIsFailure marks a tool that writes something whenever it reached its target, so that a
	// completely silent exit 0 can only mean it never got there. The archive tools are deliberately
	// not marked: an archive holding no history for a host legitimately prints nothing.
	SilenceIsFailure bool
}

// discoveryScanFailure returns an operator-facing reason when a discovery tool exited 0 without doing
// its work, and "" when the run can be trusted.
//
// vectorScan.go guards the vector tools against exactly this with refusedItsCommandLine(), which is
// called here rather than reimplemented. The discovery path had no equivalent, so a tool that never
// ran produced the same row as a tool that ran and found nothing. Measured on 10.0.0.18:3000
// (2026-08-21): waybackurls recorded "Found 0 direct endpoints", status success, in 655ms, which is
// indistinguishable from a healthy run against a domain with no archive history and was in fact a
// lookup that never left the container.
func discoveryScanFailure(run discoveryRun) string {
	// A tool complaining about its own arguments failed whatever it found, because whatever it found
	// came from a command line that is not the one the operator configured.
	if refusedItsCommandLine(run.Stdout + "\n" + run.Stderr) {
		return fmt.Sprintf("%s rejected its own command line rather than scanning: %s",
			run.Tool, firstLineOf(run.Stderr+"\n"+run.Stdout))
	}

	// Anything produced is evidence the tool ran. Everything below is only about zeroes.
	if run.URLsFound > 0 {
		return ""
	}

	if run.MinRuntime > 0 && run.Elapsed < run.MinRuntime {
		return fmt.Sprintf(
			"%s returned nothing in %s, and a lookup that reaches a public archive takes at least %s "+
				"(measured 3.4s for an empty answer, 14s to 21s for a populated one). This is a query "+
				"that never happened, not an archive with no history for the target. The archive "+
				"refuses some clients outright: it answers Go's default User-Agent with HTTP 429, "+
				"which is why waybackurls was replaced with archivefetch. Read the run's stderr for "+
				"what the archive actually said.",
			run.Tool, run.Elapsed.Round(time.Millisecond), run.MinRuntime)
	}

	if run.SilenceIsFailure && strings.TrimSpace(run.Stdout) == "" && strings.TrimSpace(run.Stderr) == "" {
		return fmt.Sprintf(
			"%s exited 0 after %s having written nothing at all, on stdout or stderr, which is what a "+
				"crawler does when it never reached the target: one that got a response echoes at "+
				"least the seed URL back. Measured 2026-08-21 against a closed port, gospider produced "+
				"exactly this and katana still printed its seed.",
			run.Tool, run.Elapsed.Round(time.Millisecond))
	}

	return ""
}

// firstLineOf reduces a tool's output to the one line an operator needs to recognise what happened.
// The whole output goes in the stdout column; the error column is a summary of it.
func firstLineOf(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200]
		}
		return line
	}
	return ""
}

// storeDiscoveryScanOutput records what a discovery tool actually printed.
//
// The five discovery tables have carried stdout and stderr columns since they were created and
// nothing ever wrote to them: every row in waybackurls_scans has both NULL. That is why LinkFinder,
// Katana and GoSpider were all misdiagnosed as broken after the 2026-08-21 run. Each had recorded an
// error or a zero, and with no output stored there was no way to tell a tool that rejected its
// arguments from a tool whose target had gone to sleep, which is what had actually happened. Stored
// on every outcome including success, because a successful run's output is what proves its count.
func storeDiscoveryScanOutput(table, scanID, stdout, stderr string) {
	// table is a compile-time constant at every call site, never anything an operator or a tool
	// supplies, so interpolating it carries no injection risk.
	query := fmt.Sprintf(`UPDATE %s SET stdout = $1, stderr = $2 WHERE scan_id = $3`, table)
	_, err := dbPool.Exec(context.Background(), query,
		sanitizeForTextColumn(cappedToolOutput(stdout)),
		sanitizeForTextColumn(cappedToolOutput(stderr)),
		scanID)
	if err != nil {
		// Logged rather than swallowed. Losing this column silently is precisely how the last
		// misdiagnosis happened, and a Postgres rejection of raw wire bytes has bitten this codebase
		// before, in the ffuf evidence column.
		log.Printf("[ERROR] Failed to store %s output for scan %s: %v", table, scanID, err)
	}
}

// cappedToolOutput keeps a tool's output storable. A katana crawl prints megabytes and this column is
// for diagnosis, not for results, which are already parsed into discovered_endpoints. Head and tail
// are both kept: the head carries the banner and any refusal message, the tail carries how the run
// ended.
func cappedToolOutput(s string) string {
	const keep = 64 * 1024
	if len(s) <= 2*keep {
		return s
	}
	return s[:keep] +
		fmt.Sprintf("\n\n... [%d bytes omitted by the framework] ...\n\n", len(s)-2*keep) +
		s[len(s)-keep:]
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
// auth is resolved by the CALLER for the host being crawled. It used to be looked up in here
// from the scope target alone, which was safe only while a crawl had one seed: with several
// hosts that hands the target's session to every one of them, including hosts on a different
// registrable domain that ScopedAuthContext.For would have refused.
func buildKatanaCommand(crawlURL string, cfg KatanaURLConfig, auth crawlAuth) []string {
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
	headers = append(headers, auth.Headers...)
	if strings.TrimSpace(auth.Cookie) != "" {
		headers = append(headers, NameVal{Name: "Cookie", Value: auth.Cookie})
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
	log.Printf("[INFO] Starting Katana scan for %s (scan ID: %s)", targetURL, scanID)

	cfg := LoadKatanaURLConfig(scopeTargetID)
	targets, err := ResolveScanHosts(scopeTargetID, cfg.HostMode, cfg.SelectedHosts)
	if err != nil {
		UpdateKatanaURLScanStatus(scanID, "error", "", err.Error(), "", "0s")
		return
	}
	selected := SelectedScanHosts(targets)
	if len(selected) == 0 {
		UpdateKatanaURLScanStatus(scanID, "error", "",
			"No hosts are selected for this scan. Open Config and choose at least one host.", "", "0s")
		return
	}
	log.Printf("[INFO] Katana crawling %d host(s) one at a time", len(selected))

	executeCrawlerScan("katana", "katana_url_scans", scanID, targetURL, scopeTargetID,
		selected, time.Duration(cfg.TimeoutMinutes)*time.Minute, cfg.UseFFUFAuth, cfg.BaseURL,
		func(seedURL string, t ScanHostTarget, auth crawlAuth) []string {
			return buildKatanaCommand(seedURL, cfg, auth)
		},
		UpdateKatanaURLScanStatus)
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code, target_results
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
			// Per-host outcomes, now that one run covers several hosts.
			TargetResults *string `json:"target_results"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
			&scan.TargetResults)
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
			"target_results": scan.TargetResults,
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
		// cfg.MaxJSFiles is passed straight through, including zero, which discoveredJSURLs reads as
		// "no cap". There is deliberately no fallback to a default here: substituting a number when
		// the operator set none is how the old silent truncation happened.
		for _, u := range discoveredJSURLs(scopeTargetID, cfg.MaxJSFiles) {
			inputs = append(inputs, linkFinderInput{url: u, isJSFile: true})
		}
	}

	return inputs
}

// discoveredJSURLs collects JavaScript assets that earlier steps already found, from both the
// crawlers' endpoint table and the manual crawl captures. Both are consulted because the manual
// crawl routinely reaches authenticated bundles no unauthenticated crawler will ever see.
//
// A limit of zero or less means NO cap, which is how the corpus is sized for the JS Files metric.
// Sizing it by any other route would be a bug waiting to happen: the capped call returns at most
// `limit` entries, so len() of it is a page size rather than a total, and a metric built on that
// would read "50 / 50" forever no matter how much JavaScript the target actually has. Both numbers
// coming out of this one function is what makes them impossible to disagree.
func discoveredJSURLs(scopeTargetID string, limit int) []string {
	unbounded := limit <= 0
	seen := map[string]bool{}
	capacity := limit
	if unbounded {
		capacity = 0
	}
	out := make([]string, 0, capacity)

	// pgx panics rather than erroring on a nil pool, which would take the process down instead of
	// producing a scan that reports it found nothing to read.
	if dbPool == nil {
		log.Printf("[WARN] LinkFinder asked for discovered JS before the database was ready")
		return out
	}

	collect := func(table string) {
		// The dedupe below is what makes the number meaningful, so the query must not also try to
		// distinct: two rows differing only by a cache-busting query string are one bundle, and only
		// the stripped form can see that.
		query := fmt.Sprintf(`SELECT url FROM %s
		         WHERE scope_target_id = $1 AND url ~* '\.js($|\?)'
		         ORDER BY created_at DESC`, table)
		args := []interface{}{scopeTargetID}
		if !unbounded {
			query += " LIMIT $2"
			args = append(args, limit)
		}

		rows, err := dbPool.Query(context.Background(), query, args...)
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
			if seen[base] || (!unbounded && len(out) >= limit) {
				continue
			}
			seen[base] = true
			out = append(out, base)
		}
	}

	collect("discovered_endpoints")
	collect("manual_crawl_captures")

	return out
}

// linkFinderJSPlan says how many of the available JavaScript files a run would actually read.
//
// Kept separate from the handler so the rule is testable without a database, because the rule has
// two edges that are easy to get wrong: "target" and the EMPTY STRING both mean the JS arm does not
// run at all (linkFinderInputs matches the empty string only in the target arm), and the cap is a
// ceiling rather than a target, so a corpus smaller than the cap is scanned whole.
// A limit of zero or less means unlimited, and is reported back as zero rather than as a number,
// so the client can say "no limit" instead of inventing a ceiling that does not exist.
func linkFinderJSPlan(available, maxJSFiles int, inputSource string) (scanned, limit int) {
	limit = maxJSFiles
	if limit < 0 {
		limit = 0
	}
	if inputSource != "discovered_js" && inputSource != "both" {
		return 0, limit
	}
	if limit == 0 || available < limit {
		return available, limit
	}
	return limit, limit
}

// GetLinkFinderJSFiles reports how much JavaScript LinkFinder will read against how much exists.
//
// The gap between the two is the whole point. The scan truncates newest-first and says nothing
// about it: the summary line reports only endpoints found, so a target with 900 bundles and the
// default cap of 50 looks identical to one with 50. This is the only place that difference is
// visible before the operator goes looking for it.
func GetLinkFinderJSFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_target", "scope_target_id is required")
		return
	}

	cfg := LoadLinkFinderURLConfig(scopeTargetID)
	available := len(discoveredJSURLs(scopeTargetID, 0))
	scanned, limit := linkFinderJSPlan(available, cfg.MaxJSFiles, cfg.InputSource)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"available":    available,
		"scanned":      scanned,
		"max_js_files": limit,
		"input_source": cfg.InputSource,
		"truncated":    limit > 0 && available > scanned && scanned > 0,
		"scans_js":     cfg.InputSource == "discovered_js" || cfg.InputSource == "both",
	})
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
		// LinkFinder runs once per input, so the stdout column has to be the transcript of the whole
		// scan rather than whichever bundle happened to be last, for the same reason the command
		// column already carries a note about the run shape.
		transcript strings.Builder
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

		fmt.Fprintf(&transcript, "$ %s\n%s%s\n", strings.Join(dockerCmd, " "), stdout.String(), stderr.String())

		if err != nil {
			// One unreadable bundle must not lose the endpoints from the other forty.
			failures++
			if firstStderr == "" {
				firstStderr = stderr.String()
			}
			log.Printf("[WARN] LinkFinder failed on %s: %v", in.url, err)
			continue
		}

		// A refusal is not "this bundle had no endpoints in it", it is the whole scan running a
		// command line the operator did not configure, so it counts against every input rather than
		// one. refusedItsCommandLine lives in vectorScan.go and is the shared list of the messages
		// argparse, cobra and friends print when they reject their own arguments.
		if refusedItsCommandLine(stdout.String() + "\n" + stderr.String()) {
			failures++
			if firstStderr == "" {
				firstStderr = "LinkFinder rejected its own command line rather than scanning: " +
					firstLineOf(stderr.String()+"\n"+stdout.String())
			}
			log.Printf("[WARN] LinkFinder refused its command line on %s", in.url)
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

	// Before any branching, so the transcript is on record whichever way this run ends. LinkFinder was
	// misdiagnosed as broken off the back of four error rows with no stored output; the invocation had
	// been fine and the target had been asleep.
	storeDiscoveryScanOutput("linkfinder_url_scans", scanID, transcript.String(), "")

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

	cfg := LoadWaybackURLsURLConfig(scopeTargetID)
	targets, err := ResolveScanHosts(scopeTargetID, cfg.HostMode, cfg.SelectedHosts)
	if err != nil {
		UpdateWaybackURLsScanStatus(scanID, "error", "", err.Error(), "", "0s")
		return
	}
	selected := SelectedScanHosts(targets)
	if len(selected) == 0 {
		// Refused rather than run as a green zero. A custom selection that matches nothing is an
		// operator mistake, and a scan reporting "0 endpoints" for it is indistinguishable from an
		// archive that genuinely holds nothing.
		UpdateWaybackURLsScanStatus(scanID, "error", "",
			"No hosts are selected for this scan. Open Configure and choose at least one host.", "", "0s")
		return
	}
	log.Printf("[INFO] WaybackURLs querying %d host(s) sequentially", len(selected))

	executeArchiveScan("waybackurls", "waybackurls_scans", scanID, targetURL, scopeTargetID,
		selected, time.Duration(cfg.TimeoutMinutes)*time.Minute,
		func(plan archiveQuery) []string { return buildArchiveFetchCommand(plan, cfg) },
		UpdateWaybackURLsScanStatus)
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code, target_results
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
			// Per-host outcomes for a run that queried several hosts. Sent as raw JSON so the
			// results modal can show which host each number came from and which ones failed.
			TargetResults *string `json:"target_results"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
			&scan.TargetResults)
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
			"target_results": scan.TargetResults,
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
	log.Printf("[INFO] Starting GAU scan for %s (scan ID: %s)", targetURL, scanID)

	cfg := LoadGAUURLConfig(scopeTargetID)
	targets, err := ResolveScanHosts(scopeTargetID, cfg.HostMode, cfg.SelectedHosts)
	if err != nil {
		UpdateGAUURLScanStatus(scanID, "error", "", err.Error(), "", "0s")
		return
	}
	selected := SelectedScanHosts(targets)
	if len(selected) == 0 {
		UpdateGAUURLScanStatus(scanID, "error", "",
			"No hosts are selected for this scan. Open Configure and choose at least one host.", "", "0s")
		return
	}
	log.Printf("[INFO] GAU querying %d host(s) sequentially", len(selected))

	executeArchiveScan("gau", "gau_url_scans", scanID, targetURL, scopeTargetID,
		selected, time.Duration(cfg.TimeoutMinutes)*time.Minute,
		func(plan archiveQuery) []string { return buildGAUCommand(plan, cfg) },
		UpdateGAUURLScanStatus)
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, status_code, target_results
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
			// Per-host outcomes for a run that queried several hosts. Sent as raw JSON so the
			// results modal can show which host each number came from and which ones failed.
			TargetResults *string `json:"target_results"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.StatusCode,
			&scan.TargetResults)
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
			"target_results": scan.TargetResults,
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

	// THE PLACEHOLDER COUNTER USED TO ADVANCE HERE WITHOUT AN ARGUMENT BEING ADDED.
	//
	// These two branches take no bind parameter: the value is a literal in the SQL. Incrementing
	// argCount anyway left the counter one ahead of the argument list, so the NEXT filter to use a
	// placeholder emitted $3 while only two arguments were ever supplied, and Postgres rejected the
	// whole statement. The result was a 500 from get_discovered_endpoints whenever reach was set
	// alongside a scan type, which is how the MCP tool calls it.
	//
	// Bound properly now rather than patched, so the counter and the argument list cannot drift apart
	// again by adding another filter above this one.
	if isDirect == "true" || isDirect == "false" {
		argCount++
		baseQuery += fmt.Sprintf(" AND e.is_direct = $%d", argCount)
		args = append(args, isDirect == "true")
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
// See buildKatanaCommand: auth belongs to one host and is resolved by the caller.
func buildGoSpiderCommand(crawlURL string, cfg GoSpiderURLConfig, auth crawlAuth) []string {
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
	headers = append(headers, auth.Headers...)
	if strings.TrimSpace(cookie) == "" {
		cookie = auth.Cookie
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
	log.Printf("[GOSPIDER-URL] Starting GoSpider scan for %s (scan ID: %s)", targetURL, scanID)

	cfg := LoadGoSpiderURLConfig(scopeTargetID)
	targets, err := ResolveScanHosts(scopeTargetID, cfg.HostMode, cfg.SelectedHosts)
	if err != nil {
		UpdateGoSpiderURLScanStatus(scanID, "error", "", err.Error(), "", "0s")
		return
	}
	selected := SelectedScanHosts(targets)
	if len(selected) == 0 {
		UpdateGoSpiderURLScanStatus(scanID, "error", "",
			"No hosts are selected for this scan. Open Config and choose at least one host.", "", "0s")
		return
	}
	log.Printf("[GOSPIDER-URL] Crawling %d host(s) one at a time", len(selected))

	executeCrawlerScan("gospider", "gospider_url_scans", scanID, targetURL, scopeTargetID,
		selected, time.Duration(cfg.TimeoutMinutes)*time.Minute, cfg.UseFFUFAuth, cfg.BaseURL,
		func(seedURL string, t ScanHostTarget, auth crawlAuth) []string {
			hostCfg := cfg
			if !t.IsDirect {
				// --whitelist and --whitelist-domain were written against the scope target's own
				// host. Carrying them to an adjacent host would confine that crawl to a domain it
				// is not on, which reads as "the adjacent host had nothing" rather than "the crawl
				// was pointed at the wrong boundary".
				hostCfg.Whitelist = ""
				hostCfg.WhitelistDomain = ""
			}
			return buildGoSpiderCommand(seedURL, hostCfg, auth)
		},
		UpdateGoSpiderURLScanStatus)
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at, target_results
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
			// Per-host outcomes, now that one run covers several hosts.
			TargetResults *string `json:"target_results"`
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt, &scan.TargetResults)
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
			"target_results": scan.TargetResults,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
