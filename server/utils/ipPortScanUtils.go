package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type IPPortScan struct {
	ID                  string    `json:"id"`
	ScanID              string    `json:"scan_id"`
	ScopeTargetID       string    `json:"scope_target_id"`
	Status              string    `json:"status"`
	TotalNetworkRanges  int       `json:"total_network_ranges"`
	ProcessedRanges     int       `json:"processed_network_ranges"`
	TotalIPsDiscovered  int       `json:"total_ips_discovered"`
	TotalPortsScanned   int       `json:"total_ports_scanned"`
	LiveWebServersFound int       `json:"live_web_servers_found"`
	ErrorMessage        string    `json:"error_message,omitempty"`
	ExecutionTime       string    `json:"execution_time,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	AutoScanSessionID   string    `json:"auto_scan_session_id,omitempty"`
}

type LiveWebServer struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	IPAddress     string    `json:"ip_address"`
	Hostname      string    `json:"hostname,omitempty"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	URL           string    `json:"url"`
	StatusCode    *int      `json:"status_code,omitempty"`
	Title         string    `json:"title,omitempty"`
	ServerHeader  string    `json:"server_header,omitempty"`
	ContentLength *int64    `json:"content_length,omitempty"`
	Technologies  []string  `json:"technologies,omitempty"`
	ResponseTime  *float64  `json:"response_time_ms,omitempty"`
	LastChecked   time.Time `json:"last_checked"`
}

type DiscoveredIP struct {
	ID           string    `json:"id"`
	ScanID       string    `json:"scan_id"`
	IPAddress    string    `json:"ip_address"`
	Hostname     string    `json:"hostname,omitempty"`
	NetworkRange string    `json:"network_range"`
	PingTime     *float64  `json:"ping_time_ms,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

type ScanConfig struct {
	MaxIPsPerRange     int           `json:"max_ips_per_range"`
	MaxConcurrentIPs   int           `json:"max_concurrent_ips"`
	MaxConcurrentPorts int           `json:"max_concurrent_ports"`
	HostProbeTimeout   time.Duration `json:"host_probe_timeout"`
	PortScanTimeout    time.Duration `json:"port_scan_timeout"`
	WebServiceTimeout  time.Duration `json:"web_service_timeout"`
}

// Common ports to probe for host discovery
var hostDiscoveryPorts = []int{80, 443, 22, 21, 25, 53, 110, 995, 993, 143}

// Common web ports for detailed scanning
var webPorts = []int{
	80, 443, 8080, 8443, 8000, 8001, 8008, 8888,
	9000, 9001, 9080, 9443, 3000, 3001, 4000, 4001,
	5000, 5001, 7000, 7001, 10000, 10001, 8090, 8181,
	8009, 8006, 8005, 8002, 8007, 8200, 8500, 9090,
	9200, 9300, 5432, 3306, 1433, 27017, 6379, 11211,
}

func getDefaultScanConfig() ScanConfig {
	return ScanConfig{
		MaxIPsPerRange:     254,             // Limit IPs per CIDR
		MaxConcurrentIPs:   50,              // Max concurrent IP probes
		MaxConcurrentPorts: 20,              // Max concurrent port scans
		HostProbeTimeout:   1 * time.Second, // Per port connection timeout
		PortScanTimeout:    1 * time.Second, // Per port connection timeout
		WebServiceTimeout:  5 * time.Second, // Per HTTP request timeout
	}
}

// Main function to run IP/Port scan
func RunIPPortScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[IP-PORT-SCAN] [INFO] Starting IP/Port scan request handling")
	var payload struct {
		ScopeTargetID     string  `json:"scope_target_id" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.ScopeTargetID == "" {
		log.Printf("[IP-PORT-SCAN] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. scope_target_id is required.", http.StatusBadRequest)
		return
	}

	log.Printf("[IP-PORT-SCAN] [INFO] Processing IP/Port scan for scope target: %s", payload.ScopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[IP-PORT-SCAN] [INFO] Generated new scan ID: %s", scanID)

	// Create tables if they don't exist
	createIPPortScanTables()

	// Insert scan record
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO ip_port_scans (scan_id, scope_target_id, status, auto_scan_session_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, payload.ScopeTargetID, "pending", *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO ip_port_scans (scan_id, scope_target_id, status) VALUES ($1, $2, $3)`
		args = []interface{}{scanID, payload.ScopeTargetID, "pending"}
	}

	_, err := dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record", http.StatusInternalServerError)
		return
	}

	// Start the scan in background
	go ExecuteIPPortScan(scanID, payload.ScopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// Execute the complete IP/Port scan process
func ExecuteIPPortScan(scanID, scopeTargetID string) {
	log.Printf("[IP-PORT-SCAN] [INFO] Starting IP/Port scan execution for scope target: %s", scopeTargetID)
	startTime := time.Now()

	// Get consolidated network ranges
	networkRanges, err := getConsolidatedNetworkRanges(scopeTargetID)
	if err != nil {
		updateIPPortScanStatus(scanID, "error", fmt.Sprintf("Failed to get network ranges: %v", err))
		return
	}

	if len(networkRanges) == 0 {
		updateIPPortScanStatus(scanID, "error", "No consolidated network ranges found. Run Amass Intel and Metabigor scans first, then consolidate.")
		return
	}

	log.Printf("[IP-PORT-SCAN] [INFO] Found %d consolidated network ranges", len(networkRanges))

	// Update scan with total ranges
	updateIPPortScanProgress(scanID, "discovering_ips", len(networkRanges), 0, 0, 0, 0)

	// Phase 1: Discover live IPs
	liveIPs, err := discoverLiveIPs(scanID, networkRanges)
	if err != nil {
		updateIPPortScanStatus(scanID, "error", fmt.Sprintf("IP discovery failed: %v", err))
		return
	}

	log.Printf("[IP-PORT-SCAN] [INFO] Discovered %d live IPs", len(liveIPs))
	updateIPPortScanProgress(scanID, "port_scanning", len(networkRanges), len(networkRanges), len(liveIPs), 0, 0)

	// Phase 2: Port scan for web services
	liveWebServers, err := discoverLiveWebServers(scanID, liveIPs)
	if err != nil {
		updateIPPortScanStatus(scanID, "error", fmt.Sprintf("Port scanning failed: %v", err))
		return
	}

	log.Printf("[IP-PORT-SCAN] [INFO] Found %d live web servers", len(liveWebServers))

	// Update final status
	totalPortsScanned := len(liveIPs) * len(webPorts)
	updateIPPortScanProgress(scanID, "success", len(networkRanges), len(networkRanges), len(liveIPs), totalPortsScanned, len(liveWebServers))
	updateIPPortScanExecutionTime(scanID, time.Since(startTime).String())

	log.Printf("[IP-PORT-SCAN] [INFO] IP/Port scan completed in %s", time.Since(startTime).String())
}

// Get consolidated network ranges for a scope target
func getConsolidatedNetworkRanges(scopeTargetID string) ([]ConsolidatedNetworkRange, error) {
	query := `SELECT cidr_block, asn, organization, description, country, source, scan_type 
			  FROM consolidated_network_ranges 
			  WHERE scope_target_id = $1 
			  ORDER BY cidr_block ASC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to query consolidated network ranges: %v", err)
	}
	defer rows.Close()

	var networkRanges []ConsolidatedNetworkRange
	for rows.Next() {
		var networkRange ConsolidatedNetworkRange
		var scanType *string
		if err := rows.Scan(&networkRange.CIDRBlock, &networkRange.ASN, &networkRange.Organization,
			&networkRange.Description, &networkRange.Country, &networkRange.Source, &scanType); err != nil {
			continue
		}
		if scanType != nil {
			networkRange.ScanType = *scanType
		}
		networkRanges = append(networkRanges, networkRange)
	}

	return networkRanges, nil
}

// Discover live IPs using TCP connect probes
func discoverLiveIPs(scanID string, networkRanges []ConsolidatedNetworkRange) ([]string, error) {
	log.Printf("[IP-PORT-SCAN] [INFO] Starting IP discovery for %d network ranges", len(networkRanges))

	config := getDefaultScanConfig()
	var allLiveIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	totalIPsToScan := 0

	// Semaphore to limit concurrent operations
	semaphore := make(chan struct{}, config.MaxConcurrentIPs)

	for rangeIdx, networkRange := range networkRanges {
		log.Printf("[IP-PORT-SCAN] [DEBUG] Processing network range %d/%d: %s", rangeIdx+1, len(networkRanges), networkRange.CIDRBlock)

		// Parse CIDR
		_, ipNet, err := net.ParseCIDR(networkRange.CIDRBlock)
		if err != nil {
			log.Printf("[IP-PORT-SCAN] [ERROR] Invalid CIDR %s: %v", networkRange.CIDRBlock, err)
			continue
		}

		// Generate all IPs in the range
		ips := generateIPsFromCIDR(ipNet)
		log.Printf("[IP-PORT-SCAN] [DEBUG] Generated %d IPs from CIDR %s", len(ips), networkRange.CIDRBlock)

		// Limit the number of IPs to scan per range
		if len(ips) > config.MaxIPsPerRange {
			log.Printf("[IP-PORT-SCAN] [INFO] Limiting scan to first %d IPs in range %s", config.MaxIPsPerRange, networkRange.CIDRBlock)
			ips = ips[:config.MaxIPsPerRange]
		}

		// Probe each IP
		totalIPsToScan += len(ips)
		log.Printf("[IP-PORT-SCAN] [DEBUG] Starting to probe %d IPs in range %s", len(ips), networkRange.CIDRBlock)
		for ipIdx, ip := range ips {
			wg.Add(1)
			go func(ipAddr string, cidr string, idx int) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire
				defer func() { <-semaphore }() // Release

				if idx%50 == 0 {
					log.Printf("[IP-PORT-SCAN] [DEBUG] Probing IP %d/%d in range %s: %s", idx+1, len(ips), cidr, ipAddr)
				}

				if isHostAlive(ipAddr, config.HostProbeTimeout) {
					mu.Lock()
					allLiveIPs = append(allLiveIPs, ipAddr)
					mu.Unlock()

					// Store in database
					insertDiscoveredIP(scanID, ipAddr, cidr)
					log.Printf("[IP-PORT-SCAN] [DEBUG] Live IP discovered: %s", ipAddr)
				}
			}(ip, networkRange.CIDRBlock, ipIdx)
		}
	}

	log.Printf("[IP-PORT-SCAN] [INFO] Total IPs to scan across all ranges: %d", totalIPsToScan)
	log.Printf("[IP-PORT-SCAN] [DEBUG] Waiting for all IP discovery goroutines to complete...")
	wg.Wait()
	log.Printf("[IP-PORT-SCAN] [DEBUG] All IP discovery goroutines completed. Found %d live IPs before deduplication", len(allLiveIPs))

	// Remove duplicates
	uniqueIPs := removeDuplicateIPs(allLiveIPs)
	log.Printf("[IP-PORT-SCAN] [INFO] Total unique live IPs discovered: %d", len(uniqueIPs))

	return uniqueIPs, nil
}

// Check if a host is alive by trying to connect to common ports
func isHostAlive(ip string, timeout time.Duration) bool {
	// Use the timeout directly per port - no division needed
	// Each port gets the full timeout (1 second)

	for _, port := range hostDiscoveryPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true // Host is alive
		}
	}
	return false
}

// Generate all IP addresses from a CIDR block
func generateIPsFromCIDR(ipNet *net.IPNet) []string {
	var ips []string

	// Get the network address
	ip := ipNet.IP

	// Convert to 4-byte representation
	if ip.To4() == nil {
		// IPv6 not supported for now
		return ips
	}

	ip = ip.To4()
	mask := ipNet.Mask

	// Calculate network size
	ones, bits := mask.Size()
	if bits != 32 {
		return ips // Invalid mask
	}

	// For large networks, limit to avoid memory issues
	networkSize := 1 << (bits - ones)
	maxIPs := 65536 // Limit to ~65k IPs max
	if networkSize > maxIPs {
		networkSize = maxIPs
	}

	// Generate IPs
	for i := 1; i < networkSize-1; i++ { // Skip network and broadcast
		newIP := make(net.IP, 4)
		copy(newIP, ip)

		// Add offset
		carry := i
		for j := 3; j >= 0 && carry > 0; j-- {
			sum := int(newIP[j]) + carry
			newIP[j] = byte(sum & 0xFF)
			carry = sum >> 8
		}

		// Check if still in network
		if ipNet.Contains(newIP) {
			ips = append(ips, newIP.String())
		}
	}

	return ips
}

// Port scan live IPs for web services
func discoverLiveWebServers(scanID string, liveIPs []string) ([]LiveWebServer, error) {
	log.Printf("[IP-PORT-SCAN] [INFO] Starting port scanning for %d live IPs", len(liveIPs))

	config := getDefaultScanConfig()
	var allWebServers []LiveWebServer
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrent port scans
	semaphore := make(chan struct{}, config.MaxConcurrentPorts)

	for ipIdx, ip := range liveIPs {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			log.Printf("[IP-PORT-SCAN] [DEBUG] Port scanning IP %d/%d: %s", idx+1, len(liveIPs), ipAddr)

			// Scan web ports
			openPorts := scanTCPPorts(ipAddr, webPorts, config.PortScanTimeout)

			// Check each open port for web services
			for _, port := range openPorts {
				webServer := checkForWebService(scanID, ipAddr, port, config.WebServiceTimeout)
				if webServer != nil {
					mu.Lock()
					allWebServers = append(allWebServers, *webServer)
					mu.Unlock()

					// Store in database
					insertLiveWebServer(scanID, *webServer)
				}
			}

		}(ipIdx, ip)
	}

	wg.Wait()

	log.Printf("[IP-PORT-SCAN] [INFO] Total live web servers found: %d", len(allWebServers))
	return allWebServers, nil
}

// TCP port scanner using connect() method
func scanTCPPorts(ip string, ports []int, timeout time.Duration) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for port scanning concurrency
	semaphore := make(chan struct{}, 10) // Max 10 concurrent connections per IP

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// Check if an open port is running a web service
func checkForWebService(scanID, ipAddr string, port int, timeout time.Duration) *LiveWebServer {
	protocols := []string{"http", "https"}

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s:%d", protocol, ipAddr, port)

		// Custom HTTP client with short timeout
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DisableKeepAlives: true,
			},
		}

		startTime := time.Now()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		responseTime := float64(time.Since(startTime).Nanoseconds()) / 1e6 // Convert to milliseconds

		if err != nil {
			// Try next protocol
			continue
		}
		defer resp.Body.Close()

		// We found a web service!
		webServer := &LiveWebServer{
			ScanID:       scanID,
			IPAddress:    ipAddr,
			Port:         port,
			Protocol:     protocol,
			URL:          url,
			StatusCode:   &resp.StatusCode,
			ResponseTime: &responseTime,
			LastChecked:  time.Now(),
		}

		// Extract server header
		if server := resp.Header.Get("Server"); server != "" {
			webServer.ServerHeader = server
		}

		// Get content length
		if resp.ContentLength > 0 {
			webServer.ContentLength = &resp.ContentLength
		}

		// Try to extract page title
		if title := extractPageTitle(resp); title != "" {
			webServer.Title = title
		}

		// Detect technologies from headers
		technologies := detectTechnologies(resp)
		if len(technologies) > 0 {
			webServer.Technologies = technologies
		}

		return webServer
	}

	return nil
}

// Extract page title from HTTP response
func extractPageTitle(resp *http.Response) string {
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" || !strings.Contains(strings.ToLower(contentType), "text/html") {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Read first 8KB only
	if err != nil {
		return ""
	}

	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

// Detect technologies from HTTP headers
func detectTechnologies(resp *http.Response) []string {
	var technologies []string

	// Check Server header
	if server := resp.Header.Get("Server"); server != "" {
		technologies = append(technologies, server)
	}

	// Check X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		technologies = append(technologies, poweredBy)
	}

	// Check other technology indicators
	for header, values := range resp.Header {
		switch strings.ToLower(header) {
		case "x-aspnet-version":
			if len(values) > 0 {
				technologies = append(technologies, fmt.Sprintf("ASP.NET %s", values[0]))
			}
		case "x-generator":
			if len(values) > 0 {
				technologies = append(technologies, values[0])
			}
		case "x-drupal-cache":
			technologies = append(technologies, "Drupal")
		case "x-powered-cms":
			if len(values) > 0 {
				technologies = append(technologies, values[0])
			}
		}
	}

	return technologies
}

// Database helper functions
func createIPPortScanTables() {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS ip_port_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_network_ranges INT DEFAULT 0,
			processed_network_ranges INT DEFAULT 0,
			total_ips_discovered INT DEFAULT 0,
			total_ports_scanned INT DEFAULT 0,
			live_web_servers_found INT DEFAULT 0,
			error_message TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,
		`CREATE TABLE IF NOT EXISTS discovered_live_ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			network_range TEXT NOT NULL,
			ping_time_ms FLOAT,
			discovered_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS live_web_servers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			port INT NOT NULL,
			protocol VARCHAR(10) NOT NULL,
			url TEXT NOT NULL,
			status_code INT,
			title TEXT,
			server_header TEXT,
			content_length BIGINT,
			technologies JSONB,
			response_time_ms FLOAT,
			screenshot_path TEXT,
			last_checked TIMESTAMP DEFAULT NOW(),
			UNIQUE(scan_id, ip_address, port, protocol)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_live_ips_scan_id ON discovered_live_ips(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_scan_id ON live_web_servers(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_ip_port ON live_web_servers(ip_address, port);`,
		`ALTER TABLE discovered_live_ips ADD COLUMN IF NOT EXISTS hostname TEXT;`,
		`ALTER TABLE live_web_servers ADD COLUMN IF NOT EXISTS hostname TEXT;`,
	}

	for _, tableQuery := range tables {
		_, err := dbPool.Exec(context.Background(), tableQuery)
		if err != nil {
			log.Printf("[IP-PORT-SCAN] [ERROR] Failed to create table/index: %v", err)
		}
	}
}

func insertDiscoveredIP(scanID, ipAddress, networkRange string) {
	// Resolve hostname for the IP address
	hostname := resolveHostname(ipAddress)

	query := `INSERT INTO discovered_live_ips (scan_id, ip_address, hostname, network_range) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), query, scanID, ipAddress, hostname, networkRange)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to insert discovered IP: %v", err)
	} else if hostname != "" {
		log.Printf("[IP-PORT-SCAN] [DEBUG] Resolved hostname for %s: %s", ipAddress, hostname)
	}
}

func insertLiveWebServer(scanID string, webServer LiveWebServer) {
	// Resolve hostname for the IP address if not already set
	if webServer.Hostname == "" {
		webServer.Hostname = resolveHostname(webServer.IPAddress)
	}

	query := `INSERT INTO live_web_servers (scan_id, ip_address, hostname, port, protocol, url, status_code, title, server_header, content_length, technologies, response_time_ms) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			  ON CONFLICT (scan_id, ip_address, port, protocol) DO UPDATE SET
			  hostname = EXCLUDED.hostname, status_code = EXCLUDED.status_code, title = EXCLUDED.title, server_header = EXCLUDED.server_header,
			  content_length = EXCLUDED.content_length, technologies = EXCLUDED.technologies, 
			  response_time_ms = EXCLUDED.response_time_ms, last_checked = NOW()`

	technologiesJSON, _ := json.Marshal(webServer.Technologies)

	_, err := dbPool.Exec(context.Background(), query,
		scanID, webServer.IPAddress, webServer.Hostname, webServer.Port, webServer.Protocol, webServer.URL,
		webServer.StatusCode, webServer.Title, webServer.ServerHeader, webServer.ContentLength,
		technologiesJSON, webServer.ResponseTime)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to insert live web server: %v", err)
	} else if webServer.Hostname != "" {
		log.Printf("[IP-PORT-SCAN] [DEBUG] Resolved hostname for %s: %s", webServer.IPAddress, webServer.Hostname)
	}
}

func updateIPPortScanStatus(scanID, status, errorMessage string) {
	query := `UPDATE ip_port_scans SET status = $1, error_message = $2 WHERE scan_id = $3`
	_, err := dbPool.Exec(context.Background(), query, status, errorMessage, scanID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to update scan status: %v", err)
	}
}

func updateIPPortScanProgress(scanID string, status string, totalRanges, processedRanges, totalIPs, totalPorts, liveServers int) {
	query := `UPDATE ip_port_scans SET 
			  status = $1, 
			  total_network_ranges = $2, 
			  processed_network_ranges = $3, 
			  total_ips_discovered = $4, 
			  total_ports_scanned = $5, 
			  live_web_servers_found = $6 
			  WHERE scan_id = $7`

	_, err := dbPool.Exec(context.Background(), query, status, totalRanges, processedRanges, totalIPs, totalPorts, liveServers, scanID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to update scan progress: %v", err)
	}
}

func updateIPPortScanExecutionTime(scanID, executionTime string) {
	query := `UPDATE ip_port_scans SET execution_time = $1 WHERE scan_id = $2`
	_, err := dbPool.Exec(context.Background(), query, executionTime, scanID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to update execution time: %v", err)
	}
}

func removeDuplicateIPs(ips []string) []string {
	keys := make(map[string]bool)
	var unique []string

	for _, ip := range ips {
		if !keys[ip] {
			keys[ip] = true
			unique = append(unique, ip)
		}
	}

	return unique
}

// Resolve hostname for an IP address with timeout
func resolveHostname(ipAddr string) string {
	// Set a timeout for DNS resolution
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 2 * time.Second, // 2 second timeout for DNS resolution
			}
			return d.DialContext(ctx, network, address)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, ipAddr)
	if err != nil || len(names) == 0 {
		return "" // No hostname found
	}

	// Return the first hostname, removing trailing dot
	hostname := names[0]
	if strings.HasSuffix(hostname, ".") {
		hostname = hostname[:len(hostname)-1]
	}
	return hostname
}

// API handlers
func GetIPPortScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT scan_id, scope_target_id, status, total_network_ranges, processed_network_ranges, 
			  total_ips_discovered, total_ports_scanned, live_web_servers_found, error_message, 
			  execution_time, created_at, auto_scan_session_id FROM ip_port_scans WHERE scan_id = $1`

	var scan IPPortScan
	var autoScanSessionID *string
	var errorMessage *string
	var executionTime *string
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.ScopeTargetID, &scan.Status, &scan.TotalNetworkRanges,
		&scan.ProcessedRanges, &scan.TotalIPsDiscovered, &scan.TotalPortsScanned,
		&scan.LiveWebServersFound, &errorMessage, &executionTime,
		&scan.CreatedAt, &autoScanSessionID)

	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to get scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	if autoScanSessionID != nil {
		scan.AutoScanSessionID = *autoScanSessionID
	}
	if errorMessage != nil {
		scan.ErrorMessage = *errorMessage
	}
	if executionTime != nil {
		scan.ExecutionTime = *executionTime
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetLiveWebServers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("[IP-PORT-SCAN] [DEBUG] Fetching live web servers for scan ID: %s", scanID)

	query := `SELECT scan_id, ip_address, hostname, port, protocol, url, status_code, title, 
			  server_header, content_length, technologies, response_time_ms, last_checked 
			  FROM live_web_servers WHERE scan_id = $1 ORDER BY ip_address, port`

	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to get live web servers: %v", err)
		http.Error(w, "Failed to get live web servers", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var webServers []LiveWebServer
	for rows.Next() {
		var ws LiveWebServer
		var technologiesJSON *string
		var ipAddress net.IP
		var hostname *string

		err := rows.Scan(&ws.ScanID, &ipAddress, &hostname, &ws.Port, &ws.Protocol, &ws.URL,
			&ws.StatusCode, &ws.Title, &ws.ServerHeader, &ws.ContentLength,
			&technologiesJSON, &ws.ResponseTime, &ws.LastChecked)
		if err != nil {
			log.Printf("[IP-PORT-SCAN] [ERROR] Error scanning web server row: %v", err)
			continue
		}

		// Convert net.IP to string
		ws.IPAddress = ipAddress.String()

		// Set hostname if available
		if hostname != nil {
			ws.Hostname = *hostname
		}

		// Parse technologies JSON
		if technologiesJSON != nil && *technologiesJSON != "" {
			json.Unmarshal([]byte(*technologiesJSON), &ws.Technologies)
		}

		webServers = append(webServers, ws)
	}

	log.Printf("[IP-PORT-SCAN] [DEBUG] Found %d live web servers for scan %s", len(webServers), scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(webServers)
}

func GetIPPortScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT scan_id, scope_target_id, status, total_network_ranges, processed_network_ranges,
			  total_ips_discovered, total_ports_scanned, live_web_servers_found, error_message,
			  execution_time, created_at, auto_scan_session_id FROM ip_port_scans 
			  WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to get IP/Port scans: %v", err)
		http.Error(w, "Failed to get IP/Port scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []IPPortScan
	for rows.Next() {
		var scan IPPortScan
		var autoScanSessionID *string
		var errorMessage *string
		var executionTime *string
		err := rows.Scan(&scan.ScanID, &scan.ScopeTargetID, &scan.Status, &scan.TotalNetworkRanges,
			&scan.ProcessedRanges, &scan.TotalIPsDiscovered, &scan.TotalPortsScanned,
			&scan.LiveWebServersFound, &errorMessage, &executionTime,
			&scan.CreatedAt, &autoScanSessionID)
		if err != nil {
			log.Printf("[IP-PORT-SCAN] [ERROR] Error scanning IP/Port scan row: %v", err)
			continue
		}

		if autoScanSessionID != nil {
			scan.AutoScanSessionID = *autoScanSessionID
		}
		if errorMessage != nil {
			scan.ErrorMessage = *errorMessage
		}
		if executionTime != nil {
			scan.ExecutionTime = *executionTime
		}

		scans = append(scans, scan)
	}

	// Return scans wrapped in a "scans" object to match frontend expectations
	response := map[string]interface{}{
		"scans": scans,
		"count": len(scans),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetDiscoveredIPs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("[IP-PORT-SCAN] [DEBUG] Fetching discovered IPs for scan ID: %s", scanID)

	query := `SELECT scan_id, ip_address, hostname, network_range, ping_time_ms, discovered_at 
			  FROM discovered_live_ips WHERE scan_id = $1 ORDER BY ip_address`

	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[IP-PORT-SCAN] [ERROR] Failed to get discovered IPs: %v", err)
		http.Error(w, "Failed to get discovered IPs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var discoveredIPs []DiscoveredIP
	for rows.Next() {
		var ip DiscoveredIP
		var ipAddress net.IP
		var hostname *string

		err := rows.Scan(&ip.ScanID, &ipAddress, &hostname, &ip.NetworkRange, &ip.PingTime, &ip.DiscoveredAt)
		if err != nil {
			log.Printf("[IP-PORT-SCAN] [ERROR] Error scanning discovered IP row: %v", err)
			continue
		}

		// Convert net.IP to string
		ip.IPAddress = ipAddress.String()

		// Set hostname if available
		if hostname != nil {
			ip.Hostname = *hostname
		}

		discoveredIPs = append(discoveredIPs, ip)
	}

	log.Printf("[IP-PORT-SCAN] [DEBUG] Found %d discovered IPs for scan %s", len(discoveredIPs), scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discoveredIPs)
}
