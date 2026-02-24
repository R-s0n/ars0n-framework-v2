package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

// GetRateLimit retrieves the rate limit for a specific tool from the database
func GetRateLimit(tool string) int {
	// Default rate limits
	defaultLimits := map[string]int{
		"amass":             10,
		"httpx":             150,
		"subfinder":         20,
		"gau":               10,
		"sublist3r":         10,
		"ctl":               10,
		"shuffledns":        10000,
		"cewl":              10,
		"gospider":          5,
		"subdomainizer":     5,
		"nuclei_screenshot": 20,
	}

	// Check if the tool has a default rate limit
	defaultLimit, exists := defaultLimits[tool]
	if !exists {
		return 10 // Default fallback if tool not found
	}

	// Query the database for the tool's rate limit
	columnName := tool + "_rate_limit"
	query := "SELECT " + columnName + " FROM user_settings LIMIT 1"

	var rateLimit int
	err := dbPool.QueryRow(context.Background(), query).Scan(&rateLimit)
	if err != nil {
		log.Printf("Error fetching rate limit for %s: %v", tool, err)
		return defaultLimit
	}

	return rateLimit
}

// GetAmassRateLimit returns the rate limit for Amass
func GetAmassRateLimit() int {
	return GetRateLimit("amass")
}

// GetHttpxRateLimit returns the rate limit for HTTPX
func GetHttpxRateLimit() int {
	return GetRateLimit("httpx")
}

// GetSubfinderRateLimit returns the rate limit for Subfinder
func GetSubfinderRateLimit() int {
	return GetRateLimit("subfinder")
}

// GetGauRateLimit returns the rate limit for GAU
func GetGauRateLimit() int {
	return GetRateLimit("gau")
}

// GetSublist3rRateLimit returns the rate limit for Sublist3r
func GetSublist3rRateLimit() int {
	return GetRateLimit("sublist3r")
}

// GetCTLRateLimit returns the rate limit for CTL
func GetCTLRateLimit() int {
	return GetRateLimit("ctl")
}

// GetShuffleDNSRateLimit returns the rate limit for ShuffleDNS
func GetShuffleDNSRateLimit() int {
	return GetRateLimit("shuffledns")
}

// GetCeWLRateLimit returns the rate limit for CeWL
func GetCeWLRateLimit() int {
	return GetRateLimit("cewl")
}

// GetGoSpiderRateLimit returns the rate limit for GoSpider
func GetGoSpiderRateLimit() int {
	return GetRateLimit("gospider")
}

// GetSubdomainizerRateLimit returns the rate limit for Subdomainizer
func GetSubdomainizerRateLimit() int {
	return GetRateLimit("subdomainizer")
}

// GetNucleiScreenshotRateLimit returns the rate limit for Nuclei Screenshot
func GetNucleiScreenshotRateLimit() int {
	return GetRateLimit("nuclei_screenshot")
}

// GetCustomHTTPSettings retrieves the custom HTTP settings from the database
func GetCustomHTTPSettings() (string, string) {
	var customUserAgent, customHeader sql.NullString

	err := dbPool.QueryRow(context.Background(), `
		SELECT custom_user_agent, custom_header
		FROM user_settings
		LIMIT 1
	`).Scan(&customUserAgent, &customHeader)

	if err != nil {
		log.Printf("[ERROR] Failed to fetch custom HTTP settings: %v", err)
		return "", ""
	}

	return customUserAgent.String, customHeader.String
}

func GetBurpSuiteProxySettings() (string, int) {
	var burpProxyIP sql.NullString
	var burpProxyPort int

	err := dbPool.QueryRow(context.Background(), `
		SELECT burp_proxy_ip, burp_proxy_port
		FROM user_settings
		LIMIT 1
	`).Scan(&burpProxyIP, &burpProxyPort)

	if err != nil {
		log.Printf("[ERROR] Failed to fetch Burp Suite proxy settings: %v", err)
		return "127.0.0.1", 8080
	}

	ip := burpProxyIP.String
	if ip == "" {
		ip = "127.0.0.1"
	}

	if burpProxyPort == 0 {
		burpProxyPort = 8080
	}

	return ip, burpProxyPort
}

func GetBurpSuiteAPISettings() (string, int, string) {
	var burpAPIIP, burpAPIKey sql.NullString
	var burpAPIPort int

	err := dbPool.QueryRow(context.Background(), `
		SELECT burp_api_ip, burp_api_port, burp_api_key
		FROM user_settings
		LIMIT 1
	`).Scan(&burpAPIIP, &burpAPIPort, &burpAPIKey)

	if err != nil {
		log.Printf("[ERROR] Failed to fetch Burp Suite API settings: %v", err)
		return "127.0.0.1", 1337, ""
	}

	ip := burpAPIIP.String
	if ip == "" {
		ip = "127.0.0.1"
	}

	if burpAPIPort == 0 {
		burpAPIPort = 1337
	}

	return ip, burpAPIPort, burpAPIKey.String
}

func GetBurpSuiteSettings() (string, int, string, int, string) {
	var burpProxyIP, burpAPIIP, burpAPIKey sql.NullString
	var burpProxyPort, burpAPIPort int

	err := dbPool.QueryRow(context.Background(), `
		SELECT burp_proxy_ip, burp_proxy_port, burp_api_ip, burp_api_port, burp_api_key
		FROM user_settings
		LIMIT 1
	`).Scan(&burpProxyIP, &burpProxyPort, &burpAPIIP, &burpAPIPort, &burpAPIKey)

	if err != nil {
		log.Printf("[ERROR] Failed to fetch Burp Suite settings: %v", err)
		return "127.0.0.1", 8080, "127.0.0.1", 1337, ""
	}

	proxyIP := burpProxyIP.String
	if proxyIP == "" {
		proxyIP = "127.0.0.1"
	}

	apiIP := burpAPIIP.String
	if apiIP == "" {
		apiIP = "127.0.0.1"
	}

	if burpProxyPort == 0 {
		burpProxyPort = 8080
	}

	if burpAPIPort == 0 {
		burpAPIPort = 1337
	}

	return proxyIP, burpProxyPort, apiIP, burpAPIPort, burpAPIKey.String
}

func GetAiAPIKeyByProvider(provider string) (string, map[string]interface{}, error) {
	var apiKeyName, keyValuesJSON string

	err := dbPool.QueryRow(context.Background(), `
		SELECT api_key_name, key_values
		FROM ai_api_keys
		WHERE provider = $1
		LIMIT 1
	`, provider).Scan(&apiKeyName, &keyValuesJSON)

	if err != nil {
		log.Printf("[ERROR] Failed to fetch AI API key for provider %s: %v", provider, err)
		return "", nil, err
	}

	var keyValues map[string]interface{}
	if err := json.Unmarshal([]byte(keyValuesJSON), &keyValues); err != nil {
		log.Printf("[ERROR] Failed to parse AI API key values for provider %s: %v", provider, err)
		return "", nil, err
	}

	return apiKeyName, keyValues, nil
}

func GetAllAiAPIKeys() ([]map[string]interface{}, error) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, provider, api_key_name, key_values, created_at, updated_at
		FROM ai_api_keys
		ORDER BY provider, api_key_name
	`)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch AI API keys: %v", err)
		return nil, err
	}
	defer rows.Close()

	var aiApiKeys []map[string]interface{}
	for rows.Next() {
		var id, provider, apiKeyName, keyValuesJSON string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &provider, &apiKeyName, &keyValuesJSON, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("[ERROR] Error scanning AI API key row: %v", err)
			continue
		}

		var keyValues map[string]interface{}
		if err := json.Unmarshal([]byte(keyValuesJSON), &keyValues); err != nil {
			log.Printf("[ERROR] Error parsing AI key values: %v", err)
			continue
		}

		aiApiKeys = append(aiApiKeys, map[string]interface{}{
			"id":           id,
			"provider":     provider,
			"api_key_name": apiKeyName,
			"key_values":   keyValues,
			"created_at":   createdAt,
			"updated_at":   updatedAt,
		})
	}

	return aiApiKeys, nil
}

func GetAiAPIKeysByProvider(provider string) ([]map[string]interface{}, error) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, api_key_name, key_values, created_at, updated_at
		FROM ai_api_keys
		WHERE provider = $1
		ORDER BY api_key_name
	`, provider)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch AI API keys for provider %s: %v", provider, err)
		return nil, err
	}
	defer rows.Close()

	var aiApiKeys []map[string]interface{}
	for rows.Next() {
		var id, apiKeyName, keyValuesJSON string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &apiKeyName, &keyValuesJSON, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("[ERROR] Error scanning AI API key row: %v", err)
			continue
		}

		var keyValues map[string]interface{}
		if err := json.Unmarshal([]byte(keyValuesJSON), &keyValues); err != nil {
			log.Printf("[ERROR] Error parsing AI key values: %v", err)
			continue
		}

		aiApiKeys = append(aiApiKeys, map[string]interface{}{
			"id":           id,
			"api_key_name": apiKeyName,
			"key_values":   keyValues,
			"created_at":   createdAt,
			"updated_at":   updatedAt,
		})
	}

	return aiApiKeys, nil
}
