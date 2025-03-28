package utils

import (
	"context"
	"database/sql"
	"log"
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
