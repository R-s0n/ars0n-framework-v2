package utils

import (
	"context"
	"encoding/json"
	"log"
	"strings"
)

// Google Dorking domain functions
func GetGoogleDorkingDomainsForTool(scopeTargetID string) ([]string, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT domain FROM google_dorking_domains WHERE scope_target_id = $1 ORDER BY created_at DESC`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func DeleteGoogleDorkingDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] DeleteGoogleDorkingDomainFromTool called: domainToDelete='%s'", domainToDelete)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for Google Dorking deletion: %v", err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Delete the specific domain
	result, err := tx.Exec(context.Background(),
		`DELETE FROM google_dorking_domains 
		 WHERE scope_target_id = $1 AND domain = $2`,
		scopeTargetID, domainToDelete)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to delete Google Dorking domain: %v", err)
		return false, err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		log.Printf("[DOMAIN-MANAGER] [WARNING] Google Dorking domain '%s' not found", domainToDelete)
		return false, nil
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit Google Dorking transaction: %v", err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully deleted Google Dorking domain '%s'", domainToDelete)
	return true, nil
}

func DeleteAllGoogleDorkingDomainsFromTool(scopeTargetID string) (int64, error) {
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM google_dorking_domains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// Reverse Whois domain functions
func GetReverseWhoisDomainsForTool(scopeTargetID string) ([]string, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT domain FROM reverse_whois_domains WHERE scope_target_id = $1 ORDER BY created_at DESC`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func DeleteReverseWhoisDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] DeleteReverseWhoisDomainFromTool called: domainToDelete='%s'", domainToDelete)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for Reverse Whois deletion: %v", err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Delete the specific domain
	result, err := tx.Exec(context.Background(),
		`DELETE FROM reverse_whois_domains 
		 WHERE scope_target_id = $1 AND domain = $2`,
		scopeTargetID, domainToDelete)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to delete Reverse Whois domain: %v", err)
		return false, err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		log.Printf("[DOMAIN-MANAGER] [WARNING] Reverse Whois domain '%s' not found", domainToDelete)
		return false, nil
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit Reverse Whois transaction: %v", err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully deleted Reverse Whois domain '%s'", domainToDelete)
	return true, nil
}

func DeleteAllReverseWhoisDomainsFromTool(scopeTargetID string) (int64, error) {
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM reverse_whois_domains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// CTL Company domain functions
func GetCTLCompanyDomainsForTool(scopeTargetID string) ([]string, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT result FROM ctl_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err == nil && result != "" {
			lines := strings.Split(result, "\n")
			for _, line := range lines {
				domain := strings.TrimSpace(line)
				if domain != "" {
					domains = append(domains, domain)
				}
			}
		}
	}
	return domains, nil
}

func DeleteCTLCompanyDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] DeleteCTLCompanyDomainFromTool called: domainToDelete='%s'", domainToDelete)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for CTL deletion: %v", err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Get current results with row lock
	row := tx.QueryRow(context.Background(),
		`SELECT id, result FROM ctl_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
		scopeTargetID)

	var scanID string
	var result string
	if err := row.Scan(&scanID, &result); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to get CTL scan result: %v", err)
		return false, err
	}

	// Parse domains and remove the target domain
	lines := strings.Split(result, "\n")
	var newLines []string
	found := false
	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" && domain != domainToDelete {
			newLines = append(newLines, domain)
		} else if domain == domainToDelete {
			found = true
			log.Printf("[DOMAIN-MANAGER] [DEBUG] Found CTL domain match: '%s'", domain)
		}
	}

	if !found {
		log.Printf("[DOMAIN-MANAGER] [WARNING] CTL domain '%s' not found", domainToDelete)
		return false, nil
	}

	// Update the scan result
	newResult := strings.Join(newLines, "\n")
	_, err = tx.Exec(context.Background(),
		`UPDATE ctl_company_scans SET result = $1 WHERE id = $2`,
		newResult, scanID)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to update CTL scan result: %v", err)
		return false, err
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit CTL transaction: %v", err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully deleted CTL domain '%s'", domainToDelete)
	return true, nil
}

func DeleteAllCTLCompanyDomainsFromTool(scopeTargetID string) (int64, error) {
	// Clear all scan results for CTL company scans
	result, err := dbPool.Exec(context.Background(),
		`UPDATE ctl_company_scans SET result = '' 
		 WHERE scope_target_id = $1 AND status = 'success'`,
		scopeTargetID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// SecurityTrails Company domain functions
func GetSecurityTrailsCompanyDomainsForTool(scopeTargetID string) ([]string, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] GetSecurityTrailsCompanyDomainsForTool called for scope target: %s", scopeTargetID)
	result, err := getJSONDomainsFromScan(scopeTargetID, "securitytrails_company_scans")
	log.Printf("[DOMAIN-MANAGER] [DEBUG] GetSecurityTrailsCompanyDomainsForTool returning %d domains", len(result))
	return result, err
}

func DeleteSecurityTrailsCompanyDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	return updateJSONScanResult(scopeTargetID, "securitytrails_company_scans", domainToDelete, false)
}

func DeleteAllSecurityTrailsCompanyDomainsFromTool(scopeTargetID string) (int64, error) {
	return clearJSONScanResults(scopeTargetID, "securitytrails_company_scans")
}

// Censys Company domain functions
func GetCensysCompanyDomainsForTool(scopeTargetID string) ([]string, error) {
	return getJSONDomainsFromScan(scopeTargetID, "censys_company_scans")
}

func DeleteCensysCompanyDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	return updateJSONScanResult(scopeTargetID, "censys_company_scans", domainToDelete, false)
}

func DeleteAllCensysCompanyDomainsFromTool(scopeTargetID string) (int64, error) {
	return clearJSONScanResults(scopeTargetID, "censys_company_scans")
}

// GitHub Recon domain functions
func GetGitHubReconDomainsForTool(scopeTargetID string) ([]string, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] GetGitHubReconDomainsForTool called for scope target: %s", scopeTargetID)
	result, err := getJSONDomainsFromScan(scopeTargetID, "github_recon_scans")
	log.Printf("[DOMAIN-MANAGER] [DEBUG] GetGitHubReconDomainsForTool returning %d domains", len(result))
	return result, err
}

func DeleteGitHubReconDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	return updateJSONScanResult(scopeTargetID, "github_recon_scans", domainToDelete, false)
}

func DeleteAllGitHubReconDomainsFromTool(scopeTargetID string) (int64, error) {
	return clearJSONScanResults(scopeTargetID, "github_recon_scans")
}

// Shodan Company domain functions
func GetShodanCompanyDomainsForTool(scopeTargetID string) ([]string, error) {
	return getJSONDomainsFromScan(scopeTargetID, "shodan_company_scans")
}

func DeleteShodanCompanyDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	return updateJSONScanResult(scopeTargetID, "shodan_company_scans", domainToDelete, false)
}

func DeleteAllShodanCompanyDomainsFromTool(scopeTargetID string) (int64, error) {
	return clearJSONScanResults(scopeTargetID, "shodan_company_scans")
}

// Metabigor Company domain functions (similar to CTL)
func GetMetabigorCompanyDomainsForTool(scopeTargetID string) ([]string, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT result FROM metabigor_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err == nil && result != "" {
			lines := strings.Split(result, "\n")
			for _, line := range lines {
				domain := strings.TrimSpace(line)
				if domain != "" {
					domains = append(domains, domain)
				}
			}
		}
	}
	return domains, nil
}

func DeleteMetabigorCompanyDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] DeleteMetabigorCompanyDomainFromTool called: domainToDelete='%s'", domainToDelete)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for Metabigor deletion: %v", err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Similar to CTL implementation with row lock
	row := tx.QueryRow(context.Background(),
		`SELECT id, result FROM metabigor_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
		scopeTargetID)

	var scanID string
	var result string
	if err := row.Scan(&scanID, &result); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to get Metabigor scan result: %v", err)
		return false, err
	}

	lines := strings.Split(result, "\n")
	var newLines []string
	found := false
	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" && domain != domainToDelete {
			newLines = append(newLines, domain)
		} else if domain == domainToDelete {
			found = true
			log.Printf("[DOMAIN-MANAGER] [DEBUG] Found Metabigor domain match: '%s'", domain)
		}
	}

	if !found {
		log.Printf("[DOMAIN-MANAGER] [WARNING] Metabigor domain '%s' not found", domainToDelete)
		return false, nil
	}

	newResult := strings.Join(newLines, "\n")
	_, err = tx.Exec(context.Background(),
		`UPDATE metabigor_company_scans SET result = $1 WHERE id = $2`,
		newResult, scanID)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to update Metabigor scan result: %v", err)
		return false, err
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit Metabigor transaction: %v", err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully deleted Metabigor domain '%s'", domainToDelete)
	return true, nil
}

func DeleteAllMetabigorCompanyDomainsFromTool(scopeTargetID string) (int64, error) {
	result, err := dbPool.Exec(context.Background(),
		`UPDATE metabigor_company_scans SET result = '' 
		 WHERE scope_target_id = $1 AND status = 'success'`,
		scopeTargetID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// Helper functions for JSON-based scan results
func getJSONDomainsFromScan(scopeTargetID, tableName string) ([]string, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] Fetching domains from %s for scope target %s", tableName, scopeTargetID)

	query := `SELECT result FROM ` + tableName + ` 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`
	log.Printf("[DOMAIN-MANAGER] [DEBUG] Executing query: %s with scope_target_id: %s", query, scopeTargetID)

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Query failed for %s: %v", tableName, err)
		return nil, err
	}
	defer rows.Close()

	var domains []string
	rowCount := 0
	for rows.Next() {
		rowCount++
		log.Printf("[DOMAIN-MANAGER] [DEBUG] Processing row %d from %s", rowCount, tableName)

		var result string
		if err := rows.Scan(&result); err == nil && result != "" {
			log.Printf("[DOMAIN-MANAGER] [DEBUG] Found result for %s, length: %d", tableName, len(result))
			log.Printf("[DOMAIN-MANAGER] [DEBUG] First 200 chars of result: %.200s", result)

			var resultData map[string]interface{}
			if err := json.Unmarshal([]byte(result), &resultData); err == nil {
				log.Printf("[DOMAIN-MANAGER] [DEBUG] Successfully parsed JSON for %s", tableName)

				// Log the keys in the JSON
				keys := make([]string, 0, len(resultData))
				for k := range resultData {
					keys = append(keys, k)
				}
				log.Printf("[DOMAIN-MANAGER] [DEBUG] JSON keys for %s: %v", tableName, keys)

				if domainList, ok := resultData["domains"].([]interface{}); ok {
					log.Printf("[DOMAIN-MANAGER] [DEBUG] Found domains array with %d items for %s", len(domainList), tableName)

					for i, d := range domainList {
						// Only log details for first 5 items
						if i < 5 {
							log.Printf("[DOMAIN-MANAGER] [DEBUG] Domain item %d type: %T, value: %+v", i, d, d)
						}

						if domain, ok := d.(string); ok {
							domains = append(domains, strings.TrimSpace(domain))
							if i < 5 { // Log first 5 domains
								log.Printf("[DOMAIN-MANAGER] [DEBUG] Domain %d: %s", i, domain)
							}
						} else {
							// Check if it's an object with domain field
							if domainObj, ok := d.(map[string]interface{}); ok {
								if i < 5 {
									log.Printf("[DOMAIN-MANAGER] [DEBUG] Domain item %d is object with keys: %v", i, func() []string {
										keys := make([]string, 0, len(domainObj))
										for k := range domainObj {
											keys = append(keys, k)
										}
										return keys
									}())
								}

								// Try different possible field names
								var actualDomain string
								if domainName, ok := domainObj["domain"].(string); ok {
									actualDomain = strings.TrimSpace(domainName)
								} else if domainName, ok := domainObj["hostname"].(string); ok {
									actualDomain = strings.TrimSpace(domainName)
								} else if domainName, ok := domainObj["name"].(string); ok {
									actualDomain = strings.TrimSpace(domainName)
								}

								if actualDomain != "" {
									domains = append(domains, actualDomain)
									if i < 5 {
										log.Printf("[DOMAIN-MANAGER] [DEBUG] Extracted domain from object: %s", actualDomain)
									}
								} else {
									if i < 5 {
										log.Printf("[DOMAIN-MANAGER] [WARNING] Could not extract domain from object: %+v", domainObj)
									}
								}
							} else {
								if i < 5 {
									log.Printf("[DOMAIN-MANAGER] [WARNING] Domain item %d is not string or object: %T", i, d)
								}
							}
						}
					}
				} else {
					log.Printf("[DOMAIN-MANAGER] [WARNING] No domains array found in result for %s", tableName)
					log.Printf("[DOMAIN-MANAGER] [DEBUG] Type of 'domains' field: %T", resultData["domains"])
				}
			} else {
				log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to parse JSON for %s: %v", tableName, err)
			}
		} else {
			log.Printf("[DOMAIN-MANAGER] [DEBUG] No valid result found for %s, scan error: %v", tableName, err)
		}
	}

	if rowCount == 0 {
		log.Printf("[DOMAIN-MANAGER] [WARNING] No rows found for %s with scope_target_id %s", tableName, scopeTargetID)

		// Let's check if there are any rows at all for this scope target
		var totalRows int
		countQuery := `SELECT COUNT(*) FROM ` + tableName + ` WHERE scope_target_id = $1`
		if err := dbPool.QueryRow(context.Background(), countQuery, scopeTargetID).Scan(&totalRows); err == nil {
			log.Printf("[DOMAIN-MANAGER] [DEBUG] Total rows in %s for scope_target_id %s: %d", tableName, scopeTargetID, totalRows)

			// Check status distribution
			statusQuery := `SELECT status, COUNT(*) FROM ` + tableName + ` WHERE scope_target_id = $1 GROUP BY status`
			statusRows, err := dbPool.Query(context.Background(), statusQuery, scopeTargetID)
			if err == nil {
				defer statusRows.Close()
				log.Printf("[DOMAIN-MANAGER] [DEBUG] Status distribution for %s:", tableName)
				for statusRows.Next() {
					var status string
					var count int
					if statusRows.Scan(&status, &count) == nil {
						log.Printf("[DOMAIN-MANAGER] [DEBUG] - %s: %d", status, count)
					}
				}
			}
		}
	}

	log.Printf("[DOMAIN-MANAGER] [DEBUG] Returning %d domains for %s", len(domains), tableName)
	return domains, nil
}

func updateJSONScanResult(scopeTargetID, tableName, domainToDelete string, clear bool) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] updateJSONScanResult called: table=%s, domainToDelete='%s', clear=%v", tableName, domainToDelete, clear)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for %s: %v", tableName, err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Use SELECT FOR UPDATE to lock the row
	row := tx.QueryRow(context.Background(),
		`SELECT id, result FROM `+tableName+` 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
		scopeTargetID)

	var scanID string
	var result string
	if err := row.Scan(&scanID, &result); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to get scan result for %s: %v", tableName, err)
		return false, err
	}

	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &resultData); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to unmarshal JSON for %s: %v", tableName, err)
		return false, err
	}

	domainList, ok := resultData["domains"].([]interface{})
	if !ok {
		log.Printf("[DOMAIN-MANAGER] [ERROR] No domains array found in result for %s", tableName)
		return false, nil
	}

	log.Printf("[DOMAIN-MANAGER] [DEBUG] Processing %d domains in %s, looking for '%s'", len(domainList), tableName, domainToDelete)

	var newDomains []interface{}
	found := false
	for i, d := range domainList {
		if domain, ok := d.(string); ok {
			if !clear && strings.TrimSpace(domain) != domainToDelete {
				newDomains = append(newDomains, domain)
			} else if strings.TrimSpace(domain) == domainToDelete {
				found = true
				log.Printf("[DOMAIN-MANAGER] [DEBUG] Found string domain match at index %d: '%s'", i, domain)
			}
		} else if domainObj, ok := d.(map[string]interface{}); ok {
			var actualDomain string
			if domainName, ok := domainObj["domain"].(string); ok {
				actualDomain = strings.TrimSpace(domainName)
			} else if domainName, ok := domainObj["hostname"].(string); ok {
				actualDomain = strings.TrimSpace(domainName)
			} else if domainName, ok := domainObj["name"].(string); ok {
				actualDomain = strings.TrimSpace(domainName)
			}

			if actualDomain != "" {
				if !clear && actualDomain != domainToDelete {
					newDomains = append(newDomains, d)
				} else if actualDomain == domainToDelete {
					found = true
					log.Printf("[DOMAIN-MANAGER] [DEBUG] Found object domain match at index %d: '%s'", i, actualDomain)
				}
			} else {
				newDomains = append(newDomains, d)
			}
		} else {
			newDomains = append(newDomains, d)
		}
	}

	if !clear && !found {
		log.Printf("[DOMAIN-MANAGER] [WARNING] Domain '%s' not found in %s (searched %d domains)", domainToDelete, tableName, len(domainList))
		return false, nil
	}

	if clear {
		newDomains = []interface{}{}
	}

	resultData["domains"] = newDomains
	if meta, ok := resultData["meta"].(map[string]interface{}); ok {
		meta["total"] = len(newDomains)
	}

	log.Printf("[DOMAIN-MANAGER] [DEBUG] Domain count changed from %d to %d in %s", len(domainList), len(newDomains), tableName)

	newResultJSON, err := json.Marshal(resultData)
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to marshal updated JSON for %s: %v", tableName, err)
		return false, err
	}

	_, err = tx.Exec(context.Background(),
		`UPDATE `+tableName+` SET result = $1 WHERE id = $2`,
		string(newResultJSON), scanID)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to update database for %s: %v", tableName, err)
		return false, err
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit transaction for %s: %v", tableName, err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully updated %s, found=%v", tableName, found)
	return true, nil
}

func clearJSONScanResults(scopeTargetID, tableName string) (int64, error) {
	// Get the current count before clearing
	domains, err := getJSONDomainsFromScan(scopeTargetID, tableName)
	if err != nil {
		return 0, err
	}
	count := int64(len(domains))

	// Clear all domains
	success, err := updateJSONScanResult(scopeTargetID, tableName, "", true)
	if err != nil {
		return 0, err
	}
	if !success {
		return 0, nil
	}
	return count, nil
}

// Live Web Server domain functions
func GetLiveWebServerDomainsForTool(scopeTargetID string) ([]string, error) {
	// Get all IP port scans for this scope target
	rows, err := dbPool.Query(context.Background(),
		`SELECT DISTINCT lws.hostname, lws.url 
		 FROM live_web_servers lws
		 JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		 WHERE ips.scope_target_id = $1 AND ips.status = 'success' 
		 AND (lws.hostname IS NOT NULL AND lws.hostname != '')
		 ORDER BY lws.hostname`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	domainSet := make(map[string]bool)
	var domains []string

	for rows.Next() {
		var hostname, url string
		if err := rows.Scan(&hostname, &url); err == nil {
			// Add hostname if it's a valid domain (not an IP)
			if hostname != "" && !isIPv4Address(hostname) {
				if !domainSet[hostname] {
					domainSet[hostname] = true
					domains = append(domains, hostname)
				}
			}

			// Extract domain from URL
			if url != "" {
				if domain := extractDomainFromURL(url); domain != "" && !isIPv4Address(domain) {
					if !domainSet[domain] {
						domainSet[domain] = true
						domains = append(domains, domain)
					}
				}
			}
		}
	}
	return domains, nil
}

func DeleteLiveWebServerDomainFromTool(scopeTargetID, domainToDelete string) (bool, error) {
	log.Printf("[DOMAIN-MANAGER] [DEBUG] DeleteLiveWebServerDomainFromTool called: domainToDelete='%s'", domainToDelete)

	// Begin a transaction to prevent race conditions
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to begin transaction for Live Web Server deletion: %v", err)
		return false, err
	}
	defer tx.Rollback(context.Background())

	// Delete live web servers that have this domain as hostname or in URL
	result, err := tx.Exec(context.Background(),
		`DELETE FROM live_web_servers 
		 WHERE scan_id IN (
			 SELECT scan_id FROM ip_port_scans WHERE scope_target_id = $1
		 ) AND (
			 hostname = $2 OR 
			 url LIKE '%' || $2 || '%'
		 )`,
		scopeTargetID, domainToDelete)

	if err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to delete Live Web Server domain: %v", err)
		return false, err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		log.Printf("[DOMAIN-MANAGER] [WARNING] Live Web Server domain '%s' not found", domainToDelete)
		return false, nil
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[DOMAIN-MANAGER] [ERROR] Failed to commit Live Web Server transaction: %v", err)
		return false, err
	}

	log.Printf("[DOMAIN-MANAGER] [INFO] Successfully deleted Live Web Server domain '%s' (%d records)", domainToDelete, rowsAffected)
	return true, nil
}

func DeleteAllLiveWebServerDomainsFromTool(scopeTargetID string) (int64, error) {
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM live_web_servers 
		 WHERE scan_id IN (
			 SELECT scan_id FROM ip_port_scans WHERE scope_target_id = $1
		 )`,
		scopeTargetID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// Helper functions for live web server domain extraction
func isIPv4Address(s string) bool {
	return strings.Contains(s, ".") &&
		len(strings.Split(s, ".")) == 4 &&
		!strings.Contains(s, " ")
}

func extractDomainFromURL(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	// Simple domain extraction from URL
	parts := strings.Split(urlStr, "/")
	if len(parts) >= 3 {
		hostPart := parts[2]
		// Remove port if present
		if colonIndex := strings.Index(hostPart, ":"); colonIndex != -1 {
			hostPart = hostPart[:colonIndex]
		}
		return hostPart
	}
	return ""
}
