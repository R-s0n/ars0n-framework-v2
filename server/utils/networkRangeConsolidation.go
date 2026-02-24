package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
)

type ConsolidatedNetworkRange struct {
	ID           string `json:"id"`
	CIDRBlock    string `json:"cidr_block"`
	ASN          string `json:"asn"`
	Organization string `json:"organization"`
	Description  string `json:"description"`
	Country      string `json:"country"`
	Source       string `json:"source"`
	ScanType     string `json:"scan_type,omitempty"`
}

// ConsolidateNetworkRanges consolidates network ranges from Amass Intel and Metabigor sources
func ConsolidateNetworkRanges(scopeTargetID string) ([]ConsolidatedNetworkRange, error) {
	log.Printf("[NETWORK-CONSOLIDATION] [INFO] Starting network range consolidation for scope target: %s", scopeTargetID)

	// Start a transaction
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	// Map to store unique network ranges by CIDR+ASN combination
	rangeMap := make(map[string]ConsolidatedNetworkRange)

	// 1. Get network ranges from Amass Intel scans (most recent only)
	log.Printf("[NETWORK-CONSOLIDATION] [INFO] Fetching Amass Intel network ranges...")
	amassRows, err := tx.Query(context.Background(), `
		SELECT inr.id, inr.cidr_block, inr.asn, inr.organization, inr.description, inr.country, inr.scan_id
		FROM intel_network_ranges inr
		JOIN amass_intel_scans ais ON inr.scan_id = ais.scan_id
		WHERE ais.scope_target_id = $1 AND ais.status = 'success'
		ORDER BY ais.created_at DESC`, scopeTargetID)

	if err != nil {
		log.Printf("[NETWORK-CONSOLIDATION] [ERROR] Failed to get Amass Intel network ranges: %v", err)
	} else {
		defer amassRows.Close()
		for amassRows.Next() {
			var id, cidrBlock, asn, organization, description, country, scanID string
			if err := amassRows.Scan(&id, &cidrBlock, &asn, &organization, &description, &country, &scanID); err == nil {
				// Create unique key using CIDR block and ASN
				key := fmt.Sprintf("%s|%s", cidrBlock, asn)
				rangeMap[key] = ConsolidatedNetworkRange{
					ID:           id,
					CIDRBlock:    cidrBlock,
					ASN:          asn,
					Organization: organization,
					Description:  description,
					Country:      country,
					Source:       "amass_intel",
				}
			}
		}
	}

	// 2. Get network ranges from Metabigor scans (most recent only)
	log.Printf("[NETWORK-CONSOLIDATION] [INFO] Fetching Metabigor network ranges...")
	metabigorRows, err := tx.Query(context.Background(), `
		SELECT mnr.id, mnr.cidr_block, mnr.asn, mnr.organization, mnr.country, mnr.scan_type, mnr.scan_id
		FROM metabigor_network_ranges mnr
		JOIN metabigor_company_scans mcs ON mnr.scan_id = mcs.scan_id
		WHERE mcs.scope_target_id = $1 AND mcs.status = 'success'
		ORDER BY mcs.created_at DESC`, scopeTargetID)

	if err != nil {
		log.Printf("[NETWORK-CONSOLIDATION] [ERROR] Failed to get Metabigor network ranges: %v", err)
	} else {
		defer metabigorRows.Close()
		for metabigorRows.Next() {
			var id, cidrBlock, asn, organization, country, scanType, scanID string
			if err := metabigorRows.Scan(&id, &cidrBlock, &asn, &organization, &country, &scanType, &scanID); err == nil {
				// Create unique key using CIDR block and ASN
				key := fmt.Sprintf("%s|%s", cidrBlock, asn)
				if existing, exists := rangeMap[key]; exists {
					// If already exists from Amass Intel, combine sources
					existing.Source = "amass_intel, metabigor"
					existing.ScanType = scanType // Add scan type from Metabigor
					rangeMap[key] = existing
				} else {
					// New entry from Metabigor only
					rangeMap[key] = ConsolidatedNetworkRange{
						ID:           id,
						CIDRBlock:    cidrBlock,
						ASN:          asn,
						Organization: organization,
						Country:      country,
						Source:       "metabigor",
						ScanType:     scanType,
					}
				}
			}
		}
	}

	// Convert to sorted slice
	var consolidatedRanges []ConsolidatedNetworkRange
	for _, networkRange := range rangeMap {
		consolidatedRanges = append(consolidatedRanges, networkRange)
	}

	// Sort by CIDR block for consistent ordering
	sort.Slice(consolidatedRanges, func(i, j int) bool {
		// Try to parse as IP networks for proper sorting
		_, netA, errA := net.ParseCIDR(consolidatedRanges[i].CIDRBlock)
		_, netB, errB := net.ParseCIDR(consolidatedRanges[j].CIDRBlock)

		if errA != nil || errB != nil {
			// Fall back to string comparison if parsing fails
			return consolidatedRanges[i].CIDRBlock < consolidatedRanges[j].CIDRBlock
		}

		// Compare by network address
		return netA.String() < netB.String()
	})

	log.Printf("[NETWORK-CONSOLIDATION] [INFO] Total unique network ranges found: %d", len(consolidatedRanges))

	// Clear old consolidated network ranges and insert new ones
	_, err = tx.Exec(context.Background(), `DELETE FROM consolidated_network_ranges WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old consolidated network ranges: %v", err)
	}

	for _, networkRange := range consolidatedRanges {
		_, err = tx.Exec(context.Background(), `
			INSERT INTO consolidated_network_ranges (scope_target_id, cidr_block, asn, organization, description, country, source, scan_type) 
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (scope_target_id, cidr_block, source) DO UPDATE SET
				asn = EXCLUDED.asn,
				organization = EXCLUDED.organization,
				description = EXCLUDED.description,
				country = EXCLUDED.country,
				scan_type = EXCLUDED.scan_type`,
			scopeTargetID, networkRange.CIDRBlock, networkRange.ASN, networkRange.Organization,
			networkRange.Description, networkRange.Country, networkRange.Source, networkRange.ScanType)
		if err != nil {
			return nil, fmt.Errorf("failed to insert consolidated network range: %v", err)
		}
	}

	if err = tx.Commit(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return consolidatedRanges, nil
}

// HandleConsolidateNetworkRanges handles the HTTP request to consolidate network ranges
func HandleConsolidateNetworkRanges(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	consolidatedRanges, err := ConsolidateNetworkRanges(scopeTargetID)
	if err != nil {
		log.Printf("[NETWORK-CONSOLIDATION] [ERROR] Failed to consolidate network ranges: %v", err)
		http.Error(w, "Failed to consolidate network ranges", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":          len(consolidatedRanges),
		"network_ranges": consolidatedRanges,
	})
}

// GetConsolidatedNetworkRanges retrieves consolidated network ranges for a scope target
func GetConsolidatedNetworkRanges(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT cidr_block, asn, organization, description, country, source, scan_type 
			  FROM consolidated_network_ranges 
			  WHERE scope_target_id = $1 
			  ORDER BY cidr_block ASC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to get consolidated network ranges", http.StatusInternalServerError)
		return
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":          len(networkRanges),
		"network_ranges": networkRanges,
	})
}
