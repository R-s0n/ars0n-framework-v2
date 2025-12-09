package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type AttackSurfaceAsset struct {
	ID              string  `json:"id"`
	ScopeTargetID   string  `json:"scope_target_id"`
	AssetType       string  `json:"asset_type"`
	AssetIdentifier string  `json:"asset_identifier"`
	AssetSubtype    *string `json:"asset_subtype,omitempty"`

	// ASN fields
	ASNNumber       *string `json:"asn_number,omitempty"`
	ASNOrganization *string `json:"asn_organization,omitempty"`
	ASNDescription  *string `json:"asn_description,omitempty"`
	ASNCountry      *string `json:"asn_country,omitempty"`

	// Network Range fields
	CIDRBlock           *string `json:"cidr_block,omitempty"`
	SubnetSize          *int    `json:"subnet_size,omitempty"`
	ResponsiveIPCount   *int    `json:"responsive_ip_count,omitempty"`
	ResponsivePortCount *int    `json:"responsive_port_count,omitempty"`

	// IP Address fields
	IPAddress *string `json:"ip_address,omitempty"`
	IPType    *string `json:"ip_type,omitempty"`

	// Live Web Server fields
	URL                 *string                `json:"url,omitempty"`
	Domain              *string                `json:"domain,omitempty"`
	Port                *int                   `json:"port,omitempty"`
	Protocol            *string                `json:"protocol,omitempty"`
	StatusCode          *int                   `json:"status_code,omitempty"`
	Title               *string                `json:"title,omitempty"`
	WebServer           *string                `json:"web_server,omitempty"`
	Technologies        []string               `json:"technologies,omitempty"`
	ContentLength       *int                   `json:"content_length,omitempty"`
	ResponseTime        *float64               `json:"response_time_ms,omitempty"`
	ScreenshotPath      *string                `json:"screenshot_path,omitempty"`
	SSLInfo             map[string]interface{} `json:"ssl_info,omitempty"`
	HTTPResponseHeaders map[string]interface{} `json:"http_response_headers,omitempty"`
	FindingsJSON        map[string]interface{} `json:"findings_json,omitempty"`

	// Cloud Asset fields
	CloudProvider    *string `json:"cloud_provider,omitempty"`
	CloudServiceType *string `json:"cloud_service_type,omitempty"`
	CloudRegion      *string `json:"cloud_region,omitempty"`

	// FQDN fields
	FQDN           *string                `json:"fqdn,omitempty"`
	RootDomain     *string                `json:"root_domain,omitempty"`
	Subdomain      *string                `json:"subdomain,omitempty"`
	Registrar      *string                `json:"registrar,omitempty"`
	CreationDate   *time.Time             `json:"creation_date,omitempty"`
	ExpirationDate *time.Time             `json:"expiration_date,omitempty"`
	UpdatedDate    *time.Time             `json:"updated_date,omitempty"`
	NameServers    []string               `json:"name_servers,omitempty"`
	Status         []string               `json:"status,omitempty"`
	WhoisInfo      map[string]interface{} `json:"whois_info,omitempty"`
	SSLCertificate map[string]interface{} `json:"ssl_certificate,omitempty"`
	SSLExpiryDate  *time.Time             `json:"ssl_expiry_date,omitempty"`
	SSLIssuer      *string                `json:"ssl_issuer,omitempty"`
	SSLSubject     *string                `json:"ssl_subject,omitempty"`
	SSLVersion     *string                `json:"ssl_version,omitempty"`
	SSLCipherSuite *string                `json:"ssl_cipher_suite,omitempty"`
	SSLProtocols   []string               `json:"ssl_protocols,omitempty"`
	ResolvedIPs    []string               `json:"resolved_ips,omitempty"`
	MailServers    []string               `json:"mail_servers,omitempty"`
	SPFRecord      *string                `json:"spf_record,omitempty"`
	DKIMRecord     *string                `json:"dkim_record,omitempty"`
	DMARCRecord    *string                `json:"dmarc_record,omitempty"`
	CAARecords     []string               `json:"caa_records,omitempty"`
	TXTRecords     []string               `json:"txt_records,omitempty"`
	MXRecords      []string               `json:"mx_records,omitempty"`
	NSRecords      []string               `json:"ns_records,omitempty"`
	ARecords       []string               `json:"a_records,omitempty"`
	AAAARecords    []string               `json:"aaaa_records,omitempty"`
	CNAMERecords   []string               `json:"cname_records,omitempty"`
	PTRRecords     []string               `json:"ptr_records,omitempty"`
	SRVRecords     []string               `json:"srv_records,omitempty"`
	SOARecord      map[string]interface{} `json:"soa_record,omitempty"`
	LastDNSScan    *time.Time             `json:"last_dns_scan,omitempty"`
	LastSSLScan    *time.Time             `json:"last_ssl_scan,omitempty"`
	LastWhoisScan  *time.Time             `json:"last_whois_scan,omitempty"`

	LastUpdated time.Time `json:"last_updated"`
	CreatedAt   time.Time `json:"created_at"`

	// Related data
	DNSRecords    []AttackSurfaceDNSRecord `json:"dns_records,omitempty"`
	Relationships []AssetRelationship      `json:"relationships,omitempty"`
}

type AttackSurfaceDNSRecord struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	RecordType  string    `json:"record_type"`
	RecordValue string    `json:"record_value"`
	TTL         *int      `json:"ttl,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type AssetRelationship struct {
	ID               string                 `json:"id"`
	ParentAssetID    string                 `json:"parent_asset_id"`
	ChildAssetID     string                 `json:"child_asset_id"`
	RelationshipType string                 `json:"relationship_type"`
	RelationshipData map[string]interface{} `json:"relationship_data,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

type ConsolidationResult struct {
	TotalAssets        int                  `json:"total_assets"`
	ASNs               int                  `json:"asns"`
	NetworkRanges      int                  `json:"network_ranges"`
	IPAddresses        int                  `json:"ip_addresses"`
	LiveWebServers     int                  `json:"live_web_servers"`
	CloudAssets        int                  `json:"cloud_assets"`
	FQDNs              int                  `json:"fqdns"`
	TotalRelationships int                  `json:"total_relationships"`
	Assets             []AttackSurfaceAsset `json:"assets"`
	ExecutionTime      string               `json:"execution_time"`
	ConsolidatedAt     time.Time            `json:"consolidated_at"`
}

func ConsolidateAttackSurface(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope_target_id", http.StatusBadRequest)
		return
	}

	log.Printf("[ATTACK SURFACE] Starting consolidation for scope target: %s", scopeTargetID)
	startTime := time.Now()

	// Clear existing data
	log.Printf("[ATTACK SURFACE] Clearing existing attack surface data...")
	err := clearExistingAttackSurfaceData(scopeTargetID)
	if err != nil {
		log.Printf("Error clearing existing attack surface data: %v", err)
		http.Error(w, "Failed to clear existing data", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Successfully cleared existing data")

	// Consolidate each asset type
	log.Printf("[ATTACK SURFACE] Consolidating ASNs...")
	asns, err := consolidateASNs(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating ASNs: %v", err)
		http.Error(w, "Failed to consolidate ASNs", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d ASNs", asns)

	log.Printf("[ATTACK SURFACE] Consolidating network ranges...")
	networkRanges, err := consolidateNetworkRanges(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating network ranges: %v", err)
		http.Error(w, "Failed to consolidate network ranges", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d network ranges", networkRanges)

	log.Printf("[ATTACK SURFACE] Consolidating IP addresses...")
	ipAddresses, err := consolidateIPAddresses(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating IP addresses: %v", err)
		http.Error(w, "Failed to consolidate IP addresses", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d IP addresses", ipAddresses)

	log.Printf("[ATTACK SURFACE] Consolidating live web servers...")
	liveWebServers, err := consolidateLiveWebServers(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating live web servers: %v", err)
		http.Error(w, "Failed to consolidate live web servers", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d live web servers", liveWebServers)

	// Consolidate FQDNs (before cloud assets so we can parse them for cloud domains)
	log.Printf("[ATTACK SURFACE] Consolidating FQDNs...")
	fqdns, err := consolidateFQDNs(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating FQDNs: %v", err)
		http.Error(w, "Failed to consolidate FQDNs", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d FQDNs", fqdns)

	log.Printf("[ATTACK SURFACE] Consolidating cloud assets...")
	cloudAssets, err := consolidateCloudAssets(scopeTargetID)
	if err != nil {
		log.Printf("Error consolidating cloud assets: %v", err)
		http.Error(w, "Failed to consolidate cloud assets", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Consolidated %d cloud assets", cloudAssets)

	// Create comprehensive relationships between assets
	log.Printf("[ATTACK SURFACE] Creating comprehensive asset relationships...")
	relationshipCount, err := createComprehensiveAssetRelationships(scopeTargetID)
	if err != nil {
		log.Printf("Error creating asset relationships: %v", err)
		http.Error(w, "Failed to create asset relationships", http.StatusInternalServerError)
		return
	}
	log.Printf("[ATTACK SURFACE] Created %d asset relationships", relationshipCount)

	// Fetch all consolidated assets
	log.Printf("[ATTACK SURFACE] Fetching consolidated assets...")
	assets, err := fetchConsolidatedAssets(scopeTargetID)
	if err != nil {
		log.Printf("Error fetching consolidated assets: %v", err)
		http.Error(w, "Failed to fetch consolidated assets", http.StatusInternalServerError)
		return
	}

	executionTime := time.Since(startTime)

	result := ConsolidationResult{
		TotalAssets:        len(assets),
		ASNs:               asns,
		NetworkRanges:      networkRanges,
		IPAddresses:        ipAddresses,
		LiveWebServers:     liveWebServers,
		CloudAssets:        cloudAssets,
		FQDNs:              fqdns,
		TotalRelationships: relationshipCount,
		Assets:             assets,
		ExecutionTime:      executionTime.String(),
		ConsolidatedAt:     time.Now(),
	}

	// Log the final results
	log.Printf("[ATTACK SURFACE] ✅ CONSOLIDATION COMPLETE!")
	log.Printf("[ATTACK SURFACE] Summary for scope target %s:", scopeTargetID)
	log.Printf("[ATTACK SURFACE]   • Total Assets: %d", len(assets))
	log.Printf("[ATTACK SURFACE]   • ASNs: %d", asns)
	log.Printf("[ATTACK SURFACE]   • Network Ranges: %d", networkRanges)
	log.Printf("[ATTACK SURFACE]   • IP Addresses: %d", ipAddresses)
	log.Printf("[ATTACK SURFACE]   • Live Web Servers: %d", liveWebServers)
	log.Printf("[ATTACK SURFACE]   • Cloud Assets: %d", cloudAssets)
	log.Printf("[ATTACK SURFACE]   • FQDNs: %d", fqdns)
	log.Printf("[ATTACK SURFACE]   • Asset Relationships: %d", relationshipCount)
	log.Printf("[ATTACK SURFACE]   • Execution Time: %s", executionTime.String())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func InvestigateFQDNs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope_target_id", http.StatusBadRequest)
		return
	}

	log.Printf("[INVESTIGATE] Starting FQDN investigation for scope target: %s", scopeTargetID)
	startTime := time.Now()

	enrichedFqdns, err := enrichFQDNsWithInvestigateData(scopeTargetID)
	if err != nil {
		log.Printf("Error investigating FQDNs: %v", err)
		http.Error(w, "Failed to investigate FQDNs", http.StatusInternalServerError)
		return
	}

	executionTime := time.Since(startTime)

	result := map[string]interface{}{
		"enriched_fqdns": enrichedFqdns,
		"execution_time": executionTime.String(),
		"investigated_at": time.Now(),
	}

	log.Printf("[INVESTIGATE] ✅ INVESTIGATION COMPLETE!")
	log.Printf("[INVESTIGATE] Summary for scope target %s:", scopeTargetID)
	log.Printf("[INVESTIGATE]   • Enriched FQDNs: %d", enrichedFqdns)
	log.Printf("[INVESTIGATE]   • Execution Time: %s", executionTime.String())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func GetAttackSurfaceAssetCounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT 
			asset_type,
			COUNT(*) as count
		FROM consolidated_attack_surface_assets
		WHERE scope_target_id = $1::uuid
		GROUP BY asset_type
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("Error querying attack surface asset counts: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	counts := map[string]int{
		"asns":             0,
		"network_ranges":   0,
		"ip_addresses":     0,
		"live_web_servers": 0,
		"cloud_assets":     0,
		"fqdns":            0,
	}

	for rows.Next() {
		var assetType string
		var count int

		if err := rows.Scan(&assetType, &count); err != nil {
			log.Printf("Error scanning attack surface asset count row: %v", err)
			continue
		}

		switch assetType {
		case "asn":
			counts["asns"] = count
		case "network_range":
			counts["network_ranges"] = count
		case "ip_address":
			counts["ip_addresses"] = count
		case "live_web_server":
			counts["live_web_servers"] = count
		case "cloud_asset":
			counts["cloud_assets"] = count
		case "fqdn":
			counts["fqdns"] = count
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating attack surface asset count rows: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(counts)
}

func clearExistingAttackSurfaceData(scopeTargetID string) error {
	queries := []string{
		"DELETE FROM consolidated_attack_surface_metadata WHERE asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid)",
		"DELETE FROM consolidated_attack_surface_dns_records WHERE asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid)",
		"DELETE FROM consolidated_attack_surface_relationships WHERE parent_asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid) OR child_asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid)",
		"DELETE FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid",
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query, scopeTargetID)
		if err != nil {
			return fmt.Errorf("failed to execute query %s: %v", query, err)
		}
	}

	return nil
}

func consolidateASNs(scopeTargetID string) (int, error) {
	log.Printf("[ASN CONSOLIDATION] Starting ASN consolidation for scope target: %s", scopeTargetID)

	// Helper function to normalize ASN format
	normalizeASN := func(asn string) string {
		// Remove 'AS' prefix if present and trim whitespace
		normalized := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(asn), "AS"))
		// Ensure it's a valid ASN number (numeric)
		if _, err := strconv.Atoi(normalized); err == nil {
			return normalized
		}
		// If not numeric, return original but cleaned
		return strings.TrimSpace(asn)
	}

	// Query to get ASNs from each source with detailed logging
	query := `
		WITH amass_intel_asns AS (
			SELECT asn_number, organization, description, country, 'Amass Intel' as source
			FROM intel_asn_data ia
			JOIN amass_intel_scans ais ON ia.scan_id = ais.scan_id
			WHERE ais.scope_target_id = $1::uuid AND ais.status = 'success'
		),
		metabigor_asns AS (
			SELECT 
				jsonb_array_elements_text(result::jsonb->'asns') as asn_number,
				'Unknown' as organization,
				'Discovered by Metabigor' as description,
				'Unknown' as country,
				'Metabigor' as source
			FROM metabigor_company_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
				AND result::jsonb ? 'asns'
		),
		amass_enum_asns AS (
			SELECT
				unnest(regexp_matches(result, 'AS\d+', 'g')) as asn_number,
				'Unknown' as organization,
				'Discovered by Amass Enum' as description,
				'Unknown' as country,
				'Amass Enum' as source
			FROM amass_enum_company_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
		),
		wildcard_asns AS (
			SELECT
				unnest(regexp_matches(result, 'AS\d+', 'g')) as asn_number,
				'Unknown' as organization,
				'Discovered by Wildcard Amass' as description,
				'Unknown' as country,
				'Wildcard Amass' as source
			FROM amass_scans am
			JOIN scope_targets st ON am.scope_target_id = st.id
			WHERE st.type = 'Wildcard'
				AND st.scope_target IN (
					SELECT DISTINCT domain
					FROM consolidated_company_domains
					WHERE scope_target_id = $1::uuid
				)
				AND am.status = 'success' AND am.result IS NOT NULL
		),
		network_range_asns AS (
			SELECT NULL as asn_number, NULL as organization, NULL as description, NULL as country, 'Network Ranges' as source
			FROM consolidated_network_ranges
			WHERE scope_target_id = $1::uuid
			LIMIT 0
		),
		all_asns AS (
			SELECT * FROM amass_intel_asns
			UNION ALL
			SELECT * FROM metabigor_asns
			UNION ALL
			SELECT * FROM amass_enum_asns
			UNION ALL
			SELECT * FROM wildcard_asns
			UNION ALL
			SELECT * FROM network_range_asns
		)
		SELECT asn_number, organization, description, country, source
		FROM all_asns
		WHERE asn_number IS NOT NULL AND asn_number != ''
		ORDER BY source, asn_number
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ASN CONSOLIDATION] Error querying ASN sources: %v", err)
		return 0, err
	}
	defer rows.Close()

	// Track ASNs by source for logging
	sourceCounts := make(map[string]int)
	allASNs := make(map[string]map[string]string) // normalized_asn_number -> {organization, description, country, source}

	for rows.Next() {
		var asnNumber, organization, description, country, source string
		err := rows.Scan(&asnNumber, &organization, &description, &country, &source)
		if err != nil {
			log.Printf("[ASN CONSOLIDATION] Error scanning ASN row: %v", err)
			continue
		}

		// Normalize the ASN number
		normalizedASN := normalizeASN(asnNumber)
		if normalizedASN == "" {
			continue
		}

		sourceCounts[source]++
		allASNs[normalizedASN] = map[string]string{
			"organization": organization,
			"description":  description,
			"country":      country,
			"source":       source,
		}

		log.Printf("[ASN CONSOLIDATION] Found ASN %s (normalized: %s) from %s (Org: %s, Country: %s)",
			asnNumber, normalizedASN, source, organization, country)
	}

	// Log summary by source
	log.Printf("[ASN CONSOLIDATION] ASN discovery summary:")
	for source, count := range sourceCounts {
		log.Printf("[ASN CONSOLIDATION]   • %s: %d ASNs", source, count)
	}

	// Log unique ASNs
	log.Printf("[ASN CONSOLIDATION] Unique ASNs found: %d", len(allASNs))
	for asnNumber, details := range allASNs {
		log.Printf("[ASN CONSOLIDATION]   • %s (Org: %s, Country: %s, Source: %s)",
			asnNumber, details["organization"], details["country"], details["source"])
	}

	// Now insert the consolidated ASNs with proper deduplication and normalization
	insertQuery := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_identifier, 
			asn_number, asn_organization, asn_description, asn_country
		)
		SELECT DISTINCT ON (normalized_asn)
			$1::uuid, 'asn', normalized_asn,
			normalized_asn, 
			COALESCE(NULLIF(organization, 'Unknown'), 'Unknown') as organization,
			COALESCE(NULLIF(description, 'Unknown'), 'Discovered') as description,
			COALESCE(NULLIF(country, 'Unknown'), 'Unknown') as country
		FROM (
			-- 1. Amass Intel ASN data (highest priority)
			SELECT 
				TRIM(BOTH 'AS' FROM UPPER(asn_number)) as normalized_asn,
				organization, description, country, 1 as priority
			FROM intel_asn_data ia
			JOIN amass_intel_scans ais ON ia.scan_id = ais.scan_id
			WHERE ais.scope_target_id = $1::uuid AND ais.status = 'success'
				AND asn_number IS NOT NULL AND asn_number != ''
			
			UNION ALL
			
			-- 2. Network range ASN data (second priority) - disabled for now
			SELECT 
				NULL as normalized_asn,
				NULL as organization, NULL as description, NULL as country, 2 as priority
			FROM consolidated_network_ranges
			WHERE scope_target_id = $1::uuid AND false
			
			UNION ALL
			
			-- 3. Metabigor ASN data (third priority)
			SELECT 
				TRIM(BOTH 'AS' FROM UPPER(jsonb_array_elements_text(result::jsonb->'asns'))) as normalized_asn,
				'Unknown' as organization,
				'Discovered by Metabigor' as description,
				'Unknown' as country,
				3 as priority
			FROM metabigor_company_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
				AND result::jsonb ? 'asns'
			
			UNION ALL
			
			-- 4. Amass Enum raw results (fourth priority)
			SELECT 
				TRIM(BOTH 'AS' FROM UPPER(unnest(regexp_matches(result, 'AS\d+', 'g')))) as normalized_asn,
				'Unknown' as organization,
				'Discovered by Amass Enum' as description,
				'Unknown' as country,
				4 as priority
			FROM amass_enum_company_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
			
			UNION ALL
			
			-- 5. Wildcard Amass scans (lowest priority)
			SELECT 
				TRIM(BOTH 'AS' FROM UPPER(unnest(regexp_matches(result, 'AS\d+', 'g')))) as normalized_asn,
				'Unknown' as organization,
				'Discovered by Wildcard Amass' as description,
				'Unknown' as country,
				5 as priority
			FROM amass_scans am
			JOIN scope_targets st ON am.scope_target_id = st.id
			WHERE st.type = 'Wildcard' 
				AND st.scope_target IN (
					SELECT DISTINCT domain 
					FROM consolidated_company_domains 
					WHERE scope_target_id = $1::uuid
				)
				AND am.status = 'success' AND am.result IS NOT NULL
		) asn_data
		WHERE normalized_asn IS NOT NULL AND normalized_asn != ''
			AND normalized_asn ~ '^[0-9]+$'
		ORDER BY normalized_asn, priority
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			asn_organization = EXCLUDED.asn_organization,
			asn_description = EXCLUDED.asn_description,
			asn_country = EXCLUDED.asn_country,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), insertQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ASN CONSOLIDATION] Error inserting consolidated ASNs: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())
	log.Printf("[ASN CONSOLIDATION] ✅ Successfully inserted/updated %d ASN records", insertedCount)
	log.Printf("[ASN CONSOLIDATION] ASN consolidation complete for scope target: %s", scopeTargetID)

	return insertedCount, nil
}

func consolidateNetworkRanges(scopeTargetID string) (int, error) {
	log.Printf("[NETWORK RANGE CONSOLIDATION] Starting network range consolidation for scope target: %s", scopeTargetID)

	query := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_identifier, cidr_block,
			asn_number, asn_organization, asn_description, asn_country,
			subnet_size, responsive_ip_count, responsive_port_count
		)
		WITH network_range_data AS (
			-- 1. Amass Intel network ranges (highest priority - rich ASN data)
			SELECT 
				inr.cidr_block,
				TRIM(BOTH 'AS' FROM inr.asn) as asn_number,
				inr.organization as asn_organization,
				inr.description as asn_description,
				inr.country as asn_country,
				1 as priority
			FROM intel_network_ranges inr
			JOIN amass_intel_scans ais ON inr.scan_id = ais.scan_id
			WHERE ais.scope_target_id = $1::uuid AND ais.status = 'success'
				AND inr.cidr_block IS NOT NULL AND inr.cidr_block != ''
				AND inr.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
			
			UNION ALL
			
			-- 2. Metabigor network ranges (second priority)
			SELECT 
				mnr.cidr_block,
				TRIM(BOTH 'AS' FROM mnr.asn) as asn_number,
				mnr.organization as asn_organization,
				'Discovered by Metabigor' as asn_description,
				mnr.country as asn_country,
				2 as priority
			FROM metabigor_network_ranges mnr
			JOIN metabigor_company_scans mcs ON mnr.scan_id = mcs.scan_id
			WHERE mcs.scope_target_id = $1::uuid AND mcs.status = 'success'
				AND mnr.cidr_block IS NOT NULL AND mnr.cidr_block != ''
				AND mnr.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
			
			UNION ALL
			
			-- 3. Previously consolidated network ranges (third priority)
			SELECT 
				cnr.cidr_block,
				TRIM(BOTH 'AS' FROM cnr.asn) as asn_number,
				cnr.organization as asn_organization,
				COALESCE(cnr.description, 'Previously consolidated') as asn_description,
				cnr.country as asn_country,
				3 as priority
			FROM consolidated_network_ranges cnr
			WHERE cnr.scope_target_id = $1::uuid
				AND cnr.cidr_block IS NOT NULL AND cnr.cidr_block != ''
				AND cnr.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
			
			UNION ALL
			
			-- 4. Amass Enum company scan raw results (extract CIDR blocks)
			SELECT 
				unnest(regexp_matches(result, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b', 'g')) as cidr_block,
				NULL as asn_number,
				'Unknown' as asn_organization,
				'Discovered by Amass Enum' as asn_description,
				'Unknown' as asn_country,
				4 as priority
			FROM amass_enum_company_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
			
			UNION ALL
			
			-- 5. Wildcard Amass scans for company root domains
			SELECT 
				unnest(regexp_matches(result, '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b', 'g')) as cidr_block,
				NULL as asn_number,
				'Unknown' as asn_organization,
				'Discovered by Wildcard Amass' as asn_description,
				'Unknown' as asn_country,
				5 as priority
			FROM amass_scans am
			JOIN scope_targets st ON am.scope_target_id = st.id
			WHERE st.type = 'Wildcard'
				AND st.scope_target IN (
					SELECT DISTINCT domain 
					FROM consolidated_company_domains 
					WHERE scope_target_id = $1::uuid
				)
				AND am.status = 'success' AND am.result IS NOT NULL
		)
		SELECT DISTINCT ON (nrd.cidr_block)
			$1::uuid, 'network_range', nrd.cidr_block, nrd.cidr_block,
			nrd.asn_number, nrd.asn_organization, nrd.asn_description, nrd.asn_country,
			CASE 
				WHEN nrd.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$' AND 
					 SPLIT_PART(nrd.cidr_block, '/', 2) ~ '^\d+$' AND
					 CAST(SPLIT_PART(nrd.cidr_block, '/', 2) AS INTEGER) BETWEEN 0 AND 32
				THEN POWER(2, 32 - CAST(SPLIT_PART(nrd.cidr_block, '/', 2) AS INTEGER))::INTEGER
				ELSE NULL
			END as subnet_size,
			0 as responsive_ip_count,
			0 as responsive_port_count
		FROM network_range_data nrd
		WHERE nrd.cidr_block IS NOT NULL AND nrd.cidr_block != ''
		ORDER BY nrd.cidr_block, nrd.priority
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			asn_number = EXCLUDED.asn_number,
			asn_organization = EXCLUDED.asn_organization,
			asn_description = EXCLUDED.asn_description,
			asn_country = EXCLUDED.asn_country,
			subnet_size = EXCLUDED.subnet_size,
			responsive_ip_count = EXCLUDED.responsive_ip_count,
			responsive_port_count = EXCLUDED.responsive_port_count,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[NETWORK RANGE CONSOLIDATION] Error inserting consolidated network ranges: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())
	log.Printf("[NETWORK RANGE CONSOLIDATION] ✅ Successfully inserted/updated %d network range records", insertedCount)
	log.Printf("[NETWORK RANGE CONSOLIDATION] Network range consolidation complete for scope target: %s", scopeTargetID)

	return insertedCount, nil
}

func consolidateIPAddresses(scopeTargetID string) (int, error) {
	log.Printf("[IP CONSOLIDATION] Starting IP address consolidation for scope target: %s", scopeTargetID)

	// First, let's check what data we have
	debugQuery := `
		SELECT 
			'discovered_live_ips' as source,
			COUNT(*) as count
		FROM discovered_live_ips dli
		JOIN ip_port_scans ips ON dli.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
		
		UNION ALL
		
		SELECT 
			'live_web_servers' as source,
			COUNT(*) as count
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
		
		UNION ALL
		
		SELECT 
			'httpx_scans' as source,
			COUNT(*) as count
		FROM httpx_scans hs
		WHERE hs.scope_target_id = $1::uuid AND hs.status = 'success'
		
		UNION ALL
		
		SELECT 
			'dns_records_a' as source,
			COUNT(*) as count
		FROM dns_records dr
		JOIN amass_scans ams ON dr.scan_id = ams.scan_id
		WHERE ams.scope_target_id = $1::uuid AND ams.status = 'success'
		AND dr.record_type = 'A'
		
		UNION ALL
		
		SELECT 
			'dnsx_company_dns_records_a' as source,
			COUNT(*) as count
		FROM dnsx_company_dns_records dcdr
		WHERE dcdr.scope_target_id = $1::uuid AND dcdr.record_type = 'A'
		
		UNION ALL
		
		SELECT 
			'target_urls_with_ips' as source,
			COUNT(*) as count
		FROM target_urls tu
		WHERE tu.scope_target_id = $1::uuid AND tu.ip_address IS NOT NULL
	`

	debugRows, err := dbPool.Query(context.Background(), debugQuery, scopeTargetID)
	if err != nil {
		log.Printf("[IP CONSOLIDATION] Error in debug query: %v", err)
	} else {
		defer debugRows.Close()
		for debugRows.Next() {
			var source, count string
			if err := debugRows.Scan(&source, &count); err == nil {
				log.Printf("[IP CONSOLIDATION] Debug - %s: %s records", source, count)
			}
		}
	}

	// Enhanced query to capture IPs from multiple sources with proper validation
	query := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_identifier, ip_address,
			asn_number, asn_organization, asn_country, resolved_ips, ptr_records, 
			dnsx_a_records, amass_a_records, httpx_sources, ip_type
		)
		WITH comprehensive_ip_data AS (
			-- 1. Discovered IPs from IP/Port scans (already INET type)
			SELECT DISTINCT 
				dli.ip_address as ip_address,
				'ip_port_scan' as source_type,
				ARRAY[host(dli.ip_address)]::text[] as source_ips
			FROM discovered_live_ips dli
			JOIN ip_port_scans ips ON dli.scan_id = ips.scan_id
			WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
			AND dli.ip_address IS NOT NULL

			UNION

			-- 2. Live web server IPs (already INET type)
			SELECT DISTINCT
				lws.ip_address as ip_address,
				'live_web_server' as source_type,
				ARRAY[host(lws.ip_address)]::text[] as source_ips
			FROM live_web_servers lws
			JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
			WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
			AND lws.ip_address IS NOT NULL

			UNION

			-- 3. Target URL IPs (TEXT type - validate before casting)
			SELECT DISTINCT
				tu.ip_address::inet as ip_address,
				'target_url' as source_type,
				ARRAY[tu.ip_address]::text[] as source_ips
			FROM target_urls tu
			WHERE tu.scope_target_id = $1::uuid
			AND tu.ip_address IS NOT NULL AND tu.ip_address != ''
			AND tu.ip_address ~ '^(\d{1,3}\.){3}\d{1,3}$'

			UNION

			-- 4. DNS A records from Amass scans (validate before casting)
			SELECT DISTINCT
				dr.record::inet as ip_address,
				'dns_a_record' as source_type,
				ARRAY[dr.record]::text[] as source_ips
			FROM dns_records dr
			JOIN amass_scans ams ON dr.scan_id = ams.scan_id
			WHERE ams.scope_target_id = $1::uuid AND ams.status = 'success'
			AND dr.record_type = 'A' AND dr.record ~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND dr.record IS NOT NULL AND dr.record != ''

			UNION

			-- 5. DNS A records from DNSx company scans (validate before casting)
			SELECT DISTINCT
				dcdr.record::inet as ip_address,
				'dnsx_a_record' as source_type,
				ARRAY[dcdr.record]::text[] as source_ips
			FROM dnsx_company_dns_records dcdr
			WHERE dcdr.scope_target_id = $1::uuid AND dcdr.record_type = 'A'
			AND dcdr.record ~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND dcdr.record IS NOT NULL AND dcdr.record != ''

			UNION

			-- 6. IPs from HTTPx scan results (extract from URLs with validation)
			SELECT DISTINCT
				extracted_ip::inet as ip_address,
				'httpx_scan' as source_type,
				ARRAY[extracted_ip]::text[] as source_ips
			FROM (
				SELECT DISTINCT
					CASE
						WHEN line ~ '^https?://(\d{1,3}\.){3}\d{1,3}' THEN
							substring(line from 'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
						ELSE NULL
					END as extracted_ip
				FROM (
					SELECT unnest(string_to_array(result, E'\n')) as line
					FROM httpx_scans
					WHERE scope_target_id = $1::uuid AND status = 'success'
					AND result IS NOT NULL AND result != ''
				) httpx_lines
			) httpx_ips
			WHERE extracted_ip IS NOT NULL AND extracted_ip != ''
			AND extracted_ip ~ '^(\d{1,3}\.){3}\d{1,3}$'

			UNION

			-- 7. IPs from Amass Enum Company DNS records (validate before casting)
			SELECT DISTINCT
				aecdr.record::inet as ip_address,
				'amass_enum_dns' as source_type,
				ARRAY[aecdr.record]::text[] as source_ips
			FROM amass_enum_company_dns_records aecdr
			WHERE aecdr.scope_target_id = $1::uuid AND aecdr.record_type = 'A'
			AND aecdr.record ~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND aecdr.record IS NOT NULL AND aecdr.record != ''
		),
		ip_enriched_data AS (
			SELECT
				ip.ip_address,
				string_agg(DISTINCT ip.source_type, ', ') as ip_type,
				TRIM(BOTH 'AS' FROM mnr.asn) as asn_number,
				mnr.organization as asn_organization,
				mnr.country as asn_country,
				ARRAY_AGG(DISTINCT lws.hostname) FILTER (WHERE lws.hostname IS NOT NULL) as hostnames,
				ARRAY_AGG(DISTINCT ptr_record) FILTER (WHERE ptr_record IS NOT NULL) as ptr_records,
				ARRAY_AGG(DISTINCT dcdr.record) FILTER (WHERE dcdr.record_type = 'A' AND dcdr.record = host(ip.ip_address)) as dnsx_a_records,
				ARRAY_AGG(DISTINCT aedr.record) FILTER (WHERE aedr.record_type = 'A' AND aedr.record = host(ip.ip_address)) as amass_a_records,
				ARRAY_AGG(DISTINCT ip.source_type) as httpx_sources
			FROM comprehensive_ip_data ip
			LEFT JOIN metabigor_network_ranges mnr ON ip.ip_address << mnr.cidr_block::inet
			LEFT JOIN metabigor_company_scans mcs ON mnr.scan_id = mcs.scan_id
			LEFT JOIN live_web_servers lws ON ip.ip_address = lws.ip_address
			LEFT JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
			LEFT JOIN (
				SELECT tu.url, unnest(tu.dns_ptr_records) as ptr_record
				FROM target_urls tu
				WHERE tu.dns_ptr_records IS NOT NULL
			) ptrs ON ptrs.ptr_record = host(ip.ip_address)
			LEFT JOIN dnsx_company_dns_records dcdr ON dcdr.record = host(ip.ip_address) AND dcdr.scope_target_id = $1::uuid
			LEFT JOIN amass_enum_company_dns_records aedr ON aedr.record = host(ip.ip_address) AND aedr.scope_target_id = $1::uuid
			WHERE (mcs.scope_target_id = $1::uuid OR mcs.scope_target_id IS NULL)
				AND (ips.scope_target_id = $1::uuid OR ips.scope_target_id IS NULL)
			GROUP BY ip.ip_address, mnr.asn, mnr.organization, mnr.country
		)
		SELECT DISTINCT
			$1::uuid, 'ip_address', host(ipd.ip_address), host(ipd.ip_address),
			ipd.asn_number,
			ipd.asn_organization,
			ipd.asn_country,
			COALESCE(ipd.hostnames, ARRAY[]::text[]) as resolved_ips,
			COALESCE(ipd.ptr_records, ARRAY[]::text[]) as ptr_records,
			COALESCE(ipd.dnsx_a_records, ARRAY[]::text[]) as dnsx_a_records,
			COALESCE(ipd.amass_a_records, ARRAY[]::text[]) as amass_a_records,
			COALESCE(ipd.httpx_sources, ARRAY[]::text[]) as httpx_sources,
			ipd.ip_type
		FROM ip_enriched_data ipd
		WHERE ipd.ip_address IS NOT NULL
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			asn_number = EXCLUDED.asn_number,
			asn_organization = EXCLUDED.asn_organization,
			asn_country = EXCLUDED.asn_country,
			resolved_ips = EXCLUDED.resolved_ips,
			ptr_records = EXCLUDED.ptr_records,
			dnsx_a_records = EXCLUDED.dnsx_a_records,
			amass_a_records = EXCLUDED.amass_a_records,
			httpx_sources = EXCLUDED.httpx_sources,
			ip_type = EXCLUDED.ip_type,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[IP CONSOLIDATION] Error inserting consolidated IP addresses: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())
	log.Printf("[IP CONSOLIDATION] ✅ Successfully inserted/updated %d IP address records", insertedCount)
	log.Printf("[IP CONSOLIDATION] IP address consolidation complete for scope target: %s", scopeTargetID)

	return insertedCount, nil
}

func consolidateLiveWebServers(scopeTargetID string) (int, error) {
	log.Printf("[LIVE WEB SERVER CONSOLIDATION] Starting live web server consolidation for scope target: %s", scopeTargetID)

	// Debug query to check data availability
	debugQuery := `
		SELECT 
			'ip_port_live_web_servers' as source,
			COUNT(*) as count
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
		
		UNION ALL
		
		SELECT 
			'httpx_scans' as source,
			COUNT(*) as count
		FROM httpx_scans hs
		WHERE hs.scope_target_id = $1::uuid AND hs.status = 'success'
		
		UNION ALL
		
		SELECT 
			'target_urls_live' as source,
			COUNT(*) as count
		FROM target_urls tu
		WHERE tu.scope_target_id = $1::uuid AND tu.no_longer_live = false
		
		UNION ALL
		
		SELECT 
			'target_urls_from_wildcards' as source,
			COUNT(*) as count
		FROM target_urls tu
		JOIN scope_targets st ON tu.scope_target_id = st.id
		WHERE st.type = 'Wildcard' 
		AND CASE 
			WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
			ELSE st.scope_target
		END IN (
			SELECT DISTINCT domain 
			FROM consolidated_company_domains 
			WHERE scope_target_id = $1::uuid
		)
		AND tu.no_longer_live = false
		
		UNION ALL
		
		SELECT 
			'investigate_scans' as source,
			COUNT(*) as count
		FROM investigate_scans ins
		WHERE ins.scope_target_id = $1::uuid AND ins.status = 'success'
	`

	debugRows, err := dbPool.Query(context.Background(), debugQuery, scopeTargetID)
	if err != nil {
		log.Printf("[LIVE WEB SERVER CONSOLIDATION] Error in debug query: %v", err)
	} else {
		defer debugRows.Close()
		for debugRows.Next() {
			var source, count string
			if err := debugRows.Scan(&source, &count); err == nil {
				log.Printf("[LIVE WEB SERVER CONSOLIDATION] Debug - %s: %s records", source, count)
			}
		}
	}

	// Comprehensive live web server consolidation query
	consolidatedQuery := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_subtype, asset_identifier,
			ip_address, port, protocol, url, domain, status_code, title, web_server,
			technologies, content_length, response_time_ms, screenshot_path,
			ssl_info, http_response_headers, findings_json
		)
		WITH comprehensive_live_web_servers AS (
			-- 1. IP/Port scan live web servers
			SELECT DISTINCT 
				host(lws.ip_address) || ':' || lws.port::text || '/' || lws.protocol as asset_identifier,
				'ip_port' as asset_subtype,
				host(lws.ip_address) as ip_address,
				lws.port as port,
				lws.protocol,
				lws.url,
				CASE 
					WHEN lws.url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(lws.url from 8)) > 0 THEN 
								substring(substring(lws.url from 8) from 1 for position(':' in substring(lws.url from 8)) - 1)
							ELSE split_part(substring(lws.url from 8), '/', 1)
						END
					WHEN lws.url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(lws.url from 9)) > 0 THEN 
								substring(substring(lws.url from 9) from 1 for position(':' in substring(lws.url from 9)) - 1)
							ELSE split_part(substring(lws.url from 9), '/', 1)
						END
					ELSE NULL
				END as domain,
				lws.status_code as status_code,
				lws.title,
				lws.server_header as web_server,
				-- Simplified technologies handling
				CASE 
					WHEN lws.technologies IS NOT NULL THEN 
						CASE 
							WHEN jsonb_typeof(lws.technologies) = 'array' THEN 
								ARRAY(SELECT jsonb_array_elements_text(lws.technologies))
							WHEN jsonb_typeof(lws.technologies) = 'string' THEN 
								ARRAY[lws.technologies #>> '{}']
							ELSE ARRAY[]::text[]
						END
					ELSE ARRAY[]::text[]
				END as technologies,
				NULL::bigint as content_length,
				NULL::double precision as response_time_ms,
				lws.screenshot_path,
				lws.ssl_info,
				lws.http_response_headers,
				lws.findings_json
			FROM live_web_servers lws
			JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
			WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
				
			UNION ALL
				
			-- 2. HTTPx scan results (parse JSON formatted results)
			SELECT DISTINCT
				httpx_data.url as asset_identifier,
				'httpx_scan' as asset_subtype,
				CASE 
					WHEN httpx_data.url ~ '^https?://(\d{1,3}\.){3}\d{1,3}' THEN
						substring(httpx_data.url from 'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
					ELSE NULL
				END as ip_address,
				CASE 
					WHEN httpx_data.url ~ ':(\d+)' THEN
						substring(httpx_data.url from ':(\d+)')::int
					WHEN httpx_data.url LIKE 'https://%' THEN 443
					WHEN httpx_data.url LIKE 'http://%' THEN 80
					ELSE NULL
				END as port,
				CASE 
					WHEN httpx_data.url LIKE 'https://%' THEN 'https'
					WHEN httpx_data.url LIKE 'http://%' THEN 'http'
					ELSE 'unknown'
				END as protocol,
				httpx_data.url,
				CASE 
					WHEN httpx_data.url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(httpx_data.url from 8)) > 0 THEN 
								substring(substring(httpx_data.url from 8) from 1 for position(':' in substring(httpx_data.url from 8)) - 1)
							ELSE split_part(substring(httpx_data.url from 8), '/', 1)
						END
					WHEN httpx_data.url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(httpx_data.url from 9)) > 0 THEN 
								substring(substring(httpx_data.url from 9) from 1 for position(':' in substring(httpx_data.url from 9)) - 1)
							ELSE split_part(substring(httpx_data.url from 9), '/', 1)
						END
					ELSE NULL
				END as domain,
				COALESCE(httpx_data.status_code, 200) as status_code,
				httpx_data.title,
				httpx_data.web_server,
				COALESCE(httpx_data.technologies, ARRAY[]::text[]) as technologies,
				httpx_data.content_length,
				NULL::double precision as response_time_ms,
				NULL as screenshot_path,
				NULL::jsonb as ssl_info,
				NULL::jsonb as http_response_headers,
				NULL::jsonb as findings_json
			FROM (
				SELECT DISTINCT
					parsed_json->>'url' as url,
					CASE 
						WHEN parsed_json->>'status_code' IS NOT NULL AND parsed_json->>'status_code' ~ '^\d+$' THEN
							(parsed_json->>'status_code')::int
						ELSE NULL
					END as status_code,
					parsed_json->>'title' as title,
					parsed_json->>'webserver' as web_server,
					CASE 
						WHEN parsed_json->'tech' IS NOT NULL THEN
							ARRAY(SELECT jsonb_array_elements_text(parsed_json->'tech'))
						ELSE ARRAY[]::text[]
					END as technologies,
					CASE 
						WHEN parsed_json->>'content_length' IS NOT NULL AND parsed_json->>'content_length' ~ '^\d+$' THEN
							(parsed_json->>'content_length')::bigint
						ELSE NULL
					END as content_length
				FROM (
					SELECT 
						CASE 
							WHEN trim(httpx_line) ~ '^{.*}$' THEN
								trim(httpx_line)::jsonb
							ELSE NULL
						END as parsed_json
					FROM (
						SELECT DISTINCT
							unnest(string_to_array(result, E'\n')) as httpx_line
						FROM httpx_scans
						WHERE scope_target_id = $1::uuid AND status = 'success'
						AND result IS NOT NULL AND result != ''
					) httpx_lines
					WHERE trim(httpx_line) != '' 
					AND trim(httpx_line) ~ '^{.*}$'
				) httpx_json_parsed
				WHERE parsed_json IS NOT NULL
				AND parsed_json->>'url' IS NOT NULL
				AND parsed_json->>'url' ~ '^https?://'
			) httpx_data
			WHERE httpx_data.url IS NOT NULL AND httpx_data.url != ''
			
			UNION ALL
			
			-- 3. Target URLs (wildcard targets with rich data)
			SELECT DISTINCT
				tu.url as asset_identifier,
				'target_url' as asset_subtype,
				tu.ip_address,
				CASE 
					WHEN tu.url ~ ':(\d+)' THEN
						substring(tu.url from ':(\d+)')::int
					WHEN tu.url LIKE 'https://%' THEN 443
					WHEN tu.url LIKE 'http://%' THEN 80
					ELSE NULL
				END as port,
				CASE 
					WHEN tu.url LIKE 'https://%' THEN 'https'
					WHEN tu.url LIKE 'http://%' THEN 'http'
					ELSE 'unknown'
				END as protocol,
				tu.url,
				CASE 
					WHEN tu.url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(tu.url from 8)) > 0 THEN 
								substring(substring(tu.url from 8) from 1 for position(':' in substring(tu.url from 8)) - 1)
							ELSE split_part(substring(tu.url from 8), '/', 1)
						END
					WHEN tu.url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(tu.url from 9)) > 0 THEN 
								substring(substring(tu.url from 9) from 1 for position(':' in substring(tu.url from 9)) - 1)
							ELSE split_part(substring(tu.url from 9), '/', 1)
						END
					ELSE NULL
				END as domain,
				tu.status_code as status_code,
				tu.title,
				tu.web_server,
				-- Simplified technologies handling for target_urls
				CASE 
					WHEN tu.technologies IS NOT NULL THEN tu.technologies
					ELSE ARRAY[]::text[]
				END as technologies,
				tu.content_length::bigint as content_length,
				NULL::double precision as response_time_ms,
				tu.screenshot as screenshot_path,
				NULL::jsonb as ssl_info,
				NULL::jsonb as http_response_headers,
				NULL::jsonb as findings_json
			FROM target_urls tu
			WHERE tu.scope_target_id = $1::uuid AND tu.no_longer_live = false
			
			UNION ALL
			
			-- 3b. Target URLs from wildcard targets (matching company domains)
			SELECT DISTINCT
				tu.url as asset_identifier,
				'wildcard_target_url' as asset_subtype,
				tu.ip_address,
				CASE 
					WHEN tu.url ~ ':(\d+)' THEN
						substring(tu.url from ':(\d+)')::int
					WHEN tu.url LIKE 'https://%' THEN 443
					WHEN tu.url LIKE 'http://%' THEN 80
					ELSE NULL
				END as port,
				CASE 
					WHEN tu.url LIKE 'https://%' THEN 'https'
					WHEN tu.url LIKE 'http://%' THEN 'http'
					ELSE 'unknown'
				END as protocol,
				tu.url,
				CASE 
					WHEN tu.url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(tu.url from 8)) > 0 THEN 
								substring(substring(tu.url from 8) from 1 for position(':' in substring(tu.url from 8)) - 1)
							ELSE split_part(substring(tu.url from 8), '/', 1)
						END
					WHEN tu.url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(tu.url from 9)) > 0 THEN 
								substring(substring(tu.url from 9) from 1 for position(':' in substring(tu.url from 9)) - 1)
							ELSE split_part(substring(tu.url from 9), '/', 1)
						END
					ELSE NULL
				END as domain,
				tu.status_code as status_code,
				tu.title,
				tu.web_server,
				-- Simplified technologies handling for wildcard target_urls
				CASE 
					WHEN tu.technologies IS NOT NULL THEN tu.technologies
					ELSE ARRAY[]::text[]
				END as technologies,
				tu.content_length::bigint as content_length,
				NULL::double precision as response_time_ms,
				tu.screenshot as screenshot_path,
				NULL::jsonb as ssl_info,
				NULL::jsonb as http_response_headers,
				NULL::jsonb as findings_json
			FROM target_urls tu
			JOIN scope_targets st ON tu.scope_target_id = st.id
			WHERE st.type = 'Wildcard' 
			AND CASE 
				WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
				ELSE st.scope_target
			END IN (
				SELECT DISTINCT domain 
				FROM consolidated_company_domains 
				WHERE scope_target_id = $1::uuid
			)
			AND tu.no_longer_live = false
			
			UNION ALL
			
			-- 4. Investigate scan results (only those with valid HTTP responses)
			SELECT DISTINCT
				domain_name || ':' || port::text || '/' || protocol as asset_identifier,
				'investigate_scan' as asset_subtype,
				ip_address,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 443
					ELSE 80
				END as port,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 'https'
					ELSE 'http'
				END as protocol,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 'https://' || domain_name
					ELSE 'http://' || domain_name
				END as url,
				domain_name as domain,
				status_code,
				title,
				web_server,
				ARRAY[]::text[] as technologies,
				NULL::bigint as content_length,
				NULL::double precision as response_time_ms,
				NULL as screenshot_path,
				ssl_info,
				NULL::jsonb as http_response_headers,
				NULL::jsonb as findings_json
			FROM (
				SELECT DISTINCT
					elem->>'domain' as domain_name,
					elem->>'ip_address' as ip_address,
					(elem->'http'->>'status_code')::int as status_code,
					elem->'http'->>'title' as title,
					elem->'http'->>'server' as web_server,
					elem->'ssl' as ssl_info,
					CASE 
						WHEN elem->'ssl' IS NOT NULL THEN 443
						ELSE 80
					END as port,
					CASE 
						WHEN elem->'ssl' IS NOT NULL THEN 'https'
						ELSE 'http'
					END as protocol
				FROM (
					SELECT result, created_at
					FROM investigate_scans
					WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
					ORDER BY created_at DESC
					LIMIT 1
				) latest_investigate_scan
				CROSS JOIN LATERAL jsonb_array_elements(latest_investigate_scan.result::jsonb) as elem
				WHERE latest_investigate_scan.result::jsonb IS NOT NULL
					AND elem->'http' IS NOT NULL
					AND elem->'http'->>'status_code' IS NOT NULL
					AND (elem->'http'->>'status_code') ~ '^\d+$'
			) investigate_http_domains
			WHERE domain_name IS NOT NULL AND domain_name != ''
				AND domain_name ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			
			UNION ALL
			
			-- 5. Enriched FQDNs with valid HTTP responses (from FQDN enrichment process)
			SELECT DISTINCT
				CASE 
					WHEN ssl_info IS NOT NULL THEN fqdn || ':443/https'
					ELSE fqdn || ':80/http'
				END as asset_identifier,
				'enriched_fqdn' as asset_subtype,
				CASE 
					WHEN cardinality(resolved_ips) > 0 THEN resolved_ips[1]
					ELSE NULL
				END as ip_address,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 443
					ELSE 80
				END as port,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 'https'
					ELSE 'http'
				END as protocol,
				CASE 
					WHEN ssl_info IS NOT NULL THEN 'https://' || fqdn
					ELSE 'http://' || fqdn
				END as url,
				fqdn as domain,
				status_code,
				title,
				web_server,
				ARRAY[]::text[] as technologies,
				NULL::bigint as content_length,
				NULL::double precision as response_time_ms,
				NULL as screenshot_path,
				ssl_info,
				NULL::jsonb as http_response_headers,
				NULL::jsonb as findings_json
			FROM consolidated_attack_surface_assets
			WHERE scope_target_id = $1::uuid 
				AND asset_type = 'fqdn'
				AND status_code IS NOT NULL
				AND status_code >= 200 
				AND status_code < 400
				AND fqdn IS NOT NULL 
				AND fqdn != ''
		)
		SELECT DISTINCT ON (asset_identifier)
			$1::uuid, 'live_web_server', 
			asset_subtype,
			asset_identifier,
			ip_address, port, protocol, url, domain, status_code, title, web_server,
			technologies, content_length, response_time_ms, screenshot_path,
			ssl_info, http_response_headers, findings_json
		FROM comprehensive_live_web_servers
		WHERE asset_identifier IS NOT NULL
		ORDER BY asset_identifier, 
			CASE 
				WHEN asset_subtype = 'ip_port' THEN 1
				WHEN asset_subtype = 'target_url' THEN 2
				WHEN asset_subtype = 'wildcard_target_url' THEN 3
				WHEN asset_subtype = 'investigate_scan' THEN 4
				WHEN asset_subtype = 'enriched_fqdn' THEN 5
				WHEN asset_subtype = 'httpx_scan' THEN 6
				ELSE 7
			END
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			asset_subtype = EXCLUDED.asset_subtype,
			ip_address = EXCLUDED.ip_address,
			port = EXCLUDED.port,
			protocol = EXCLUDED.protocol,
			url = EXCLUDED.url,
			domain = EXCLUDED.domain,
			status_code = EXCLUDED.status_code,
			title = EXCLUDED.title,
			web_server = EXCLUDED.web_server,
			technologies = EXCLUDED.technologies,
			content_length = EXCLUDED.content_length,
			response_time_ms = EXCLUDED.response_time_ms,
			screenshot_path = EXCLUDED.screenshot_path,
			ssl_info = EXCLUDED.ssl_info,
			http_response_headers = EXCLUDED.http_response_headers,
			findings_json = EXCLUDED.findings_json,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), consolidatedQuery, scopeTargetID)
	if err != nil {
		log.Printf("[LIVE WEB SERVER CONSOLIDATION] Error inserting consolidated live web servers: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())
	log.Printf("[LIVE WEB SERVER CONSOLIDATION] ✅ Successfully inserted/updated %d live web server records", insertedCount)

	return insertedCount, nil
}

func consolidateCloudAssets(scopeTargetID string) (int, error) {
	log.Printf("[CLOUD ASSET CONSOLIDATION] Starting cloud asset consolidation for scope target: %s", scopeTargetID)

	// Debug query to check cloud asset data availability
	debugQuery := `
		SELECT 
			'amass_enum_cloud_domains' as source,
			COUNT(*) as count
		FROM amass_enum_company_cloud_domains
		WHERE scope_target_id = $1::uuid
		
		UNION ALL
		
		SELECT 
			'cloud_enum_scans' as source,
			COUNT(*) as count
		FROM cloud_enum_scans
		WHERE scope_target_id = $1::uuid AND status = 'success'
		
		UNION ALL
		
		SELECT 
			'katana_cloud_assets' as source,
			COUNT(*) as count
		FROM katana_company_cloud_assets
		WHERE scope_target_id = $1::uuid
		
		UNION ALL
		
		SELECT 
			'github_recon_cloud' as source,
			COUNT(*) as count
		FROM github_recon_scans
		WHERE scope_target_id = $1::uuid AND status = 'success'
		AND result IS NOT NULL
		
		UNION ALL
		
		SELECT 
			'security_trails_cloud' as source,
			COUNT(*) as count
		FROM securitytrails_company_scans
		WHERE scope_target_id = $1::uuid AND status = 'success'
		AND result IS NOT NULL
	`

	debugRows, err := dbPool.Query(context.Background(), debugQuery, scopeTargetID)
	if err != nil {
		log.Printf("[CLOUD ASSET CONSOLIDATION] Error in debug query: %v", err)
	} else {
		defer debugRows.Close()
		for debugRows.Next() {
			var source, count string
			if err := debugRows.Scan(&source, &count); err == nil {
				log.Printf("[CLOUD ASSET CONSOLIDATION] Debug - %s: %s records", source, count)
			}
		}
	}

	// Enhanced cloud asset consolidation query with proper NULL handling
	consolidatedQuery := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_identifier,
			domain, url, cloud_provider, cloud_service_type, cloud_region,
			a_records, aaaa_records, cname_records, mx_records, ns_records, txt_records
		)
		SELECT 
			$1::uuid, 'cloud_asset', 
			asset_identifier,
			COALESCE(string_agg(DISTINCT domain_name, ', ') FILTER (WHERE domain_name IS NOT NULL), ''),
			COALESCE(string_agg(DISTINCT url_value, ', ') FILTER (WHERE url_value IS NOT NULL), ''),
			COALESCE(string_agg(DISTINCT cloud_provider, ', ') FILTER (WHERE cloud_provider IS NOT NULL), 'unknown'),
			COALESCE(string_agg(DISTINCT service_type, ', ') FILTER (WHERE service_type IS NOT NULL), 'unknown'),
			COALESCE(string_agg(DISTINCT region_value, ', ') FILTER (WHERE region_value IS NOT NULL), ''),
			ARRAY[]::text[] as a_records,
			ARRAY[]::text[] as aaaa_records,
			ARRAY[]::text[] as cname_records,
			ARRAY[]::text[] as mx_records,
			ARRAY[]::text[] as ns_records,
			ARRAY[]::text[] as txt_records
		FROM (
			-- 1. Amass Enum cloud domains (direct cloud domains)
			SELECT 
				cloud_domain as asset_identifier,
				cloud_domain as domain_name,
				NULL as url_value,
				type as cloud_provider,
				'domain' as service_type,
				NULL as region_value
			FROM amass_enum_company_cloud_domains
			WHERE scope_target_id = $1::uuid
			
			UNION ALL
			
			-- 1b. Amass Enum DNS records (extract cloud domains from CNAME relationships)
			SELECT 
				extracted_cloud_domain as asset_identifier,
				extracted_cloud_domain as domain_name,
				NULL as url_value,
				CASE 
					WHEN extracted_cloud_domain ILIKE '%amazonaws%' OR extracted_cloud_domain ILIKE '%aws%' OR extracted_cloud_domain ILIKE '%awsdns%' OR extracted_cloud_domain ILIKE '%cloudfront%' OR extracted_cloud_domain ILIKE '%s3%' OR extracted_cloud_domain ILIKE '%elasticbeanstalk%' OR extracted_cloud_domain ILIKE '%amplifyapp%' THEN 'aws'
					WHEN extracted_cloud_domain ILIKE '%googleapis%' OR extracted_cloud_domain ILIKE '%googleusercontent%' OR extracted_cloud_domain ILIKE '%gcp%' OR extracted_cloud_domain ILIKE '%appspot%' OR extracted_cloud_domain ILIKE '%gcloud%' OR extracted_cloud_domain ILIKE '%withgoogle%' THEN 'gcp'
					WHEN extracted_cloud_domain ILIKE '%azure%' OR extracted_cloud_domain ILIKE '%microsoft%' OR extracted_cloud_domain ILIKE '%windows.net%' OR extracted_cloud_domain ILIKE '%trafficmanager%' OR extracted_cloud_domain ILIKE '%azureedge%' OR extracted_cloud_domain ILIKE '%azurewebsites%' OR extracted_cloud_domain ILIKE '%azure-api%' OR extracted_cloud_domain ILIKE '%cloudapp%' OR extracted_cloud_domain ILIKE '%microsoftonline%' THEN 'azure'
					WHEN extracted_cloud_domain ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN extracted_cloud_domain ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'amass_cname_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					CASE 
						-- Extract cloud domain from CNAME relationships like: "domain (FQDN) --> cname_record --> cloud-domain (FQDN)"
						WHEN record ~ '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)' THEN
							substring(record from '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)')
						-- Extract cloud domain from simpler CNAME patterns like: "domain --> cloud-domain"
						WHEN record ~ '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' THEN
							substring(record from '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
						-- If it's already a cloud domain, use it directly
						WHEN record ~ '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' AND (
							record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
							OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
							OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
							OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
						) THEN record
						ELSE NULL
					END as extracted_cloud_domain
				FROM amass_enum_company_dns_records
				WHERE scope_target_id = $1::uuid 
				AND record_type = 'CNAME'
				AND (
					record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
					OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
					OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
					OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
				)
			) amass_cname_extractions
			WHERE extracted_cloud_domain IS NOT NULL AND extracted_cloud_domain != ''
			
			UNION ALL
			
			-- 2. Cloud Enum results (AWS)
			SELECT 
				jsonb_array_elements_text(result::jsonb->'aws') as asset_identifier,
				jsonb_array_elements_text(result::jsonb->'aws') as domain_name,
				NULL as url_value,
				'aws' as cloud_provider,
				'domain' as service_type,
				NULL as region_value
			FROM cloud_enum_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
				AND result::jsonb ? 'aws'
			
			UNION ALL
			
			-- 3. Cloud Enum results (GCP)
			SELECT 
				jsonb_array_elements_text(result::jsonb->'gcp') as asset_identifier,
				jsonb_array_elements_text(result::jsonb->'gcp') as domain_name,
				NULL as url_value,
				'gcp' as cloud_provider,
				'domain' as service_type,
				NULL as region_value
			FROM cloud_enum_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
				AND result::jsonb ? 'gcp'
			
			UNION ALL
			
			-- 4. Cloud Enum results (Azure)
			SELECT 
				jsonb_array_elements_text(result::jsonb->'azure') as asset_identifier,
				jsonb_array_elements_text(result::jsonb->'azure') as domain_name,
				NULL as url_value,
				'azure' as cloud_provider,
				'domain' as service_type,
				NULL as region_value
			FROM cloud_enum_scans
			WHERE scope_target_id = $1::uuid AND status = 'success' AND result IS NOT NULL
				AND result::jsonb ? 'azure'
			
			UNION ALL
			
			-- 5. Katana cloud assets
			SELECT 
				asset_url as asset_identifier,
				asset_domain as domain_name,
				asset_url as url_value,
				CASE 
					WHEN service ILIKE '%aws%' THEN 'aws'
					WHEN service ILIKE '%gcp%' OR service ILIKE '%google%' THEN 'gcp'
					WHEN service ILIKE '%azure%' THEN 'azure'
					ELSE 'unknown'
				END as cloud_provider,
				service as service_type,
				region as region_value
			FROM katana_company_cloud_assets
			WHERE scope_target_id = $1::uuid
			
			UNION ALL
			
			-- 6. GitHub Recon cloud findings (extract cloud URLs/domains from results)
			SELECT DISTINCT
				cloud_asset as asset_identifier,
				CASE 
					WHEN cloud_asset ~ '^https?://' THEN 
						CASE 
							WHEN cloud_asset LIKE 'http://%' THEN 
								split_part(substring(cloud_asset from 8), '/', 1)
							WHEN cloud_asset LIKE 'https://%' THEN 
								split_part(substring(cloud_asset from 9), '/', 1)
							ELSE cloud_asset
						END
					ELSE cloud_asset
				END as domain_name,
				CASE 
					WHEN cloud_asset ~ '^https?://' THEN cloud_asset
					ELSE NULL
				END as url_value,
				CASE 
					WHEN cloud_asset ILIKE '%amazonaws%' OR cloud_asset ILIKE '%aws%' OR cloud_asset ILIKE '%awsdns%' OR cloud_asset ILIKE '%cloudfront%' OR cloud_asset ILIKE '%s3%' OR cloud_asset ILIKE '%elasticbeanstalk%' OR cloud_asset ILIKE '%amplifyapp%' THEN 'aws'
					WHEN cloud_asset ILIKE '%googleapis%' OR cloud_asset ILIKE '%googleusercontent%' OR cloud_asset ILIKE '%gcp%' OR cloud_asset ILIKE '%appspot%' OR cloud_asset ILIKE '%gcloud%' OR cloud_asset ILIKE '%withgoogle%' THEN 'gcp'
					WHEN cloud_asset ILIKE '%azure%' OR cloud_asset ILIKE '%microsoft%' OR cloud_asset ILIKE '%windows.net%' OR cloud_asset ILIKE '%trafficmanager%' OR cloud_asset ILIKE '%azureedge%' OR cloud_asset ILIKE '%azurewebsites%' OR cloud_asset ILIKE '%azure-api%' OR cloud_asset ILIKE '%cloudapp%' OR cloud_asset ILIKE '%microsoftonline%' THEN 'azure'
					WHEN cloud_asset ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN cloud_asset ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'github_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'cloud_assets') as cloud_asset
				FROM github_recon_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'cloud_assets'
				
				UNION ALL
				
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'urls') as cloud_asset
				FROM github_recon_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'urls'
			) github_cloud_data
			WHERE cloud_asset IS NOT NULL AND cloud_asset != ''
				AND (
					cloud_asset ILIKE '%amazonaws%' OR cloud_asset ILIKE '%aws%' OR cloud_asset ILIKE '%awsdns%' OR cloud_asset ILIKE '%cloudfront%' OR cloud_asset ILIKE '%s3%' OR cloud_asset ILIKE '%elasticbeanstalk%' OR cloud_asset ILIKE '%amplifyapp%'
					OR cloud_asset ILIKE '%googleapis%' OR cloud_asset ILIKE '%googleusercontent%' OR cloud_asset ILIKE '%gcp%' OR cloud_asset ILIKE '%appspot%' OR cloud_asset ILIKE '%gcloud%' OR cloud_asset ILIKE '%withgoogle%'
					OR cloud_asset ILIKE '%azure%' OR cloud_asset ILIKE '%microsoft%' OR cloud_asset ILIKE '%windows.net%' OR cloud_asset ILIKE '%trafficmanager%' OR cloud_asset ILIKE '%azureedge%' OR cloud_asset ILIKE '%azurewebsites%' OR cloud_asset ILIKE '%azure-api%' OR cloud_asset ILIKE '%cloudapp%' OR cloud_asset ILIKE '%microsoftonline%'
					OR cloud_asset ILIKE '%digitalocean%' OR cloud_asset ILIKE '%cloudflare%'
				)
			
			UNION ALL
			
			-- 7. Security Trails cloud findings (extract cloud domains from results)
			SELECT DISTINCT
				cloud_domain as asset_identifier,
				cloud_domain as domain_name,
				NULL as url_value,
				CASE 
					WHEN cloud_domain ILIKE '%amazonaws%' OR cloud_domain ILIKE '%aws%' OR cloud_domain ILIKE '%awsdns%' OR cloud_domain ILIKE '%cloudfront%' OR cloud_domain ILIKE '%s3%' OR cloud_domain ILIKE '%elasticbeanstalk%' OR cloud_domain ILIKE '%amplifyapp%' THEN 'aws'
					WHEN cloud_domain ILIKE '%googleapis%' OR cloud_domain ILIKE '%googleusercontent%' OR cloud_domain ILIKE '%gcp%' OR cloud_domain ILIKE '%appspot%' OR cloud_domain ILIKE '%gcloud%' OR cloud_domain ILIKE '%withgoogle%' THEN 'gcp'
					WHEN cloud_domain ILIKE '%azure%' OR cloud_domain ILIKE '%microsoft%' OR cloud_domain ILIKE '%windows.net%' OR cloud_domain ILIKE '%trafficmanager%' OR cloud_domain ILIKE '%azureedge%' OR cloud_domain ILIKE '%azurewebsites%' OR cloud_domain ILIKE '%azure-api%' OR cloud_domain ILIKE '%cloudapp%' OR cloud_domain ILIKE '%microsoftonline%' THEN 'azure'
					WHEN cloud_domain ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN cloud_domain ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'security_trails_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'subdomains') as cloud_domain
				FROM securitytrails_company_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'subdomains'
			) security_trails_cloud_data
			WHERE cloud_domain IS NOT NULL AND cloud_domain != ''
				AND (
					cloud_domain ILIKE '%amazonaws%' OR cloud_domain ILIKE '%aws%' OR cloud_domain ILIKE '%awsdns%' OR cloud_domain ILIKE '%cloudfront%' OR cloud_domain ILIKE '%s3%' OR cloud_domain ILIKE '%elasticbeanstalk%' OR cloud_domain ILIKE '%amplifyapp%'
					OR cloud_domain ILIKE '%googleapis%' OR cloud_domain ILIKE '%googleusercontent%' OR cloud_domain ILIKE '%gcp%' OR cloud_domain ILIKE '%appspot%' OR cloud_domain ILIKE '%gcloud%' OR cloud_domain ILIKE '%withgoogle%'
					OR cloud_domain ILIKE '%azure%' OR cloud_domain ILIKE '%microsoft%' OR cloud_domain ILIKE '%windows.net%' OR cloud_domain ILIKE '%trafficmanager%' OR cloud_domain ILIKE '%azureedge%' OR cloud_domain ILIKE '%azurewebsites%' OR cloud_domain ILIKE '%azure-api%' OR cloud_domain ILIKE '%cloudapp%' OR cloud_domain ILIKE '%microsoftonline%'
					OR cloud_domain ILIKE '%digitalocean%' OR cloud_domain ILIKE '%cloudflare%'
				)
			
			UNION ALL
			
			-- 8. Additional cloud assets from DNS records (cloud-related CNAMEs)
			SELECT DISTINCT
				extracted_cloud_domain as asset_identifier,
				extracted_cloud_domain as domain_name,
				NULL as url_value,
				CASE 
					WHEN extracted_cloud_domain ILIKE '%amazonaws%' OR extracted_cloud_domain ILIKE '%aws%' OR extracted_cloud_domain ILIKE '%awsdns%' OR extracted_cloud_domain ILIKE '%cloudfront%' OR extracted_cloud_domain ILIKE '%s3%' OR extracted_cloud_domain ILIKE '%elasticbeanstalk%' OR extracted_cloud_domain ILIKE '%amplifyapp%' THEN 'aws'
					WHEN extracted_cloud_domain ILIKE '%googleapis%' OR extracted_cloud_domain ILIKE '%googleusercontent%' OR extracted_cloud_domain ILIKE '%gcp%' OR extracted_cloud_domain ILIKE '%appspot%' OR extracted_cloud_domain ILIKE '%gcloud%' OR extracted_cloud_domain ILIKE '%withgoogle%' THEN 'gcp'
					WHEN extracted_cloud_domain ILIKE '%azure%' OR extracted_cloud_domain ILIKE '%microsoft%' OR extracted_cloud_domain ILIKE '%windows.net%' OR extracted_cloud_domain ILIKE '%trafficmanager%' OR extracted_cloud_domain ILIKE '%azureedge%' OR extracted_cloud_domain ILIKE '%azurewebsites%' OR extracted_cloud_domain ILIKE '%azure-api%' OR extracted_cloud_domain ILIKE '%cloudapp%' OR extracted_cloud_domain ILIKE '%microsoftonline%' THEN 'azure'
					WHEN extracted_cloud_domain ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN extracted_cloud_domain ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'dns_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					CASE 
						-- Extract cloud domain from CNAME relationships like: "domain (FQDN) --> cname_record --> cloud-domain (FQDN)"
						WHEN record ~ '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)' THEN
							substring(record from '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)')
						-- Extract cloud domain from simpler CNAME patterns like: "domain --> cloud-domain"
						WHEN record ~ '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' THEN
							substring(record from '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
						-- If it's already a cloud domain, use it directly
						WHEN record ~ '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' AND (
							record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
							OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
							OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
							OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
						) THEN record
						ELSE NULL
					END as extracted_cloud_domain
				FROM dnsx_company_dns_records
				WHERE scope_target_id = $1::uuid AND record_type = 'CNAME'
				AND (
					record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
					OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
					OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
					OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
				)
				
				UNION ALL
				
				SELECT DISTINCT
					CASE 
						-- Extract cloud domain from CNAME relationships like: "domain (FQDN) --> cname_record --> cloud-domain (FQDN)"
						WHEN record ~ '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)' THEN
							substring(record from '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)')
						-- Extract cloud domain from simpler CNAME patterns like: "domain --> cloud-domain"
						WHEN record ~ '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' THEN
							substring(record from '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
						-- If it's already a cloud domain, use it directly
						WHEN record ~ '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' AND (
							record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
							OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
							OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
							OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
						) THEN record
						ELSE NULL
					END as extracted_cloud_domain
				FROM amass_enum_company_dns_records
				WHERE scope_target_id = $1::uuid AND record_type = 'CNAME'
				AND (
					record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
					OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
					OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
					OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
				)
			) dns_cloud_data
			WHERE extracted_cloud_domain IS NOT NULL AND extracted_cloud_domain != ''
			
			UNION ALL
			
			-- 8b. DNSx non-CNAME records (A, AAAA, NS, TXT, MX) that contain cloud domains
			SELECT DISTINCT
				extracted_cloud_domain as asset_identifier,
				extracted_cloud_domain as domain_name,
				NULL as url_value,
				CASE 
					WHEN extracted_cloud_domain ILIKE '%amazonaws%' OR extracted_cloud_domain ILIKE '%aws%' OR extracted_cloud_domain ILIKE '%awsdns%' OR extracted_cloud_domain ILIKE '%cloudfront%' OR extracted_cloud_domain ILIKE '%s3%' OR extracted_cloud_domain ILIKE '%elasticbeanstalk%' OR extracted_cloud_domain ILIKE '%amplifyapp%' THEN 'aws'
					WHEN extracted_cloud_domain ILIKE '%googleapis%' OR extracted_cloud_domain ILIKE '%googleusercontent%' OR extracted_cloud_domain ILIKE '%gcp%' OR extracted_cloud_domain ILIKE '%appspot%' OR extracted_cloud_domain ILIKE '%gcloud%' OR extracted_cloud_domain ILIKE '%withgoogle%' THEN 'gcp'
					WHEN extracted_cloud_domain ILIKE '%azure%' OR extracted_cloud_domain ILIKE '%microsoft%' OR extracted_cloud_domain ILIKE '%windows.net%' OR extracted_cloud_domain ILIKE '%trafficmanager%' OR extracted_cloud_domain ILIKE '%azureedge%' OR extracted_cloud_domain ILIKE '%azurewebsites%' OR extracted_cloud_domain ILIKE '%azure-api%' OR extracted_cloud_domain ILIKE '%cloudapp%' OR extracted_cloud_domain ILIKE '%microsoftonline%' THEN 'azure'
					WHEN extracted_cloud_domain ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN extracted_cloud_domain ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'dnsx_non_cname_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					CASE 
						-- For A/AAAA records, check if the record value itself is a cloud domain
						WHEN record_type IN ('A', 'AAAA') AND record ~ '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' AND (
							record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
							OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
							OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
							OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
						) THEN record
						-- For NS, TXT, MX records, extract domain from the record value
						WHEN record_type IN ('NS', 'TXT', 'MX') AND record ~ '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' THEN
							CASE
								WHEN record ~ '([a-zA-Z0-9.-]+\.(amazonaws|aws|awsdns|cloudfront|s3|elasticbeanstalk|amplifyapp)\.[a-zA-Z0-9.-]+)' THEN
									substring(record from '([a-zA-Z0-9.-]+\.(amazonaws|aws|awsdns|cloudfront|s3|elasticbeanstalk|amplifyapp)\.[a-zA-Z0-9.-]+)')
								WHEN record ~ '([a-zA-Z0-9.-]+\.(googleapis|googleusercontent|gcp|appspot|gcloud|withgoogle)\.[a-zA-Z0-9.-]+)' THEN
									substring(record from '([a-zA-Z0-9.-]+\.(googleapis|googleusercontent|gcp|appspot|gcloud|withgoogle)\.[a-zA-Z0-9.-]+)')
								WHEN record ~ '([a-zA-Z0-9.-]+\.(azure|microsoft|windows\.net|trafficmanager|azureedge|azurewebsites|azure-api|cloudapp|microsoftonline)\.[a-zA-Z0-9.-]+)' THEN
									substring(record from '([a-zA-Z0-9.-]+\.(azure|microsoft|windows\.net|trafficmanager|azureedge|azurewebsites|azure-api|cloudapp|microsoftonline)\.[a-zA-Z0-9.-]+)')
								WHEN record ~ '([a-zA-Z0-9.-]+\.(digitalocean|cloudflare)\.[a-zA-Z0-9.-]+)' THEN
									substring(record from '([a-zA-Z0-9.-]+\.(digitalocean|cloudflare)\.[a-zA-Z0-9.-]+)')
								ELSE NULL
							END
						ELSE NULL
					END as extracted_cloud_domain
				FROM dnsx_company_dns_records
				WHERE scope_target_id = $1::uuid 
				AND record_type IN ('A', 'AAAA', 'NS', 'TXT', 'MX')
				AND (
					record ILIKE '%amazonaws%' OR record ILIKE '%aws%' OR record ILIKE '%awsdns%' OR record ILIKE '%cloudfront%' OR record ILIKE '%s3%' OR record ILIKE '%elasticbeanstalk%' OR record ILIKE '%amplifyapp%'
					OR record ILIKE '%googleapis%' OR record ILIKE '%googleusercontent%' OR record ILIKE '%gcp%' OR record ILIKE '%appspot%' OR record ILIKE '%gcloud%' OR record ILIKE '%withgoogle%'
					OR record ILIKE '%azure%' OR record ILIKE '%microsoft%' OR record ILIKE '%windows.net%' OR record ILIKE '%trafficmanager%' OR record ILIKE '%azureedge%' OR record ILIKE '%azurewebsites%' OR record ILIKE '%azure-api%' OR record ILIKE '%cloudapp%' OR record ILIKE '%microsoftonline%'
					OR record ILIKE '%digitalocean%' OR record ILIKE '%cloudflare%'
				)
			) dnsx_non_cname_cloud_data
			WHERE extracted_cloud_domain IS NOT NULL AND extracted_cloud_domain != ''
			AND extracted_cloud_domain !~ '^(\d{1,3}\.){3}\d{1,3}$'
			
			UNION ALL
			
			-- 9. Extract cloud domains from raw Amass results (complex relationships)
			SELECT DISTINCT
				extracted_cloud_domain as asset_identifier,
				extracted_cloud_domain as domain_name,
				NULL as url_value,
				CASE
					WHEN extracted_cloud_domain ILIKE '%amazonaws%' OR extracted_cloud_domain ILIKE '%aws%' OR extracted_cloud_domain ILIKE '%awsdns%' OR extracted_cloud_domain ILIKE '%cloudfront%' OR extracted_cloud_domain ILIKE '%s3%' OR extracted_cloud_domain ILIKE '%elasticbeanstalk%' OR extracted_cloud_domain ILIKE '%amplifyapp%' THEN 'aws'
					WHEN extracted_cloud_domain ILIKE '%googleapis%' OR extracted_cloud_domain ILIKE '%googleusercontent%' OR extracted_cloud_domain ILIKE '%gcp%' OR extracted_cloud_domain ILIKE '%appspot%' OR extracted_cloud_domain ILIKE '%gcloud%' OR extracted_cloud_domain ILIKE '%withgoogle%' THEN 'gcp'
					WHEN extracted_cloud_domain ILIKE '%azure%' OR extracted_cloud_domain ILIKE '%microsoft%' OR extracted_cloud_domain ILIKE '%windows.net%' OR extracted_cloud_domain ILIKE '%trafficmanager%' OR extracted_cloud_domain ILIKE '%azureedge%' OR extracted_cloud_domain ILIKE '%azurewebsites%' OR extracted_cloud_domain ILIKE '%azure-api%' OR extracted_cloud_domain ILIKE '%cloudapp%' OR extracted_cloud_domain ILIKE '%microsoftonline%' THEN 'azure'
					WHEN extracted_cloud_domain ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN extracted_cloud_domain ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'amass_raw_discovery' as service_type,
				NULL as region_value
			FROM (
				SELECT DISTINCT
					CASE
						-- Extract cloud domain from CNAME relationships like: "domain (FQDN) --> cname_record --> cloud-domain (FQDN)"
						WHEN raw_output ~ '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)' THEN
							substring(raw_output from '\(FQDN\) --> cname_record --> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) \(FQDN\)')
						-- Extract cloud domain from simpler CNAME patterns like: "domain --> cloud-domain"
						WHEN raw_output ~ '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' THEN
							substring(raw_output from '--> ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
						-- Extract cloud domains that are already in the output (simplified approach)
						WHEN raw_output ~ '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' AND (
							raw_output ILIKE '%amazonaws%' OR raw_output ILIKE '%aws%' OR raw_output ILIKE '%awsdns%' OR raw_output ILIKE '%cloudfront%' OR raw_output ILIKE '%s3%' OR raw_output ILIKE '%elasticbeanstalk%' OR raw_output ILIKE '%amplifyapp%'
							OR raw_output ILIKE '%googleapis%' OR raw_output ILIKE '%googleusercontent%' OR raw_output ILIKE '%gcp%' OR raw_output ILIKE '%appspot%' OR raw_output ILIKE '%gcloud%' OR raw_output ILIKE '%withgoogle%'
							OR raw_output ILIKE '%azure%' OR raw_output ILIKE '%microsoft%' OR raw_output ILIKE '%windows.net%' OR raw_output ILIKE '%trafficmanager%' OR raw_output ILIKE '%azureedge%' OR raw_output ILIKE '%azurewebsites%' OR raw_output ILIKE '%azure-api%' OR raw_output ILIKE '%cloudapp%' OR raw_output ILIKE '%microsoftonline%'
							OR raw_output ILIKE '%digitalocean%' OR raw_output ILIKE '%cloudflare%'
						) THEN
							-- Use a simpler regex extraction for the first match
							substring(raw_output from '([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
						ELSE NULL
					END as extracted_cloud_domain
				FROM amass_enum_company_domain_results
				WHERE scope_target_id = $1::uuid
				AND (
					raw_output ILIKE '%amazonaws%' OR raw_output ILIKE '%aws%' OR raw_output ILIKE '%awsdns%' OR raw_output ILIKE '%cloudfront%' OR raw_output ILIKE '%s3%' OR raw_output ILIKE '%elasticbeanstalk%' OR raw_output ILIKE '%amplifyapp%'
					OR raw_output ILIKE '%googleapis%' OR raw_output ILIKE '%googleusercontent%' OR raw_output ILIKE '%gcp%' OR raw_output ILIKE '%appspot%' OR raw_output ILIKE '%gcloud%' OR raw_output ILIKE '%withgoogle%'
					OR raw_output ILIKE '%azure%' OR raw_output ILIKE '%microsoft%' OR raw_output ILIKE '%windows.net%' OR raw_output ILIKE '%trafficmanager%' OR raw_output ILIKE '%azureedge%' OR raw_output ILIKE '%azurewebsites%' OR raw_output ILIKE '%azure-api%' OR raw_output ILIKE '%cloudapp%' OR raw_output ILIKE '%microsoftonline%'
					OR raw_output ILIKE '%digitalocean%' OR raw_output ILIKE '%cloudflare%'
				)
			) amass_raw_extractions
			WHERE extracted_cloud_domain IS NOT NULL AND extracted_cloud_domain != ''
			
			UNION ALL
			
			-- 10. Extract cloud domains from consolidated FQDNs (Domain Names list)
			SELECT DISTINCT
				fqdn as asset_identifier,
				fqdn as domain_name,
				NULL as url_value,
				CASE
					WHEN fqdn ILIKE '%amazonaws%' OR fqdn ILIKE '%aws%' OR fqdn ILIKE '%awsdns%' OR fqdn ILIKE '%cloudfront%' OR fqdn ILIKE '%s3%' OR fqdn ILIKE '%elasticbeanstalk%' OR fqdn ILIKE '%amplifyapp%' THEN 'aws'
					WHEN fqdn ILIKE '%googleapis%' OR fqdn ILIKE '%googleusercontent%' OR fqdn ILIKE '%gcp%' OR fqdn ILIKE '%appspot%' OR fqdn ILIKE '%gcloud%' OR fqdn ILIKE '%withgoogle%' THEN 'gcp'
					WHEN fqdn ILIKE '%azure%' OR fqdn ILIKE '%microsoft%' OR fqdn ILIKE '%windows.net%' OR fqdn ILIKE '%trafficmanager%' OR fqdn ILIKE '%azureedge%' OR fqdn ILIKE '%azurewebsites%' OR fqdn ILIKE '%azure-api%' OR fqdn ILIKE '%cloudapp%' OR fqdn ILIKE '%microsoftonline%' THEN 'azure'
					WHEN fqdn ILIKE '%digitalocean%' THEN 'digitalocean'
					WHEN fqdn ILIKE '%cloudflare%' THEN 'cloudflare'
					ELSE 'unknown'
				END as cloud_provider,
				'consolidated_fqdn_discovery' as service_type,
				NULL as region_value
			FROM consolidated_attack_surface_assets
			WHERE scope_target_id = $1::uuid
			AND asset_type = 'fqdn'
			AND fqdn IS NOT NULL
			AND fqdn != ''
			AND (
				fqdn ILIKE '%amazonaws%' OR fqdn ILIKE '%aws%' OR fqdn ILIKE '%awsdns%' OR fqdn ILIKE '%cloudfront%' OR fqdn ILIKE '%s3%' OR fqdn ILIKE '%elasticbeanstalk%' OR fqdn ILIKE '%amplifyapp%'
				OR fqdn ILIKE '%googleapis%' OR fqdn ILIKE '%googleusercontent%' OR fqdn ILIKE '%gcp%' OR fqdn ILIKE '%appspot%' OR fqdn ILIKE '%gcloud%' OR fqdn ILIKE '%withgoogle%'
				OR fqdn ILIKE '%azure%' OR fqdn ILIKE '%microsoft%' OR fqdn ILIKE '%windows.net%' OR fqdn ILIKE '%trafficmanager%' OR fqdn ILIKE '%azureedge%' OR fqdn ILIKE '%azurewebsites%' OR fqdn ILIKE '%azure-api%' OR fqdn ILIKE '%cloudapp%' OR fqdn ILIKE '%microsoftonline%'
				OR fqdn ILIKE '%digitalocean%' OR fqdn ILIKE '%cloudflare%'
			)
			AND fqdn !~ '^(\d{1,3}\.){3}\d{1,3}$'
		) all_cloud_data
		WHERE asset_identifier IS NOT NULL
		GROUP BY asset_identifier
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			domain = EXCLUDED.domain,
			url = EXCLUDED.url,
			cloud_provider = EXCLUDED.cloud_provider,
			cloud_service_type = EXCLUDED.cloud_service_type,
			cloud_region = EXCLUDED.cloud_region,
			a_records = EXCLUDED.a_records,
			aaaa_records = EXCLUDED.aaaa_records,
			cname_records = EXCLUDED.cname_records,
			mx_records = EXCLUDED.mx_records,
			ns_records = EXCLUDED.ns_records,
			txt_records = EXCLUDED.txt_records,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), consolidatedQuery, scopeTargetID)
	if err != nil {
		log.Printf("[CLOUD ASSET CONSOLIDATION] Error inserting consolidated cloud assets: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())
	log.Printf("[CLOUD ASSET CONSOLIDATION] ✅ Successfully inserted/updated %d cloud asset records", insertedCount)

	// DNS record aggregation is handled separately and is already comprehensive
	// so we'll skip that part for now to avoid complexity

	return insertedCount, nil
}

func consolidateFQDNs(scopeTargetID string) (int, error) {
	log.Printf("[FQDN CONSOLIDATION] Starting FQDN consolidation for scope target: %s", scopeTargetID)

	// Debug query to check FQDN data availability
	debugQuery := `
		SELECT 
			'consolidated_subdomains' as source,
			COUNT(*) as count
		FROM consolidated_subdomains cs
		WHERE (
			-- Company scope target subdomains
			cs.scope_target_id = $1::uuid
			OR
			-- Wildcard scope target subdomains that match company domains
			cs.scope_target_id IN (
				SELECT st.id
				FROM scope_targets st
				WHERE st.type = 'Wildcard'
				AND CASE 
					WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
					ELSE st.scope_target
				END IN (
					SELECT DISTINCT domain 
					FROM consolidated_company_domains 
					WHERE scope_target_id = $1::uuid
				)
			)
		)
		
						UNION ALL
		
		SELECT 
			'consolidated_company_domains' as source,
			COUNT(*) as count
		FROM consolidated_company_domains
		WHERE scope_target_id = $1::uuid
		
						UNION ALL
		
		SELECT 
			'dnsx_company_dns_records' as source,
			COUNT(*) as count
		FROM dnsx_company_dns_records
		WHERE scope_target_id = $1::uuid
		
						UNION ALL
		
		SELECT 
			'target_urls' as source,
			COUNT(*) as count
		FROM target_urls
		WHERE scope_target_id = $1::uuid AND no_longer_live = false
		
						UNION ALL
		
		SELECT 
			'target_urls_from_wildcards' as source,
			COUNT(*) as count
		FROM target_urls tu
		JOIN scope_targets st ON tu.scope_target_id = st.id
		WHERE st.type = 'Wildcard' 
		AND CASE 
			WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
			ELSE st.scope_target
		END IN (
			SELECT DISTINCT domain 
			FROM consolidated_company_domains 
			WHERE scope_target_id = $1::uuid
		)
		AND tu.no_longer_live = false
		
						UNION ALL
		
		SELECT 
			'live_web_servers' as source,
			COUNT(*) as count
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
		
						UNION ALL
		
		SELECT 
			'wildcard_targets_available' as source,
			COUNT(*) as count
		FROM scope_targets
		WHERE type = 'Wildcard'
		
						UNION ALL
		
		SELECT 
			'wildcard_targets_matching_company_domains' as source,
			COUNT(*) as count
		FROM scope_targets st
		WHERE st.type = 'Wildcard' 
		AND CASE 
			WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
			ELSE st.scope_target
		END IN (
			SELECT DISTINCT domain 
			FROM consolidated_company_domains 
			WHERE scope_target_id = $1::uuid
		)
		
						UNION ALL
		
		SELECT 
			'target_urls_in_wildcard_targets' as source,
			COUNT(*) as count
		FROM target_urls tu
		JOIN scope_targets st ON tu.scope_target_id = st.id
		WHERE st.type = 'Wildcard'
		AND tu.no_longer_live = false
	`

	debugRows, err := dbPool.Query(context.Background(), debugQuery, scopeTargetID)
	if err != nil {
		log.Printf("[FQDN CONSOLIDATION] Error in debug query: %v", err)
	} else {
		defer debugRows.Close()
		for debugRows.Next() {
			var source, count string
			if err := debugRows.Scan(&source, &count); err == nil {
				log.Printf("[FQDN CONSOLIDATION] Debug - %s: %s records", source, count)
			}
		}
	}

	// Enhanced FQDN consolidation with additional sources
	consolidatedQuery := `
		INSERT INTO consolidated_attack_surface_assets (
			scope_target_id, asset_type, asset_identifier, fqdn, root_domain, subdomain,
			registrar, creation_date, expiration_date, updated_date, name_servers, status,
			whois_info, ssl_certificate, ssl_expiry_date, ssl_issuer, ssl_subject, ssl_version,
			ssl_cipher_suite, ssl_protocols, resolved_ips, mail_servers, spf_record, dkim_record,
			dmarc_record, caa_records, txt_records, mx_records, ns_records, a_records,
			aaaa_records, cname_records, ptr_records, srv_records, soa_record,
			last_dns_scan, last_ssl_scan, last_whois_scan
		)
		WITH enhanced_fqdn_sources AS (
			-- 1. Consolidated subdomains (from company scope target and wildcard targets)
			SELECT
				subdomain as fqdn,
				subdomain as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM consolidated_subdomains cs
			WHERE (
				-- Company scope target subdomains
				cs.scope_target_id = $1::uuid
				OR
				-- Wildcard scope target subdomains that match company domains
				cs.scope_target_id IN (
					SELECT st.id
					FROM scope_targets st
					WHERE st.type = 'Wildcard'
					AND CASE 
						WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
						ELSE st.scope_target
					END IN (
						SELECT DISTINCT domain 
						FROM consolidated_company_domains 
						WHERE scope_target_id = $1::uuid
					)
				)
			)
			AND subdomain ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			
			UNION ALL
			
			-- 2. Consolidated company domains (root domains)
			SELECT
				domain as fqdn,
				domain as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM consolidated_company_domains
			WHERE scope_target_id = $1::uuid
				AND domain ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			
			UNION ALL
			
			-- 3. Target URLs from wildcard targets (consolidate button workflow results)
			SELECT DISTINCT
				domain_from_url as fqdn,
				domain_from_url as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM (
				SELECT DISTINCT
					CASE 
						WHEN tu.url LIKE 'http://%' THEN 
							CASE 
								WHEN position(':' in substring(tu.url from 8)) > 0 THEN 
									substring(substring(tu.url from 8) from 1 for position(':' in substring(tu.url from 8)) - 1)
								ELSE split_part(substring(tu.url from 8), '/', 1)
							END
						WHEN tu.url LIKE 'https://%' THEN 
							CASE 
								WHEN position(':' in substring(tu.url from 9)) > 0 THEN 
									substring(substring(tu.url from 9) from 1 for position(':' in substring(tu.url from 9)) - 1)
								ELSE split_part(substring(tu.url from 9), '/', 1)
							END
						ELSE NULL
					END as domain_from_url
				FROM target_urls tu
				JOIN scope_targets st ON tu.scope_target_id = st.id
				WHERE st.type = 'Wildcard' 
				AND CASE 
					WHEN st.scope_target LIKE '*%.%' THEN SUBSTRING(st.scope_target FROM 3)
					ELSE st.scope_target
				END IN (
					SELECT DISTINCT domain 
					FROM consolidated_company_domains 
					WHERE scope_target_id = $1::uuid
				)
				AND tu.no_longer_live = false
				AND tu.url IS NOT NULL AND tu.url != ''
			) target_url_domains
			WHERE domain_from_url IS NOT NULL 
			AND domain_from_url != ''
			AND domain_from_url ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			AND domain_from_url !~ '^(\d{1,3}\.){3}\d{1,3}$'
			
			UNION ALL
			
			-- 4. DNSx Company DNS records (only CNAME, NS records that are valid domains)
			SELECT
				record as fqdn,
				root_domain,
				CASE
					WHEN record != root_domain AND position('.' in record) > 0 THEN
						substring(record from 1 for position('.' in record) - 1)
					ELSE NULL
				END as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				last_scanned_at as last_dns_scan,
				NULL as last_ssl_scan,
				NULL as last_whois_scan
			FROM dnsx_company_dns_records
			WHERE scope_target_id = $1::uuid
				AND record_type IN ('CNAME', 'NS')
				AND record ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
				AND record NOT LIKE '%:%'
				AND record NOT LIKE '%-->%'
				AND record NOT LIKE '%=%'
				AND record NOT LIKE 'http://%'
				AND record NOT LIKE 'https://%'
				AND record !~ '^(\d{1,3}\.){3}\d{1,3}$'
				AND record !~ '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
				AND record !~ '^([0-9a-fA-F]{1,4}:)*:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'
			
			UNION ALL
			
			-- 5. Amass Enum Company DNS records (only CNAME, NS records that are valid domains)
			SELECT
				record as fqdn,
				root_domain,
				CASE
					WHEN record != root_domain AND position('.' in record) > 0 THEN
						substring(record from 1 for position('.' in record) - 1)
					ELSE NULL
				END as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				last_scanned_at as last_dns_scan,
				NULL as last_ssl_scan,
				NULL as last_whois_scan
			FROM amass_enum_company_dns_records
			WHERE scope_target_id = $1::uuid
				AND record_type IN ('CNAME', 'NS')
				AND record ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
				AND record NOT LIKE '%:%'
				AND record NOT LIKE '%-->%'
				AND record NOT LIKE '%=%'
				AND record NOT LIKE 'http://%'
				AND record NOT LIKE 'https://%'
				AND record !~ '^(\d{1,3}\.){3}\d{1,3}$'
				AND record !~ '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
				AND record !~ '^([0-9a-fA-F]{1,4}:)*:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'
			
			UNION ALL
			
			-- 6. Target URLs (wildcard targets with rich data)
			SELECT
				CASE
					WHEN url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(url from 8)) > 0 THEN 
								substring(substring(url from 8) from 1 for position(':' in substring(url from 8)) - 1)
							ELSE substring(url from 8)
						END
					WHEN url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(url from 9)) > 0 THEN 
								substring(substring(url from 9) from 1 for position(':' in substring(url from 9)) - 1)
							ELSE substring(url from 9)
						END
					ELSE url
				END as fqdn,
				CASE
					WHEN url LIKE 'http://%' THEN 
						CASE 
							WHEN position(':' in substring(url from 8)) > 0 THEN 
								substring(substring(url from 8) from 1 for position(':' in substring(url from 8)) - 1)
							ELSE substring(url from 8)
						END
					WHEN url LIKE 'https://%' THEN 
						CASE 
							WHEN position(':' in substring(url from 9)) > 0 THEN 
								substring(substring(url from 9) from 1 for position(':' in substring(url from 9)) - 1)
							ELSE substring(url from 9)
						END
					ELSE url
				END as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM target_urls
			WHERE scope_target_id = $1::uuid AND no_longer_live = false
				AND (
					CASE
						WHEN url LIKE 'http://%' THEN 
							CASE 
								WHEN position(':' in substring(url from 8)) > 0 THEN 
									substring(substring(url from 8) from 1 for position(':' in substring(url from 8)) - 1)
								ELSE substring(url from 8)
							END
						WHEN url LIKE 'https://%' THEN 
							CASE 
								WHEN position(':' in substring(url from 9)) > 0 THEN 
									substring(substring(url from 9) from 1 for position(':' in substring(url from 9)) - 1)
								ELSE substring(url from 9)
							END
						ELSE url
					END
				) ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			
			UNION ALL
			
			-- 7. Domains from live web servers (IP/Port scan results)
			SELECT DISTINCT
				domain_from_url as fqdn,
				domain_from_url as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM (
				SELECT DISTINCT
					CASE
						WHEN lws.url LIKE 'http://%' THEN 
							CASE 
								WHEN position(':' in substring(lws.url from 8)) > 0 THEN 
									substring(substring(lws.url from 8) from 1 for position(':' in substring(lws.url from 8)) - 1)
								ELSE split_part(substring(lws.url from 8), '/', 1)
							END
						WHEN lws.url LIKE 'https://%' THEN 
							CASE 
								WHEN position(':' in substring(lws.url from 9)) > 0 THEN 
									substring(substring(lws.url from 9) from 1 for position(':' in substring(lws.url from 9)) - 1)
								ELSE split_part(substring(lws.url from 9), '/', 1)
							END
						ELSE lws.url
					END as domain_from_url
				FROM live_web_servers lws
				JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
				WHERE ips.scope_target_id = $1::uuid AND ips.status = 'success'
				AND lws.url IS NOT NULL
			) lws_domains
			WHERE domain_from_url IS NOT NULL 
			AND domain_from_url != ''
			AND domain_from_url ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			AND domain_from_url !~ '^(\d{1,3}\.){3}\d{1,3}$'
			
			UNION ALL
			
			-- 8. Consolidated root domains (from consolidate button process)
			SELECT DISTINCT
				domain as fqdn,
				domain as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM consolidated_company_domains
			WHERE scope_target_id = $1::uuid
				AND domain ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			
			UNION ALL
			
			-- 9. Additional domains from various company workflow results
			SELECT DISTINCT
				domain_result as fqdn,
				domain_result as root_domain,
				NULL as subdomain_part,
				NULL as registrar,
				NULL::DATE as creation_date,
				NULL::DATE as expiration_date,
				NULL::DATE as updated_date,
				NULL::TEXT[] as name_servers,
				NULL::TEXT[] as status,
				NULL::JSONB as whois_info,
				NULL::JSONB as ssl_certificate,
				NULL::DATE as ssl_expiry_date,
				NULL as ssl_issuer,
				NULL as ssl_subject,
				NULL as ssl_version,
				NULL as ssl_cipher_suite,
				NULL::TEXT[] as ssl_protocols,
				NULL::TEXT[] as resolved_ips,
				NULL::TEXT[] as mail_servers,
				NULL as spf_record,
				NULL as dkim_record,
				NULL as dmarc_record,
				NULL::TEXT[] as caa_records,
				NULL::TEXT[] as txt_records,
				NULL::TEXT[] as mx_records,
				NULL::TEXT[] as ns_records,
				NULL::TEXT[] as a_records,
				NULL::TEXT[] as aaaa_records,
				NULL::TEXT[] as cname_records,
				NULL::TEXT[] as ptr_records,
				NULL::TEXT[] as srv_records,
				NULL::JSONB as soa_record,
				NULL::TIMESTAMP as last_dns_scan,
				NULL::TIMESTAMP as last_ssl_scan,
				NULL::TIMESTAMP as last_whois_scan
			FROM (
				-- Security Trails company scan domains
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'subdomains') as domain_result
				FROM securitytrails_company_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'subdomains'
				
				UNION ALL
				
				-- GitHub Recon domains
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'domains') as domain_result
				FROM github_recon_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'domains'
				
				UNION ALL
				
				-- Shodan company scan domains
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'hostnames') as domain_result
				FROM shodan_company_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'hostnames'
				
				UNION ALL
				
				-- Censys company scan domains
				SELECT DISTINCT
					jsonb_array_elements_text(result::jsonb->'names') as domain_result
				FROM censys_company_scans
				WHERE scope_target_id = $1::uuid AND status = 'success' 
				AND result IS NOT NULL AND result::jsonb ? 'names'
			) company_domains
			WHERE domain_result IS NOT NULL 
			AND domain_result != ''
			AND domain_result ~ '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
			AND domain_result !~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND domain_result NOT LIKE '%amazonaws%'
			AND domain_result NOT LIKE '%googleapis%'
			AND domain_result NOT LIKE '%azure%'
			AND domain_result NOT LIKE '%cloudflare%'
			-- Additional infrastructure/cloud domain patterns
			AND domain_result NOT LIKE '%.awsdns-%'
			AND domain_result NOT LIKE 'ns-%.awsdns-%'
			AND domain_result NOT LIKE '%.googledns.com'
			AND domain_result NOT LIKE '%.googledomains.com'
			AND domain_result NOT LIKE '%.google.com'
			AND domain_result NOT LIKE 'ns%.google.com'
			AND domain_result NOT LIKE '%.outlook.com'
			AND domain_result NOT LIKE '%.live.com'
			AND domain_result NOT LIKE '%.hotmail.com'
			AND domain_result NOT LIKE 'mx%.mail.protection.outlook.com'
			AND domain_result NOT LIKE '%.mail.protection.outlook.com'
			AND domain_result NOT LIKE '%.onmicrosoft.com'
			AND domain_result NOT LIKE '%.microsoftonline.com'
			AND domain_result NOT LIKE '%.azure.com'
			AND domain_result NOT LIKE '%.azurefd.net'
			AND domain_result NOT LIKE '%.azureedge.net'
			AND domain_result NOT LIKE '%.cloudapp.net'
			AND domain_result NOT LIKE '%.trafficmanager.net'
			AND domain_result NOT LIKE '%.core.windows.net'
			AND domain_result NOT LIKE '%.database.windows.net'
		)
		SELECT DISTINCT ON (fqdn)
			$1::uuid, 'fqdn', 
			fqdn,
			fqdn, root_domain, subdomain_part,
			registrar, creation_date, expiration_date, updated_date, name_servers, status,
			whois_info, ssl_certificate, ssl_expiry_date, ssl_issuer, ssl_subject, ssl_version,
			ssl_cipher_suite, ssl_protocols, resolved_ips, mail_servers, spf_record, dkim_record,
			dmarc_record, caa_records, txt_records, mx_records, ns_records, a_records,
			aaaa_records, cname_records, ptr_records, srv_records, soa_record,
			last_dns_scan, last_ssl_scan, last_whois_scan
		FROM enhanced_fqdn_sources
		WHERE fqdn IS NOT NULL
		AND fqdn NOT IN (
			SELECT DISTINCT asset_identifier 
			FROM consolidated_attack_surface_assets 
			WHERE scope_target_id = $1::uuid 
			AND asset_type = 'cloud_asset'
			AND asset_identifier IS NOT NULL
		)
		-- Filter out common infrastructure/cloud domains that are not company-specific
		AND fqdn NOT LIKE '%.awsdns-%'
		AND fqdn NOT LIKE 'ns-%.awsdns-%'
		AND fqdn NOT LIKE '%.googledns.com'
		AND fqdn NOT LIKE '%.googledomains.com'
		AND fqdn NOT LIKE '%.google.com'
		AND fqdn NOT LIKE 'ns%.google.com'
		AND fqdn NOT LIKE '%.outlook.com'
		AND fqdn NOT LIKE '%.live.com'
		AND fqdn NOT LIKE '%.hotmail.com'
		AND fqdn NOT LIKE 'mx%.mail.protection.outlook.com'
		AND fqdn NOT LIKE '%.mail.protection.outlook.com'
		AND fqdn NOT LIKE '%.onmicrosoft.com'
		AND fqdn NOT LIKE '%.microsoftonline.com'
		AND fqdn NOT LIKE '%.azure.com'
		AND fqdn NOT LIKE '%.azurefd.net'
		AND fqdn NOT LIKE '%.azureedge.net'
		AND fqdn NOT LIKE '%.cloudapp.net'
		AND fqdn NOT LIKE '%.trafficmanager.net'
		AND fqdn NOT LIKE '%.core.windows.net'
		AND fqdn NOT LIKE '%.database.windows.net'
		ORDER BY fqdn, 
			CASE 
				WHEN registrar IS NOT NULL THEN 1
				WHEN creation_date IS NOT NULL THEN 2
				WHEN last_dns_scan IS NOT NULL THEN 3
				ELSE 4
			END
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) DO UPDATE SET
			fqdn = EXCLUDED.fqdn,
			root_domain = EXCLUDED.root_domain,
			subdomain = EXCLUDED.subdomain,
			registrar = EXCLUDED.registrar,
			creation_date = EXCLUDED.creation_date,
			expiration_date = EXCLUDED.expiration_date,
			updated_date = EXCLUDED.updated_date,
			name_servers = EXCLUDED.name_servers,
			status = EXCLUDED.status,
			whois_info = EXCLUDED.whois_info,
			ssl_certificate = EXCLUDED.ssl_certificate,
			ssl_expiry_date = EXCLUDED.ssl_expiry_date,
			ssl_issuer = EXCLUDED.ssl_issuer,
			ssl_subject = EXCLUDED.ssl_subject,
			ssl_version = EXCLUDED.ssl_version,
			ssl_cipher_suite = EXCLUDED.ssl_cipher_suite,
			ssl_protocols = EXCLUDED.ssl_protocols,
			resolved_ips = EXCLUDED.resolved_ips,
			mail_servers = EXCLUDED.mail_servers,
			spf_record = EXCLUDED.spf_record,
			dkim_record = EXCLUDED.dkim_record,
			dmarc_record = EXCLUDED.dmarc_record,
			caa_records = EXCLUDED.caa_records,
			txt_records = EXCLUDED.txt_records,
			mx_records = EXCLUDED.mx_records,
			ns_records = EXCLUDED.ns_records,
			a_records = EXCLUDED.a_records,
			aaaa_records = EXCLUDED.aaaa_records,
			cname_records = EXCLUDED.cname_records,
			ptr_records = EXCLUDED.ptr_records,
			srv_records = EXCLUDED.srv_records,
			soa_record = EXCLUDED.soa_record,
			last_dns_scan = EXCLUDED.last_dns_scan,
			last_ssl_scan = EXCLUDED.last_ssl_scan,
			last_whois_scan = EXCLUDED.last_whois_scan,
			last_updated = NOW()
	`

	result, err := dbPool.Exec(context.Background(), consolidatedQuery, scopeTargetID)
	if err != nil {
		log.Printf("[FQDN CONSOLIDATION] Error inserting consolidated FQDNs: %v", err)
		return 0, err
	}

	insertedCount := int(result.RowsAffected())

	cloudFilteredQuery := `
		SELECT COUNT(DISTINCT asset_identifier) 
		FROM consolidated_attack_surface_assets 
		WHERE scope_target_id = $1::uuid 
		AND asset_type = 'cloud_asset'
		AND asset_identifier IS NOT NULL
	`
	var cloudAssetCount int
	err = dbPool.QueryRow(context.Background(), cloudFilteredQuery, scopeTargetID).Scan(&cloudAssetCount)
	if err != nil {
		log.Printf("[FQDN CONSOLIDATION] Error counting cloud assets: %v", err)
	} else {
		log.Printf("[FQDN CONSOLIDATION] Filtered out %d cloud asset domains from FQDN consolidation", cloudAssetCount)
	}

	log.Printf("[FQDN CONSOLIDATION] ✅ Successfully inserted/updated %d FQDN records", insertedCount)

	return insertedCount, nil
}

func createAssetRelationships(scopeTargetID string) (int, error) {
	totalRelationships := 0

	// Create relationships: IP addresses belong to network ranges
	ipToNetworkQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			nr.id, ip.id, 'contains'
		FROM consolidated_attack_surface_assets nr
		JOIN consolidated_attack_surface_assets ip ON nr.scope_target_id = ip.scope_target_id
		WHERE nr.scope_target_id = $1::uuid 
			AND nr.asset_type = 'network_range'
			AND ip.asset_type = 'ip_address'
			AND nr.cidr_block IS NOT NULL 
			AND ip.ip_address IS NOT NULL
			AND nr.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
			AND ip.ip_address ~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND ip.ip_address::inet <<= nr.cidr_block::cidr
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	ipToNetworkResult, err := dbPool.Exec(context.Background(), ipToNetworkQuery, scopeTargetID)
	if err != nil {
		return 0, err
	}
	totalRelationships += int(ipToNetworkResult.RowsAffected())

	// Create relationships: Network ranges belong to ASNs
	networkToASNQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			asn.id, nr.id, 'contains'
		FROM consolidated_attack_surface_assets asn
		JOIN consolidated_attack_surface_assets nr ON asn.scope_target_id = nr.scope_target_id
		JOIN consolidated_network_ranges cnr ON nr.cidr_block = cnr.cidr_block
		WHERE asn.scope_target_id = $1::uuid 
			AND asn.asset_type = 'asn'
			AND nr.asset_type = 'network_range'
			AND cnr.scope_target_id = $1::uuid
			AND cnr.asn IS NOT NULL
			AND asn.asn_number IS NOT NULL
			AND cnr.asn = asn.asn_number
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	networkToASNResult, err := dbPool.Exec(context.Background(), networkToASNQuery, scopeTargetID)
	if err != nil {
		return totalRelationships, err
	}
	totalRelationships += int(networkToASNResult.RowsAffected())

	// Create relationships: Live web servers to IP addresses
	liveWebServerToIPQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			lws.id, ip.id, 'hosted_on'
		FROM consolidated_attack_surface_assets lws
		JOIN consolidated_attack_surface_assets ip ON lws.scope_target_id = ip.scope_target_id
		WHERE lws.scope_target_id = $1::uuid 
			AND lws.asset_type = 'live_web_server'
			AND ip.asset_type = 'ip_address'
			AND lws.ip_address IS NOT NULL
			AND ip.ip_address IS NOT NULL
			AND lws.ip_address = ip.ip_address
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	liveWebServerToIPResult, err := dbPool.Exec(context.Background(), liveWebServerToIPQuery, scopeTargetID)
	if err != nil {
		return totalRelationships, err
	}
	totalRelationships += int(liveWebServerToIPResult.RowsAffected())

	return totalRelationships, nil
}

func createComprehensiveAssetRelationships(scopeTargetID string) (int, error) {
	log.Printf("[RELATIONSHIP MAPPING] Starting comprehensive relationship mapping for scope target: %s", scopeTargetID)
	totalRelationships := 0

	// Clear existing relationships first
	log.Printf("[RELATIONSHIP MAPPING] Clearing existing relationships...")
	clearQuery := `DELETE FROM consolidated_attack_surface_relationships 
		WHERE parent_asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid)
		OR child_asset_id IN (SELECT id FROM consolidated_attack_surface_assets WHERE scope_target_id = $1::uuid)`

	_, err := dbPool.Exec(context.Background(), clearQuery, scopeTargetID)
	if err != nil {
		return 0, fmt.Errorf("failed to clear existing relationships: %v", err)
	}

	// 1. Network Ranges -> ASNs
	log.Printf("[RELATIONSHIP MAPPING] Creating Network Range -> ASN relationships...")
	networkToASNQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			asn.id, nr.id, 'contains'
		FROM consolidated_attack_surface_assets asn
		JOIN consolidated_attack_surface_assets nr ON asn.scope_target_id = nr.scope_target_id
		WHERE asn.scope_target_id = $1::uuid 
			AND asn.asset_type = 'asn'
			AND nr.asset_type = 'network_range'
			AND asn.asn_number IS NOT NULL
			AND nr.asn_number IS NOT NULL
			AND asn.asn_number = nr.asn_number
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	networkToASNResult, err := dbPool.Exec(context.Background(), networkToASNQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating Network Range -> ASN relationships: %v", err)
		return totalRelationships, err
	}
	networkToASNCount := int(networkToASNResult.RowsAffected())
	totalRelationships += networkToASNCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d Network Range -> ASN relationships", networkToASNCount)

	// 2. IP Addresses -> Network Ranges
	log.Printf("[RELATIONSHIP MAPPING] Creating IP Address -> Network Range relationships...")
	ipToNetworkQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			nr.id, ip.id, 'contains'
		FROM consolidated_attack_surface_assets nr
		JOIN consolidated_attack_surface_assets ip ON nr.scope_target_id = ip.scope_target_id
		WHERE nr.scope_target_id = $1::uuid 
			AND nr.asset_type = 'network_range'
			AND ip.asset_type = 'ip_address'
			AND nr.cidr_block IS NOT NULL 
			AND ip.ip_address IS NOT NULL
			AND nr.cidr_block ~ '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
			AND ip.ip_address ~ '^(\d{1,3}\.){3}\d{1,3}$'
			AND ip.ip_address::inet <<= nr.cidr_block::cidr
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	ipToNetworkResult, err := dbPool.Exec(context.Background(), ipToNetworkQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating IP Address -> Network Range relationships: %v", err)
		return totalRelationships, err
	}
	ipToNetworkCount := int(ipToNetworkResult.RowsAffected())
	totalRelationships += ipToNetworkCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d IP Address -> Network Range relationships", ipToNetworkCount)

	// 3. FQDNs -> IP Addresses (via resolved IPs)
	log.Printf("[RELATIONSHIP MAPPING] Creating FQDN -> IP Address relationships...")
	fqdnToIPQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			fqdn.id, ip.id, 'resolves_to'
		FROM consolidated_attack_surface_assets fqdn
		JOIN consolidated_attack_surface_assets ip ON fqdn.scope_target_id = ip.scope_target_id
		WHERE fqdn.scope_target_id = $1::uuid 
			AND fqdn.asset_type = 'fqdn'
			AND ip.asset_type = 'ip_address'
			AND fqdn.resolved_ips IS NOT NULL
			AND ip.ip_address IS NOT NULL
			AND ip.ip_address = ANY(fqdn.resolved_ips)
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	fqdnToIPResult, err := dbPool.Exec(context.Background(), fqdnToIPQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating FQDN -> IP Address relationships: %v", err)
		return totalRelationships, err
	}
	fqdnToIPCount := int(fqdnToIPResult.RowsAffected())
	totalRelationships += fqdnToIPCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d FQDN -> IP Address relationships", fqdnToIPCount)

	// 4. Cloud Assets -> FQDNs (via domain matching)
	log.Printf("[RELATIONSHIP MAPPING] Creating Cloud Asset -> FQDN relationships...")
	cloudToFQDNQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			fqdn.id, cloud.id, 'cloud_service'
		FROM consolidated_attack_surface_assets fqdn
		JOIN consolidated_attack_surface_assets cloud ON fqdn.scope_target_id = cloud.scope_target_id
		WHERE fqdn.scope_target_id = $1::uuid 
			AND fqdn.asset_type = 'fqdn'
			AND cloud.asset_type = 'cloud_asset'
			AND fqdn.fqdn IS NOT NULL
			AND cloud.domain IS NOT NULL
			AND (
				cloud.domain LIKE '%' || fqdn.fqdn || '%'
				OR fqdn.fqdn LIKE '%' || cloud.domain || '%'
			)
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	cloudToFQDNResult, err := dbPool.Exec(context.Background(), cloudToFQDNQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating Cloud Asset -> FQDN relationships: %v", err)
		return totalRelationships, err
	}
	cloudToFQDNCount := int(cloudToFQDNResult.RowsAffected())
	totalRelationships += cloudToFQDNCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d Cloud Asset -> FQDN relationships", cloudToFQDNCount)

	// 5. Live Web Servers -> FQDNs (via domain matching)
	log.Printf("[RELATIONSHIP MAPPING] Creating Live Web Server -> FQDN relationships...")
	liveWebServerToFQDNQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			fqdn.id, lws.id, 'hosts'
		FROM consolidated_attack_surface_assets fqdn
		JOIN consolidated_attack_surface_assets lws ON fqdn.scope_target_id = lws.scope_target_id
		WHERE fqdn.scope_target_id = $1::uuid 
			AND fqdn.asset_type = 'fqdn'
			AND lws.asset_type = 'live_web_server'
			AND fqdn.fqdn IS NOT NULL
			AND lws.domain IS NOT NULL
			AND fqdn.fqdn = lws.domain
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	liveWebServerToFQDNResult, err := dbPool.Exec(context.Background(), liveWebServerToFQDNQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating Live Web Server -> FQDN relationships: %v", err)
		return totalRelationships, err
	}
	liveWebServerToFQDNCount := int(liveWebServerToFQDNResult.RowsAffected())
	totalRelationships += liveWebServerToFQDNCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d Live Web Server -> FQDN relationships", liveWebServerToFQDNCount)

	// 6. Live Web Servers -> IP Addresses (via IP matching)
	log.Printf("[RELATIONSHIP MAPPING] Creating Live Web Server -> IP Address relationships...")
	liveWebServerToIPQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			ip.id, lws.id, 'hosts'
		FROM consolidated_attack_surface_assets ip
		JOIN consolidated_attack_surface_assets lws ON ip.scope_target_id = lws.scope_target_id
		WHERE ip.scope_target_id = $1::uuid 
			AND ip.asset_type = 'ip_address'
			AND lws.asset_type = 'live_web_server'
			AND ip.ip_address IS NOT NULL
			AND lws.ip_address IS NOT NULL
			AND ip.ip_address = lws.ip_address
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	liveWebServerToIPResult, err := dbPool.Exec(context.Background(), liveWebServerToIPQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating Live Web Server -> IP Address relationships: %v", err)
		return totalRelationships, err
	}
	liveWebServerToIPCount := int(liveWebServerToIPResult.RowsAffected())
	totalRelationships += liveWebServerToIPCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d Live Web Server -> IP Address relationships", liveWebServerToIPCount)

	// 7. Live Web Servers -> Cloud Assets (via domain/URL matching)
	log.Printf("[RELATIONSHIP MAPPING] Creating Live Web Server -> Cloud Asset relationships...")
	liveWebServerToCloudQuery := `
		INSERT INTO consolidated_attack_surface_relationships (
			parent_asset_id, child_asset_id, relationship_type
		)
		SELECT DISTINCT 
			cloud.id, lws.id, 'cloud_hosted'
		FROM consolidated_attack_surface_assets cloud
		JOIN consolidated_attack_surface_assets lws ON cloud.scope_target_id = lws.scope_target_id
		WHERE cloud.scope_target_id = $1::uuid 
			AND cloud.asset_type = 'cloud_asset'
			AND lws.asset_type = 'live_web_server'
			AND cloud.domain IS NOT NULL
			AND lws.domain IS NOT NULL
			AND (
				lws.domain LIKE '%' || cloud.domain || '%'
				OR cloud.domain LIKE '%' || lws.domain || '%'
				OR (cloud.url IS NOT NULL AND lws.url IS NOT NULL AND cloud.url = lws.url)
			)
		ON CONFLICT (parent_asset_id, child_asset_id, relationship_type) DO NOTHING
	`

	liveWebServerToCloudResult, err := dbPool.Exec(context.Background(), liveWebServerToCloudQuery, scopeTargetID)
	if err != nil {
		log.Printf("[RELATIONSHIP MAPPING] Error creating Live Web Server -> Cloud Asset relationships: %v", err)
		return totalRelationships, err
	}
	liveWebServerToCloudCount := int(liveWebServerToCloudResult.RowsAffected())
	totalRelationships += liveWebServerToCloudCount
	log.Printf("[RELATIONSHIP MAPPING] Created %d Live Web Server -> Cloud Asset relationships", liveWebServerToCloudCount)

	// Log final summary
	log.Printf("[RELATIONSHIP MAPPING] ✅ RELATIONSHIP MAPPING COMPLETE!")
	log.Printf("[RELATIONSHIP MAPPING] Summary for scope target %s:", scopeTargetID)
	log.Printf("[RELATIONSHIP MAPPING]   • Network Range -> ASN: %d", networkToASNCount)
	log.Printf("[RELATIONSHIP MAPPING]   • IP Address -> Network Range: %d", ipToNetworkCount)
	log.Printf("[RELATIONSHIP MAPPING]   • FQDN -> IP Address: %d", fqdnToIPCount)
	log.Printf("[RELATIONSHIP MAPPING]   • Cloud Asset -> FQDN: %d", cloudToFQDNCount)
	log.Printf("[RELATIONSHIP MAPPING]   • Live Web Server -> FQDN: %d", liveWebServerToFQDNCount)
	log.Printf("[RELATIONSHIP MAPPING]   • Live Web Server -> IP Address: %d", liveWebServerToIPCount)
	log.Printf("[RELATIONSHIP MAPPING]   • Live Web Server -> Cloud Asset: %d", liveWebServerToCloudCount)
	log.Printf("[RELATIONSHIP MAPPING]   • Total Relationships: %d", totalRelationships)

	return totalRelationships, nil
}

func fetchConsolidatedAssets(scopeTargetID string) ([]AttackSurfaceAsset, error) {
	query := `
		SELECT 
			id, scope_target_id, asset_type, asset_identifier, 
			COALESCE(asset_subtype, '') as asset_subtype,
			COALESCE(asn_number, '') as asn_number, 
			COALESCE(asn_organization, '') as asn_organization, 
			COALESCE(asn_description, '') as asn_description, 
			COALESCE(asn_country, '') as asn_country,
			COALESCE(cidr_block, '') as cidr_block, 
			COALESCE(ip_address, '') as ip_address, 
			COALESCE(ip_type, '') as ip_type, 
			COALESCE(url, '') as url, 
			COALESCE(domain, '') as domain, 
			port, protocol,
			status_code, 
			COALESCE(title, '') as title, 
			COALESCE(web_server, '') as web_server, 
			COALESCE(technologies, ARRAY[]::text[]) as technologies, 
			content_length,
			response_time_ms, 
			COALESCE(screenshot_path, '') as screenshot_path, 
			ssl_info, http_response_headers,
			findings_json, 
			COALESCE(cloud_provider, '') as cloud_provider, 
			COALESCE(cloud_service_type, '') as cloud_service_type,
			COALESCE(cloud_region, '') as cloud_region, 
			COALESCE(fqdn, '') as fqdn, 
			COALESCE(root_domain, '') as root_domain, 
			COALESCE(subdomain, '') as subdomain, 
			COALESCE(registrar, '') as registrar, 
			creation_date,
			expiration_date, updated_date, 
			COALESCE(name_servers, ARRAY[]::text[]) as name_servers, 
			COALESCE(status, ARRAY[]::text[]) as status, 
			whois_info,
			ssl_certificate, ssl_expiry_date, 
			COALESCE(ssl_issuer, '') as ssl_issuer, 
			COALESCE(ssl_subject, '') as ssl_subject, 
			COALESCE(ssl_version, '') as ssl_version,
			COALESCE(ssl_cipher_suite, '') as ssl_cipher_suite, 
			COALESCE(ssl_protocols, ARRAY[]::text[]) as ssl_protocols, 
			COALESCE(resolved_ips, ARRAY[]::text[]) as resolved_ips, 
			COALESCE(mail_servers, ARRAY[]::text[]) as mail_servers, 
			COALESCE(spf_record, '') as spf_record,
			COALESCE(dkim_record, '') as dkim_record, 
			COALESCE(dmarc_record, '') as dmarc_record, 
			COALESCE(caa_records, ARRAY[]::text[]) as caa_records, 
			COALESCE(txt_records, ARRAY[]::text[]) as txt_records, 
			COALESCE(mx_records, ARRAY[]::text[]) as mx_records,
			COALESCE(ns_records, ARRAY[]::text[]) as ns_records, 
			COALESCE(a_records, ARRAY[]::text[]) as a_records, 
			COALESCE(aaaa_records, ARRAY[]::text[]) as aaaa_records, 
			COALESCE(cname_records, ARRAY[]::text[]) as cname_records, 
			COALESCE(ptr_records, ARRAY[]::text[]) as ptr_records,
			COALESCE(srv_records, ARRAY[]::text[]) as srv_records, 
			soa_record, last_dns_scan, last_ssl_scan, last_whois_scan,
			last_updated, created_at
		FROM consolidated_attack_surface_assets
		WHERE scope_target_id = $1::uuid
		ORDER BY asset_type, asset_identifier
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []AttackSurfaceAsset

	for rows.Next() {
		var asset AttackSurfaceAsset
		var technologies []string
		var sslInfo, httpHeaders, findings []byte
		var whoisInfo, sslCertificate, soaRecord []byte

		// Variables for nullable fields
		var assetSubtype, asnNumber, asnOrganization, asnDescription, asnCountry string
		var cidrBlock, ipAddress, ipType, url, domain, title, webServer, screenshotPath string
		var cloudProvider, cloudServiceType, cloudRegion, fqdn, rootDomain, subdomain, registrar string
		var sslIssuer, sslSubject, sslVersion, sslCipherSuite, spfRecord, dkimRecord, dmarcRecord string
		var nameServers, status, sslProtocols, resolvedIPs, mailServers []string
		var caaRecords, txtRecords, mxRecords, nsRecords, aRecords, aaaaRecords []string
		var cnameRecords, ptrRecords, srvRecords []string

		err := rows.Scan(
			&asset.ID, &asset.ScopeTargetID, &asset.AssetType, &asset.AssetIdentifier, &assetSubtype,
			&asnNumber, &asnOrganization, &asnDescription, &asnCountry,
			&cidrBlock, &ipAddress, &ipType, &url, &domain, &asset.Port, &asset.Protocol,
			&asset.StatusCode, &title, &webServer, &technologies, &asset.ContentLength,
			&asset.ResponseTime, &screenshotPath, &sslInfo, &httpHeaders,
			&findings, &cloudProvider, &cloudServiceType,
			&cloudRegion, &fqdn, &rootDomain, &subdomain, &registrar, &asset.CreationDate,
			&asset.ExpirationDate, &asset.UpdatedDate, &nameServers, &status, &whoisInfo,
			&sslCertificate, &asset.SSLExpiryDate, &sslIssuer, &sslSubject, &sslVersion,
			&sslCipherSuite, &sslProtocols, &resolvedIPs, &mailServers, &spfRecord,
			&dkimRecord, &dmarcRecord, &caaRecords, &txtRecords, &mxRecords,
			&nsRecords, &aRecords, &aaaaRecords, &cnameRecords, &ptrRecords,
			&srvRecords, &soaRecord, &asset.LastDNSScan, &asset.LastSSLScan, &asset.LastWhoisScan,
			&asset.LastUpdated, &asset.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Assign nullable fields to pointers (only if not empty)
		if assetSubtype != "" {
			asset.AssetSubtype = &assetSubtype
		}
		if asnNumber != "" {
			asset.ASNNumber = &asnNumber
		}
		if asnOrganization != "" {
			asset.ASNOrganization = &asnOrganization
		}
		if asnDescription != "" {
			asset.ASNDescription = &asnDescription
		}
		if asnCountry != "" {
			asset.ASNCountry = &asnCountry
		}
		if cidrBlock != "" {
			asset.CIDRBlock = &cidrBlock
		}
		if ipAddress != "" {
			asset.IPAddress = &ipAddress
		}
		if ipType != "" {
			asset.IPType = &ipType
		}
		if url != "" {
			asset.URL = &url
		}
		if domain != "" {
			asset.Domain = &domain
		}
		if title != "" {
			asset.Title = &title
		}
		if webServer != "" {
			asset.WebServer = &webServer
		}
		if screenshotPath != "" {
			asset.ScreenshotPath = &screenshotPath
		}
		if cloudProvider != "" {
			asset.CloudProvider = &cloudProvider
		}
		if cloudServiceType != "" {
			asset.CloudServiceType = &cloudServiceType
		}
		if cloudRegion != "" {
			asset.CloudRegion = &cloudRegion
		}
		if fqdn != "" {
			asset.FQDN = &fqdn
		}
		if rootDomain != "" {
			asset.RootDomain = &rootDomain
		}
		if subdomain != "" {
			asset.Subdomain = &subdomain
		}
		if registrar != "" {
			asset.Registrar = &registrar
		}
		if sslIssuer != "" {
			asset.SSLIssuer = &sslIssuer
		}
		if sslSubject != "" {
			asset.SSLSubject = &sslSubject
		}
		if sslVersion != "" {
			asset.SSLVersion = &sslVersion
		}
		if sslCipherSuite != "" {
			asset.SSLCipherSuite = &sslCipherSuite
		}
		if spfRecord != "" {
			asset.SPFRecord = &spfRecord
		}
		if dkimRecord != "" {
			asset.DKIMRecord = &dkimRecord
		}
		if dmarcRecord != "" {
			asset.DMARCRecord = &dmarcRecord
		}

		// Assign arrays
		asset.Technologies = technologies
		asset.NameServers = nameServers
		asset.Status = status
		asset.SSLProtocols = sslProtocols
		asset.ResolvedIPs = resolvedIPs
		asset.MailServers = mailServers
		asset.CAARecords = caaRecords
		asset.TXTRecords = txtRecords
		asset.MXRecords = mxRecords
		asset.NSRecords = nsRecords
		asset.ARecords = aRecords
		asset.AAAARecords = aaaaRecords
		asset.CNAMERecords = cnameRecords
		asset.PTRRecords = ptrRecords
		asset.SRVRecords = srvRecords

		if len(sslInfo) > 0 {
			json.Unmarshal(sslInfo, &asset.SSLInfo)
		}
		if len(httpHeaders) > 0 {
			json.Unmarshal(httpHeaders, &asset.HTTPResponseHeaders)
		}
		if len(findings) > 0 {
			json.Unmarshal(findings, &asset.FindingsJSON)
		}
		if len(whoisInfo) > 0 {
			json.Unmarshal(whoisInfo, &asset.WhoisInfo)
		}
		if len(sslCertificate) > 0 {
			json.Unmarshal(sslCertificate, &asset.SSLCertificate)
		}
		if len(soaRecord) > 0 {
			json.Unmarshal(soaRecord, &asset.SOARecord)
		}

		assets = append(assets, asset)
	}

	return assets, nil
}

func fetchAssetRelationships(assetID string) ([]AssetRelationship, error) {
	query := `
		SELECT 
			id, parent_asset_id, child_asset_id, relationship_type, 
			relationship_data, created_at
		FROM consolidated_attack_surface_relationships
		WHERE parent_asset_id = $1::uuid OR child_asset_id = $1::uuid
		ORDER BY relationship_type
	`

	rows, err := dbPool.Query(context.Background(), query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var relationships []AssetRelationship

	for rows.Next() {
		var rel AssetRelationship
		var relationshipData []byte

		err := rows.Scan(
			&rel.ID, &rel.ParentAssetID, &rel.ChildAssetID, &rel.RelationshipType,
			&relationshipData, &rel.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if len(relationshipData) > 0 {
			json.Unmarshal(relationshipData, &rel.RelationshipData)
		}

		relationships = append(relationships, rel)
	}

	return relationships, nil
}

func GetAttackSurfaceAssets(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	assets, err := fetchConsolidatedAssets(scopeTargetID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching attack surface assets: %v", err), http.StatusInternalServerError)
		return
	}

	for i := range assets {
		relationships, err := fetchAssetRelationships(assets[i].ID)
		if err != nil {
			log.Printf("Error fetching relationships for asset %s: %v", assets[i].ID, err)
			continue
		}
		assets[i].Relationships = relationships
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"assets": assets,
		"total":  len(assets),
	})
}

func enrichFQDNsWithInvestigateData(scopeTargetID string) (int, error) {
	log.Printf("[FQDN ENRICHMENT] Starting FQDN enrichment with investigate data for scope target: %s", scopeTargetID)
	startTime := time.Now()

	// Get all consolidated FQDNs for this scope target (excluding infrastructure domains)
	query := `
		SELECT id, fqdn 
		FROM consolidated_attack_surface_assets 
		WHERE scope_target_id = $1 
		AND asset_type = 'fqdn' 
		AND fqdn IS NOT NULL
		-- Filter out infrastructure/cloud domains from enrichment
		AND fqdn NOT LIKE '%.awsdns-%'
		AND fqdn NOT LIKE 'ns-%.awsdns-%'
		AND fqdn NOT LIKE '%.googledns.com'
		AND fqdn NOT LIKE '%.googledomains.com'
		AND fqdn NOT LIKE '%.google.com'
		AND fqdn NOT LIKE 'ns%.google.com'
		AND fqdn NOT LIKE '%.outlook.com'
		AND fqdn NOT LIKE '%.live.com'
		AND fqdn NOT LIKE '%.hotmail.com'
		AND fqdn NOT LIKE 'mx%.mail.protection.outlook.com'
		AND fqdn NOT LIKE '%.mail.protection.outlook.com'
		AND fqdn NOT LIKE '%.onmicrosoft.com'
		AND fqdn NOT LIKE '%.microsoftonline.com'
		AND fqdn NOT LIKE '%.azure.com'
		AND fqdn NOT LIKE '%.azurefd.net'
		AND fqdn NOT LIKE '%.azureedge.net'
		AND fqdn NOT LIKE '%.cloudapp.net'
		AND fqdn NOT LIKE '%.trafficmanager.net'
		AND fqdn NOT LIKE '%.core.windows.net'
		AND fqdn NOT LIKE '%.database.windows.net'
		ORDER BY fqdn
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[FQDN ENRICHMENT] Error querying FQDNs: %v", err)
		return 0, err
	}
	defer rows.Close()

	var fqdnsToEnrich []struct {
		ID   string
		FQDN string
	}

	for rows.Next() {
		var fqdn struct {
			ID   string
			FQDN string
		}
		if err := rows.Scan(&fqdn.ID, &fqdn.FQDN); err != nil {
			log.Printf("[FQDN ENRICHMENT] Error scanning FQDN: %v", err)
			continue
		}
		fqdnsToEnrich = append(fqdnsToEnrich, fqdn)
	}

	if len(fqdnsToEnrich) == 0 {
		log.Printf("[FQDN ENRICHMENT] No FQDNs found for enrichment")
		return 0, nil
	}

	log.Printf("[FQDN ENRICHMENT] Found %d FQDNs to enrich", len(fqdnsToEnrich))

	// Get company name for HTTP info matching
	var companyName string
	err = dbPool.QueryRow(context.Background(), `
		SELECT scope_target FROM scope_targets 
		WHERE id = $1`, scopeTargetID).Scan(&companyName)
	if err != nil {
		log.Printf("[FQDN ENRICHMENT] Failed to get company name: %v", err)
		companyName = ""
	}

	enrichedCount := 0

	// Process each FQDN with optimized timeouts (5-7s per operation)
	for i, fqdn := range fqdnsToEnrich {
		log.Printf("[FQDN ENRICHMENT] Processing domain %d/%d: %s", i+1, len(fqdnsToEnrich), fqdn.FQDN)

		// Get enriched data
		var resolvedIPs []string
		var sslInfo map[string]interface{}
		var asnNumber, asnOrganization string
		var sslExpiryDate *time.Time
		var sslIssuer, sslSubject, sslVersion string
		var sslCipherSuite *string
		var sslProtocols []string
		var statusCode *int
		var title, webServer string
		var lastSSLScan, lastDNSScan time.Time
		var dnsRecordData map[string]interface{}

		// Get comprehensive DNS information (fast version with 5s timeout)
		if ips, dnsInfo := getDNSInfoFast(fqdn.FQDN); len(ips) > 0 || len(dnsInfo) > 0 {
			resolvedIPs = ips
			dnsRecordData = dnsInfo
			lastDNSScan = time.Now()
		}

		// Get SSL information (optimized version with 5s timeout)
		if sslInfoFast := getSSLInfoFast(fqdn.FQDN); sslInfoFast != nil {
			lastSSLScan = time.Now()
			sslInfo = sslInfoFast

			if expDate, ok := sslInfoFast["expiration"].(time.Time); ok {
				sslExpiryDate = &expDate
			}
			if issuer, ok := sslInfoFast["issuer"].(string); ok {
				sslIssuer = issuer
			}
			if domain, ok := sslInfoFast["domain"].(string); ok {
				sslSubject = domain
			}
			sslVersion = "TLS"
		}

		// Get ASN information (optimized version with 5s timeout)
		if asn, org := getASNInfoFast(fqdn.FQDN); asn != "" {
			asnNumber = asn
			asnOrganization = org
		}

		// Get HTTP information (optimized version with 7s timeout)
		if status, titleStr, server := getHTTPInfoFast(fqdn.FQDN); status > 0 {
			statusCode = &status
			title = titleStr
			webServer = server
		}

		if lastDNSScan.IsZero() {
			lastDNSScan = time.Now()
		}

		// Extract DNS record fields from the DNS data
		var aRecords, aaaaRecords, cnameRecords, mxRecords, txtRecords, nsRecords []string
		var spfRecord, dmarcRecord, dkimRecord string
		var mailServers, nameServers []string

		if dnsRecordData != nil {
			if records, ok := dnsRecordData["a_records"].([]string); ok {
				aRecords = records
			}
			if records, ok := dnsRecordData["aaaa_records"].([]string); ok {
				aaaaRecords = records
			}
			if records, ok := dnsRecordData["cname_records"].([]string); ok {
				cnameRecords = records
			}
			if records, ok := dnsRecordData["mx_records"].([]string); ok {
				mxRecords = records
			}
			if records, ok := dnsRecordData["txt_records"].([]string); ok {
				txtRecords = records
			}
			if records, ok := dnsRecordData["ns_records"].([]string); ok {
				nsRecords = records
			}
			if record, ok := dnsRecordData["spf_record"].(string); ok {
				spfRecord = record
			}
			if record, ok := dnsRecordData["dmarc_record"].(string); ok {
				dmarcRecord = record
			}
			if record, ok := dnsRecordData["dkim_record"].(string); ok {
				dkimRecord = record
			}
			if servers, ok := dnsRecordData["mail_servers"].([]string); ok {
				mailServers = servers
			}
			if servers, ok := dnsRecordData["name_servers"].([]string); ok {
				nameServers = servers
			}
		}

		// Update the database record with enriched data
		updateQuery := `
			UPDATE consolidated_attack_surface_assets 
			SET 
				resolved_ips = $2,
				ssl_info = $3,
				asn_number = $4,
				asn_organization = $5,
				ssl_expiry_date = $6,
				ssl_issuer = $7,
				ssl_subject = $8,
				ssl_version = $9,
				ssl_cipher_suite = $10,
				ssl_protocols = $11,
				status_code = $12,
				title = $13,
				web_server = $14,
				a_records = $15,
				aaaa_records = $16,
				cname_records = $17,
				mx_records = $18,
				txt_records = $19,
				ns_records = $20,
				spf_record = $21,
				dmarc_record = $22,
				dkim_record = $23,
				mail_servers = $24,
				name_servers = $25,
				last_ssl_scan = $26,
				last_dns_scan = $27,
				last_updated = NOW()
			WHERE id = $1
		`

		// Convert arrays to PostgreSQL arrays
		resolvedIPsArray := "{" + strings.Join(resolvedIPs, ",") + "}"
		sslProtocolsArray := "{" + strings.Join(sslProtocols, ",") + "}"
		aRecordsArray := "{" + strings.Join(aRecords, ",") + "}"
		aaaaRecordsArray := "{" + strings.Join(aaaaRecords, ",") + "}"
		cnameRecordsArray := "{" + strings.Join(cnameRecords, ",") + "}"
		mxRecordsArray := "{" + strings.Join(mxRecords, ",") + "}"
		txtRecordsArray := "{" + strings.Join(txtRecords, ",") + "}"
		nsRecordsArray := "{" + strings.Join(nsRecords, ",") + "}"
		mailServersArray := "{" + strings.Join(mailServers, ",") + "}"
		nameServersArray := "{" + strings.Join(nameServers, ",") + "}"

		var sslInfoJSON []byte
		if sslInfo != nil {
			sslInfoJSON, _ = json.Marshal(sslInfo)
		}

		_, err = dbPool.Exec(context.Background(), updateQuery,
			fqdn.ID,
			resolvedIPsArray,
			sslInfoJSON,
			asnNumber,
			asnOrganization,
			sslExpiryDate,
			sslIssuer,
			sslSubject,
			sslVersion,
			sslCipherSuite,
			sslProtocolsArray,
			statusCode,
			title,
			webServer,
			aRecordsArray,
			aaaaRecordsArray,
			cnameRecordsArray,
			mxRecordsArray,
			txtRecordsArray,
			nsRecordsArray,
			spfRecord,
			dmarcRecord,
			dkimRecord,
			mailServersArray,
			nameServersArray,
			lastSSLScan,
			lastDNSScan,
		)

		if err != nil {
			log.Printf("[FQDN ENRICHMENT] Error updating FQDN %s: %v", fqdn.FQDN, err)
			continue
		}

		enrichedCount++
		log.Printf("[FQDN ENRICHMENT] ✓ Successfully enriched domain %d/%d: %s", i+1, len(fqdnsToEnrich), fqdn.FQDN)
	}

	duration := time.Since(startTime)
	log.Printf("[FQDN ENRICHMENT] ✅ Successfully enriched %d FQDNs out of %d in %v (avg: %v per domain)",
		enrichedCount, len(fqdnsToEnrich), duration, duration/time.Duration(len(fqdnsToEnrich)))
	return enrichedCount, nil
}

// Optimized enrichment functions with reasonable timeouts for attack surface consolidation

func getSSLInfoFast(domain string) map[string]interface{} {
	// Skip obviously non-SSL domains to save time
	if strings.Contains(domain, "_") || strings.HasPrefix(domain, "*.") {
		return nil
	}

	// 2 second timeout for SSL connections (faster)
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	isExpired := time.Now().After(cert.NotAfter)
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	// Check for domain mismatch
	isMismatched := true
	for _, name := range cert.DNSNames {
		if name == domain || (strings.HasPrefix(name, "*.") && strings.HasSuffix(domain, name[1:])) {
			isMismatched = false
			break
		}
	}

	return map[string]interface{}{
		"domain":         domain,
		"issuer":         cert.Issuer.String(),
		"expiration":     cert.NotAfter,
		"is_expired":     isExpired,
		"is_self_signed": isSelfSigned,
		"is_mismatched":  isMismatched,
	}
}

func getASNInfoFast(domain string) (string, string) {
	// 2 second timeout for DNS resolution
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return "", ""
	}

	ip := ips[0].IP.String()

	// 2 second timeout for HTTP client
	client := &http.Client{Timeout: 2 * time.Second}

	// Try ipapi.co first (faster and more reliable)
	resp, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var result struct {
			ASN string `json:"asn"`
			Org string `json:"org"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Org != "" {
			return result.ASN, result.Org
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	return "", ""
}

func getHTTPInfoFast(domain string) (int, string, string) {
	// Skip obviously non-HTTP domains to save time
	if strings.Contains(domain, "_") || strings.HasPrefix(domain, "*.") {
		return 0, "", ""
	}

	// 3 second timeout for HTTP requests (faster)
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects to save time
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first, then HTTP
	urls := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("http://%s", domain),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Extract title quickly (read only first 1KB)
		title := ""
		if resp.Header.Get("Content-Type") != "" && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			content := string(buf[:n])

			if start := strings.Index(strings.ToLower(content), "<title>"); start != -1 {
				start += 7
				if end := strings.Index(strings.ToLower(content[start:]), "</title>"); end != -1 {
					title = strings.TrimSpace(content[start : start+end])
				}
			}
		}

		server := resp.Header.Get("Server")
		return resp.StatusCode, title, server
	}

	return 0, "", ""
}

func getDNSInfoFast(domain string) ([]string, map[string]interface{}) {
	// 2 second timeout for DNS lookups
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	var resolvedIPs []string
	dnsInfo := make(map[string]interface{})

	// A Records (IPv4) and AAAA Records (IPv6)
	if ips, err := resolver.LookupIPAddr(ctx, domain); err == nil {
		var aRecords, aaaaRecords []string
		for _, ip := range ips {
			ipStr := ip.IP.String()
			resolvedIPs = append(resolvedIPs, ipStr)
			if ip.IP.To4() != nil {
				aRecords = append(aRecords, ipStr)
			} else {
				aaaaRecords = append(aaaaRecords, ipStr)
			}
		}
		if len(aRecords) > 0 {
			dnsInfo["a_records"] = aRecords
		}
		if len(aaaaRecords) > 0 {
			dnsInfo["aaaa_records"] = aaaaRecords
		}
	}

	// CNAME Records
	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		dnsInfo["cname_records"] = []string{strings.TrimSuffix(cname, ".")}
	}

	// MX Records
	if mxRecords, err := resolver.LookupMX(ctx, domain); err == nil && len(mxRecords) > 0 {
		var mxHosts []string
		for _, mx := range mxRecords {
			mxHosts = append(mxHosts, strings.TrimSuffix(mx.Host, "."))
		}
		dnsInfo["mx_records"] = mxHosts
		dnsInfo["mail_servers"] = mxHosts // Also populate mail_servers field
	}

	// TXT Records
	if txtRecords, err := resolver.LookupTXT(ctx, domain); err == nil && len(txtRecords) > 0 {
		dnsInfo["txt_records"] = txtRecords

		// Extract specific TXT record types
		for _, txt := range txtRecords {
			lower := strings.ToLower(txt)
			if strings.HasPrefix(lower, "v=spf1") {
				dnsInfo["spf_record"] = txt
			} else if strings.HasPrefix(lower, "v=dmarc1") {
				dnsInfo["dmarc_record"] = txt
			} else if strings.Contains(lower, "dkim") {
				dnsInfo["dkim_record"] = txt
			}
		}
	}

	// NS Records
	if nsRecords, err := resolver.LookupNS(ctx, domain); err == nil && len(nsRecords) > 0 {
		var nsHosts []string
		for _, ns := range nsRecords {
			nsHosts = append(nsHosts, strings.TrimSuffix(ns.Host, "."))
		}
		dnsInfo["ns_records"] = nsHosts
		dnsInfo["name_servers"] = nsHosts // Also populate name_servers field
	}

	return resolvedIPs, dnsInfo
}
