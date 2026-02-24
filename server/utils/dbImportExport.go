package utils

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DatabaseExportRequest struct {
	ScopeTargetIDs []string `json:"scope_target_ids"`
}

type DatabaseImportRequest struct {
	Data []byte `json:"data"`
}

type DatabaseImportURLRequest struct {
	URL string `json:"url"`
}

type ExportData struct {
	ExportMetadata ExportMetadata                      `json:"export_metadata"`
	ScopeTargets   []map[string]interface{}            `json:"scope_targets"`
	TableData      map[string][]map[string]interface{} `json:"table_data"`
}

type ExportMetadata struct {
	ExportedAt     time.Time `json:"exported_at"`
	Version        string    `json:"version"`
	ScopeTargetIDs []string  `json:"scope_target_ids"`
	ScopeTargets   []string  `json:"scope_targets"`
	TotalRecords   int       `json:"total_records"`
	TablesExported []string  `json:"tables_exported"`
}

var exportTableQueries = map[string]string{
	"auto_scan_sessions": `
		SELECT id, scope_target_id, config_snapshot, status, started_at, ended_at, 
		       steps_run, error_message, final_consolidated_subdomains, final_live_web_servers
		FROM auto_scan_sessions 
		WHERE scope_target_id = ANY($1)`,

	"auto_scan_state": `
		SELECT id, scope_target_id, current_step, is_paused, is_cancelled, created_at, updated_at
		FROM auto_scan_state 
		WHERE scope_target_id = ANY($1)`,

	"amass_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, 
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM amass_scans 
		WHERE scope_target_id = ANY($1)`,

	"amass_intel_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM amass_intel_scans 
		WHERE scope_target_id = ANY($1)`,

	"amass_enum_company_scans": `
		SELECT id, scan_id, scope_target_id, domains, status, result, error, stdout, stderr,
		       command, execution_time, created_at
		FROM amass_enum_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"httpx_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM httpx_scans 
		WHERE scope_target_id = ANY($1)`,

	"gau_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM gau_scans 
		WHERE scope_target_id = ANY($1)`,

	"sublist3r_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM sublist3r_scans 
		WHERE scope_target_id = ANY($1)`,

	"assetfinder_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM assetfinder_scans 
		WHERE scope_target_id = ANY($1)`,

	"ctl_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM ctl_scans 
		WHERE scope_target_id = ANY($1)`,

	"subfinder_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM subfinder_scans 
		WHERE scope_target_id = ANY($1)`,

	"shuffledns_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM shuffledns_scans 
		WHERE scope_target_id = ANY($1)`,

	"cewl_scans": `
		SELECT id, scan_id, url, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM cewl_scans 
		WHERE scope_target_id = ANY($1)`,

	"gospider_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM gospider_scans 
		WHERE scope_target_id = ANY($1)`,

	"subdomainizer_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM subdomainizer_scans 
		WHERE scope_target_id = ANY($1)`,

	"nuclei_screenshots": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM nuclei_screenshots 
		WHERE scope_target_id = ANY($1)`,

	"metadata_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM metadata_scans 
		WHERE scope_target_id = ANY($1)`,

	"target_urls": `
		SELECT id, url, screenshot, status_code, title, web_server, technologies, content_length,
		       newly_discovered, no_longer_live, scope_target_id, created_at, updated_at,
		       has_deprecated_tls, has_expired_ssl, has_mismatched_ssl, has_revoked_ssl,
		       has_self_signed_ssl, has_untrusted_root_ssl, has_wildcard_tls, findings_json,
		       http_response, http_response_headers, dns_a_records, dns_aaaa_records,
		       dns_cname_records, dns_mx_records, dns_txt_records, dns_ns_records,
		       dns_ptr_records, dns_srv_records, katana_results, ffuf_results, roi_score, ip_address
		FROM target_urls 
		WHERE scope_target_id = ANY($1)`,

	"consolidated_subdomains": `
		SELECT id, scope_target_id, subdomain, created_at
		FROM consolidated_subdomains 
		WHERE scope_target_id = ANY($1)`,

	"consolidated_company_domains": `
		SELECT id, scope_target_id, domain, source, created_at
		FROM consolidated_company_domains 
		WHERE scope_target_id = ANY($1)`,

	"consolidated_network_ranges": `
		SELECT id, scope_target_id, cidr_block, asn, organization, description, country, source, scan_type, created_at
		FROM consolidated_network_ranges 
		WHERE scope_target_id = ANY($1)`,

	"google_dorking_domains": `
		SELECT id, scope_target_id, domain, created_at
		FROM google_dorking_domains 
		WHERE scope_target_id = ANY($1)`,

	"reverse_whois_domains": `
		SELECT id, scope_target_id, domain, created_at
		FROM reverse_whois_domains 
		WHERE scope_target_id = ANY($1)`,

	"consolidated_attack_surface_assets": `
		SELECT id, scope_target_id, asset_type, asset_identifier, asset_subtype, asn_number,
		       asn_organization, asn_description, asn_country, cidr_block, subnet_size,
		       responsive_ip_count, responsive_port_count, ip_address, ip_type, dnsx_a_records,
		       amass_a_records, httpx_sources, url, domain, port, protocol, status_code, title,
		       web_server, technologies, content_length, response_time_ms, screenshot_path,
		       ssl_info, http_response_headers, findings_json, cloud_provider, cloud_service_type,
		       cloud_region, fqdn, root_domain, subdomain, registrar, creation_date, expiration_date,
		       updated_date, name_servers, status, whois_info, ssl_certificate, ssl_expiry_date,
		       ssl_issuer, ssl_subject, ssl_version, ssl_cipher_suite, ssl_protocols, resolved_ips,
		       mail_servers, spf_record, dkim_record, dmarc_record, caa_records, txt_records,
		       mx_records, ns_records, a_records, aaaa_records, cname_records, ptr_records,
		       srv_records, soa_record, last_dns_scan, last_ssl_scan, last_whois_scan,
		       last_updated, created_at
		FROM consolidated_attack_surface_assets 
		WHERE scope_target_id = ANY($1)`,

	"nuclei_scans": `
		SELECT id, scan_id, scope_target_id, targets, templates, status, result, error, stdout, stderr,
		       command, execution_time, created_at, updated_at, auto_scan_session_id
		FROM nuclei_scans 
		WHERE scope_target_id = ANY($1)`,

	"ip_port_scans": `
		SELECT id, scan_id, scope_target_id, status, total_network_ranges, processed_network_ranges,
		       total_ips_discovered, total_ports_scanned, live_web_servers_found, error_message,
		       command, execution_time, created_at, auto_scan_session_id
		FROM ip_port_scans 
		WHERE scope_target_id = ANY($1)`,

	// Missing Company scanning tools
	"cloud_enum_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM cloud_enum_scans 
		WHERE scope_target_id = ANY($1)`,

	"metabigor_company_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM metabigor_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"katana_company_scans": `
		SELECT id, scan_id, scope_target_id, domains, status, result, error, stdout, stderr,
		       command, execution_time, created_at, auto_scan_session_id
		FROM katana_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"dnsx_company_scans": `
		SELECT id, scan_id, scope_target_id, domains, status, result, error, stdout, stderr,
		       command, execution_time, created_at
		FROM dnsx_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"securitytrails_company_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM securitytrails_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"github_recon_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM github_recon_scans 
		WHERE scope_target_id = ANY($1)`,

	"shodan_company_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM shodan_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"censys_company_scans": `
		SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM censys_company_scans 
		WHERE scope_target_id = ANY($1)`,

	"company_metadata_scans": `
		SELECT id, scan_id, scope_target_id, ip_port_scan_id, status, error_message,
		       execution_time, created_at, updated_at
		FROM company_metadata_scans 
		WHERE scope_target_id = ANY($1)`,

	"investigate_scans": `
		SELECT id, scan_id, scope_target_id, status, result, error, stdout, stderr,
		       command, execution_time, created_at
		FROM investigate_scans 
		WHERE scope_target_id = ANY($1)`,

	"shufflednscustom_scans": `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command,
		       execution_time, created_at, scope_target_id, auto_scan_session_id
		FROM shufflednscustom_scans 
		WHERE scope_target_id = ANY($1)`,

	// Child tables and relationship tables that need to be exported with their parent scans
	"discovered_live_ips": `
		SELECT dli.id, dli.scan_id, dli.ip_address, dli.hostname, dli.network_range, 
		       dli.ping_time_ms, dli.discovered_at
		FROM discovered_live_ips dli
		JOIN ip_port_scans ips ON dli.scan_id = ips.scan_id
		WHERE ips.scope_target_id = ANY($1)`,

	"live_web_servers": `
		SELECT lws.id, lws.scan_id, lws.ip_address, lws.hostname, lws.port, lws.protocol,
		       lws.url, lws.status_code, lws.title, lws.server_header, lws.content_length,
		       lws.technologies, lws.response_time_ms, lws.screenshot_path, lws.ssl_info,
		       lws.http_response_headers, lws.findings_json, lws.last_checked
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = ANY($1)`,

	"metabigor_network_ranges": `
		SELECT mnr.id, mnr.scan_id, mnr.cidr_block, mnr.asn, mnr.organization, 
		       mnr.country, mnr.scan_type, mnr.created_at
		FROM metabigor_network_ranges mnr
		JOIN metabigor_company_scans mcs ON mnr.scan_id = mcs.scan_id
		WHERE mcs.scope_target_id = ANY($1)`,

	"amass_enum_cloud_domains": `
		SELECT aecd.id, aecd.scan_id, aecd.domain, aecd.type, aecd.created_at
		FROM amass_enum_cloud_domains aecd
		JOIN amass_enum_company_scans aecs ON aecd.scan_id = aecs.scan_id
		WHERE aecs.scope_target_id = ANY($1)`,

	"amass_enum_dns_records": `
		SELECT aedr.id, aedr.scan_id, aedr.record, aedr.record_type, aedr.created_at
		FROM amass_enum_dns_records aedr
		JOIN amass_enum_company_scans aecs ON aedr.scan_id = aecs.scan_id
		WHERE aecs.scope_target_id = ANY($1)`,

	"amass_enum_raw_results": `
		SELECT aerr.id, aerr.scan_id, aerr.domain, aerr.raw_output, aerr.created_at
		FROM amass_enum_raw_results aerr
		JOIN amass_enum_company_scans aecs ON aerr.scan_id = aecs.scan_id
		WHERE aecs.scope_target_id = ANY($1)`,

	"dnsx_dns_records": `
		SELECT ddr.id, ddr.scan_id, ddr.domain, ddr.record, ddr.record_type, ddr.created_at
		FROM dnsx_dns_records ddr
		JOIN dnsx_company_scans dcs ON ddr.scan_id = dcs.scan_id
		WHERE dcs.scope_target_id = ANY($1)`,

	"dnsx_raw_results": `
		SELECT drr.id, drr.scan_id, drr.domain, drr.raw_output, drr.created_at
		FROM dnsx_raw_results drr
		JOIN dnsx_company_scans dcs ON drr.scan_id = dcs.scan_id
		WHERE dcs.scope_target_id = ANY($1)`,

	"katana_company_cloud_assets": `
		SELECT id, scope_target_id, root_domain, asset_domain, asset_url, asset_type,
		       service, description, source_url, region, last_scanned_at, created_at
		FROM katana_company_cloud_assets 
		WHERE scope_target_id = ANY($1)`,

	"dnsx_company_domain_results": `
		SELECT id, scope_target_id, domain, last_scanned_at, last_scan_id, raw_output,
		       created_at, updated_at
		FROM dnsx_company_domain_results 
		WHERE scope_target_id = ANY($1)`,

	"dnsx_company_dns_records": `
		SELECT id, scope_target_id, root_domain, record, record_type, last_scanned_at, created_at
		FROM dnsx_company_dns_records 
		WHERE scope_target_id = ANY($1)`,

	"amass_enum_company_domain_results": `
		SELECT id, scope_target_id, domain, last_scanned_at, last_scan_id, raw_output,
		       created_at, updated_at
		FROM amass_enum_company_domain_results 
		WHERE scope_target_id = ANY($1)`,

	"amass_enum_company_cloud_domains": `
		SELECT id, scope_target_id, root_domain, cloud_domain, type, last_scanned_at, created_at
		FROM amass_enum_company_cloud_domains 
		WHERE scope_target_id = ANY($1)`,

	"amass_enum_company_dns_records": `
		SELECT id, scope_target_id, root_domain, record, record_type, last_scanned_at, created_at
		FROM amass_enum_company_dns_records 
		WHERE scope_target_id = ANY($1)`,

	// Configuration tables
	"amass_enum_configs": `
		SELECT id, scope_target_id, selected_domains, include_wildcard_results, wildcard_domains,
		       created_at, updated_at
		FROM amass_enum_configs 
		WHERE scope_target_id = ANY($1)`,

	"amass_intel_configs": `
		SELECT id, scope_target_id, selected_network_ranges, created_at, updated_at
		FROM amass_intel_configs 
		WHERE scope_target_id = ANY($1)`,

	"dnsx_configs": `
		SELECT id, scope_target_id, selected_domains, include_wildcard_results, wildcard_domains,
		       created_at, updated_at
		FROM dnsx_configs 
		WHERE scope_target_id = ANY($1)`,

	"katana_company_configs": `
		SELECT id, scope_target_id, selected_domains, include_wildcard_results, selected_wildcard_domains,
		       selected_live_web_servers, created_at, updated_at
		FROM katana_company_configs 
		WHERE scope_target_id = ANY($1)`,

	"cloud_enum_configs": `
		SELECT id, scope_target_id, keywords, threads, enabled_platforms, custom_dns_server,
		       dns_resolver_mode, resolver_config, additional_resolvers, mutations_file_path,
		       brute_file_path, resolver_file_path, selected_services, selected_regions,
		       created_at, updated_at
		FROM cloud_enum_configs 
		WHERE scope_target_id = ANY($1)`,

	"nuclei_configs": `
		SELECT id, scope_target_id, targets, templates, severities, uploaded_templates, created_at
		FROM nuclei_configs 
		WHERE scope_target_id = ANY($1)`,

	// Basic scan data tables (dns_records, ips, subdomains, etc. are linked to scans by scan_id)
	"dns_records": `
		SELECT dr.id, dr.scan_id, dr.record, dr.record_type, dr.created_at
		FROM dns_records dr
		JOIN amass_scans a ON dr.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"ips": `
		SELECT i.id, i.scan_id, i.ip_address, i.created_at
		FROM ips i
		JOIN amass_scans a ON i.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"subdomains": `
		SELECT s.id, s.scan_id, s.subdomain, s.created_at
		FROM subdomains s
		JOIN amass_scans a ON s.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"cloud_domains": `
		SELECT cd.id, cd.scan_id, cd.domain, cd.type, cd.created_at
		FROM cloud_domains cd
		JOIN amass_scans a ON cd.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"asns": `
		SELECT asn.id, asn.scan_id, asn.number, asn.raw_data, asn.created_at
		FROM asns asn
		JOIN amass_scans a ON asn.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"subnets": `
		SELECT sub.id, sub.scan_id, sub.cidr, sub.raw_data, sub.created_at
		FROM subnets sub
		JOIN amass_scans a ON sub.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"service_providers": `
		SELECT sp.id, sp.scan_id, sp.provider, sp.raw_data, sp.created_at
		FROM service_providers sp
		JOIN amass_scans a ON sp.scan_id = a.scan_id
		WHERE a.scope_target_id = ANY($1)`,

	"intel_network_ranges": `
		SELECT inr.id, inr.scan_id, inr.cidr_block, inr.asn, inr.organization, 
		       inr.description, inr.country, inr.created_at
		FROM intel_network_ranges inr
		JOIN amass_intel_scans ais ON inr.scan_id = ais.scan_id
		WHERE ais.scope_target_id = ANY($1)`,

	"intel_asn_data": `
		SELECT iad.id, iad.scan_id, iad.asn_number, iad.organization, 
		       iad.description, iad.country, iad.created_at
		FROM intel_asn_data iad
		JOIN amass_intel_scans ais ON iad.scan_id = ais.scan_id
		WHERE ais.scope_target_id = ANY($1)`,

	// Attack surface relationship tables
	"consolidated_attack_surface_relationships": `
		SELECT casr.id, casr.parent_asset_id, casr.child_asset_id, casr.relationship_type,
		       casr.relationship_data, casr.created_at
		FROM consolidated_attack_surface_relationships casr
		JOIN consolidated_attack_surface_assets casa_parent ON casr.parent_asset_id = casa_parent.id
		WHERE casa_parent.scope_target_id = ANY($1)`,

	"consolidated_attack_surface_dns_records": `
		SELECT casdr.id, casdr.asset_id, casdr.record_type, casdr.record_value, casdr.ttl, casdr.created_at
		FROM consolidated_attack_surface_dns_records casdr
		JOIN consolidated_attack_surface_assets casa ON casdr.asset_id = casa.id
		WHERE casa.scope_target_id = ANY($1)`,

	"consolidated_attack_surface_metadata": `
		SELECT casm.id, casm.asset_id, casm.metadata_type, casm.metadata_key, 
		       casm.metadata_value, casm.metadata_json, casm.created_at
		FROM consolidated_attack_surface_metadata casm
		JOIN consolidated_attack_surface_assets casa ON casm.asset_id = casa.id
		WHERE casa.scope_target_id = ANY($1)`,
}

func HandleDatabaseExport(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Starting database export process")

	var req DatabaseExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.ScopeTargetIDs) == 0 {
		http.Error(w, "No scope targets specified", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Database export request for %d scope targets", len(req.ScopeTargetIDs))

	exportData, err := exportDatabaseData(req.ScopeTargetIDs)
	if err != nil {
		log.Printf("[ERROR] Failed to export database data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to export data: %v", err), http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(exportData)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal export data: %v", err)
		http.Error(w, "Failed to marshal export data", http.StatusInternalServerError)
		return
	}

	var compressedData bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedData)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		log.Printf("[ERROR] Failed to compress data: %v", err)
		http.Error(w, "Failed to compress data", http.StatusInternalServerError)
		return
	}
	gzipWriter.Close()

	filename := fmt.Sprintf("rs0n-export-%s.rs0n", time.Now().Format("2006-01-02-15-04-05"))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", compressedData.Len()))

	if _, err := w.Write(compressedData.Bytes()); err != nil {
		log.Printf("[ERROR] Failed to write response: %v", err)
	}

	log.Printf("[INFO] Database export completed successfully. File: %s, Size: %d bytes", filename, compressedData.Len())
}

func HandleDatabaseImport(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Starting database import process")

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		log.Printf("[ERROR] Failed to parse multipart form: %v", err)
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("[ERROR] Failed to get file from form: %v", err)
		http.Error(w, "Failed to get uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !strings.HasSuffix(header.Filename, ".rs0n") {
		http.Error(w, "Invalid file type. Only .rs0n files are supported", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Processing import file: %s", header.Filename)

	compressedData, err := io.ReadAll(file)
	if err != nil {
		log.Printf("[ERROR] Failed to read file: %v", err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		log.Printf("[ERROR] Failed to create gzip reader: %v", err)
		http.Error(w, "Invalid file format", http.StatusBadRequest)
		return
	}
	defer gzipReader.Close()

	jsonData, err := io.ReadAll(gzipReader)
	if err != nil {
		log.Printf("[ERROR] Failed to decompress data: %v", err)
		http.Error(w, "Failed to decompress data", http.StatusInternalServerError)
		return
	}

	var exportData ExportData
	if err := json.Unmarshal(jsonData, &exportData); err != nil {
		log.Printf("[ERROR] Failed to unmarshal export data: %v", err)
		http.Error(w, "Invalid export data format", http.StatusBadRequest)
		return
	}

	if err := importDatabaseData(&exportData); err != nil {
		log.Printf("[ERROR] Failed to import database data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to import data: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":                "Database import completed successfully",
		"imported_scope_targets": len(exportData.ScopeTargets),
		"imported_tables":        len(exportData.TableData),
		"total_records":          exportData.ExportMetadata.TotalRecords,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("[INFO] Database import completed successfully. Imported %d scope targets", len(exportData.ScopeTargets))
}

func HandleDatabaseImportURL(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Starting database import from URL process")

	var request DatabaseImportURLRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Validate URL format
	parsedURL, err := url.Parse(request.URL)
	if err != nil {
		log.Printf("[ERROR] Invalid URL format: %v", err)
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	// Only allow HTTP and HTTPS schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		http.Error(w, "Only HTTP and HTTPS URLs are supported", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Downloading file from URL: %s", request.URL)

	// Download the file from the URL with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(request.URL)
	if err != nil {
		log.Printf("[ERROR] Failed to download file from URL: %v", err)
		http.Error(w, "Failed to download file from URL", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] Failed to download file, status code: %d", resp.StatusCode)
		http.Error(w, fmt.Sprintf("Failed to download file, status code: %d", resp.StatusCode), http.StatusBadRequest)
		return
	}

	// Check Content-Length if available (500MB limit)
	if resp.ContentLength > 500*1024*1024 {
		http.Error(w, "File is too large. Maximum size is 500MB", http.StatusBadRequest)
		return
	}

	// Read file with size limit
	limitedReader := io.LimitReader(resp.Body, 500*1024*1024+1) // 500MB + 1 byte
	compressedData, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("[ERROR] Failed to read downloaded file: %v", err)
		http.Error(w, "Failed to read downloaded file", http.StatusInternalServerError)
		return
	}

	// Check if we hit the size limit
	if len(compressedData) > 500*1024*1024 {
		http.Error(w, "File is too large. Maximum size is 500MB", http.StatusBadRequest)
		return
	}

	// Validate file extension from URL path
	if !strings.HasSuffix(strings.ToLower(parsedURL.Path), ".rs0n") {
		http.Error(w, "Invalid file type. Only .rs0n files are supported", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Downloaded %d bytes, processing import", len(compressedData))

	// Process the downloaded file (same as HandleDatabaseImport)
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		log.Printf("[ERROR] Failed to create gzip reader: %v", err)
		http.Error(w, "Invalid file format", http.StatusBadRequest)
		return
	}
	defer gzipReader.Close()

	jsonData, err := io.ReadAll(gzipReader)
	if err != nil {
		log.Printf("[ERROR] Failed to decompress data: %v", err)
		http.Error(w, "Failed to decompress data", http.StatusInternalServerError)
		return
	}

	var exportData ExportData
	if err := json.Unmarshal(jsonData, &exportData); err != nil {
		log.Printf("[ERROR] Failed to unmarshal export data: %v", err)
		http.Error(w, "Invalid export data format", http.StatusBadRequest)
		return
	}

	if err := importDatabaseData(&exportData); err != nil {
		log.Printf("[ERROR] Failed to import database data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to import data: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":                "Database import from URL completed successfully",
		"imported_scope_targets": len(exportData.ScopeTargets),
		"imported_tables":        len(exportData.TableData),
		"total_records":          exportData.ExportMetadata.TotalRecords,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("[INFO] Database import from URL completed successfully. Imported %d scope targets", len(exportData.ScopeTargets))
}

func exportDatabaseData(scopeTargetIDs []string) (*ExportData, error) {
	exportData := &ExportData{
		TableData: make(map[string][]map[string]interface{}),
	}

	scopeTargets, err := getScopeTargetsForExport(scopeTargetIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get scope targets: %v", err)
	}
	exportData.ScopeTargets = scopeTargets

	var scopeTargetNames []string
	for _, target := range scopeTargets {
		if name, ok := target["scope_target"].(string); ok {
			scopeTargetNames = append(scopeTargetNames, name)
		}
	}

	totalRecords := len(scopeTargets)
	var tablesExported []string

	// First pass: export all regular tables
	for tableName, query := range exportTableQueries {
		log.Printf("[INFO] Exporting data from table: %s", tableName)

		rows, err := dbPool.Query(context.Background(), query, scopeTargetIDs)
		if err != nil {
			log.Printf("[WARN] Failed to query table %s: %v", tableName, err)
			continue
		}

		tableData, err := rowsToMaps(rows)
		rows.Close()

		if err != nil {
			log.Printf("[WARN] Failed to process rows for table %s: %v", tableName, err)
			continue
		}

		if len(tableData) > 0 {
			exportData.TableData[tableName] = tableData
			totalRecords += len(tableData)
			tablesExported = append(tablesExported, tableName)
			log.Printf("[INFO] Exported %d records from table: %s", len(tableData), tableName)
		}
	}

	// Second pass: ensure parent domain records exist for all child records
	log.Printf("[INFO] Ensuring parent domain records are complete...")
	if err := ensureParentDomainRecords(exportData, scopeTargetIDs); err != nil {
		log.Printf("[WARN] Failed to ensure parent domain records: %v", err)
	}

	exportData.ExportMetadata = ExportMetadata{
		ExportedAt:     time.Now(),
		Version:        "1.0",
		ScopeTargetIDs: scopeTargetIDs,
		ScopeTargets:   scopeTargetNames,
		TotalRecords:   totalRecords,
		TablesExported: tablesExported,
	}

	return exportData, nil
}

func ensureParentDomainRecords(exportData *ExportData, scopeTargetIDs []string) error {
	// Track which parent domain records we already have
	existingParents := make(map[string]bool)

	// Check amass_enum_company_domain_results
	if amassParents, exists := exportData.TableData["amass_enum_company_domain_results"]; exists {
		for _, record := range amassParents {
			scopeTargetID, _ := record["scope_target_id"].(string)
			domain, _ := record["domain"].(string)
			key := scopeTargetID + "|" + domain
			existingParents[key] = true
		}
	}

	// Check dnsx_company_domain_results
	if dnsxParents, exists := exportData.TableData["dnsx_company_domain_results"]; exists {
		for _, record := range dnsxParents {
			scopeTargetID, _ := record["scope_target_id"].(string)
			domain, _ := record["domain"].(string)
			key := scopeTargetID + "|" + domain
			existingParents[key] = true
		}
	}

	// Check katana_company_domain_results
	if katanaParents, exists := exportData.TableData["katana_company_domain_results"]; exists {
		for _, record := range katanaParents {
			scopeTargetID, _ := record["scope_target_id"].(string)
			domain, _ := record["domain"].(string)
			key := scopeTargetID + "|" + domain
			existingParents[key] = true
		}
	}

	// Find missing parents and create them
	missingParents := make(map[string]map[string]interface{})

	// Check amass_enum child tables
	for _, tableName := range []string{"amass_enum_company_dns_records", "amass_enum_company_cloud_domains"} {
		if childRecords, exists := exportData.TableData[tableName]; exists {
			for _, record := range childRecords {
				scopeTargetID, _ := record["scope_target_id"].(string)
				rootDomain, _ := record["root_domain"].(string)
				key := scopeTargetID + "|" + rootDomain

				if !existingParents[key] && rootDomain != "" && scopeTargetID != "" {
					missingParents[key] = map[string]interface{}{
						"id":              uuid.New().String(),
						"scope_target_id": scopeTargetID,
						"domain":          rootDomain,
						"last_scanned_at": time.Now(),
						"created_at":      time.Now(),
						"updated_at":      time.Now(),
						"last_scan_id":    nil,
						"raw_output":      nil,
					}
					existingParents[key] = true
					log.Printf("[INFO] Will create missing amass_enum parent for: %s", key)
				}
			}
		}
	}

	// Add missing amass_enum parents
	if len(missingParents) > 0 {
		if exportData.TableData["amass_enum_company_domain_results"] == nil {
			exportData.TableData["amass_enum_company_domain_results"] = []map[string]interface{}{}
		}
		for _, parent := range missingParents {
			exportData.TableData["amass_enum_company_domain_results"] = append(
				exportData.TableData["amass_enum_company_domain_results"], parent)
		}
		log.Printf("[INFO] Added %d missing amass_enum parent domain records", len(missingParents))
	}

	// Reset and check dnsx child tables
	missingParents = make(map[string]map[string]interface{})
	for _, tableName := range []string{"dnsx_company_dns_records"} {
		if childRecords, exists := exportData.TableData[tableName]; exists {
			for _, record := range childRecords {
				scopeTargetID, _ := record["scope_target_id"].(string)
				rootDomain, _ := record["root_domain"].(string)
				key := scopeTargetID + "|" + rootDomain

				if !existingParents[key] && rootDomain != "" && scopeTargetID != "" {
					missingParents[key] = map[string]interface{}{
						"id":              uuid.New().String(),
						"scope_target_id": scopeTargetID,
						"domain":          rootDomain,
						"last_scanned_at": time.Now(),
						"created_at":      time.Now(),
						"updated_at":      time.Now(),
						"last_scan_id":    nil,
						"raw_output":      nil,
					}
					existingParents[key] = true
					log.Printf("[INFO] Will create missing dnsx parent for: %s", key)
				}
			}
		}
	}

	// Add missing dnsx parents
	if len(missingParents) > 0 {
		if exportData.TableData["dnsx_company_domain_results"] == nil {
			exportData.TableData["dnsx_company_domain_results"] = []map[string]interface{}{}
		}
		for _, parent := range missingParents {
			exportData.TableData["dnsx_company_domain_results"] = append(
				exportData.TableData["dnsx_company_domain_results"], parent)
		}
		log.Printf("[INFO] Added %d missing dnsx parent domain records", len(missingParents))
	}

	// Reset and check katana child tables
	missingParents = make(map[string]map[string]interface{})
	for _, tableName := range []string{"katana_company_cloud_assets"} {
		if childRecords, exists := exportData.TableData[tableName]; exists {
			for _, record := range childRecords {
				scopeTargetID, _ := record["scope_target_id"].(string)
				rootDomain, _ := record["root_domain"].(string)
				key := scopeTargetID + "|" + rootDomain

				if !existingParents[key] && rootDomain != "" && scopeTargetID != "" {
					missingParents[key] = map[string]interface{}{
						"id":              uuid.New().String(),
						"scope_target_id": scopeTargetID,
						"domain":          rootDomain,
						"last_scanned_at": time.Now(),
						"created_at":      time.Now(),
						"updated_at":      time.Now(),
						"last_scan_id":    nil,
						"raw_output":      nil,
					}
					existingParents[key] = true
					log.Printf("[INFO] Will create missing katana parent for: %s", key)
				}
			}
		}
	}

	// Add missing katana parents
	if len(missingParents) > 0 {
		if exportData.TableData["katana_company_domain_results"] == nil {
			exportData.TableData["katana_company_domain_results"] = []map[string]interface{}{}
		}
		for _, parent := range missingParents {
			exportData.TableData["katana_company_domain_results"] = append(
				exportData.TableData["katana_company_domain_results"], parent)
		}
		log.Printf("[INFO] Added %d missing katana parent domain records", len(missingParents))
	}

	return nil
}

func getScopeTargetsForExport(scopeTargetIDs []string) ([]map[string]interface{}, error) {
	query := `SELECT id, type, mode, scope_target, active, created_at FROM scope_targets WHERE id = ANY($1)`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rowsToMaps(rows)
}

func rowsToMaps(rows pgx.Rows) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	fieldDescriptions := rows.FieldDescriptions()

	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}

		record := make(map[string]interface{})
		for i, value := range values {
			fieldName := string(fieldDescriptions[i].Name)

			// Convert UUID byte arrays to strings during export
			if fieldDescriptions[i].DataTypeOID == 2950 { // UUID OID
				if bytes, ok := value.([]byte); ok && len(bytes) == 16 {
					if parsedUUID, err := uuid.FromBytes(bytes); err == nil {
						record[fieldName] = parsedUUID.String()
						continue
					}
				}
			}

			record[fieldName] = value
		}

		results = append(results, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func importDatabaseData(exportData *ExportData) error {
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	if err := importScopeTargets(tx, exportData.ScopeTargets); err != nil {
		return fmt.Errorf("failed to import scope targets: %v", err)
	}

	if err := importTableData(tx, exportData.TableData); err != nil {
		return fmt.Errorf("failed to import table data: %v", err)
	}

	if err := tx.Commit(context.Background()); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

func convertUUIDValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	// If it's already a string, return as is
	if str, ok := value.(string); ok {
		return str
	}

	// If it's a byte slice (UUID as bytes), convert to UUID string
	if bytes, ok := value.([]interface{}); ok {
		if len(bytes) == 16 {
			// Convert []interface{} to []byte
			byteArray := make([]byte, 16)
			for i, b := range bytes {
				switch v := b.(type) {
				case float64:
					byteArray[i] = byte(v)
				case int:
					byteArray[i] = byte(v)
				case int32:
					byteArray[i] = byte(v)
				case int64:
					byteArray[i] = byte(v)
				case uint8:
					byteArray[i] = v
				default:
					// If we can't convert, return original value
					return value
				}
			}

			// Parse bytes as UUID and return string representation
			if parsedUUID, err := uuid.FromBytes(byteArray); err == nil {
				return parsedUUID.String()
			}
		}
	}

	// If it's already a byte array
	if bytes, ok := value.([]byte); ok {
		if len(bytes) == 16 {
			if parsedUUID, err := uuid.FromBytes(bytes); err == nil {
				return parsedUUID.String()
			}
		}
	}

	return value
}

func convertRecordUUIDs(record map[string]interface{}) map[string]interface{} {
	// List of fields that are UUIDs
	uuidFields := []string{
		"id", "scope_target_id", "scan_id", "auto_scan_session_id",
		"ip_port_scan_id", "parent_asset_id", "child_asset_id", "asset_id",
		"last_scan_id",
	}

	for _, field := range uuidFields {
		if value, exists := record[field]; exists {
			record[field] = convertUUIDValue(value)
		}
	}

	return record
}

func importScopeTargets(tx pgx.Tx, scopeTargets []map[string]interface{}) error {
	for _, target := range scopeTargets {
		// Convert UUID fields
		target = convertRecordUUIDs(target)

		query := `
			INSERT INTO scope_targets (id, type, mode, scope_target, active, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (id) DO UPDATE SET
				type = EXCLUDED.type,
				mode = EXCLUDED.mode,
				scope_target = EXCLUDED.scope_target,
				active = EXCLUDED.active,
				created_at = EXCLUDED.created_at`

		_, err := tx.Exec(context.Background(), query,
			target["id"], target["type"], target["mode"],
			target["scope_target"], target["active"], target["created_at"])
		if err != nil {
			return fmt.Errorf("failed to insert scope target: %v", err)
		}
	}
	return nil
}

func importTableData(tx pgx.Tx, tableData map[string][]map[string]interface{}) error {
	tableOrder := []string{
		// Parent tables first
		"auto_scan_sessions", "auto_scan_state",

		// Basic scan tables
		"amass_scans", "amass_intel_scans", "amass_enum_company_scans",
		"httpx_scans", "gau_scans", "sublist3r_scans", "assetfinder_scans",
		"ctl_scans", "subfinder_scans", "shuffledns_scans", "shufflednscustom_scans",
		"cewl_scans", "gospider_scans", "subdomainizer_scans",
		"nuclei_screenshots", "metadata_scans", "nuclei_scans",

		// Company scanning tools
		"cloud_enum_scans", "metabigor_company_scans", "katana_company_scans",
		"dnsx_company_scans", "securitytrails_company_scans", "github_recon_scans",
		"shodan_company_scans", "censys_company_scans", "company_metadata_scans",
		"investigate_scans",

		// IP/Port scanning
		"ip_port_scans",

		// Child tables of scan tables (must come after parent scans)
		"dns_records", "ips", "subdomains", "cloud_domains", "asns", "subnets", "service_providers",
		"intel_network_ranges", "intel_asn_data",
		"metabigor_network_ranges",
		"amass_enum_cloud_domains", "amass_enum_dns_records", "amass_enum_raw_results",
		"dnsx_dns_records", "dnsx_raw_results",
		"discovered_live_ips", "live_web_servers",

		// Domain-centric result tables
		"dnsx_company_domain_results", "amass_enum_company_domain_results",

		// Child tables of domain result tables
		"katana_company_cloud_assets",
		"dnsx_company_dns_records", "amass_enum_company_cloud_domains", "amass_enum_company_dns_records",

		// Target URLs and consolidated data
		"target_urls",
		"consolidated_subdomains", "consolidated_company_domains", "consolidated_network_ranges",
		"google_dorking_domains", "reverse_whois_domains",

		// Attack surface assets (parent)
		"consolidated_attack_surface_assets",

		// Attack surface child tables
		"consolidated_attack_surface_relationships", "consolidated_attack_surface_dns_records",
		"consolidated_attack_surface_metadata",

		// Configuration tables (can be imported any time after scope_targets)
		"amass_enum_configs", "amass_intel_configs", "dnsx_configs",
		"katana_company_configs", "cloud_enum_configs", "nuclei_configs",
	}

	for _, tableName := range tableOrder {
		if records, exists := tableData[tableName]; exists {
			if err := importTableRecords(tx, tableName, records); err != nil {
				return fmt.Errorf("failed to import table %s: %v", tableName, err)
			}
		}
	}

	// Import any remaining tables not in the ordered list
	for tableName, records := range tableData {
		found := false
		for _, orderedTable := range tableOrder {
			if tableName == orderedTable {
				found = true
				break
			}
		}
		if !found {
			if err := importTableRecords(tx, tableName, records); err != nil {
				return fmt.Errorf("failed to import table %s: %v", tableName, err)
			}
		}
	}

	return nil
}

func importTableRecords(tx pgx.Tx, tableName string, records []map[string]interface{}) error {
	if len(records) == 0 {
		return nil
	}

	log.Printf("[INFO] Importing %d records into table: %s", len(records), tableName)

	// Check if table exists first
	var exists bool
	err := tx.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)`, tableName).Scan(&exists)

	if err != nil {
		log.Printf("[ERROR] Failed to check if table %s exists: %v", tableName, err)
		return fmt.Errorf("failed to check if table %s exists: %v", tableName, err)
	}

	if !exists {
		log.Printf("[WARN] Table %s does not exist, skipping import", tableName)
		return nil
	}

	successCount := 0
	errorCount := 0
	for i, record := range records {
		if err := importSingleRecord(tx, tableName, record); err != nil {
			errorCount++
			log.Printf("[WARN] Failed to import record %d in table %s: %v", i+1, tableName, err)
			
			// Continue processing even if individual records fail
			// This allows the import to proceed despite some foreign key constraint violations
		} else {
			successCount++
		}
	}

	log.Printf("[INFO] Successfully imported %d/%d records into table: %s (%d errors)", 
		successCount, len(records), tableName, errorCount)
	return nil
}

func importSingleRecord(tx pgx.Tx, tableName string, record map[string]interface{}) error {
	// Convert UUID fields
	record = convertRecordUUIDs(record)

	var columns []string
	var placeholders []string
	var values []interface{}
	var updateClauses []string

	i := 1
	for column, value := range record {
		columns = append(columns, column)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		values = append(values, value)
		updateClauses = append(updateClauses, fmt.Sprintf("%s = EXCLUDED.%s", column, column))
		i++
	}

	// Use savepoint to handle individual record failures
	savepointName := fmt.Sprintf("sp_%s_%d", tableName, time.Now().UnixNano())
	
	_, err := tx.Exec(context.Background(), fmt.Sprintf("SAVEPOINT %s", savepointName))
	if err != nil {
		log.Printf("[WARN] Failed to create savepoint for %s: %v", tableName, err)
		// Continue without savepoint protection
	}

	// Build the upsert query
	query := fmt.Sprintf(`
		INSERT INTO %s (%s) VALUES (%s)
		ON CONFLICT (id) DO UPDATE SET %s`,
		tableName,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(updateClauses, ", "))

	_, execErr := tx.Exec(context.Background(), query, values...)
	if execErr != nil {
		// Rollback to savepoint on error
		if err == nil { // Only rollback if savepoint was created successfully
			_, rollbackErr := tx.Exec(context.Background(), fmt.Sprintf("ROLLBACK TO SAVEPOINT %s", savepointName))
			if rollbackErr != nil {
				log.Printf("[WARN] Failed to rollback to savepoint for %s: %v", tableName, rollbackErr)
			}
		}
		
		log.Printf("[WARN] Failed to insert record into %s: %v", tableName, execErr)
		
		// For foreign key constraint violations, log the details but don't fail the transaction
		if strings.Contains(execErr.Error(), "foreign key constraint") ||
			strings.Contains(execErr.Error(), "violates foreign key constraint") {
			log.Printf("[WARN] Foreign key constraint violation in %s - this may indicate missing parent record", tableName)
		}
		
		return execErr
	} else {
		// Release savepoint on success
		if err == nil { // Only release if savepoint was created successfully
			_, _ = tx.Exec(context.Background(), fmt.Sprintf("RELEASE SAVEPOINT %s", savepointName))
		}
	}

	return nil
}

func GetScopeTargetsForExport(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Fetching scope targets for export")

	rows, err := dbPool.Query(context.Background(),
		`SELECT id, type, scope_target, active, created_at FROM scope_targets ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("[ERROR] Failed to query scope targets: %v", err)
		http.Error(w, "Failed to fetch scope targets", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var targets []map[string]interface{}
	for rows.Next() {
		var id, targetType, scopeTarget string
		var active bool
		var createdAt time.Time

		if err := rows.Scan(&id, &targetType, &scopeTarget, &active, &createdAt); err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		targets = append(targets, map[string]interface{}{
			"id":           id,
			"type":         targetType,
			"scope_target": scopeTarget,
			"active":       active,
			"created_at":   createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(targets)

	log.Printf("[INFO] Returned %d scope targets for export", len(targets))
}

func DebugExportFile(w http.ResponseWriter, r *http.Request) {
	var req DatabaseImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse the export data
	reader := bytes.NewReader(req.Data)
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create gzip reader: %v", err), http.StatusInternalServerError)
		return
	}
	defer gzReader.Close()

	var exportData ExportData
	if err := json.NewDecoder(gzReader).Decode(&exportData); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode export data: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[DEBUG] Export file contains %d scope targets and %d tables",
		len(exportData.ScopeTargets), len(exportData.TableData))

	debug := map[string]interface{}{
		"metadata":            exportData.ExportMetadata,
		"scope_targets":       len(exportData.ScopeTargets),
		"tables":              make(map[string]int),
		"amass_enum_analysis": analyzeAmassEnumData(exportData.TableData),
	}

	for tableName, records := range exportData.TableData {
		debug["tables"].(map[string]int)[tableName] = len(records)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(debug)
}

func analyzeAmassEnumData(tableData map[string][]map[string]interface{}) map[string]interface{} {
	analysis := map[string]interface{}{
		"parent_domains":      []string{},
		"child_dns_records":   []string{},
		"child_cloud_domains": []string{},
		"missing_parents":     []string{},
	}

	// Get all parent domain records
	parentDomains := make(map[string]bool)
	if parentRecords, exists := tableData["amass_enum_company_domain_results"]; exists {
		for _, record := range parentRecords {
			scopeTargetID, _ := record["scope_target_id"].(string)
			domain, _ := record["domain"].(string)
			key := scopeTargetID + "|" + domain
			parentDomains[key] = true
			analysis["parent_domains"] = append(analysis["parent_domains"].([]string), key)
		}
	}

	// Check DNS records for missing parents
	missingParents := make(map[string]bool)
	if dnsRecords, exists := tableData["amass_enum_company_dns_records"]; exists {
		for _, record := range dnsRecords {
			scopeTargetID, _ := record["scope_target_id"].(string)
			rootDomain, _ := record["root_domain"].(string)
			key := scopeTargetID + "|" + rootDomain
			analysis["child_dns_records"] = append(analysis["child_dns_records"].([]string), key)

			if !parentDomains[key] {
				missingParents[key] = true
			}
		}
	}

	// Check cloud domains for missing parents
	if cloudDomains, exists := tableData["amass_enum_company_cloud_domains"]; exists {
		for _, record := range cloudDomains {
			scopeTargetID, _ := record["scope_target_id"].(string)
			rootDomain, _ := record["root_domain"].(string)
			key := scopeTargetID + "|" + rootDomain
			analysis["child_cloud_domains"] = append(analysis["child_cloud_domains"].([]string), key)

			if !parentDomains[key] {
				missingParents[key] = true
			}
		}
	}

	for key := range missingParents {
		analysis["missing_parents"] = append(analysis["missing_parents"].([]string), key)
	}

	return analysis
}
