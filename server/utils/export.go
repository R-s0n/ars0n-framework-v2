package utils

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ExportRequest struct {
	Amass         bool `json:"amass"`
	Httpx         bool `json:"httpx"`
	Gau           bool `json:"gau"`
	Sublist3r     bool `json:"sublist3r"`
	Assetfinder   bool `json:"assetfinder"`
	Ctl           bool `json:"ctl"`
	Subfinder     bool `json:"subfinder"`
	Shuffledns    bool `json:"shuffledns"`
	Gospider      bool `json:"gospider"`
	Subdomainizer bool `json:"subdomainizer"`
	Roi           bool `json:"roi"`
	Subdomains    bool `json:"subdomains"`
}

type AmassRecord struct {
	ScanID        string
	Target        string
	ExecutionTime string
	Command       string
	Error         string
	DNSRecords    []struct {
		Record     string
		RecordType string
	}
	IPs          []string
	ASNs         map[string]ASNInfo
	Subnets      map[string]SubnetInfo
	Providers    map[string]ProviderInfo
	CloudDomains map[string]string // domain -> provider type
}

type ASNInfo struct {
	Number  string
	RawData string
}

type SubnetInfo struct {
	CIDR    string
	RawData string
}

type ProviderInfo struct {
	Provider string
	RawData  string
}

func HandleExportData(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Starting export process")
	var req ExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Export request received: %+v", req)

	// Create a temporary directory for CSV files
	tempDir, err := os.MkdirTemp("", "export-*")
	if err != nil {
		log.Printf("[ERROR] Failed to create temporary directory: %v", err)
		http.Error(w, "Failed to create temporary directory", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tempDir)
	log.Printf("[INFO] Created temporary directory: %s", tempDir)

	// Create a zip file in memory
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Process each selected export type
	if req.Amass {
		log.Println("[INFO] Starting Amass data export")
		if err := exportAmassData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Amass data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Amass data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Amass data export")
	}

	if req.Httpx {
		log.Println("[INFO] Starting HTTPX data export")
		if err := exportHttpxData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export HTTPX data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export HTTPX data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed HTTPX data export")
	}

	if req.Gau {
		log.Println("[INFO] Starting GAU data export")
		if err := exportGauData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export GAU data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export GAU data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed GAU data export")
	}

	if req.Sublist3r {
		log.Println("[INFO] Starting Sublist3r data export")
		if err := exportSublist3rData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Sublist3r data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Sublist3r data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Sublist3r data export")
	}

	if req.Assetfinder {
		log.Println("[INFO] Starting Assetfinder data export")
		if err := exportAssetfinderData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Assetfinder data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Assetfinder data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Assetfinder data export")
	}

	if req.Ctl {
		log.Println("[INFO] Starting CTL data export")
		if err := exportCtlData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export CTL data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export CTL data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed CTL data export")
	}

	if req.Subfinder {
		log.Println("[INFO] Starting Subfinder data export")
		if err := exportSubfinderData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Subfinder data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Subfinder data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Subfinder data export")
	}

	if req.Shuffledns {
		log.Println("[INFO] Starting ShuffleDNS data export")
		if err := exportShufflednsData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export ShuffleDNS data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export ShuffleDNS data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed ShuffleDNS data export")
	}

	if req.Gospider {
		log.Println("[INFO] Starting GoSpider data export")
		if err := exportGospiderData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export GoSpider data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export GoSpider data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed GoSpider data export")
	}

	if req.Subdomainizer {
		log.Println("[INFO] Starting Subdomainizer data export")
		if err := exportSubdomainizerData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Subdomainizer data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Subdomainizer data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Subdomainizer data export")
	}

	if req.Roi {
		log.Println("[INFO] Starting ROI data export")
		if err := exportRoiData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export ROI data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export ROI data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed ROI data export")
	}

	if req.Subdomains {
		log.Println("[INFO] Starting Subdomains data export")
		if err := exportSubdomainsData(zipWriter, tempDir); err != nil {
			log.Printf("[ERROR] Failed to export Subdomains data: %v", err)
			http.Error(w, fmt.Sprintf("Failed to export Subdomains data: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("[INFO] Completed Subdomains data export")
	}

	// Close the zip writer
	log.Println("[INFO] Finalizing zip file")
	if err := zipWriter.Close(); err != nil {
		log.Printf("[ERROR] Failed to create zip file: %v", err)
		http.Error(w, "Failed to create zip file", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/zip")
	filename := fmt.Sprintf("export-%s.zip", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	log.Printf("[INFO] Sending zip file: %s", filename)

	// Write the zip file to the response
	if _, err := io.Copy(w, buf); err != nil {
		log.Printf("[ERROR] Failed to send zip file: %v", err)
		http.Error(w, "Failed to send zip file", http.StatusInternalServerError)
		return
	}

	log.Println("[INFO] Export process completed successfully")
}

func exportAmassData(zipWriter *zip.Writer, tempDir string) error {
	log.Println("[INFO] Creating Amass CSV file")
	amassFile := filepath.Join(tempDir, "amass_data.csv")
	file, err := os.Create(amassFile)
	if err != nil {
		log.Printf("[ERROR] Failed to create Amass CSV file: %v", err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers
	headers := []string{
		"Scan ID", "Target", "Subdomain", "DNS Record Type", "IP Address",
		"ASN", "ASN Info", "CIDR", "Subnet Info", "Service Provider",
		"Provider Info", "Cloud Domain", "Cloud Provider", "Execution Time",
		"Command", "Error",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Get base scan data
	scans := make(map[string]*AmassRecord)
	rows, err := dbPool.Query(context.Background(), `
		SELECT s.scan_id, st.scope_target, 
			   COALESCE(s.execution_time, ''), 
			   COALESCE(s.command, ''),
			   COALESCE(s.error, '')
		FROM amass_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		record := &AmassRecord{
			ASNs:         make(map[string]ASNInfo),
			Subnets:      make(map[string]SubnetInfo),
			Providers:    make(map[string]ProviderInfo),
			CloudDomains: make(map[string]string),
		}
		err := rows.Scan(&record.ScanID, &record.Target, &record.ExecutionTime,
			&record.Command, &record.Error)
		if err != nil {
			return err
		}
		scans[record.ScanID] = record
	}

	// Get all data for each scan
	for scanID, scan := range scans {
		// Get DNS records with their associated IPs
		dnsRows, err := dbPool.Query(context.Background(), `
			SELECT dr.record, dr.record_type, i.ip_address
			FROM dns_records dr
			LEFT JOIN ips i ON dr.scan_id = i.scan_id
			WHERE dr.scan_id = $1
		`, scanID)
		if err != nil {
			return err
		}

		type dnsIPRecord struct {
			record     string
			recordType string
			ip         string
		}
		var dnsIPRecords []dnsIPRecord

		for dnsRows.Next() {
			var rec dnsIPRecord
			if err := dnsRows.Scan(&rec.record, &rec.recordType, &rec.ip); err != nil {
				dnsRows.Close()
				return err
			}
			dnsIPRecords = append(dnsIPRecords, rec)
		}
		dnsRows.Close()

		// Get ASNs
		asnRows, err := dbPool.Query(context.Background(), `
			SELECT number, raw_data 
			FROM asns 
			WHERE scan_id = $1
		`, scanID)
		if err != nil {
			return err
		}

		asns := make(map[string]ASNInfo)
		for asnRows.Next() {
			var number, rawData string
			if err := asnRows.Scan(&number, &rawData); err != nil {
				asnRows.Close()
				return err
			}
			asns[number] = ASNInfo{Number: number, RawData: rawData}
		}
		asnRows.Close()

		// Get Subnets
		subnetRows, err := dbPool.Query(context.Background(), `
			SELECT cidr, raw_data 
			FROM subnets 
			WHERE scan_id = $1
		`, scanID)
		if err != nil {
			return err
		}

		subnets := make(map[string]SubnetInfo)
		for subnetRows.Next() {
			var cidr, rawData string
			if err := subnetRows.Scan(&cidr, &rawData); err != nil {
				subnetRows.Close()
				return err
			}
			subnets[cidr] = SubnetInfo{CIDR: cidr, RawData: rawData}
		}
		subnetRows.Close()

		// Get Service Providers
		spRows, err := dbPool.Query(context.Background(), `
			SELECT provider, raw_data 
			FROM service_providers 
			WHERE scan_id = $1
		`, scanID)
		if err != nil {
			return err
		}

		providers := make(map[string]ProviderInfo)
		for spRows.Next() {
			var provider, rawData string
			if err := spRows.Scan(&provider, &rawData); err != nil {
				spRows.Close()
				return err
			}
			providers[provider] = ProviderInfo{Provider: provider, RawData: rawData}
		}
		spRows.Close()

		// For each DNS record and IP combination
		for _, dnsIP := range dnsIPRecords {
			// Find matching ASN
			var matchingASN ASNInfo
			var matchingSubnet SubnetInfo
			var matchingProvider ProviderInfo

			if dnsIP.ip != "" {
				// Find ASN for this IP
				for _, asn := range asns {
					if strings.Contains(asn.RawData, dnsIP.ip) {
						matchingASN = asn
						break
					}
				}

				// Find Subnet for this IP
				for _, subnet := range subnets {
					if strings.Contains(subnet.RawData, dnsIP.ip) {
						matchingSubnet = subnet
						break
					}
				}

				// Find Provider for this IP
				for _, provider := range providers {
					if strings.Contains(provider.RawData, dnsIP.ip) {
						matchingProvider = provider
						break
					}
				}
			}

			// Write the record
			record := []string{
				scan.ScanID,
				scan.Target,
				dnsIP.record,
				dnsIP.recordType,
				dnsIP.ip,
				matchingASN.Number,
				matchingASN.RawData,
				matchingSubnet.CIDR,
				matchingSubnet.RawData,
				matchingProvider.Provider,
				matchingProvider.RawData,
				dnsIP.record,
				scan.CloudDomains[dnsIP.record],
				scan.ExecutionTime,
				scan.Command,
				scan.Error,
			}

			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}

	return addFileToZip(zipWriter, amassFile, "amass_data.csv")
}

func writeAmassRow(writer *csv.Writer, scan *AmassRecord, dns struct {
	Record     string
	RecordType string
}, ip string, asn ASNInfo, subnet SubnetInfo,
	provider ProviderInfo, cloudType string) error {
	return writer.Write([]string{
		scan.ScanID,
		scan.Target,
		dns.Record,
		dns.RecordType,
		ip,
		asn.Number,
		asn.RawData,
		subnet.CIDR,
		subnet.RawData,
		provider.Provider,
		provider.RawData,
		dns.Record,
		cloudType,
		scan.ExecutionTime,
		scan.Command,
		scan.Error,
	})
}

func exportHttpxData(zipWriter *zip.Writer, tempDir string) error {
	httpxFile := filepath.Join(tempDir, "httpx_data.csv")
	file, err := os.Create(httpxFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM httpx_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning httpx row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, httpxFile, "httpx_data.csv")
}

func exportGauData(zipWriter *zip.Writer, tempDir string) error {
	gauFile := filepath.Join(tempDir, "gau_data.csv")
	file, err := os.Create(gauFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM gau_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning gau row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, gauFile, "gau_data.csv")
}

func exportSublist3rData(zipWriter *zip.Writer, tempDir string) error {
	sublist3rFile := filepath.Join(tempDir, "sublist3r_data.csv")
	file, err := os.Create(sublist3rFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM sublist3r_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning sublist3r row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, sublist3rFile, "sublist3r_data.csv")
}

func exportAssetfinderData(zipWriter *zip.Writer, tempDir string) error {
	assetfinderFile := filepath.Join(tempDir, "assetfinder_data.csv")
	file, err := os.Create(assetfinderFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM assetfinder_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning assetfinder row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, assetfinderFile, "assetfinder_data.csv")
}

func exportCtlData(zipWriter *zip.Writer, tempDir string) error {
	ctlFile := filepath.Join(tempDir, "ctl_data.csv")
	file, err := os.Create(ctlFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM ctl_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning ctl row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, ctlFile, "ctl_data.csv")
}

func exportSubfinderData(zipWriter *zip.Writer, tempDir string) error {
	subfinderFile := filepath.Join(tempDir, "subfinder_data.csv")
	file, err := os.Create(subfinderFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM subfinder_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning subfinder row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, subfinderFile, "subfinder_data.csv")
}

func exportShufflednsData(zipWriter *zip.Writer, tempDir string) error {
	shufflednsFile := filepath.Join(tempDir, "shuffledns_data.csv")
	file, err := os.Create(shufflednsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM shuffledns_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning shuffledns row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, shufflednsFile, "shuffledns_data.csv")
}

func exportGospiderData(zipWriter *zip.Writer, tempDir string) error {
	gospiderFile := filepath.Join(tempDir, "gospider_data.csv")
	file, err := os.Create(gospiderFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM gospider_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning gospider row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, gospiderFile, "gospider_data.csv")
}

func exportSubdomainizerData(zipWriter *zip.Writer, tempDir string) error {
	subdomainizerFile := filepath.Join(tempDir, "subdomainizer_data.csv")
	file, err := os.Create(subdomainizerFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Scan ID", "Target", "Result", "Error", "Execution Time", "Command"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			s.scan_id,
			st.scope_target,
			COALESCE(s.result, ''),
			COALESCE(s.error, ''),
			COALESCE(s.execution_time, ''),
			COALESCE(s.command, '')
		FROM subdomainizer_scans s
		JOIN scope_targets st ON s.scope_target_id = st.id
		ORDER BY s.scan_id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var scanID, target, result, errorMsg, execTime, cmd string

		if err := rows.Scan(&scanID, &target, &result, &errorMsg, &execTime, &cmd); err != nil {
			return fmt.Errorf("error scanning subdomainizer row: %v", err)
		}

		record := []string{
			scanID,
			target,
			result,
			errorMsg,
			execTime,
			cmd,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, subdomainizerFile, "subdomainizer_data.csv")
}

func exportRoiData(zipWriter *zip.Writer, tempDir string) error {
	roiFile := filepath.Join(tempDir, "roi_data.csv")
	file, err := os.Create(roiFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{
		"Target URL ID", "Target", "URL", "Status Code", "Title", "Web Server",
		"Technologies", "Content Length", "Deprecated TLS", "Expired SSL",
		"Mismatched SSL", "Revoked SSL", "Self-Signed SSL", "Untrusted Root SSL",
		"Wildcard TLS", "HTTP Response", "HTTP Headers", "DNS A Records",
		"DNS AAAA Records", "DNS CNAME Records", "DNS MX Records",
		"DNS TXT Records", "DNS NS Records", "DNS PTR Records",
		"DNS SRV Records", "ROI Score", "Last Updated",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT 
			tu.id::text,
			st.scope_target,
			tu.url,
			COALESCE(tu.status_code, 0),
			COALESCE(tu.title, ''),
			COALESCE(tu.web_server, ''),
			COALESCE(array_to_string(tu.technologies, ','), ''),
			COALESCE(tu.content_length, 0),
			COALESCE(tu.has_deprecated_tls, false),
			COALESCE(tu.has_expired_ssl, false),
			COALESCE(tu.has_mismatched_ssl, false),
			COALESCE(tu.has_revoked_ssl, false),
			COALESCE(tu.has_self_signed_ssl, false),
			COALESCE(tu.has_untrusted_root_ssl, false),
			COALESCE(tu.has_wildcard_tls, false),
			COALESCE(tu.http_response, ''),
			COALESCE(tu.http_response_headers::text, ''),
			COALESCE(array_to_string(tu.dns_a_records, ','), ''),
			COALESCE(array_to_string(tu.dns_aaaa_records, ','), ''),
			COALESCE(array_to_string(tu.dns_cname_records, ','), ''),
			COALESCE(array_to_string(tu.dns_mx_records, ','), ''),
			COALESCE(array_to_string(tu.dns_txt_records, ','), ''),
			COALESCE(array_to_string(tu.dns_ns_records, ','), ''),
			COALESCE(array_to_string(tu.dns_ptr_records, ','), ''),
			COALESCE(array_to_string(tu.dns_srv_records, ','), ''),
			COALESCE(tu.roi_score, 0),
			tu.updated_at
		FROM target_urls tu
		JOIN scope_targets st ON tu.scope_target_id = st.id
		ORDER BY tu.id
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, target, url, title, webServer, techs, httpResp, httpHeaders string
			dnsA, dnsAAAA, dnsCNAME, dnsMX, dnsTXT, dnsNS, dnsPTR, dnsSRV   string
			statusCode, contentLen, roiScore                                int
			hasDeprecatedTLS, hasExpiredSSL, hasMismatchedSSL, hasRevokedSSL,
			hasSelfSignedSSL, hasUntrustedRootSSL, hasWildcardTLS bool
			updatedAt time.Time
		)

		if err := rows.Scan(
			&id, &target, &url, &statusCode, &title, &webServer, &techs,
			&contentLen, &hasDeprecatedTLS, &hasExpiredSSL, &hasMismatchedSSL,
			&hasRevokedSSL, &hasSelfSignedSSL, &hasUntrustedRootSSL,
			&hasWildcardTLS, &httpResp, &httpHeaders, &dnsA, &dnsAAAA,
			&dnsCNAME, &dnsMX, &dnsTXT, &dnsNS, &dnsPTR, &dnsSRV,
			&roiScore, &updatedAt,
		); err != nil {
			return fmt.Errorf("error scanning roi row: %v", err)
		}

		record := []string{
			id,
			target,
			url,
			fmt.Sprintf("%d", statusCode),
			title,
			webServer,
			techs,
			fmt.Sprintf("%d", contentLen),
			fmt.Sprintf("%v", hasDeprecatedTLS),
			fmt.Sprintf("%v", hasExpiredSSL),
			fmt.Sprintf("%v", hasMismatchedSSL),
			fmt.Sprintf("%v", hasRevokedSSL),
			fmt.Sprintf("%v", hasSelfSignedSSL),
			fmt.Sprintf("%v", hasUntrustedRootSSL),
			fmt.Sprintf("%v", hasWildcardTLS),
			httpResp,
			httpHeaders,
			dnsA,
			dnsAAAA,
			dnsCNAME,
			dnsMX,
			dnsTXT,
			dnsNS,
			dnsPTR,
			dnsSRV,
			fmt.Sprintf("%d", roiScore),
			updatedAt.Format(time.RFC3339),
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return addFileToZip(zipWriter, roiFile, "roi_data.csv")
}

func exportSubdomainsData(zipWriter *zip.Writer, tempDir string) error {
	subdomainsFile := filepath.Join(tempDir, "subdomains_data.csv")
	file, err := os.Create(subdomainsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers once at the start
	headers := []string{
		"Target", "Sublist3r", "Assetfinder", "GAU", "CTL", "Subfinder",
		"ShuffleDNS", "GoSpider", "Subdomainizer", "Consolidated", "HTTPX",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Get all scope targets
	scopeTargets := make(map[string]string)
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, scope_target FROM scope_targets
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, target string
		if err := rows.Scan(&id, &target); err != nil {
			return err
		}
		scopeTargets[id] = target
	}

	// For each scope target, get all tool results
	for targetID, target := range scopeTargets {
		toolResults := make(map[string][]string)

		// Get Sublist3r results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM sublist3r_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					// Filter out empty lines and trim spaces
					subdomains := make([]string, 0)
					for _, line := range strings.Split(result, "\n") {
						if trimmed := strings.TrimSpace(line); trimmed != "" {
							subdomains = append(subdomains, trimmed)
						}
					}
					toolResults["sublist3r"] = subdomains
				}
			}
			rows.Close()
		}

		// Get Assetfinder results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM assetfinder_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["assetfinder"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get GAU results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM gau_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					var urls []string
					for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
						if line == "" {
							continue
						}
						var gauResult struct {
							URL string `json:"url"`
						}
						if err := json.Unmarshal([]byte(line), &gauResult); err == nil {
							if u, err := url.Parse(gauResult.URL); err == nil {
								urls = append(urls, u.Hostname())
							}
						}
					}
					toolResults["gau"] = urls
				}
			}
			rows.Close()
		}

		// Get CTL results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM ctl_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["ctl"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get Subfinder results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM subfinder_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["subfinder"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get ShuffleDNS results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM shuffledns_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["shuffledns"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get GoSpider results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM gospider_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["gospider"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get Subdomainizer results
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM subdomainizer_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					toolResults["subdomainizer"] = strings.Split(strings.TrimSpace(result), "\n")
				}
			}
			rows.Close()
		}

		// Get consolidated subdomains
		if rows, err := dbPool.Query(context.Background(), `
			SELECT subdomain FROM consolidated_subdomains 
			WHERE scope_target_id = $1
		`, targetID); err == nil {
			var consolidated []string
			for rows.Next() {
				var subdomain string
				if err := rows.Scan(&subdomain); err == nil {
					consolidated = append(consolidated, subdomain)
				}
			}
			toolResults["consolidated"] = consolidated
			rows.Close()
		}

		// Get live web servers from HTTPX
		if rows, err := dbPool.Query(context.Background(), `
			SELECT result FROM httpx_scans 
			WHERE scope_target_id = $1 AND result != '' 
			ORDER BY created_at DESC LIMIT 1
		`, targetID); err == nil {
			if rows.Next() {
				var result string
				if err := rows.Scan(&result); err == nil {
					var urls []string
					for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
						if line == "" {
							continue
						}
						var httpxResult struct {
							URL string `json:"url"`
						}
						if err := json.Unmarshal([]byte(line), &httpxResult); err == nil {
							urls = append(urls, httpxResult.URL)
						}
					}
					toolResults["httpx"] = urls
				}
			}
			rows.Close()
		}

		// Find the maximum number of subdomains across all tools
		maxSubdomains := 0
		for _, results := range toolResults {
			if len(results) > maxSubdomains {
				maxSubdomains = len(results)
			}
		}

		// Write rows until we've included all subdomains
		toolOrder := []string{
			"sublist3r", "assetfinder", "gau", "ctl", "subfinder",
			"shuffledns", "gospider", "subdomainizer", "consolidated", "httpx",
		}

		for i := 0; i < maxSubdomains; i++ {
			record := make([]string, len(toolOrder)+1) // +1 for target
			record[0] = target

			for j, tool := range toolOrder {
				if results, ok := toolResults[tool]; ok && i < len(results) {
					record[j+1] = results[i]
				}
			}

			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	return addFileToZip(zipWriter, subdomainsFile, "subdomains_data.csv")
}

func addFileToZip(zipWriter *zip.Writer, filePath, zipPath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer, err := zipWriter.Create(zipPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}
