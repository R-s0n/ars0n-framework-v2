package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

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

	go ExecuteAndParseKatanaURLScan(scanID, targetURL)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseKatanaURLScan(scanID, targetURL string) {
	log.Printf("[INFO] Starting Katana URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

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

	result := stdout.String()
	log.Printf("[INFO] Katana URL scan completed in %s for %s", execTime, targetURL)
	log.Printf("[DEBUG] Found %d URLs", len(strings.Split(result, "\n")))

	UpdateKatanaURLScanStatus(scanID, "success", result, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateKatanaURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE katana_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Katana URL scan status: %v", err)
	}
}

func GetKatanaURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM katana_url_scans WHERE scan_id = $1`
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
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
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
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

	go ExecuteAndParseLinkFinderURLScan(scanID, targetURL)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseLinkFinderURLScan(scanID, targetURL string) {
	log.Printf("[INFO] Starting LinkFinder URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

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

	result := stdout.String()
	log.Printf("[INFO] LinkFinder URL scan completed in %s for %s", execTime, targetURL)

	UpdateLinkFinderURLScanStatus(scanID, "success", result, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateLinkFinderURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE linkfinder_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update LinkFinder URL scan status: %v", err)
	}
}

func GetLinkFinderURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM linkfinder_url_scans WHERE scan_id = $1`
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
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
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
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

	go ExecuteAndParseWaybackURLsScan(scanID, targetURL)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseWaybackURLsScan(scanID, targetURL string) {
	log.Printf("[INFO] Starting WaybackURLs scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

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

	result := stdout.String()
	log.Printf("[INFO] WaybackURLs scan completed in %s for %s", execTime, targetURL)
	log.Printf("[DEBUG] Found %d URLs", len(strings.Split(result, "\n")))

	UpdateWaybackURLsScanStatus(scanID, "success", result, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateWaybackURLsScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE waybackurls_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update WaybackURLs scan status: %v", err)
	}
}

func GetWaybackURLsScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM waybackurls_scans WHERE scan_id = $1`
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
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
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
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

	go ExecuteAndParseGAUURLScan(scanID, targetURL)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseGAUURLScan(scanID, targetURL string) {
	log.Printf("[INFO] Starting GAU URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

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

	result := stdout.String()
	log.Printf("[INFO] GAU URL scan completed in %s for %s", execTime, targetURL)
	log.Printf("[DEBUG] Found %d URLs", len(strings.Split(result, "\n")))

	UpdateGAUURLScanStatus(scanID, "success", result, "", strings.Join(dockerCmd, " "), execTime)
}

func UpdateGAUURLScanStatus(scanID, status, result, errorMsg, command, execTime string) {
	query := `UPDATE gau_url_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GAU URL scan status: %v", err)
	}
}

func GetGAUURLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM gau_url_scans WHERE scan_id = $1`
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

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at 
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
		}

		err := rows.Scan(&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
			&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt)
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
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
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
				var customPath string
				wordlistQuery := `SELECT path FROM ffuf_wordlists WHERE id = $1`
				if dbPool.QueryRow(context.Background(), wordlistQuery, config.WordlistID).Scan(&customPath) == nil {
					wordlistPath = customPath
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

