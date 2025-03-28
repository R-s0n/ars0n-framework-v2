package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"ars0n-framework-v2-server/utils"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("Environment variable DATABASE_URL is not set")
	}

	var err error
	for i := 0; i < 10; i++ {
		dbPool, err = pgxpool.New(context.Background(), connStr)
		if err == nil {
			err = dbPool.Ping(context.Background())
		}
		if err == nil {
			fmt.Println("Connected to the database successfully!")
			break
		}
		log.Printf("Failed to connect to the database: %v. Retrying in 5 seconds...", err)
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		log.Fatalf("Could not connect to the database: %v", err)
	}
	utils.InitDB(dbPool)
	defer dbPool.Close()

	createTables()

	r := mux.NewRouter()

	// Apply CORS middleware first
	r.Use(corsMiddleware)

	// Define routes
	r.HandleFunc("/scopetarget/add", utils.CreateScopeTarget).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/read", utils.ReadScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/delete/{id}", utils.DeleteScopeTarget).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/activate", utils.ActivateScopeTarget).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/amass", utils.GetAmassScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/run", utils.RunAmassScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/amass/{scanID}", utils.GetAmassScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/dns", utils.GetDNSRecords).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/ip", utils.GetIPs).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/subdomain", utils.GetSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/cloud", utils.GetCloudDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/sp", utils.GetServiceProviders).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/asn", utils.GetASNs).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/subnet", utils.GetSubnets).Methods("GET", "OPTIONS")
	r.HandleFunc("/httpx/run", utils.RunHttpxScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/httpx/{scanID}", utils.GetHttpxScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/httpx", utils.GetHttpxScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans", utils.GetAllScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/gau/run", utils.RunGauScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/gau/{scanID}", utils.GetGauScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/gau", utils.GetGauScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/sublist3r/run", utils.RunSublist3rScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/sublist3r/{scan_id}", utils.GetSublist3rScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/sublist3r", utils.GetSublist3rScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/assetfinder/run", utils.RunAssetfinderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/assetfinder/{scan_id}", utils.GetAssetfinderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/assetfinder", utils.GetAssetfinderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/ctl/run", utils.RunCTLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ctl/{scan_id}", utils.GetCTLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/ctl", utils.GetCTLScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/subfinder/run", utils.RunSubfinderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/subfinder/{scan_id}", utils.GetSubfinderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/subfinder", utils.GetSubfinderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-subdomains/{id}", utils.HandleConsolidateSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidated-subdomains/{id}", utils.GetConsolidatedSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/shuffledns/run", utils.RunShuffleDNSScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/shuffledns/{scan_id}", utils.GetShuffleDNSScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/shuffledns", utils.GetShuffleDNSScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/cewl/run", utils.RunCeWLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl/{scan_id}", utils.GetCeWLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/cewl", utils.GetCeWLScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/cewl-urls/run", utils.RunCeWLScansForUrls).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl-wordlist/run", utils.RunShuffleDNSWithWordlist).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl-wordlist/{scan_id}", utils.GetShuffleDNSScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/scope-targets/{id}/shufflednscustom-scans", utils.GetShuffleDNSCustomScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/gospider/run", utils.RunGoSpiderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/gospider/{scan_id}", utils.GetGoSpiderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/gospider", utils.GetGoSpiderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/subdomainizer/run", utils.RunSubdomainizerScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/subdomainizer/{scan_id}", utils.GetSubdomainizerScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/subdomainizer", utils.GetSubdomainizerScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/nuclei-screenshot/run", utils.RunNucleiScreenshotScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/nuclei-screenshot", utils.GetNucleiScreenshotScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/nuclei-screenshot/run", utils.RunNucleiScreenshotScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/nuclei-screenshot/{scan_id}", utils.GetNucleiScreenshotScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/scope-targets/{id}/target-urls", utils.GetTargetURLsForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/metadata/run", utils.RunMetaDataScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/metadata/{scan_id}", utils.GetMetaDataScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/metadata", utils.GetMetaDataScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/target-urls/{id}/roi-score", utils.UpdateTargetURLROIScore).Methods("PUT", "OPTIONS")
	r.HandleFunc("/user/settings", getUserSettings).Methods("GET", "OPTIONS")
	r.HandleFunc("/user/settings", updateUserSettings).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/export-data", utils.HandleExportData).Methods("POST", "OPTIONS")

	log.Println("API server started on :8080")
	http.ListenAndServe(":8080", r)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getUserSettings(w http.ResponseWriter, r *http.Request) {
	// Get settings from the database
	var settings map[string]interface{} = make(map[string]interface{})

	row := dbPool.QueryRow(context.Background(), `
		SELECT 
			amass_rate_limit,
			httpx_rate_limit,
			subfinder_rate_limit,
			gau_rate_limit,
			sublist3r_rate_limit,
			ctl_rate_limit,
			shuffledns_rate_limit,
			cewl_rate_limit,
			gospider_rate_limit,
			subdomainizer_rate_limit,
			nuclei_screenshot_rate_limit,
			custom_user_agent,
			custom_header
		FROM user_settings
		LIMIT 1
	`)

	var amassRateLimit, httpxRateLimit, subfinderRateLimit, gauRateLimit,
		sublist3rRateLimit, ctlRateLimit, shufflednsRateLimit,
		cewlRateLimit, gospiderRateLimit, subdomainizerRateLimit, nucleiScreenshotRateLimit int
	var customUserAgent, customHeader sql.NullString

	err := row.Scan(
		&amassRateLimit,
		&httpxRateLimit,
		&subfinderRateLimit,
		&gauRateLimit,
		&sublist3rRateLimit,
		&ctlRateLimit,
		&shufflednsRateLimit,
		&cewlRateLimit,
		&gospiderRateLimit,
		&subdomainizerRateLimit,
		&nucleiScreenshotRateLimit,
		&customUserAgent,
		&customHeader,
	)

	if err != nil {
		log.Printf("Error fetching settings: %v", err)
		// Return default settings if there's an error
		settings = map[string]interface{}{
			"amass_rate_limit":             10,
			"httpx_rate_limit":             150,
			"subfinder_rate_limit":         20,
			"gau_rate_limit":               10,
			"sublist3r_rate_limit":         10,
			"ctl_rate_limit":               10,
			"shuffledns_rate_limit":        10000,
			"cewl_rate_limit":              10,
			"gospider_rate_limit":          5,
			"subdomainizer_rate_limit":     5,
			"nuclei_screenshot_rate_limit": 20,
			"custom_user_agent":            "",
			"custom_header":                "",
		}
	} else {
		settings = map[string]interface{}{
			"amass_rate_limit":             amassRateLimit,
			"httpx_rate_limit":             httpxRateLimit,
			"subfinder_rate_limit":         subfinderRateLimit,
			"gau_rate_limit":               gauRateLimit,
			"sublist3r_rate_limit":         sublist3rRateLimit,
			"ctl_rate_limit":               ctlRateLimit,
			"shuffledns_rate_limit":        shufflednsRateLimit,
			"cewl_rate_limit":              cewlRateLimit,
			"gospider_rate_limit":          gospiderRateLimit,
			"subdomainizer_rate_limit":     subdomainizerRateLimit,
			"nuclei_screenshot_rate_limit": nucleiScreenshotRateLimit,
			"custom_user_agent":            customUserAgent.String,
			"custom_header":                customHeader.String,
		}
	}

	// Return settings as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func updateUserSettings(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	var settings map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&settings)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log the received settings
	log.Printf("Received settings: %v", settings)

	// Update settings in the database
	_, err = dbPool.Exec(context.Background(), `
		UPDATE user_settings
		SET 
			amass_rate_limit = $1,
			httpx_rate_limit = $2,
			subfinder_rate_limit = $3,
			gau_rate_limit = $4,
			sublist3r_rate_limit = $5,
			ctl_rate_limit = $6,
			shuffledns_rate_limit = $7,
			cewl_rate_limit = $8,
			gospider_rate_limit = $9,
			subdomainizer_rate_limit = $10,
			nuclei_screenshot_rate_limit = $11,
			custom_user_agent = $12,
			custom_header = $13,
			updated_at = NOW()
	`,
		getIntSetting(settings, "amass_rate_limit", 10),
		getIntSetting(settings, "httpx_rate_limit", 150),
		getIntSetting(settings, "subfinder_rate_limit", 20),
		getIntSetting(settings, "gau_rate_limit", 10),
		getIntSetting(settings, "sublist3r_rate_limit", 10),
		getIntSetting(settings, "ctl_rate_limit", 10),
		getIntSetting(settings, "shuffledns_rate_limit", 10000),
		getIntSetting(settings, "cewl_rate_limit", 10),
		getIntSetting(settings, "gospider_rate_limit", 5),
		getIntSetting(settings, "subdomainizer_rate_limit", 5),
		getIntSetting(settings, "nuclei_screenshot_rate_limit", 20),
		settings["custom_user_agent"],
		settings["custom_header"],
	)

	if err != nil {
		log.Printf("Error updating settings: %v", err)
		http.Error(w, "Failed to update settings", http.StatusInternalServerError)
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success": true}`))
}

// Helper function to get integer settings with default values
func getIntSetting(settings map[string]interface{}, key string, defaultValue int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				return intVal
			}
		}
	}
	return defaultValue
}

// The createTables function is already defined in database.go
// func createTables() {
// 	// Create the tables if they don't exist
// 	_, err := dbPool.Exec(context.Background(), `
// 		CREATE TABLE IF NOT EXISTS scope_targets (
// 			id SERIAL PRIMARY KEY,
// 			type VARCHAR(255) NOT NULL,
// 			mode VARCHAR(255) NOT NULL,
// 			scope_target VARCHAR(255) NOT NULL,
// 			active BOOLEAN DEFAULT false,
// 			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
// 		);

// 		CREATE TABLE IF NOT EXISTS user_settings (
// 			id SERIAL PRIMARY KEY,
// 			amass_rate_limit INTEGER DEFAULT 10,
// 			httpx_rate_limit INTEGER DEFAULT 150,
// 			subfinder_rate_limit INTEGER DEFAULT 20,
// 			gau_rate_limit INTEGER DEFAULT 10,
// 			sublist3r_rate_limit INTEGER DEFAULT 10,
// 			assetfinder_rate_limit INTEGER DEFAULT 10,
// 			ctl_rate_limit INTEGER DEFAULT 10,
// 			shuffledns_rate_limit INTEGER DEFAULT 10,
// 			cewl_rate_limit INTEGER DEFAULT 10,
// 			gospider_rate_limit INTEGER DEFAULT 5,
// 			subdomainizer_rate_limit INTEGER DEFAULT 5,
// 			nuclei_screenshot_rate_limit INTEGER DEFAULT 20,
// 			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
// 			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
// 		);

// 		-- Insert default settings if none exist
// 		INSERT INTO user_settings (id)
// 		SELECT 1
// 		WHERE NOT EXISTS (SELECT 1 FROM user_settings WHERE id = 1);
// 	`)
// 	if err != nil {
// 		log.Fatalf("Error creating tables: %v", err)
// 	}
// }
