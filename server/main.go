package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"ars0n-framework-v2-server/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func min(a, b int) int {
	return int(math.Min(float64(a), float64(b)))
}

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
	r.HandleFunc("/amass-intel/run", utils.RunAmassIntelScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/amass-intel/{scanID}", utils.GetAmassIntelScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/amass-intel", utils.GetAmassIntelScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-intel/{scan_id}/networks", utils.GetIntelNetworkRanges).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-intel/{scan_id}/asn", utils.GetIntelASNData).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-intel/network-range/{id}", utils.DeleteIntelNetworkRange).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/amass-intel/scan/{scan_id}/network-ranges", utils.DeleteAllIntelNetworkRanges).Methods("DELETE", "OPTIONS")
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
	r.HandleFunc("/ctl-company/run", utils.RunCTLCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ctl-company/{scan_id}", utils.GetCTLCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/ctl-company", utils.GetCTLCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/cloud-enum/run", utils.RunCloudEnumScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/cloud-enum/{scan_id}", utils.GetCloudEnumScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/cloud-enum", utils.GetCloudEnumScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/metabigor-company/run", utils.RunMetabigorCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/metabigor-company/{scan_id}", utils.GetMetabigorCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/metabigor-company", utils.GetMetabigorCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/metabigor-company/{scan_id}/networks", utils.GetMetabigorNetworkRanges).Methods("GET", "OPTIONS")
	r.HandleFunc("/metabigor/network-range/{id}", utils.DeleteMetabigorNetworkRange).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/metabigor/scan/{scan_id}/network-ranges", utils.DeleteAllMetabigorNetworkRanges).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/metabigor-company/{scan_id}/asn", utils.GetMetabigorASNData).Methods("GET", "OPTIONS")
	r.HandleFunc("/metabigor-netd/run", utils.RunMetabigorNetdScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/metabigor-asn/run", utils.RunMetabigorASNScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/metabigor-ip/run", utils.RunMetabigorIPIntelligence).Methods("POST", "OPTIONS")
	r.HandleFunc("/metabigor-ip/{scan_id}/intelligence", utils.GetMetabigorIPIntelligence).Methods("GET", "OPTIONS")
	r.HandleFunc("/subfinder/run", utils.RunSubfinderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/subfinder/{scan_id}", utils.GetSubfinderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/subfinder", utils.GetSubfinderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-subdomains/{id}", utils.HandleConsolidateSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidated-subdomains/{id}", utils.GetConsolidatedSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-company-domains/{id}", utils.HandleConsolidateCompanyDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidated-company-domains/{id}", utils.GetConsolidatedCompanyDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-network-ranges/{id}", utils.HandleConsolidateNetworkRanges).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidated-network-ranges/{id}", utils.GetConsolidatedNetworkRanges).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-attack-surface/{scope_target_id}", utils.ConsolidateAttackSurface).Methods("POST", "OPTIONS")
	r.HandleFunc("/investigate-fqdns/{scope_target_id}", utils.InvestigateFQDNs).Methods("POST", "OPTIONS")
	r.HandleFunc("/attack-surface-asset-counts/{scope_target_id}", utils.GetAttackSurfaceAssetCounts).Methods("GET", "OPTIONS")
	r.HandleFunc("/attack-surface-assets/{scope_target_id}", utils.GetAttackSurfaceAssets).Methods("GET", "OPTIONS")
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
	r.HandleFunc("/metadata/run-company", utils.RunCompanyMetaDataScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ip-port-scan/{scan_id}/metadata-scans", utils.GetCompanyMetaDataScansForIPPortScan).Methods("GET", "OPTIONS")
	r.HandleFunc("/ip-port-scan/{scan_id}/metadata-results", utils.GetCompanyMetaDataResults).Methods("GET", "OPTIONS")
	r.HandleFunc("/investigate/run", utils.RunInvestigateScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/investigate/{scan_id}", utils.GetInvestigateScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/investigate", utils.GetInvestigateScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/target-urls/{id}/roi-score", utils.UpdateTargetURLROIScore).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/target-urls/{id}", utils.DeleteTargetURL).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/user/settings", getUserSettings).Methods("GET", "OPTIONS")
	r.HandleFunc("/user/settings", updateUserSettings).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/export-data", utils.HandleExportData).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/database-export", utils.HandleDatabaseExport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/database-import", utils.HandleDatabaseImport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/database-import-url", utils.HandleDatabaseImportURL).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/debug-export-file", utils.DebugExportFile).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/scope-targets-for-export", utils.GetScopeTargetsForExport).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/auto-scan-state/{target_id}", getAutoScanState).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/auto-scan-state/{target_id}", updateAutoScanState).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/auto-scan-config", getAutoScanConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/auto-scan-config", updateAutoScanConfig).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/auto-scan/session/start", startAutoScanSession).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/auto-scan/session/{id}", getAutoScanSession).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/auto-scan/sessions", listAutoScanSessions).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/auto-scan/session/{id}/cancel", cancelAutoScanSession).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/auto-scan/session/{id}/final-stats", updateAutoScanSessionFinalStats).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/google-dorking-domains", createGoogleDorkingDomain).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/google-dorking-domains/{target_id}", getGoogleDorkingDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/google-dorking-domains/{domain_id}", deleteGoogleDorkingDomain).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/reverse-whois-domains", createReverseWhoisDomain).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/reverse-whois-domains/{target_id}", getReverseWhoisDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/reverse-whois-domains/{domain_id}", deleteReverseWhoisDomain).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/api-keys", getAPIKeys).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/api-keys", createAPIKey).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/api-keys/{id}", updateAPIKey).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/api-keys/{id}", deleteAPIKey).Methods("DELETE", "OPTIONS")

	// AI API Keys routes
	r.HandleFunc("/api/ai-api-keys", getAiAPIKeys).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/ai-api-keys", createAiAPIKey).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/ai-api-keys/{id}", updateAiAPIKey).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/ai-api-keys/{id}", deleteAiAPIKey).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/securitytrails-company/run", utils.RunSecurityTrailsCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/securitytrails-company/status/{scan_id}", utils.GetSecurityTrailsCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/securitytrails-company", utils.GetSecurityTrailsCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/censys-company/run", utils.RunCensysCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/censys-company/status/{scan_id}", utils.GetCensysCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/censys-company", utils.GetCensysCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/shodan-company/run", utils.RunShodanCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/shodan-company/status/{scan_id}", utils.GetShodanCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/shodan-company", utils.GetShodanCompanyScansForScopeTarget).Methods("GET", "OPTIONS")

	// GitHub Recon routes
	r.HandleFunc("/github-recon/run", utils.RunGitHubReconScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/github-recon/status/{scan_id}", utils.GetGitHubReconScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/github-recon", utils.GetGitHubReconScansForScopeTarget).Methods("GET", "OPTIONS")

	// IP/Port scan routes
	r.HandleFunc("/ip-port-scan/run", utils.RunIPPortScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ip-port-scan/status/{scan_id}", utils.GetIPPortScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/ip-port", utils.GetIPPortScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/ip-port-scan/{scan_id}/live-web-servers", utils.GetLiveWebServers).Methods("GET", "OPTIONS")
	r.HandleFunc("/ip-port-scan/{scan_id}/discovered-ips", utils.GetDiscoveredIPs).Methods("GET", "OPTIONS")

	// Company domain management routes
	r.HandleFunc("/api/company-domains/{scope_target_id}/{tool}", getCompanyDomainsByTool).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/company-domains/{scope_target_id}/{tool}/all", deleteAllCompanyDomainsFromTool).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/company-domains/{scope_target_id}/{tool}/{domain}", deleteCompanyDomainFromTool).Methods("DELETE", "OPTIONS")

	// Amass Enum configuration routes
	r.HandleFunc("/amass-enum-config/{scope_target_id}", getAmassEnumConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-enum-config/{scope_target_id}", saveAmassEnumConfig).Methods("POST", "OPTIONS")

	// Amass Enum Company scan routes
	r.HandleFunc("/amass-enum-company/run/{scope_target_id}", utils.RunAmassEnumCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/amass-enum-company/status/{scan_id}", utils.GetAmassEnumCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/amass-enum-company", utils.GetAmassEnumCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-enum-company/{scan_id}/cloud-domains", utils.GetAmassEnumCloudDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-enum-company/{scan_id}/raw-results", utils.GetAmassEnumRawResults).Methods("GET", "OPTIONS")

	// Amass Intel configuration routes
	r.HandleFunc("/amass-intel-config/{scope_target_id}", getAmassIntelConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass-intel-config/{scope_target_id}", saveAmassIntelConfig).Methods("POST", "OPTIONS")

	// DNSx configuration routes
	r.HandleFunc("/dnsx-config/{scope_target_id}", getDNSxConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/dnsx-config/{scope_target_id}", saveDNSxConfig).Methods("POST", "OPTIONS")

	// Cloud Enum configuration routes
	r.HandleFunc("/cloud-enum-config/{scope_target_id}", getCloudEnumConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/cloud-enum-config/{scope_target_id}", saveCloudEnumConfig).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/build-wordlist/{scope_target_id}/{type}", buildWordlistFromDomains).Methods("POST", "OPTIONS")

	// DNSx Company scan routes
	r.HandleFunc("/dnsx-company/run/{scope_target_id}", utils.RunDNSxCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/dnsx-company/status/{scan_id}", utils.GetDNSxCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/dnsx-company", utils.GetDNSxCompanyScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/dnsx-company/{scan_id}/dns-records", utils.GetDNSxDNSRecords).Methods("GET", "OPTIONS")
	r.HandleFunc("/dnsx-company/{scan_id}/raw-results", utils.GetDNSxRawResults).Methods("GET", "OPTIONS")

	// Katana Company configuration routes
	r.HandleFunc("/katana-company-config/{scope_target_id}", getKatanaCompanyConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/katana-company-config/{scope_target_id}", saveKatanaCompanyConfig).Methods("POST", "OPTIONS")
	r.HandleFunc("/nuclei-config/{scope_target_id}", getNucleiConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/nuclei-config/{scope_target_id}", saveNucleiConfig).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/nuclei", getNucleiScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/nuclei/start", startNucleiScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/nuclei-scan/{scan_id}/status", getNucleiScanStatus).Methods("GET", "OPTIONS")

	// Katana Company scan routes
	r.HandleFunc("/katana-company/run/{scope_target_id}", utils.RunKatanaCompanyScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/katana-company/status/{scan_id}", utils.GetKatanaCompanyScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/katana-company", utils.GetKatanaCompanyScansForScopeTarget).Methods("GET", "OPTIONS")

	// Katana Company scope target-based routes (all scans)
	r.HandleFunc("/katana-company/target/{scope_target_id}/cloud-assets", utils.GetKatanaCompanyCloudAssetsByTarget).Methods("GET", "OPTIONS")

	// Live web servers count route
	r.HandleFunc("/scope-target/{scope_target_id}/live-web-servers-count", getLiveWebServersCount).Methods("GET", "OPTIONS")

	// Burpsuite populate route
	r.HandleFunc("/burpsuite/populate", populateBurpsuite).Methods("POST", "OPTIONS")

	// API Populator route
	r.HandleFunc("/api-populator/process", processApiEndpoint).Methods("POST", "OPTIONS")

	// URL Workflow scan routes
	r.HandleFunc("/katana-url/run", utils.RunKatanaURLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/katana-url/status/{scan_id}", utils.GetKatanaURLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/katana-url", utils.GetKatanaURLScansForScopeTarget).Methods("GET", "OPTIONS")
	
	r.HandleFunc("/linkfinder-url/run", utils.RunLinkFinderURLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/linkfinder-url/status/{scan_id}", utils.GetLinkFinderURLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/linkfinder-url", utils.GetLinkFinderURLScansForScopeTarget).Methods("GET", "OPTIONS")
	
	r.HandleFunc("/waybackurls/run", utils.RunWaybackURLsScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/waybackurls/status/{scan_id}", utils.GetWaybackURLsScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/waybackurls", utils.GetWaybackURLsScansForScopeTarget).Methods("GET", "OPTIONS")
	
	r.HandleFunc("/gau-url/run", utils.RunGAUURLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/gau-url/status/{scan_id}", utils.GetGAUURLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/gau-url", utils.GetGAUURLScansForScopeTarget).Methods("GET", "OPTIONS")
	
	r.HandleFunc("/ffuf-url/run", utils.RunFFUFURLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ffuf-url/status/{scan_id}", utils.GetFFUFURLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/ffuf-url", utils.GetFFUFURLScansForScopeTarget).Methods("GET", "OPTIONS")

	r.HandleFunc("/ffuf-config/{scope_target_id}", utils.SaveFFUFConfig).Methods("POST", "OPTIONS")
	r.HandleFunc("/ffuf-config/{scope_target_id}", utils.GetFFUFConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/ffuf-wordlists/upload", utils.UploadFFUFWordlist).Methods("POST", "OPTIONS")
	r.HandleFunc("/ffuf-wordlists", utils.GetFFUFWordlists).Methods("GET", "OPTIONS")
	r.HandleFunc("/ffuf-wordlists/{wordlist_id}", utils.DeleteFFUFWordlist).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/application-questions/{scope_target_id}/answers", utils.GetApplicationQuestionsAnswers).Methods("GET", "OPTIONS")
	r.HandleFunc("/application-questions/{scope_target_id}/answers", utils.CreateApplicationQuestionAnswer).Methods("POST", "OPTIONS")
	r.HandleFunc("/application-questions/answers/{answer_id}", utils.UpdateApplicationQuestionAnswer).Methods("PUT", "OPTIONS")
	r.HandleFunc("/application-questions/answers/{answer_id}", utils.DeleteApplicationQuestionAnswer).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/mechanisms/{scope_target_id}/examples", utils.GetMechanismsExamples).Methods("GET", "OPTIONS")
	r.HandleFunc("/mechanisms/{scope_target_id}/examples", utils.CreateMechanismExample).Methods("POST", "OPTIONS")
	r.HandleFunc("/mechanisms/examples/{example_id}", utils.UpdateMechanismExample).Methods("PUT", "OPTIONS")
	r.HandleFunc("/mechanisms/examples/{example_id}", utils.DeleteMechanismExample).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/notable-objects/{scope_target_id}", utils.GetNotableObjects).Methods("GET", "OPTIONS")
	r.HandleFunc("/notable-objects/{scope_target_id}", utils.CreateNotableObject).Methods("POST", "OPTIONS")
	r.HandleFunc("/notable-objects/{object_id}", utils.UpdateNotableObject).Methods("PUT", "OPTIONS")
	r.HandleFunc("/notable-objects/{object_id}", utils.DeleteNotableObject).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/security-controls/{scope_target_id}/notes", utils.GetSecurityControlsNotes).Methods("GET", "OPTIONS")
	r.HandleFunc("/security-controls/{scope_target_id}/notes", utils.CreateSecurityControlNote).Methods("POST", "OPTIONS")
	r.HandleFunc("/security-controls/notes/{note_id}", utils.UpdateSecurityControlNote).Methods("PUT", "OPTIONS")
	r.HandleFunc("/security-controls/notes/{note_id}", utils.DeleteSecurityControlNote).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/threat-model/{scope_target_id}", utils.GetThreatModel).Methods("GET", "OPTIONS")
	r.HandleFunc("/threat-model/{scope_target_id}", utils.CreateThreatModel).Methods("POST", "OPTIONS")
	r.HandleFunc("/threat-model/{threat_id}", utils.UpdateThreatModel).Methods("PUT", "OPTIONS")
	r.HandleFunc("/threat-model/{threat_id}", utils.DeleteThreatModel).Methods("DELETE", "OPTIONS")

	log.Println("API server started on :8443")
	http.ListenAndServe(":8443", r)
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
			custom_header,
			burp_proxy_ip,
			burp_proxy_port,
			burp_api_ip,
			burp_api_port,
			burp_api_key
		FROM user_settings
		LIMIT 1
	`)

	var amassRateLimit, httpxRateLimit, subfinderRateLimit, gauRateLimit,
		sublist3rRateLimit, ctlRateLimit, shufflednsRateLimit,
		cewlRateLimit, gospiderRateLimit, subdomainizerRateLimit, nucleiScreenshotRateLimit,
		burpProxyPort, burpApiPort int
	var customUserAgent, customHeader, burpProxyIP, burpApiIP, burpApiKey sql.NullString

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
		&burpProxyIP,
		&burpProxyPort,
		&burpApiIP,
		&burpApiPort,
		&burpApiKey,
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
			"burp_proxy_ip":                "127.0.0.1",
			"burp_proxy_port":              8080,
			"burp_api_ip":                  "127.0.0.1",
			"burp_api_port":                1337,
			"burp_api_key":                 "",
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
			"burp_proxy_ip":                burpProxyIP.String,
			"burp_proxy_port":              burpProxyPort,
			"burp_api_ip":                  burpApiIP.String,
			"burp_api_port":                burpApiPort,
			"burp_api_key":                 burpApiKey.String,
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
			burp_proxy_ip = $14,
			burp_proxy_port = $15,
			burp_api_ip = $16,
			burp_api_port = $17,
			burp_api_key = $18,
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
		getStringSetting(settings, "burp_proxy_ip", "127.0.0.1"),
		getIntSetting(settings, "burp_proxy_port", 8080),
		getStringSetting(settings, "burp_api_ip", "127.0.0.1"),
		getIntSetting(settings, "burp_api_port", 1337),
		getStringSetting(settings, "burp_api_key", ""),
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

// Helper function to get string settings with default values
func getStringSetting(settings map[string]interface{}, key string, defaultValue string) string {
	if val, ok := settings[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultValue
}

// getAutoScanState retrieves the current auto scan state for a target
func getAutoScanState(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetID := vars["target_id"]

	// First try with new columns
	var state struct {
		ID            string    `json:"id"`
		ScopeTargetID string    `json:"scope_target_id"`
		CurrentStep   string    `json:"current_step"`
		IsPaused      bool      `json:"is_paused"`
		IsCancelled   bool      `json:"is_cancelled"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), `
		SELECT id, scope_target_id, current_step, 
		COALESCE((SELECT column_name FROM information_schema.columns WHERE table_name='auto_scan_state' AND column_name='is_paused') IS NOT NULL AND is_paused, false) as is_paused,
		COALESCE((SELECT column_name FROM information_schema.columns WHERE table_name='auto_scan_state' AND column_name='is_cancelled') IS NOT NULL AND is_cancelled, false) as is_cancelled,
		created_at, updated_at
		FROM auto_scan_state
		WHERE scope_target_id = $1
	`, targetID).Scan(&state.ID, &state.ScopeTargetID, &state.CurrentStep, &state.IsPaused, &state.IsCancelled, &state.CreatedAt, &state.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			// No state found, return empty object with IDLE state
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"scope_target_id": targetID,
				"current_step":    "IDLE",
				"is_paused":       false,
				"is_cancelled":    false,
			})
			return
		}

		// If the error is about missing columns, try the fallback query
		if strings.Contains(err.Error(), "column") && (strings.Contains(err.Error(), "is_paused") || strings.Contains(err.Error(), "is_cancelled")) {
			var basicState struct {
				ID            string    `json:"id"`
				ScopeTargetID string    `json:"scope_target_id"`
				CurrentStep   string    `json:"current_step"`
				CreatedAt     time.Time `json:"created_at"`
				UpdatedAt     time.Time `json:"updated_at"`
			}

			fallbackErr := dbPool.QueryRow(context.Background(), `
				SELECT id, scope_target_id, current_step, created_at, updated_at
				FROM auto_scan_state
				WHERE scope_target_id = $1
			`, targetID).Scan(&basicState.ID, &basicState.ScopeTargetID, &basicState.CurrentStep, &basicState.CreatedAt, &basicState.UpdatedAt)

			if fallbackErr == nil {
				// Successfully got basic state, return it with default pause/cancel values
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id":              basicState.ID,
					"scope_target_id": basicState.ScopeTargetID,
					"current_step":    basicState.CurrentStep,
					"is_paused":       false,
					"is_cancelled":    false,
					"created_at":      basicState.CreatedAt,
					"updated_at":      basicState.UpdatedAt,
				})
				return
			}

			// If even the fallback failed with no rows, return idle state
			if fallbackErr == pgx.ErrNoRows {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"scope_target_id": targetID,
					"current_step":    "IDLE",
					"is_paused":       false,
					"is_cancelled":    false,
				})
				return
			}
		}

		log.Printf("Error fetching auto scan state: %v", err)
		http.Error(w, "Failed to fetch auto scan state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

// updateAutoScanState updates the current auto scan state for a target
func updateAutoScanState(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetID := vars["target_id"]

	var requestData struct {
		CurrentStep string `json:"current_step"`
		IsPaused    bool   `json:"is_paused"`
		IsCancelled bool   `json:"is_cancelled"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if requestData.CurrentStep == "" {
		http.Error(w, "Current step is required", http.StatusBadRequest)
		return
	}

	// First check if columns exist
	var hasPausedColumn, hasCancelledColumn bool
	err = dbPool.QueryRow(context.Background(), `
		SELECT 
			EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='auto_scan_state' AND column_name='is_paused') as has_paused,
			EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='auto_scan_state' AND column_name='is_cancelled') as has_cancelled
	`).Scan(&hasPausedColumn, &hasCancelledColumn)

	if err != nil {
		log.Printf("Error checking for columns: %v", err)
		http.Error(w, "Failed to update auto scan state", http.StatusInternalServerError)
		return
	}

	var execErr error
	if hasPausedColumn && hasCancelledColumn {
		// Use upsert with all columns
		_, execErr = dbPool.Exec(context.Background(), `
			INSERT INTO auto_scan_state (scope_target_id, current_step, is_paused, is_cancelled)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (scope_target_id)
			DO UPDATE SET 
				current_step = $2, 
				is_paused = $3, 
				is_cancelled = $4, 
				updated_at = NOW()
		`, targetID, requestData.CurrentStep, requestData.IsPaused, requestData.IsCancelled)
	} else {
		// Use upsert with only current_step
		_, execErr = dbPool.Exec(context.Background(), `
			INSERT INTO auto_scan_state (scope_target_id, current_step)
			VALUES ($1, $2)
			ON CONFLICT (scope_target_id)
			DO UPDATE SET 
				current_step = $2, 
				updated_at = NOW()
		`, targetID, requestData.CurrentStep)

		// Try to add the missing columns
		_, alterErr := dbPool.Exec(context.Background(), `
			ALTER TABLE auto_scan_state 
			ADD COLUMN IF NOT EXISTS is_paused BOOLEAN DEFAULT false,
			ADD COLUMN IF NOT EXISTS is_cancelled BOOLEAN DEFAULT false;
		`)
		if alterErr != nil {
			log.Printf("Error adding missing columns: %v", alterErr)
		}
	}

	if execErr != nil {
		log.Printf("Error updating auto scan state: %v", execErr)
		http.Error(w, "Failed to update auto scan state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"scope_target_id": targetID,
		"current_step":    requestData.CurrentStep,
		"is_paused":       requestData.IsPaused,
		"is_cancelled":    requestData.IsCancelled,
	})
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

func getAutoScanConfig(w http.ResponseWriter, r *http.Request) {
	row := dbPool.QueryRow(context.Background(), `
		SELECT amass, sublist3r, assetfinder, gau, ctl, subfinder, consolidate_httpx_round1, shuffledns, cewl, consolidate_httpx_round2, gospider, subdomainizer, consolidate_httpx_round3, nuclei_screenshot, metadata, max_consolidated_subdomains, max_live_web_servers
		FROM auto_scan_config
		LIMIT 1
	`)
	var config struct {
		Amass                     bool `json:"amass"`
		Sublist3r                 bool `json:"sublist3r"`
		Assetfinder               bool `json:"assetfinder"`
		Gau                       bool `json:"gau"`
		Ctl                       bool `json:"ctl"`
		Subfinder                 bool `json:"subfinder"`
		ConsolidateHttpxRound1    bool `json:"consolidate_httpx_round1"`
		Shuffledns                bool `json:"shuffledns"`
		Cewl                      bool `json:"cewl"`
		ConsolidateHttpxRound2    bool `json:"consolidate_httpx_round2"`
		Gospider                  bool `json:"gospider"`
		Subdomainizer             bool `json:"subdomainizer"`
		ConsolidateHttpxRound3    bool `json:"consolidate_httpx_round3"`
		NucleiScreenshot          bool `json:"nuclei_screenshot"`
		Metadata                  bool `json:"metadata"`
		MaxConsolidatedSubdomains int  `json:"maxConsolidatedSubdomains"`
		MaxLiveWebServers         int  `json:"maxLiveWebServers"`
	}
	err := row.Scan(
		&config.Amass,
		&config.Sublist3r,
		&config.Assetfinder,
		&config.Gau,
		&config.Ctl,
		&config.Subfinder,
		&config.ConsolidateHttpxRound1,
		&config.Shuffledns,
		&config.Cewl,
		&config.ConsolidateHttpxRound2,
		&config.Gospider,
		&config.Subdomainizer,
		&config.ConsolidateHttpxRound3,
		&config.NucleiScreenshot,
		&config.Metadata,
		&config.MaxConsolidatedSubdomains,
		&config.MaxLiveWebServers,
	)
	if err != nil {
		// Return defaults if not found
		config = struct {
			Amass                     bool `json:"amass"`
			Sublist3r                 bool `json:"sublist3r"`
			Assetfinder               bool `json:"assetfinder"`
			Gau                       bool `json:"gau"`
			Ctl                       bool `json:"ctl"`
			Subfinder                 bool `json:"subfinder"`
			ConsolidateHttpxRound1    bool `json:"consolidate_httpx_round1"`
			Shuffledns                bool `json:"shuffledns"`
			Cewl                      bool `json:"cewl"`
			ConsolidateHttpxRound2    bool `json:"consolidate_httpx_round2"`
			Gospider                  bool `json:"gospider"`
			Subdomainizer             bool `json:"subdomainizer"`
			ConsolidateHttpxRound3    bool `json:"consolidate_httpx_round3"`
			NucleiScreenshot          bool `json:"nuclei_screenshot"`
			Metadata                  bool `json:"metadata"`
			MaxConsolidatedSubdomains int  `json:"maxConsolidatedSubdomains"`
			MaxLiveWebServers         int  `json:"maxLiveWebServers"`
		}{
			Amass: true, Sublist3r: true, Assetfinder: true, Gau: true, Ctl: true, Subfinder: true, ConsolidateHttpxRound1: true, Shuffledns: true, Cewl: true, ConsolidateHttpxRound2: true, Gospider: true, Subdomainizer: true, ConsolidateHttpxRound3: true, NucleiScreenshot: true, Metadata: true, MaxConsolidatedSubdomains: 2500, MaxLiveWebServers: 500,
		}
	}
	log.Printf("[AutoScanConfig] GET: %+v", config)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func updateAutoScanConfig(w http.ResponseWriter, r *http.Request) {
	var config struct {
		Amass                     bool `json:"amass"`
		Sublist3r                 bool `json:"sublist3r"`
		Assetfinder               bool `json:"assetfinder"`
		Gau                       bool `json:"gau"`
		Ctl                       bool `json:"ctl"`
		Subfinder                 bool `json:"subfinder"`
		ConsolidateHttpxRound1    bool `json:"consolidate_httpx_round1"`
		Shuffledns                bool `json:"shuffledns"`
		Cewl                      bool `json:"cewl"`
		ConsolidateHttpxRound2    bool `json:"consolidate_httpx_round2"`
		Gospider                  bool `json:"gospider"`
		Subdomainizer             bool `json:"subdomainizer"`
		ConsolidateHttpxRound3    bool `json:"consolidate_httpx_round3"`
		NucleiScreenshot          bool `json:"nuclei_screenshot"`
		Metadata                  bool `json:"metadata"`
		MaxConsolidatedSubdomains int  `json:"maxConsolidatedSubdomains"`
		MaxLiveWebServers         int  `json:"maxLiveWebServers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	log.Printf("[AutoScanConfig] POST: %+v", config)
	_, err := dbPool.Exec(context.Background(), `
		UPDATE auto_scan_config SET
			amass = $1,
			sublist3r = $2,
			assetfinder = $3,
			gau = $4,
			ctl = $5,
			subfinder = $6,
			consolidate_httpx_round1 = $7,
			shuffledns = $8,
			cewl = $9,
			consolidate_httpx_round2 = $10,
			gospider = $11,
			subdomainizer = $12,
			consolidate_httpx_round3 = $13,
			nuclei_screenshot = $14,
			metadata = $15,
			max_consolidated_subdomains = $16,
			max_live_web_servers = $17,
			updated_at = NOW()
		WHERE id = (SELECT id FROM auto_scan_config LIMIT 1)
	`,
		config.Amass,
		config.Sublist3r,
		config.Assetfinder,
		config.Gau,
		config.Ctl,
		config.Subfinder,
		config.ConsolidateHttpxRound1,
		config.Shuffledns,
		config.Cewl,
		config.ConsolidateHttpxRound2,
		config.Gospider,
		config.Subdomainizer,
		config.ConsolidateHttpxRound3,
		config.NucleiScreenshot,
		config.Metadata,
		config.MaxConsolidatedSubdomains,
		config.MaxLiveWebServers,
	)
	if err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}
	getAutoScanConfig(w, r)
}

func startAutoScanSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID  string      `json:"scope_target_id"`
		ConfigSnapshot interface{} `json:"config_snapshot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	var sessionID string
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO auto_scan_sessions (scope_target_id, config_snapshot, status, started_at)
		VALUES ($1, $2, 'running', NOW())
		RETURNING id
	`, req.ScopeTargetID, req.ConfigSnapshot).Scan(&sessionID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"session_id": sessionID})
}

func getAutoScanSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	row := dbPool.QueryRow(context.Background(), `
		SELECT id, scope_target_id, config_snapshot, status, started_at, ended_at, steps_run, error_message, final_consolidated_subdomains, final_live_web_servers
		FROM auto_scan_sessions WHERE id = $1
	`, sessionID)
	var session struct {
		ID                          string      `json:"id"`
		ScopeTargetID               string      `json:"scope_target_id"`
		ConfigSnapshot              interface{} `json:"config_snapshot"`
		Status                      string      `json:"status"`
		StartedAt                   time.Time   `json:"started_at"`
		EndedAt                     *time.Time  `json:"ended_at"`
		StepsRun                    interface{} `json:"steps_run"`
		ErrorMessage                *string     `json:"error_message"`
		FinalConsolidatedSubdomains *int        `json:"final_consolidated_subdomains"`
		FinalLiveWebServers         *int        `json:"final_live_web_servers"`
	}
	err := row.Scan(&session.ID, &session.ScopeTargetID, &session.ConfigSnapshot, &session.Status, &session.StartedAt, &session.EndedAt, &session.StepsRun, &session.ErrorMessage, &session.FinalConsolidatedSubdomains, &session.FinalLiveWebServers)
	if err != nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func listAutoScanSessions(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, scope_target_id, config_snapshot, status, started_at, ended_at, steps_run, error_message, final_consolidated_subdomains, final_live_web_servers
		FROM auto_scan_sessions WHERE scope_target_id = $1 ORDER BY started_at DESC
	`, targetID)
	if err != nil {
		http.Error(w, "Failed to list sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var sessions []interface{}
	for rows.Next() {
		var session struct {
			ID                          string      `json:"id"`
			ScopeTargetID               string      `json:"scope_target_id"`
			ConfigSnapshot              interface{} `json:"config_snapshot"`
			Status                      string      `json:"status"`
			StartedAt                   time.Time   `json:"started_at"`
			EndedAt                     *time.Time  `json:"ended_at"`
			StepsRun                    interface{} `json:"steps_run"`
			ErrorMessage                *string     `json:"error_message"`
			FinalConsolidatedSubdomains *int        `json:"final_consolidated_subdomains"`
			FinalLiveWebServers         *int        `json:"final_live_web_servers"`
		}
		err := rows.Scan(&session.ID, &session.ScopeTargetID, &session.ConfigSnapshot, &session.Status, &session.StartedAt, &session.EndedAt, &session.StepsRun, &session.ErrorMessage, &session.FinalConsolidatedSubdomains, &session.FinalLiveWebServers)
		if err == nil {
			sessions = append(sessions, session)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func cancelAutoScanSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	log.Printf("Cancelling session %s", sessionID)

	// First, get the current status to see if it's already completed or cancelled
	var currentStatus string
	err := dbPool.QueryRow(context.Background(),
		`SELECT status FROM auto_scan_sessions WHERE id = $1`, sessionID).Scan(&currentStatus)

	if err == nil {
		log.Printf("Current status for session %s: %s", sessionID, currentStatus)

		// Don't overwrite completed status with cancelled
		if currentStatus == "completed" {
			log.Printf("Session %s is already completed, not updating to cancelled", sessionID)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "status": "completed", "message": "Session already completed"}`))
			return
		}
	}

	// Mark as cancelled or completed based on request type
	// If this is coming from the completed code path, mark as completed
	status := "cancelled"
	if r.URL.Query().Get("completed") == "true" {
		status = "completed"
	}

	log.Printf("Setting session %s status to %s", sessionID, status)
	_, err = dbPool.Exec(context.Background(), `
		UPDATE auto_scan_sessions SET status = $1, ended_at = NOW() WHERE id = $2
	`, status, sessionID)

	if err != nil {
		log.Printf("Error cancelling session: %v", err)
		http.Error(w, "Failed to cancel session", http.StatusInternalServerError)
		return
	}

	// Verify the update was successful
	var newStatus string
	err = dbPool.QueryRow(context.Background(), `SELECT status FROM auto_scan_sessions WHERE id = $1`,
		sessionID).Scan(&newStatus)
	if err != nil {
		log.Printf("Error verifying session update: %v", err)
	} else {
		log.Printf("Session %s status after update: %s", sessionID, newStatus)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"success": true, "status": "%s"}`, status)))
}

func updateAutoScanSessionFinalStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]
	log.Printf("Updating final stats for session %s", sessionID)

	var payload struct {
		FinalConsolidatedSubdomains *int   `json:"final_consolidated_subdomains"`
		FinalLiveWebServers         *int   `json:"final_live_web_servers"`
		ScopeTargetID               string `json:"scope_target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Final stats: subdomains=%v, webservers=%v, scope_target_id=%s",
		payload.FinalConsolidatedSubdomains, payload.FinalLiveWebServers, payload.ScopeTargetID)

	// First, verify this session belongs to this scope target to prevent cross-target modification
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), `
		SELECT scope_target_id FROM auto_scan_sessions WHERE id = $1
	`, sessionID).Scan(&scopeTargetID)

	if err != nil {
		log.Printf("Error fetching session: %v", err)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Ensure the scope_target_id in the request matches the one in the database
	if payload.ScopeTargetID != "" && scopeTargetID != payload.ScopeTargetID {
		log.Printf("Scope target ID mismatch: %s (request) vs %s (database)", payload.ScopeTargetID, scopeTargetID)
		http.Error(w, "Scope target ID mismatch", http.StatusBadRequest)
		return
	}

	_, err = dbPool.Exec(context.Background(), `
		UPDATE auto_scan_sessions
		SET final_consolidated_subdomains = $1, 
		    final_live_web_servers = $2, 
		    ended_at = COALESCE(ended_at, NOW()),
		    status = 'completed'
		WHERE id = $3
	`, payload.FinalConsolidatedSubdomains, payload.FinalLiveWebServers, sessionID)

	if err != nil {
		log.Printf("Error updating session stats: %v", err)
		http.Error(w, "Failed to update session stats", http.StatusInternalServerError)
		return
	}

	// Verify the update was successful
	var status string
	err = dbPool.QueryRow(context.Background(), `SELECT status FROM auto_scan_sessions WHERE id = $1`, sessionID).Scan(&status)
	if err != nil {
		log.Printf("Error verifying session update: %v", err)
	} else {
		log.Printf("Session %s status after update: %s", sessionID, status)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success": true, "status": "completed"}`))
}

func createGoogleDorkingDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
		Domain        string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ScopeTargetID == "" || req.Domain == "" {
		http.Error(w, "scope_target_id and domain are required", http.StatusBadRequest)
		return
	}

	// Check if domain already exists for this scope target
	var existingCount int
	err := dbPool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM google_dorking_domains 
		WHERE scope_target_id = $1 AND LOWER(domain) = LOWER($2)
	`, req.ScopeTargetID, req.Domain).Scan(&existingCount)

	if err != nil {
		log.Printf("Error checking existing domain: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingCount > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Domain \"%s\" already exists for this target", req.Domain),
		})
		return
	}

	// Insert the domain
	var domainID string
	err = dbPool.QueryRow(context.Background(), `
		INSERT INTO google_dorking_domains (scope_target_id, domain, created_at)
		VALUES ($1, $2, NOW())
		RETURNING id
	`, req.ScopeTargetID, req.Domain).Scan(&domainID)

	if err != nil {
		log.Printf("Error creating Google dorking domain: %v", err)
		http.Error(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":              domainID,
		"scope_target_id": req.ScopeTargetID,
		"domain":          req.Domain,
		"success":         true,
	})
}

func getGoogleDorkingDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetID := vars["target_id"]

	if targetID == "" {
		http.Error(w, "target_id is required", http.StatusBadRequest)
		return
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, scope_target_id, domain, created_at
		FROM google_dorking_domains
		WHERE scope_target_id = $1
		ORDER BY created_at DESC
	`, targetID)

	if err != nil {
		log.Printf("Error fetching Google dorking domains: %v", err)
		http.Error(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var domains []map[string]interface{}
	for rows.Next() {
		var domain struct {
			ID            string    `json:"id"`
			ScopeTargetID string    `json:"scope_target_id"`
			Domain        string    `json:"domain"`
			CreatedAt     time.Time `json:"created_at"`
		}

		err := rows.Scan(&domain.ID, &domain.ScopeTargetID, &domain.Domain, &domain.CreatedAt)
		if err != nil {
			log.Printf("Error scanning Google dorking domain: %v", err)
			continue
		}

		domains = append(domains, map[string]interface{}{
			"id":              domain.ID,
			"scope_target_id": domain.ScopeTargetID,
			"domain":          domain.Domain,
			"created_at":      domain.CreatedAt,
		})
	}

	if domains == nil {
		domains = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

func deleteGoogleDorkingDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domainID := vars["domain_id"]

	if domainID == "" {
		http.Error(w, "domain_id is required", http.StatusBadRequest)
		return
	}

	result, err := dbPool.Exec(context.Background(), `
		DELETE FROM google_dorking_domains WHERE id = $1
	`, domainID)

	if err != nil {
		log.Printf("Error deleting Google dorking domain: %v", err)
		http.Error(w, "Failed to delete domain", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Domain deleted successfully",
	})
}

func createReverseWhoisDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
		Domain        string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ScopeTargetID == "" || req.Domain == "" {
		http.Error(w, "scope_target_id and domain are required", http.StatusBadRequest)
		return
	}

	// Check if domain already exists for this scope target
	var existingCount int
	err := dbPool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM reverse_whois_domains 
		WHERE scope_target_id = $1 AND LOWER(domain) = LOWER($2)
	`, req.ScopeTargetID, req.Domain).Scan(&existingCount)

	if err != nil {
		log.Printf("Error checking existing reverse whois domain: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingCount > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Domain \"%s\" already exists for this target", req.Domain),
		})
		return
	}

	// Insert the domain
	var domainID string
	err = dbPool.QueryRow(context.Background(), `
		INSERT INTO reverse_whois_domains (scope_target_id, domain, created_at)
		VALUES ($1, $2, NOW())
		RETURNING id
	`, req.ScopeTargetID, req.Domain).Scan(&domainID)

	if err != nil {
		log.Printf("Error creating reverse whois domain: %v", err)
		http.Error(w, "Failed to create domain", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":              domainID,
		"scope_target_id": req.ScopeTargetID,
		"domain":          req.Domain,
		"success":         true,
	})
}

func getReverseWhoisDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetID := vars["target_id"]

	if targetID == "" {
		http.Error(w, "target_id is required", http.StatusBadRequest)
		return
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, scope_target_id, domain, created_at
		FROM reverse_whois_domains
		WHERE scope_target_id = $1
		ORDER BY created_at DESC
	`, targetID)

	if err != nil {
		log.Printf("Error fetching reverse whois domains: %v", err)
		http.Error(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var domains []map[string]interface{}
	for rows.Next() {
		var domain struct {
			ID            string    `json:"id"`
			ScopeTargetID string    `json:"scope_target_id"`
			Domain        string    `json:"domain"`
			CreatedAt     time.Time `json:"created_at"`
		}

		err := rows.Scan(&domain.ID, &domain.ScopeTargetID, &domain.Domain, &domain.CreatedAt)
		if err != nil {
			log.Printf("Error scanning reverse whois domain: %v", err)
			continue
		}

		domains = append(domains, map[string]interface{}{
			"id":              domain.ID,
			"scope_target_id": domain.ScopeTargetID,
			"domain":          domain.Domain,
			"created_at":      domain.CreatedAt,
		})
	}

	if domains == nil {
		domains = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domains)
}

func deleteReverseWhoisDomain(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domainID := vars["domain_id"]

	if domainID == "" {
		http.Error(w, "domain_id is required", http.StatusBadRequest)
		return
	}

	result, err := dbPool.Exec(context.Background(), `
		DELETE FROM reverse_whois_domains WHERE id = $1
	`, domainID)

	if err != nil {
		log.Printf("Error deleting reverse whois domain: %v", err)
		http.Error(w, "Failed to delete domain", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Domain deleted successfully",
	})
}

func getAPIKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, tool_name, api_key_name, api_key_value, created_at, updated_at
		FROM api_keys
		ORDER BY tool_name, api_key_name
	`)
	if err != nil {
		log.Printf("Error fetching API keys: %v", err)
		http.Error(w, "Failed to fetch API keys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var apiKeys []map[string]interface{}
	for rows.Next() {
		var id, toolName, apiKeyName, apiKeyValue string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &toolName, &apiKeyName, &apiKeyValue, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("Error scanning API key row: %v", err)
			continue
		}

		// Parse the key_values JSON
		var keyValues struct {
			APIKey    string `json:"api_key"`
			AppID     string `json:"app_id"`
			AppSecret string `json:"app_secret"`
		}
		if err := json.Unmarshal([]byte(apiKeyValue), &keyValues); err != nil {
			log.Printf("Error parsing key values: %v", err)
			continue
		}

		// Mask sensitive values
		if keyValues.APIKey != "" {
			if len(keyValues.APIKey) > 4 {
				keyValues.APIKey = strings.Repeat("*", len(keyValues.APIKey)-4) + keyValues.APIKey[len(keyValues.APIKey)-4:]
			} else {
				keyValues.APIKey = strings.Repeat("*", len(keyValues.APIKey))
			}
		}
		if keyValues.AppID != "" {
			if len(keyValues.AppID) > 4 {
				keyValues.AppID = strings.Repeat("*", len(keyValues.AppID)-4) + keyValues.AppID[len(keyValues.AppID)-4:]
			} else {
				keyValues.AppID = strings.Repeat("*", len(keyValues.AppID))
			}
		}
		if keyValues.AppSecret != "" {
			if len(keyValues.AppSecret) > 4 {
				keyValues.AppSecret = strings.Repeat("*", len(keyValues.AppSecret)-4) + keyValues.AppSecret[len(keyValues.AppSecret)-4:]
			} else {
				keyValues.AppSecret = strings.Repeat("*", len(keyValues.AppSecret))
			}
		}

		apiKeys = append(apiKeys, map[string]interface{}{
			"id":           id,
			"tool_name":    toolName,
			"api_key_name": apiKeyName,
			"key_values":   keyValues,
			"created_at":   createdAt,
			"updated_at":   updatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apiKeys)
}

func createAPIKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ToolName  string `json:"tool_name"`
		KeyName   string `json:"api_key_name"`
		KeyValues struct {
			APIKey    string `json:"api_key"`
			AppID     string `json:"app_id"`
			AppSecret string `json:"app_secret"`
		} `json:"key_values"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("[ERROR] Failed to decode API key request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log the incoming request data
	log.Printf("[DEBUG] Incoming API key request:")
	log.Printf("  Tool Name: %s", request.ToolName)
	log.Printf("  Key Name: %s", request.KeyName)
	log.Printf("  Key Values:")
	log.Printf("    API Key: %s", request.KeyValues.APIKey)
	log.Printf("    App ID: %s", request.KeyValues.AppID)
	log.Printf("    App Secret: %s", request.KeyValues.AppSecret)

	// Validate required fields
	if request.ToolName == "" || request.KeyName == "" {
		log.Printf("[ERROR] Missing required fields - Tool Name: %v, Key Name: %v", request.ToolName == "", request.KeyName == "")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate key values based on tool type
	if request.ToolName == "Censys" {
		if request.KeyValues.AppID == "" || request.KeyValues.AppSecret == "" {
			log.Printf("[ERROR] Missing Censys credentials - App ID: %v, App Secret: %v", request.KeyValues.AppID == "", request.KeyValues.AppSecret == "")
			http.Error(w, "Missing Censys credentials", http.StatusBadRequest)
			return
		}
	} else {
		if request.KeyValues.APIKey == "" {
			log.Printf("[ERROR] Missing API key for tool: %s", request.ToolName)
			http.Error(w, "Missing API key", http.StatusBadRequest)
			return
		}
	}

	// Convert key_values to JSON string
	keyValuesJSON, err := json.Marshal(request.KeyValues)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal key values: %v", err)
		http.Error(w, "Failed to process key values", http.StatusInternalServerError)
		return
	}

	// Log the data being stored
	log.Printf("[DEBUG] Storing API key in database:")
	log.Printf("  Tool Name: %s", request.ToolName)
	log.Printf("  Key Name: %s", request.KeyName)
	log.Printf("  Key Values JSON: %s", string(keyValuesJSON))

	// Try to insert the API key
	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO api_keys (tool_name, api_key_name, api_key_value)
		VALUES ($1, $2, $3)
	`, request.ToolName, request.KeyName, string(keyValuesJSON))

	if err != nil {
		// Check if this is a unique constraint violation
		if strings.Contains(err.Error(), "unique constraint") {
			log.Printf("[ERROR] API key with name '%s' already exists for tool '%s'", request.KeyName, request.ToolName)
			http.Error(w, fmt.Sprintf("An API key with name '%s' already exists for %s", request.KeyName, request.ToolName), http.StatusConflict)
			return
		}
		// Any other database error
		log.Printf("[ERROR] Failed to store API key: %v", err)
		http.Error(w, "Failed to store API key", http.StatusInternalServerError)
		return
	}

	log.Printf("[DEBUG] API key stored successfully")
	w.WriteHeader(http.StatusCreated)
}

func updateAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var request struct {
		APIKeyName  string `json:"api_key_name"`
		APIKeyValue string `json:"api_key_value"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.APIKeyName == "" || request.APIKeyValue == "" {
		http.Error(w, "api_key_name and api_key_value are required", http.StatusBadRequest)
		return
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE api_keys 
		SET api_key_name = $1, api_key_value = $2, updated_at = NOW()
		WHERE id = $3
	`, request.APIKeyName, request.APIKeyValue, id)

	if err != nil {
		log.Printf("Error updating API key: %v", err)
		http.Error(w, "Failed to update API key", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "API key updated successfully"})
}

func deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	result, err := dbPool.Exec(context.Background(), `
		DELETE FROM api_keys WHERE id = $1
	`, id)

	if err != nil {
		log.Printf("Error deleting API key: %v", err)
		http.Error(w, "Failed to delete API key", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "API key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "API key deleted successfully"})
}

func getAiAPIKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, provider, api_key_name, key_values, created_at, updated_at
		FROM ai_api_keys
		ORDER BY provider, api_key_name
	`)
	if err != nil {
		log.Printf("Error fetching AI API keys: %v", err)
		http.Error(w, "Failed to fetch AI API keys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var aiApiKeys []map[string]interface{}
	for rows.Next() {
		var id, provider, apiKeyName, keyValuesJSON string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &provider, &apiKeyName, &keyValuesJSON, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("Error scanning AI API key row: %v", err)
			continue
		}

		// Parse the key_values JSON
		var keyValues map[string]interface{}
		if err := json.Unmarshal([]byte(keyValuesJSON), &keyValues); err != nil {
			log.Printf("Error parsing AI key values: %v", err)
			continue
		}

		// Mask sensitive values
		maskedKeyValues := make(map[string]interface{})
		for key, value := range keyValues {
			if strValue, ok := value.(string); ok && strValue != "" {
				if len(strValue) > 4 {
					maskedKeyValues[key] = strings.Repeat("*", len(strValue)-4) + strValue[len(strValue)-4:]
				} else {
					maskedKeyValues[key] = strings.Repeat("*", len(strValue))
				}
			} else {
				maskedKeyValues[key] = value
			}
		}

		aiApiKeys = append(aiApiKeys, map[string]interface{}{
			"id":           id,
			"provider":     provider,
			"api_key_name": apiKeyName,
			"key_values":   maskedKeyValues,
			"created_at":   createdAt,
			"updated_at":   updatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aiApiKeys)
}

func createAiAPIKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Provider  string                 `json:"provider"`
		KeyName   string                 `json:"api_key_name"`
		KeyValues map[string]interface{} `json:"key_values"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("[ERROR] Failed to decode AI API key request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Log the incoming request data
	log.Printf("[DEBUG] Incoming AI API key request:")
	log.Printf("  Provider: %s", request.Provider)
	log.Printf("  Key Name: %s", request.KeyName)

	// Validate required fields
	if request.Provider == "" || request.KeyName == "" {
		log.Printf("[ERROR] Missing required fields - Provider: %v, Key Name: %v", request.Provider == "", request.KeyName == "")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate that API key is provided for all providers
	if apiKey, ok := request.KeyValues["api_key"].(string); !ok || apiKey == "" {
		log.Printf("[ERROR] Missing API key for provider: %s", request.Provider)
		http.Error(w, "Missing API key", http.StatusBadRequest)
		return
	}

	// Convert key_values to JSON string
	keyValuesJSON, err := json.Marshal(request.KeyValues)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal AI key values: %v", err)
		http.Error(w, "Failed to process key values", http.StatusInternalServerError)
		return
	}

	// Log the data being stored
	log.Printf("[DEBUG] Storing AI API key in database:")
	log.Printf("  Provider: %s", request.Provider)
	log.Printf("  Key Name: %s", request.KeyName)

	// Try to insert the AI API key
	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO ai_api_keys (provider, api_key_name, key_values)
		VALUES ($1, $2, $3)
	`, request.Provider, request.KeyName, string(keyValuesJSON))

	if err != nil {
		// Check if this is a unique constraint violation
		if strings.Contains(err.Error(), "unique constraint") {
			log.Printf("[ERROR] AI API key with name '%s' already exists for provider '%s'", request.KeyName, request.Provider)
			http.Error(w, fmt.Sprintf("An API key with name '%s' already exists for %s", request.KeyName, request.Provider), http.StatusConflict)
			return
		}
		// Any other database error
		log.Printf("[ERROR] Failed to store AI API key: %v", err)
		http.Error(w, "Failed to store AI API key", http.StatusInternalServerError)
		return
	}

	log.Printf("[DEBUG] AI API key stored successfully")
	w.WriteHeader(http.StatusCreated)
}

func updateAiAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var request struct {
		APIKeyName string                 `json:"api_key_name"`
		KeyValues  map[string]interface{} `json:"key_values"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert key_values to JSON string
	keyValuesJSON, err := json.Marshal(request.KeyValues)
	if err != nil {
		http.Error(w, "Failed to process key values", http.StatusInternalServerError)
		return
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE ai_api_keys 
		SET api_key_name = $1, key_values = $2, updated_at = NOW()
		WHERE id = $3
	`, request.APIKeyName, string(keyValuesJSON), id)

	if err != nil {
		log.Printf("Error updating AI API key: %v", err)
		http.Error(w, "Failed to update AI API key", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "AI API key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "AI API key updated successfully"})
}

func deleteAiAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	result, err := dbPool.Exec(context.Background(), `
		DELETE FROM ai_api_keys WHERE id = $1
	`, id)

	if err != nil {
		log.Printf("Error deleting AI API key: %v", err)
		http.Error(w, "Failed to delete AI API key", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "AI API key not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "AI API key deleted successfully"})
}

func getCompanyDomainsByTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	tool := vars["tool"]

	if scopeTargetID == "" || tool == "" {
		http.Error(w, "scope_target_id and tool are required", http.StatusBadRequest)
		return
	}

	var domains []string
	var err error

	switch tool {
	case "google_dorking":
		domains, err = utils.GetGoogleDorkingDomainsForTool(scopeTargetID)
	case "reverse_whois":
		domains, err = utils.GetReverseWhoisDomainsForTool(scopeTargetID)
	case "ctl_company":
		domains, err = utils.GetCTLCompanyDomainsForTool(scopeTargetID)
	case "securitytrails_company":
		domains, err = utils.GetSecurityTrailsCompanyDomainsForTool(scopeTargetID)
	case "censys_company":
		domains, err = utils.GetCensysCompanyDomainsForTool(scopeTargetID)
	case "github_recon":
		domains, err = utils.GetGitHubReconDomainsForTool(scopeTargetID)
	case "shodan_company":
		domains, err = utils.GetShodanCompanyDomainsForTool(scopeTargetID)
	case "live_web_servers":
		domains, err = utils.GetLiveWebServerDomainsForTool(scopeTargetID)
	default:
		http.Error(w, "Invalid tool specified", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("Error fetching domains for tool %s: %v", tool, err)
		http.Error(w, "Failed to fetch domains", http.StatusInternalServerError)
		return
	}

	if domains == nil {
		domains = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domains": domains,
		"count":   len(domains),
	})
}

func deleteCompanyDomainFromTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	tool := vars["tool"]
	domain := vars["domain"]

	log.Printf("[DOMAIN-API] [DEBUG] Individual delete request: scope_target_id=%s, tool=%s, domain='%s'", scopeTargetID, tool, domain)

	if scopeTargetID == "" || tool == "" || domain == "" {
		log.Printf("[DOMAIN-API] [ERROR] Missing required parameters: scope_target_id='%s', tool='%s', domain='%s'", scopeTargetID, tool, domain)
		http.Error(w, "scope_target_id, tool, and domain are required", http.StatusBadRequest)
		return
	}

	var err error
	var success bool

	log.Printf("[DOMAIN-API] [DEBUG] Processing individual delete for tool: %s, domain: '%s'", tool, domain)

	switch tool {
	case "google_dorking":
		success, err = utils.DeleteGoogleDorkingDomainFromTool(scopeTargetID, domain)
	case "reverse_whois":
		success, err = utils.DeleteReverseWhoisDomainFromTool(scopeTargetID, domain)
	case "ctl_company":
		success, err = utils.DeleteCTLCompanyDomainFromTool(scopeTargetID, domain)
	case "securitytrails_company":
		success, err = utils.DeleteSecurityTrailsCompanyDomainFromTool(scopeTargetID, domain)
	case "censys_company":
		success, err = utils.DeleteCensysCompanyDomainFromTool(scopeTargetID, domain)
	case "github_recon":
		success, err = utils.DeleteGitHubReconDomainFromTool(scopeTargetID, domain)
	case "shodan_company":
		success, err = utils.DeleteShodanCompanyDomainFromTool(scopeTargetID, domain)
	case "live_web_servers":
		success, err = utils.DeleteLiveWebServerDomainFromTool(scopeTargetID, domain)
	default:
		log.Printf("[DOMAIN-API] [ERROR] Invalid tool specified: %s", tool)
		http.Error(w, "Invalid tool specified", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("[DOMAIN-API] [ERROR] Error deleting domain '%s' from tool %s: %v", domain, tool, err)
		http.Error(w, "Failed to delete domain", http.StatusInternalServerError)
		return
	}

	if !success {
		log.Printf("[DOMAIN-API] [WARNING] Domain '%s' not found in tool %s", domain, tool)
		http.Error(w, "Domain not found", http.StatusNotFound)
		return
	}

	log.Printf("[DOMAIN-API] [INFO] Successfully deleted domain '%s' from tool %s", domain, tool)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Domain deleted successfully",
	})
}

func deleteAllCompanyDomainsFromTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	tool := vars["tool"]

	log.Printf("[DOMAIN-API] [DEBUG] Delete all domains request: scope_target_id=%s, tool=%s", scopeTargetID, tool)
	log.Printf("[DOMAIN-API] [DEBUG] Request URL: %s", r.URL.Path)

	if scopeTargetID == "" || tool == "" {
		log.Printf("[DOMAIN-API] [ERROR] Missing parameters: scope_target_id=%s, tool=%s", scopeTargetID, tool)
		http.Error(w, "scope_target_id and tool are required", http.StatusBadRequest)
		return
	}

	var err error
	var count int64

	log.Printf("[DOMAIN-API] [DEBUG] Processing delete all for tool: %s", tool)

	switch tool {
	case "google_dorking":
		count, err = utils.DeleteAllGoogleDorkingDomainsFromTool(scopeTargetID)
	case "reverse_whois":
		count, err = utils.DeleteAllReverseWhoisDomainsFromTool(scopeTargetID)
	case "ctl_company":
		log.Printf("[DOMAIN-API] [DEBUG] Calling DeleteAllCTLCompanyDomainsFromTool")
		count, err = utils.DeleteAllCTLCompanyDomainsFromTool(scopeTargetID)
	case "securitytrails_company":
		count, err = utils.DeleteAllSecurityTrailsCompanyDomainsFromTool(scopeTargetID)
	case "censys_company":
		count, err = utils.DeleteAllCensysCompanyDomainsFromTool(scopeTargetID)
	case "github_recon":
		count, err = utils.DeleteAllGitHubReconDomainsFromTool(scopeTargetID)
	case "shodan_company":
		count, err = utils.DeleteAllShodanCompanyDomainsFromTool(scopeTargetID)
	case "live_web_servers":
		count, err = utils.DeleteAllLiveWebServerDomainsFromTool(scopeTargetID)
	default:
		log.Printf("[DOMAIN-API] [ERROR] Invalid tool specified: %s", tool)
		http.Error(w, "Invalid tool specified", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("[DOMAIN-API] [ERROR] Error deleting all domains from tool %s: %v", tool, err)
		http.Error(w, "Failed to delete domains", http.StatusInternalServerError)
		return
	}

	log.Printf("[DOMAIN-API] [INFO] Successfully deleted %d domains from tool %s", count, tool)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Deleted %d domains successfully", count),
		"count":   count,
	})
}

// getAmassEnumConfig retrieves the Amass Enum configuration for a scope target
func getAmassEnumConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Query the configuration from the database
	query := `
		SELECT selected_domains, 
		       COALESCE(wildcard_domains, '[]'::jsonb) as wildcard_domains
		FROM amass_enum_configs 
		WHERE scope_target_id = $1
		ORDER BY updated_at DESC 
		LIMIT 1
	`

	var selectedDomainsJSON, wildcardDomainsJSON []byte
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&selectedDomainsJSON, &wildcardDomainsJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
			// No configuration found, return empty response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"domains":                  []string{},
				"include_wildcard_results": true,
				"wildcard_domains":         []string{},
			})
			return
		}
		log.Printf("Error fetching Amass Enum config: %v", err)
		http.Error(w, "Failed to fetch configuration", http.StatusInternalServerError)
		return
	}

	// Parse the JSONB arrays
	var selectedDomains, wildcardDomains []string
	if err := json.Unmarshal(selectedDomainsJSON, &selectedDomains); err != nil {
		log.Printf("Error parsing selected domains JSON: %v", err)
		http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(wildcardDomainsJSON, &wildcardDomains); err != nil {
		log.Printf("Error parsing wildcard domains JSON: %v", err)
		http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domains":                  selectedDomains,
		"include_wildcard_results": true,
		"wildcard_domains":         wildcardDomains,
	})
}

// saveAmassEnumConfig saves the Amass Enum configuration for a scope target
func saveAmassEnumConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Parse the request body
	var request struct {
		Domains                []string `json:"domains"`
		IncludeWildcardResults bool     `json:"include_wildcard_results"`
		WildcardDomains        []string `json:"wildcard_domains"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert arrays to JSON
	selectedDomainsJSON, err := json.Marshal(request.Domains)
	if err != nil {
		log.Printf("Error marshaling selected domains: %v", err)
		http.Error(w, "Failed to process domains", http.StatusInternalServerError)
		return
	}

	wildcardDomainsJSON, err := json.Marshal(request.WildcardDomains)
	if err != nil {
		log.Printf("Error marshaling wildcard domains: %v", err)
		http.Error(w, "Failed to process wildcard domains", http.StatusInternalServerError)
		return
	}

	// Insert or update the configuration
	query := `
		INSERT INTO amass_enum_configs (scope_target_id, selected_domains, include_wildcard_results, wildcard_domains, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (scope_target_id)
		DO UPDATE SET 
			selected_domains = EXCLUDED.selected_domains,
			include_wildcard_results = EXCLUDED.include_wildcard_results,
			wildcard_domains = EXCLUDED.wildcard_domains,
			updated_at = NOW()
		RETURNING id
	`

	var configID string
	err = dbPool.QueryRow(context.Background(), query, scopeTargetID, string(selectedDomainsJSON), request.IncludeWildcardResults, string(wildcardDomainsJSON)).Scan(&configID)
	if err != nil {
		log.Printf("Error saving Amass Enum config: %v", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Printf("Saved Amass Enum config for scope target %s with %d domains", scopeTargetID, len(request.Domains))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"config_id": configID,
		"message":   fmt.Sprintf("Configuration saved with %d domains", len(request.Domains)),
	})
}

// getAmassIntelConfig retrieves the Amass Intel configuration for a scope target
func getAmassIntelConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Query the configuration from the database
	query := `
		SELECT selected_network_ranges
		FROM amass_intel_configs 
		WHERE scope_target_id = $1
		ORDER BY updated_at DESC 
		LIMIT 1
	`

	var selectedNetworkRangesJSON []byte
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&selectedNetworkRangesJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
			// No configuration found, return empty response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"network_ranges": []string{},
			})
			return
		}
		log.Printf("Error fetching Amass Intel config: %v", err)
		http.Error(w, "Failed to fetch configuration", http.StatusInternalServerError)
		return
	}

	// Parse the JSONB array of selected network ranges
	var selectedNetworkRanges []string
	if err := json.Unmarshal(selectedNetworkRangesJSON, &selectedNetworkRanges); err != nil {
		log.Printf("Error parsing selected network ranges JSON: %v", err)
		http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"network_ranges": selectedNetworkRanges,
	})
}

// saveAmassIntelConfig saves the Amass Intel configuration for a scope target
func saveAmassIntelConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Parse the request body
	var request struct {
		NetworkRanges []string `json:"network_ranges"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert selected network ranges to JSON
	selectedNetworkRangesJSON, err := json.Marshal(request.NetworkRanges)
	if err != nil {
		log.Printf("Error marshaling selected network ranges: %v", err)
		http.Error(w, "Failed to process network ranges", http.StatusInternalServerError)
		return
	}

	// Insert or update the configuration
	query := `
		INSERT INTO amass_intel_configs (scope_target_id, selected_network_ranges, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (scope_target_id)
		DO UPDATE SET 
			selected_network_ranges = EXCLUDED.selected_network_ranges,
			updated_at = NOW()
		RETURNING id
	`

	var configID string
	err = dbPool.QueryRow(context.Background(), query, scopeTargetID, string(selectedNetworkRangesJSON)).Scan(&configID)
	if err != nil {
		log.Printf("Error saving Amass Intel config: %v", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Printf("Saved Amass Intel config for scope target %s with %d network ranges", scopeTargetID, len(request.NetworkRanges))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"config_id": configID,
		"message":   fmt.Sprintf("Configuration saved with %d network ranges", len(request.NetworkRanges)),
	})
}

// getDNSxConfig retrieves the DNSx configuration for a scope target
func getDNSxConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Query the configuration from the database
	query := `
		SELECT selected_domains, 
		       COALESCE(wildcard_domains, '[]'::jsonb) as wildcard_domains
		FROM dnsx_configs 
		WHERE scope_target_id = $1
		ORDER BY updated_at DESC 
		LIMIT 1
	`

	var selectedDomainsJSON, wildcardDomainsJSON []byte
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&selectedDomainsJSON, &wildcardDomainsJSON)

	if err != nil {
		if err.Error() == "no rows in result set" {
			// No configuration found, return empty response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"domains":                  []string{},
				"include_wildcard_results": true,
				"wildcard_domains":         []string{},
			})
			return
		}
		log.Printf("Error fetching DNSx config: %v", err)
		http.Error(w, "Failed to fetch configuration", http.StatusInternalServerError)
		return
	}

	// Parse the JSONB arrays
	var selectedDomains, wildcardDomains []string
	if err := json.Unmarshal(selectedDomainsJSON, &selectedDomains); err != nil {
		log.Printf("Error parsing selected domains JSON: %v", err)
		http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(wildcardDomainsJSON, &wildcardDomains); err != nil {
		log.Printf("Error parsing wildcard domains JSON: %v", err)
		http.Error(w, "Failed to parse configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domains":                  selectedDomains,
		"include_wildcard_results": true,
		"wildcard_domains":         wildcardDomains,
	})
}

// saveDNSxConfig saves the DNSx configuration for a scope target
func saveDNSxConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Parse the request body
	var request struct {
		Domains                []string `json:"domains"`
		IncludeWildcardResults bool     `json:"include_wildcard_results"`
		WildcardDomains        []string `json:"wildcard_domains"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert arrays to JSON
	selectedDomainsJSON, err := json.Marshal(request.Domains)
	if err != nil {
		log.Printf("Error marshaling selected domains: %v", err)
		http.Error(w, "Failed to process domains", http.StatusInternalServerError)
		return
	}

	wildcardDomainsJSON, err := json.Marshal(request.WildcardDomains)
	if err != nil {
		log.Printf("Error marshaling wildcard domains: %v", err)
		http.Error(w, "Failed to process wildcard domains", http.StatusInternalServerError)
		return
	}

	// Insert or update the configuration
	query := `
		INSERT INTO dnsx_configs (scope_target_id, selected_domains, include_wildcard_results, wildcard_domains, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (scope_target_id)
		DO UPDATE SET 
			selected_domains = EXCLUDED.selected_domains,
			include_wildcard_results = EXCLUDED.include_wildcard_results,
			wildcard_domains = EXCLUDED.wildcard_domains,
			updated_at = NOW()
		RETURNING id
	`

	var configID string
	err = dbPool.QueryRow(context.Background(), query, scopeTargetID, string(selectedDomainsJSON), request.IncludeWildcardResults, string(wildcardDomainsJSON)).Scan(&configID)
	if err != nil {
		log.Printf("Error saving DNSx config: %v", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	log.Printf("Saved DNSx config for scope target %s with %d domains", scopeTargetID, len(request.Domains))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"config_id": configID,
		"message":   fmt.Sprintf("Configuration saved with %d domains", len(request.Domains)),
	})
}

// getLiveWebServersCount returns the count of live web servers for a scope target
func getLiveWebServersCount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	var count int

	// First try to count from IP/Port scans (for Company targets)
	ipPortQuery := `
		SELECT COUNT(DISTINCT lws.id)
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1 AND ips.status = 'success'
	`

	err := dbPool.QueryRow(context.Background(), ipPortQuery, scopeTargetID).Scan(&count)
	if err != nil {
		log.Printf("Error fetching live web servers count from IP/Port scans for scope target %s: %v", scopeTargetID, err)
		count = 0
	}

	// If no results from IP/Port scans, try HTTPx scans (for Wildcard targets)
	if count == 0 {
		httpxQuery := `
			SELECT COALESCE(
				ARRAY_LENGTH(
					ARRAY_REMOVE(
						STRING_TO_ARRAY(TRIM(result), E'\n'), 
						''
					), 
					1
				), 
				0
			) as count
			FROM httpx_scans 
			WHERE scope_target_id = $1 
			AND status = 'success' 
			AND result IS NOT NULL 
			AND TRIM(result) != ''
			ORDER BY created_at DESC 
			LIMIT 1
		`

		err = dbPool.QueryRow(context.Background(), httpxQuery, scopeTargetID).Scan(&count)
		if err != nil {
			log.Printf("Error fetching live web servers count from HTTPx scans for scope target %s: %v", scopeTargetID, err)
			count = 0
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": count,
	})
}

func populateBurpsuite(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		URLs []string `json:"urls"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(requestBody.URLs) == 0 {
		http.Error(w, "No URLs provided", http.StatusBadRequest)
		return
	}

	err = utils.PopulateBurpsuite(requestBody.URLs)
	if err != nil {
		log.Printf("[ERROR] Failed to populate Burpsuite: %v", err)
		http.Error(w, fmt.Sprintf("Failed to populate Burpsuite: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": fmt.Sprintf("Successfully populated Burpsuite with %d URLs", len(requestBody.URLs)),
	})
}

func processApiEndpoint(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Method            string                 `json:"method"`
		Path              string                 `json:"path"`
		BaseURL           string                 `json:"baseUrl"`
		Body              interface{}            `json:"body"`
		APIKey            string                 `json:"apiKey"`
		ProxyIP           string                 `json:"proxyIP"`
		ProxyPort         int                    `json:"proxyPort"`
		Parameters        []interface{}          `json:"parameters"`
		ManualInputValues map[string]interface{} `json:"manualInputValues"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if requestBody.Method == "" || requestBody.Path == "" {
		http.Error(w, "Method and Path are required", http.StatusBadRequest)
		return
	}

	err = utils.ProcessApiRequest(
		requestBody.Method,
		requestBody.Path,
		requestBody.BaseURL,
		requestBody.Body,
		requestBody.APIKey,
		requestBody.ProxyIP,
		requestBody.ProxyPort,
		requestBody.Parameters,
		requestBody.ManualInputValues,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to process API endpoint: %v", err)
		http.Error(w, fmt.Sprintf("Failed to process API endpoint: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Successfully processed %s %s", requestBody.Method, requestBody.Path),
	})
}

func getCloudEnumConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	log.Printf("[CLOUD-ENUM-CONFIG] Getting configuration for scope target: %s", scopeTargetID)

	var config struct {
		Keywords            []string               `json:"keywords"`
		Threads             int                    `json:"threads"`
		EnabledPlatforms    map[string]interface{} `json:"enabled_platforms"`
		CustomDNSServer     string                 `json:"custom_dns_server"`
		DNSResolverMode     string                 `json:"dns_resolver_mode"`
		ResolverConfig      string                 `json:"resolver_config"`
		AdditionalResolvers string                 `json:"additional_resolvers"`
		MutationsFilePath   string                 `json:"mutations_file_path"`
		BruteFilePath       string                 `json:"brute_file_path"`
		ResolverFilePath    string                 `json:"resolver_file_path"`
		SelectedServices    map[string][]string    `json:"selected_services"`
		SelectedRegions     map[string][]string    `json:"selected_regions"`
	}

	var platformsJSON []byte
	var servicesJSON []byte
	var regionsJSON []byte
	err := dbPool.QueryRow(context.Background(), `
		SELECT keywords, threads, enabled_platforms, custom_dns_server, 
		       dns_resolver_mode, resolver_config, additional_resolvers,
		       mutations_file_path, brute_file_path, resolver_file_path,
		       selected_services, selected_regions
		FROM cloud_enum_configs 
		WHERE scope_target_id = $1 
		ORDER BY updated_at DESC 
		LIMIT 1
	`, scopeTargetID).Scan(
		&config.Keywords,
		&config.Threads,
		&platformsJSON,
		&config.CustomDNSServer,
		&config.DNSResolverMode,
		&config.ResolverConfig,
		&config.AdditionalResolvers,
		&config.MutationsFilePath,
		&config.BruteFilePath,
		&config.ResolverFilePath,
		&servicesJSON,
		&regionsJSON,
	)

	if err != nil && err != sql.ErrNoRows {
		log.Printf("[CLOUD-ENUM-CONFIG] Error getting config: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if err == sql.ErrNoRows {
		// Return default config
		config.Keywords = []string{}
		config.Threads = 5
		config.EnabledPlatforms = map[string]interface{}{
			"aws":   true,
			"azure": true,
			"gcp":   true,
		}
		config.CustomDNSServer = ""
		config.DNSResolverMode = "multiple"
		config.ResolverConfig = "default"
		config.AdditionalResolvers = ""
		config.MutationsFilePath = ""
		config.BruteFilePath = ""
		config.ResolverFilePath = ""
		config.SelectedServices = map[string][]string{
			"aws":   {"s3"},
			"azure": {"storage-accounts"},
			"gcp":   {"gcp-buckets"},
		}
		config.SelectedRegions = map[string][]string{
			"aws":   {"us-east-1"},
			"azure": {"eastus"},
			"gcp":   {"us-central1"},
		}
	} else {
		// Parse JSON fields
		json.Unmarshal(platformsJSON, &config.EnabledPlatforms)
		json.Unmarshal(servicesJSON, &config.SelectedServices)
		json.Unmarshal(regionsJSON, &config.SelectedRegions)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func saveCloudEnumConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	log.Printf("[CLOUD-ENUM-CONFIG] Saving configuration for scope target: %s", scopeTargetID)

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20) // 10 MB limit
	if err != nil {
		log.Printf("[CLOUD-ENUM-CONFIG] Error parsing multipart form: %v", err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get config JSON
	configJSON := r.FormValue("config")
	if configJSON == "" {
		http.Error(w, "Config is required", http.StatusBadRequest)
		return
	}

	var config struct {
		Keywords            []string               `json:"keywords"`
		Threads             int                    `json:"threads"`
		EnabledPlatforms    map[string]interface{} `json:"enabled_platforms"`
		CustomDNSServer     string                 `json:"custom_dns_server"`
		DNSResolverMode     string                 `json:"dns_resolver_mode"`
		ResolverConfig      string                 `json:"resolver_config"`
		AdditionalResolvers string                 `json:"additional_resolvers"`
		SelectedServices    map[string][]string    `json:"selected_services"`
		SelectedRegions     map[string][]string    `json:"selected_regions"`
	}

	err = json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		log.Printf("[CLOUD-ENUM-CONFIG] Error parsing config JSON: %v", err)
		http.Error(w, "Invalid config format", http.StatusBadRequest)
		return
	}

	// Handle file uploads
	var mutationsFilePath, bruteFilePath, resolverFilePath string

	// Create uploads directory if it doesn't exist
	os.MkdirAll("/tmp/cloud_enum_configs", 0755)

	// Handle mutations file
	mutationsFile, _, err := r.FormFile("mutations_file")
	if err == nil {
		defer mutationsFile.Close()

		mutationsFilePath = fmt.Sprintf("/tmp/cloud_enum_configs/mutations_%s.txt", scopeTargetID)
		outFile, err := os.Create(mutationsFilePath)
		if err != nil {
			log.Printf("[CLOUD-ENUM-CONFIG] Error creating mutations file: %v", err)
		} else {
			defer outFile.Close()
			io.Copy(outFile, mutationsFile)
			log.Printf("[CLOUD-ENUM-CONFIG] Saved mutations file: %s", mutationsFilePath)
		}
	}

	// Handle brute force file
	bruteFile, _, err := r.FormFile("brute_file")
	if err == nil {
		defer bruteFile.Close()

		bruteFilePath = fmt.Sprintf("/tmp/cloud_enum_configs/brute_%s.txt", scopeTargetID)
		outFile, err := os.Create(bruteFilePath)
		if err != nil {
			log.Printf("[CLOUD-ENUM-CONFIG] Error creating brute file: %v", err)
		} else {
			defer outFile.Close()
			io.Copy(outFile, bruteFile)
			log.Printf("[CLOUD-ENUM-CONFIG] Saved brute file: %s", bruteFilePath)
		}
	}

	// Handle resolver file
	resolverFile, _, err := r.FormFile("resolver_file")
	if err == nil {
		defer resolverFile.Close()

		resolverFilePath = fmt.Sprintf("/tmp/cloud_enum_configs/resolvers_%s.txt", scopeTargetID)
		outFile, err := os.Create(resolverFilePath)
		if err != nil {
			log.Printf("[CLOUD-ENUM-CONFIG] Error creating resolver file: %v", err)
		} else {
			defer outFile.Close()
			io.Copy(outFile, resolverFile)
			log.Printf("[CLOUD-ENUM-CONFIG] Saved resolver file: %s", resolverFilePath)
		}
	}

	// Convert to JSON for database storage (JSONB columns)
	platformsJSON, _ := json.Marshal(config.EnabledPlatforms)
	servicesJSON, _ := json.Marshal(config.SelectedServices)
	regionsJSON, _ := json.Marshal(config.SelectedRegions)

	// Insert or update config
	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO cloud_enum_configs (
			scope_target_id, keywords, threads, enabled_platforms, 
			custom_dns_server, dns_resolver_mode, resolver_config, additional_resolvers,
			mutations_file_path, brute_file_path, resolver_file_path, 
			selected_services, selected_regions, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP)
		ON CONFLICT (scope_target_id) 
		DO UPDATE SET 
			keywords = EXCLUDED.keywords,
			threads = EXCLUDED.threads,
			enabled_platforms = EXCLUDED.enabled_platforms,
			custom_dns_server = EXCLUDED.custom_dns_server,
			dns_resolver_mode = EXCLUDED.dns_resolver_mode,
			resolver_config = EXCLUDED.resolver_config,
			additional_resolvers = EXCLUDED.additional_resolvers,
			mutations_file_path = COALESCE(NULLIF(EXCLUDED.mutations_file_path, ''), cloud_enum_configs.mutations_file_path),
			brute_file_path = COALESCE(NULLIF(EXCLUDED.brute_file_path, ''), cloud_enum_configs.brute_file_path),
			resolver_file_path = COALESCE(NULLIF(EXCLUDED.resolver_file_path, ''), cloud_enum_configs.resolver_file_path),
			selected_services = EXCLUDED.selected_services,
			selected_regions = EXCLUDED.selected_regions,
			updated_at = CURRENT_TIMESTAMP
	`, scopeTargetID, config.Keywords, config.Threads, platformsJSON,
		config.CustomDNSServer, config.DNSResolverMode, config.ResolverConfig, config.AdditionalResolvers,
		mutationsFilePath, bruteFilePath, resolverFilePath, servicesJSON, regionsJSON)

	if err != nil {
		log.Printf("[CLOUD-ENUM-CONFIG] Error saving config: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("[CLOUD-ENUM-CONFIG] Configuration saved successfully for scope target: %s", scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func buildWordlistFromDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	wordlistType := vars["type"] // "mutations" or "brute"

	log.Printf("[BUILD-WORDLIST] Building %s wordlist for scope target: %s", wordlistType, scopeTargetID)

	// Get domains from various sources
	rootDomains, err := getConsolidatedRootDomains(scopeTargetID)
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error fetching root domains: %v", err)
	}

	amassEnumDomains, err := getAmassEnumDomains(scopeTargetID)
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error fetching Amass domains: %v", err)
	}

	dnsxDomains, err := getDNSxDomains(scopeTargetID)
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error fetching DNSx domains: %v", err)
	}

	liveWebServerDomains, err := getLiveWebServerDomains(scopeTargetID)
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error fetching live web server domains: %v", err)
	}

	// Combine all domains
	allDomains := append(rootDomains, amassEnumDomains...)
	allDomains = append(allDomains, dnsxDomains...)
	allDomains = append(allDomains, liveWebServerDomains...)

	log.Printf("[BUILD-WORDLIST] Found %d root domains, %d Amass domains, %d DNSx domains, %d live web server domains",
		len(rootDomains), len(amassEnumDomains), len(dnsxDomains), len(liveWebServerDomains))

	// Extract unique words from domains
	domainWords := make(map[string]bool)
	tlds := map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true,
		"mil": true, "co": true, "uk": true, "au": true, "ca": true,
		"de": true, "fr": true, "jp": true, "br": true, "mx": true,
		"in": true, "cn": true, "ru": true, "kr": true, "it": true,
		"www": true, "mail": true, "ftp": true, "smtp": true, "pop": true,
		"imap": true, "ns": true, "dns": true,
	}

	for _, domain := range allDomains {
		// Split domain by dots and extract words
		parts := strings.Split(strings.ToLower(domain), ".")
		for _, part := range parts {
			// Further split by hyphens and underscores
			subParts := strings.FieldsFunc(part, func(c rune) bool {
				return c == '-' || c == '_'
			})

			for _, word := range subParts {
				word = strings.TrimSpace(word)
				if len(word) >= 2 && !tlds[word] && word != "" {
					domainWords[word] = true
				}
			}
		}
	}

	// Build wordlist in container using the same pattern as resolvers
	containerName := "ars0n-framework-v2-cloud_enum-1"
	tempFile := fmt.Sprintf("/tmp/generated_%s_%s.txt", wordlistType, scopeTargetID)

	// Create the wordlist generation script
	var domainWordsList []string
	for word := range domainWords {
		domainWordsList = append(domainWordsList, word)
	}

	domainWordsContent := strings.Join(domainWordsList, "\n")

	createScript := fmt.Sprintf(`
		# Copy base rs0nfuzz.txt wordlist
		cp /app/rs0nfuzz.txt %s
		
		# Add domain-derived words
		cat << 'EOF' >> %s
%s
EOF
		
		# Remove duplicates and sort
		sort %s | uniq > %s.tmp && mv %s.tmp %s
	`, tempFile, tempFile, domainWordsContent, tempFile, tempFile, tempFile, tempFile)

	log.Printf("[BUILD-WORDLIST] Extracted %d unique words from domains", len(domainWordsList))

	// First test if rs0nfuzz.txt exists in container
	testCmd := exec.Command("docker", "exec", containerName, "test", "-f", "/app/rs0nfuzz.txt")
	if err := testCmd.Run(); err != nil {
		log.Printf("[BUILD-WORDLIST] rs0nfuzz.txt not found in container, using fallback approach")

		// Fallback: Create wordlist with domain words + basic terms
		fallbackWords := strings.Join(domainWordsList, "\n")
		if fallbackWords == "" {
			fallbackWords = "admin\napi\ndev\ntest\nstaging\nprod\nbackup\nassets\ndata\nfiles"
		} else {
			fallbackWords += "\nadmin\napi\ndev\ntest\nstaging\nprod\nbackup\nassets\ndata\nfiles"
		}

		// Count words in fallback
		fallbackWordCount := len(strings.Split(fallbackWords, "\n"))

		filename := fmt.Sprintf("%s-wordlist.txt", wordlistType)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fallbackWords)))

		w.Write([]byte(fallbackWords))

		log.Printf("[BUILD-WORDLIST] Generated %d total words (fallback) for %s wordlist",
			fallbackWordCount, wordlistType)
		return
	}

	log.Printf("[BUILD-WORDLIST] rs0nfuzz.txt found in container, executing script...")

	// Execute script in container
	cmd := exec.Command("docker", "exec", containerName, "sh", "-c", createScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error creating wordlist in container: %v", err)
		log.Printf("[BUILD-WORDLIST] Container output: %s", string(output))
		http.Error(w, "Failed to generate wordlist", http.StatusInternalServerError)
		return
	}
	log.Printf("[BUILD-WORDLIST] Container script executed successfully")

	// Copy the generated wordlist back to host for download
	hostTempFile := fmt.Sprintf("/tmp/wordlist_%s_%s.txt", wordlistType, scopeTargetID)
	copyCmd := exec.Command("docker", "cp", fmt.Sprintf("%s:%s", containerName, tempFile), hostTempFile)
	copyOutput, copyErr := copyCmd.CombinedOutput()
	if copyErr != nil {
		log.Printf("[BUILD-WORDLIST] Error copying wordlist from container: %v", copyErr)
		log.Printf("[BUILD-WORDLIST] Copy output: %s", string(copyOutput))
		http.Error(w, "Failed to retrieve wordlist", http.StatusInternalServerError)
		return
	}
	log.Printf("[BUILD-WORDLIST] Successfully copied wordlist from container to host")

	// Read the generated file to count words and send response
	content, err := os.ReadFile(hostTempFile)
	if err != nil {
		log.Printf("[BUILD-WORDLIST] Error reading generated wordlist: %v", err)
		http.Error(w, "Failed to read wordlist", http.StatusInternalServerError)
		return
	}

	// Count total words
	lines := strings.Split(string(content), "\n")
	var totalWords int
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			totalWords++
		}
	}

	baseWordCount := totalWords - len(domainWordsList)
	if baseWordCount < 0 {
		baseWordCount = 0
	}

	log.Printf("[BUILD-WORDLIST] Generated %d total words (%d from domains, %d from base) for %s wordlist",
		totalWords, len(domainWordsList), baseWordCount, wordlistType)

	// Set headers for file download
	filename := fmt.Sprintf("%s-wordlist.txt", wordlistType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))

	// Send file content
	w.Write(content)

	// Clean up temp files
	os.Remove(hostTempFile)

	// Clean up container temp file
	cleanupCmd := exec.Command("docker", "exec", containerName, "rm", "-f", tempFile)
	cleanupCmd.Run()
}

func getConsolidatedRootDomains(scopeTargetID string) ([]string, error) {
	var domains []string

	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT domain 
		FROM consolidated_company_domains 
		WHERE scope_target_id = $1
	`, scopeTargetID)
	if err != nil {
		return domains, err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

func getAmassEnumDomains(scopeTargetID string) ([]string, error) {
	var domains []string

	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT subdomain 
		FROM subdomains s
		JOIN amass_scans a ON s.scan_id = a.scan_id
		WHERE a.scope_target_id = $1
	`, scopeTargetID)
	if err != nil {
		return domains, err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

func getDNSxDomains(scopeTargetID string) ([]string, error) {
	var domains []string

	// Get domains from dnsx company scans
	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT record 
		FROM dns_records d
		JOIN dnsx_company_scans ds ON d.scan_id = ds.scan_id
		WHERE ds.scope_target_id = $1
		AND d.record_type IN ('A', 'AAAA', 'CNAME')
	`, scopeTargetID)
	if err != nil {
		return domains, err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

func getLiveWebServerDomains(scopeTargetID string) ([]string, error) {
	var domains []string
	domainMap := make(map[string]bool)

	// Get domains from live web server URLs
	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT lws.url 
		FROM live_web_servers lws
		JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		WHERE ips.scope_target_id = $1 AND ips.status = 'success' 
		AND lws.url IS NOT NULL AND lws.url != ''
	`, scopeTargetID)
	if err != nil {
		return domains, err
	}
	defer rows.Close()

	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err == nil {
			// Extract domain from URL
			if url != "" {
				if domain := extractDomainFromURL(url); domain != "" && !isIPv4Address(domain) {
					domainMap[domain] = true
				}
			}
		}
	}

	// Convert map to slice
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	return domains, nil
}

// Helper function to extract domain from URL
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

// Helper function to check if a string is an IPv4 address
func isIPv4Address(s string) bool {
	return strings.Contains(s, ".") &&
		len(strings.Split(s, ".")) == 4 &&
		!strings.Contains(s, " ")
}

func getKatanaCompanyConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	log.Printf("[INFO] Getting Katana Company config for scope target ID: %s", scopeTargetID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS katana_company_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			selected_wildcard_domains JSONB DEFAULT '[]',
			selected_live_web_servers JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`
	_, err := dbPool.Exec(context.Background(), createTableQuery)
	if err != nil {
		log.Printf("[ERROR] Failed to create katana_company_configs table: %v", err)
		http.Error(w, "Failed to create config table.", http.StatusInternalServerError)
		return
	}

	var config struct {
		ID                      string    `json:"id"`
		ScopeTargetID           string    `json:"scope_target_id"`
		SelectedDomains         []string  `json:"selected_domains"`
		IncludeWildcardResults  bool      `json:"include_wildcard_results"`
		SelectedWildcardDomains []string  `json:"selected_wildcard_domains"`
		SelectedLiveWebServers  []string  `json:"selected_live_web_servers"`
		CreatedAt               time.Time `json:"created_at"`
		UpdatedAt               time.Time `json:"updated_at"`
	}

	query := `SELECT id, scope_target_id, selected_domains, include_wildcard_results, selected_wildcard_domains, selected_live_web_servers, created_at, updated_at FROM katana_company_configs WHERE scope_target_id = $1`

	var selectedDomainsJSON, selectedWildcardDomainsJSON, selectedLiveWebServersJSON string
	err = dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(
		&config.ID,
		&config.ScopeTargetID,
		&selectedDomainsJSON,
		&config.IncludeWildcardResults,
		&selectedWildcardDomainsJSON,
		&selectedLiveWebServersJSON,
		&config.CreatedAt,
		&config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[INFO] No Katana Company config found for scope target %s, returning empty config", scopeTargetID)
			config = struct {
				ID                      string    `json:"id"`
				ScopeTargetID           string    `json:"scope_target_id"`
				SelectedDomains         []string  `json:"selected_domains"`
				IncludeWildcardResults  bool      `json:"include_wildcard_results"`
				SelectedWildcardDomains []string  `json:"selected_wildcard_domains"`
				SelectedLiveWebServers  []string  `json:"selected_live_web_servers"`
				CreatedAt               time.Time `json:"created_at"`
				UpdatedAt               time.Time `json:"updated_at"`
			}{
				ScopeTargetID:           scopeTargetID,
				SelectedDomains:         []string{},
				IncludeWildcardResults:  false,
				SelectedWildcardDomains: []string{},
				SelectedLiveWebServers:  []string{},
			}
		} else {
			log.Printf("[ERROR] Failed to get Katana Company config: %v", err)
			http.Error(w, "Failed to get config", http.StatusInternalServerError)
			return
		}
	} else {
		json.Unmarshal([]byte(selectedDomainsJSON), &config.SelectedDomains)
		json.Unmarshal([]byte(selectedWildcardDomainsJSON), &config.SelectedWildcardDomains)
		json.Unmarshal([]byte(selectedLiveWebServersJSON), &config.SelectedLiveWebServers)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func saveKatanaCompanyConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	log.Printf("[INFO] Saving Katana Company config for scope target ID: %s", scopeTargetID)

	var config struct {
		SelectedDomains         []string `json:"selected_domains"`
		IncludeWildcardResults  bool     `json:"include_wildcard_results"`
		SelectedWildcardDomains []string `json:"selected_wildcard_domains"`
		SelectedLiveWebServers  []string `json:"selected_live_web_servers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	selectedDomainsJSON, _ := json.Marshal(config.SelectedDomains)
	selectedWildcardDomainsJSON, _ := json.Marshal(config.SelectedWildcardDomains)
	selectedLiveWebServersJSON, _ := json.Marshal(config.SelectedLiveWebServers)

	query := `
		INSERT INTO katana_company_configs (scope_target_id, selected_domains, include_wildcard_results, selected_wildcard_domains, selected_live_web_servers, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (scope_target_id)
		DO UPDATE SET
			selected_domains = $2,
			include_wildcard_results = $3,
			selected_wildcard_domains = $4,
			selected_live_web_servers = $5,
			updated_at = NOW()
	`

	_, err := dbPool.Exec(context.Background(), query, scopeTargetID, selectedDomainsJSON, config.IncludeWildcardResults, selectedWildcardDomainsJSON, selectedLiveWebServersJSON)
	if err != nil {
		log.Printf("[ERROR] Failed to save Katana Company config: %v", err)
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Successfully saved Katana Company config for scope target %s", scopeTargetID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Nuclei Configuration handlers
func getNucleiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope_target_id", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Getting Nuclei config for scope target: %s", scopeTargetID)

	var targets, templates, severities []string
	var uploadedTemplates []byte
	var createdAt time.Time

	err := dbPool.QueryRow(context.Background(),
		`SELECT targets, templates, severities, uploaded_templates, created_at FROM nuclei_configs WHERE scope_target_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID).Scan(&targets, &templates, &severities, &uploadedTemplates, &createdAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[INFO] No Nuclei config found for scope target %s", scopeTargetID)
			defaultTemplates := []string{"cves", "vulnerabilities", "exposures", "technologies", "misconfiguration", "takeovers", "network", "dns", "headless"}
			defaultSeverities := []string{"critical", "high", "medium", "low", "info"}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"targets":            []string{},
				"templates":          defaultTemplates,
				"severities":         defaultSeverities,
				"uploaded_templates": []interface{}{},
				"created_at":         nil,
			})
			return
		}
		log.Printf("[ERROR] Failed to get Nuclei config: %v", err)
		http.Error(w, "Failed to get config", http.StatusInternalServerError)
		return
	}

	var uploadedTemplatesData []interface{}
	if len(uploadedTemplates) > 0 {
		if err := json.Unmarshal(uploadedTemplates, &uploadedTemplatesData); err != nil {
			log.Printf("[WARN] Failed to unmarshal uploaded templates: %v", err)
			uploadedTemplatesData = []interface{}{}
		}
	}

	response := map[string]interface{}{
		"targets":            targets,
		"templates":          templates,
		"severities":         severities,
		"uploaded_templates": uploadedTemplatesData,
		"created_at":         createdAt,
	}

	log.Printf("[INFO] Successfully retrieved Nuclei config for scope target %s", scopeTargetID)
	json.NewEncoder(w).Encode(response)
}

func saveNucleiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope_target_id", http.StatusBadRequest)
		return
	}

	var config struct {
		Targets           []string      `json:"targets"`
		Templates         []string      `json:"templates"`
		Severities        []string      `json:"severities"`
		UploadedTemplates []interface{} `json:"uploaded_templates"`
		CreatedAt         string        `json:"created_at"`
	}

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		log.Printf("[ERROR] Failed to decode Nuclei config: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Saving Nuclei config for scope target %s", scopeTargetID)
	log.Printf("[INFO] Targets: %d, Templates: %d, Uploaded Templates: %d", len(config.Targets), len(config.Templates), len(config.UploadedTemplates))

	uploadedTemplatesJSON, _ := json.Marshal(config.UploadedTemplates)

	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO nuclei_configs (scope_target_id, targets, templates, severities, uploaded_templates, created_at)
		VALUES ($1::uuid, $2, $3, $4, $5, NOW())
		ON CONFLICT (scope_target_id) 
		DO UPDATE SET 
			targets = EXCLUDED.targets,
			templates = EXCLUDED.templates,
			severities = EXCLUDED.severities,
			uploaded_templates = EXCLUDED.uploaded_templates,
			created_at = NOW()
	`, scopeTargetID, config.Targets, config.Templates, config.Severities, uploadedTemplatesJSON)

	if err != nil {
		log.Printf("[ERROR] Failed to save Nuclei config: %v", err)
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Successfully saved Nuclei config for scope target %s", scopeTargetID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func getNucleiScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Getting Nuclei scans for scope target: %s", scopeTargetID)

	query := `
		SELECT scan_id, status, targets, templates, result, error, created_at, execution_time
		FROM nuclei_scans 
		WHERE scope_target_id = $1::uuid 
		ORDER BY created_at DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Nuclei scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scanID, status, result, error, executionTime sql.NullString
		var targets, templates []string
		var createdAt time.Time

		err := rows.Scan(&scanID, &status, &targets, &templates, &result, &error, &createdAt, &executionTime)
		if err != nil {
			log.Printf("[ERROR] Failed to scan Nuclei scan row: %v", err)
			continue
		}

		scan := map[string]interface{}{
			"scan_id":        scanID.String,
			"status":         status.String,
			"targets":        targets,
			"templates":      templates,
			"result":         result.String,
			"error":          error.String,
			"created_at":     createdAt,
			"execution_time": executionTime.String,
		}

		scans = append(scans, scan)
	}

	log.Printf("[INFO] Found %d Nuclei scans for scope target %s", len(scans), scopeTargetID)

	// Debug: Log the first scan's result if it exists
	if len(scans) > 0 {
		if result, exists := scans[0]["result"]; exists && result != nil {
			if resultStr, ok := result.(string); ok && len(resultStr) > 0 {
				log.Printf("[DEBUG] First scan result (first 500 chars): %s", resultStr[:min(len(resultStr), 500)])
				log.Printf("[DEBUG] First scan result length: %d", len(resultStr))
			}
		}
	}

	json.NewEncoder(w).Encode(scans)
}

func startNucleiScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Starting Nuclei scan for scope target: %s", scopeTargetID)

	// Get the latest Nuclei config for this scope target
	var targets, templates, severities []string
	var uploadedTemplatesJSON []byte
	err := dbPool.QueryRow(context.Background(),
		`SELECT targets, templates, severities, uploaded_templates FROM nuclei_configs WHERE scope_target_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID).Scan(&targets, &templates, &severities, &uploadedTemplatesJSON)

	if err != nil {
		log.Printf("[ERROR] Failed to get Nuclei config: %v", err)
		http.Error(w, "No Nuclei configuration found. Please configure targets and templates first.", http.StatusBadRequest)
		return
	}

	if len(targets) == 0 {
		http.Error(w, "No targets configured. Please configure targets first.", http.StatusBadRequest)
		return
	}

	// Parse uploaded templates
	var uploadedTemplates []map[string]interface{}
	if len(uploadedTemplatesJSON) > 0 {
		if err := json.Unmarshal(uploadedTemplatesJSON, &uploadedTemplates); err != nil {
			log.Printf("[WARN] Failed to parse uploaded templates: %v", err)
		}
	}

	// Generate scan ID
	scanID := uuid.New().String()

	// Insert scan record with pending status
	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO nuclei_scans (scan_id, scope_target_id, targets, templates, status, created_at) 
		VALUES ($1, $2::uuid, $3, $4, 'pending', NOW())
	`, scanID, scopeTargetID, targets, templates)

	if err != nil {
		log.Printf("[ERROR] Failed to insert Nuclei scan record: %v", err)
		http.Error(w, "Failed to create scan record", http.StatusInternalServerError)
		return
	}

	// Start scan in background goroutine
	go func() {
		log.Printf("[INFO] Starting background Nuclei scan %s", scanID)

		// Update status to running
		_, err := dbPool.Exec(context.Background(), `
			UPDATE nuclei_scans SET status = 'running', updated_at = NOW() WHERE scan_id = $1
		`, scanID)

		if err != nil {
			log.Printf("[ERROR] Failed to update scan status to running: %v", err)
			return
		}

		startTime := time.Now()

		// Execute the scan
		outputFile, findings, err := utils.ExecuteNucleiScanForScopeTarget(scopeTargetID, targets, templates, severities, uploadedTemplates, dbPool)

		executionTime := time.Since(startTime)

		if err != nil {
			log.Printf("[ERROR] Nuclei scan failed: %v", err)

			// Update scan with error status
			_, updateErr := dbPool.Exec(context.Background(), `
				UPDATE nuclei_scans SET 
					status = 'failed', 
					error = $1, 
					execution_time = $2,
					updated_at = NOW() 
				WHERE scan_id = $3
			`, err.Error(), executionTime.String(), scanID)

			if updateErr != nil {
				log.Printf("[ERROR] Failed to update scan with error: %v", updateErr)
			}
			return
		}

		// Convert findings to JSON
		findingsJSON, err := json.Marshal(findings)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal findings: %v", err)
			findingsJSON = []byte("[]")
		}

		// Update scan with success status and results
		_, err = dbPool.Exec(context.Background(), `
			UPDATE nuclei_scans SET 
				status = 'success', 
				result = $1, 
				execution_time = $2,
				updated_at = NOW() 
			WHERE scan_id = $3
		`, string(findingsJSON), executionTime.String(), scanID)

		if err != nil {
			log.Printf("[ERROR] Failed to update scan with results: %v", err)
		} else {
			log.Printf("[INFO] Nuclei scan %s completed successfully with %d findings", scanID, len(findings))
		}

		// Clean up output file
		if outputFile != "" {
			os.Remove(outputFile)
		}
	}()

	// Return scan ID immediately
	response := map[string]string{
		"scan_id": scanID,
		"status":  "pending",
		"message": "Nuclei scan started successfully",
	}

	log.Printf("[INFO] Nuclei scan %s initiated for scope target %s", scanID, scopeTargetID)
	json.NewEncoder(w).Encode(response)
}

func getNucleiScanStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	if scanID == "" {
		http.Error(w, "Missing scan_id parameter", http.StatusBadRequest)
		return
	}

	var status, result, error, executionTime sql.NullString
	var createdAt, updatedAt time.Time

	err := dbPool.QueryRow(context.Background(), `
		SELECT status, result, error, execution_time, created_at, updated_at
		FROM nuclei_scans 
		WHERE scan_id = $1
	`, scanID).Scan(&status, &result, &error, &executionTime, &createdAt, &updatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] Failed to get scan status: %v", err)
		http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"scan_id":        scanID,
		"status":         status.String,
		"result":         result.String,
		"error":          error.String,
		"execution_time": executionTime.String,
		"created_at":     createdAt,
		"updated_at":     updatedAt,
	}

	json.NewEncoder(w).Encode(response)
}
