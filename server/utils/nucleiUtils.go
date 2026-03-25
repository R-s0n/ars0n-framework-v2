package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type NucleiFinding struct {
	TemplateID    string     `json:"template-id"`
	Info          NucleiInfo `json:"info"`
	Type          string     `json:"type"`
	Host          string     `json:"host"`
	Matched       string     `json:"matched"`
	MatchedAt     string     `json:"matched-at"`
	IP            string     `json:"ip"`
	Port          string     `json:"port"`
	URL           string     `json:"url"`
	Timestamp     string     `json:"timestamp"`
	MatcherName   string     `json:"matcher-name,omitempty"`
	MatcherStatus bool       `json:"matcher-status,omitempty"`
	Extracted     []string   `json:"extracted-results,omitempty"`
	CurlCommand   string     `json:"curl-command,omitempty"`
	Request       string     `json:"request,omitempty"`
	Response      string     `json:"response,omitempty"`
}

type NucleiInfo struct {
	Name        string   `json:"name"`
	Author      []string `json:"author,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
}

func convertAttackSurfaceAssetsToTargets(assetIDs []string, scopeTargetID string, dbPool *pgxpool.Pool) ([]string, error) {
	var targets []string

	log.Printf("[DEBUG] Converting %d asset IDs to Nuclei targets", len(assetIDs))

	for _, assetID := range assetIDs {
		var assetType, assetIdentifier string
		var asnNumber, cidrBlock, ipAddress, url, fqdn *string

		err := dbPool.QueryRow(context.Background(), `
			SELECT asset_type, asset_identifier, asn_number, cidr_block, ip_address, url, fqdn
			FROM consolidated_attack_surface_assets 
			WHERE id = $1 AND scope_target_id = $2
		`, assetID, scopeTargetID).Scan(&assetType, &assetIdentifier, &asnNumber, &cidrBlock, &ipAddress, &url, &fqdn)

		if err != nil {
			log.Printf("[WARN] Failed to get asset %s: %v", assetID, err)
			continue
		}

		log.Printf("[DEBUG] Processing asset %s: type=%s, identifier=%s", assetID, assetType, assetIdentifier)

		switch assetType {
		case "asn":
			if asnNumber != nil {
				target := "AS" + *asnNumber
				targets = append(targets, target)
				log.Printf("[DEBUG] Added ASN target: %s", target)
			}
		case "network_range":
			if cidrBlock != nil {
				targets = append(targets, *cidrBlock)
				log.Printf("[DEBUG] Added network range target: %s", *cidrBlock)
			}
		case "ip_address":
			if ipAddress != nil {
				targets = append(targets, *ipAddress)
				log.Printf("[DEBUG] Added IP target: %s", *ipAddress)
			}
		case "live_web_server":
			if url != nil {
				targets = append(targets, *url)
				log.Printf("[DEBUG] Added live web server target: %s", *url)
			}
		case "fqdn":
			if fqdn != nil {
				targets = append(targets, *fqdn)
				log.Printf("[DEBUG] Added FQDN target: %s", *fqdn)
			}
		case "cloud_asset":
			if url != nil {
				targets = append(targets, *url)
				log.Printf("[DEBUG] Added cloud asset target (URL): %s", *url)
			} else if fqdn != nil {
				targets = append(targets, *fqdn)
				log.Printf("[DEBUG] Added cloud asset target (FQDN): %s", *fqdn)
			}
		}
	}

	log.Printf("[DEBUG] Converted %d asset IDs to %d Nuclei targets", len(assetIDs), len(targets))
	return targets, nil
}

type logWriter struct {
	prefix string
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	output := string(p)
	lines := strings.Split(strings.TrimRight(output, "\n\r"), "\n")
	for _, line := range lines {
		if line != "" {
			log.Printf("%s %s", lw.prefix, line)
		}
	}
	return len(p), nil
}

type capturingLogWriter struct {
	prefix  string
	buf     bytes.Buffer
}

func (cw *capturingLogWriter) Write(p []byte) (n int, err error) {
	cw.buf.Write(p)
	output := string(p)
	lines := strings.Split(strings.TrimRight(output, "\n\r"), "\n")
	for _, line := range lines {
		if line != "" {
			log.Printf("%s %s", cw.prefix, line)
		}
	}
	return len(p), nil
}

func getFloatConfig(config map[string]interface{}, key string, defaultVal float64) float64 {
	if v, ok := config[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		}
	}
	return defaultVal
}

func getStringConfig(config map[string]interface{}, key string, defaultVal string) string {
	if v, ok := config[key]; ok {
		if val, ok := v.(string); ok {
			return val
		}
	}
	return defaultVal
}

func getBoolConfig(config map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := config[key]; ok {
		if val, ok := v.(bool); ok {
			return val
		}
	}
	return defaultVal
}

func getStringSliceConfig(config map[string]interface{}, key string) []string {
	if v, ok := config[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			var result []string
			for _, item := range arr {
				if s, ok := item.(string); ok && s != "" {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return nil
}

func executeNucleiScan(targets []string, templates []string, severities []string,
	templateIDs []string, excludeIDs []string, excludeTags []string,
	uploadedTemplates []map[string]interface{}, advancedConfig map[string]interface{},
	outputFile string, capturedStdout *bytes.Buffer) error {

	log.Printf("[DEBUG] Starting Nuclei scan with %d targets", len(targets))
	log.Printf("[DEBUG] Targets: %v", targets)
	log.Printf("[DEBUG] Templates: %v", templates)
	log.Printf("[DEBUG] TemplateIDs: %v", templateIDs)
	log.Printf("[DEBUG] Severities: %v", severities)
	log.Printf("[DEBUG] ExcludeIDs: %v", excludeIDs)
	log.Printf("[DEBUG] ExcludeTags: %v", excludeTags)

	tempFile, err := os.CreateTemp("", "nuclei_targets_*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp targets file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	targetsContent := strings.Join(targets, "\n")
	if _, err := tempFile.WriteString(targetsContent); err != nil {
		return fmt.Errorf("failed to write targets to temp file: %v", err)
	}
	tempFile.Close()

	log.Printf("[DEBUG] Created temp targets file: %s with %d targets", tempFile.Name(), len(targets))

	copyCmd := exec.Command(
		"docker", "cp",
		tempFile.Name(),
		"ars0n-framework-v2-nuclei-1:/targets.txt",
	)
	if err := copyCmd.Run(); err != nil {
		return fmt.Errorf("failed to copy targets file to container: %v", err)
	}

	var args []string
	args = append(args, "-list", "/targets.txt", "-jsonl", "-nh", "-o", "/output.jsonl")

	rateLimit := int(getFloatConfig(advancedConfig, "rate_limit", 150))
	bulkSize := int(getFloatConfig(advancedConfig, "bulk_size", 25))
	concurrency := int(getFloatConfig(advancedConfig, "concurrency", 25))
	timeout := int(getFloatConfig(advancedConfig, "timeout", 10))
	retries := int(getFloatConfig(advancedConfig, "retries", 1))
	maxHostError := int(getFloatConfig(advancedConfig, "max_host_error", 30))

	args = append(args, "-c", fmt.Sprintf("%d", concurrency))
	args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	args = append(args, "-timeout", fmt.Sprintf("%d", timeout))
	args = append(args, "-retries", fmt.Sprintf("%d", retries))
	args = append(args, "-bs", fmt.Sprintf("%d", bulkSize))
	args = append(args, "-mhe", fmt.Sprintf("%d", maxHostError))

	if getBoolConfig(advancedConfig, "follow_redirects", false) {
		args = append(args, "-fr")
	}
	if getBoolConfig(advancedConfig, "follow_host_redirects", false) {
		args = append(args, "-fhr")
	}

	maxRedirects := int(getFloatConfig(advancedConfig, "max_redirects", 10))
	if maxRedirects != 10 {
		args = append(args, "-mr", fmt.Sprintf("%d", maxRedirects))
	}

	customHeaders := getStringSliceConfig(advancedConfig, "custom_headers")
	for _, header := range customHeaders {
		if header != "" {
			args = append(args, "-H", header)
		}
	}

	proxy := getStringConfig(advancedConfig, "proxy", "")
	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}

	if getBoolConfig(advancedConfig, "no_interactsh", false) {
		args = append(args, "-ni")
	}
	interactshServer := getStringConfig(advancedConfig, "interactsh_server", "")
	if interactshServer != "" {
		args = append(args, "-iserver", interactshServer)
	}
	interactshToken := getStringConfig(advancedConfig, "interactsh_token", "")
	if interactshToken != "" {
		args = append(args, "-itoken", interactshToken)
	}

	if getBoolConfig(advancedConfig, "headless", false) {
		args = append(args, "-headless")
		hbs := int(getFloatConfig(advancedConfig, "headless_bulk_size", 10))
		hc := int(getFloatConfig(advancedConfig, "headless_concurrency", 10))
		args = append(args, "-hbs", fmt.Sprintf("%d", hbs))
		args = append(args, "-headc", fmt.Sprintf("%d", hc))
	}

	scanStrategy := getStringConfig(advancedConfig, "scan_strategy", "auto")
	if scanStrategy != "auto" && scanStrategy != "" {
		args = append(args, "-ss", scanStrategy)
	}

	if getBoolConfig(advancedConfig, "stop_at_first_match", false) {
		args = append(args, "-spm")
	}

	protocolTypes := getStringSliceConfig(advancedConfig, "protocol_types")
	for _, pt := range protocolTypes {
		args = append(args, "-pt", pt)
	}

	templateCondition := getStringConfig(advancedConfig, "template_condition", "")
	if templateCondition != "" {
		args = append(args, "-tc", templateCondition)
	}

	authorFilter := getStringSliceConfig(advancedConfig, "author_filter")
	for _, author := range authorFilter {
		args = append(args, "-a", author)
	}

	if getBoolConfig(advancedConfig, "system_resolvers", false) {
		args = append(args, "-sr")
	}

	if getBoolConfig(advancedConfig, "leave_default_ports", false) {
		args = append(args, "-ldp")
	}

	if len(templateIDs) > 0 {
		for _, tid := range templateIDs {
			if tid != "" {
				args = append(args, "-id", tid)
			}
		}
	}

	if len(templates) > 0 {
		for _, template := range templates {
			switch template {
			case "cves":
				args = append(args, "-tags", "cve")
			case "vulnerabilities":
				args = append(args, "-tags", "vuln")
			case "exposures":
				args = append(args, "-tags", "exposure")
			case "technologies":
				args = append(args, "-tags", "tech")
			case "misconfiguration":
				args = append(args, "-tags", "misconfig")
			case "takeovers":
				args = append(args, "-tags", "takeover")
			case "network":
				args = append(args, "-tags", "network")
			case "dns":
				args = append(args, "-tags", "dns")
			case "headless":
				args = append(args, "-tags", "headless")
			}
		}
	}

	for _, eid := range excludeIDs {
		if eid != "" {
			args = append(args, "-eid", eid)
		}
	}

	for _, etag := range excludeTags {
		if etag != "" {
			args = append(args, "-etags", etag)
		}
	}

	if len(severities) > 0 {
		severityArgs := []string{}
		for _, severity := range severities {
			severityArgs = append(severityArgs, "-severity", severity)
		}
		args = append(args, severityArgs...)
	}

	if len(uploadedTemplates) > 0 {
		mkdirCmd := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "mkdir", "-p", "/custom_templates")
		if err := mkdirCmd.Run(); err != nil {
			return fmt.Errorf("failed to create custom templates directory: %v", err)
		}

		for i, template := range uploadedTemplates {
			if content, ok := template["content"].(string); ok {
				tempTemplateFile, err := os.CreateTemp("", fmt.Sprintf("nuclei_template_%d_*.yaml", i))
				if err != nil {
					log.Printf("[WARN] Failed to create temp template file %d: %v", i, err)
					continue
				}

				if _, err := tempTemplateFile.WriteString(content); err != nil {
					log.Printf("[WARN] Failed to write template content %d: %v", i, err)
					tempTemplateFile.Close()
					os.Remove(tempTemplateFile.Name())
					continue
				}
				tempTemplateFile.Close()

				templatePath := fmt.Sprintf("/custom_templates/custom_%d.yaml", i)
				copyTemplateCmd := exec.Command("docker", "cp", tempTemplateFile.Name(), "ars0n-framework-v2-nuclei-1:"+templatePath)
				if err := copyTemplateCmd.Run(); err != nil {
					log.Printf("[WARN] Failed to copy custom template %d to container: %v", i, err)
				}

				os.Remove(tempTemplateFile.Name())
			}
		}

		args = append(args, "-t", "/custom_templates")
	}

	dockerArgs := []string{"exec", "-i", "ars0n-framework-v2-nuclei-1", "nuclei"}
	dockerArgs = append(dockerArgs, args...)

	log.Printf("[INFO] Executing Nuclei command: docker %s", strings.Join(dockerArgs, " "))
	dockerCmd := exec.Command("docker", dockerArgs...)

	stdoutWriter := &capturingLogWriter{prefix: "[NUCLEI]"}
	stderrWriter := &logWriter{prefix: "[NUCLEI-ERR]"}

	dockerCmd.Stdout = stdoutWriter
	dockerCmd.Stderr = stderrWriter

	if err = dockerCmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start Nuclei command: %v", err)
		return fmt.Errorf("failed to start nuclei: %v", err)
	}

	log.Printf("[INFO] Nuclei scan started, streaming output...")

	if err = dockerCmd.Wait(); err != nil {
		log.Printf("[ERROR] Nuclei command failed: %v", err)
		return fmt.Errorf("nuclei execution failed: %v", err)
	}

	log.Printf("[INFO] Nuclei scan completed successfully")

	if capturedStdout != nil {
		capturedStdout.Write(stdoutWriter.buf.Bytes())
	}

	copyOutputCmd := exec.Command(
		"docker", "cp",
		"ars0n-framework-v2-nuclei-1:/output.jsonl",
		outputFile,
	)
	if err := copyOutputCmd.Run(); err != nil {
		log.Printf("[WARN] Failed to copy output file from container: %v", err)
		readOutputCmd := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "cat", "/output.jsonl")
		if outputContent, readErr := readOutputCmd.Output(); readErr == nil {
			if writeErr := os.WriteFile(outputFile, outputContent, 0644); writeErr != nil {
				return fmt.Errorf("failed to copy output from container and write to host: %v", writeErr)
			}
			log.Printf("[INFO] Successfully read output directly from container")
		} else {
			log.Printf("[WARN] Fallback cat also failed: %v, using captured stdout", readErr)
			if stdoutWriter.buf.Len() > 0 {
				if writeErr := os.WriteFile(outputFile, stdoutWriter.buf.Bytes(), 0644); writeErr != nil {
					return fmt.Errorf("failed to write captured stdout to output file: %v", writeErr)
				}
				log.Printf("[INFO] Successfully recovered output from captured stdout (%d bytes)", stdoutWriter.buf.Len())
			} else {
				return fmt.Errorf("failed to copy output file from container and no stdout captured: %v", err)
			}
		}
	}

	log.Printf("[DEBUG] Output file created at: %s", outputFile)

	if fileInfo, err := os.Stat(outputFile); err == nil {
		log.Printf("[DEBUG] Output file exists, size: %d bytes", fileInfo.Size())
		if fileInfo.Size() > 0 {
			content, _ := os.ReadFile(outputFile)
			contentLen := len(content)
			if contentLen > 500 {
				contentLen = 500
			}
			log.Printf("[DEBUG] Output file content (first %d chars): %s", contentLen, string(content[:contentLen]))
		}
	} else {
		log.Printf("[DEBUG] Output file does not exist: %v", err)
	}

	cleanupCmd := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "rm", "-f", "/targets.txt", "/output.jsonl")
	cleanupCmd.Run()

	return nil
}

func parseNucleiResults(outputFile string) ([]NucleiFinding, error) {
	var findings []NucleiFinding

	log.Printf("[DEBUG] Parsing Nuclei results from file: %s", outputFile)

	content, err := os.ReadFile(outputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to read results file: %v", err)
		return findings, fmt.Errorf("failed to read results file: %v", err)
	}

	log.Printf("[DEBUG] Read %d bytes from results file", len(content))
	log.Printf("[DEBUG] Results file content:\n%s", string(content))

	lines := strings.Split(string(content), "\n")
	log.Printf("[DEBUG] Found %d lines in results file", len(lines))

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		log.Printf("[DEBUG] Parsing line %d: %s", lineNum+1, line)

		var finding NucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			log.Printf("[WARN] Failed to parse JSON on line %d: %v", lineNum+1, err)
			continue
		}

		log.Printf("[DEBUG] Successfully parsed finding: %s", finding.TemplateID)
		findings = append(findings, finding)
	}

	log.Printf("[INFO] Parsed %d findings from Nuclei results", len(findings))
	return findings, nil
}

func ExecuteNucleiScanForScopeTarget(scopeTargetID string, selectedTargets []string, selectedTemplates []string,
	selectedSeverities []string, templateIDs []string, excludeIDs []string, excludeTags []string,
	uploadedTemplates []map[string]interface{}, advancedConfig map[string]interface{},
	dbPool *pgxpool.Pool) (string, []NucleiFinding, error) {

	targets, err := convertAttackSurfaceAssetsToTargets(selectedTargets, scopeTargetID, dbPool)
	if err != nil {
		return "", nil, fmt.Errorf("failed to convert targets: %v", err)
	}

	if len(targets) == 0 {
		return "", nil, fmt.Errorf("no valid targets found")
	}

	outputDir := filepath.Join(os.TempDir(), "nuclei_scans")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("nuclei_scan_%s_%d.jsonl", scopeTargetID, time.Now().Unix()))

	if err := executeNucleiScan(targets, selectedTemplates, selectedSeverities,
		templateIDs, excludeIDs, excludeTags,
		uploadedTemplates, advancedConfig, outputFile, nil); err != nil {
		return "", nil, fmt.Errorf("scan execution failed: %v", err)
	}

	findings, err := parseNucleiResults(outputFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse results: %v", err)
	}

	return outputFile, findings, nil
}

func ExecuteNucleiScanDirect(targets []string, selectedTemplates []string,
	selectedSeverities []string, templateIDs []string, excludeIDs []string, excludeTags []string,
	uploadedTemplates []map[string]interface{}, advancedConfig map[string]interface{}) (string, []NucleiFinding, error) {

	if len(targets) == 0 {
		return "", nil, fmt.Errorf("no targets provided")
	}

	outputDir := filepath.Join(os.TempDir(), "nuclei_scans")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("nuclei_scan_direct_%d.jsonl", time.Now().Unix()))

	if err := executeNucleiScan(targets, selectedTemplates, selectedSeverities,
		templateIDs, excludeIDs, excludeTags,
		uploadedTemplates, advancedConfig, outputFile, nil); err != nil {
		return "", nil, fmt.Errorf("scan execution failed: %v", err)
	}

	findings, err := parseNucleiResults(outputFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse results: %v", err)
	}

	return outputFile, findings, nil
}
