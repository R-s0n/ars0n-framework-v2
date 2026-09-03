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
	prefix string
	buf    bytes.Buffer
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

// nucleiWildcardBaseArity is the arity of every flag executeNucleiScan builds for itself, so the
// Wildcard settings overlay can walk the vector and never mistake a value for a flag.
//
// Keep it in step with the args below. A flag missing from here is not a crash; it means the token
// after it is inspected as though it were a flag, which only matters if a header value or a template
// id happens to spell one.
var nucleiWildcardBaseArity = map[string]int{
	"-list": 1, "-jsonl": 0, "-nh": 0, "-o": 1,
	"-c": 1, "-rl": 1, "-timeout": 1, "-retries": 1, "-bs": 1, "-mhe": 1,
	"-fr": 0, "-fhr": 0, "-mr": 1, "-H": 1, "-proxy": 1,
	"-ni": 0, "-iserver": 1, "-itoken": 1,
	"-headless": 0, "-hbs": 1, "-headc": 1,
	"-ss": 1, "-spm": 0, "-pt": 1, "-tc": 1, "-a": 1,
	"-sr": 0, "-ldp": 0,
	"-id": 1, "-tags": 1, "-eid": 1, "-etags": 1, "-severity": 1, "-t": 1,
}

// applyNucleiWildcardSettings overlays the per-target Wildcard settings onto the argument vector
// this function has already built from nuclei_configs.advanced_config.
//
// PRECEDENCE, DECIDED AND STATED: THE WILDCARD SETTING WINS. Every engine option in the Wildcard
// vocabulary declares a shadowed_by against an advanced_config key, and this runner emits -c, -rl,
// -timeout, -retries, -bs and -mhe on EVERY scan whether or not anything is stored, falling back to
// hardcoded defaults on a key miss. So if advanced_config won, a Wildcard rate limit could never
// take effect under any circumstances: it would save successfully, appear in would_add_args, and be
// displaced on every single run. There is no version of "the other store wins" that leaves this
// screen honest, which is why the more specific per-target value takes it, in place, so the stored
// command shows one value for one flag.
//
// THE OTHER HALF OF THAT DECISION IS THAT THE UI MUST SAY SO. The Configure modal's Advanced
// Settings accordion still writes advanced_config, and an operator who tunes a rate limit there and
// sees a different one on the scan deserves to know which store they are looking at.
func applyNucleiWildcardSettings(args []string, scopeTargetID string) ([]string, []string) {
	tool, settings := wildcardRunnerSettings(scopeTargetID, "nuclei")
	return composeNucleiWildcardArgs(tool, settings, args)
}

// composeNucleiWildcardArgs is the pure half of the above, so the overlay can be proven without a
// database. Everything that decides what the command line looks like lives here.
func composeNucleiWildcardArgs(tool WildcardTool, settings map[string]any, args []string) ([]string, []string) {
	if len(settings) == 0 {
		return args, nil
	}

	overlay := wildcardOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: nucleiWildcardBaseArity,
	}
	out, notes := overlay.apply(args)

	// MEASURED, and it is a defect rather than a preference: `nuclei -headless` without -sc starts
	// downloading chrome-linux.zip, about 150MB, from storage.googleapis.com AT SCAN TIME, even though
	// /usr/bin/google-chrome is already installed in this container; the same run with -sc completed
	// RC=0 with no download. On an egress-filtered host that download is also how a headless scan
	// comes to produce nothing. This only fires when the WILDCARD settings are what turned headless
	// on, so a scan configured entirely through the existing Configure modal behaves exactly as it
	// did before, and an operator who deliberately sets systemChrome to false is obeyed.
	if truthySetting(settings["headless"]) {
		if explicit, set := settings["systemChrome"].(bool); !set || explicit {
			if wildcardFlagIndex(out, nucleiWildcardBaseArity, "-sc") < 0 {
				out = append(out, "-sc")
				notes = append(notes, "-sc was added alongside -headless. Measured on this exact container: "+
					"headless without it downloads ~150MB of Chromium at scan time even though Chrome is already "+
					"installed at /usr/bin/google-chrome. Set systemChrome to false to suppress this.")
			}
		}
	}

	return out, notes
}

func executeNucleiScan(targets []string, templates []string, severities []string,
	templateIDs []string, excludeIDs []string, excludeTags []string,
	uploadedTemplates []map[string]interface{}, advancedConfig map[string]interface{},
	outputFile string, capturedStdout *bytes.Buffer, scopeTargetID string) (string, error) {

	log.Printf("[DEBUG] Starting Nuclei scan with %d targets", len(targets))
	log.Printf("[DEBUG] Targets: %v", targets)
	log.Printf("[DEBUG] Templates: %v", templates)
	log.Printf("[DEBUG] TemplateIDs: %v", templateIDs)
	log.Printf("[DEBUG] Severities: %v", severities)
	log.Printf("[DEBUG] ExcludeIDs: %v", excludeIDs)
	log.Printf("[DEBUG] ExcludeTags: %v", excludeTags)

	// The command as it was finally composed, returned to the caller so it can be written onto the
	// scan row. "What did this actually run" is the question the whole diagnostic layer exists to
	// answer, and until now nuclei answered it only into a log line that has already rotated by the
	// time anyone asks. It is set as soon as there is a command, so an error path still reports the
	// vector that failed.
	var nucleiCommand string

	tempFile, err := os.CreateTemp("", "nuclei_targets_*.txt")
	if err != nil {
		return nucleiCommand, fmt.Errorf("failed to create temp targets file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	targetsContent := strings.Join(targets, "\n")
	if _, err := tempFile.WriteString(targetsContent); err != nil {
		return nucleiCommand, fmt.Errorf("failed to write targets to temp file: %v", err)
	}
	tempFile.Close()

	log.Printf("[DEBUG] Created temp targets file: %s with %d targets", tempFile.Name(), len(targets))

	copyCmd := exec.Command(
		"docker", "cp",
		tempFile.Name(),
		"ars0n-framework-v2-nuclei-1:/targets.txt",
	)
	if err := copyCmd.Run(); err != nil {
		return nucleiCommand, fmt.Errorf("failed to copy targets file to container: %v", err)
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
			return nucleiCommand, fmt.Errorf("failed to create custom templates directory: %v", err)
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

	// The ONE place the per-target Wildcard settings meet this command line. Everything above came
	// from nuclei_configs; this is the store the Wildcard Settings screen and the MCP wildcard tool
	// both write, and with nothing stored it returns args untouched.
	args, wildcardNotes := applyNucleiWildcardSettings(args, scopeTargetID)
	for _, note := range wildcardNotes {
		log.Printf("[INFO] Nuclei wildcard settings: %s", note)
	}

	dockerArgs := []string{"exec", "-i", "ars0n-framework-v2-nuclei-1", "nuclei"}
	dockerArgs = append(dockerArgs, args...)

	nucleiCommand = "docker " + strings.Join(dockerArgs, " ")
	log.Printf("[INFO] Executing Nuclei command: %s", nucleiCommand)
	dockerCmd := exec.Command("docker", dockerArgs...)

	stdoutWriter := &capturingLogWriter{prefix: "[NUCLEI]"}
	stderrWriter := &logWriter{prefix: "[NUCLEI-ERR]"}

	dockerCmd.Stdout = stdoutWriter
	dockerCmd.Stderr = stderrWriter

	if err = dockerCmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start Nuclei command: %v", err)
		return nucleiCommand, fmt.Errorf("failed to start nuclei: %v", err)
	}

	log.Printf("[INFO] Nuclei scan started, streaming output...")

	if err = dockerCmd.Wait(); err != nil {
		log.Printf("[ERROR] Nuclei command failed: %v", err)
		return nucleiCommand, fmt.Errorf("nuclei execution failed: %v", err)
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
				return nucleiCommand, fmt.Errorf("failed to copy output from container and write to host: %v", writeErr)
			}
			log.Printf("[INFO] Successfully read output directly from container")
		} else {
			log.Printf("[WARN] Fallback cat also failed: %v, using captured stdout", readErr)
			if stdoutWriter.buf.Len() > 0 {
				if writeErr := os.WriteFile(outputFile, stdoutWriter.buf.Bytes(), 0644); writeErr != nil {
					return nucleiCommand, fmt.Errorf("failed to write captured stdout to output file: %v", writeErr)
				}
				log.Printf("[INFO] Successfully recovered output from captured stdout (%d bytes)", stdoutWriter.buf.Len())
			} else {
				return nucleiCommand, fmt.Errorf("failed to copy output file from container and no stdout captured: %v", err)
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

	return nucleiCommand, nil
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

	command, err := executeNucleiScan(targets, selectedTemplates, selectedSeverities,
		templateIDs, excludeIDs, excludeTags,
		uploadedTemplates, advancedConfig, outputFile, nil, scopeTargetID)
	recordNucleiScanCommand(dbPool, scopeTargetID, command)
	if err != nil {
		return "", nil, fmt.Errorf("scan execution failed: %v", err)
	}

	findings, err := parseNucleiResults(outputFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse results: %v", err)
	}

	return outputFile, findings, nil
}

// recordNucleiScanCommand writes the command that was actually composed onto the scan row.
//
// nuclei_scans has had a command column since it was created and nothing has ever written to it, so
// the only record of what a scan ran was a log line. That is the one question the diagnostic layer
// exists to answer, and it matters more now that a per-target settings store can change the flags.
//
// It targets the most recent RUNNING scan for the target whose command is still empty, because the
// scan id lives in main.go's handler and is not passed down. That is a compromise, not a design:
// plumbing the scan id into the runner is a one-line change in main.go and is reported as such.
// Every failure here is swallowed, because a diagnostic write must never fail a scan.
func recordNucleiScanCommand(pool *pgxpool.Pool, scopeTargetID, command string) {
	if pool == nil || strings.TrimSpace(scopeTargetID) == "" || strings.TrimSpace(command) == "" {
		return
	}
	_, err := pool.Exec(context.Background(), `
		UPDATE nuclei_scans SET command = $1
		WHERE scan_id = (
			SELECT scan_id FROM nuclei_scans
			WHERE scope_target_id = $2::uuid AND status = 'running' AND command IS NULL
			ORDER BY created_at DESC LIMIT 1
		)`, command, scopeTargetID)
	if err != nil {
		log.Printf("[WARN] Could not record the Nuclei command on the scan row: %v", err)
	}
}

// ExecuteNucleiScanDirect is the httpx target mode.
//
// scopeTargetID is VARIADIC only so the existing call site keeps compiling. It should be passed:
// without it this path cannot read the per-target Wildcard settings, so the same target configured
// the same way behaves differently depending on which target mode is selected, which is precisely
// the kind of invisible divergence this store exists to remove. The one-line change is reported.
func ExecuteNucleiScanDirect(targets []string, selectedTemplates []string,
	selectedSeverities []string, templateIDs []string, excludeIDs []string, excludeTags []string,
	uploadedTemplates []map[string]interface{}, advancedConfig map[string]interface{},
	scopeTargetID ...string) (string, []NucleiFinding, error) {

	if len(targets) == 0 {
		return "", nil, fmt.Errorf("no targets provided")
	}

	targetID := ""
	if len(scopeTargetID) > 0 {
		targetID = scopeTargetID[0]
	} else {
		log.Printf("[WARN] ExecuteNucleiScanDirect was called without a scope target id, so the per-target " +
			"Wildcard nuclei settings could not be read and this scan runs on nuclei_configs alone.")
	}

	outputDir := filepath.Join(os.TempDir(), "nuclei_scans")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("nuclei_scan_direct_%d.jsonl", time.Now().Unix()))

	if _, err := executeNucleiScan(targets, selectedTemplates, selectedSeverities,
		templateIDs, excludeIDs, excludeTags,
		uploadedTemplates, advancedConfig, outputFile, nil, targetID); err != nil {
		return "", nil, fmt.Errorf("scan execution failed: %v", err)
	}

	findings, err := parseNucleiResults(outputFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse results: %v", err)
	}

	return outputFile, findings, nil
}
