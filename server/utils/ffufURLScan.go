package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// FFUF runner.
//
// The previous implementation had four defects that between them made this tool look broken:
//
//  1. The default wordlist path was `/wordlists/...`, which does not exist in the ffuf container.
//     Its wordlists are bind-mounted at `/app/wordlists`. Any scan whose saved config had no
//     wordlistId, which includes the partial configs the WAF Probe's Apply writes, ran
//     `ffuf -w /wordlists/ffuf-wordlist-5000.txt` and died before sending a request.
//  2. Wordlist existence was checked with os.Stat in the API container for a path used inside the
//     ffuf container. Two different filesystems; it agreed only by mount coincidence.
//  3. A scan that legitimately found nothing was stored as a bare success with `{"endpoints":null}`
//     and no explanation. Against a client-side-routed app, where every path returns the same
//     shell, that is the *expected* outcome and the operator had no way to learn it.
//  4. With -ac enabled, ffuf writes the calibration probe's string into the first result's
//     input.FUZZ while the url field holds the real path, so finding #1 always had a garbage path.
//
// It also ignored most of the saved configuration, including the autoCalibrate and followRedirects
// toggles, and had no header or cookie fuzzing at all.

const ffufContainer = "ars0n-framework-v2-ffuf-1"

// Wordlists are bind-mounted into the ffuf container from ./wordlists. This is the path *inside
// that container*, which is the only path that matters, because ffuf is what opens the file.
const ffufWordlistDir = "/app/wordlists"

type ffufConfig struct {
	// What to fuzz. Endpoints default on so an operator who never opens the modal gets the
	// previous behaviour; the other two are opt-in because they are a different kind of noise.
	FuzzEndpoints *bool `json:"fuzzEndpoints"`
	FuzzHeaders   bool  `json:"fuzzHeaders"`
	FuzzCookies   bool  `json:"fuzzCookies"`

	HeaderWordlistID string `json:"headerWordlistId"`
	CookieWordlistID string `json:"cookieWordlistId"`
	HeaderFuzzValue  string `json:"headerFuzzValue"`
	CookieFuzzValue  string `json:"cookieFuzzValue"`

	URL        string `json:"url"`
	WordlistID string `json:"wordlistId"`
	Keyword    string `json:"keyword"`
	Method     string `json:"method"`
	PostData   string `json:"postData"`
	Extensions string `json:"extensions"`

	Threads   int    `json:"threads"`
	RateLimit int    `json:"rateLimit"`
	Delay     string `json:"delay"`
	Timeout   int    `json:"timeout"`
	MaxTime   int    `json:"maxTime"`

	MatchStatusCodes string `json:"matchStatusCodes"`
	MatchSize        string `json:"matchSize"`
	MatchLines       string `json:"matchLines"`
	MatchWords       string `json:"matchWords"`
	MatchRegex       string `json:"matchRegex"`
	MatcherMode      string `json:"matcherMode"`

	FilterStatusCodes string `json:"filterStatusCodes"`
	FilterSize        string `json:"filterSize"`
	FilterLines       string `json:"filterLines"`
	FilterWords       string `json:"filterWords"`
	FilterRegex       string `json:"filterRegex"`
	FilterMode        string `json:"filterMode"`

	// Pointers so "absent" is distinguishable from "explicitly false". A config written by the WAF
	// Probe's Apply contains only the fields it set, and treating every missing bool as false there
	// would silently turn off calibration and redirect following.
	AutoCalibrate   *bool `json:"autoCalibrate"`
	FollowRedirects *bool `json:"followRedirects"`
	Recursion       bool  `json:"recursion"`
	RecursionDepth  int   `json:"recursionDepth"`
	HTTP2           bool  `json:"http2"`

	StopOnAll    bool `json:"stopOnAll"`
	StopOn403    bool `json:"stopOn403"`
	StopOnErrors bool `json:"stopOnErrors"`

	Cookies  string              `json:"cookies"`
	Headers  []map[string]string `json:"headers"`
	ProxyURL string              `json:"proxyURL"`
}

func defaultFFUFConfig() ffufConfig {
	yes := true
	return ffufConfig{
		FuzzEndpoints:    &yes,
		AutoCalibrate:    &yes,
		FollowRedirects:  &yes,
		Threads:          40,
		Timeout:          30,
		Keyword:          "FUZZ",
		Method:           "GET",
		MatchStatusCodes: "200-299,301,302,307,401,403,405,500",
		HeaderFuzzValue:  "ars0nprobe",
		CookieFuzzValue:  "ars0nprobe",
	}
}

func (c ffufConfig) endpointsEnabled() bool {
	return c.FuzzEndpoints == nil || *c.FuzzEndpoints
}
func (c ffufConfig) autoCalibrate() bool { return c.AutoCalibrate == nil || *c.AutoCalibrate }
func (c ffufConfig) followRedirects() bool {
	return c.FollowRedirects == nil || *c.FollowRedirects
}

func loadFFUFConfig(scopeTargetID string) ffufConfig {
	cfg := defaultFFUFConfig()

	var raw []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&raw); err != nil {
		return cfg
	}
	// Unmarshalling onto the populated default leaves anything the operator never set alone.
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Printf("[FFUF-URL] Ignoring unreadable config for %s: %v", scopeTargetID, err)
		return defaultFFUFConfig()
	}
	return cfg
}

// ---------------------------------------------------------------- wordlists

// resolveWordlist returns a path *inside the ffuf container* and verifies it there.
//
// The previous code called os.Stat from the API server for a file ffuf would open, which is a
// different filesystem. Asking the container settles it, and a missing wordlist becomes a sentence
// the operator can act on instead of an opaque ffuf error.
func resolveWordlist(id, fallback string) (string, error) {
	path := fallback

	switch {
	case id == "":
	case strings.HasPrefix(id, "builtin-"):
		switch id {
		case "builtin-default":
			path = ffufWordlistDir + "/ffuf-wordlist-5000.txt"
		case "builtin-small":
			path = ffufWordlistDir + "/ffuf-wordlist-default-small.txt"
		case "builtin-large":
			path = ffufWordlistDir + "/ffuf-wordlist-default-long.txt"
		case "builtin-headers":
			path = ffufWordlistDir + "/ffuf-headers.txt"
		case "builtin-cookies":
			path = ffufWordlistDir + "/ffuf-cookies.txt"
		default:
			return "", fmt.Errorf("unknown built-in wordlist %q", id)
		}
	default:
		var custom string
		if err := dbPool.QueryRow(context.Background(),
			`SELECT path FROM ffuf_wordlists WHERE id = $1`, id).Scan(&custom); err != nil {
			return "", fmt.Errorf("wordlist %q is not in the database", id)
		}
		path = custom
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "exec", ffufContainer,
		"test", "-f", path).Run(); err != nil {
		return "", fmt.Errorf("wordlist %q does not exist inside the ffuf container", path)
	}
	return path, nil
}

// ---------------------------------------------------------------- preflight

type ffufPreflight struct {
	Reachable      bool   `json:"reachable"`
	BaselineStatus int    `json:"baseline_status"`
	BaselineSize   int    `json:"baseline_size"`
	BaselineStable bool   `json:"baseline_stable"`
	CatchAllStatus int    `json:"catchall_status"`
	CatchAllSize   int    `json:"catchall_size"`
	CatchAllStable bool   `json:"catchall_stable"`
	SoftNotFound   bool   `json:"soft_404"`
	Indistinct     bool   `json:"indistinguishable"`
	Note           string `json:"note"`
}

// preflightTarget measures two things before any fuzzing starts: what the target returns for the
// URL that will be held constant, and what it returns for paths that cannot exist.
//
// Six requests buys two things. The first is the difference between "this wordlist found nothing"
// and "this target answers everything identically, so no wordlist could have found anything",
// which is the difference between a useful result and an operator concluding the tool is broken.
// The second is a response filter the operator can read and check, rather than one ffuf derived
// from probe strings nobody sees.
func preflightTarget(base string) ffufPreflight {
	out := ffufPreflight{}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
	}

	get := func(u string) (int, int, bool) {
		resp, err := client.Get(u)
		if err != nil {
			return 0, 0, false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, len(body), true
	}

	root := strings.TrimSuffix(base, "/")
	status, size, ok := get(root + "/")
	if !ok {
		out.Note = "The target did not answer a request from the framework, so a scan finding " +
			"nothing says nothing about the target."
		return out
	}
	out.Reachable = true
	out.BaselineStatus, out.BaselineSize = status, size

	// The header and cookie phases hold this URL constant, so their filter comes from here. Sampled
	// twice: a page carrying a CSRF token or a timestamp is a different size every request, and a
	// static size filter built from one sample would then filter nothing at all.
	if s2, n2, ok2 := get(root + "/"); ok2 {
		out.BaselineStable = s2 == status && n2 == size
	}

	type obs struct{ status, size int }
	var probes []obs
	for i := 0; i < 3; i++ {
		s, n, ok := get(fmt.Sprintf("%s/%s", root, randomToken(18)))
		if ok {
			probes = append(probes, obs{s, n})
		}
	}
	if len(probes) < 2 {
		return out
	}

	allSame, byteIdentical := true, true
	for _, p := range probes[1:] {
		if p.status != probes[0].status {
			allSame, byteIdentical = false, false
			break
		}
		if p.size != probes[0].size {
			byteIdentical = false
			// A few bytes of drift is a timestamp or a token, not a different page.
			if abs(p.size-probes[0].size) > 64 {
				allSame = false
			}
		}
	}

	out.CatchAllStatus, out.CatchAllSize = probes[0].status, probes[0].size
	out.CatchAllStable = byteIdentical
	out.SoftNotFound = probes[0].status >= 200 && probes[0].status < 300
	out.Indistinct = allSame && out.SoftNotFound

	if out.Indistinct {
		out.Note = fmt.Sprintf(
			"Paths that cannot exist return %d with ~%d bytes, the same as every other path. This "+
				"target routes on the client, so the server hands back one shell for everything. "+
				"Auto-calibration will filter that shell, which is correct: anything reported is a "+
				"genuine exception, and finding nothing means no word in the list reached a distinct "+
				"server-side route. Header and cookie fuzzing test this target far better than path "+
				"fuzzing, and an /api-oriented wordlist will outperform a generic one.",
			probes[0].status, probes[0].size)
	} else if allSame && probes[0].status == 404 {
		out.Note = "Unknown paths return a clean 404, so path fuzzing is meaningful here."
	}

	return out
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

// ---------------------------------------------------------------- phases

type ffufPhase struct {
	kind     string // endpoints | headers | cookies
	wordlist string
	url      string
	// extra flags placing the keyword on the carrier this phase fuzzes
	extra []string
	// What the target does before this phase started. Drives calibration, so the filter is derived
	// from a measurement rather than from ffuf's random probes.
	preflight ffufPreflight
}

type ffufFinding struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
	Status int64  `json:"status"`
	Size   int64  `json:"size"`
	Words  int64  `json:"words"`
	Lines  int64  `json:"lines"`
}

func ExecuteAndParseFFUFURLScan(scanID, targetURL, scopeTargetID string) {
	log.Printf("[FFUF-URL] Starting FFUF URL scan for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()

	cfg := loadFFUFConfig(scopeTargetID)

	// Measured first, because it decides how each phase separates a real finding from the target's
	// catch-all response.
	pre := preflightTarget(targetURL)
	if !pre.Reachable {
		UpdateFFUFURLScanStatus(scanID, "error", "", pre.Note, "", time.Since(startTime).String())
		return
	}

	phases, err := buildFFUFPhases(targetURL, cfg, pre)
	if err != nil {
		UpdateFFUFURLScanStatus(scanID, "error", "", err.Error(), "", time.Since(startTime).String())
		return
	}
	if len(phases) == 0 {
		UpdateFFUFURLScanStatus(scanID, "error", "",
			"Nothing is enabled to fuzz. Turn on endpoints, headers or cookies in Configure.",
			"", time.Since(startTime).String())
		return
	}

	results := map[string][]ffufFinding{}
	var commands []string
	var phaseErrors []string

	for _, phase := range phases {
		findings, cmdStr, err := runFFUFPhase(scanID, phase, cfg)
		commands = append(commands, cmdStr)
		if err != nil {
			// One phase failing must not discard the phases that worked.
			log.Printf("[FFUF-URL] phase %s failed: %v", phase.kind, err)
			phaseErrors = append(phaseErrors, fmt.Sprintf("%s: %v", phase.kind, err))
			continue
		}
		results[phase.kind] = findings
		log.Printf("[FFUF-URL] phase %s found %d", phase.kind, len(findings))
	}

	execTime := time.Since(startTime).String()
	command := strings.Join(commands, "  &&  ")

	if len(results) == 0 {
		UpdateFFUFURLScanStatus(scanID, "error", "", strings.Join(phaseErrors, "; "),
			command, execTime)
		return
	}

	payload := map[string]interface{}{
		"endpoints": nilIfEmpty(results["endpoints"]),
		"headers":   nilIfEmpty(results["headers"]),
		"cookies":   nilIfEmpty(results["cookies"]),
		"preflight": pre,
		"phases_run": func() []string {
			out := []string{}
			for _, p := range phases {
				out = append(out, p.kind)
			}
			return out
		}(),
		"diagnosis": diagnoseFFUF(results, pre, cfg, phaseErrors),
		// How each phase separated a finding from the target's catch-all, so an operator can check
		// the filter rather than trust it.
		"calibration": func() map[string]string {
			out := map[string]string{}
			mc := cfg.MatchStatusCodes
			if mc == "" {
				mc = "200-299,301,302,307,401,403,405,500"
			}
			for _, p := range phases {
				mode, value := calibrationFor(cfg, p, mc)
				switch mode {
				case "none":
					out[p.kind] = fmt.Sprintf(
						"no filter needed: unknown paths answer %d, which the status matcher already excludes",
						pre.CatchAllStatus)
				case "size":
					out[p.kind] = fmt.Sprintf(
						"filtered responses of exactly %s bytes, the target's measured catch-all", value)
				default:
					out[p.kind] = "ffuf auto-calibration: the catch-all response is a different " +
						"size on every request, so no fixed filter would be correct"
				}
			}
			return out
		}(),
	}
	if len(phaseErrors) > 0 {
		payload["phase_errors"] = phaseErrors
	}

	resultJSON, _ := json.Marshal(payload)
	log.Printf("[FFUF-URL] FFUF URL scan completed in %s for %s", execTime, targetURL)
	UpdateFFUFURLScanStatus(scanID, "success", string(resultJSON), "", command, execTime)
}

func nilIfEmpty(in []ffufFinding) []ffufFinding {
	if len(in) == 0 {
		return []ffufFinding{}
	}
	return in
}

// diagnoseFFUF explains an empty result set.
//
// This is the whole point of the rewrite. "0 endpoints, status success" is the same output whether
// the target has nothing to find, the wordlist never loaded, or the target answers every path
// identically, and an operator cannot tell those apart without reading the container logs.
func diagnoseFFUF(results map[string][]ffufFinding, pre ffufPreflight, cfg ffufConfig,
	phaseErrors []string) string {

	total := 0
	for _, v := range results {
		total += len(v)
	}
	if total > 0 {
		if pre.Indistinct {
			return "Everything reported here differs from the target's catch-all response, which " +
				"is what makes it worth looking at. " + pre.Note
		}
		return ""
	}

	if len(phaseErrors) > 0 {
		return "No results, and some phases failed: " + strings.Join(phaseErrors, "; ")
	}
	if pre.Indistinct {
		return pre.Note
	}
	if !cfg.autoCalibrate() && (cfg.FilterSize != "" || cfg.FilterStatusCodes != "") {
		return "No results. Explicit response filters are configured and auto-calibration is off, " +
			"so check that the filters are not excluding real findings: " +
			describeFilters(cfg)
	}
	return "No results. The target returns a distinguishable response for unknown paths, so this " +
		"wordlist genuinely did not hit anything. A larger or more targeted wordlist is the next step."
}

func describeFilters(cfg ffufConfig) string {
	var parts []string
	if cfg.FilterStatusCodes != "" {
		parts = append(parts, "status "+cfg.FilterStatusCodes)
	}
	if cfg.FilterSize != "" {
		parts = append(parts, "size "+cfg.FilterSize)
	}
	if cfg.FilterLines != "" {
		parts = append(parts, "lines "+cfg.FilterLines)
	}
	if cfg.FilterWords != "" {
		parts = append(parts, "words "+cfg.FilterWords)
	}
	return strings.Join(parts, ", ")
}

func buildFFUFPhases(targetURL string, cfg ffufConfig, pre ffufPreflight) ([]ffufPhase, error) {
	var phases []ffufPhase
	keyword := cfg.Keyword
	if keyword == "" {
		keyword = "FUZZ"
	}

	if cfg.endpointsEnabled() {
		wl, err := resolveWordlist(cfg.WordlistID, ffufWordlistDir+"/ffuf-wordlist-5000.txt")
		if err != nil {
			return nil, fmt.Errorf("endpoint wordlist: %w", err)
		}
		// The saved URL is honoured when it carries the keyword, so an operator can fuzz a
		// subdirectory or a query parameter. The old code discarded this field entirely.
		fuzzURL := targetURL
		if strings.Contains(cfg.URL, keyword) {
			fuzzURL = cfg.URL
		} else if !strings.Contains(fuzzURL, keyword) {
			fuzzURL = strings.TrimSuffix(fuzzURL, "/") + "/" + keyword
		}
		phases = append(phases, ffufPhase{kind: "endpoints", wordlist: wl, url: fuzzURL,
			preflight: pre})
	}

	// Header and cookie fuzzing put the keyword in the carrier rather than the path, so the URL
	// stays constant and every response is compared against the same baseline. That is why they
	// still work on a target where path fuzzing cannot: the only thing changing is the header or
	// cookie name, so any difference in the response is attributable to it.
	base := strings.TrimSuffix(targetURL, "/") + "/"

	if cfg.FuzzHeaders {
		wl, err := resolveWordlist(cfg.HeaderWordlistID, ffufWordlistDir+"/ffuf-headers.txt")
		if err != nil {
			return nil, fmt.Errorf("header wordlist: %w", err)
		}
		value := cfg.HeaderFuzzValue
		if value == "" {
			value = "ars0nprobe"
		}
		phases = append(phases, ffufPhase{
			kind: "headers", wordlist: wl, url: base, preflight: pre,
			extra: []string{"-H", fmt.Sprintf("%s: %s", keyword, value)},
		})
	}

	if cfg.FuzzCookies {
		wl, err := resolveWordlist(cfg.CookieWordlistID, ffufWordlistDir+"/ffuf-cookies.txt")
		if err != nil {
			return nil, fmt.Errorf("cookie wordlist: %w", err)
		}
		value := cfg.CookieFuzzValue
		if value == "" {
			value = "ars0nprobe"
		}
		phases = append(phases, ffufPhase{
			kind: "cookies", wordlist: wl, url: base, preflight: pre,
			extra: []string{"-b", fmt.Sprintf("%s=%s", keyword, value)},
		})
	}

	return phases, nil
}

func runFFUFPhase(scanID string, phase ffufPhase, cfg ffufConfig) ([]ffufFinding, string, error) {
	// Per scan and per phase. The old fixed /tmp/ffuf-output.json in a shared long-lived container
	// meant two concurrent scans read each other's results.
	outPath := fmt.Sprintf("/tmp/ffuf-%s-%s.json", scanID, phase.kind)

	args := []string{
		"exec", ffufContainer, "ffuf",
		"-w", phase.wordlist,
		"-u", phase.url,
		"-o", outPath,
		"-of", "json",
		"-s", // no progress spam; the JSON file is the output that matters
	}
	args = append(args, phase.extra...)
	args = append(args, buildFFUFFlags(cfg, phase)...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmdStr := "docker " + strings.Join(args, " ")
	log.Printf("[FFUF-URL] Executing: %s", cmdStr)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	defer func() {
		_ = exec.Command("docker", "exec", ffufContainer, "rm", "-f", outPath).Run()
	}()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, cmdStr, fmt.Errorf("timed out after 30 minutes")
	}
	if runErr != nil {
		return nil, cmdStr, fmt.Errorf("%s", ffufErrorMessage(stderr.String(), cfg))
	}

	raw, err := exec.Command("docker", "exec", ffufContainer, "cat", outPath).Output()
	if err != nil {
		// ffuf skips writing the file when it aborts early, so this is usually a real failure
		// rather than an empty result, and it must not be reported as "found nothing".
		return nil, cmdStr, fmt.Errorf("ffuf wrote no output file: %s",
			ffufErrorMessage(stderr.String(), cfg))
	}

	findings, err := parseFFUFOutput(raw, phase)
	if err != nil {
		return nil, cmdStr, err
	}
	return findings, cmdStr, nil
}

func buildFFUFFlags(cfg ffufConfig, phase ffufPhase) []string {
	var args []string
	add := func(a ...string) { args = append(args, a...) }

	threads := cfg.Threads
	if threads <= 0 {
		threads = 40
	}
	add("-t", fmt.Sprintf("%d", threads))

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	add("-timeout", fmt.Sprintf("%d", timeout))

	mc := cfg.MatchStatusCodes
	if mc == "" {
		mc = "200-299,301,302,307,401,403,405,500"
	}
	add("-mc", mc)

	if cfg.followRedirects() {
		add("-r")
	}
	if cfg.HTTP2 {
		add("-http2")
	}
	if cfg.Method != "" && strings.ToUpper(cfg.Method) != "GET" {
		add("-X", strings.ToUpper(cfg.Method))
	}
	if cfg.PostData != "" {
		add("-d", cfg.PostData)
	}
	// Extensions only make sense when the keyword is a path segment.
	if phase.kind == "endpoints" && cfg.Extensions != "" {
		add("-e", cfg.Extensions)
	}
	if phase.kind == "endpoints" && cfg.Recursion {
		add("-recursion")
		if cfg.RecursionDepth > 0 {
			add("-recursion-depth", fmt.Sprintf("%d", cfg.RecursionDepth))
		}
	}
	if cfg.RateLimit > 0 {
		add("-rate", fmt.Sprintf("%d", cfg.RateLimit))
	}
	if cfg.Delay != "" {
		add("-p", cfg.Delay)
	}
	if cfg.MaxTime > 0 {
		add("-maxtime", fmt.Sprintf("%d", cfg.MaxTime))
	}
	if cfg.ProxyURL != "" {
		add("-x", cfg.ProxyURL)
	}

	// The cookie phase owns the Cookie header; adding the saved session on top would send two
	// cookie values for the same name and make the result unattributable.
	if cfg.Cookies != "" && phase.kind != "cookies" {
		add("-b", cfg.Cookies)
	}
	for _, h := range cfg.Headers {
		name := h["name"]
		if name == "" {
			continue
		}
		// Same reasoning for the header phase: a static header of the same name would collide with
		// the one being fuzzed.
		if phase.kind == "headers" && strings.EqualFold(name, "Cookie") {
			continue
		}
		add("-H", fmt.Sprintf("%s: %s", name, h["value"]))
	}

	// Matchers beyond status.
	if cfg.MatchSize != "" {
		add("-ms", cfg.MatchSize)
	}
	if cfg.MatchLines != "" {
		add("-ml", cfg.MatchLines)
	}
	if cfg.MatchWords != "" {
		add("-mw", cfg.MatchWords)
	}
	if cfg.MatchRegex != "" {
		add("-mr", cfg.MatchRegex)
	}
	if cfg.MatcherMode != "" {
		add("-mmode", cfg.MatcherMode)
	}

	// Filters.
	if cfg.FilterStatusCodes != "" {
		add("-fc", cfg.FilterStatusCodes)
	}
	if cfg.FilterSize != "" {
		add("-fs", cfg.FilterSize)
	}
	if cfg.FilterLines != "" {
		add("-fl", cfg.FilterLines)
	}
	if cfg.FilterWords != "" {
		add("-fw", cfg.FilterWords)
	}
	if cfg.FilterRegex != "" {
		add("-fr", cfg.FilterRegex)
	}
	if cfg.FilterMode != "" {
		add("-fmode", cfg.FilterMode)
	}

	// Calibration. An operator-set size filter wins outright, because running both filters the same
	// responses twice and reliably empties the result set.
	hasSizeFilter := cfg.FilterSize != "" || cfg.FilterLines != "" || cfg.FilterWords != ""
	if cfg.autoCalibrate() && !hasSizeFilter {
		mode, value := calibrationFor(cfg, phase, mc)
		switch mode {
		case "none":
		case "size":
			add("-fs", value)
		default:
			add("-ac")
		}
	}

	if cfg.StopOnAll {
		add("-sa")
	} else {
		if cfg.StopOn403 {
			add("-sf")
		}
		if cfg.StopOnErrors {
			add("-se")
		}
	}

	return args
}

// calibrationFor decides how a phase separates signal from the target's catch-all response.
//
// Measured against a controlled target, -ac and an exact size filter derived from the preflight
// return identical findings, so this is not about accuracy. It is about two other things. The
// filter becomes a number the operator can see and disagree with, instead of one ffuf derived from
// probe strings nobody sees. And -ac is what corrupts the first result's label, so not passing it
// where it earns nothing removes that whole class of bad output at the source.
//
// Returns one of:
//
//	"none" - the catch-all already falls outside the status matcher, typically a clean 404, so
//	         nothing needs filtering and every match is real.
//	"size" - the catch-all is matched but byte-identical every time, so filtering that one size is
//	         exact, and the number is reported alongside the results.
//	"ac"   - the catch-all is matched and varies between requests, so no static filter is correct
//	         and ffuf's own calibration is the right tool.
func calibrationFor(cfg ffufConfig, phase ffufPhase, matchCodes string) (string, string) {
	pre := phase.preflight
	if !pre.Reachable {
		return "ac", ""
	}

	// Header and cookie phases hold the URL constant, so their baseline is that URL's own response
	// and every carrier the target ignores returns exactly it.
	if phase.kind != "endpoints" {
		if pre.BaselineStable && statusMatched(pre.BaselineStatus, matchCodes) {
			return "size", fmt.Sprintf("%d", pre.BaselineSize)
		}
		return "ac", ""
	}

	if pre.CatchAllStatus == 0 {
		return "ac", ""
	}
	if !statusMatched(pre.CatchAllStatus, matchCodes) {
		return "none", ""
	}
	if pre.CatchAllStable {
		return "size", fmt.Sprintf("%d", pre.CatchAllSize)
	}
	return "ac", ""
}

// statusMatched reports whether ffuf's -mc value would match a status, so calibration can be
// skipped when the catch-all is already excluded.
func statusMatched(status int, matchCodes string) bool {
	if status == 0 {
		return false
	}
	for _, part := range strings.Split(matchCodes, ",") {
		part = strings.TrimSpace(part)
		if part == "all" {
			return true
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := atoiFFUF(lo)
			h, e2 := atoiFFUF(hi)
			if e1 && e2 && status >= l && status <= h {
				return true
			}
			continue
		}
		if v, ok := atoiFFUF(part); ok && v == status {
			return true
		}
	}
	return false
}

func atoiFFUF(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func ffufErrorMessage(stderr string, cfg ffufConfig) string {
	s := strings.TrimSpace(stderr)
	switch {
	case strings.Contains(s, "no such file or directory"):
		return "ffuf could not open the wordlist inside its container: " + truncateFFUF(s)
	case strings.Contains(s, "connection refused") || strings.Contains(s, "no such host"):
		return "ffuf could not reach the target: " + truncateFFUF(s)
	case cfg.StopOn403 && strings.Contains(s, "403"):
		return "Stopped: more than 95% of responses were 403. Stop-on-403 is enabled in Configure; " +
			"turn it off to characterise a target that answers 403 routinely."
	case cfg.StopOnAll || cfg.StopOnErrors:
		return "Stopped early by a stop-on condition set in Configure: " + truncateFFUF(s)
	case s == "":
		return "ffuf exited non-zero without writing anything to stderr"
	}
	return truncateFFUF(s)
}

func truncateFFUF(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

// parseFFUFOutput turns ffuf's JSON into findings.
//
// The fuzzed value is taken from the result URL rather than from input.FUZZ. With -ac enabled ffuf
// writes the calibration probe's string into the first result's input map while the url field
// stays correct, so reading input.FUZZ gave every scan's first finding a path that was never
// requested. For header and cookie phases the URL is constant, so those keep using the input map,
// which ffuf populates correctly there.
func parseFFUFOutput(raw []byte, phase ffufPhase) ([]ffufFinding, error) {
	var doc struct {
		Results []struct {
			Input  map[string]string `json:"input"`
			Status int64             `json:"status"`
			Length int64             `json:"length"`
			Words  int64             `json:"words"`
			Lines  int64             `json:"lines"`
			URL    string            `json:"url"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("could not parse ffuf output: %w", err)
	}

	baseTemplate := phase.url
	out := make([]ffufFinding, 0, len(doc.Results))
	for _, r := range doc.Results {
		name := r.Input["FUZZ"]

		if phase.kind == "endpoints" {
			if derived, ok := fuzzValueFromURL(baseTemplate, r.URL); ok {
				name = derived
			}
		}

		out = append(out, ffufFinding{
			Name:   name,
			Path:   name,
			URL:    r.URL,
			Status: r.Status,
			Size:   r.Length,
			Words:  r.Words,
			Lines:  r.Lines,
		})
	}
	return out, nil
}

// fuzzValueFromURL recovers what was substituted for the keyword by diffing the result URL against
// the template it was built from.
func fuzzValueFromURL(template, resultURL string) (string, bool) {
	if resultURL == "" {
		return "", false
	}
	idx := strings.Index(template, "FUZZ")
	if idx < 0 {
		return "", false
	}
	prefix, suffix := template[:idx], template[idx+len("FUZZ"):]

	// Normalise both sides so a template written with an explicit :443 still matches a result URL
	// that dropped the default port, or the reverse.
	np, nr := normaliseFFUFURL(prefix), normaliseFFUFURL(resultURL)
	if !strings.HasPrefix(nr, np) {
		return "", false
	}
	value := nr[len(np):]
	if suffix != "" && strings.HasSuffix(value, suffix) {
		value = value[:len(value)-len(suffix)]
	}
	if value == "" {
		return "", false
	}
	return value, true
}

func normaliseFFUFURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	host := u.Host
	if (u.Scheme == "https" && strings.HasSuffix(host, ":443")) ||
		(u.Scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	u.Host = host
	return u.String()
}
