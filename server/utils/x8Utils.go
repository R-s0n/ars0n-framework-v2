package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type X8Config struct {
	Headers  []map[string]string `json:"headers"`
	BodyType string              `json:"bodyType"`
	Wordlist string              `json:"wordlist"`

	// x8 has TWO concurrency knobs and they are not the same thing. -W/--workers is "the number of
	// concurrent url checks"; -c is "the number of concurrent requests per url". Both default to 1.
	// A single field labelled "concurrency" was mapped onto workers and left -c at 1, so every URL
	// was probed one request at a time no matter what the operator set.
	Workers          int  `json:"workers"`
	RequestsPerURL   int  `json:"requestsPerUrl"`
	Delay            int  `json:"delay"`
	LearnRequests    int  `json:"learnRequests"`
	Timeout          int  `json:"timeout"`
	MaxParamsPerReq  int  `json:"maxParamsPerRequest"`
	DisableCustomSet bool `json:"disableCustomParameters"`
	MimicBrowser     bool `json:"mimicBrowser"`
	Strict           bool `json:"strict"`

	// Concurrency is the old single field, read only so stored configs still resolve. It seeded
	// --workers, so that is where it lands.
	Concurrency int `json:"concurrency"`

	// ReflectedOnly emits --reflected-only, which DISABLES page comparison and searches for
	// reflected parameters only. Deliberately a new key rather than a rename of the old
	// `checkReflection`: that field defaulted to true, so reusing the name would silently carry the
	// old behaviour forward on every stored config and keep x8's primary detector switched off.
	ReflectedOnly   bool `json:"reflectedOnly"`
	Verify          bool `json:"verify"`
	FollowRedirects bool `json:"followRedirects"`
	DisableColors   bool `json:"disableColors"`

	// IncludeScripts brings content_class='script' endpoints into the target set. Off by default.
	IncludeScripts bool `json:"includeScripts"`

	// Places holds per-injection-point overrides, keyed by query/body/headers/cookies. x8 varies by
	// WHERE candidates go rather than by verb, so that is the axis worth configuring separately: a
	// header sweep wants different pacing and a much lower max-per-request than a query sweep.
	Places map[string]X8PlaceOverride `json:"places"`
	// Verbs is the previous per-verb shape, still read so an older stored config resolves.
	Verbs map[string]X8PlaceOverride `json:"verbs"`

	// BodyTemplate is x8 -b, e.g. {"data":{%s}}. The literal {%s} marks where candidates go, which
	// is what makes it possible to reach parameters nested under a wrapper object instead of only
	// at the top level. Only meaningful for the body place.
	BodyTemplate string `json:"bodyTemplate"`

	// Method, MaxDepth, VerifyRequests, CheckReflection, CheckBooleans and ValueSize are gone.
	// The verb now comes from the scan's verb groups; CheckBooleans emitted --check-binary, an
	// unrelated flag about binary response bodies; ValueSize and MaxDepth were never passed to x8
	// at all.
}

func SaveX8Config(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var config X8Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := `
		INSERT INTO x8_configs (scope_target_id, config)
		VALUES ($1, $2)
		ON CONFLICT (scope_target_id)
		DO UPDATE SET config = $2, updated_at = NOW()
	`

	_, err = dbPool.Exec(context.Background(), query, scopeTargetID, configJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func GetX8Config(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var configJSON []byte
	query := `SELECT config FROM x8_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&configJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
		return
	}

	var config X8Config
	if err := UnmarshalConfigTolerant(configJSON, &config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func RunX8Scan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()

	insertQuery := `
		INSERT INTO x8_scans (scan_id, scope_target_id, status, total_endpoints, processed_endpoints, parameters_found)
		VALUES ($1, $2, 'pending', 0, 0, 0)
	`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, req.ScopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go ExecuteX8Scan(scanID, req.ScopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  "pending",
	})
}

func ExecuteX8Scan(scanID, scopeTargetID string) {
	startTime := time.Now()
	ctx := context.Background()

	UpdateX8ScanStatus(scanID, "running", "", "")

	config := DefaultX8Config()
	var configJSON []byte
	if err := dbPool.QueryRow(ctx,
		`SELECT config FROM x8_configs WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&configJSON); err == nil {
		_ = UnmarshalConfigTolerant(configJSON, &config)
	}

	sel, err := SelectParamEnumTargets(ctx, scopeTargetID,
		ParamTargetOptions{Tool: "x8", IncludeScripts: config.IncludeScripts})
	if err != nil {
		UpdateX8ScanStatus(scanID, "error", "", fmt.Sprintf("Failed to select endpoints: %v", err))
		return
	}
	if sel.Total == 0 {
		// Two different causes, and telling them apart is the whole point: "run Consolidate and
		// Investigate first" is wrong and insulting advice for an operator who has done both and then
		// deselected every endpoint in the Config modal.
		all, allErr := SelectParamEnumTargets(ctx, scopeTargetID,
			ParamTargetOptions{Tool: "x8", IncludeScripts: config.IncludeScripts,
				IncludeDisabled: true})
		if allErr == nil && all.Total > 0 {
			UpdateX8ScanStatus(scanID, "error", "", fmt.Sprintf(
				"Every one of the %d eligible endpoints is deselected for x8. Open Config and "+
					"enable at least one.", all.Total))
			return
		}
		UpdateX8ScanStatus(scanID, "error", "", "No valid endpoints to scan. Parameter "+
			"enumeration runs against endpoints Validate confirmed as valid, so run Consolidate "+
			"and Investigate first. Scope: "+sel.Scope)
		return
	}

	groups := PlanVerbGroups("x8", sel.Targets)
	total := TotalGroupWork(groups)
	dbPool.Exec(ctx, `UPDATE x8_scans SET total_endpoints = $1 WHERE scan_id = $2`, total, scanID)

	var (
		allOutput strings.Builder
		cmdStrs   []string
		results   []paramEnumGroupResult
		processed int
		found     int
	)

	for _, g := range groups {
		gr, out, cmdStr, n := runX8Group(ctx, scanID, scopeTargetID, config, g)
		found += n
		processed += len(g.Targets)
		results = append(results, gr)
		cmdStrs = append(cmdStrs, cmdStr)
		allOutput.WriteString(fmt.Sprintf("\n===== %s (%d endpoints) =====\n", g.Label, len(g.Targets)))
		allOutput.WriteString(out)

		dbPool.Exec(ctx,
			`UPDATE x8_scans SET processed_endpoints = $1, parameters_found = $2 WHERE scan_id = $3`,
			processed, found, scanID)
	}

	status := "success"
	var failed []string
	for _, r := range results {
		if r.Failed {
			failed = append(failed, r.Label)
		}
	}
	if len(failed) > 0 {
		status = "partial"
		if len(failed) == len(results) {
			status = "error"
		}
	}

	summary, _ := json.Marshal(map[string]interface{}{
		"groups": results, "selection": sel, "failed_groups": failed,
	})

	// The summary goes in `result` and `error` carries an error or nothing.
	//
	// It used to be written to `error` on every run, so a completely successful scan left a JSON blob
	// in the column whose whole job is to answer "what went wrong", `result` was never written at
	// all, and anything reading `error` to decide whether a scan failed saw one that never had.
	errMsg := ""
	if len(failed) > 0 {
		var details []string
		for _, r := range results {
			if r.Failed {
				details = append(details, r.Label+": "+r.Detail)
			}
		}
		errMsg = fmt.Sprintf("%d of %d passes failed. %s",
			len(failed), len(results), strings.Join(details, " | "))
	}

	dbPool.Exec(ctx, `
		UPDATE x8_scans
		SET status = $1, processed_endpoints = $2, parameters_found = $3,
		    execution_time = $4, command = $5, stdout = $6, result = $7, error = $8
		WHERE scan_id = $9`,
		status, processed, found, time.Since(startTime).String(),
		strings.Join(cmdStrs, "\n"), allOutput.String(), string(summary), errMsg, scanID)
}

// X8PlaceOverride is the per-injection-point half of the config. Pointers so "not set" stays
// distinguishable from "set to 0" or "set to false"; see ArjunVerbOverride for why that matters.
type X8PlaceOverride struct {
	Workers         *int                `json:"workers,omitempty"`
	RequestsPerURL  *int                `json:"requestsPerUrl,omitempty"`
	Delay           *int                `json:"delay,omitempty"`
	LearnRequests   *int                `json:"learnRequests,omitempty"`
	Timeout         *int                `json:"timeout,omitempty"`
	MaxParamsPerReq *int                `json:"maxParamsPerRequest,omitempty"`
	Wordlist        *string             `json:"wordlist,omitempty"`
	BodyType        *string             `json:"bodyType,omitempty"`
	BodyTemplate    *string             `json:"bodyTemplate,omitempty"`
	ReflectedOnly   *bool               `json:"reflectedOnly,omitempty"`
	Verify          *bool               `json:"verify,omitempty"`
	FollowRedirects *bool               `json:"followRedirects,omitempty"`
	Strict          *bool               `json:"strict,omitempty"`
	Headers         []map[string]string `json:"headers,omitempty"`

	// Concurrency is the previous single knob, read so an older stored override still resolves.
	Concurrency *int `json:"concurrency,omitempty"`
}

// ForPlace resolves the config a pass on this injection point will run with. Shared by the runner
// and the preview endpoint so the two cannot disagree.
func (c X8Config) ForPlace(place string) X8Config {
	place = strings.ToLower(strings.TrimSuffix(place, "!"))
	o, ok := c.Places[place]
	if !ok {
		// Fall back to the older per-verb map so a config written before places existed still
		// applies rather than silently reverting to the base values.
		o, ok = c.Verbs[strings.ToUpper(place)]
	}

	out := c
	// The old single concurrency field seeded workers, so honour it when workers itself is unset.
	if out.Workers == 0 && out.Concurrency > 0 {
		out.Workers = out.Concurrency
	}
	if ok {
		if o.Workers != nil {
			out.Workers = *o.Workers
		} else if o.Concurrency != nil {
			out.Workers = *o.Concurrency
		}
		if o.RequestsPerURL != nil {
			out.RequestsPerURL = *o.RequestsPerURL
		}
		if o.Delay != nil {
			out.Delay = *o.Delay
		}
		if o.LearnRequests != nil {
			out.LearnRequests = *o.LearnRequests
		}
		if o.Timeout != nil {
			out.Timeout = *o.Timeout
		}
		if o.MaxParamsPerReq != nil {
			out.MaxParamsPerReq = *o.MaxParamsPerReq
		}
		if o.Wordlist != nil {
			out.Wordlist = *o.Wordlist
		}
		if o.BodyType != nil {
			out.BodyType = *o.BodyType
		}
		if o.BodyTemplate != nil {
			out.BodyTemplate = *o.BodyTemplate
		}
		if o.ReflectedOnly != nil {
			out.ReflectedOnly = *o.ReflectedOnly
		}
		if o.Verify != nil {
			out.Verify = *o.Verify
		}
		if o.FollowRedirects != nil {
			out.FollowRedirects = *o.FollowRedirects
		}
		if o.Strict != nil {
			out.Strict = *o.Strict
		}
		if o.Headers != nil {
			out.Headers = o.Headers
		}
	}
	// Resolved here rather than inside buildX8Args so the preview reports the same wordlist the run
	// will read. A blank wordlist is never sent to x8: see DefaultX8WordlistFor.
	if strings.TrimSpace(out.Wordlist) == "" {
		out.Wordlist = DefaultX8WordlistFor(place)
	}
	return out
}

// The wordlists an x8 pass falls back to, by injection place.
//
// These paths are inside the x8 container, which mounts ./wordlists at /app/wordlists exactly as the
// ffuf container does. x8 itself ships no wordlist at all, and its -w default is "read from stdin",
// so a pass with nothing here tests only x8's built-in custom parameter names.
//
// The place-specific split matters as much as having a list at all: in --headers mode the candidates
// become header NAMES, so X-Forwarded-For and X-Original-URL are the useful vocabulary and `page` is
// not, and the repo already ships that list for ffuf's header fuzzing.
const (
	x8QueryWordlist  = "/app/wordlists/param-names.txt"
	x8HeaderWordlist = "/app/wordlists/ffuf-headers.txt"
	x8CookieWordlist = "/app/wordlists/ffuf-cookies.txt"
)

// x8DataType maps a configured body encoding onto the value x8 -t actually accepts, and returns ""
// for anything it does not.
//
// x8 4.3.1 accepts "json" and "urlencoded". Its own --help says "Available: urlencode, json", and
// that help text is wrong: `-t urlencode` prints "[#] Incorrect --data-type specified", tests
// nothing, and EXITS 0, which the framework records as a successful scan that found no parameters.
// The normalisation here used to rewrite urlencoded to urlencode, i.e. it turned the only valid
// spelling into the invalid one, so a body pass configured for form encoding always did nothing.
//
// Anything unrecognised is dropped rather than passed through, because passing it through is the
// silent-zero case above.
func x8DataType(bodyType string) string {
	switch strings.ToLower(strings.TrimSpace(bodyType)) {
	case "json":
		return "json"
	case "form", "urlencode", "urlencoded", "form-urlencoded", "x-www-form-urlencoded":
		return "urlencoded"
	}
	return ""
}

// DefaultX8WordlistFor picks the fallback wordlist for an injection place. Shared by the runner and
// the preview through ForPlace, so the command shown is the command sent.
func DefaultX8WordlistFor(place string) string {
	switch strings.ToLower(strings.TrimSuffix(place, "!")) {
	case "headers":
		return x8HeaderWordlist
	case "cookies":
		return x8CookieWordlist
	default:
		return x8QueryWordlist
	}
}

// DefaultX8Config is applied before the stored row is unmarshalled over it, so a partially saved
// config cannot zero out the fields it does not mention.
func DefaultX8Config() X8Config {
	return X8Config{
		BodyType:       "json",
		Workers:        10,
		RequestsPerURL: 1,
		LearnRequests:  9,
		Timeout:        15,
		Verify:         true,
		// Matches the modal's own default. Left false, the ANSI colour codes x8 writes around every
		// finding were stored verbatim in x8_scans.stdout and rendered as escape litter.
		DisableColors: true,
		// ReflectedOnly is deliberately false. It was true, and it emits --reflected-only, which
		// x8 documents as "Disable page comparison and search for reflected parameters only".
		// Page comparison is x8's primary detector, so a parameter that changes behaviour without
		// echoing its value was invisible. Verified against a local reflector: default mode finds
		// a reflected parameter anyway and reports reason_kind "Reflected", so the flag only ever
		// subtracted detections.
		ReflectedOnly: false,
	}
}

const x8GroupTimeout = 2 * time.Hour

func runX8Group(ctx context.Context, scanID, scopeTargetID string, config X8Config,
	g VerbGroup) (paramEnumGroupResult, string, string, int) {

	res := paramEnumGroupResult{Label: g.Label, Mode: g.Mode, Endpoints: len(g.Targets)}

	// Resolve the per-verb settings for this pass. Arjun's two POST passes share a verb, so
	// both pick up the same POST overrides, which is the intent: they are one decision about
	// how hard to hit body routes, not two.
	config = config.ForPlace(g.Mode)

	safeLabel := strings.NewReplacer(" ", "_", "(", "", ")", "").Replace(g.Label)
	urlsFile := fmt.Sprintf("/tmp/x8_urls_%s_%s.txt", scanID, safeLabel)
	outputFile := fmt.Sprintf("/tmp/x8_output_%s_%s.json", scanID, safeLabel)
	defer os.Remove(urlsFile)
	defer os.Remove(outputFile)

	urls := make([]string, 0, len(g.Targets))
	for _, t := range g.Targets {
		urls = append(urls, t.URL)
	}
	if err := os.WriteFile(urlsFile, []byte(strings.Join(urls, "\n")+"\n"), 0644); err != nil {
		res.Failed, res.Detail = true, fmt.Sprintf("could not write URL list: %v", err)
		return res, "", "", 0
	}

	// The distinct verbs in this group, so -X carries what these endpoints actually answer.
	seenVerb := map[string]bool{}
	var verbs []string
	for _, t := range g.Targets {
		v := strings.ToUpper(t.Method)
		if v != "" && !seenVerb[v] {
			seenVerb[v] = true
			verbs = append(verbs, v)
		}
	}
	sort.Strings(verbs)

	args := buildX8Args(config, g.Mode, urlsFile, outputFile, verbs)
	cmdStr := "docker exec ars0n-framework-v2-x8-1 x8 " + strings.Join(args, " ")

	runCtx, cancel := context.WithTimeout(ctx, x8GroupTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx,
		"docker", append([]string{"exec", "ars0n-framework-v2-x8-1", "x8"}, args...)...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		res.Failed = true
		// The first line of x8's own output, when it has one, says far more than "exit status 1":
		// a rejected flag combination prints a clap usage error and nothing else.
		res.Detail = fmt.Sprintf("x8 exited with %v", err)
		if first := firstLine(string(output)); first != "" {
			res.Detail += ": " + first
		}
		if runCtx.Err() != nil {
			res.Detail = fmt.Sprintf("timed out after %s", x8GroupTimeout)
			// Killing the context kills the `docker exec` CLIENT, not the x8 process inside the
			// container, which would otherwise keep sending requests to the target long after the
			// framework had given up on it. Matched on this pass's own output path so a concurrent
			// scan for another target is untouched.
			killX8InContainer(outputFile)
		}
		return res, string(output), cmdStr, 0
	}

	found, parseErr := parseX8Output(ctx, outputFile, scanID, scopeTargetID, g)
	res.Found = found
	switch {
	case parseErr != nil:
		// x8 exited 0 but produced nothing readable, so this is not "no parameters found": it is a
		// run whose result was never seen. Reporting it as a failure is what stops a broken pass
		// from being indistinguishable from a clean one.
		res.Failed = true
		res.Detail = parseErr.Error()
	case found == 0:
		res.Detail = "x8 completed and reported no hidden parameters for this pass"
	}
	return res, string(output), cmdStr, found
}

// firstLine is the leading non-empty line, used to put a tool's own error message in front of the
// operator instead of an exit code.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			if len(t) > 300 {
				t = t[:300] + "..."
			}
			return t
		}
	}
	return ""
}

// killX8InContainer stops an x8 process left running after its group timed out.
//
// /proc is walked by hand because the image is debian-slim with neither pkill nor ps, and the match
// is on the unique output path this pass was given rather than on the program name, so a scan running
// for a different target is not caught by it.
func killX8InContainer(marker string) {
	script := fmt.Sprintf(
		`for p in /proc/[0-9]*; do if grep -qa %q "$p/cmdline" 2>/dev/null; then `+
			`kill -TERM "${p##*/}" 2>/dev/null; fi; done`, marker)
	killCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	exec.CommandContext(killCtx, "docker", "exec", "ars0n-framework-v2-x8-1",
		"sh", "-c", script).Run()
}

// buildX8Args builds one x8 invocation for one injection place.
//
// The place is what varies, and it is expressed three different ways depending on which one:
// --headers and --cookies switch the injection point outright, while query and body are x8 own
// default (query for GET, body for POST/PUT/PATCH/DELETE) and reaching the other one needs
// --invert. That asymmetry is why a place can require two invocations.
func buildX8Args(config X8Config, mode, urlsFile, outputFile string, verbs []string) []string {
	place := strings.ToLower(strings.TrimSuffix(mode, "!"))
	invert := strings.HasSuffix(mode, "!")

	args := []string{"-u", urlsFile, "-o", outputFile, "-O", "json"}

	// The verbs this group holds, as ONE -X with its values after it.
	//
	// "-X POST -X PUT" is rejected outright: x8 4.3.1 exits 1 with "The argument
	// '--method <methods>' was provided more than once, but cannot be used multiple times", so the
	// group failed as a whole and reported zero findings. PlanVerbGroups now puts one verb in each
	// x8 group, which is also what keeps x8 from testing every url with every verb, so this is
	// normally a single value; the loop stays multi-value-safe rather than assuming that.
	if len(verbs) > 0 {
		args = append(args, "-X")
		args = append(args, verbs...)
	}

	switch place {
	case "headers":
		args = append(args, "--headers")
	case "cookies":
		args = append(args, "--cookies")
	}
	if invert {
		args = append(args, "--invert")
	}

	// -W is concurrent URLs, -c is concurrent requests per URL. Both default to 1 in x8, so leaving
	// -c unset means every URL is probed one request at a time however many workers are running.
	if config.Workers > 0 {
		args = append(args, "-W", fmt.Sprintf("%d", config.Workers))
	}
	if config.RequestsPerURL > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", config.RequestsPerURL))
	}
	if config.LearnRequests > 0 {
		args = append(args, "--learn-requests", fmt.Sprintf("%d", config.LearnRequests))
	}
	if config.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", config.Timeout))
	}
	// x8 caps candidates per request differently per place already (256 query, 64 headers, 512
	// body), so this is only sent when the operator has asked for something specific.
	if config.MaxParamsPerReq > 0 {
		args = append(args, "-m", fmt.Sprintf("%d", config.MaxParamsPerReq))
	}
	// Encoding and body template only mean anything where there is a body, which is the body place
	// and nowhere else.
	//
	// The condition used to be `place == "body" || invert`, which also caught the inverted QUERY
	// pass, and -t is where that turns destructive. -t sets the parameter TEMPLATE, so with
	// -t json x8 wrote JSON fragments into the URL: the request line became
	// `POST /q"6ilf3v":"52xns8",... HTTP/1.1`, every response was a 404, and the pass reported no
	// parameters. Verified against x8 4.3.1: the identical command without -t sends
	// `POST /q?a=b&c=d` and finds the hidden parameter.
	if place == "body" {
		if bt := x8DataType(config.BodyType); bt != "" {
			args = append(args, "-t", bt)
		}
		if tpl := strings.TrimSpace(config.BodyTemplate); strings.Contains(tpl, "%s") {
			args = append(args, "-b", tpl)
		}
	}
	if config.Delay > 0 {
		args = append(args, "--delay", fmt.Sprintf("%d", config.Delay))
	}
	// Always a wordlist. -w is not optional in practice: x8 documents the empty default as "read
	// from stdin", the runner attaches no stdin, and x8 then reports "wordlist len: 0" and tests
	// nothing but its own 11 built-in custom parameter names (admin bot captcha debug disable
	// encryption env show sso test waf). A scan in that state finds a hidden `debug` and misses
	// every other name in existence, while still reporting success.
	if wl := strings.TrimSpace(config.Wordlist); wl != "" {
		args = append(args, "--wordlist", wl)
	} else {
		args = append(args, "--wordlist", DefaultX8WordlistFor(place))
	}
	if config.ReflectedOnly {
		args = append(args, "--reflected-only")
	}
	if config.Strict {
		args = append(args, "--strict")
	}
	if config.DisableCustomSet {
		args = append(args, "--disable-custom-parameters")
	}
	if config.MimicBrowser {
		args = append(args, "--mimic-browser")
	}
	if config.FollowRedirects {
		args = append(args, "--follow-redirects")
	}
	if config.Verify {
		args = append(args, "--verify")
	}
	if config.DisableColors {
		args = append(args, "--disable-colors")
	}
	// This output is captured with CombinedOutput and stored in x8_scans.stdout for the operator to
	// read, so the progress bar's carriage returns and the ASCII banner are noise in a database
	// column rather than something anybody watches redraw.
	args = append(args, "--disable-progress-bar", "--remove-banner")
	// Static headers: ONE -H followed by every header as a separate value, which is the form x8
	// documents ("-H 'one:one' 'two:two'").
	//
	// A -H per header is rejected exactly like a -X per verb: x8 4.3.1 exits 1 with "The argument
	// '-H <headers>' was provided more than once, but cannot be used multiple times". One header
	// worked, two failed every pass of the scan, which is the shape of bug that hides until somebody
	// configures both an Authorization and a Cookie header.
	//
	// This stays LAST in the argument list on purpose. It is a multi-value flag, so it consumes
	// following arguments until the next one starting with "-", and a header line never does.
	//
	// Note --headers is a discovery MODE and not header input; passing headers there would silently
	// switch the run to header brute-forcing.
	if lines := ParamHeaderLines(config.Headers); len(lines) > 0 {
		args = append(args, "-H")
		args = append(args, lines...)
	}
	return args
}

// parseX8Output reads x8's JSON report.
//
// Verified shape, captured from x8 4.3.1 against a local target:
//
//	[{"method":"GET","url":"...","status":200,"size":322,
//	  "found_params":[{"name":"debug","value":"no",
//	                   "diffs":"-1,1 +1,1|-1,1 +1,1 (1)|-16,2 +16,0",
//	                   "status":200,"size":349,"reason_kind":"Text"}],
//	  "injection_place":"Path"}]
//
// injection_place has exactly four values (read out of the binary's serde table): Path, Body,
// Headers, HeaderValue. reason_kind has exactly four: Reflected, NotReflected, Text, Code.
//
// x8 writes this file even when it finds nothing, as [] or as a row with an empty found_params, so a
// file that is missing or unparseable means x8 did not complete rather than "no parameters".
func parseX8Output(ctx context.Context, outputFile, scanID, scopeTargetID string, g VerbGroup) (int, error) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return 0, fmt.Errorf("x8 wrote no output file: %w", err)
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("x8 wrote an empty output file")
	}

	var x8Results []struct {
		URL            string `json:"url"`
		Method         string `json:"method"`
		InjectionPlace string `json:"injection_place"`
		FoundParams    []struct {
			Name       string  `json:"name"`
			Value      *string `json:"value"`
			ReasonKind string  `json:"reason_kind"`
		} `json:"found_params"`
	}
	if err := json.Unmarshal(data, &x8Results); err != nil {
		return 0, fmt.Errorf("x8 output was not the expected JSON: %w", err)
	}
	// x8 emits one entry per url:method pair it tested, with an empty found_params when it found
	// nothing there. A top-level [] therefore means it tested NOTHING, which is a different fact
	// from finding nothing and has to be reported as one.
	//
	// The reproducible cause is a --invert pass on a GET: x8 4.3.1 makes two requests and returns []
	// with no message at any verbosity, so an operator who moves a GET endpoint to the body tab gets
	// a pass that silently does nothing.
	if len(x8Results) == 0 {
		detail := "x8 tested no url in this pass and returned an empty result set"
		if strings.HasSuffix(g.Mode, "!") && strings.EqualFold(g.Verb, "GET") {
			detail += ". x8 4.3.1 does not implement --invert for GET, which is what sending a GET " +
				"endpoint to the body place requires, so this pass cannot produce a result"
		}
		return 0, fmt.Errorf("%s", detail)
	}

	found := 0
	for _, r := range x8Results {
		// No fallback to "whatever URL sorted first". x8 always reports the URL it tested, and
		// guessing attributed a finding to an unrelated endpoint the moment a group held more than
		// one target.
		if strings.TrimSpace(r.URL) == "" {
			continue
		}
		method := strings.ToUpper(r.Method)
		if method == "" {
			method = strings.ToUpper(g.Verb)
		}
		for _, p := range r.FoundParams {
			name := strings.TrimSpace(p.Name)
			// x8 can report "name=value"; keep the name.
			if i := strings.IndexAny(name, "=:"); i > 0 {
				name = name[:i]
			}
			if name == "" {
				continue
			}
			value := ""
			if p.Value != nil {
				value = *p.Value
			}
			if StoreParameterFinding(ctx, scanID, "x8", scopeTargetID, r.URL, method,
				g.Label, name, x8ParamType(g.Mode, r.InjectionPlace),
				x8Confidence(p.ReasonKind), value, p.ReasonKind) {
				found++
			}
		}
	}
	return found, nil
}

// x8Confidence grades a finding by how x8 came to it.
//
// A reflected value and a changed status code are both directly observed; a body-text difference is
// inferred from a diff and is the one that catches ordinary page variation. NotReflected is x8
// reporting that a parameter suppressed a reflection it expected, which is a real signal but a
// subtler one, so it stays with the inferred group.
func x8Confidence(reasonKind string) string {
	switch strings.ToLower(strings.TrimSpace(reasonKind)) {
	case "reflected", "code":
		return "high"
	default:
		return "medium"
	}
}

// x8ParamType maps a pass onto the stored parameter_type. Everything used to be recorded as "query",
// so a header or body parameter was mislabelled as a query string one.
//
// The PASS is the authority, not injection_place, because x8 reports "HeaderValue" for both a cookie
// run and a header-value run: a --cookies pass returned injection_place "HeaderValue" and every
// hidden cookie was therefore filed as a header, leaving no way to tell the two apart in the results
// table. injection_place is still read as the fallback for a pass whose place is somehow unset.
func x8ParamType(mode, injectionPlace string) string {
	switch strings.ToLower(strings.TrimSuffix(mode, "!")) {
	case "body":
		return "body"
	case "headers":
		return "header"
	case "cookies":
		return "cookie"
	case "query":
		return "query"
	}
	switch strings.ToLower(injectionPlace) {
	case "body":
		return "body"
	case "headers", "headervalue":
		return "header"
	default:
		return "query"
	}
}

func UpdateX8ScanStatus(scanID, status, stdout, errorMsg string) {
	query := `UPDATE x8_scans SET status = $1, stdout = $2, error = $3 WHERE scan_id = $4`
	dbPool.Exec(context.Background(), query, status, stdout, errorMsg, scanID)
}

func GetX8ScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var status, result, errorMsg, stdout, stderr, command, executionTime string
	var totalEndpoints, processedEndpoints, parametersFound int
	var createdAt time.Time

	query := `
		SELECT status, COALESCE(result, ''), COALESCE(error, ''), COALESCE(stdout, ''), 
		       COALESCE(stderr, ''), COALESCE(command, ''), COALESCE(execution_time, ''),
		       total_endpoints, processed_endpoints, parameters_found, created_at
		FROM x8_scans WHERE scan_id = $1
	`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&status, &result, &errorMsg, &stdout, &stderr, &command, &executionTime,
		&totalEndpoints, &processedEndpoints, &parametersFound, &createdAt,
	)

	if err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":             scanID,
		"status":              status,
		"result":              result,
		"error":               errorMsg,
		"stdout":              stdout,
		"stderr":              stderr,
		"command":             command,
		"execution_time":      executionTime,
		"total_endpoints":     totalEndpoints,
		"processed_endpoints": processedEndpoints,
		"parameters_found":    parametersFound,
		"created_at":          createdAt,
	})
}

func GetX8ScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `
		SELECT scan_id, status, COALESCE(execution_time, ''), total_endpoints, 
		       processed_endpoints, parameters_found, created_at
		FROM x8_scans 
		WHERE scope_target_id = $1
		ORDER BY created_at DESC
	`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Initialised, not nil: a nil slice marshals to JSON null, and every client that does
	// scans.length on the response throws before it can check.
	scans := []map[string]interface{}{}
	for rows.Next() {
		var scanID, status, executionTime string
		var totalEndpoints, processedEndpoints, parametersFound int
		var createdAt time.Time

		if err := rows.Scan(&scanID, &status, &executionTime, &totalEndpoints, &processedEndpoints, &parametersFound, &createdAt); err != nil {
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":             scanID,
			"status":              status,
			"execution_time":      executionTime,
			"total_endpoints":     totalEndpoints,
			"processed_endpoints": processedEndpoints,
			"parameters_found":    parametersFound,
			"created_at":          createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func GetX8ScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `
		SELECT endpoint_url, COALESCE(http_method, 'GET'), COALESCE(verb_group, ''),
		       parameter_name, parameter_type,
		       COALESCE(example_value, ''), COALESCE(confidence, ''),
		       COALESCE(detection_reason, ''), created_at
		FROM parameter_enumeration_results
		WHERE scan_id = $1 AND scan_type = 'x8'
		ORDER BY endpoint_url, http_method, parameter_name
	`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results = []map[string]interface{}{}
	for rows.Next() {
		var endpointURL, method, verbGroup, paramName, paramType string
		var exampleValue, confidence, detectionReason string
		var createdAt time.Time

		if err := rows.Scan(&endpointURL, &method, &verbGroup, &paramName, &paramType,
			&exampleValue, &confidence, &detectionReason, &createdAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"endpoint_url": endpointURL,
			// The verb is part of the finding's identity: a hidden parameter on POST /accounts is a
			// different finding from one on GET /accounts, and both used to be stored and rendered
			// as the same row.
			"http_method":    method,
			"verb_group":     verbGroup,
			"parameter_name": paramName,
			"parameter_type": paramType,
			"example_value":  exampleValue,
			"confidence":     confidence,
			// x8's own word for why it reported this: Reflected, Code, Text or NotReflected.
			"detection_reason": detectionReason,
			"created_at":       createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
