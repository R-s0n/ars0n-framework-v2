package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// What a parameter scan will actually send, shown before it is sent.
//
// These tools are the most expensive thing this framework does per endpoint, and until now the
// operator could only find out what a run did by reading its stdout afterwards. Everything here is
// derived from the same resolvers the runners use: ForVerb for the settings, buildArjunArgs and
// buildX8Args for the command, ParamHeaderLines for the headers. A preview assembled from a second
// copy of that logic would drift, and a preview that drifts is worse than none, because it is a
// confident description of something that did not happen.
//
// The one thing that CANNOT be exact is the candidate parameter names: those come from a wordlist
// inside the tool's own container and the tool picks them itself. So the sample names are labelled
// as a sample and the real count is stated alongside, rather than presenting a fabricated request
// as the literal bytes on the wire.

type paramEnumRequestPreview struct {
	EndpointID string `json:"endpoint_id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Raw        string `json:"raw"`

	// Mode is the pass this endpoint is assigned to; AutoMode is what the categoriser derived from
	// its recorded request. When they differ the operator has moved it deliberately, and the UI says
	// so rather than leaving a silent reclassification.
	Mode     string `json:"mode"`
	AutoMode string `json:"auto_mode"`
	Enabled  bool   `json:"enabled"`
}

type paramEnumPassPreview struct {
	Label     string                    `json:"label"`
	Verb      string                    `json:"verb"`
	Mode      string                    `json:"mode"`
	Command   string                    `json:"command"`
	Settings  map[string]interface{}    `json:"settings"`
	Endpoints int                       `json:"endpoint_count"`
	Note      string                    `json:"note"`
	Requests  []paramEnumRequestPreview `json:"requests"`
}

// GetParamEnumPreview renders the passes a tool will run, with a request per endpoint.
func GetParamEnumPreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	tool := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tool")))
	if !paramEnumTools[tool] {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool", "tool must be one of arjun or x8")
		return
	}
	wantVerb := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("verb")))
	// The config UI needs the endpoints this tool is NOT set to scan as well, or a disabled one can
	// never be found again to re-enable. A plain preview stays honest and shows only what will run.
	includeDisabled := r.URL.Query().Get("all") == "true"

	ctx := context.Background()

	// Loaded exactly as the runner loads it: defaults first, stored row unmarshalled over the top.
	var includeScripts bool
	var arjun ArjunConfig
	var x8 X8Config
	var configJSON []byte
	if tool == "arjun" {
		arjun = DefaultArjunConfig()
		if dbPool.QueryRow(ctx, `SELECT config FROM arjun_configs WHERE scope_target_id = $1`,
			scopeTargetID).Scan(&configJSON) == nil {
			_ = UnmarshalConfigTolerant(configJSON, &arjun)
		}
		includeScripts = arjun.IncludeScripts
	} else {
		x8 = DefaultX8Config()
		if dbPool.QueryRow(ctx, `SELECT config FROM x8_configs WHERE scope_target_id = $1`,
			scopeTargetID).Scan(&configJSON) == nil {
			_ = UnmarshalConfigTolerant(configJSON, &x8)
		}
		includeScripts = x8.IncludeScripts
	}

	sel, err := SelectParamEnumTargets(ctx, scopeTargetID,
		ParamTargetOptions{Tool: tool, IncludeScripts: includeScripts,
			IncludeDisabled: includeDisabled})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	passes := []paramEnumPassPreview{}
	for _, g := range PlanVerbGroups(tool, sel.Targets) {
		if wantVerb != "" && g.Verb != wantVerb {
			continue
		}
		p := paramEnumPassPreview{
			Label: g.Label, Verb: g.Verb, Mode: g.Mode, Endpoints: len(g.Targets),
			Requests: []paramEnumRequestPreview{},
		}

		// Placeholder paths so the command reads like the real one without inventing a scan id.
		urlsFile := fmt.Sprintf("/tmp/%s_urls_<scan>_%s.txt", tool, safeGroupLabel(g.Label))
		outFile := fmt.Sprintf("/tmp/%s_output_<scan>_%s.json", tool, safeGroupLabel(g.Label))

		var headerLines []string
		var chunk int

		if tool == "arjun" {
			cfg := arjun.ForVerb(g.Verb)
			args := buildArjunArgs(cfg, g.Mode, urlsFile, outFile)
			p.Command = "docker exec ars0n-framework-v2-arjun-1 arjun " + strings.Join(args, " ")
			headerLines = ParamHeaderLines(cfg.Headers)
			chunk = cfg.ChunkSize
			if g.Mode != "GET" {
				// Arjun overrides -c to 500 internally for every non-GET mode.
				chunk = 500
			}
			p.Settings = map[string]interface{}{
				"threads": cfg.Threads, "delay": cfg.Delay, "timeout": cfg.Timeout,
				"chunkSize": chunk, "wordlist": cfg.Wordlist,
				"stableDetection": cfg.StableDetection,
			}
			p.Note = fmt.Sprintf(
				"Arjun packs up to %d candidate names into each request, so this is one request "+
					"shape rather than one request per parameter.", chunk)
			switch g.Mode {
			case "JSON":
				p.Note += " Candidates go in a JSON body. Endpoints land here when their recorded " +
					"request carried a JSON content type."
			case "XML":
				p.Note += " XML mode only functions with --include, which is why one is always sent: " +
					"without it Arjun raises internally, swallows the error per URL and exits 0 having " +
					"tested nothing."
			case "POST":
				p.Note += " Candidates go in a form-encoded body."
			}
		} else {
			cfg := x8.ForPlace(g.Mode)
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
			args := buildX8Args(cfg, g.Mode, urlsFile, outFile, verbs)
			p.Command = "docker exec ars0n-framework-v2-x8-1 x8 " + strings.Join(args, " ")
			headerLines = ParamHeaderLines(cfg.Headers)
			chunk = 0 // x8 decides its own batch size and narrows by bisection
			p.Settings = map[string]interface{}{
				"workers": cfg.Workers, "requestsPerUrl": cfg.RequestsPerURL,
				"delay": cfg.Delay, "timeout": cfg.Timeout,
				"learnRequests": cfg.LearnRequests, "wordlist": cfg.Wordlist,
				"bodyType": cfg.BodyType, "bodyTemplate": cfg.BodyTemplate,
				"maxParamsPerRequest": cfg.MaxParamsPerReq,
				"reflectedOnly":       cfg.ReflectedOnly, "verify": cfg.Verify,
				"followRedirects": cfg.FollowRedirects, "strict": cfg.Strict,
			}
			if cfg.MaxParamsPerReq > 0 {
				p.Note = fmt.Sprintf(
					"x8 sends up to %d candidates per request, which is the Max params/request you "+
						"set rather than its own per-place cap, then bisects to find which one caused "+
						"a difference, so the batch below is illustrative.", cfg.MaxParamsPerReq)
			} else {
				p.Note = "x8 sends candidates in batches it sizes itself (up to 256 for a query, 64 " +
					"for headers, 512 for a body), then bisects to find which one caused a " +
					"difference, so the batch below is illustrative."
			}
			if strings.HasSuffix(g.Mode, "!") {
				p.Note += " This pass carries --invert, because x8 would otherwise put candidates " +
					"in the other place for these verbs."
				// Measured, not inferred: x8 4.3.1 makes two requests for an inverted GET and returns
				// an empty result set with no message. Saying so here is the difference between an
				// operator choosing this deliberately and one waiting for a result that cannot come.
				if strings.EqualFold(g.Verb, "GET") {
					p.Note += " WARNING: x8 4.3.1 does not implement --invert for GET. This pass will " +
						"make two requests and report nothing, whatever the endpoint accepts."
				}
			}
		}

		xmlTemplate := defaultArjunXMLTemplate
		if tool == "arjun" {
			if tpl := strings.TrimSpace(arjun.ForVerb(g.Verb).XMLTemplate); strings.Contains(tpl, "$arjun$") {
				xmlTemplate = tpl
			}
		}

		bodyType := "json"
		bodyTemplate := ""
		if tool == "x8" {
			placeCfg := x8.ForPlace(g.Mode)
			if bt := placeCfg.BodyType; bt != "" {
				bodyType = bt
			}
			bodyTemplate = strings.TrimSpace(placeCfg.BodyTemplate)
		}

		enabledCount := 0
		for _, t := range g.Targets {
			if t.Enabled {
				enabledCount++
			}
			host, path := splitURLForDisplay(t.URL)
			p.Requests = append(p.Requests, paramEnumRequestPreview{
				EndpointID: t.ID, Method: t.Method, URL: t.URL, Host: host, Path: path,
				Mode: t.ModeFor(tool), AutoMode: t.AutoModeFor(tool), Enabled: t.Enabled,
				Raw: buildRequestPreview(tool, g.Mode, t, headerLines, bodyType, xmlTemplate,
					bodyTemplate),
			})
		}
		// The headline count is what will actually be sent, never the number of rows listed.
		p.Endpoints = enabledCount
		if enabledCount == 0 {
			// Otherwise a full, plausible command is displayed for a pass the runner will never
			// create, because it selects only enabled endpoints.
			p.Note = "Every endpoint in this pass is deselected, so it will not run at all. " + p.Note
		}
		passes = append(passes, p)
	}

	// Arjun's four modes are the tabs, so every one is returned even when empty. A missing tab would
	// leave an operator no way to move an endpoint INTO that mode.
	if tool == "x8" && wantVerb == "" {
		seen := map[string]bool{}
		for _, p := range passes {
			seen[strings.TrimSuffix(p.Mode, "!")] = true
		}
		for _, place := range X8Places {
			if seen[place] {
				continue
			}
			passes = append(passes, paramEnumPassPreview{
				Label: place, Mode: place, Requests: []paramEnumRequestPreview{},
				Note: "No endpoints are set to inject into the " + place + " yet. Move one here " +
					"from another tab to test it this way.",
			})
		}
		order := map[string]int{}
		for i, place := range X8Places {
			order[place] = i
		}
		sort.SliceStable(passes, func(i, j int) bool {
			return order[strings.TrimSuffix(passes[i].Mode, "!")] <
				order[strings.TrimSuffix(passes[j].Mode, "!")]
		})
	}

	if tool == "arjun" && wantVerb == "" {
		seen := map[string]bool{}
		for _, p := range passes {
			seen[p.Mode] = true
		}
		for _, m := range ArjunModes {
			if seen[m] {
				continue
			}
			passes = append(passes, paramEnumPassPreview{
				Label: m, Verb: map[bool]string{true: "GET", false: "POST"}[m == "GET"], Mode: m,
				Requests: []paramEnumRequestPreview{},
				Note:     "No endpoints are categorised as " + m + " yet. Move one here from another tab to test it this way.",
			})
		}
		order := map[string]int{}
		for i, m := range ArjunModes {
			order[m] = i
		}
		sort.SliceStable(passes, func(i, j int) bool { return order[passes[i].Mode] < order[passes[j].Mode] })
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tool":       tool,
		"passes":     passes,
		"total":      sel.Total,
		"by_method":  sel.ByMethod,
		"scope":      sel.Scope,
		"disclaimer": "Candidate parameter names come from the tool's wordlist inside its own container. The names shown are a sample, and FUZZ stands in for the value the tool generates, which for x8 is a fresh random string per candidate. The counts and every other part of the request are exact.",
	})
}

func splitURLForDisplay(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", raw
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return u.Host, p
}

func safeGroupLabel(label string) string {
	return strings.NewReplacer(" ", "_", "(", "", ")", "").Replace(label)
}

// sampleParamNames are stand-ins for whatever the wordlist holds, chosen to look like what a real
// list contains rather than like p1/p2, so the shape of the request reads true.
var sampleParamNames = []string{"debug", "redirect_uri", "callback", "admin", "id", "next", "test", "format"}

// buildRequestPreview renders the HTTP request this pass will send to one endpoint.
//
// The two tools vary along different axes, so the dispatch does too. Arjun's mode is a body
// ENCODING and replaces the request shape; x8's is an injection PLACE, and the verb stays whatever
// the endpoint answers.
func buildRequestPreview(tool, mode string, t ParamTarget, headerLines []string,
	bodyType, xmlTemplate, bodyTemplate string) string {

	u, err := url.Parse(t.URL)
	if err != nil {
		return "(unparseable URL: " + t.URL + ")"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}

	place := strings.ToLower(strings.TrimSuffix(mode, "!"))
	inQuery := mode == "GET" // arjun
	inHeaders, inCookies := false, false
	if tool == "x8" {
		inQuery = place == "query"
		inHeaders = place == "headers"
		inCookies = place == "cookies"
	}
	inBody := !inQuery && !inHeaders && !inCookies

	var b strings.Builder
	existing := u.RawQuery

	if inQuery {
		injected := make([]string, 0, len(sampleParamNames))
		for _, n := range sampleParamNames {
			injected = append(injected, n+"=FUZZ")
		}
		q := strings.Join(injected, "&")
		if existing != "" {
			// The endpoint's own parameters are preserved; candidates are appended to them.
			q = existing + "&" + q
		}
		fmt.Fprintf(&b, "%s %s?%s HTTP/1.1\n", t.Method, path, q)
	} else if existing != "" {
		fmt.Fprintf(&b, "%s %s?%s HTTP/1.1\n", t.Method, path, existing)
	} else {
		fmt.Fprintf(&b, "%s %s HTTP/1.1\n", t.Method, path)
	}

	fmt.Fprintf(&b, "Host: %s\n", u.Host)

	// x8 merges its cookie candidates into a configured Cookie header rather than sending a second
	// one, and joins them with ";" and no space. Verified against x8 4.3.1, which sent
	// `Cookie: session=testsession;oy5an4=08akq3;...` for a --cookies pass with -H 'Cookie: ...'.
	// Both halves matter: an operator reading two Cookie headers here would reasonably conclude the
	// session cookie was being clobbered.
	staticCookie := ""
	var otherHeaders []string
	for _, h := range headerLines {
		if name, value, ok := strings.Cut(h, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "cookie") {
			staticCookie = strings.TrimSpace(value)
			continue
		}
		otherHeaders = append(otherHeaders, h)
	}
	if !inCookies {
		// Outside the cookies place the Cookie header is sent as configured, so keep it in place.
		otherHeaders = headerLines
		staticCookie = ""
	}

	contentType := ""
	if inBody {
		switch {
		case tool == "arjun" && mode == "JSON":
			contentType = "application/json"
		case tool == "arjun" && mode == "XML":
			// requester.py sets this itself for XML mode, so it is stated rather than guessed.
			contentType = "application/xml"
		case tool == "arjun":
			contentType = "application/x-www-form-urlencoded"
		case strings.Contains(strings.ToLower(bodyType), "json"):
			contentType = "application/json"
		default:
			contentType = "application/x-www-form-urlencoded"
		}
	}
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", contentType)
	}
	for _, h := range otherHeaders {
		b.WriteString(h + "\n")
	}

	// Header and cookie discovery put the candidates in the request head, not in a body. x8 removes
	// Content-Length and Host from the candidate list itself, which its --headers help states.
	if inHeaders {
		for _, n := range sampleParamNames {
			fmt.Fprintf(&b, "%s: FUZZ\n", n)
		}
	}
	if inCookies {
		parts := make([]string, 0, len(sampleParamNames)+1)
		if staticCookie != "" {
			parts = append(parts, staticCookie)
		}
		for _, n := range sampleParamNames {
			parts = append(parts, n+"=FUZZ")
		}
		fmt.Fprintf(&b, "Cookie: %s\n", strings.Join(parts, ";"))
	}

	// Stated rather than invented: both tools set their own agent and connection handling, and
	// showing a made-up User-Agent would be the kind of small lie that makes the rest untrustworthy.
	b.WriteString("(the tool adds its own User-Agent and connection headers)\n")

	if inBody {
		b.WriteString("\n")
		switch contentType {
		case "application/xml":
			// Arjun substitutes the generated element list into the --include template at the
			// $arjun$ marker, so the preview does the same rather than inventing a shape.
			elems := make([]string, 0, len(sampleParamNames))
			for _, n := range sampleParamNames {
				elems = append(elems, fmt.Sprintf("<%s>FUZZ</%s>", n, n))
			}
			b.WriteString(strings.Replace(xmlTemplate, "$arjun$", strings.Join(elems, ""), 1))
		case "application/json":
			parts := make([]string, 0, len(sampleParamNames))
			for _, n := range sampleParamNames {
				parts = append(parts, fmt.Sprintf("%q: \"FUZZ\"", n))
			}
			// A configured -b template is where the candidates actually land, so a flat top-level
			// object is the wrong shape to show: the whole point of the template is reaching
			// parameters nested under a wrapper.
			if strings.Contains(bodyTemplate, "%s") {
				b.WriteString(strings.Replace(bodyTemplate, "%s", strings.Join(parts, ", "), 1))
			} else {
				b.WriteString("{" + strings.Join(parts, ", ") + "}")
			}
		default:
			parts := make([]string, 0, len(sampleParamNames))
			for _, n := range sampleParamNames {
				parts = append(parts, n+"=FUZZ")
			}
			b.WriteString(strings.Join(parts, "&"))
		}
	}
	return b.String()
}
