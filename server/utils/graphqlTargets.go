package utils

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// Where the GraphQL section gets its targets.
//
// Nothing here is discovered automatically, by decision: identifying which of a target's endpoints
// speak GraphQL is the operator's call, not a heuristic's. Each tool carries its OWN list of
// endpoints in its OWN settings, which is why the RowSource below loads settings rather than
// querying a table. That is the shape the operator asked for.
//
// The cost of that shape is drift: the same endpoint marked in three places can disagree, and a URL
// added to graphql-cop is invisible to clairvoyance. GraphQLKnownEndpoints exists to make the drift
// visible rather than silent, by telling each config modal what the other two already know about.

// graphqlEndpointsSetting is the key every tool that takes a hand-picked endpoint list stores it
// under. Shared by the GraphQL, sensitive leak and exposed git sections: in all three the operator
// decides what gets scanned rather than a heuristic, and in all three the list is per tool.
const graphqlEndpointsSetting = "endpoints"

// graphqlSectionTools is every tool whose settings can hold an endpoint list, grouped by section so
// "what do the other tools here already know about" stays within a section rather than spanning all
// of them.
var graphqlSectionTools = []string{"graphql-cop", "clairvoyance", "graphw00f"}

var endpointListSections = map[string][]string{
	"graphql":        {"graphql-cop", "clairvoyance", "graphw00f"},
	"sensitive-leak": {"snallygaster", "mantra", "trufflehog"},
	"exposed-git":    {"git-dumper", "gittools"},
}

// endpointSourceTables is every table holding a URL alongside a scope target, used to offer the
// operator the endpoints this target already has rather than making them retype one.
//
// The two filters are not cosmetic and were verified against the database: only live_web_server rows
// in the attack surface table carry a url at all, and a host already marked no_longer_live is one
// the framework has decided is dead.
var endpointSourceTables = []struct {
	Name  string
	Table string
	Where string
}{
	{"consolidated-endpoints", "consolidated_url_endpoints", ""},
	{"endpoint-discovery", "discovered_endpoints", ""},
	{"manual-crawl", "manual_crawl_captures", ""},
	{"endpoint-validation", "endpoint_validation_results", ""},
	{"target-urls", "target_urls", "AND COALESCE(no_longer_live, false) = false"},
	{"attack-surface", "consolidated_attack_surface_assets", "AND asset_type = 'live_web_server'"},
}

// endpointListPeers returns the other tools whose lists are worth comparing against this one.
func endpointListPeers(toolKey string) []string {
	for _, tools := range endpointListSections {
		for _, key := range tools {
			if key == toolKey {
				return tools
			}
		}
	}
	return nil
}

// graphqlEndpointsFor reads one tool's endpoint list.
//
// Stored as a newline or comma separated string rather than a JSON array because that is what a
// textarea in the config modal produces, and because the same value has to survive a round trip
// through the MCP server, which sends plain strings.
func graphqlEndpointsFor(ctx context.Context, scopeTargetID, toolKey string) []string {
	settings := loadVectorSettings(ctx, scopeTargetID, toolKey)

	// settingValues, NOT stringifySetting. The list arrives in two shapes: the config modal posts one
	// string with a URL per line, and the API and MCP post a JSON array. stringifySetting flattens an
	// array by joining it with "; ", because its other callers are building Cookie headers, and the
	// splitter below never treated ";" as a separator. So a list set through MCP came back as
	//
	//	https://host/admin;  https://host/admin/login;  https://host/admin/users
	//
	// and the first two were scanned WITH THE SEMICOLON ATTACHED: a different URL from the one the
	// operator chose, silently, with the tool reporting a clean result for a path nobody asked about.
	// Measured on ginandjuice.shop, where two of three bypass targets were scanned as /admin; and
	// /admin/login;.
	var raw []string
	for _, item := range settingValues(settings[graphqlEndpointsSetting]) {
		raw = append(raw, splitEndpointList(item)...)
	}
	seen := map[string]bool{}
	var out []string
	for _, url := range raw {
		if seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, url)
	}
	return out
}

// splitEndpointList turns whatever the operator typed into a clean list of URLs.
func splitEndpointList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		// ";" is in here as well as the whitespace and comma separators, so a list that has already
		// been flattened by stringifySetting somewhere upstream still splits correctly rather than
		// leaving the separator glued to the end of every URL but the last.
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	seen := map[string]bool{}
	var out []string
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		// A bare host is accepted and made explicit. All three tools want a URL, and two of them
		// behave differently, or not at all, without a scheme.
		if !strings.Contains(field, "://") {
			field = "https://" + field
		}
		if seen[field] {
			continue
		}
		seen[field] = true
		out = append(out, field)
	}
	return out
}

// graphqlRowSource builds the RowSource for one tool: its own endpoint list, nothing else.
//
// Returns rows rather than an error when the list is empty, so the card reads 0 of 0 and the
// eligibility report can say WHY, rather than the scan failing with something an operator has to
// interpret.
func graphqlRowSource(toolKey string) func(context.Context, string) ([]vectorRow, error) {
	return func(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
		var out []vectorRow
		for _, endpoint := range graphqlEndpointsFor(ctx, scopeTargetID, toolKey) {
			row := vectorRow{
				ID:              graphqlEndpointID(scopeTargetID, toolKey, endpoint),
				Method:          "POST",
				InsertionPoint:  "body",
				EvidenceURL:     endpoint,
				IsGraphQLTarget: true,
			}
			row.Scheme, row.Domain, row.Port, row.Path = splitURLParts(endpoint)
			out = append(out, row)
		}
		return out, nil
	}
}

// graphqlEndpointID is a stable identifier for an endpoint in a tool's list.
//
// A UUID, because the scan tables key on one, derived from the values so the same endpoint keeps the
// same id across runs and its history survives. Not stored anywhere: the list is the settings.
func graphqlEndpointID(scopeTargetID, toolKey, endpoint string) string {
	return deterministicUUID(scopeTargetID + "|" + toolKey + "|" + endpoint)
}

// GraphQLKnownEndpoints reports every endpoint any tool in this section has been given, and which
// tools have it.
//
// The section stores three separate lists by choice. This is what stops that being invisible: the
// config modal shows an endpoint the other tools know about, so an operator can see at a glance that
// clairvoyance is about to skip something graphql-cop is scanning.
func GraphQLKnownEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	byEndpoint := map[string][]string{}
	for _, toolKey := range graphqlSectionTools {
		for _, endpoint := range graphqlEndpointsFor(r.Context(), scopeTargetID, toolKey) {
			byEndpoint[endpoint] = append(byEndpoint[endpoint], toolKey)
		}
	}

	type entry struct {
		URL   string   `json:"url"`
		Tools []string `json:"tools"`
	}
	out := make([]entry, 0, len(byEndpoint))
	for endpoint, tools := range byEndpoint {
		sort.Strings(tools)
		out = append(out, entry{URL: endpoint, Tools: tools})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"endpoints": out,
		"tools":     graphqlSectionTools,
	})
}

// DetectGraphQLEndpoints runs graphw00f's detect mode against a host and returns what it found, for
// the operator to accept or reject.
//
// Nothing is added to any list here and nothing is scanned. graphw00f already knows the common
// GraphQL paths and tries them, so this is the tool doing work the operator would otherwise do by
// hand, with the operator still deciding.
func DetectGraphQLEndpoints(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Host) == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	target := strings.TrimSpace(body.Host)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	// Stripped, because graphw00f builds the candidate URL by string concatenation rather than
	// joining paths: given a target ending in a slash it reports http://host//graphql.
	target = strings.TrimRight(target, "/")
	if _, err := url.Parse(target); err != nil {
		http.Error(w, "host is not a URL", http.StatusBadRequest)
		return
	}

	tool, _ := VectorToolByKey("graphw00f")
	cmd := exec.CommandContext(r.Context(), "docker", "exec", tool.Container,
		"graphw00f-batch", "-d", "-t", target)
	output, err := cmd.CombinedOutput()

	found := ParseGraphw00fDetect(string(output))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"host":     target,
		"found":    found,
		"output":   stripANSI(string(output)),
		"error":    errText(err),
		"searched": "graphw00f's own list of common GraphQL paths",
	})
}

// ParseGraphw00fDetect pulls the endpoints out of graphw00f's detect output.
//
// The line is, verbatim from main.py:
//
//	print('[!] Found GraphQL at {}'.format(target))
//
// and when nothing is found:
//
//	print('[x] Could not find GraphQL anywhere.')
//
// Exported so the parse is testable without a container, because a detect button that silently finds
// nothing is indistinguishable from a host that has no GraphQL.
func ParseGraphw00fDetect(output string) []string {
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(stripANSI(output), "\n") {
		line = strings.TrimSpace(line)
		const marker = "Found GraphQL at "
		index := strings.Index(line, marker)
		if index < 0 {
			continue
		}
		endpoint := strings.TrimSpace(line[index+len(marker):])
		if endpoint == "" || seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		found = append(found, endpoint)
	}
	return found
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// deterministicUUID derives a stable UUID from a string.
//
// The scan tables key on a UUID, but a GraphQL endpoint has no row anywhere to take one from: the
// list lives in the tool's settings. Deriving it from the values means the same endpoint keeps the
// same identity between runs, so its scan history and findings stay attached to it, while adding or
// removing other endpoints does not disturb it.
//
// SHA-256 rather than a random id for exactly that reason, formatted as a version 4 UUID so the
// uuid columns accept it.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	buf := sum[:16]
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// graphqlEndpointIsPathless reports whether graphql-cop would discard this URL and scan its own list.
//
// From graphql-cop.py: `if parsed.path and parsed.path != '/'` keeps the URL, and anything else falls
// through to a hardcoded five. So "https://x.test" and "https://x.test/" are both pathless, and
// "https://x.test/graphql" is not.
func graphqlEndpointIsPathless(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return parsed.Path == "" || parsed.Path == "/"
}

// GraphQLCandidateEndpoints lists the URLs this scope target already has, so an operator can MARK one
// as GraphQL rather than typing it out.
//
// "Identify any endpoint as a GraphQL endpoint" was the requirement, and a free-text box does not
// meet it: the endpoints are already in the database, and retyping one is both work and a chance to
// get it wrong. Likely candidates are floated to the top, but everything is listed, because the whole
// point of this section is that the operator decides rather than a heuristic.
func GraphQLCandidateEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	var unions []string
	for _, source := range endpointSourceTables {
		unions = append(unions, fmt.Sprintf(
			`SELECT url, '%s' AS source FROM %s WHERE scope_target_id = $1 AND url IS NOT NULL AND url <> '' %s`,
			source.Name, source.Table, source.Where))
	}

	rows, err := dbPool.Query(r.Context(), `WITH found AS (`+strings.Join(unions, " UNION ALL ")+`)
		SELECT url, source FROM found`, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type candidate struct {
		URL     string   `json:"url"`
		Sources []string `json:"sources"`
		Likely  bool     `json:"likely"`
		InScope bool     `json:"in_scope"`
	}

	// The endpoint tables carry more than endpoints. Crawlers record every absolute URL they see in a
	// page, so XML namespaces (http://www.w3.org/2000/svg) and OAuth grant-type URNs
	// (http://auth0.com/oauth/grant-type/password-realm) end up here. They are all third party, so
	// ordering the operator's own hosts first sinks them without inventing a junk filter that would
	// eventually hide something real.
	scopeHost := bypassScopeHost(r.Context(), scopeTargetID)

	bySource := map[string]map[string]bool{}
	for rows.Next() {
		var rawURL, source string
		if err := rows.Scan(&rawURL, &source); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The query string is dropped: /graphql?x=1 and /graphql are the same endpoint to these tools.
		if parsed, err := url.Parse(rawURL); err == nil {
			parsed.RawQuery, parsed.Fragment = "", ""
			rawURL = parsed.String()
		}
		if search != "" && !strings.Contains(strings.ToLower(rawURL), search) {
			continue
		}
		if bySource[rawURL] == nil {
			bySource[rawURL] = map[string]bool{}
		}
		bySource[rawURL][source] = true
	}

	out := make([]candidate, 0, len(bySource))
	for rawURL, sources := range bySource {
		names := make([]string, 0, len(sources))
		for source := range sources {
			names = append(names, source)
		}
		sort.Strings(names)
		out = append(out, candidate{URL: rawURL, Sources: names, Likely: looksLikeGraphQL(rawURL),
			InScope: bypassHostInScope(rawURL, scopeHost)})
	}

	// The operator's own hosts first, then the ones that look like GraphQL, then alphabetically.
	// Nothing is hidden: marking a third-party endpoint is still possible, it is just not what the
	// list offers first, and the row says which it is.
	sort.Slice(out, func(i, j int) bool {
		if out[i].InScope != out[j].InScope {
			return out[i].InScope
		}
		if out[i].Likely != out[j].Likely {
			return out[i].Likely
		}
		return out[i].URL < out[j].URL
	})

	limit := 500
	truncated := false
	if len(out) > limit {
		out, truncated = out[:limit], true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"candidates": out,
		"count":      len(out),
		"truncated":  truncated,
	})
}

// looksLikeGraphQL is a HINT for ordering, never a filter. Marking an endpoint is the operator's job;
// this only decides what appears first.
func looksLikeGraphQL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	for _, hint := range []string{"graphql", "/gql", "graphiql", "playground", "/query", "altair"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// GitCandidateEndpoints lists the directories where a .git has ALREADY been found, so the exposed
// git section can be pointed at them without the operator copying URLs between screens.
//
// This is the handover the workflow is built around: snallygaster discovers, and these two tools do
// the work afterwards. A directory nobody has found a repository in is still selectable through the
// ordinary endpoint list, because a scanner missing one is not proof there is none.
func GitCandidateEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	// snallygaster reports the FILE it found (.../.git/config); the git tools want the directory that
	// contains the repository, which is two levels up.
	rows, err := dbPool.Query(r.Context(), `
		SELECT DISTINCT f.url, f.kind, f.tool
		FROM vector_findings f
		JOIN vector_scans s ON s.id = f.scan_id
		WHERE s.scope_target_id = $1
		  AND f.triage <> 'dismissed'
		  AND (f.kind IN ('leak-git_dir', 'leak-svn_dir') OR f.url ILIKE '%/.git/%')
		ORDER BY f.url`, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type found struct {
		Directory string `json:"directory"`
		FoundAt   string `json:"found_at"`
		By        string `json:"by"`
	}

	seen := map[string]bool{}
	out := []found{}
	for rows.Next() {
		var rawURL, kind, tool string
		if err := rows.Scan(&rawURL, &kind, &tool); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		directory := gitDirectoryOf(rawURL)
		if directory == "" || seen[directory] {
			continue
		}
		seen[directory] = true
		out = append(out, found{Directory: directory, FoundAt: rawURL, By: tool})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"found": out,
		"count": len(out),
		"note": "Directories where a version control directory has already been found. Run " +
			"snallygaster in the section above to populate this.",
	})
}

// gitDirectoryOf turns whatever was reported into the directory CONTAINING the repository.
//
// snallygaster reports the file it matched, which is ".../.git/config", and the recovery tools want
// ".../" so they can build ".../.git/" themselves. Handing them the config URL would produce
// ".../.git/config/.git/".
func gitDirectoryOf(rawURL string) string {
	lower := strings.ToLower(rawURL)
	for _, marker := range []string{"/.git/", "/.svn/"} {
		if index := strings.Index(lower, marker); index >= 0 {
			return rawURL[:index+1]
		}
	}
	if strings.HasSuffix(lower, "/.git") || strings.HasSuffix(lower, "/.svn") {
		return rawURL[:len(rawURL)-4]
	}
	return ""
}

// deniedStatusSources is every table that records an HTTP status alongside a URL and a scope target.
//
// Written out rather than discovered: this database has around forty columns called "status" and
// almost all of them hold 'running' or 'completed', which is SCAN status rather than HTTP status.
// Treating one of those as a status code would produce an empty list and a section that silently has
// nothing to offer.
var deniedStatusSources = []struct {
	Name         string
	Table        string
	StatusColumn string
	Where        string
}{
	{"endpoint-discovery", "discovered_endpoints", "status_code", ""},
	{"endpoint-validation", "endpoint_validation_results", "http_status", ""},
	{"manual-crawl", "manual_crawl_captures", "status_code", ""},
	{"fuzz", "fuzz_findings", "http_status", ""},
	{"target-urls", "target_urls", "status_code", "AND COALESCE(no_longer_live, false) = false"},
	{"attack-surface", "consolidated_attack_surface_assets", "status_code", "AND asset_type = 'live_web_server'"},
}

// consolidatedDeniedUnion is the seventh source, kept apart from the six above because it does not
// fit their shape: consolidated_url_endpoints records status_codes as a JSONB ARRAY, since one
// endpoint can have answered differently on different observations. Expanding that array is the only
// way a 403 recorded there reaches the bypass section, and without it the largest endpoint table on
// the target contributes nothing.
const consolidatedDeniedUnion = `
	SELECT url, (jsonb_array_elements_text(status_codes))::int AS status_code,
	       'consolidated' AS source
	FROM consolidated_url_endpoints
	WHERE scope_target_id = $1 AND url IS NOT NULL AND url <> ''`

// DeniedEndpoints lists the URLs that already answered 401 or 403, so the bypass tools can be aimed
// at the things that actually denied something.
//
// The same idea as the exposed git handover: the framework knows which endpoints refused it, and
// making the operator rediscover that by hand would be pointless. Nothing is selected automatically,
// and anything else on the target remains pickable through the ordinary endpoint list, because an
// endpoint that returned 200 to us may still deny somebody else.
//
// 404 and 405 are offered separately from 401 and 403. A 404 can hide a resource that exists, which
// is a real class, but it is also what every directory brute force emits by the thousand.
func DeniedEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var unions []string
	for _, source := range deniedStatusSources {
		unions = append(unions, fmt.Sprintf(
			`SELECT url, %s AS status_code, '%s' AS source FROM %s
			 WHERE scope_target_id = $1 AND url IS NOT NULL AND url <> ''
			   AND %s IN (401, 403, 404, 405, 407) %s`,
			source.StatusColumn, source.Name, source.Table, source.StatusColumn, source.Where))
	}
	// The JSONB-array source cannot filter inside its own SELECT, because the status code only exists
	// after the array is expanded, so it is filtered in the outer query below.
	unions = append(unions, consolidatedDeniedUnion)

	rows, err := dbPool.Query(r.Context(), `WITH found AS (`+strings.Join(unions, " UNION ALL ")+`)
		SELECT url, MIN(status_code), ARRAY_AGG(DISTINCT source ORDER BY source)
		FROM found WHERE status_code IN (401, 403, 404, 405, 407)
		GROUP BY url ORDER BY MIN(status_code), url`, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	scopeHost := bypassScopeHost(r.Context(), scopeTargetID)

	type denied struct {
		URL        string   `json:"url"`
		StatusCode int      `json:"status_code"`
		Sources    []string `json:"sources"`
		InScope    bool     `json:"in_scope"`
		Primary    bool     `json:"primary"`
	}

	out := []denied{}
	counts := map[int]int{}
	for rows.Next() {
		var d denied
		if err := rows.Scan(&d.URL, &d.StatusCode, &d.Sources); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d.InScope = bypassHostInScope(d.URL, scopeHost)
		// 401 and 403 are an access control decision on a resource that exists. The others are
		// offered, but they are not what this section is for.
		d.Primary = d.StatusCode == 401 || d.StatusCode == 403 || d.StatusCode == 407
		out = append(out, d)
		counts[d.StatusCode]++
	}

	// In scope first, then the real denials, then by status. A third party's 403 is not this
	// operator's business, and a 404 is not what they came here for.
	sort.Slice(out, func(i, j int) bool {
		if out[i].InScope != out[j].InScope {
			return out[i].InScope
		}
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		if out[i].StatusCode != out[j].StatusCode {
			return out[i].StatusCode < out[j].StatusCode
		}
		return out[i].URL < out[j].URL
	})

	statuses := make([]int, 0, len(counts))
	for code := range counts {
		statuses = append(statuses, code)
	}
	sort.Ints(statuses)
	summary := make([]map[string]int, 0, len(statuses))
	for _, code := range statuses {
		summary = append(summary, map[string]int{"status_code": code, "count": counts[code]})
	}

	limit := 400
	truncated := false
	if len(out) > limit {
		out, truncated = out[:limit], true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"denied":     out,
		"count":      len(out),
		"by_status":  summary,
		"truncated":  truncated,
		"scope_host": scopeHost,
	})
}
