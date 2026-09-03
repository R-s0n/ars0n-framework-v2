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

// Configuration for the two archive tools in the URL workflow's Archive & JavaScript Mining row.
//
// Neither tool touches the target: both ask public archives what they already hold. That is why
// they get a host SELECTION rather than a rate limit. The interesting question for an archive tool
// is not how fast to go, it is which hosts to ask about, and until now the answer was hardcoded to
// exactly one: the scope target's own.
//
// That single host was leaving most of the estate unqueried, and the two tools lost different
// halves of it. archivefetch asks the CDX API for `*.<host>/*`, so it covers subdomains of the
// target and nothing else. gau is not passed --subs at all, so it covers the exact host and nothing
// else. Neither has ever covered an adjacent host on a different registrable domain, which on a
// single-page app is usually where the API lives: in one recording the target host served static
// assets while every meaningful call went to a host on a different domain entirely.
//
// Fields here map to flags the tools actually accept. archivefetch takes exactly one (-no-subs);
// gau's are read from its --help. Nothing is offered that no command builder can deliver, because a
// setting the operator can toggle and the tool can never receive reads as a feature that works.

// ArchiveHostMode decides where the host list comes from.
//
// A string rather than a nullable slice on purpose. "No hosts chosen" and "the operator chose none"
// are different instructions and a bare []string cannot tell them apart: an empty array would mean
// scan everything on one reading and scan nothing on the other, and both are defensible enough that
// the ambiguity would eventually be resolved wrongly and silently.
const (
	ArchiveHostModeDefault = "default" // the direct host plus every in-scope adjacent host, resolved at run time
	ArchiveHostModeCustom  = "custom"  // exactly the hosts in SelectedHosts
)

type WaybackURLsURLConfig struct {
	HostMode      string   `json:"hostMode"`
	SelectedHosts []string `json:"selectedHosts"`

	// IncludeSubdomains maps to archivefetch's only flag, inverted: false passes -no-subs.
	// It is a REQUEST, not a guarantee. A host carrying a non-default port always queries without
	// the wildcard whatever this says, because `*.host:8080/*` is not a pattern the CDX API can
	// match: the wildcard belongs in front of a hostname, not a host:port authority.
	IncludeSubdomains bool `json:"includeSubdomains"`

	// TimeoutMinutes bounds each host's query, not the run. A run over twelve hosts is allowed to
	// take twelve times this.
	TimeoutMinutes int `json:"timeoutMinutes"`
}

type GAUURLConfig struct {
	HostMode      string   `json:"hostMode"`
	SelectedHosts []string `json:"selectedHosts"`

	// Providers defaults to all four. Excluding `wayback` on the premise that the waybackurls scan
	// covers it cost 85% of the archive surface when measured (29 URLs without it, 187 with), and
	// duplicates are folded by consolidation anyway.
	Providers []string `json:"providers"`

	IncludeSubdomains bool     `json:"includeSubdomains"` // --subs
	Threads           int      `json:"threads"`           // --threads
	TimeoutSeconds    int      `json:"timeoutSeconds"`    // --timeout, gau's own HTTP client timeout
	Retries           int      `json:"retries"`           // --retries
	Blacklist         []string `json:"blacklist"`         // --blacklist, file extensions to skip
	FromDate          string   `json:"fromDate"`          // --from, YYYYMM
	ToDate            string   `json:"toDate"`            // --to, YYYYMM

	// TimeoutMinutes bounds each host's query from the outside, the same way it does for
	// archivefetch. gau's own --timeout applies per HTTP request, not to the process.
	TimeoutMinutes int `json:"timeoutMinutes"`
}

// GAUProviders is every provider gau accepts, and the default set.
var GAUProviders = []string{"wayback", "commoncrawl", "otx", "urlscan"}

func DefaultWaybackURLsURLConfig() WaybackURLsURLConfig {
	return WaybackURLsURLConfig{
		HostMode:          ArchiveHostModeDefault,
		IncludeSubdomains: true,
		TimeoutMinutes:    10,
	}
}

func DefaultGAUURLConfig() GAUURLConfig {
	return GAUURLConfig{
		HostMode: ArchiveHostModeDefault,
		// Matches what the hardcoded command sent, so an operator who never opens the modal gets
		// exactly the behaviour they had before.
		Providers:      append([]string{}, GAUProviders...),
		Threads:        1,
		TimeoutSeconds: 45,
		Retries:        0,
		TimeoutMinutes: 10,
	}
}

func LoadWaybackURLsURLConfig(scopeTargetID string) WaybackURLsURLConfig {
	cfg := DefaultWaybackURLsURLConfig()
	loadCrawlerConfig("waybackurls_url_configs", scopeTargetID, &cfg)
	return normaliseWaybackConfig(cfg)
}

func LoadGAUURLConfig(scopeTargetID string) GAUURLConfig {
	cfg := DefaultGAUURLConfig()
	loadCrawlerConfig("gau_url_configs", scopeTargetID, &cfg)
	return normaliseGAUConfig(cfg)
}

// normaliseWaybackConfig repairs a stored config rather than trusting it. A row written before a
// field existed, or by an MCP caller, can carry a mode this code does not know.
func normaliseWaybackConfig(cfg WaybackURLsURLConfig) WaybackURLsURLConfig {
	if cfg.HostMode != ArchiveHostModeCustom {
		cfg.HostMode = ArchiveHostModeDefault
	}
	cfg.SelectedHosts = normaliseHostList(cfg.SelectedHosts)
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 10
	}
	return cfg
}

func normaliseGAUConfig(cfg GAUURLConfig) GAUURLConfig {
	if cfg.HostMode != ArchiveHostModeCustom {
		cfg.HostMode = ArchiveHostModeDefault
	}
	cfg.SelectedHosts = normaliseHostList(cfg.SelectedHosts)

	// An unknown provider is dropped rather than passed through: gau exits on one, which would turn
	// a typo into a whole run failing with a message about provider parsing.
	known := map[string]bool{}
	for _, p := range GAUProviders {
		known[p] = true
	}
	var providers []string
	seen := map[string]bool{}
	for _, p := range cfg.Providers {
		p = strings.ToLower(strings.TrimSpace(p))
		if known[p] && !seen[p] {
			providers = append(providers, p)
			seen[p] = true
		}
	}
	if len(providers) == 0 {
		providers = append([]string{}, GAUProviders...)
	}
	cfg.Providers = providers

	if cfg.Threads <= 0 {
		cfg.Threads = 1
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 45
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 10
	}
	var blacklist []string
	for _, b := range cfg.Blacklist {
		if b = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(b), ".")); b != "" {
			blacklist = append(blacklist, b)
		}
	}
	cfg.Blacklist = blacklist
	return cfg
}

func normaliseHostList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range in {
		h = archiveHostKey(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// archiveHostKey reduces anything the operator or an MCP caller might send (a bare host, a URL, a
// host:port) to the lowercase authority used as the identity of an archive target everywhere here.
func archiveHostKey(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		// url.Host, not url.Hostname(): the port is part of the archive identity. A CDX index keys on
		// the whole authority, so dropping :8443 here would ask about port 443 and hand back another
		// service's history under this host's name.
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return ""
		}
		return strings.ToLower(parsed.Host)
	}
	return strings.Trim(raw, "/")
}

// ---------------------------------------------------------------- host resolution

// ArchiveTarget is one host an archive run will be asked about, as the picker and the run both see it.
type ArchiveTarget struct {
	Host     string `json:"host"`
	URL      string `json:"url"`
	IsDirect bool   `json:"is_direct"`
	Selected bool   `json:"selected"`

	// Requests is what the manual crawl saw, so the picker can rank hosts by how central they were.
	Requests int `json:"requests"`

	// Skip explains why a selected host will not actually be queried. Populated at run time only,
	// by planArchiveQuery: an IP literal has no stable archive identity and is refused outright.
	Skip string `json:"skip,omitempty"`
}

// ResolveArchiveTargets returns every host this target's archive tools could be asked about, with
// the ones the config selects flagged.
//
// Candidates are the scope target's own host plus the adjacent hosts the manual crawl observed and
// the operator left in scope. Out-of-scope hosts are excluded entirely rather than offered and
// unticked: an archive query does not touch the host, but the scope boundary is the operator's
// decision about what this engagement covers, and quietly widening it for one tool because that
// tool happens to be passive is how a boundary stops meaning anything.
//
// The direct host is always present and always first, even when no crawl has ever run, so a target
// with no recording still scans the thing it is named after.
func ResolveArchiveTargets(scopeTargetID, hostMode string, selected []string) ([]ArchiveTarget, error) {
	primary := strings.ToLower(scopeTargetHost(scopeTargetID))

	hosts, err := loadCrawlHosts(scopeTargetID)
	if err != nil {
		// A crawl that cannot be read must not take the direct host down with it: the tools worked
		// on one host before this feature existed and they still have to.
		hosts = nil
	}

	var out []ArchiveTarget
	seen := map[string]bool{}
	add := func(host, scheme string, isDirect bool, requests int) {
		host = archiveHostKey(host)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		if scheme == "" {
			scheme = "https"
		}
		out = append(out, ArchiveTarget{
			Host:     host,
			URL:      scheme + "://" + host,
			IsDirect: isDirect,
			Requests: requests,
		})
	}

	if primary != "" {
		scheme := "https"
		for _, h := range hosts {
			if strings.EqualFold(h.Host, primary) && h.Scheme != "" {
				scheme = h.Scheme
			}
		}
		add(primary, scheme, true, 0)
	}
	for _, h := range hosts {
		if !h.InScope && !h.WithinTargetDomain {
			continue
		}
		add(h.Host, h.Scheme, strings.EqualFold(h.Host, primary), h.Requests)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no host to query: this target has no readable host and no in-scope crawl hosts")
	}

	// Direct first, then busiest. The run follows this order, so the host the operator cares about
	// most is queried before a long tail of adjacent ones can exhaust a timeout.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsDirect != out[j].IsDirect {
			return out[i].IsDirect
		}
		return out[i].Requests > out[j].Requests
	})

	if hostMode != ArchiveHostModeCustom {
		for i := range out {
			out[i].Selected = true
		}
		return out, nil
	}

	want := map[string]bool{}
	for _, h := range normaliseHostList(selected) {
		want[h] = true
	}
	for i := range out {
		out[i].Selected = want[out[i].Host]
	}
	return out, nil
}

// SelectedArchiveTargets narrows a resolved list to what the run will actually query.
func SelectedArchiveTargets(all []ArchiveTarget) []ArchiveTarget {
	var out []ArchiveTarget
	for _, t := range all {
		if t.Selected {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------- handlers

// GetArchiveHostCandidates backs the host picker in the Configure modal, for both tools.
func GetArchiveHostCandidates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	tool := strings.ToLower(mux.Vars(r)["tool"])

	var mode string
	var selected []string
	switch tool {
	case "waybackurls":
		cfg := LoadWaybackURLsURLConfig(scopeTargetID)
		mode, selected = cfg.HostMode, cfg.SelectedHosts
	case "gau":
		cfg := LoadGAUURLConfig(scopeTargetID)
		mode, selected = cfg.HostMode, cfg.SelectedHosts
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown_tool", "tool must be waybackurls or gau")
		return
	}

	targets, err := ResolveArchiveTargets(scopeTargetID, mode, selected)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "no_hosts", err.Error())
		return
	}

	adjacent := 0
	for _, t := range targets {
		if !t.IsDirect {
			adjacent++
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tool":           tool,
		"host_mode":      mode,
		"targets":        targets,
		"total":          len(targets),
		"adjacent_count": adjacent,
		"selected_count": len(SelectedArchiveTargets(targets)),
	})
}

func GetWaybackURLsURLConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoadWaybackURLsURLConfig(mux.Vars(r)["scope_target_id"]))
}

func GetGAUURLConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoadGAUURLConfig(mux.Vars(r)["scope_target_id"]))
}

func SaveWaybackURLsURLConfig(w http.ResponseWriter, r *http.Request) {
	cfg := LoadWaybackURLsURLConfig(mux.Vars(r)["scope_target_id"])
	saveCrawlerConfig(w, r, "waybackurls_url_configs", &cfg)
}

func SaveGAUURLConfig(w http.ResponseWriter, r *http.Request) {
	cfg := LoadGAUURLConfig(mux.Vars(r)["scope_target_id"])
	saveCrawlerConfig(w, r, "gau_url_configs", &cfg)
}

// ---------------------------------------------------------------- run bookkeeping

// ArchiveTargetResult records what one host's query did, so a run over twelve hosts can be read
// afterwards rather than collapsing into a single number.
//
// Partial failure is the normal case here, not the exception: an archive holding nothing for one
// adjacent host says nothing about the other eleven, and a 429 on one query is not a reason to
// throw away the ten that worked.
type ArchiveTargetResult struct {
	Host     string `json:"host"`
	IsDirect bool   `json:"is_direct"`
	Status   string `json:"status"` // success | error | skipped
	URLs     int    `json:"urls"`
	Command  string `json:"command,omitempty"`
	Error    string `json:"error,omitempty"`
	Elapsed  string `json:"elapsed,omitempty"`
}

// summariseArchiveRun turns per-host outcomes into the one line the tool card shows.
//
// It names failures explicitly. The alternative, reporting only the endpoint count, is how a run
// where nine of twelve hosts were refused reads as a success.
func summariseArchiveRun(results []ArchiveTargetResult, direct, adjacent int) string {
	ok, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "success":
			ok++
		case "skipped":
			skipped++
		default:
			failed++
		}
	}
	summary := fmt.Sprintf("Found %d direct and %d adjacent endpoints across %d of %d hosts",
		direct, adjacent, ok, len(results))
	if failed > 0 {
		summary += fmt.Sprintf(", %d failed", failed)
	}
	if skipped > 0 {
		summary += fmt.Sprintf(", %d skipped", skipped)
	}
	return summary
}

// storeArchiveTargetResults writes the per-host breakdown onto the scan row.
func storeArchiveTargetResults(table, scanID string, results []ArchiveTargetResult) {
	payload, err := json.Marshal(results)
	if err != nil {
		return
	}
	_, _ = dbPool.Exec(context.Background(),
		fmt.Sprintf(`UPDATE %s SET target_results = $1 WHERE scan_id = $2`, table),
		string(payload), scanID)
}
