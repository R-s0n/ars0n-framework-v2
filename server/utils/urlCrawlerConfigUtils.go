package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Configuration for the three URL-workflow crawlers that touch the live target.
//
// These exist so the Target Behaviour Probe's measurements have somewhere to land. Before this
// file, katana and gospider had no config table at all, so a measured rate had nowhere to go: the
// operator was told a rate had been applied while katana carried on at `-p 15` with no rate limit.
// Every field the probe recommends is settable here and read at launch time, in the same request
// that builds the command line. The probe itself only reports; the operator sets the value.
//
// Defaults are the previously hardcoded flags, so an operator who never opens a config modal gets
// exactly the behaviour they had before.

type KatanaURLConfig struct {
	BaseURL string `json:"baseUrl"`

	// Which hosts to crawl. Same meaning as the archive tools: "default" is the direct host plus
	// every in-scope adjacent host, resolved at run time. Unlike the archive tools these send real
	// requests, so ScanScope is consulted again per host at launch and credentials are resolved per
	// host rather than shared.
	HostMode      string   `json:"hostMode"`
	SelectedHosts []string `json:"selectedHosts"`
	// Bound on EACH host's crawl. Was a hardcoded 20 minutes; a run over six hosts may take six
	// times this because hosts are crawled one at a time.
	TimeoutMinutes int `json:"timeoutMinutes"`

	RateLimit         int    `json:"rateLimit"`
	Concurrency       int    `json:"concurrency"`
	Parallelism       int    `json:"parallelism"`
	Depth             int    `json:"depth"`
	Timeout           int    `json:"timeout"`
	Retry             int    `json:"retry"`
	CrawlDurationS    int    `json:"crawlDurationSeconds"`
	MaxResponseSize   int    `json:"maxResponseSize"`
	JSCrawl           bool   `json:"jsCrawl"`
	JSLuice           bool   `json:"jsluice"`
	KnownFiles        string `json:"knownFiles"`
	FieldScope        string `json:"fieldScope"`
	ExtensionFilter   string `json:"extensionFilter"`
	IgnoreQueryParams bool   `json:"ignoreQueryParams"`
	AutoFormFill      bool   `json:"automaticFormFill"`
	Headless          bool   `json:"headless"`
	XHRExtraction     bool   `json:"xhrExtraction"`
	// cache_bust and reuse_session are deliberately absent. Neither katana nor gospider has a
	// flag for either, so the fields were stored, shown as switches in the Configure modal, and
	// recommended by the Target Behaviour Probe, while no command builder ever read them. A
	// setting the operator can toggle and the tool can never receive is worse than a missing
	// feature, because it reads as one that works.
	Proxy       string    `json:"proxy"`
	Headers     []NameVal `json:"headers"`
	UseFFUFAuth bool      `json:"useFFUFAuth"`
}

type GoSpiderURLConfig struct {
	BaseURL string `json:"baseUrl"`

	// See KatanaURLConfig for what these mean and why the crawlers re-check scope per host.
	HostMode       string   `json:"hostMode"`
	SelectedHosts  []string `json:"selectedHosts"`
	TimeoutMinutes int      `json:"timeoutMinutes"`

	Concurrent         int       `json:"concurrent"`
	Threads            int       `json:"threads"`
	Depth              int       `json:"depth"`
	DelayS             int       `json:"delay"`
	RandomDelayS       int       `json:"randomDelay"`
	Timeout            int       `json:"timeout"`
	Sitemap            bool      `json:"sitemap"`
	Robots             bool      `json:"robots"`
	OtherSource        bool      `json:"otherSource"`
	IncludeSubs        bool      `json:"includeSubs"`
	IncludeOtherSource bool      `json:"includeOtherSource"`
	JS                 bool      `json:"js"`
	NoRedirect         bool      `json:"noRedirect"`
	Blacklist          string    `json:"blacklist"`
	Whitelist          string    `json:"whitelist"`
	WhitelistDomain    string    `json:"whitelistDomain"`
	UserAgent          string    `json:"userAgent"`
	Cookie             string    `json:"cookie"`
	Proxy              string    `json:"proxy"`
	Headers            []NameVal `json:"headers"`
	UseFFUFAuth        bool      `json:"useFFUFAuth"`
	// cache_bust and reuse_session are deliberately absent. Neither katana nor gospider has a
	// flag for either, so the fields were stored, shown as switches in the Configure modal, and
	// recommended by the Target Behaviour Probe, while no command builder ever read them. A
	// setting the operator can toggle and the tool can never receive is worse than a missing
	// feature, because it reads as one that works.
}

// LinkFinderURLConfig carries the setting that actually matters for this tool.
//
// LinkFinder is a regex over a body of text, nothing more. Pointed at a target URL with no -d it
// fetches that one page and scans it, which on any modern SPA means scanning an empty shell and
// never opening a single bundle. InputSource is what fixes that: `discovered_js` feeds it the .js
// URLs the crawlers and the manual crawl already found.
type LinkFinderURLConfig struct {
	BaseURL         string    `json:"baseUrl"`
	InputSource     string    `json:"inputSource"` // target | discovered_js | both
	DomainMode      bool      `json:"domainMode"`  // -d, only meaningful for the target arm
	MaxJSFiles      int       `json:"maxJsFiles"`
	RequestDelayMS  int       `json:"requestDelayMs"`
	Timeout         int       `json:"timeout"`
	RegexFilter     string    `json:"regexFilter"`
	Cookies         string    `json:"cookies"`
	UseFFUFAuth     bool      `json:"useFFUFAuth"`
	IncludeRelative bool      `json:"includeRelative"`
	Headers         []NameVal `json:"headers"`
}

type NameVal struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func DefaultKatanaURLConfig() KatanaURLConfig {
	return KatanaURLConfig{
		HostMode: ArchiveHostModeDefault, TimeoutMinutes: 20,
		RateLimit: 0, Concurrency: 10, Parallelism: 15, Depth: 5, Timeout: 10, Retry: 1,
		CrawlDurationS: 0, MaxResponseSize: 4194304,
		JSCrawl: true, JSLuice: false, KnownFiles: "all", FieldScope: "rdn",
		UseFFUFAuth: true,
	}
}

func DefaultGoSpiderURLConfig() GoSpiderURLConfig {
	return GoSpiderURLConfig{
		HostMode: ArchiveHostModeDefault, TimeoutMinutes: 20,
		Concurrent: 10, Threads: 2, Depth: 5, DelayS: 0, RandomDelayS: 0, Timeout: 10,
		Sitemap: true, Robots: true, OtherSource: true, JS: true, NoRedirect: true,
		UseFFUFAuth: true,
	}
}

func DefaultLinkFinderURLConfig() LinkFinderURLConfig {
	return LinkFinderURLConfig{
		// `both` by default because the old behaviour (target only) is what made this tool look
		// useless, and scanning discovered bundles is the thing it was built to do.
		// MaxJSFiles 0 means NO cap. It was 50, which silently skipped 40 of 90 bundles on a
		// real target and reported nothing about it: the scan summary counts endpoints found,
		// not files read, so a truncated run looks identical to a complete one. A tool whose job
		// is to read the JavaScript that was already discovered should read all of it by
		// default; an operator who wants a ceiling sets one.
		InputSource: "both", DomainMode: true, MaxJSFiles: 0, RequestDelayMS: 0,
		Timeout: 10, UseFFUFAuth: true, IncludeRelative: true,
	}
}

// ---------------------------------------------------------------- load

func loadCrawlerConfig(table, scopeTargetID string, out interface{}) {
	var raw []byte
	err := dbPool.QueryRow(context.Background(),
		fmt.Sprintf(`SELECT config FROM %s WHERE scope_target_id = $1`, table),
		scopeTargetID).Scan(&raw)
	if err != nil || len(raw) == 0 {
		return // the caller keeps its defaults
	}
	// Unmarshalling onto a pre-populated struct leaves any field the operator never set at its
	// default, so adding a knob later does not silently zero it for existing targets.
	//
	// Tolerant, because these structs are almost entirely int fields and a fractional number in any
	// one of them makes the strict decoder abandon that field while reporting nothing the operator
	// will see. A rate limit that quietly reverts to its default is the failure this whole change
	// was about.
	if err := UnmarshalConfigTolerant(raw, out); err != nil {
		log.Printf("[CRAWLER-CONFIG] Ignoring unreadable %s for %s: %v", table, scopeTargetID, err)
	}
}

func LoadKatanaURLConfig(scopeTargetID string) KatanaURLConfig {
	cfg := DefaultKatanaURLConfig()
	loadCrawlerConfig("katana_url_configs", scopeTargetID, &cfg)
	if cfg.HostMode != ArchiveHostModeCustom {
		cfg.HostMode = ArchiveHostModeDefault
	}
	cfg.SelectedHosts = normaliseHostList(cfg.SelectedHosts)
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 20
	}
	return cfg
}

func LoadGoSpiderURLConfig(scopeTargetID string) GoSpiderURLConfig {
	cfg := DefaultGoSpiderURLConfig()
	loadCrawlerConfig("gospider_url_configs", scopeTargetID, &cfg)
	if cfg.HostMode != ArchiveHostModeCustom {
		cfg.HostMode = ArchiveHostModeDefault
	}
	cfg.SelectedHosts = normaliseHostList(cfg.SelectedHosts)
	if cfg.TimeoutMinutes <= 0 {
		cfg.TimeoutMinutes = 20
	}
	return cfg
}

func LoadLinkFinderURLConfig(scopeTargetID string) LinkFinderURLConfig {
	cfg := DefaultLinkFinderURLConfig()
	loadCrawlerConfig("linkfinder_url_configs", scopeTargetID, &cfg)
	return cfg
}

// ffufAuthMaterial returns the target's saved FFUF headers and cookie string, so a crawler can see
// the application the way the authenticated scanners do rather than fingerprinting a login wall.
func ffufAuthMaterial(scopeTargetID string) ([]NameVal, string) {
	// A missing or unreadable ffuf_configs row is NOT a reason to stop. It used to return here, which
	// meant the Session Manager overlay below was never reached and a target with a live declared
	// token crawled the login wall anyway. That row is also no longer written by the app at all now
	// that the FFUF config modal has been replaced by the fuzz composer, so absent is the normal case
	// rather than the exception.
	var cfg struct {
		Headers []NameVal `json:"headers"`
		Cookies string    `json:"cookies"`
	}
	var raw []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	out := make([]NameVal, 0, len(cfg.Headers))
	for _, h := range cfg.Headers {
		if strings.TrimSpace(h.Name) != "" {
			out = append(out, h)
		}
	}
	cookies := cfg.Cookies

	// Overlay the Session Manager, which the crawlers could not see at all until now: useFFUFAuth
	// read this table and nothing else, so an operator with a live declared session watched Katana,
	// GoSpider and LinkFinder crawl the login wall while the UI showed the session active. The
	// declared token wins over whatever was typed into the FFUF config, matching the rule the
	// endpoint scan already follows.
	//
	// Scoped to the target's own host: the crawlers are pointed at one origin, and a credential must
	// not be handed to a third-party host that happens to appear in the crawl.
	if _, targetHost, _ := ScopeTargetBase(scopeTargetID); targetHost != "" {
		auth := &ScopedAuthContext{
			byHost:   map[string]*ScopedAuthMaterial{},
			byDomain: map[string]*ScopedAuthMaterial{},
		}
		auth.ApplySessionTokens(scopeTargetID)
		if material, _ := auth.For(strings.ToLower(targetHost)); material != nil {
			for name, value := range material.Headers {
				replaced := false
				for i := range out {
					if strings.EqualFold(out[i].Name, name) {
						out[i].Value = value
						replaced = true
						break
					}
				}
				if !replaced {
					out = append(out, NameVal{Name: name, Value: value})
				}
			}
			if material.Cookies != "" {
				cookies = material.Cookies
			}
			// A query-borne credential cannot be expressed as a header, and none of the three
			// crawlers takes one, so it is reported rather than silently dropped.
			if len(material.QueryParams) > 0 {
				log.Printf("[CRAWLER-CONFIG] %s: session token(s) ride in the query string and cannot "+
					"be given to a crawler; those endpoints will be crawled unauthenticated", scopeTargetID)
			}
		}
	}

	return out, cookies
}

// ---------------------------------------------------------------- handlers

func GetKatanaURLConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, LoadKatanaURLConfig(mux.Vars(r)["scope_target_id"]))
}

func SaveKatanaURLConfig(w http.ResponseWriter, r *http.Request) {
	cfg := DefaultKatanaURLConfig()
	saveCrawlerConfig(w, r, "katana_url_configs", &cfg)
}

func GetGoSpiderURLConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, LoadGoSpiderURLConfig(mux.Vars(r)["scope_target_id"]))
}

func SaveGoSpiderURLConfig(w http.ResponseWriter, r *http.Request) {
	cfg := DefaultGoSpiderURLConfig()
	saveCrawlerConfig(w, r, "gospider_url_configs", &cfg)
}

func GetLinkFinderURLConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, LoadLinkFinderURLConfig(mux.Vars(r)["scope_target_id"]))
}

func SaveLinkFinderURLConfig(w http.ResponseWriter, r *http.Request) {
	cfg := DefaultLinkFinderURLConfig()
	saveCrawlerConfig(w, r, "linkfinder_url_configs", &cfg)
}

func saveCrawlerConfig(w http.ResponseWriter, r *http.Request, table string, cfg interface{}) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if err := json.NewDecoder(r.Body).Decode(cfg); err != nil {
		http.Error(w, "Invalid config JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := dbPool.Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (scope_target_id, config) VALUES ($1, $2)
		ON CONFLICT (scope_target_id) DO UPDATE SET config = $2, updated_at = NOW()`, table),
		scopeTargetID, payload); err != nil {
		log.Printf("[CRAWLER-CONFIG] Failed to save %s: %v", table, err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "success"})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
