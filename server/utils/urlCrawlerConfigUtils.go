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
// These exist so the Target Behaviour Probe's measurements can reach the tools that have to obey
// them. Before this file, the probe's katana and gospider recommendations were written to
// probe_tool_tuning, which nothing read: the operator was told a rate had been applied while
// katana carried on at `-p 15` with no rate limit at all. Every field the probe can set is read
// here at launch time, in the same request that builds the command line.
//
// Defaults are the previously hardcoded flags, so an operator who never opens a config modal gets
// exactly the behaviour they had before.

type KatanaURLConfig struct {
	BaseURL           string    `json:"baseUrl"`
	RateLimit         int       `json:"rateLimit"`
	Concurrency       int       `json:"concurrency"`
	Parallelism       int       `json:"parallelism"`
	Depth             int       `json:"depth"`
	Timeout           int       `json:"timeout"`
	Retry             int       `json:"retry"`
	CrawlDurationS    int       `json:"crawlDurationSeconds"`
	MaxResponseSize   int       `json:"maxResponseSize"`
	JSCrawl           bool      `json:"jsCrawl"`
	JSLuice           bool      `json:"jsluice"`
	KnownFiles        string    `json:"knownFiles"`
	FieldScope        string    `json:"fieldScope"`
	ExtensionFilter   string    `json:"extensionFilter"`
	IgnoreQueryParams bool      `json:"ignoreQueryParams"`
	AutoFormFill      bool      `json:"automaticFormFill"`
	Headless          bool      `json:"headless"`
	XHRExtraction     bool      `json:"xhrExtraction"`
	CacheBust         bool      `json:"cache_bust"`
	ReuseSession      bool      `json:"reuse_session"`
	Proxy             string    `json:"proxy"`
	Headers           []NameVal `json:"headers"`
	UseFFUFAuth       bool      `json:"useFFUFAuth"`
}

type GoSpiderURLConfig struct {
	BaseURL            string    `json:"baseUrl"`
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
	CacheBust          bool      `json:"cache_bust"`
	ReuseSession       bool      `json:"reuse_session"`
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
		RateLimit: 0, Concurrency: 10, Parallelism: 15, Depth: 5, Timeout: 10, Retry: 1,
		CrawlDurationS: 0, MaxResponseSize: 4194304,
		JSCrawl: true, JSLuice: false, KnownFiles: "all", FieldScope: "rdn",
		UseFFUFAuth: true,
	}
}

func DefaultGoSpiderURLConfig() GoSpiderURLConfig {
	return GoSpiderURLConfig{
		Concurrent: 10, Threads: 2, Depth: 5, DelayS: 0, RandomDelayS: 0, Timeout: 10,
		Sitemap: true, Robots: true, OtherSource: true, JS: true, NoRedirect: true,
		UseFFUFAuth: true,
	}
}

func DefaultLinkFinderURLConfig() LinkFinderURLConfig {
	return LinkFinderURLConfig{
		// `both` by default because the old behaviour (target only) is what made this tool look
		// useless, and scanning discovered bundles is the thing it was built to do.
		InputSource: "both", DomainMode: true, MaxJSFiles: 50, RequestDelayMS: 0,
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
	if err := json.Unmarshal(raw, out); err != nil {
		log.Printf("[CRAWLER-CONFIG] Ignoring unreadable %s for %s: %v", table, scopeTargetID, err)
	}
}

func LoadKatanaURLConfig(scopeTargetID string) KatanaURLConfig {
	cfg := DefaultKatanaURLConfig()
	loadCrawlerConfig("katana_url_configs", scopeTargetID, &cfg)
	return cfg
}

func LoadGoSpiderURLConfig(scopeTargetID string) GoSpiderURLConfig {
	cfg := DefaultGoSpiderURLConfig()
	loadCrawlerConfig("gospider_url_configs", scopeTargetID, &cfg)
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
	var raw []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&raw); err != nil {
		return nil, ""
	}
	var cfg struct {
		Headers []NameVal `json:"headers"`
		Cookies string    `json:"cookies"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, ""
	}
	out := make([]NameVal, 0, len(cfg.Headers))
	for _, h := range cfg.Headers {
		if strings.TrimSpace(h.Name) != "" {
			out = append(out, h)
		}
	}
	return out, cfg.Cookies
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
