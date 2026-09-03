package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// WHAT THE APPLICATION ADVERTISES, AGAINST WHAT WE ACTUALLY TESTED.
//
// A vector list inherits every gap of the crawl that produced it, and it inherits them silently. A
// feature nobody exercised produces no vector, so every scanner reports clean on it, and the report
// is accurate and useless.
//
// THE CASE THIS EXISTS FOR. On the target this framework was developed against, the newsletter
// subscribe widget is a <div> carrying data-action and data-method, driven by an XHR, rather than a
// <form>. A crawl records requests, and no request was ever made, so it produced zero rows, so it
// became no vector, so every section reported clean on it. It held a real cross-site scripting
// vulnerability. Nothing anywhere said the feature existed and had never been touched.
//
// The fix is to compare two different things that were previously never compared:
//   - WHAT WAS REQUESTED: attack_vectors, built from traffic the crawl observed.
//   - WHAT THE MARKUP ADVERTISES: forms, data-action widgets and fetch/XHR targets read out of the
//     response bodies the crawl stored.
//
// These are kept as separate questions on purpose. Widening the vector source to read response bodies
// would blur "we saw this request happen" into "we saw something that could make this request", and
// the first of those is the one an operator relies on.
//
// A HONEST LIMIT, STATED UP FRONT. This can only read bodies the crawl retained. Deep capture is off
// by default and bodies are capped at 128 KB, so a feature defined below the cap in a large bundle is
// invisible here too. An empty result means nothing was found in what was stored, not that the
// application has no untested features.

// advertisedFeature is one thing the application's own markup or scripts say it can do.
type advertisedFeature struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Source    string `json:"source"`
	FoundOn   string `json:"found_on"`
	Tested    bool   `json:"tested"`
	Why       string `json:"why,omitempty"`
	RawTarget string `json:"raw_target"`
}

var (
	// A widget that posts without being a form. This is the exact shape the subscribe widget uses and
	// the reason it was never captured, so it is the first thing this looks for.
	reDataAction = regexp.MustCompile(`(?i)data-action\s*=\s*["']([^"']+)["']`)
	reDataMethod = regexp.MustCompile(`(?i)data-method\s*=\s*["']([^"']+)["']`)
	// XMLHttpRequest, where the verb and the URL are the first two arguments of the same call, so both
	// are captured from ONE match. The first version of this searched the whole file for a verb and
	// applied it to every target in that file: correct for a single-purpose script, and wrong for any
	// bundle, where the first .open in the file decided the verb for endpoints it had nothing to do
	// with.
	reXHROpen = regexp.MustCompile(`(?i)\.open\s*\(\s*["']([A-Za-z]+)["']\s*,\s*["']([^"']+)["']`)
	// fetch(url, {... method: "POST" ...}). The options object is optional and the method may or may
	// not be in it, so the verb is captured separately and only from the SAME call's options, within a
	// bounded window so it cannot reach into the next statement.
	reFetchCall = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']([^)]{0,200})`)
	reMethodOpt = regexp.MustCompile(`(?i)method\s*:\s*["']([A-Za-z]+)["']`)
)

// GetFeatureCompleteness answers GET /attack-vectors/{scope_target_id}/completeness.
func GetFeatureCompleteness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	features := advertisedFeaturesFor(ctx, scopeTargetID)
	byPath, byPathMethod := testedPathsFor(ctx, scopeTargetID)

	untested := []advertisedFeature{}
	wrongVerb := []advertisedFeature{}
	for i := range features {
		path := strings.ToLower(features[i].Path)
		switch {
		case byPathMethod[strings.ToUpper(features[i].Method)+" "+path]:
			features[i].Tested = true
		case byPath[path]:
			// THE CASE THAT PROVED PATH-ONLY MATCHING WRONG. /catalog/subscribe HAS a vector, as
			// GET with a query insertion point, because LinkFinder read the path out of a script.
			// The feature is a POST carrying a JSON body. Every tool aimed at that vector sends a
			// query string to an endpoint that reads a body, so the path looks covered, the section
			// reports clean, and nothing has ever been sent to the thing that is actually there.
			features[i].Why = "This path has attack vectors, but none for " + features[i].Method +
				". A vector with the wrong verb sends input somewhere the endpoint does not read " +
				"it, so this reads as covered while nothing has ever exercised the real feature. " +
				"This is exactly how a vulnerable endpoint was missed on the reference target."
			wrongVerb = append(wrongVerb, features[i])
		default:
			features[i].Why = "The markup or a script says this endpoint exists, and no attack " +
				"vector covers it at all. Nothing was ever sent here, so every section will report " +
				"clean on it."
			untested = append(untested, features[i])
		}
	}

	json.NewEncoder(w).Encode(map[string]any{
		"advertised":      len(features),
		"untested":        untested,
		"wrong_verb_only": wrongVerb,
		"bodies_read":     bodiesReadFor(ctx, scopeTargetID),
		"caveat": "Only response bodies the crawl retained can be read. Deep capture is off by " +
			"default and bodies are capped at 128 KB, so an empty result means nothing was found in " +
			"what was stored rather than that every feature is covered.",
	})
}

// advertisedFeaturesFor reads the stored bodies and extracts everything that looks like an endpoint
// the application can call.
func advertisedFeaturesFor(ctx context.Context, scopeTargetID string) []advertisedFeature {
	rows, err := dbPool.Query(ctx, `
		SELECT url, COALESCE(mime_type,''), COALESCE(response_body,'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND COALESCE(response_body,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := map[string]bool{}
	var out []advertisedFeature
	add := func(f advertisedFeature) {
		if f.Path == "" {
			return
		}
		key := strings.ToUpper(f.Method) + " " + strings.ToLower(f.Path)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, f)
	}

	for rows.Next() {
		var pageURL, mime, body string
		if rows.Scan(&pageURL, &mime, &body) != nil {
			continue
		}
		isHTML := strings.Contains(strings.ToLower(mime), "html")
		isJS := strings.Contains(strings.ToLower(mime), "javascript")

		if isHTML {
			// Real forms first. These usually WERE exercised, so most will come back tested; they are
			// included so the list is a comparison rather than only a complaint.
			for _, form := range extractForms(body) {
				add(advertisedFeature{
					Method: strings.ToUpper(defaultString(form.Method, "GET")),
					Path:   normaliseFeaturePath(form.Action, pageURL),
					Source: "form", FoundOn: pageURL, RawTarget: form.Action,
				})
			}
			// Then the widgets that post without being forms, which is the class a crawl misses.
			for _, m := range reDataAction.FindAllStringSubmatch(body, -1) {
				method := "POST"
				if mm := reDataMethod.FindStringSubmatch(body); mm != nil {
					method = strings.ToUpper(mm[1])
				}
				add(advertisedFeature{
					Method: method, Path: normaliseFeaturePath(m[1], pageURL),
					Source: "data-action widget", FoundOn: pageURL, RawTarget: m[1],
				})
			}
		}
		if isJS || isHTML {
			// Each call contributes its OWN verb, taken from the same call's arguments.
			calls := [][2]string{}
			for _, m := range reXHROpen.FindAllStringSubmatch(body, -1) {
				calls = append(calls, [2]string{strings.ToUpper(m[1]), m[2]})
			}
			for _, m := range reFetchCall.FindAllStringSubmatch(body, -1) {
				verb := "GET"
				if opt := reMethodOpt.FindStringSubmatch(m[2]); opt != nil {
					verb = strings.ToUpper(opt[1])
				}
				calls = append(calls, [2]string{verb, m[1]})
			}
			for _, call := range calls {
				target := call[1]
				// Only same-origin paths. An absolute third-party URL is not this application's
				// attack surface and would fill the list with CDN and analytics noise.
				if strings.Contains(target, "://") || !strings.HasPrefix(target, "/") {
					continue
				}
				add(advertisedFeature{
					Method: call[0], Path: normaliseFeaturePath(target, pageURL),
					Source: "fetch/XHR", FoundOn: pageURL, RawTarget: target,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// testedPathsFor returns what has vectors, at two resolutions: by path, and by path plus verb.
//
// BOTH are needed and the difference between them is the interesting output. Matching on path alone
// says a feature is covered whenever anything at all points at that path, which is how a GET query
// vector recovered from a JavaScript file made a POST JSON endpoint look tested. Matching only on
// path plus verb would be too strict on its own, because a path with no vectors whatsoever is a
// bigger problem than a path with the wrong verb, and collapsing the two would bury it.
func testedPathsFor(ctx context.Context, scopeTargetID string) (byPath, byPathMethod map[string]bool) {
	byPath, byPathMethod = map[string]bool{}, map[string]bool{}
	rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT lower(path), upper(method) FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		return byPath, byPathMethod
	}
	defer rows.Close()
	for rows.Next() {
		var path, method string
		if rows.Scan(&path, &method) == nil {
			byPath[path] = true
			byPathMethod[method+" "+path] = true
		}
	}
	return byPath, byPathMethod
}

func bodiesReadFor(ctx context.Context, scopeTargetID string) int {
	var n int
	dbPool.QueryRow(ctx, `
		SELECT count(*) FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND COALESCE(response_body,'') <> ''`, scopeTargetID).Scan(&n)
	return n
}

// normaliseFeaturePath resolves whatever the markup carried against the page it was found on, and
// returns just the path. Query strings are dropped: the identity of a feature is where it goes, and
// the values are what a scan varies.
func normaliseFeaturePath(target, pageURL string) string {
	target = strings.TrimSpace(target)
	if target == "" || strings.HasPrefix(target, "#") ||
		strings.HasPrefix(strings.ToLower(target), "javascript:") ||
		strings.HasPrefix(strings.ToLower(target), "mailto:") {
		return ""
	}
	if strings.HasPrefix(target, "/") {
		if u, err := url.Parse(target); err == nil {
			return u.Path
		}
		return target
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	resolved, err := base.Parse(target)
	if err != nil {
		return ""
	}
	// Off-origin targets belong to somebody else.
	if resolved.Host != base.Host {
		return ""
	}
	return resolved.Path
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
