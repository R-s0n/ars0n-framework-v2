package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// Replay Request VARIANTS.
//
// A variant is one distinct recorded request/response of an endpoint (method+host+path). The client
// already collapses the captures of an endpoint into variants by the coarse request/response
// signatures (see requestSig/responseSig); this file is the small amount of state that turns those
// read-time groupings into things an operator can NAME and choose a PRIMARY among.
//
// Nothing here stores a variant. Variants are still derived from captures on every read, so a new
// capture that joins an existing variant group needs no migration. What is stored is an OVERLAY: a
// user-chosen name and the one primary flag, keyed by the variant's identity. Absent a row, a
// variant's name is its source label and the primary is the newest recording - both computed, both
// free.
//
// THE KEY IS FIVE COLUMNS, NOT ONE STRING. The client identifies a variant in memory as
// endpoint_key\u0000variant_sig, but that string carries NUL bytes and Postgres TEXT cannot hold a
// NUL. So the identity is stored decomposed - method, host, path, request_sig, response_sig - which
// is also what lets "one primary per endpoint" be a partial unique index rather than a trigger.

// ---------------------------------------------------------------------------
// Source label
// ---------------------------------------------------------------------------

// replayVariantSourceLabel turns the raw capture provenance into the friendly default name a variant
// carries before anyone renames it. Mirrored on the client (SingleRequestPane variantSourceLabel) so
// the UI and the MCP show the same default. capture_source is the axis that matters to an operator -
// active detection sent it, or it was recorded while browsing - and the low-level sources array
// (webrequest/hook/debugger) is extension plumbing that is not worth surfacing.
func replayVariantSourceLabel(captureSource, sourcesCSV string) string {
	cs := strings.ToLower(strings.TrimSpace(captureSource))
	if cs == "active" || strings.Contains(strings.ToLower(sourcesCSV), "active_detection") {
		return "Active detection"
	}
	return "Manual crawl"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

var replayVariantMetaSchema = []string{
	`CREATE TABLE IF NOT EXISTS replay_variant_meta (
		scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		method TEXT NOT NULL,
		host TEXT NOT NULL,
		path TEXT NOT NULL,
		request_sig TEXT NOT NULL,
		response_sig TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		is_primary BOOLEAN NOT NULL DEFAULT FALSE,
		updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
		PRIMARY KEY (scope_target_id, method, host, path, request_sig, response_sig)
	);`,
	`CREATE INDEX IF NOT EXISTS idx_replay_variant_meta_endpoint
	   ON replay_variant_meta (scope_target_id, method, host, path);`,
	// One primary per endpoint, enforced rather than assumed. Setting a new primary clears the old one
	// in the same transaction; the index is what stops two tabs racing to two primaries.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_replay_variant_meta_one_primary
	   ON replay_variant_meta (scope_target_id, method, host, path) WHERE is_primary;`,
}

var replayVariantMetaSchemaOnce sync.Once

// EnsureReplayVariantMetaSchema applies the overlay schema once per process. Cheap after the first
// call and safe at the top of every handler, the same pattern the versions table uses.
func EnsureReplayVariantMetaSchema() {
	replayVariantMetaSchemaOnce.Do(func() {
		if dbPool == nil {
			return
		}
		for _, stmt := range replayVariantMetaSchema {
			if _, err := dbPool.Exec(context.Background(), stmt); err != nil {
				log.Printf("[REPLAY-VARIANTS] Schema statement failed: %v", err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ReplayVariantMeta is one overlay row: a user's name and/or primary choice for one variant.
type ReplayVariantMeta struct {
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	RequestSig  string `json:"request_sig"`
	ResponseSig string `json:"response_sig"`
	Name        string `json:"name"`
	IsPrimary   bool   `json:"is_primary"`
}

func replayVariantMetaKey(method, host, path, reqSig, respSig string) string {
	return method + "\x00" + host + "\x00" + path + "\x00" + reqSig + "\x00" + respSig
}

func loadReplayVariantMeta(scopeTargetID string) (map[string]ReplayVariantMeta, error) {
	EnsureReplayVariantMetaSchema()
	rows, err := dbPool.Query(context.Background(),
		`SELECT method, host, path, request_sig, response_sig, COALESCE(name,''), is_primary
		   FROM replay_variant_meta WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ReplayVariantMeta{}
	for rows.Next() {
		var m ReplayVariantMeta
		if err := rows.Scan(&m.Method, &m.Host, &m.Path, &m.RequestSig, &m.ResponseSig,
			&m.Name, &m.IsPrimary); err != nil {
			log.Printf("[REPLAY-VARIANTS] Failed to scan meta row: %v", err)
			continue
		}
		out[replayVariantMetaKey(m.Method, m.Host, m.Path, m.RequestSig, m.ResponseSig)] = m
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// GET /replay-request/{scope_target_id}/variant-meta
// ---------------------------------------------------------------------------

// GetReplayVariantMeta returns every overlay row for a target. The client reads this once and merges
// it onto the variants it groups from the captures, so names and the primary survive a re-search.
func GetReplayVariantMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}
	meta, err := loadReplayVariantMeta(scopeTargetID)
	if err != nil {
		log.Printf("[REPLAY-VARIANTS] Failed to load meta for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The variant names could not be read: "+err.Error())
		return
	}
	list := make([]ReplayVariantMeta, 0, len(meta))
	for _, m := range meta {
		list = append(list, m)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"variant_meta": list, "count": len(list)})
}

// ---------------------------------------------------------------------------
// POST /replay-request/{scope_target_id}/variant-meta
// ---------------------------------------------------------------------------

type replayVariantMetaRequest struct {
	Method      string  `json:"method"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	RequestSig  string  `json:"request_sig"`
	ResponseSig string  `json:"response_sig"`
	// Pointer so "omitted" and "cleared" differ: nil leaves the name as it was, "" reverts it to the
	// source default (the row is deleted when that leaves nothing else stored).
	Name *string `json:"name"`
	// Pointer so a rename does not silently touch the primary. true makes this the endpoint's one
	// primary and clears the previous one; false clears it.
	SetPrimary *bool `json:"set_primary"`
}

// UpsertReplayVariantMeta sets a variant's name and/or makes it the endpoint's primary. Both live on
// one row, and a row that ends up with no name and not primary is deleted rather than kept as an
// empty overlay, so the table holds only real operator choices.
func UpsertReplayVariantMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	EnsureReplayVariantMetaSchema()

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var req replayVariantMetaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}
	req.Method = strings.TrimSpace(req.Method)
	req.Host = strings.TrimSpace(req.Host)
	req.Path = strings.TrimSpace(req.Path)
	req.RequestSig = strings.TrimSpace(req.RequestSig)
	req.ResponseSig = strings.TrimSpace(req.ResponseSig)
	if req.Method == "" || req.Host == "" || req.Path == "" ||
		(req.RequestSig == "" && req.ResponseSig == "") {
		writeJSONError(w, http.StatusBadRequest, "variant_identity_required",
			"method, host, path and at least one of request_sig / response_sig identify the variant "+
				"and are all required.")
		return
	}
	if req.Name == nil && req.SetPrimary == nil {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_do",
			"Pass name (to rename) or set_primary (to choose the primary), or both.")
		return
	}

	ctx := context.Background()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer tx.Rollback(ctx)

	// Read the current row, so an omitted field keeps its stored value rather than being wiped.
	var curName string
	var curPrimary bool
	found := true
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(name,''), is_primary FROM replay_variant_meta
		  WHERE scope_target_id=$1 AND method=$2 AND host=$3 AND path=$4
		    AND request_sig=$5 AND response_sig=$6`,
		scopeTargetID, req.Method, req.Host, req.Path, req.RequestSig, req.ResponseSig).
		Scan(&curName, &curPrimary)
	if err != nil {
		if err == pgx.ErrNoRows {
			found = false
		} else {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
	}

	name := curName
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	primary := curPrimary
	if req.SetPrimary != nil {
		primary = *req.SetPrimary
	}

	// Making this the primary clears whatever was primary on the same endpoint first, so the partial
	// unique index never has two to enforce against.
	if primary {
		if _, err := tx.Exec(ctx,
			`UPDATE replay_variant_meta SET is_primary=false, updated_at=NOW()
			  WHERE scope_target_id=$1 AND method=$2 AND host=$3 AND path=$4 AND is_primary`,
			scopeTargetID, req.Method, req.Host, req.Path); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
	}

	if name == "" && !primary {
		// Nothing left worth storing: this variant is back to its default name and default primary.
		if found {
			if _, err := tx.Exec(ctx,
				`DELETE FROM replay_variant_meta
				  WHERE scope_target_id=$1 AND method=$2 AND host=$3 AND path=$4
				    AND request_sig=$5 AND response_sig=$6`,
				scopeTargetID, req.Method, req.Host, req.Path, req.RequestSig, req.ResponseSig); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
				return
			}
		}
	} else {
		if _, err := tx.Exec(ctx,
			`INSERT INTO replay_variant_meta
			   (scope_target_id, method, host, path, request_sig, response_sig, name, is_primary, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			 ON CONFLICT (scope_target_id, method, host, path, request_sig, response_sig)
			 DO UPDATE SET name=EXCLUDED.name, is_primary=EXCLUDED.is_primary, updated_at=NOW()`,
			scopeTargetID, req.Method, req.Host, req.Path, req.RequestSig, req.ResponseSig,
			name, primary); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"name":       name,
		"is_primary": primary,
	})
}

// ---------------------------------------------------------------------------
// GET /replay-request/{scope_target_id}/variants
//
// The grouped view, for the MCP: every endpoint with its variants, each carrying the resolved name
// (custom or default), the primary flag (stored or, absent any stored primary, the newest recording)
// and the identifiers needed to rename it or make it primary. The UI does its own grouping while it
// builds the sitemap tree; this endpoint exists so the MCP does not have to reimplement that.
// ---------------------------------------------------------------------------

type replayVariantOut struct {
	RequestSig  string `json:"request_sig"`
	ResponseSig string `json:"response_sig"`
	Name        string `json:"name"`
	NameCustom  bool   `json:"name_custom"`
	IsPrimary   bool   `json:"is_primary"`
	Status      int    `json:"status"`
	Source      string `json:"source"`
	MimeType    string `json:"mime_type"`
	Size        int    `json:"size"`
	URL         string `json:"url"`
	Count       int    `json:"count"`
	SampleID    string `json:"sample_capture_id"`
}

type replayVariantEndpointOut struct {
	Method   string             `json:"method"`
	Host     string             `json:"host"`
	Path     string             `json:"path"`
	Variants []replayVariantOut `json:"variants"`
}

func GetReplayVariants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	filterMethod := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method")))
	filterHost := strings.TrimSpace(r.URL.Query().Get("host"))
	filterPath := strings.TrimSpace(r.URL.Query().Get("path"))

	caps, err := loadAllReplayCaptureSummaries(scopeTargetID)
	if err != nil {
		log.Printf("[REPLAY-VARIANTS] Failed to load captures for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The captures could not be read: "+err.Error())
		return
	}
	meta, err := loadReplayVariantMeta(scopeTargetID)
	if err != nil {
		log.Printf("[REPLAY-VARIANTS] Failed to load meta for %s: %v", scopeTargetID, err)
		meta = map[string]ReplayVariantMeta{}
	}

	// Group by endpoint, newest first, deduped by variant signature - the same shape buildTree
	// produces on the client.
	type epGroup struct {
		method, host, path string
		order              []string // variant keys, newest-first
		byKey              map[string]replayVariantOut
	}
	groups := map[string]*epGroup{}
	epOrder := []string{}

	for _, c := range caps {
		if filterMethod != "" && !strings.EqualFold(c.Method, filterMethod) {
			continue
		}
		if filterHost != "" && !strings.EqualFold(c.Host, filterHost) {
			continue
		}
		if filterPath != "" && c.Path != filterPath {
			continue
		}
		epKey := replayVariantMetaKey(c.Method, c.Host, c.Path, "", "")
		g := groups[epKey]
		if g == nil {
			g = &epGroup{method: c.Method, host: c.Host, path: c.Path, byKey: map[string]replayVariantOut{}}
			groups[epKey] = g
			epOrder = append(epOrder, epKey)
		}
		vkey := c.RequestSig + "\x00" + c.ResponseSig
		if existing, ok := g.byKey[vkey]; ok {
			existing.Count++
			g.byKey[vkey] = existing
			continue
		}
		g.order = append(g.order, vkey)
		g.byKey[vkey] = replayVariantOut{
			RequestSig:  c.RequestSig,
			ResponseSig: c.ResponseSig,
			Status:      c.StatusCode,
			Source:      c.Source,
			MimeType:    c.MimeType,
			Size:        c.Size,
			URL:         c.URL,
			Count:       1,
			SampleID:    c.ID,
		}
	}

	out := make([]replayVariantEndpointOut, 0, len(epOrder))
	for _, epKey := range epOrder {
		g := groups[epKey]
		ep := replayVariantEndpointOut{Method: g.method, Host: g.host, Path: g.path}
		storedPrimary := false
		for _, vkey := range g.order {
			v := g.byKey[vkey]
			mk := replayVariantMetaKey(g.method, g.host, g.path, v.RequestSig, v.ResponseSig)
			if m, ok := meta[mk]; ok {
				if strings.TrimSpace(m.Name) != "" {
					v.Name = m.Name
					v.NameCustom = true
				}
				if m.IsPrimary {
					v.IsPrimary = true
					storedPrimary = true
				}
			}
			if v.Name == "" {
				v.Name = v.Source
			}
			ep.Variants = append(ep.Variants, v)
		}
		// No stored primary: the newest recording (first in order) is the effective primary, matching
		// what the sitemap shows.
		if !storedPrimary && len(ep.Variants) > 0 {
			ep.Variants[0].IsPrimary = true
		}
		out = append(out, ep)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"endpoints": out,
		"count":     len(out),
	})
}

// loadAllReplayCaptureSummaries reads every capture for a target with the fields variant grouping
// needs, computing host and path with the SAME SQL expressions the capture list uses and the same
// request/response signatures, so a variant's identity matches across the sitemap, this endpoint and
// the overlay table.
func loadAllReplayCaptureSummaries(scopeTargetID string) ([]ReplayCaptureSummary, error) {
	sqlText := fmt.Sprintf(`
		SELECT id, COALESCE(method,''), COALESCE(url,''),
		       %s AS host, %s AS path,
		       COALESCE(status_code,0), COALESCE(mime_type,''),
		       COALESCE(octet_length(response_body),0), timestamp,
		       COALESCE(left(post_data, 65536),''), COALESCE(response_body_sha256,''),
		       COALESCE(NULLIF(response_headers->>'location',''), NULLIF(response_headers->>'Location',''), ''),
		       COALESCE(capture_source,''), COALESCE(array_to_string(sources,','),'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp DESC
		LIMIT %d`, captureSQLHost, captureSQLPath, replayCaptureScanCeiling)
	rows, err := dbPool.Query(context.Background(), sqlText, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReplayCaptureSummary{}
	for rows.Next() {
		var c ReplayCaptureSummary
		var postData, respSha, respLoc, captureSource, sourcesCSV string
		if err := rows.Scan(&c.ID, &c.Method, &c.URL, &c.Host, &c.Path, &c.StatusCode, &c.MimeType,
			&c.Size, &c.Timestamp, &postData, &respSha, &respLoc, &captureSource, &sourcesCSV); err != nil {
			log.Printf("[REPLAY-VARIANTS] Failed to scan capture: %v", err)
			continue
		}
		c.Method = strings.ToUpper(strings.TrimSpace(c.Method))
		c.RequestSig = requestSig(c.Method, c.URL, postData)
		c.ResponseSig = responseSig(c.StatusCode, c.MimeType, respSha, respLoc, c.Size)
		c.Source = replayVariantSourceLabel(captureSource, sourcesCSV)
		out = append(out, c)
	}
	return out, rows.Err()
}
