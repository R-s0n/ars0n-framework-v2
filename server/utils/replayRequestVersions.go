package utils

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// Replay Request versioning.
//
// The repeater used to be a scratchpad: load a capture, edit the bytes, send, and the thing you
// started from was gone. That is fine for one experiment and useless for an afternoon of them,
// because the question an operator asks four edits in is always "what did the ORIGINAL do?" and by
// then the original only exists in their memory.
//
// So nothing is ever overwritten. The capture's unmodified request is stored once, as the ORIGINAL,
// and every edit is a NEW ROW that remembers which row it was edited FROM. The result is a tree the
// operator can walk backwards: any version can be reopened, edited again, and that edit becomes yet
// another version rather than replacing the one they opened.
//
// Three rules make the difference between a version list and a pile of rows:
//
//	THE ORIGINAL IS IMMUTABLE. is_original rows refuse PUT and refuse DELETE. The whole point of the
//	  feature is that there is always a way back to what was actually observed on the wire, and a
//	  "way back" that an accidental save can destroy is not one.
//	IDENTICAL VERSIONS ARE REFUSED. A UI that saves on blur, or on a debounce, will try to create a
//	  version every time focus moves. Comparing the normalised bytes against the parent turns those
//	  into a 409 instead of a row, which is the only thing standing between this column and a
//	  hundred entries that all say the same thing.
//	LABELS ARE GENERATED FROM THE DIFF. "Version 2, Version 3, Version 4" is useless a day later.
//	  "Cookie edited", "method GET to POST", "3 headers, body changed" is not. The operator will
//	  never type these, so they have to be earned from the bytes.
//
// Nothing here re-implements sending. The version send path uses normalizeRawRequest,
// rawModeFramingNote, sendRawRequest and buildRawHTTPResponse, the same four functions POST
// /replay-request/send uses, so a version replayed from its row and the same bytes pasted into the
// editor go out identically.

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

// ReplayRequestVersionsSchema is the migration, in the form this repo uses everywhere else: a list
// of idempotent statements run on every boot. It is exported so createTables() in database.go can
// append it to its own list without this file having to be edited from there; it is also applied
// lazily by EnsureReplayRequestVersionsSchema so the handlers work on an install whose createTables
// has not been updated yet.
//
// Every statement is safe to run twice. That is not a style preference: createTables runs on EVERY
// boot and log.Fatalf's on a statement that fails, so a migration that is correct once and fatal
// afterwards takes the whole API down on its second deploy.
var ReplayRequestVersionsSchema = []string{
	// capture_id is nullable twice over: a request can be typed from scratch and never descend from
	// a capture at all, and ON DELETE SET NULL means clearing a manual crawl does not take the
	// versions with it. Losing the link is survivable; losing the observed original is the one thing
	// this table exists to prevent.
	//
	// parent_version_id is ON DELETE SET NULL as a backstop only. DeleteReplayRequestVersion
	// reparents children onto the deleted row's own parent inside a transaction, which is what
	// should happen; the constraint is there so a deletion that somehow bypasses that path leaves
	// orphans that are still readable rather than rows pointing at nothing.
	`CREATE TABLE IF NOT EXISTS replay_request_versions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		capture_id UUID REFERENCES manual_crawl_captures(id) ON DELETE SET NULL,
		parent_version_id UUID REFERENCES replay_request_versions(id) ON DELETE SET NULL,
		label TEXT NOT NULL DEFAULT '',
		raw_request TEXT NOT NULL,
		base_url TEXT NOT NULL DEFAULT '',
		is_original BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW()
	);`,
	// Whether the label was generated or typed. A generated label describes a diff against a
	// particular parent, so when a version is reparented by a deletion its generated label is now a
	// description of a comparison that no longer exists and gets recomputed. A label the operator
	// typed is theirs and is left alone. Without this flag the choice is between lying labels and
	// destroying the operator's own words, and both are worse than one boolean.
	`ALTER TABLE replay_request_versions
	   ADD COLUMN IF NOT EXISTS label_auto BOOLEAN NOT NULL DEFAULT TRUE;`,
	`CREATE INDEX IF NOT EXISTS idx_replay_request_versions_target
	   ON replay_request_versions(scope_target_id);`,
	`CREATE INDEX IF NOT EXISTS idx_replay_request_versions_capture
	   ON replay_request_versions(scope_target_id, capture_id);`,
	`CREATE INDEX IF NOT EXISTS idx_replay_request_versions_parent
	   ON replay_request_versions(parent_version_id);`,
	// One original per capture, enforced rather than assumed. Two browser tabs opening the same
	// capture at the same moment both find no original and both try to insert one; without this the
	// version column shows two identical roots and the operator has no way to tell which of them
	// their edits descend from.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_replay_request_versions_one_original
	   ON replay_request_versions(scope_target_id, capture_id) WHERE is_original;`,
}

var replayVersionSchemaOnce sync.Once

// EnsureReplayRequestVersionsSchema applies the schema once per process. Cheap after the first call
// and safe to put at the top of every handler: the table has to exist before the first request that
// touches it, and an install whose createTables predates this feature would otherwise 500 forever
// with a message about a missing relation.
func EnsureReplayRequestVersionsSchema() {
	replayVersionSchemaOnce.Do(func() {
		if dbPool == nil {
			return
		}
		for _, stmt := range ReplayRequestVersionsSchema {
			if _, err := dbPool.Exec(context.Background(), stmt); err != nil {
				log.Printf("[REPLAY-VERSIONS] Schema statement failed: %v", err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ReplayRequestVersion is one saved state of one request.
//
// RawRequest is returned in the list rather than behind a per-version fetch, because the list IS the
// way a version is reopened and a second round trip to read bytes the client is about to need
// anyway buys nothing. Requests are headers plus a small body; the recorder caps what it stores.
type ReplayRequestVersion struct {
	ID              string    `json:"id"`
	ScopeTargetID   string    `json:"scope_target_id"`
	CaptureID       string    `json:"capture_id,omitempty"`
	ParentVersionID string    `json:"parent_version_id,omitempty"`
	Label           string    `json:"label"`
	LabelAuto       bool      `json:"label_auto"`
	RawRequest      string    `json:"raw_request"`
	BaseURL         string    `json:"base_url"`
	IsOriginal      bool      `json:"is_original"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Derived, not stored. The column needs a one-line identity for each row that is not the label,
	// because "Cookie edited" does not say which request had its cookie edited.
	Summary   string `json:"summary"`
	SizeBytes int    `json:"size_bytes"`
}

const replayVersionColumns = `id::text, scope_target_id::text,
	COALESCE(capture_id::text,''), COALESCE(parent_version_id::text,''),
	COALESCE(label,''), COALESCE(label_auto,true), COALESCE(raw_request,''),
	COALESCE(base_url,''), is_original, created_at, updated_at`

// replayVersionRow is the shared shape of pgx.Row and pgx.Rows, so one scan function serves the
// single-row reads and the list.
type replayVersionRow interface {
	Scan(dest ...any) error
}

func scanReplayVersion(row replayVersionRow) (ReplayRequestVersion, error) {
	var v ReplayRequestVersion
	err := row.Scan(&v.ID, &v.ScopeTargetID, &v.CaptureID, &v.ParentVersionID, &v.Label,
		&v.LabelAuto, &v.RawRequest, &v.BaseURL, &v.IsOriginal, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return v, err
	}
	v.Summary = summarizeRawRequest(v.RawRequest)
	v.SizeBytes = len(v.RawRequest)
	return v, nil
}

func loadReplayVersion(id string) (ReplayRequestVersion, error) {
	row := dbPool.QueryRow(context.Background(),
		`SELECT `+replayVersionColumns+` FROM replay_request_versions WHERE id = $1`, id)
	return scanReplayVersion(row)
}

// nullableUUIDArg turns an empty string into a real SQL NULL. Passing "" into a uuid column is a
// type error, and passing it into a nullable column as an empty string is a different bug that only
// shows up as a foreign key violation later.
func nullableUUIDArg(s string) interface{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return s
}

func replayVersionsReady(w http.ResponseWriter) bool {
	if dbPool == nil {
		writeJSONError(w, http.StatusInternalServerError, "database_unavailable",
			"The database connection is not available")
		return false
	}
	EnsureReplayRequestVersionsSchema()
	return true
}

// ---------------------------------------------------------------------------
// GET /replay-request/{scope_target_id}/versions?capture_id=
// ---------------------------------------------------------------------------

type replayVersionsListResponse struct {
	ScopeTargetID string                 `json:"scope_target_id"`
	CaptureID     string                 `json:"capture_id,omitempty"`
	Count         int                    `json:"count"`
	Versions      []ReplayRequestVersion `json:"versions"`
}

// ListReplayRequestVersions handles GET /replay-request/{scope_target_id}/versions.
//
// With capture_id it returns that capture's version tree and MATERIALISES the original if it does
// not exist yet: the original is defined as the capture's unmodified request, so creating it is
// copying a fact, not recording a decision. That makes this GET idempotent in the way that matters,
// it never changes an answer, it only writes down one that was already true. It also means the
// client does not need a separate "start versioning this capture" call that it could forget to make
// and end up with edits whose root is missing.
//
// Without capture_id it returns every version for the target, including requests typed from
// scratch, which have no capture to descend from.
func ListReplayRequestVersions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !replayVersionsReady(w) {
		return
	}

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required",
			"scope_target_id must be a UUID")
		return
	}

	captureID := strings.TrimSpace(r.URL.Query().Get("capture_id"))
	if captureID != "" {
		if _, err := uuid.Parse(captureID); err != nil {
			writeJSONError(w, http.StatusBadRequest, "capture_id_invalid",
				"capture_id must be a UUID")
			return
		}
		// Best effort. A capture that has been purged still has versions worth listing, so a failure
		// to materialise the original must not empty the list.
		if _, err := ensureCaptureOriginal(scopeTargetID, captureID); err != nil {
			log.Printf("[REPLAY-VERSIONS] Could not ensure original for capture %s: %v", captureID, err)
		}
	}

	// is_original DESC puts the observed request at the top of the column whatever its timestamp,
	// then created_at ASC reads down the history in the order the operator made it. id is the final
	// tie-break so two versions saved in the same millisecond do not swap places between two loads.
	sqlText := `SELECT ` + replayVersionColumns + `
		FROM replay_request_versions
		WHERE scope_target_id = $1`
	args := []interface{}{scopeTargetID}
	if captureID != "" {
		sqlText += ` AND capture_id = $2`
		args = append(args, captureID)
	}
	sqlText += ` ORDER BY is_original DESC, created_at ASC, id ASC`

	rows, err := dbPool.Query(context.Background(), sqlText, args...)
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] List failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to list versions")
		return
	}
	defer rows.Close()

	versions := []ReplayRequestVersion{}
	for rows.Next() {
		v, scanErr := scanReplayVersion(rows)
		if scanErr != nil {
			log.Printf("[REPLAY-VERSIONS] Failed to scan version row: %v", scanErr)
			continue
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[REPLAY-VERSIONS] List iteration failed: %v", err)
	}

	json.NewEncoder(w).Encode(replayVersionsListResponse{
		ScopeTargetID: scopeTargetID,
		CaptureID:     captureID,
		Count:         len(versions),
		Versions:      versions,
	})
}

// ensureCaptureOriginal returns the id of the is_original row for a capture, creating it from the
// capture's own bytes if it is not there. Returns "" with no error when the capture does not exist
// for that scope target, which is not a failure: the versions that descend from it are still valid.
func ensureCaptureOriginal(scopeTargetID, captureID string) (string, error) {
	existing := ""
	err := dbPool.QueryRow(context.Background(),
		`SELECT id::text FROM replay_request_versions
		 WHERE scope_target_id = $1 AND capture_id = $2 AND is_original`,
		scopeTargetID, captureID).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	var urlStr, method, postData string
	var headersJSON []byte
	err = dbPool.QueryRow(context.Background(), `
		SELECT COALESCE(url,''), COALESCE(method,''), COALESCE(post_data,''), headers
		FROM manual_crawl_captures
		WHERE id = $1 AND scope_target_id = $2`, captureID, scopeTargetID).
		Scan(&urlStr, &method, &postData, &headersJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	var headers map[string]interface{}
	json.Unmarshal(headersJSON, &headers)
	raw := BuildRawHTTPRequest(method, urlStr, headers, postData)

	baseURL := ""
	if parsed, perr := url.Parse(urlStr); perr == nil && parsed.Host != "" {
		baseURL = parsed.Scheme + "://" + parsed.Host
	}

	newID := ""
	err = dbPool.QueryRow(context.Background(), `
		INSERT INTO replay_request_versions
			(scope_target_id, capture_id, parent_version_id, label, label_auto,
			 raw_request, base_url, is_original)
		VALUES ($1, $2, NULL, 'Original', TRUE, $3, $4, TRUE)
		ON CONFLICT DO NOTHING
		RETURNING id::text`, scopeTargetID, captureID, raw, baseURL).Scan(&newID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Lost the race with another tab. The other insert is the original; read it back rather than
		// reporting a failure the operator would see as "versioning is broken".
		err = dbPool.QueryRow(context.Background(),
			`SELECT id::text FROM replay_request_versions
			 WHERE scope_target_id = $1 AND capture_id = $2 AND is_original`,
			scopeTargetID, captureID).Scan(&newID)
		if err != nil {
			return "", err
		}
		return newID, nil
	}
	if err != nil {
		return "", err
	}
	return newID, nil
}

// ---------------------------------------------------------------------------
// POST /replay-request/{scope_target_id}/versions
// ---------------------------------------------------------------------------

type replayVersionCreatePayload struct {
	CaptureID       string `json:"capture_id"`
	ParentVersionID string `json:"parent_version_id"`
	Label           string `json:"label"`
	RawRequest      string `json:"raw_request"`
	BaseURL         string `json:"base_url"`
}

type replayVersionConflictResponse struct {
	Error    string                `json:"error"`
	Message  string                `json:"message"`
	Existing *ReplayRequestVersion `json:"existing,omitempty"`
}

// CreateReplayRequestVersion handles POST /replay-request/{scope_target_id}/versions.
func CreateReplayRequestVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !replayVersionsReady(w) {
		return
	}

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required",
			"scope_target_id must be a UUID")
		return
	}

	var payload replayVersionCreatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if strings.TrimSpace(payload.RawRequest) == "" {
		writeJSONError(w, http.StatusBadRequest, "raw_request_required", "raw_request is required")
		return
	}

	captureID := strings.TrimSpace(payload.CaptureID)
	if captureID != "" {
		if _, err := uuid.Parse(captureID); err != nil {
			writeJSONError(w, http.StatusBadRequest, "capture_id_invalid", "capture_id must be a UUID")
			return
		}
		// Checked up front rather than left to the foreign key. A capture that has been purged, or
		// that belongs to another scope target, would otherwise fail the insert and surface as a
		// generic 500, and the operator would be told "failed to create version" about a problem
		// with the capture they picked.
		exists := false
		if err := dbPool.QueryRow(context.Background(),
			`SELECT EXISTS(SELECT 1 FROM manual_crawl_captures WHERE id = $1 AND scope_target_id = $2)`,
			captureID, scopeTargetID).Scan(&exists); err != nil {
			log.Printf("[REPLAY-VERSIONS] Capture existence check failed for %s: %v", captureID, err)
			writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to check the capture")
			return
		}
		if !exists {
			writeJSONError(w, http.StatusBadRequest, "capture_not_found",
				"No capture with that id belongs to this scope target. If the manual crawl was "+
					"cleared, save the request without a capture_id instead.")
			return
		}
	}

	// Resolve the parent. An explicit parent_version_id wins; otherwise a version saved against a
	// capture descends from that capture's original, which is what makes the first edit produce a
	// diff-derived label instead of a bare summary.
	var parent *ReplayRequestVersion
	parentID := strings.TrimSpace(payload.ParentVersionID)
	if parentID != "" {
		if _, err := uuid.Parse(parentID); err != nil {
			writeJSONError(w, http.StatusBadRequest, "parent_version_id_invalid",
				"parent_version_id must be a UUID")
			return
		}
		loaded, err := loadReplayVersion(parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "parent_not_found",
				"No version with that parent_version_id")
			return
		}
		if err != nil {
			log.Printf("[REPLAY-VERSIONS] Failed to load parent %s: %v", parentID, err)
			writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load parent version")
			return
		}
		if loaded.ScopeTargetID != scopeTargetID {
			// Cross-target parenting would let one target's version tree hang off another's. Refused
			// rather than silently reparented, because a request that belongs to a different scope is
			// exactly the request that must not be sent by accident.
			writeJSONError(w, http.StatusBadRequest, "parent_scope_mismatch",
				"That parent version belongs to a different scope target")
			return
		}
		parent = &loaded
	} else if captureID != "" {
		originalID, err := ensureCaptureOriginal(scopeTargetID, captureID)
		if err != nil {
			log.Printf("[REPLAY-VERSIONS] Could not ensure original for capture %s: %v", captureID, err)
		} else if originalID != "" {
			if loaded, lerr := loadReplayVersion(originalID); lerr == nil {
				parent = &loaded
			}
		}
	}

	baseURL := strings.TrimSpace(payload.BaseURL)
	if parent != nil {
		if captureID == "" {
			captureID = parent.CaptureID
		}
		if baseURL == "" {
			baseURL = parent.BaseURL
		}

		// The keystroke guard. A UI that saves on blur will offer the parent's bytes back verbatim
		// every time focus leaves the editor, and every one of those would otherwise be a row.
		if versionsAreIdentical(parent.RawRequest, parent.BaseURL, payload.RawRequest, baseURL) {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(replayVersionConflictResponse{
				Error: "identical_to_parent",
				Message: "This request is byte-identical to the version it was edited from, " +
					"so no new version was created. Select the existing version instead.",
				Existing: parent,
			})
			return
		}
	}

	label := strings.TrimSpace(payload.Label)
	labelAuto := false
	if label == "" {
		labelAuto = true
		if parent != nil {
			label = describeVersionChange(parent.RawRequest, parent.BaseURL, payload.RawRequest, baseURL)
		} else {
			// Nothing to diff against, so the label is what the request IS rather than what changed.
			label = summarizeRawRequest(payload.RawRequest)
		}
	}

	var parentArg interface{}
	if parent != nil {
		parentArg = parent.ID
	}

	// is_original is FALSE unconditionally. A request typed from scratch is the root of its own tree
	// but it was never observed on the wire, and is_original means "this is what the target actually
	// sent us". Marking a typed request original would make it immutable and undeletable for no
	// reason, and would put a fiction at the top of the column.
	row := dbPool.QueryRow(context.Background(), `
		INSERT INTO replay_request_versions
			(scope_target_id, capture_id, parent_version_id, label, label_auto,
			 raw_request, base_url, is_original)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, FALSE)
		RETURNING `+replayVersionColumns,
		scopeTargetID, nullableUUIDArg(captureID), parentArg, label, labelAuto,
		payload.RawRequest, baseURL)

	created, err := scanReplayVersion(row)
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Insert failed: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create version")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

// ---------------------------------------------------------------------------
// PUT /replay-request/versions/{id}
// ---------------------------------------------------------------------------

// Pointers, not strings. The difference between "the caller did not send base_url" and "the caller
// sent an empty base_url" is the difference between leaving a column alone and wiping it, and a
// partial update that wipes columns is the kind of bug that is only noticed after it has run over
// every row.
type replayVersionUpdatePayload struct {
	Label      *string `json:"label"`
	RawRequest *string `json:"raw_request"`
	BaseURL    *string `json:"base_url"`
}

// UpdateReplayRequestVersion handles PUT /replay-request/versions/{id}.
func UpdateReplayRequestVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !replayVersionsReady(w) {
		return
	}

	versionID := mux.Vars(r)["id"]
	if _, err := uuid.Parse(versionID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "version_id_required", "version id must be a UUID")
		return
	}

	var payload replayVersionUpdatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	current, err := loadReplayVersion(versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "version_not_found", "No version with that id")
		return
	}
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Failed to load version %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load version")
		return
	}
	if current.IsOriginal {
		writeJSONError(w, http.StatusConflict, "original_immutable",
			"This is the original request as it was observed. It cannot be edited, because being "+
				"able to get back to it is the point. Save your changes as a new version instead.")
		return
	}

	if payload.RawRequest != nil && strings.TrimSpace(*payload.RawRequest) == "" {
		writeJSONError(w, http.StatusBadRequest, "raw_request_required",
			"raw_request cannot be emptied")
		return
	}

	newRaw := current.RawRequest
	if payload.RawRequest != nil {
		newRaw = *payload.RawRequest
	}
	newBase := current.BaseURL
	if payload.BaseURL != nil {
		newBase = strings.TrimSpace(*payload.BaseURL)
	}

	contentChanged := newRaw != current.RawRequest || newBase != current.BaseURL

	var parent *ReplayRequestVersion
	if current.ParentVersionID != "" {
		if loaded, lerr := loadReplayVersion(current.ParentVersionID); lerr == nil {
			parent = &loaded
		}
	}
	if parent != nil && contentChanged &&
		versionsAreIdentical(parent.RawRequest, parent.BaseURL, newRaw, newBase) {
		writeJSONError(w, http.StatusConflict, "identical_to_parent",
			"That edit would make this version byte-identical to the one it was edited from. "+
				"Delete this version instead of keeping a duplicate of its parent.")
		return
	}

	// A generated label describes the old bytes. Leaving it in place after an edit means the column
	// says "Cookie edited" next to a row whose cookie is now the parent's and whose body is not.
	label := current.Label
	labelAuto := current.LabelAuto
	if payload.Label != nil {
		label = strings.TrimSpace(*payload.Label)
		labelAuto = label == ""
	}
	if labelAuto && (contentChanged || payload.Label != nil) {
		if parent != nil {
			label = describeVersionChange(parent.RawRequest, parent.BaseURL, newRaw, newBase)
		} else {
			label = summarizeRawRequest(newRaw)
		}
	}

	row := dbPool.QueryRow(context.Background(), `
		UPDATE replay_request_versions
		SET label = $2, label_auto = $3, raw_request = $4, base_url = $5, updated_at = NOW()
		WHERE id = $1 AND NOT is_original
		RETURNING `+replayVersionColumns,
		versionID, label, labelAuto, newRaw, newBase)

	updated, err := scanReplayVersion(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// The NOT is_original in the WHERE is a second lock on the same door: the check above can
		// lose a race with a concurrent write, and this cannot.
		writeJSONError(w, http.StatusConflict, "original_immutable",
			"This version is the original and cannot be edited")
		return
	}
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Update failed for %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update version")
		return
	}

	json.NewEncoder(w).Encode(updated)
}

// ---------------------------------------------------------------------------
// DELETE /replay-request/versions/{id}
// ---------------------------------------------------------------------------

type replayVersionDeleteResponse struct {
	Deleted       string                 `json:"deleted"`
	ReparentedTo  string                 `json:"reparented_to,omitempty"`
	ReparentedIDs []string               `json:"reparented_ids"`
	Reparented    []ReplayRequestVersion `json:"reparented"`
}

// DeleteReplayRequestVersion handles DELETE /replay-request/versions/{id}.
//
// Deleting a version in the middle of a chain must not take its descendants with it. The children
// are reparented onto the deleted row's own parent, so the history stays a connected tree: the
// operator loses the step they asked to lose and nothing else.
func DeleteReplayRequestVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !replayVersionsReady(w) {
		return
	}

	versionID := mux.Vars(r)["id"]
	if _, err := uuid.Parse(versionID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "version_id_required", "version id must be a UUID")
		return
	}

	current, err := loadReplayVersion(versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "version_not_found", "No version with that id")
		return
	}
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Failed to load version %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load version")
		return
	}
	if current.IsOriginal {
		writeJSONError(w, http.StatusConflict, "original_immutable",
			"This is the original request as it was observed and cannot be deleted. Every other "+
				"version is an edit you can throw away; this one is the evidence.")
		return
	}

	ctx := context.Background()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Failed to begin delete transaction: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete version")
		return
	}
	defer tx.Rollback(ctx)

	// The new parent for the orphans, which may legitimately be NULL: deleting the first edit off a
	// scratch request leaves its children as roots.
	newParent := nullableUUIDArg(current.ParentVersionID)

	rows, err := tx.Query(ctx, `
		UPDATE replay_request_versions
		SET parent_version_id = $2::uuid, updated_at = NOW()
		WHERE parent_version_id = $1
		RETURNING `+replayVersionColumns, versionID, newParent)
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Reparent failed for %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"Failed to reparent the versions that descend from this one")
		return
	}

	children := []ReplayRequestVersion{}
	for rows.Next() {
		child, scanErr := scanReplayVersion(rows)
		if scanErr != nil {
			log.Printf("[REPLAY-VERSIONS] Failed to scan reparented child: %v", scanErr)
			continue
		}
		children = append(children, child)
	}
	rows.Close()
	rowsErr := rows.Err()
	if rowsErr != nil {
		log.Printf("[REPLAY-VERSIONS] Reparent iteration failed: %v", rowsErr)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"Failed to reparent the versions that descend from this one")
		return
	}

	// A generated label on a reparented child now describes a diff against a row that is about to
	// stop existing. Recomputed against the new parent so the column keeps telling the truth. Labels
	// the operator typed are left exactly as typed.
	var newParentVersion *ReplayRequestVersion
	if current.ParentVersionID != "" {
		row := tx.QueryRow(ctx, `SELECT `+replayVersionColumns+
			` FROM replay_request_versions WHERE id = $1`, current.ParentVersionID)
		if loaded, lerr := scanReplayVersion(row); lerr == nil {
			newParentVersion = &loaded
		}
	}
	for i := range children {
		if !children[i].LabelAuto {
			continue
		}
		relabel := ""
		if newParentVersion != nil {
			relabel = describeVersionChange(newParentVersion.RawRequest, newParentVersion.BaseURL,
				children[i].RawRequest, children[i].BaseURL)
		} else {
			relabel = summarizeRawRequest(children[i].RawRequest)
		}
		if relabel == children[i].Label {
			continue
		}
		if _, uerr := tx.Exec(ctx,
			`UPDATE replay_request_versions SET label = $2 WHERE id = $1`,
			children[i].ID, relabel); uerr != nil {
			log.Printf("[REPLAY-VERSIONS] Relabel failed for %s: %v", children[i].ID, uerr)
			continue
		}
		children[i].Label = relabel
	}

	tag, err := tx.Exec(ctx, `DELETE FROM replay_request_versions WHERE id = $1 AND NOT is_original`,
		versionID)
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Delete failed for %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete version")
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusConflict, "original_immutable",
			"This version is the original and cannot be deleted")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[REPLAY-VERSIONS] Commit failed for delete of %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete version")
		return
	}

	ids := make([]string, 0, len(children))
	for _, child := range children {
		ids = append(ids, child.ID)
	}
	json.NewEncoder(w).Encode(replayVersionDeleteResponse{
		Deleted:       versionID,
		ReparentedTo:  current.ParentVersionID,
		ReparentedIDs: ids,
		Reparented:    children,
	})
}

// ---------------------------------------------------------------------------
// POST /replay-request/versions/{id}/send
// ---------------------------------------------------------------------------

type replayVersionSendPayload struct {
	// Optional override, for pointing a saved version at a different host without editing its bytes.
	// Empty means "use the version's own base_url".
	BaseURL string `json:"base_url"`
	RawMode bool   `json:"raw_mode"`
}

// The same JSON keys POST /replay-request/send returns, so one response component renders both.
// Written out rather than embedded so the shapes cannot drift apart silently.
type replayVersionSendResponse struct {
	VersionID   string              `json:"version_id"`
	Label       string              `json:"label"`
	Status      int                 `json:"status"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	RawResponse string              `json:"raw_response"`
	TimeMs      float64             `json:"time_ms"`
	SizeBytes   int                 `json:"size_bytes"`
	Error       string              `json:"error"`
	Note        string              `json:"note,omitempty"`
}

// SendReplayRequestVersion handles POST /replay-request/versions/{id}/send.
//
// Sends the version's stored bytes, including the original: replaying the original is how an
// operator establishes what the target does now versus what it did when the capture was recorded,
// and refusing it would make the immutability rule mean "cannot be used" rather than "cannot be
// changed". Nothing is written back, the version is not modified by being sent.
func SendReplayRequestVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !replayVersionsReady(w) {
		return
	}

	versionID := mux.Vars(r)["id"]
	if _, err := uuid.Parse(versionID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "version_id_required", "version id must be a UUID")
		return
	}

	var payload replayVersionSendPayload
	if r.Body != nil {
		// An empty body is fine: send this version as it stands, with its own base URL.
		json.NewDecoder(r.Body).Decode(&payload)
	}

	version, err := loadReplayVersion(versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "version_not_found", "No version with that id")
		return
	}
	if err != nil {
		log.Printf("[REPLAY-VERSIONS] Failed to load version %s: %v", versionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load version")
		return
	}

	baseURL := strings.TrimSpace(payload.BaseURL)
	if baseURL == "" {
		baseURL = version.BaseURL
	}

	result := executeReplaySend(version.RawRequest, baseURL, payload.RawMode)
	json.NewEncoder(w).Encode(replayVersionSendResponse{
		VersionID:   version.ID,
		Label:       version.Label,
		Status:      result.Status,
		Headers:     result.Headers,
		Body:        result.Body,
		RawResponse: result.RawResponse,
		TimeMs:      result.TimeMs,
		SizeBytes:   result.SizeBytes,
		Error:       result.Error,
		Note:        result.Note,
	})
}

// executeReplaySend is the send path POST /replay-request/send performs, as a function rather than
// inline in a handler, so a version can be replayed through exactly the same steps in the same
// order. SendReplayRequest still has its own copy of this sequence; collapsing that one onto this
// function is a one-line change in replayRequestUtils.go and belongs to whoever owns that file.
//
// Every decision here is the existing one, deliberately: raw mode skips normalisation because the
// disagreement between Content-Length and Transfer-Encoding IS the payload in a smuggling probe, a
// parse failure is reported as a result rather than an error, and a fresh cookie jar per send stops
// a jar re-attaching a cookie the operator just deleted.
func executeReplaySend(rawRequest, baseURL string, rawMode bool) replaySendResponse {
	result := replaySendResponse{Headers: map[string][]string{}}

	if strings.TrimSpace(rawRequest) == "" {
		result.Error = "This version has no request to send."
		return result
	}

	request := rawRequest
	if rawMode {
		result.Note = rawModeFramingNote(request)
	} else {
		request = normalizeRawRequest(request)
	}

	parsed, parseErr := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	if parseErr != nil {
		result.Error = "This does not parse as an HTTP request: " + parseErr.Error() +
			". Expected a request line, then headers, then a blank line, then the body."
		return result
	}
	if parsed.Host == "" && strings.TrimSpace(baseURL) == "" {
		result.Error = "The request has no Host header and no base_url was given, " +
			"so there is no way to tell which server to send it to."
		return result
	}

	jar, _ := cookiejar.New(nil)
	status, headers, body, elapsed, sendErr := sendRawRequest(request, baseURL, jar)

	result.Status = status
	result.Headers = headers
	result.Body = body
	result.TimeMs = elapsed
	result.SizeBytes = len([]byte(body))
	if result.Headers == nil {
		result.Headers = map[string][]string{}
	}
	if sendErr != nil {
		result.Error = sendErr.Error()
	} else {
		result.RawResponse = buildRawHTTPResponse(status, headers, body)
	}
	return result
}

// ---------------------------------------------------------------------------
// Normalisation and identity
// ---------------------------------------------------------------------------

// normalizeVersionBytes is the comparison form of a raw request. Deliberately minimal: line endings
// unified and trailing newlines dropped, because those are artefacts of textareas and of whatever
// pasted the request, and nothing else.
//
// It does NOT call normalizeRawRequest. That function recomputes Content-Length to match the body,
// which would make a version whose only edit is a deliberately wrong Content-Length compare equal to
// its parent and get refused. That edit is the entire content of a request smuggling probe, and a
// "no changes detected" on it would be the framework telling the operator their test is not a test.
func normalizeVersionBytes(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimRight(s, "\n")
}

// versionsAreIdentical decides whether a proposed version is worth a row.
//
// base_url is part of the identity, not decoration: the same bytes aimed at a different host is a
// different experiment, and it is one of the more useful things an operator does with the repeater.
func versionsAreIdentical(parentRaw, parentBase, childRaw, childBase string) bool {
	return normalizeVersionBytes(parentRaw) == normalizeVersionBytes(childRaw) &&
		strings.TrimSpace(parentBase) == strings.TrimSpace(childBase)
}

// ---------------------------------------------------------------------------
// The differ
// ---------------------------------------------------------------------------

// Labels above this length stop being scannable and become a paragraph in a column. The compact
// forms take over rather than the label being cut mid-word.
const replayVersionLabelMaxRunes = 90

// rawRequestParts is a raw HTTP request pulled apart far enough to diff, and no further. Header
// values keep their duplicates and their order, because a request with two Cookie headers is a
// different request from one with them merged, and losing that would make a real edit invisible.
type rawRequestParts struct {
	Method  string
	Target  string
	Proto   string
	Path    string
	Query   string
	Order   []string            // lowercase header names, first-appearance order
	Values  map[string][]string // lowercase name -> values, in order
	Display map[string]string   // lowercase name -> the casing the operator typed
	Body    string
	HasLine bool
}

func parseRawRequestParts(raw string) rawRequestParts {
	p := rawRequestParts{
		Values:  map[string][]string{},
		Display: map[string]string{},
	}

	text := strings.ReplaceAll(raw, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	head, body, found := strings.Cut(text, "\n\n")
	if !found {
		head = strings.TrimRight(text, "\n")
		body = ""
	}
	p.Body = body

	lines := strings.Split(head, "\n")
	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}
	if i < len(lines) {
		fields := strings.Fields(lines[i])
		if len(fields) > 0 {
			p.Method = strings.ToUpper(fields[0])
			p.HasLine = true
		}
		if len(fields) > 1 {
			p.Target = fields[1]
		}
		if len(fields) > 2 {
			p.Proto = strings.ToUpper(fields[2])
		}
		i++
	}
	p.Path, p.Query, _ = strings.Cut(p.Target, "?")

	lastKey := ""
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		// An obs-fold continuation belongs to the header above it, not to a header of its own.
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && lastKey != "" {
			vals := p.Values[lastKey]
			if len(vals) > 0 {
				vals[len(vals)-1] += " " + strings.TrimSpace(line)
				p.Values[lastKey] = vals
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, seen := p.Values[key]; !seen {
			p.Order = append(p.Order, key)
			p.Display[key] = name
		}
		p.Values[key] = append(p.Values[key], strings.TrimSpace(value))
		lastKey = key
	}

	return p
}

// rawRequestDiff is what changed between two versions, in the terms an operator thinks in.
type rawRequestDiff struct {
	Identical bool

	BaseFrom, BaseTo     string
	MethodFrom, MethodTo string
	PathFrom, PathTo     string
	ProtoFrom, ProtoTo   string

	QueryAdded, QueryRemoved, QueryChanged       []string
	HeadersAdded, HeadersRemoved, HeadersChanged []string
	HeaderOrderChanged                           bool

	BodyAdded, BodyRemoved, BodyChanged                   bool
	BodyFieldsKnown                                       bool
	BodyFieldsAdded, BodyFieldsRemoved, BodyFieldsChanged []string

	// Kept so Label can tell "only whitespace moved" from "something changed that this differ does
	// not have a name for". Unexported: a caller builds one of these with diffRawRequests.
	rawFrom, rawTo string
}

func diffRawRequests(parentRaw, parentBase, childRaw, childBase string) rawRequestDiff {
	d := rawRequestDiff{
		BaseFrom: strings.TrimSpace(parentBase),
		BaseTo:   strings.TrimSpace(childBase),
		rawFrom:  parentRaw,
		rawTo:    childRaw,
	}
	if versionsAreIdentical(parentRaw, parentBase, childRaw, childBase) {
		d.Identical = true
		return d
	}

	from := parseRawRequestParts(parentRaw)
	to := parseRawRequestParts(childRaw)

	d.MethodFrom, d.MethodTo = from.Method, to.Method
	d.PathFrom, d.PathTo = from.Path, to.Path
	d.ProtoFrom, d.ProtoTo = from.Proto, to.Proto

	fromQuery, fromQueryOrder := parseFormPairs(from.Query)
	toQuery, toQueryOrder := parseFormPairs(to.Query)
	d.QueryAdded, d.QueryRemoved, d.QueryChanged =
		diffKeyedValues(fromQuery, fromQueryOrder, toQuery, toQueryOrder)

	seen := map[string]bool{}
	for _, key := range to.Order {
		seen[key] = true
		fromVals, existed := from.Values[key]
		if !existed {
			d.HeadersAdded = append(d.HeadersAdded, to.Display[key])
			continue
		}
		if !equalStrings(fromVals, to.Values[key]) {
			d.HeadersChanged = append(d.HeadersChanged, to.Display[key])
		}
	}
	for _, key := range from.Order {
		if !seen[key] {
			d.HeadersRemoved = append(d.HeadersRemoved, from.Display[key])
		}
	}
	if len(d.HeadersAdded) == 0 && len(d.HeadersRemoved) == 0 && len(d.HeadersChanged) == 0 &&
		!equalStrings(from.Order, to.Order) {
		// Same headers, same values, different order. Worth naming: header order is a real variable
		// on some targets, and a version whose only change had no label would look like a bug.
		d.HeaderOrderChanged = true
	}

	switch {
	case from.Body == to.Body:
		// nothing
	case from.Body == "":
		d.BodyAdded = true
	case to.Body == "":
		d.BodyRemoved = true
	default:
		d.BodyChanged = true
		fromFields, fromOrder, fromOK := parseBodyFields(from.Body)
		toFields, toOrder, toOK := parseBodyFields(to.Body)
		if fromOK && toOK {
			added, removed, changed := diffKeyedValues(fromFields, fromOrder, toFields, toOrder)
			if len(added)+len(removed)+len(changed) > 0 {
				d.BodyFieldsKnown = true
				d.BodyFieldsAdded, d.BodyFieldsRemoved, d.BodyFieldsChanged = added, removed, changed
			}
		}
	}

	return d
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parseFormPairs reads `a=1&b=2` into values keyed by name, preserving first-appearance order and
// folding duplicates into one comma-joined value. Used for both query strings and form bodies.
func parseFormPairs(s string) (map[string]string, []string) {
	values := map[string]string{}
	order := []string{}
	if strings.TrimSpace(s) == "" {
		return values, order
	}
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawVal, _ := strings.Cut(pair, "=")
		key := rawKey
		if decoded, err := url.QueryUnescape(rawKey); err == nil {
			key = decoded
		}
		val := rawVal
		if decoded, err := url.QueryUnescape(rawVal); err == nil {
			val = decoded
		}
		if key == "" {
			continue
		}
		if existing, seen := values[key]; seen {
			values[key] = existing + ", " + val
			continue
		}
		values[key] = val
		order = append(order, key)
	}
	return values, order
}

// parseBodyFields names the parts of a body when it has nameable parts. A JSON object and a form
// post both do; anything else does not, and saying "body changed" is better than inventing detail.
func parseBodyFields(body string) (map[string]string, []string, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, nil, false
	}

	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			values := make(map[string]string, len(obj))
			order := make([]string, 0, len(obj))
			for key, val := range obj {
				values[key] = string(val)
				order = append(order, key)
			}
			// JSON object key order is not preserved by the decoder, so sort for a stable label.
			sort.Strings(order)
			return values, order, true
		}
		return nil, nil, false
	}

	// A form body has no newlines and at least one `=`. Anything with a newline is more likely to be
	// multipart, XML or prose, none of which this is equipped to name.
	if strings.Contains(trimmed, "=") && !strings.ContainsAny(trimmed, "\n") &&
		!strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "<") {
		values, order := parseFormPairs(trimmed)
		if len(order) > 0 {
			return values, order, true
		}
	}
	return nil, nil, false
}

// diffKeyedValues returns added, removed and changed names. Order follows the child for added and
// changed, and the parent for removed, so the label reads in the order the operator sees them.
func diffKeyedValues(from map[string]string, fromOrder []string,
	to map[string]string, toOrder []string) (added, removed, changed []string) {

	for _, key := range toOrder {
		fromVal, existed := from[key]
		if !existed {
			added = append(added, key)
			continue
		}
		if fromVal != to[key] {
			changed = append(changed, key)
		}
	}
	for _, key := range fromOrder {
		if _, still := to[key]; !still {
			removed = append(removed, key)
		}
	}
	return added, removed, changed
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

// labelPart is one clause of a label in three lengths.
//
//	full     what it says on its own              "3 headers changed"
//	short    what it says with a clause after it  "3 headers"        -> "3 headers, body changed"
//	compact  what it says when the label is too long to fit
type labelPart struct {
	full    string
	short   string
	compact string
}

// describeVersionChange is the auto-label: what an operator would say they did, derived from the
// bytes rather than from a counter. Returns "" only when the two versions are identical, which the
// create path refuses before it ever gets here.
func describeVersionChange(parentRaw, parentBase, childRaw, childBase string) string {
	if strings.TrimSpace(parentRaw) == "" {
		// No parent to compare against, so the only honest label is what the request is.
		return summarizeRawRequest(childRaw)
	}
	return diffRawRequests(parentRaw, parentBase, childRaw, childBase).label()
}

func (d rawRequestDiff) label() string {
	if d.Identical {
		return ""
	}

	parts := []labelPart{}

	if d.BaseFrom != d.BaseTo {
		switch {
		case d.BaseFrom == "":
			parts = append(parts, labelPart{
				full: "base URL set to " + d.BaseTo, compact: "base URL set"})
		case d.BaseTo == "":
			parts = append(parts, labelPart{full: "base URL cleared", compact: "base URL cleared"})
		default:
			parts = append(parts, labelPart{
				full:    fmt.Sprintf("base URL %s to %s", d.BaseFrom, d.BaseTo),
				compact: "base URL changed"})
		}
	}

	if d.MethodFrom != d.MethodTo {
		from, to := d.MethodFrom, d.MethodTo
		if from == "" {
			from = "(none)"
		}
		if to == "" {
			to = "(none)"
		}
		parts = append(parts, labelPart{full: fmt.Sprintf("method %s to %s", from, to)})
	}

	if d.PathFrom != d.PathTo {
		full := fmt.Sprintf("path %s to %s", d.PathFrom, d.PathTo)
		if utf8.RuneCountInString(full) > 56 {
			full = "path changed"
		}
		parts = append(parts, labelPart{full: full, compact: "path changed"})
	}

	// A protocol version change is only worth a clause when both sides declared one; a request that
	// simply lost its request line is described by the method clause above.
	if d.ProtoFrom != d.ProtoTo && d.ProtoFrom != "" && d.ProtoTo != "" {
		parts = append(parts, labelPart{full: fmt.Sprintf("%s to %s", d.ProtoFrom, d.ProtoTo)})
	}

	if part, ok := namedChangePart(d.QueryAdded, d.QueryRemoved, d.QueryChanged,
		"query ", "query param", "query params", 1); ok {
		parts = append(parts, part)
	}

	// Two named headers still read as a sentence. Three do not, and three is where the count starts
	// carrying more information than the names would.
	if part, ok := namedChangePart(d.HeadersAdded, d.HeadersRemoved, d.HeadersChanged,
		"", "header", "headers", 2); ok {
		parts = append(parts, part)
	}

	switch {
	case d.BodyAdded:
		parts = append(parts, labelPart{full: "body added"})
	case d.BodyRemoved:
		parts = append(parts, labelPart{full: "body removed"})
	case d.BodyChanged:
		if d.BodyFieldsKnown {
			if part, ok := namedChangePart(d.BodyFieldsAdded, d.BodyFieldsRemoved, d.BodyFieldsChanged,
				"body field ", "body field", "body fields", 1); ok {
				parts = append(parts, part)
				break
			}
		}
		parts = append(parts, labelPart{full: "body changed"})
	}

	if len(parts) == 0 {
		// The bytes differ but nothing this differ names has moved.
		switch {
		case d.HeaderOrderChanged:
			return "header order changed"
		case collapseWhitespace(d.rawFrom) == collapseWhitespace(d.rawTo):
			return "whitespace changed"
		default:
			return "edited"
		}
	}

	label := joinLabelParts(parts, false)
	if utf8.RuneCountInString(label) <= replayVersionLabelMaxRunes {
		return label
	}
	label = joinLabelParts(parts, true)
	if utf8.RuneCountInString(label) <= replayVersionLabelMaxRunes {
		return label
	}
	return string([]rune(label)[:replayVersionLabelMaxRunes])
}

// joinLabelParts renders the clauses. Outside compact mode a clause that has a short form uses it
// whenever another clause follows, so "3 headers changed" plus "body changed" becomes
// "3 headers, body changed" rather than saying "changed" twice.
func joinLabelParts(parts []labelPart, compact bool) string {
	rendered := make([]string, 0, len(parts))
	for i, part := range parts {
		text := part.full
		if compact {
			if part.compact != "" {
				text = part.compact
			}
		} else if i < len(parts)-1 && part.short != "" {
			text = part.short
		}
		rendered = append(rendered, text)
	}
	return strings.Join(rendered, ", ")
}

// namedChangePart names the things that changed while there are few enough of them to name, and
// counts them once there are not.
func namedChangePart(added, removed, changed []string, prefix, singular, plural string,
	nameLimit int) (labelPart, bool) {

	total := len(added) + len(removed) + len(changed)
	if total == 0 {
		return labelPart{}, false
	}

	if total <= nameLimit {
		phrases := make([]string, 0, total)
		for _, name := range changed {
			phrases = append(phrases, prefix+name+" edited")
		}
		for _, name := range added {
			phrases = append(phrases, prefix+name+" added")
		}
		for _, name := range removed {
			phrases = append(phrases, prefix+name+" removed")
		}
		full := strings.Join(phrases, ", ")
		compact := full
		if total > 1 {
			compact = fmt.Sprintf("%d %s", total, plural)
		}
		return labelPart{full: full, compact: compact}, true
	}

	noun := plural
	if total == 1 {
		noun = singular
	}
	return labelPart{
		full:    fmt.Sprintf("%d %s changed", total, noun),
		short:   fmt.Sprintf("%d %s", total, noun),
		compact: fmt.Sprintf("%d %s", total, noun),
	}, true
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// summarizeRawRequest is the one-line identity of a request: what it is, rather than what changed.
// The version column needs it next to the label, because "Cookie edited" does not say which request
// had its cookie edited.
func summarizeRawRequest(raw string) string {
	p := parseRawRequestParts(raw)
	if !p.HasLine {
		return "request"
	}
	target := p.Target
	if target == "" {
		target = "/"
	}
	if utf8.RuneCountInString(target) > 60 {
		target = string([]rune(target)[:60])
	}
	return strings.TrimSpace(p.Method + " " + target)
}
