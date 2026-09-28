package utils

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Manual crawl capture is driven by the browser extension. Everything here is deliberately
// stateless: the extension owns the session id and sends it with every request. The previous
// implementation kept the active session in a package-level global, which meant an API restart
// (or a second target) silently voided an in-progress recording and every capture 400'd.
//
// Liveness is tracked with `last_heartbeat_at` rather than status alone, because an MV3 service
// worker can be terminated by the browser at any time. A session whose heartbeat has gone quiet is
// reported as not live so the UI stops claiming it is recording.

// A session is considered live if it has heartbeat within this window. The extension beats every
// 20s, so this tolerates roughly four missed beats before the session is treated as dead.
const manualCrawlHeartbeatTimeout = 90 * time.Second

type ManualCrawlCapture struct {
	ID              string                 `json:"id"`
	SessionID       string                 `json:"session_id"`
	ScopeTargetID   string                 `json:"scope_target_id"`
	URL             string                 `json:"url"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"status_code"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	PostData        string                 `json:"post_data,omitempty"`
	ResponseBody    string                 `json:"response_body,omitempty"`
	GetParams       map[string]interface{} `json:"get_params,omitempty"`
	PostParams      map[string]interface{} `json:"post_params,omitempty"`
	BodyType        string                 `json:"body_type,omitempty"`
	TabID           *int                   `json:"tab_id,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	MimeType        string                 `json:"mime_type"`
	// Provenance and richer detail from the multi-source extension. `Sources` names which of
	// webrequest / hook / debugger contributed, which is how a metadata-only record is told apart
	// from one carrying real request and response bodies.
	// Direct means the capture is on the scope target's own host; adjacent means any other in-scope
	// host, which is where an application's API usually lives.
	IsDirect              bool          `json:"is_direct"`
	Sources               []string      `json:"sources"`
	GraphQLOperation      string        `json:"graphql_operation,omitempty"`
	ResourceType          string        `json:"resource_type,omitempty"`
	Initiator             string        `json:"initiator,omitempty"`
	RedirectChain         []interface{} `json:"redirect_chain,omitempty"`
	Error                 string        `json:"error,omitempty"`
	DurationMs            int           `json:"duration_ms"`
	RequestBodyTruncated  bool          `json:"request_body_truncated"`
	ResponseBodyTruncated bool          `json:"response_body_truncated"`

	// Content-addressed response body. A rendered-media response (image, video, audio, font) has
	// no text form, so its bytes live in manual_crawl_body_blobs keyed by this digest and the row
	// points at them. Hundreds of navigations pulling the same sprite cost one copy.
	//
	// ResponseBodySHA256 is the digest of the bytes actually stored, recomputed by the framework
	// from what arrived, so it is always checkable. ResponseBodyBytes is the size ON THE WIRE:
	// when ResponseBodyCapped is set, the stored bytes are only the leading part of an object that
	// big, and the digest names the prefix, not the whole object.
	ResponseBodySHA256      string `json:"response_body_sha256,omitempty"`
	ResponseBodyBytes       int64  `json:"response_body_bytes,omitempty"`
	ResponseBodyCapped      bool   `json:"response_body_capped,omitempty"`
	ResponseBodyBlobMissing bool   `json:"response_body_blob_missing,omitempty"`

	// What storing this row changed about the bytes the target sent. sanitizeForPostgres has to
	// strip NUL bytes and invalid UTF-8 because a Postgres text column cannot hold them, but a
	// reader looking at a replacement character could not tell whether the target sent it or
	// whether we put it there. StorageOriginals maps an altered field to the digest of its
	// pre-sanitiser bytes, which are kept in manual_crawl_body_blobs.
	StorageAltered       bool              `json:"storage_altered,omitempty"`
	StorageAlteredFields []string          `json:"storage_altered_fields,omitempty"`
	StorageAlteredBytes  int64             `json:"storage_altered_bytes,omitempty"`
	StorageOriginals     map[string]string `json:"storage_originals,omitempty"`
}

type ManualCrawlSession struct {
	ID                 string         `json:"id"`
	ScopeTargetID      string         `json:"scope_target_id"`
	TargetURL          string         `json:"target_url"`
	Status             string         `json:"status"`
	StartedAt          time.Time      `json:"started_at"`
	EndedAt            *time.Time     `json:"ended_at,omitempty"`
	LastHeartbeatAt    *time.Time     `json:"last_heartbeat_at,omitempty"`
	RequestCount       int            `json:"request_count"`
	EndpointCount      int            `json:"endpoint_count"`
	IsLive             bool           `json:"is_live"`
	ObservedOutOfScope map[string]int `json:"observed_out_of_scope,omitempty"`
}

type CaptureRequest struct {
	SessionID string `json:"sessionId"`
	// A stable per-capture identity minted by the extension at enqueue time and persisted with the
	// queue entry, so a batch that is re-sent (a lost/timed-out 200 after the rows already committed,
	// or a worker restart mid-flush) is deduped by the primary key instead of inserting duplicate
	// rows. Empty from an older extension build; the server then falls back to a fresh uuid.
	CaptureUID      string                 `json:"captureUid,omitempty"`
	URL             string                 `json:"url"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	StatusCode      int                    `json:"statusCode"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"responseHeaders"`
	PostData        string                 `json:"postData,omitempty"`
	ResponseBody    string                 `json:"responseBody,omitempty"`
	GetParams       map[string]interface{} `json:"getParams,omitempty"`
	PostParams      map[string]interface{} `json:"postParams,omitempty"`
	BodyType        string                 `json:"bodyType,omitempty"`
	TabID           *int                   `json:"tabId,omitempty"`
	Timestamp       string                 `json:"timestamp"`
	MimeType        string                 `json:"mimeType"`

	Sources               []string      `json:"sources,omitempty"`
	GraphQLOperation      string        `json:"graphqlOperation,omitempty"`
	ResourceType          string        `json:"resourceType,omitempty"`
	Initiator             string        `json:"initiator,omitempty"`
	RedirectChain         []interface{} `json:"redirectChain,omitempty"`
	Error                 string        `json:"error,omitempty"`
	DurationMs            int           `json:"durationMs,omitempty"`
	RequestBodyTruncated  bool          `json:"requestBodyTruncated,omitempty"`
	ResponseBodyTruncated bool          `json:"responseBodyTruncated,omitempty"`

	// A response body with no text form. The extension sends the bytes base64 encoded the first
	// time it sees a given digest in a session and sends the reference alone afterwards, because a
	// page load pulls the same logo, sprite and font on every navigation.
	ResponseBodyBlob *CaptureBodyBlob `json:"responseBodyBlob,omitempty"`
}

// CaptureBodyBlob is a response body carried out of band from the row. Base64 may be empty, which
// means the extension believes the framework already holds these bytes under this digest; the row
// still records the reference, and the framework flags it if the bytes turn out not to be here.
type CaptureBodyBlob struct {
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes,omitempty"`
	Capped   bool   `json:"capped,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Base64   string `json:"base64,omitempty"`
}

// storedBlob is one row of manual_crawl_body_blobs. SHA256 is the digest of Content, so it is
// recomputable from what is stored. ByteSize is the size on the wire, which is larger than
// StoredBytes exactly when Capped is set.
type storedBlob struct {
	SHA256      string
	ByteSize    int64
	StoredBytes int64
	Capped      bool
	MimeType    string
	Content     []byte
}

type BatchCaptureRequest struct {
	SessionID string           `json:"sessionId"`
	Captures  []CaptureRequest `json:"captures"`
}

type StartCaptureRequest struct {
	TargetURL     string `json:"targetUrl"`
	ScopeTargetID string `json:"scopeTargetId"`
}

// SessionStatsRequest is the payload for heartbeat and stop. Stats are advisory only: the
// authoritative counts are recomputed from manual_crawl_captures so a session that dies without a
// clean stop still reports the right numbers.
type SessionStatsRequest struct {
	SessionID string `json:"sessionId"`
	Stats     struct {
		RequestCount  int `json:"requestCount"`
		EndpointCount int `json:"endpointCount"`
	} `json:"stats"`
	// Hosts the extension rejected as out of scope. Surfaced in the results modal so "where is my
	// API traffic" is answerable from the framework rather than only from the extension popup.
	ObservedOutOfScope map[string]int `json:"observedOutOfScope,omitempty"`
}

// sessionLookupError distinguishes "this session id is unknown" from "this session was already
// stopped" so the extension can react differently (drop the queue vs stop recording).
type sessionLookupError struct {
	code    string
	status  int
	message string
}

func (e *sessionLookupError) Error() string { return e.message }

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "ars0n-framework",
	})
}

// resolveActiveCrawlSession validates a session id and returns the scope target it belongs to.
func resolveActiveCrawlSession(sessionID string) (string, error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", &sessionLookupError{"session_id_required", http.StatusBadRequest, "sessionId is required"}
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return "", &sessionLookupError{"session_not_found", http.StatusNotFound, "Unknown capture session"}
	}

	var scopeTargetID, status string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id, status FROM manual_crawl_sessions WHERE id = $1`, sessionID).
		Scan(&scopeTargetID, &status)
	if err != nil {
		return "", &sessionLookupError{"session_not_found", http.StatusNotFound, "Unknown capture session"}
	}
	if status != "active" {
		return "", &sessionLookupError{"session_not_active", http.StatusConflict, "Capture session is no longer active"}
	}
	return scopeTargetID, nil
}

func respondSessionError(w http.ResponseWriter, err error) {
	if lookupErr, ok := err.(*sessionLookupError); ok {
		writeJSONError(w, lookupErr.status, lookupErr.code, lookupErr.message)
		return
	}
	writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

func StartManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req StartCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if req.TargetURL == "" {
		writeJSONError(w, http.StatusBadRequest, "target_url_required", "targetUrl is required")
		return
	}
	if req.ScopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scopeTargetId is required")
		return
	}

	var scopeTargetExists bool
	err := dbPool.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1 AND type = 'URL')",
		req.ScopeTargetID).Scan(&scopeTargetExists)

	if err != nil || !scopeTargetExists {
		log.Printf("[MANUAL-CRAWL] Invalid scope target ID: %s", req.ScopeTargetID)
		writeJSONError(w, http.StatusBadRequest, "scope_target_not_found", "Invalid scopeTargetId - target not found")
		return
	}

	// Close out any session still marked active for this target. Multiple targets can record
	// concurrently, but a single target recording twice is always a stale row from a dead worker.
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE manual_crawl_sessions
		SET status = 'abandoned', ended_at = COALESCE(last_heartbeat_at, started_at)
		WHERE scope_target_id = $1 AND status = 'active'`, req.ScopeTargetID); err != nil {
		log.Printf("[MANUAL-CRAWL] Failed to close previous sessions for %s: %v", req.ScopeTargetID, err)
	}

	sessionID := uuid.New().String()
	now := time.Now()

	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO manual_crawl_sessions (id, scope_target_id, target_url, status, started_at, last_heartbeat_at)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		sessionID, req.ScopeTargetID, req.TargetURL, "active", now)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error creating session: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create capture session")
		return
	}

	log.Printf("[MANUAL-CRAWL] Started session %s for target %s", sessionID, req.TargetURL)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"sessionId":        sessionID,
		"scopeTargetId":    req.ScopeTargetID,
		"heartbeatSeconds": int(manualCrawlHeartbeatTimeout.Seconds()) / 3,
	})
}

// CaptureManualCrawlRequest stores a single capture. Kept for compatibility with older extension
// builds; the current extension posts batches to /manual-crawl/capture/batch.
func CaptureManualCrawlRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req CaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding capture request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	scopeTargetID, err := resolveActiveCrawlSession(req.SessionID)
	if err != nil {
		respondSessionError(w, err)
		return
	}

	stored, _, missingBlobs, err := insertManualCrawlCaptures(req.SessionID, scopeTargetID, []CaptureRequest{req})
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error storing capture: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store capture")
		return
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error refreshing session counts: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"stored":        stored,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
		// Digests the capture referenced but the framework does not hold, so the extension can stop
		// assuming those bytes are already here and send them again next time it sees them.
		"missingBlobs": missingBlobs,
	})
}

// CaptureManualCrawlBatch stores many captures in one round trip. The extension queues captures
// locally and flushes them here, so a slow or briefly unavailable API costs latency, not data.
func CaptureManualCrawlBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchCaptureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding batch capture request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	scopeTargetID, err := resolveActiveCrawlSession(req.SessionID)
	if err != nil {
		respondSessionError(w, err)
		return
	}

	if len(req.Captures) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "stored": 0})
		return
	}

	stored, dropped, missingBlobs, err := insertManualCrawlCaptures(req.SessionID, scopeTargetID, req.Captures)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error storing capture batch: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store captures")
		return
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error refreshing session counts: %v", err)
	}

	// received - stored - dropped is the deduplicated remainder: rows that were already committed
	// (an idempotent re-POST after a lost 200 / a resumed queue), NOT failures. Only `dropped` rows
	// genuinely could not be stored, so `rejected` reports only those — otherwise a clean re-flush
	// would light up the operator's failure counter and a false "could not be stored" banner.
	deduplicated := len(req.Captures) - stored - dropped
	if deduplicated < 0 {
		deduplicated = 0
	}
	if dropped > 0 {
		log.Printf("[MANUAL-CRAWL] Stored %d/%d captures for session %s (%d unstorable, %d already stored)",
			stored, len(req.Captures), req.SessionID, dropped, deduplicated)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"stored":        stored,
		"received":      len(req.Captures),
		"rejected":      dropped,
		"deduplicated":  deduplicated,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
		// Digests these captures referenced without sending the bytes, which the framework turns
		// out not to hold. The extension drops them from its "already uploaded" set so the next
		// response carrying those bytes ships them rather than assuming they are here.
		"missingBlobs": missingBlobs,
	})
}

// PostgreSQL text and jsonb columns cannot hold a NUL byte, and captured bodies genuinely contain
// them (a response with a texty content-type but binary payload, or JSON carrying an escaped
// null). A single such byte used to fail the whole multi-row INSERT, silently destroying every
// other capture batched with it. Strip them, and drop anything else that is not valid UTF-8.
func sanitizeForPostgres(s string) string {
	cleaned, _ := sanitizeForPostgresChecked(s)
	return cleaned
}

// sanitizeForPostgresChecked is the same transformation, reporting how many WIRE BYTES it changed.
// A stored body is not the body the target sent whenever that count is non-zero, and an operator
// looking at a replacement character has no other way to tell whether the target sent it or
// whether we put it there. On a binary payload behind a texty content-type that is the difference
// between a finding and a rendering artefact.
//
// A replacement character that really was on the wire decodes as a 3-byte rune and is left alone
// and NOT counted; only a byte that is not valid UTF-8 on its own decodes as a 1-byte RuneError
// and gets replaced.
func sanitizeForPostgresChecked(s string) (string, int) {
	if s == "" {
		return s, 0
	}
	if !strings.ContainsRune(s, 0) && utf8.ValidString(s) {
		return s, 0
	}

	var b strings.Builder
	b.Grow(len(s))
	altered := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == 0:
			// dropped: not representable in a Postgres text column
			altered++
		case r == utf8.RuneError && size == 1:
			b.WriteRune('�')
			altered++
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String(), altered
}

// sanitizeJSONValue walks a decoded JSON value and cleans every string it contains, so header maps
// and parameter maps are safe to store as jsonb.
func sanitizeJSONValue(v interface{}) interface{} {
	cleaned, _ := sanitizeJSONValueChecked(v)
	return cleaned
}

func sanitizeJSONValueChecked(v interface{}) (interface{}, int) {
	switch typed := v.(type) {
	case string:
		cleaned, altered := sanitizeForPostgresChecked(typed)
		return cleaned, altered
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		altered := 0
		for key, value := range typed {
			cleanKey, keyAltered := sanitizeForPostgresChecked(key)
			cleanValue, valueAltered := sanitizeJSONValueChecked(value)
			out[cleanKey] = cleanValue
			altered += keyAltered + valueAltered
		}
		return out, altered
	case []interface{}:
		out := make([]interface{}, len(typed))
		altered := 0
		for i, value := range typed {
			cleanValue, valueAltered := sanitizeJSONValueChecked(value)
			out[i] = cleanValue
			altered += valueAltered
		}
		return out, altered
	default:
		return v, 0
	}
}

func sanitizeJSONMap(m map[string]interface{}) map[string]interface{} {
	cleaned, _ := sanitizeJSONValue(orEmptyMap(m)).(map[string]interface{})
	if cleaned == nil {
		return map[string]interface{}{}
	}
	return cleaned
}

// captureAlterations records, per capture row, exactly what storing it changed. Every field goes
// through it, so the row can say which fields were altered, by how many bytes, and where the
// pre-sanitiser bytes are.
type captureAlterations struct {
	fields    []string
	bytes     int
	originals map[string]string
	blobs     map[string]storedBlob
}

// text sanitises one text column and records the alteration if there was one, keeping the original
// bytes. Rows where the sanitiser actually changed something are the rows where the operator most
// needs the wire truth, and they are rare enough that keeping the original is cheap.
func (a *captureAlterations) text(field, value string) string {
	cleaned, altered := sanitizeForPostgresChecked(value)
	if altered == 0 {
		return cleaned
	}
	a.note(field, altered, []byte(value))
	return cleaned
}

// jsonMap sanitises one jsonb column. No original is kept: encoding/json rewrites invalid UTF-8 on
// the way out, so there is no lossless byte form of the original map to point at. The fact and the
// count are recorded; claiming an original we cannot reproduce would be worse than claiming none.
func (a *captureAlterations) jsonMap(field string, m map[string]interface{}) []byte {
	cleanedValue, altered := sanitizeJSONValueChecked(orEmptyMap(m))
	cleaned, _ := cleanedValue.(map[string]interface{})
	if cleaned == nil {
		cleaned = map[string]interface{}{}
	}
	out, _ := json.Marshal(cleaned)
	if altered > 0 {
		a.note(field, altered, nil)
	}
	return out
}

func (a *captureAlterations) jsonValue(field string, v interface{}) []byte {
	cleaned, altered := sanitizeJSONValueChecked(v)
	out, _ := json.Marshal(cleaned)
	if altered > 0 {
		a.note(field, altered, nil)
	}
	return out
}

func (a *captureAlterations) note(field string, bytes int, original []byte) {
	a.fields = append(a.fields, field)
	a.bytes += bytes
	if original == nil {
		return
	}
	digest := digestOf(original)
	if a.originals == nil {
		a.originals = map[string]string{}
	}
	a.originals[field] = digest
	if a.blobs == nil {
		a.blobs = map[string]storedBlob{}
	}
	a.blobs[digest] = storedBlob{
		SHA256:      digest,
		ByteSize:    int64(len(original)),
		StoredBytes: int64(len(original)),
		MimeType:    "application/octet-stream",
		Content:     original,
	}
}

func (a *captureAlterations) altered() bool { return len(a.fields) > 0 }

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// decodeCaptureBlob turns what the extension sent into a row of manual_crawl_body_blobs. The digest
// is RECOMPUTED from the bytes that arrived rather than taken on trust, so a stored blob always
// hashes to the name it is filed under; a declared digest that disagrees means the payload was
// corrupted in transit and is refused.
func decodeCaptureBlob(blob *CaptureBodyBlob) (storedBlob, error) {
	if blob == nil {
		return storedBlob{}, fmt.Errorf("no blob")
	}

	declared := strings.ToLower(strings.TrimSpace(blob.SHA256))

	// A reference with no bytes: the extension has shipped these bytes earlier in the session and
	// believes the framework still holds them. The row records the reference either way.
	if blob.Base64 == "" {
		if declared == "" {
			return storedBlob{}, fmt.Errorf("blob reference has neither bytes nor a digest")
		}
		return storedBlob{
			SHA256:   declared,
			ByteSize: blob.Bytes,
			Capped:   blob.Capped,
			MimeType: strings.TrimSpace(blob.MimeType),
		}, nil
	}

	content, err := base64.StdEncoding.DecodeString(blob.Base64)
	if err != nil {
		return storedBlob{}, fmt.Errorf("blob is not valid base64: %w", err)
	}

	digest := digestOf(content)
	if declared != "" && declared != digest {
		return storedBlob{}, fmt.Errorf("blob digest mismatch: declared %s, bytes hash to %s", declared, digest)
	}

	wireSize := blob.Bytes
	if wireSize < int64(len(content)) {
		wireSize = int64(len(content))
	}

	return storedBlob{
		SHA256:      digest,
		ByteSize:    wireSize,
		StoredBytes: int64(len(content)),
		Capped:      blob.Capped,
		MimeType:    strings.TrimSpace(blob.MimeType),
		Content:     content,
	}, nil
}

// storeCaptureBlobs writes bodies content addressed, so the sprite pulled on every navigation of a
// session costs one copy however many rows point at it. A digest already present is left alone:
// the bytes under a given digest are by definition the same bytes.
func storeCaptureBlobs(blobs map[string]storedBlob) error {
	if len(blobs) == 0 {
		return nil
	}

	digests := make([]string, 0, len(blobs))
	for digest := range blobs {
		digests = append(digests, digest)
	}
	sort.Strings(digests)

	valueGroups := make([]string, 0, len(digests))
	args := make([]interface{}, 0, len(digests)*6)
	for _, digest := range digests {
		blob := blobs[digest]
		if blob.Content == nil {
			continue
		}
		base := len(args)
		valueGroups = append(valueGroups, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6))
		args = append(args, blob.SHA256, blob.ByteSize, blob.StoredBytes, blob.Capped,
			sanitizeForPostgres(blob.MimeType), blob.Content)
	}
	if len(valueGroups) == 0 {
		return nil
	}

	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO manual_crawl_body_blobs (sha256, byte_size, stored_bytes, capped, mime_type, content)
		VALUES `+strings.Join(valueGroups, ", ")+`
		ON CONFLICT (sha256) DO NOTHING`, args...)
	return err
}

func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// mediaContentTypes are the ones a stored blob may be served back under. Anything else is served as
// octet-stream: the bytes are handed over in full either way, but a captured text/html body must
// not be rendered as a page by the framework's own origin.
func servableBlobContentType(mimeType string) string {
	mime := strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0]))
	for _, prefix := range []string{"image/", "video/", "audio/", "font/"} {
		if strings.HasPrefix(mime, prefix) {
			return mime
		}
	}
	return "application/octet-stream"
}

// serveCaptureBlob hands over the bytes of one stored body. The digest has to be referenced by a
// capture in the named session or target, so the URL means something and a blob cannot be fetched
// from a context that never saw it.
func serveCaptureBlob(w http.ResponseWriter, scopeColumn, scopeValue, digest string) {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !isHexDigest(digest) {
		writeJSONError(w, http.StatusBadRequest, "invalid_digest", "blob must be a 64 character hex sha256")
		return
	}

	var referenced bool
	err := dbPool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM manual_crawl_captures c
			WHERE c.`+scopeColumn+` = $1
			  AND (c.response_body_sha256 = $2
			       OR EXISTS (
			            SELECT 1 FROM jsonb_each_text(COALESCE(c.storage_originals, '{}'::jsonb)) o
			            WHERE o.value = $2))
		)`, scopeValue, digest).Scan(&referenced)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error checking blob reference: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to look up body")
		return
	}
	if !referenced {
		writeJSONError(w, http.StatusNotFound, "blob_not_referenced",
			"No capture here references that body digest")
		return
	}

	var content []byte
	var mimeType string
	var capped bool
	var byteSize, storedBytes int64
	err = dbPool.QueryRow(context.Background(), `
		SELECT content, COALESCE(mime_type, ''), COALESCE(capped, false), byte_size, stored_bytes
		FROM manual_crawl_body_blobs WHERE sha256 = $1`, digest).
		Scan(&content, &mimeType, &capped, &byteSize, &storedBytes)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "blob_missing",
			"The capture references this body but the framework does not hold the bytes")
		return
	}

	w.Header().Set("Content-Type", servableBlobContentType(mimeType))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	w.Header().Set("Content-Disposition", "inline")
	// Everything a reader needs to judge what they are looking at, without a second request.
	w.Header().Set("X-Capture-Body-Sha256", digest)
	w.Header().Set("X-Capture-Body-Wire-Bytes", fmt.Sprintf("%d", byteSize))
	w.Header().Set("X-Capture-Body-Stored-Bytes", fmt.Sprintf("%d", storedBytes))
	if capped {
		w.Header().Set("X-Capture-Body-Capped", "true")
	}
	w.Write(content)
}

// includeMediaBodies says whether a listing should carry blob-backed bodies inline. Off by default
// because a target's whole capture set would otherwise grow by every image on every page it serves;
// the bytes are one request away at ?blob=<digest>, and the digest, both sizes and the capped flag
// are on the row either way, so nothing is hidden by the default.
func includeMediaBodies(r *http.Request) bool {
	value := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("include_media")))
	return value == "1" || value == "true" || value == "yes"
}

// attachBlobBodies fills in response_body from the blob store for rows whose body has no text form.
// Off unless asked for: the digest, the size and the capped flag are always on the row, and the
// bytes are one request away at ?blob=<digest>, which is also the form that lets an operator LOOK
// at the photo instead of reading base64.
func attachBlobBodies(captures []ManualCrawlCapture, include bool) {
	if !include {
		return
	}
	digests := map[string]bool{}
	for i := range captures {
		if captures[i].ResponseBodySHA256 != "" && captures[i].ResponseBody == "" {
			digests[captures[i].ResponseBodySHA256] = true
		}
	}
	if len(digests) == 0 {
		return
	}

	rows, err := dbPool.Query(context.Background(),
		`SELECT sha256, content FROM manual_crawl_body_blobs WHERE sha256 = ANY($1)`, sortedDigests(digests))
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error loading body blobs: %v", err)
		return
	}
	defer rows.Close()

	bodies := map[string]string{}
	for rows.Next() {
		var digest string
		var content []byte
		if err := rows.Scan(&digest, &content); err == nil {
			// Same spelling the extension uses for a body that is bytes rather than text, so a
			// reader never has to know which source produced a given capture.
			bodies[digest] = "base64," + base64.StdEncoding.EncodeToString(content)
		}
	}

	for i := range captures {
		if body, ok := bodies[captures[i].ResponseBodySHA256]; ok && captures[i].ResponseBody == "" {
			captures[i].ResponseBody = body
		}
	}
}

// knownBlobDigests reports which of these digests the framework actually holds. A capture that
// references bytes nobody has is recorded as such rather than silently pointing at nothing.
func knownBlobDigests(digests []string) (map[string]bool, error) {
	known := map[string]bool{}
	if len(digests) == 0 {
		return known, nil
	}
	rows, err := dbPool.Query(context.Background(),
		`SELECT sha256 FROM manual_crawl_body_blobs WHERE sha256 = ANY($1)`, digests)
	if err != nil {
		return known, err
	}
	defer rows.Close()
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err == nil {
			known[digest] = true
		}
	}
	return known, nil
}

// insertManualCrawlCaptures writes captures with a single multi-row INSERT, falling back to
// one-row-at-a-time on failure so a single unstorable capture costs one record instead of the
// whole batch.
// Returns (stored, dropped, missing, err): stored is rows newly written (ON CONFLICT skips are NOT
// counted, so an idempotent re-POST reports stored=0); dropped is rows that genuinely could not be
// stored even on the individual retry. received - stored - dropped is the deduplicated remainder,
// which the caller must NOT report as a failure.
func insertManualCrawlCaptures(sessionID, scopeTargetID string, captures []CaptureRequest) (int, int, []string, error) {
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)

	stored, missing, err := insertCaptureBatch(sessionID, scopeTargetID, targetDomain, captures)
	if err == nil {
		// Whole batch went in as one statement; anything not stored was an ON CONFLICT dedup, not a
		// failure, so nothing is "dropped".
		return stored, 0, missing, nil
	}

	log.Printf("[MANUAL-CRAWL] Batch insert failed (%v); retrying %d captures individually", err, len(captures))

	inserted := 0
	dropped := 0
	allMissing := map[string]bool{}
	var lastErr error
	for _, capture := range captures {
		one, oneMissing, oneErr := insertCaptureBatch(sessionID, scopeTargetID, targetDomain, []CaptureRequest{capture})
		if oneErr != nil {
			lastErr = oneErr
			dropped++
			log.Printf("[MANUAL-CRAWL] Dropping unstorable capture %s %s: %v", capture.Method, capture.URL, oneErr)
			continue
		}
		// one == 0 here means the row was an ON CONFLICT dedup, not stored and not dropped.
		inserted += one
		for _, digest := range oneMissing {
			allMissing[digest] = true
		}
	}

	// Nothing got in and we hit an error: surface it as a 5xx so the client keeps the batch and
	// retries (the error may be a transient DB hiccup affecting the whole batch, not per-row).
	if inserted == 0 && lastErr != nil {
		return 0, 0, nil, lastErr
	}
	return inserted, dropped, sortedDigests(allMissing), nil
}

func sortedDigests(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// captureRow is one prepared row. Built in a first pass so the blobs a batch references can be
// stored and checked for presence BEFORE the rows that point at them are written: a row must never
// claim bytes the framework does not hold.
type captureRow struct {
	args       []interface{}
	blobDigest string
	blobBytes  int64
	blobCapped bool
}

func insertCaptureBatch(sessionID, scopeTargetID, targetDomain string, captures []CaptureRequest) (int, []string, error) {
	const columnCount = 35

	rows := make([]captureRow, 0, len(captures))
	blobs := map[string]storedBlob{}

	for _, capture := range captures {
		if strings.TrimSpace(capture.URL) == "" {
			continue
		}

		timestamp, err := time.Parse(time.RFC3339, capture.Timestamp)
		if err != nil {
			timestamp = time.Now()
		}

		method := strings.ToUpper(strings.TrimSpace(capture.Method))
		if method == "" {
			method = "GET"
		}
		// The column is VARCHAR(10); a malformed method must not fail the whole batch.
		if len(method) > 10 {
			method = method[:10]
		}

		endpoint := capture.Endpoint
		if endpoint == "" {
			endpoint = capture.URL
		}

		// Same host as the scope target is direct; anything else in scope is adjacent. Matches the
		// rule the crawlers and the consolidation step already use.
		isDirect := false
		if parsed, perr := url.Parse(capture.URL); perr == nil && targetDomain != "" {
			isDirect = strings.EqualFold(parsed.Hostname(), targetDomain)
		}

		// Every field goes through the tracker, so the row can say exactly what storing it changed.
		var alt captureAlterations

		urlValue := alt.text("url", capture.URL)
		endpointValue := alt.text("endpoint", endpoint)
		postData := alt.text("post_data", capture.PostData)
		responseBody := alt.text("response_body", capture.ResponseBody)
		bodyType := alt.text("body_type", capture.BodyType)
		mimeType := alt.text("mime_type", capture.MimeType)
		graphqlOperation := alt.text("graphql_operation", capture.GraphQLOperation)
		resourceType := alt.text("resource_type", capture.ResourceType)
		initiator := alt.text("initiator", capture.Initiator)
		captureError := alt.text("error", capture.Error)

		headersJSON := alt.jsonMap("headers", capture.Headers)
		responseHeadersJSON := alt.jsonMap("response_headers", capture.ResponseHeaders)
		getParamsJSON := alt.jsonMap("get_params", capture.GetParams)
		postParamsJSON := alt.jsonMap("post_params", capture.PostParams)

		redirectChain := capture.RedirectChain
		if redirectChain == nil {
			redirectChain = []interface{}{}
		}
		redirectChainJSON := alt.jsonValue("redirect_chain", redirectChain)

		sources := capture.Sources
		if sources == nil {
			sources = []string{}
		}

		// A body with no text form. The bytes are content addressed, so hundreds of navigations
		// pulling the same sprite cost one copy while every row still points at them.
		blobDigest := ""
		var blobBytes int64
		blobCapped := false
		if capture.ResponseBodyBlob != nil {
			blob, blobErr := decodeCaptureBlob(capture.ResponseBodyBlob)
			if blobErr != nil {
				// The reference is still recorded so the row is honest about what it was carrying;
				// it will be flagged as pointing at bytes we do not hold.
				blobDigest = strings.ToLower(strings.TrimSpace(capture.ResponseBodyBlob.SHA256))
				blobBytes = capture.ResponseBodyBlob.Bytes
				blobCapped = capture.ResponseBodyBlob.Capped
				log.Printf("[MANUAL-CRAWL] Rejecting body blob for %s %s: %v", method, capture.URL, blobErr)
			} else {
				if blob.MimeType == "" {
					blob.MimeType = mimeType
				}
				blobDigest = blob.SHA256
				blobBytes = blob.ByteSize
				blobCapped = blob.Capped
				if blob.Content != nil {
					blobs[blob.SHA256] = blob
				}
			}
		}

		for digest, blob := range alt.blobs {
			blobs[digest] = blob
		}

		originalsJSON, _ := json.Marshal(orEmptyStringMap(alt.originals))
		alteredFields := alt.fields
		if alteredFields == nil {
			alteredFields = []string{}
		}

		// Prefer the client-supplied stable id (so a re-POST deduplicates on the primary key); fall
		// back to a fresh uuid for an older build that sends none or a malformed value.
		rowID := uuid.New().String()
		if trimmed := strings.TrimSpace(capture.CaptureUID); trimmed != "" {
			if parsed, err := uuid.Parse(trimmed); err == nil {
				rowID = parsed.String()
			}
		}

		rows = append(rows, captureRow{
			blobDigest: blobDigest,
			blobBytes:  blobBytes,
			blobCapped: blobCapped,
			args: []interface{}{
				rowID,
				sessionID,
				scopeTargetID,
				urlValue,
				endpointValue,
				method,
				capture.StatusCode,
				headersJSON,
				responseHeadersJSON,
				postData,
				responseBody,
				getParamsJSON,
				postParamsJSON,
				bodyType,
				capture.TabID,
				timestamp,
				mimeType,
				sources,
				graphqlOperation,
				resourceType,
				initiator,
				redirectChainJSON,
				captureError,
				capture.DurationMs,
				capture.RequestBodyTruncated,
				capture.ResponseBodyTruncated,
				isDirect,
				blobDigest,
				blobBytes,
				blobCapped,
				false, // response_body_blob_missing, resolved below
				alt.altered(),
				alteredFields,
				int64(alt.bytes),
				originalsJSON,
			},
		})
	}

	if len(rows) == 0 {
		return 0, nil, nil
	}

	if err := storeCaptureBlobs(blobs); err != nil {
		// Losing the bytes must not lose the rows. The captures are still stored and the ones that
		// referenced those bytes are flagged, which is visible rather than silent.
		log.Printf("[MANUAL-CRAWL] Failed to store %d body blob(s): %v", len(blobs), err)
	}

	referenced := map[string]bool{}
	for _, row := range rows {
		if row.blobDigest != "" {
			referenced[row.blobDigest] = true
		}
	}
	known, err := knownBlobDigests(sortedDigests(referenced))
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Could not check body blob presence: %v", err)
		// Unknown is not the same as missing; do not flag rows on a failed check.
		for digest := range referenced {
			known[digest] = true
		}
	}

	missing := map[string]bool{}
	valueGroups := make([]string, 0, len(rows))
	args := make([]interface{}, 0, len(rows)*columnCount)
	for _, row := range rows {
		if row.blobDigest != "" && !known[row.blobDigest] {
			row.args[30] = true
			missing[row.blobDigest] = true
		}
		base := len(args)
		placeholders := make([]string, columnCount)
		for i := 0; i < columnCount; i++ {
			placeholders[i] = fmt.Sprintf("$%d", base+i+1)
		}
		valueGroups = append(valueGroups, "("+strings.Join(placeholders, ", ")+")")
		args = append(args, row.args...)
	}

	query := `
		INSERT INTO manual_crawl_captures
		(id, session_id, scope_target_id, url, endpoint, method, status_code, headers, response_headers,
		 post_data, response_body, get_params, post_params, body_type, tab_id, timestamp, mime_type,
		 sources, graphql_operation, resource_type, initiator, redirect_chain, error, duration_ms,
		 request_body_truncated, response_body_truncated, is_direct,
		 response_body_sha256, response_body_bytes, response_body_capped, response_body_blob_missing,
		 storage_altered, storage_altered_fields, storage_altered_bytes, storage_originals)
		VALUES ` + strings.Join(valueGroups, ", ") + `
		ON CONFLICT (id) DO NOTHING`

	tag, err := dbPool.Exec(context.Background(), query, args...)
	if err != nil {
		return 0, nil, err
	}

	if len(missing) > 0 {
		log.Printf("[MANUAL-CRAWL] %d capture body digest(s) reference bytes the framework does not hold", len(missing))
	}

	// RowsAffected, not len(valueGroups): a re-POSTed batch whose rows already exist is a no-op under
	// ON CONFLICT DO NOTHING, and counting it as stored would inflate the session's request_count.
	return int(tag.RowsAffected()), sortedDigests(missing), nil
}

func orEmptyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func orEmptyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

// refreshManualCrawlSessionCounts recomputes the session totals from the captures actually stored
// and stamps the heartbeat. Counts used to be written only on an explicit stop, so any session that
// died reported zero forever.
func refreshManualCrawlSessionCounts(sessionID string) (int, int, error) {
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		SET request_count = c.request_count,
		    endpoint_count = c.endpoint_count,
		    last_heartbeat_at = NOW()
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, sessionID).Scan(&requestCount, &endpointCount)
	return requestCount, endpointCount, err
}

// HeartbeatManualCrawl keeps a session marked live while the extension is still recording. Without
// it the framework cannot tell a real recording from one whose service worker was terminated.
func HeartbeatManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SessionStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if _, err := resolveActiveCrawlSession(req.SessionID); err != nil {
		respondSessionError(w, err)
		return
	}

	if len(req.ObservedOutOfScope) > 0 {
		if payload, mErr := json.Marshal(req.ObservedOutOfScope); mErr == nil {
			if _, uErr := dbPool.Exec(context.Background(),
				`UPDATE manual_crawl_sessions SET observed_out_of_scope = $1 WHERE id = $2`,
				payload, req.SessionID); uErr != nil {
				log.Printf("[MANUAL-CRAWL] Failed to record out-of-scope hosts: %v", uErr)
			}
		}
	}

	requestCount, endpointCount, err := refreshManualCrawlSessionCounts(req.SessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Heartbeat failed for session %s: %v", req.SessionID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to record heartbeat")
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"sessionId":     req.SessionID,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

func StopManualCrawl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SessionStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[MANUAL-CRAWL] Error decoding stop request: %v", err)
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	if strings.TrimSpace(req.SessionID) == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id_required", "sessionId is required")
		return
	}

	// Stop is idempotent on purpose: the extension may retry it, and stopping an already-stopped
	// session should not surface an error to the user.
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		-- Only an active session completes. A session already marked 'abandoned' (its worker died and
		-- cleanup/StartManualCrawl retired it) keeps that terminal status and its original ended_at;
		-- a late Stop must not relabel a dead session as a clean completion or move its end time. The
		-- counts are still refreshed and returned so Stop stays idempotent from the client's view.
		SET status = CASE WHEN s.status = 'active' THEN 'completed' ELSE s.status END,
		    ended_at = CASE WHEN s.status = 'active' THEN NOW() ELSE s.ended_at END,
		    request_count = c.request_count,
		    endpoint_count = c.endpoint_count
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, req.SessionID).Scan(&requestCount, &endpointCount)

	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error stopping session %s: %v", req.SessionID, err)
		writeJSONError(w, http.StatusNotFound, "session_not_found", "Unknown capture session")
		return
	}

	log.Printf("[MANUAL-CRAWL] Stopped session %s. Requests: %d, Endpoints: %d",
		req.SessionID, requestCount, endpointCount)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"sessionId":     req.SessionID,
		"requestCount":  requestCount,
		"endpointCount": endpointCount,
	})
}

const manualCrawlSessionSelect = `
	SELECT id, scope_target_id, target_url, status, started_at, ended_at, last_heartbeat_at,
	       request_count, endpoint_count, COALESCE(observed_out_of_scope, '{}'::jsonb)
	FROM manual_crawl_sessions`

func scanManualCrawlSessions(rows interface {
	Next() bool
	Scan(...interface{}) error
}) []ManualCrawlSession {
	sessions := make([]ManualCrawlSession, 0)
	for rows.Next() {
		var session ManualCrawlSession
		var endedAt, lastHeartbeatAt *time.Time
		var outOfScopeJSON []byte

		err := rows.Scan(
			&session.ID,
			&session.ScopeTargetID,
			&session.TargetURL,
			&session.Status,
			&session.StartedAt,
			&endedAt,
			&lastHeartbeatAt,
			&session.RequestCount,
			&session.EndpointCount,
			&outOfScopeJSON,
		)
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning session: %v", err)
			continue
		}

		if len(outOfScopeJSON) > 0 {
			json.Unmarshal(outOfScopeJSON, &session.ObservedOutOfScope)
		}
		session.EndedAt = endedAt
		session.LastHeartbeatAt = lastHeartbeatAt
		session.IsLive = isManualCrawlSessionLive(session.Status, lastHeartbeatAt)
		sessions = append(sessions, session)
	}
	return sessions
}

// isManualCrawlSessionLive is the single definition of "actively recording" used by every surface,
// so the framework card, the results modal, and cleanup cannot disagree.
func isManualCrawlSessionLive(status string, lastHeartbeatAt *time.Time) bool {
	if status != "active" {
		return false
	}
	if lastHeartbeatAt == nil {
		return false
	}
	return time.Since(*lastHeartbeatAt) <= manualCrawlHeartbeatTimeout
}

func GetManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	rows, err := dbPool.Query(context.Background(),
		manualCrawlSessionSelect+` WHERE scope_target_id = $1 ORDER BY started_at DESC`, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query sessions")
		return
	}
	defer rows.Close()

	json.NewEncoder(w).Encode(scanManualCrawlSessions(rows))
}

func GetAllManualCrawlSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := dbPool.Query(context.Background(),
		manualCrawlSessionSelect+` ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying all sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query all sessions")
		return
	}
	defer rows.Close()

	sessions := scanManualCrawlSessions(rows)
	log.Printf("[MANUAL-CRAWL] Returning %d total sessions", len(sessions))
	json.NewEncoder(w).Encode(sessions)
}

// CleanupStaleSessions closes sessions whose extension stopped heartbeating. The old version only
// closed sessions with request_count = 0, and request_count was only written on a clean stop, so
// any session that captured anything and then died stayed 'active' forever.
func CleanupStaleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cutoff := time.Now().Add(-manualCrawlHeartbeatTimeout)

	rows, err := dbPool.Query(context.Background(), `
		UPDATE manual_crawl_sessions
		SET status = 'abandoned',
		    ended_at = COALESCE(last_heartbeat_at, started_at)
		WHERE status = 'active'
		  AND COALESCE(last_heartbeat_at, started_at) < $1
		RETURNING id`, cutoff)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error cleaning up stale sessions: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to cleanup sessions")
		return
	}
	defer rows.Close()

	staleIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			staleIDs = append(staleIDs, id)
		}
	}
	rows.Close()

	// Backfill counts for the sessions we just closed so their captures are not reported as zero.
	for _, id := range staleIDs {
		if _, _, err := refreshManualCrawlSessionCountsPreservingStatus(id); err != nil {
			log.Printf("[MANUAL-CRAWL] Failed to backfill counts for stale session %s: %v", id, err)
		}
		log.Printf("[MANUAL-CRAWL] Cleaned up stale session: %s", id)
	}

	log.Printf("[MANUAL-CRAWL] Cleaned up %d stale sessions", len(staleIDs))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"cleaned": len(staleIDs),
	})
}

// refreshManualCrawlSessionCountsPreservingStatus recomputes counts without touching the heartbeat,
// used when closing out a session that is already known to be dead.
func refreshManualCrawlSessionCountsPreservingStatus(sessionID string) (int, int, error) {
	var requestCount, endpointCount int
	err := dbPool.QueryRow(context.Background(), `
		UPDATE manual_crawl_sessions s
		SET request_count = c.request_count,
		    endpoint_count = c.endpoint_count
		FROM (
			SELECT COUNT(*) AS request_count,
			       -- Host is part of the endpoint's identity: the same path on the app host and on
			       -- a separate API host are two distinct endpoints.
			       COUNT(DISTINCT (capture_host(url), endpoint, method)) AS endpoint_count
			FROM manual_crawl_captures
			WHERE session_id = $1
		) c
		WHERE s.id = $1
		RETURNING s.request_count, s.endpoint_count`, sessionID).Scan(&requestCount, &endpointCount)
	return requestCount, endpointCount, err
}

func GetManualCrawlCaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sessionID := mux.Vars(r)["session_id"]

	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id_required", "session_id is required")
		return
	}

	// ?blob=<sha256> serves the stored bytes themselves. An operator proving an IDOR that returned
	// another user's photo has to be able to LOOK at the photo; base64 in a JSON field proves the
	// bytes were kept but shows nobody anything.
	if digest := r.URL.Query().Get("blob"); digest != "" {
		serveCaptureBlob(w, "session_id", sessionID, digest)
		return
	}

	query := `
		SELECT id, session_id, scope_target_id, url, endpoint, method, status_code,
		       headers, response_headers, post_data, response_body, get_params, post_params,
		       body_type, tab_id, timestamp, mime_type, sources, graphql_operation, resource_type,
		       initiator, redirect_chain, error, duration_ms, request_body_truncated,
		       response_body_truncated, COALESCE(is_direct, false),
		       COALESCE(response_body_sha256, ''), COALESCE(response_body_bytes, 0),
		       COALESCE(response_body_capped, false), COALESCE(response_body_blob_missing, false),
		       COALESCE(storage_altered, false), COALESCE(storage_altered_fields, '{}'),
		       COALESCE(storage_altered_bytes, 0), COALESCE(storage_originals, '{}'::jsonb)
		FROM manual_crawl_captures
		WHERE session_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, sessionID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying captures: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query captures")
		return
	}
	defer rows.Close()

	captures := scanManualCrawlCaptures(rows)
	attachBlobBodies(captures, includeMediaBodies(r))
	json.NewEncoder(w).Encode(captures)
}

// GetManualCrawlCapturesForTarget returns every capture for a scope target in one call. The results
// modal used to fetch captures session-by-session in a loop driven by possibly-stale state.
func GetManualCrawlCapturesForTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	if digest := r.URL.Query().Get("blob"); digest != "" {
		serveCaptureBlob(w, "scope_target_id", scopeTargetID, digest)
		return
	}

	query := `
		SELECT id, session_id, scope_target_id, url, endpoint, method, status_code,
		       headers, response_headers, post_data, response_body, get_params, post_params,
		       body_type, tab_id, timestamp, mime_type, sources, graphql_operation, resource_type,
		       initiator, redirect_chain, error, duration_ms, request_body_truncated,
		       response_body_truncated, COALESCE(is_direct, false),
		       COALESCE(response_body_sha256, ''), COALESCE(response_body_bytes, 0),
		       COALESCE(response_body_capped, false), COALESCE(response_body_blob_missing, false),
		       COALESCE(storage_altered, false), COALESCE(storage_altered_fields, '{}'),
		       COALESCE(storage_altered_bytes, 0), COALESCE(storage_originals, '{}'::jsonb)
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying captures for target: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query captures")
		return
	}
	defer rows.Close()

	captures := scanManualCrawlCaptures(rows)
	attachBlobBodies(captures, includeMediaBodies(r))
	json.NewEncoder(w).Encode(captures)
}

func scanManualCrawlCaptures(rows interface {
	Next() bool
	Scan(...interface{}) error
}) []ManualCrawlCapture {
	captures := make([]ManualCrawlCapture, 0)
	for rows.Next() {
		var capture ManualCrawlCapture
		var headersJSON, responseHeadersJSON, getParamsJSON, postParamsJSON, redirectChainJSON []byte
		var bodyType, postData, responseBody, mimeType *string
		var graphqlOperation, resourceType, initiator, captureError *string
		var statusCode, tabID, durationMs *int
		var requestBodyTruncated, responseBodyTruncated *bool
		var storageOriginalsJSON []byte

		err := rows.Scan(
			&capture.ID,
			&capture.SessionID,
			&capture.ScopeTargetID,
			&capture.URL,
			&capture.Endpoint,
			&capture.Method,
			&statusCode,
			&headersJSON,
			&responseHeadersJSON,
			&postData,
			&responseBody,
			&getParamsJSON,
			&postParamsJSON,
			&bodyType,
			&tabID,
			&capture.Timestamp,
			&mimeType,
			&capture.Sources,
			&graphqlOperation,
			&resourceType,
			&initiator,
			&redirectChainJSON,
			&captureError,
			&durationMs,
			&requestBodyTruncated,
			&responseBodyTruncated,
			&capture.IsDirect,
			&capture.ResponseBodySHA256,
			&capture.ResponseBodyBytes,
			&capture.ResponseBodyCapped,
			&capture.ResponseBodyBlobMissing,
			&capture.StorageAltered,
			&capture.StorageAlteredFields,
			&capture.StorageAlteredBytes,
			&storageOriginalsJSON,
		)
		if err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning capture: %v", err)
			continue
		}

		if statusCode != nil {
			capture.StatusCode = *statusCode
		}
		if postData != nil {
			capture.PostData = *postData
		}
		if responseBody != nil {
			capture.ResponseBody = *responseBody
		}
		if bodyType != nil {
			capture.BodyType = *bodyType
		}
		if mimeType != nil {
			capture.MimeType = *mimeType
		}
		if graphqlOperation != nil {
			capture.GraphQLOperation = *graphqlOperation
		}
		if resourceType != nil {
			capture.ResourceType = *resourceType
		}
		if initiator != nil {
			capture.Initiator = *initiator
		}
		if captureError != nil {
			capture.Error = *captureError
		}
		if durationMs != nil {
			capture.DurationMs = *durationMs
		}
		if requestBodyTruncated != nil {
			capture.RequestBodyTruncated = *requestBodyTruncated
		}
		if responseBodyTruncated != nil {
			capture.ResponseBodyTruncated = *responseBodyTruncated
		}
		if capture.Sources == nil {
			capture.Sources = []string{}
		}
		if len(redirectChainJSON) > 0 {
			json.Unmarshal(redirectChainJSON, &capture.RedirectChain)
		}
		capture.TabID = tabID

		json.Unmarshal(headersJSON, &capture.Headers)
		json.Unmarshal(responseHeadersJSON, &capture.ResponseHeaders)
		if len(getParamsJSON) > 0 {
			json.Unmarshal(getParamsJSON, &capture.GetParams)
		}
		if len(postParamsJSON) > 0 {
			json.Unmarshal(postParamsJSON, &capture.PostParams)
		}
		if len(storageOriginalsJSON) > 0 {
			json.Unmarshal(storageOriginalsJSON, &capture.StorageOriginals)
		}

		captures = append(captures, capture)
	}
	return captures
}

func GetManualCrawlEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	query := `
		SELECT capture_host(url) AS host, endpoint, method, COUNT(*) as request_count,
		       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
		       bool_or(COALESCE(is_direct, false)) as is_direct
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		GROUP BY capture_host(url), endpoint, method
		ORDER BY last_seen DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying endpoints: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query endpoints")
		return
	}
	defer rows.Close()

	type EndpointSummary struct {
		Host         string    `json:"host"`
		Endpoint     string    `json:"endpoint"`
		Method       string    `json:"method"`
		RequestCount int       `json:"request_count"`
		FirstSeen    time.Time `json:"first_seen"`
		LastSeen     time.Time `json:"last_seen"`
		IsDirect     bool      `json:"is_direct"`
	}

	endpoints := make([]EndpointSummary, 0)
	for rows.Next() {
		var ep EndpointSummary
		if err := rows.Scan(&ep.Host, &ep.Endpoint, &ep.Method, &ep.RequestCount, &ep.FirstSeen, &ep.LastSeen, &ep.IsDirect); err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning endpoint: %v", err)
			continue
		}
		endpoints = append(endpoints, ep)
	}

	json.NewEncoder(w).Encode(endpoints)
}

// GetProbeCandidateEndpoints returns the endpoints the Routing & WAF Probe is allowed to be pointed
// at: ones the manual crawl actually saw return HTTP 200.
//
// Three deliberate differences from GetManualCrawlEndpoints above, each of which the probe needs:
//
//   - 200 ONLY. A probe reads meaning out of how a target's behaviour CHANGES under load and under
//     hostile-looking input. A baseline that is already a 404, a 401 or a redirect has no signal to
//     move, so probing it produces confident nonsense rather than nothing.
//   - A CONCRETE URL, not the templated endpoint. GetManualCrawlEndpoints groups to "/sites/{id}/x"
//     which cannot be requested. Rows are still grouped per logical endpoint so the picker is not
//     thousands of near-identical URLs, but each carries a real URL that was really seen returning
//     200, chosen as the most recent one.
//   - ADJACENT HOSTS INCLUDED. This is the point of the feature: an application's API, chat transport
//     and asset hosts are usually different hostnames from the scope target, and each can sit behind
//     different routing and a different WAF. is_direct is returned so the picker can group by it, not
//     so it can filter on it.
//
// Hosts the operator has explicitly excluded are dropped. Manual-crawl hosts are in scope by default
// (the capturer refuses to record a host nobody authorized), so only an explicit in_scope=false row
// removes one, which is why this is a LEFT JOIN with COALESCE rather than an inner join.
func GetProbeCandidateEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id is required")
		return
	}

	// Grouped per (host, endpoint, method) so one logical endpoint is one row, with the most recently
	// seen concrete URL as the representative. status_code is compared against the captures rather
	// than re-requested: this handler sends no traffic to the target.
	//
	// is_static exists because a crawl of any real application is mostly assets, and a stylesheet is a
	// bad thing to point a behaviour probe at: it is usually served by a CDN or a different edge path
	// from the application, so what comes back describes the cache rather than the app. They are
	// CLASSIFIED and sorted last rather than filtered out, because "this whole host only ever served
	// static files" is itself worth seeing in the picker, and a hidden row cannot say that.
	query := `
		WITH picked AS (
			SELECT (array_agg(c.url ORDER BY c.timestamp DESC))[1] AS url,
			       capture_host(c.url) AS host,
			       c.endpoint,
			       c.method,
			       COUNT(*) AS request_count,
			       MAX(c.timestamp) AS last_seen,
			       bool_or(COALESCE(c.is_direct, false)) AS is_direct,
			       bool_or(COALESCE(c.mime_type, '') LIKE 'image/%'
			            OR COALESCE(c.mime_type, '') LIKE 'font/%'
			            OR COALESCE(c.mime_type, '') LIKE 'video/%'
			            OR COALESCE(c.mime_type, '') LIKE 'audio/%'
			            OR COALESCE(c.mime_type, '') IN ('text/css', 'application/javascript',
			                                             'text/javascript')) AS mime_static
			FROM manual_crawl_captures c
			LEFT JOIN scope_target_scope_hosts h
			       ON h.scope_target_id = c.scope_target_id
			      AND h.host = capture_host(c.url)
			WHERE c.scope_target_id = $1
			  AND c.status_code = 200
			  AND COALESCE(h.in_scope, TRUE)
			  -- OPTIONS is dropped outright rather than classified like static assets. A preflight is
			  -- generated by the browser, not exposed by the application, and it answers 200 by
			  -- design, so it is never a meaningful probe target. Unlike a static-only host there is
			  -- nothing lost by hiding it: a preflight only exists because a real request followed it,
			  -- so the same endpoint is always present under its actual verb as well.
			  AND UPPER(c.method) <> 'OPTIONS'
			GROUP BY capture_host(c.url), c.endpoint, c.method
		)
		SELECT url, host, endpoint, method, request_count, last_seen, is_direct,
		       (mime_static OR url ~* '\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|mp3|wav)(\?|$)') AS is_static
		FROM picked
		ORDER BY is_static ASC, is_direct DESC, host ASC, request_count DESC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[MANUAL-CRAWL] Error querying probe candidates: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to query probe candidates")
		return
	}
	defer rows.Close()

	type ProbeCandidate struct {
		URL          string    `json:"url"`
		Host         string    `json:"host"`
		Endpoint     string    `json:"endpoint"`
		Method       string    `json:"method"`
		RequestCount int       `json:"request_count"`
		LastSeen     time.Time `json:"last_seen"`
		IsDirect     bool      `json:"is_direct"`
		IsStatic     bool      `json:"is_static"`
	}

	candidates := make([]ProbeCandidate, 0)
	hosts := map[string]bool{}
	dynamicHosts := map[string]bool{}
	for rows.Next() {
		var c ProbeCandidate
		if err := rows.Scan(&c.URL, &c.Host, &c.Endpoint, &c.Method, &c.RequestCount,
			&c.LastSeen, &c.IsDirect, &c.IsStatic); err != nil {
			log.Printf("[MANUAL-CRAWL] Error scanning probe candidate: %v", err)
			continue
		}
		candidates = append(candidates, c)
		hosts[c.Host] = true
		if !c.IsStatic {
			dynamicHosts[c.Host] = true
		}
	}

	// host_count answers "how much of the estate could I cover", which is the question the picker
	// exists to serve. dynamic_host_count is the more honest version of it: a host that only ever
	// served assets is a host the probe will learn nothing useful from, and the difference between
	// the two numbers is exactly the set of hosts worth a second look before selecting anything.
	json.NewEncoder(w).Encode(map[string]interface{}{
		"candidates":         candidates,
		"total":              len(candidates),
		"host_count":         len(hosts),
		"dynamic_host_count": len(dynamicHosts),
	})
}
