package utils

// Free-text notes attached to a single threat model entry.
//
// This is scope-target notes one level down: a title, a body, and the threat it belongs to. A note is
// deliberately dumb. Nothing here parses or interprets the content, because the whole point is
// somewhere to put the reasoning a test produced that the threat's own columns have no field for: the
// exact request that was ambiguous, the account that was needed and not available, the thing to try
// next.
//
// Two separate things in this codebase are called notes and they are not related. scope_target_notes
// hangs off a scope target and is served from /notes by notesUtils.go. These hang off one threat, are
// served from /threat-notes, and log under [THREAT-NOTES] so a failure in one is not read as a
// failure in the other.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// ThreatNote is the wire shape. Timestamps are RFC3339 strings rather than time.Time because that is
// what the notes API already emits and the client renders them as text.
type ThreatNote struct {
	ID        string `json:"id"`
	ThreatID  string `json:"threat_id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// One column list for every query, so POST, PUT and GET cannot drift into returning different field
// sets for the same object.
const threatNoteColumns = `id::text, threat_id::text, title, content, created_at, updated_at`

// noteRowScanner is declared in notesUtils.go and satisfied by both pgx.Row and pgx.Rows, which is
// what lets the single-row and list paths here share scanThreatNote instead of keeping two copies of
// the column order in sync.
func scanThreatNote(row noteRowScanner) (ThreatNote, error) {
	var n ThreatNote
	var created, updated time.Time
	if err := row.Scan(&n.ID, &n.ThreatID, &n.Title, &n.Content, &created, &updated); err != nil {
		return n, err
	}
	n.CreatedAt = created.Format(time.RFC3339)
	n.UpdatedAt = updated.Format(time.RFC3339)
	return n, nil
}

func writeThreatNoteJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// GetThreatNotes handles GET /threat-notes/{threat_id}.
//
// Ordered by updated_at so the note you just touched is the one at the top. created_at breaks the
// tie, which only matters for notes written inside the same clock tick but keeps the order stable
// across two requests instead of letting Postgres pick. The index on (threat_id, updated_at DESC) is
// built to match this and only this.
func GetThreatNotes(w http.ResponseWriter, r *http.Request) {
	threatID := mux.Vars(r)["threat_id"]
	// Checked here rather than left to Postgres: a malformed id is a caller mistake, and without this
	// it surfaces as a 500 that reads like the server is broken.
	if _, err := uuid.Parse(threatID); err != nil {
		http.Error(w, "The threat id in the URL is not a valid UUID.", http.StatusBadRequest)
		return
	}

	rows, err := dbPool.Query(context.Background(),
		`SELECT `+threatNoteColumns+` FROM threat_notes
		 WHERE threat_id = $1
		 ORDER BY updated_at DESC, created_at DESC`, threatID)
	if err != nil {
		log.Printf("[THREAT-NOTES] Failed to read notes for threat %s: %v", threatID, err)
		http.Error(w, "Failed to read notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Non-nil on purpose. A nil slice marshals to JSON null, and then every consumer has to defend
	// against null before it can iterate.
	notes := make([]ThreatNote, 0)
	for rows.Next() {
		n, scanErr := scanThreatNote(rows)
		if scanErr != nil {
			// Deliberately fatal rather than skipped. A dropped row still returns 200, and a note
			// missing from the list is indistinguishable from one the user deleted, so the failure
			// would read as data loss. Better to say nothing than to say something short.
			log.Printf("[THREAT-NOTES] Failed to scan a note row for threat %s: %v", threatID, scanErr)
			http.Error(w, "Failed to read notes", http.StatusInternalServerError)
			return
		}
		notes = append(notes, n)
	}
	// rows.Next() returns false both for "done" and for "the connection died mid-read". Without this
	// the second case is a 200 carrying however many notes arrived before the break.
	if err := rows.Err(); err != nil {
		log.Printf("[THREAT-NOTES] Note list for threat %s ended early: %v", threatID, err)
		http.Error(w, "Failed to read notes", http.StatusInternalServerError)
		return
	}

	writeThreatNoteJSON(w, http.StatusOK, map[string]interface{}{"notes": notes})
}

// CreateThreatNote handles POST /threat-notes.
func CreateThreatNote(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ThreatID string `json:"threat_id"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with threat_id, title and content.",
			http.StatusBadRequest)
		return
	}

	threatID := strings.TrimSpace(payload.ThreatID)
	if threatID == "" {
		http.Error(w, "threat_id is required. A note has to belong to a threat.",
			http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(threatID); err != nil {
		http.Error(w, "threat_id is not a valid UUID.", http.StatusBadRequest)
		return
	}

	// The title is the only thing the collapsed list shows, so a whitespace-only one produces a row
	// you cannot tell apart from any other. Content is not trimmed: leading indentation in a pasted
	// request or snippet is the user's, not ours to remove.
	title := strings.TrimSpace(payload.Title)
	if title == "" {
		http.Error(w, "title is required and cannot be only whitespace.", http.StatusBadRequest)
		return
	}

	note, err := scanThreatNote(dbPool.QueryRow(context.Background(),
		`INSERT INTO threat_notes (threat_id, title, content)
		 VALUES ($1, $2, $3)
		 RETURNING `+threatNoteColumns, threatID, title, payload.Content))
	if err != nil {
		// The one failure a caller can fix: a syntactically valid id for a threat that is not there.
		// The foreign key is what catches it, so there is no check-then-insert race to lose, and a
		// note orphaned against a mistyped id is worse than a refusal. The constraint name is the
		// Postgres default for threat_notes.threat_id, so it changes only if the column does.
		if strings.Contains(err.Error(), "threat_notes_threat_id_fkey") {
			http.Error(w, "No threat with that id exists.", http.StatusBadRequest)
			return
		}
		log.Printf("[THREAT-NOTES] Failed to create note for threat %s: %v", threatID, err)
		http.Error(w, "Failed to create the note", http.StatusInternalServerError)
		return
	}

	// The full object comes back so the client can insert it into its list without re-fetching.
	writeThreatNoteJSON(w, http.StatusCreated, note)
}

// UpdateThreatNote handles PUT /threat-notes/{note_id}.
//
// PRESERVE-ON-OMIT, and this is the one place this file deliberately diverges from notesUtils.go.
// UpdateNote there writes title and content unconditionally, so a caller that sends only a title
// blanks the body; manage_notes in the MCP compensates by reading the row back and re-sending both
// fields, which leaves a lost-update race between the read and the write and protects nobody who
// does not perform that dance. Doing it in SQL instead means every caller gets the guarantee. This is
// the same rule the threat_model PUT carries for the same reason: a partial update there once erased
// five columns on 58 rows.
//
// The two title cases are not the same and must not be collapsed. Omitted means preserve. Supplied
// but whitespace-only is a 400, because with COALESCE it would otherwise silently preserve and the
// caller would believe it renamed the note. Content supplied as "" is an honoured blanking, since an
// empty body is a legitimate note.
func UpdateThreatNote(w http.ResponseWriter, r *http.Request) {
	noteID := mux.Vars(r)["note_id"]
	// An id that is not a UUID cannot name an existing note, so it is a 404 rather than a 400. The
	// caller's next move is the same either way and it keeps the failure modes of this route to one.
	if _, err := uuid.Parse(noteID); err != nil {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	// Pointers, so the handler can tell "field not supplied" (nil, preserve what is stored) from
	// "field supplied as empty" (clear it).
	var payload struct {
		Title   *string `json:"title"`
		Content *string `json:"content"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with title, content or both.",
			http.StatusBadRequest)
		return
	}

	// Refused rather than treated as a no-op: an empty edit would still stamp updated_at, which is
	// the list's sort key, so the note would jump to the top having changed nothing.
	if payload.Title == nil && payload.Content == nil {
		http.Error(w, "Nothing to update. Supply title, content or both.", http.StatusBadRequest)
		return
	}

	var title *string
	if payload.Title != nil {
		trimmed := strings.TrimSpace(*payload.Title)
		if trimmed == "" {
			http.Error(w, "title is required and cannot be only whitespace.", http.StatusBadRequest)
			return
		}
		title = &trimmed
	}

	// updated_at is stamped here and nowhere else. It is the sort key the list is built on, so an
	// edit that did not move it would leave the note the user just changed buried.
	note, err := scanThreatNote(dbPool.QueryRow(context.Background(),
		`UPDATE threat_notes
		 SET title = COALESCE($2, title),
		     content = COALESCE($3, content),
		     updated_at = NOW()
		 WHERE id = $1
		 RETURNING `+threatNoteColumns, noteID, title, payload.Content))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "No such note", http.StatusNotFound)
			return
		}
		log.Printf("[THREAT-NOTES] Failed to update note %s: %v", noteID, err)
		http.Error(w, "Failed to update the note", http.StatusInternalServerError)
		return
	}

	writeThreatNoteJSON(w, http.StatusOK, note)
}

// DeleteThreatNote handles DELETE /threat-notes/{note_id}.
//
// Deleting the threat itself also deletes its notes, by ON DELETE CASCADE on the table. That is
// deliberate: a note about a threat that no longer exists has nothing to refer to, and threat
// deletion is already a hard delete with no restore.
func DeleteThreatNote(w http.ResponseWriter, r *http.Request) {
	noteID := mux.Vars(r)["note_id"]
	if _, err := uuid.Parse(noteID); err != nil {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	tag, err := dbPool.Exec(context.Background(),
		`DELETE FROM threat_notes WHERE id = $1`, noteID)
	if err != nil {
		log.Printf("[THREAT-NOTES] Failed to delete note %s: %v", noteID, err)
		http.Error(w, "Failed to delete the note", http.StatusInternalServerError)
		return
	}
	// Distinguishing "deleted nothing" from "deleted one" is what makes a second DELETE of the same
	// note a 404 instead of a silent success the client would read as another row disappearing.
	if tag.RowsAffected() == 0 {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	writeThreatNoteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
