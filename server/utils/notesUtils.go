package utils

// Free-text notes attached to a scope target.
//
// A note is deliberately dumb: a title, a body, and the target it belongs to. Nothing here parses
// or interprets the content, because the whole point is somewhere to put the things the schema does
// not have a column for.

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

// ScopeTargetNote is the wire shape. Timestamps are RFC3339 strings rather than time.Time because
// that is what the rest of this API emits and the client already renders them as text.
type ScopeTargetNote struct {
	ID            string `json:"id"`
	ScopeTargetID string `json:"scope_target_id"`
	Title         string `json:"title"`
	Content       string `json:"content"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// One column list for every query, so POST, PUT and GET cannot drift into returning different field
// sets for the same object.
const noteColumns = `id::text, scope_target_id::text, title, content, created_at, updated_at`

// pgx.Row and pgx.Rows both satisfy this, which is what lets the single-row and list paths share
// scanNote instead of keeping two copies of the column order in sync.
type noteRowScanner interface {
	Scan(dest ...any) error
}

func scanNote(row noteRowScanner) (ScopeTargetNote, error) {
	var n ScopeTargetNote
	var created, updated time.Time
	if err := row.Scan(&n.ID, &n.ScopeTargetID, &n.Title, &n.Content, &created, &updated); err != nil {
		return n, err
	}
	n.CreatedAt = created.Format(time.RFC3339)
	n.UpdatedAt = updated.Format(time.RFC3339)
	return n, nil
}

func writeNoteJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// GetNotes handles GET /notes/{scope_target_id}.
//
// Ordered by updated_at so the note you just touched is the one at the top. created_at breaks the
// tie, which only matters for notes written inside the same clock tick but keeps the order stable
// across two requests instead of letting Postgres pick.
func GetNotes(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	// Checked here rather than left to Postgres: a malformed id is a caller mistake, and without
	// this it surfaces as a 500 that reads like the server is broken.
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "The scope target id in the URL is not a valid UUID.", http.StatusBadRequest)
		return
	}

	rows, err := dbPool.Query(context.Background(),
		`SELECT `+noteColumns+` FROM scope_target_notes
		 WHERE scope_target_id = $1
		 ORDER BY updated_at DESC, created_at DESC`, scopeTargetID)
	if err != nil {
		log.Printf("[NOTES] Failed to read notes for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to read notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Non-nil on purpose. A nil slice marshals to JSON null, and then every consumer has to defend
	// against null before it can iterate.
	notes := make([]ScopeTargetNote, 0)
	for rows.Next() {
		n, scanErr := scanNote(rows)
		if scanErr != nil {
			// Deliberately fatal rather than skipped. A dropped row still returns 200, and a note
			// missing from the list is indistinguishable from one the user deleted, so the failure
			// would read as data loss. Better to say nothing than to say something short.
			log.Printf("[NOTES] Failed to scan a note row for target %s: %v", scopeTargetID, scanErr)
			http.Error(w, "Failed to read notes", http.StatusInternalServerError)
			return
		}
		notes = append(notes, n)
	}
	// rows.Next() returns false both for "done" and for "the connection died mid-read". Without this
	// the second case is a 200 carrying however many notes arrived before the break.
	if err := rows.Err(); err != nil {
		log.Printf("[NOTES] Note list for target %s ended early: %v", scopeTargetID, err)
		http.Error(w, "Failed to read notes", http.StatusInternalServerError)
		return
	}

	writeNoteJSON(w, http.StatusOK, map[string]interface{}{"notes": notes})
}

// CreateNote handles POST /notes.
func CreateNote(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id"`
		Title         string `json:"title"`
		Content       string `json:"content"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with scope_target_id, title and content.",
			http.StatusBadRequest)
		return
	}

	scopeTargetID := strings.TrimSpace(payload.ScopeTargetID)
	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required. A note has to belong to a scope target.",
			http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "scope_target_id is not a valid UUID.", http.StatusBadRequest)
		return
	}

	// The title is the only thing the list view shows, so a whitespace-only one produces a row you
	// cannot tell apart from any other. Content is not trimmed: leading indentation in a pasted
	// snippet is the user's, not ours to remove.
	title := strings.TrimSpace(payload.Title)
	if title == "" {
		http.Error(w, "title is required and cannot be only whitespace.", http.StatusBadRequest)
		return
	}

	note, err := scanNote(dbPool.QueryRow(context.Background(),
		`INSERT INTO scope_target_notes (scope_target_id, title, content)
		 VALUES ($1, $2, $3)
		 RETURNING `+noteColumns, scopeTargetID, title, payload.Content))
	if err != nil {
		// The one failure a caller can fix: a syntactically valid id for a target that is not there.
		// The foreign key is what catches it, so there is no check-then-insert race to lose.
		if strings.Contains(err.Error(), "scope_target_notes_scope_target_id_fkey") {
			http.Error(w, "No scope target with that id exists.", http.StatusBadRequest)
			return
		}
		log.Printf("[NOTES] Failed to create note for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to create the note", http.StatusInternalServerError)
		return
	}

	// The full object comes back so the client can insert it into its list without re-fetching.
	writeNoteJSON(w, http.StatusCreated, note)
}

// UpdateNote handles PUT /notes/{note_id}.
func UpdateNote(w http.ResponseWriter, r *http.Request) {
	noteID := mux.Vars(r)["note_id"]
	// An id that is not a UUID cannot name an existing note, so it is a 404 rather than a 400. The
	// caller's next move is the same either way and it keeps the failure modes of this route to one.
	if _, err := uuid.Parse(noteID); err != nil {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	var payload struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with title and content.",
			http.StatusBadRequest)
		return
	}

	title := strings.TrimSpace(payload.Title)
	if title == "" {
		http.Error(w, "title is required and cannot be only whitespace.", http.StatusBadRequest)
		return
	}

	// updated_at is stamped here and nowhere else. It is the sort key the list is built on, so an
	// edit that did not move it would leave the note the user just changed buried.
	note, err := scanNote(dbPool.QueryRow(context.Background(),
		`UPDATE scope_target_notes
		 SET title = $2, content = $3, updated_at = NOW()
		 WHERE id = $1
		 RETURNING `+noteColumns, noteID, title, payload.Content))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "No such note", http.StatusNotFound)
			return
		}
		log.Printf("[NOTES] Failed to update note %s: %v", noteID, err)
		http.Error(w, "Failed to update the note", http.StatusInternalServerError)
		return
	}

	writeNoteJSON(w, http.StatusOK, note)
}

// DeleteNote handles DELETE /notes/{note_id}.
func DeleteNote(w http.ResponseWriter, r *http.Request) {
	noteID := mux.Vars(r)["note_id"]
	if _, err := uuid.Parse(noteID); err != nil {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	tag, err := dbPool.Exec(context.Background(),
		`DELETE FROM scope_target_notes WHERE id = $1`, noteID)
	if err != nil {
		log.Printf("[NOTES] Failed to delete note %s: %v", noteID, err)
		http.Error(w, "Failed to delete the note", http.StatusInternalServerError)
		return
	}
	// Distinguishing "deleted nothing" from "deleted one" is what makes a second DELETE of the same
	// note a 404 instead of a silent success the client would read as another row disappearing.
	if tag.RowsAffected() == 0 {
		http.Error(w, "No such note", http.StatusNotFound)
		return
	}

	writeNoteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
