package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func GetSecurityControlsNotes(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, control_name, note, created_at, updated_at 
	          FROM security_controls_notes 
	          WHERE scope_target_id = $1 
	          ORDER BY control_name, created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get security controls notes: %v", err)
		http.Error(w, "Failed to fetch notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []map[string]interface{}
	for rows.Next() {
		var note struct {
			ID          string    `json:"id"`
			ControlName string    `json:"control_name"`
			Note        string    `json:"note"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
		}

		err := rows.Scan(&note.ID, &note.ControlName, &note.Note, &note.CreatedAt, &note.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		notes = append(notes, map[string]interface{}{
			"id":           note.ID,
			"control_name": note.ControlName,
			"note":         note.Note,
			"created_at":   note.CreatedAt,
			"updated_at":   note.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notes)
}

func CreateSecurityControlNote(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		ControlName string `json:"control_name"`
		Note        string `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.ControlName == "" || payload.Note == "" {
		http.Error(w, "Control name and note are required", http.StatusBadRequest)
		return
	}

	noteID := uuid.New().String()
	query := `INSERT INTO security_controls_notes (id, scope_target_id, control_name, note) 
	          VALUES ($1, $2, $3, $4) 
	          RETURNING id, control_name, note, created_at, updated_at`

	var note struct {
		ID          string    `json:"id"`
		ControlName string    `json:"control_name"`
		Note        string    `json:"note"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, noteID, scopeTargetID, payload.ControlName, payload.Note).Scan(
		&note.ID, &note.ControlName, &note.Note, &note.CreatedAt, &note.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create security control note: %v", err)
		http.Error(w, "Failed to create note", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(note)
}

func UpdateSecurityControlNote(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	noteID := vars["note_id"]

	var payload struct {
		Note string `json:"note"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Note == "" {
		http.Error(w, "Note is required", http.StatusBadRequest)
		return
	}

	query := `UPDATE security_controls_notes 
	          SET note = $1, updated_at = NOW() 
	          WHERE id = $2 
	          RETURNING id, control_name, note, created_at, updated_at`

	var note struct {
		ID          string    `json:"id"`
		ControlName string    `json:"control_name"`
		Note        string    `json:"note"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.Note, noteID).Scan(
		&note.ID, &note.ControlName, &note.Note, &note.CreatedAt, &note.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update security control note: %v", err)
		http.Error(w, "Failed to update note", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(note)
}

func DeleteSecurityControlNote(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	noteID := vars["note_id"]

	query := `DELETE FROM security_controls_notes WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, noteID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete security control note: %v", err)
		http.Error(w, "Failed to delete note", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Note not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

