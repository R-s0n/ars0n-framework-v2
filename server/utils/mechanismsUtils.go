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

func GetMechanismsExamples(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, mechanism, url, notes, created_at, updated_at 
	          FROM mechanisms_examples 
	          WHERE scope_target_id = $1 
	          ORDER BY mechanism, created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get mechanisms examples: %v", err)
		http.Error(w, "Failed to fetch examples", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var examples []map[string]interface{}
	for rows.Next() {
		var example struct {
			ID        string    `json:"id"`
			Mechanism string    `json:"mechanism"`
			URL       string    `json:"url"`
			Notes     string    `json:"notes"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}

		err := rows.Scan(&example.ID, &example.Mechanism, &example.URL, &example.Notes, &example.CreatedAt, &example.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		examples = append(examples, map[string]interface{}{
			"id":         example.ID,
			"mechanism":  example.Mechanism,
			"url":        example.URL,
			"notes":      example.Notes,
			"created_at": example.CreatedAt,
			"updated_at": example.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(examples)
}

func CreateMechanismExample(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		Mechanism string `json:"mechanism"`
		URL       string `json:"url"`
		Notes     string `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Mechanism == "" || payload.URL == "" {
		http.Error(w, "Mechanism and URL are required", http.StatusBadRequest)
		return
	}

	exampleID := uuid.New().String()
	query := `INSERT INTO mechanisms_examples (id, scope_target_id, mechanism, url, notes) 
	          VALUES ($1, $2, $3, $4, $5) 
	          RETURNING id, mechanism, url, notes, created_at, updated_at`

	var example struct {
		ID        string    `json:"id"`
		Mechanism string    `json:"mechanism"`
		URL       string    `json:"url"`
		Notes     string    `json:"notes"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, exampleID, scopeTargetID, payload.Mechanism, payload.URL, payload.Notes).Scan(
		&example.ID, &example.Mechanism, &example.URL, &example.Notes, &example.CreatedAt, &example.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create mechanism example: %v", err)
		http.Error(w, "Failed to create example", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(example)
}

func UpdateMechanismExample(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	exampleID := vars["example_id"]

	var payload struct {
		URL   string `json:"url"`
		Notes string `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	query := `UPDATE mechanisms_examples 
	          SET url = $1, notes = $2, updated_at = NOW() 
	          WHERE id = $3 
	          RETURNING id, mechanism, url, notes, created_at, updated_at`

	var example struct {
		ID        string    `json:"id"`
		Mechanism string    `json:"mechanism"`
		URL       string    `json:"url"`
		Notes     string    `json:"notes"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.URL, payload.Notes, exampleID).Scan(
		&example.ID, &example.Mechanism, &example.URL, &example.Notes, &example.CreatedAt, &example.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update mechanism example: %v", err)
		http.Error(w, "Failed to update example", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(example)
}

func DeleteMechanismExample(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	exampleID := vars["example_id"]

	query := `DELETE FROM mechanisms_examples WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, exampleID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete mechanism example: %v", err)
		http.Error(w, "Failed to delete example", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Example not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

