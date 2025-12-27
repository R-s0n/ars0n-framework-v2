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

func GetNotableObjects(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, object_name, object_json, created_at, updated_at 
	          FROM notable_objects 
	          WHERE scope_target_id = $1 
	          ORDER BY object_name`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get notable objects: %v", err)
		http.Error(w, "Failed to fetch objects", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var objects []map[string]interface{}
	for rows.Next() {
		var object struct {
			ID         string    `json:"id"`
			ObjectName string    `json:"object_name"`
			ObjectJSON string    `json:"object_json"`
			CreatedAt  time.Time `json:"created_at"`
			UpdatedAt  time.Time `json:"updated_at"`
		}

		err := rows.Scan(&object.ID, &object.ObjectName, &object.ObjectJSON, &object.CreatedAt, &object.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		objects = append(objects, map[string]interface{}{
			"id":          object.ID,
			"object_name": object.ObjectName,
			"object_json": object.ObjectJSON,
			"created_at":  object.CreatedAt,
			"updated_at":  object.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(objects)
}

func CreateNotableObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		ObjectName string `json:"object_name"`
		ObjectJSON string `json:"object_json"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.ObjectName == "" {
		http.Error(w, "Object name is required", http.StatusBadRequest)
		return
	}

	objectID := uuid.New().String()
	query := `INSERT INTO notable_objects (id, scope_target_id, object_name, object_json) 
	          VALUES ($1, $2, $3, $4) 
	          RETURNING id, object_name, object_json, created_at, updated_at`

	var object struct {
		ID         string    `json:"id"`
		ObjectName string    `json:"object_name"`
		ObjectJSON string    `json:"object_json"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, objectID, scopeTargetID, payload.ObjectName, payload.ObjectJSON).Scan(
		&object.ID, &object.ObjectName, &object.ObjectJSON, &object.CreatedAt, &object.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create notable object: %v", err)
		http.Error(w, "Failed to create object", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(object)
}

func UpdateNotableObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	objectID := vars["object_id"]

	var payload struct {
		ObjectName string `json:"object_name"`
		ObjectJSON string `json:"object_json"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.ObjectName == "" {
		http.Error(w, "Object name is required", http.StatusBadRequest)
		return
	}

	query := `UPDATE notable_objects 
	          SET object_name = $1, object_json = $2, updated_at = NOW() 
	          WHERE id = $3 
	          RETURNING id, object_name, object_json, created_at, updated_at`

	var object struct {
		ID         string    `json:"id"`
		ObjectName string    `json:"object_name"`
		ObjectJSON string    `json:"object_json"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.ObjectName, payload.ObjectJSON, objectID).Scan(
		&object.ID, &object.ObjectName, &object.ObjectJSON, &object.CreatedAt, &object.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update notable object: %v", err)
		http.Error(w, "Failed to update object", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(object)
}

func DeleteNotableObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	objectID := vars["object_id"]

	query := `DELETE FROM notable_objects WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, objectID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete notable object: %v", err)
		http.Error(w, "Failed to delete object", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Object not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

