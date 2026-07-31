package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Client Identifiers are candidate unique identifiers pulled out of a discovered endpoint's raw
// HTTP request (path/query IDs, JWT/base64 claims, etc.) — the targets for IDOR / access-control
// testing in the Authorization > Client Identity view. Stored per scope target, keyed to the
// endpoint URL + method so they survive endpoint re-consolidation.

func GetClientIdentifiers(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(),
		`SELECT id, scope_target_id, endpoint_url, method, value, source, label, created_at
		 FROM authz_client_identifiers WHERE scope_target_id = $1 ORDER BY created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get client identifiers: %v", err)
		http.Error(w, "Failed to fetch client identifiers", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	identifiers := []map[string]interface{}{}
	for rows.Next() {
		var id, stID, endpointURL, method, value, source, label string
		var createdAt time.Time
		if err := rows.Scan(&id, &stID, &endpointURL, &method, &value, &source, &label, &createdAt); err != nil {
			log.Printf("[ERROR] Failed to scan client identifier: %v", err)
			continue
		}
		identifiers = append(identifiers, map[string]interface{}{
			"id":              id,
			"scope_target_id": stID,
			"endpoint_url":    endpointURL,
			"method":          method,
			"value":           value,
			"source":          source,
			"label":           label,
			"created_at":      createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(identifiers)
}

func CreateClientIdentifier(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		EndpointURL string `json:"endpoint_url"`
		Method      string `json:"method"`
		Value       string `json:"value"`
		Source      string `json:"source"`
		Label       string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Value) == "" || strings.TrimSpace(payload.EndpointURL) == "" {
		http.Error(w, "endpoint_url and value are required", http.StatusBadRequest)
		return
	}
	if payload.Method == "" {
		payload.Method = "GET"
	}
	if payload.Source == "" {
		payload.Source = "request"
	}

	id := uuid.New().String()
	query := `INSERT INTO authz_client_identifiers (id, scope_target_id, endpoint_url, method, value, source, label)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING id, scope_target_id, endpoint_url, method, value, source, label, created_at`

	var respID, stID, endpointURL, method, value, source, label string
	var createdAt time.Time
	err := dbPool.QueryRow(context.Background(), query,
		id, scopeTargetID, payload.EndpointURL, payload.Method, payload.Value, payload.Source, payload.Label).Scan(
		&respID, &stID, &endpointURL, &method, &value, &source, &label, &createdAt)
	if err != nil {
		log.Printf("[ERROR] Failed to create client identifier: %v", err)
		http.Error(w, "Failed to create client identifier", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":              respID,
		"scope_target_id": stID,
		"endpoint_url":    endpointURL,
		"method":          method,
		"value":           value,
		"source":          source,
		"label":           label,
		"created_at":      createdAt,
	})
}

func DeleteClientIdentifier(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := dbPool.Exec(context.Background(), `DELETE FROM authz_client_identifiers WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to delete client identifier: %v", err)
		http.Error(w, "Failed to delete client identifier", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Client identifier not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
