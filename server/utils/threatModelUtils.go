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

func GetThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, category, url, mechanism, target_object, steps, 
	          impact_customer_data, impact_attacker_scope, impact_company_reputation, 
	          created_at, updated_at 
	          FROM threat_model 
	          WHERE scope_target_id = $1 
	          ORDER BY category, created_at`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get threat model: %v", err)
		http.Error(w, "Failed to fetch threats", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var threats []map[string]interface{}
	for rows.Next() {
		var threat struct {
			ID                        string    `json:"id"`
			Category                  string    `json:"category"`
			URL                       string    `json:"url"`
			Mechanism                 string    `json:"mechanism"`
			TargetObject              string    `json:"target_object"`
			Steps                     string    `json:"steps"`
			ImpactCustomerData        string    `json:"impact_customer_data"`
			ImpactAttackerScope       string    `json:"impact_attacker_scope"`
			ImpactCompanyReputation   string    `json:"impact_company_reputation"`
			CreatedAt                 time.Time `json:"created_at"`
			UpdatedAt                 time.Time `json:"updated_at"`
		}

		err := rows.Scan(&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism, 
			&threat.TargetObject, &threat.Steps, &threat.ImpactCustomerData, 
			&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation, 
			&threat.CreatedAt, &threat.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		threats = append(threats, map[string]interface{}{
			"id":                          threat.ID,
			"category":                    threat.Category,
			"url":                         threat.URL,
			"mechanism":                   threat.Mechanism,
			"target_object":               threat.TargetObject,
			"steps":                       threat.Steps,
			"impact_customer_data":        threat.ImpactCustomerData,
			"impact_attacker_scope":       threat.ImpactAttackerScope,
			"impact_company_reputation":   threat.ImpactCompanyReputation,
			"created_at":                  threat.CreatedAt,
			"updated_at":                  threat.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

func CreateThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		Category                  string `json:"category"`
		URL                       string `json:"url"`
		Mechanism                 string `json:"mechanism"`
		TargetObject              string `json:"target_object"`
		Steps                     string `json:"steps"`
		ImpactCustomerData        string `json:"impact_customer_data"`
		ImpactAttackerScope       string `json:"impact_attacker_scope"`
		ImpactCompanyReputation   string `json:"impact_company_reputation"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Category == "" || payload.URL == "" {
		http.Error(w, "Category and URL are required", http.StatusBadRequest)
		return
	}

	threatID := uuid.New().String()
	query := `INSERT INTO threat_model (id, scope_target_id, category, url, mechanism, 
	          target_object, steps, impact_customer_data, impact_attacker_scope, 
	          impact_company_reputation) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
	          RETURNING id, category, url, mechanism, target_object, steps, 
	          impact_customer_data, impact_attacker_scope, impact_company_reputation, 
	          created_at, updated_at`

	var threat struct {
		ID                        string    `json:"id"`
		Category                  string    `json:"category"`
		URL                       string    `json:"url"`
		Mechanism                 string    `json:"mechanism"`
		TargetObject              string    `json:"target_object"`
		Steps                     string    `json:"steps"`
		ImpactCustomerData        string    `json:"impact_customer_data"`
		ImpactAttackerScope       string    `json:"impact_attacker_scope"`
		ImpactCompanyReputation   string    `json:"impact_company_reputation"`
		CreatedAt                 time.Time `json:"created_at"`
		UpdatedAt                 time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, threatID, scopeTargetID, 
		payload.Category, payload.URL, payload.Mechanism, payload.TargetObject, 
		payload.Steps, payload.ImpactCustomerData, payload.ImpactAttackerScope, 
		payload.ImpactCompanyReputation).Scan(
		&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism, 
		&threat.TargetObject, &threat.Steps, &threat.ImpactCustomerData, 
		&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation, 
		&threat.CreatedAt, &threat.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create threat: %v", err)
		http.Error(w, "Failed to create threat", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(threat)
}

func UpdateThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	threatID := vars["threat_id"]

	var payload struct {
		Category                  string `json:"category"`
		URL                       string `json:"url"`
		Mechanism                 string `json:"mechanism"`
		TargetObject              string `json:"target_object"`
		Steps                     string `json:"steps"`
		ImpactCustomerData        string `json:"impact_customer_data"`
		ImpactAttackerScope       string `json:"impact_attacker_scope"`
		ImpactCompanyReputation   string `json:"impact_company_reputation"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Category == "" || payload.URL == "" {
		http.Error(w, "Category and URL are required", http.StatusBadRequest)
		return
	}

	query := `UPDATE threat_model 
	          SET category = $1, url = $2, mechanism = $3, target_object = $4, 
	          steps = $5, impact_customer_data = $6, impact_attacker_scope = $7, 
	          impact_company_reputation = $8, updated_at = NOW() 
	          WHERE id = $9 
	          RETURNING id, category, url, mechanism, target_object, steps, 
	          impact_customer_data, impact_attacker_scope, impact_company_reputation, 
	          created_at, updated_at`

	var threat struct {
		ID                        string    `json:"id"`
		Category                  string    `json:"category"`
		URL                       string    `json:"url"`
		Mechanism                 string    `json:"mechanism"`
		TargetObject              string    `json:"target_object"`
		Steps                     string    `json:"steps"`
		ImpactCustomerData        string    `json:"impact_customer_data"`
		ImpactAttackerScope       string    `json:"impact_attacker_scope"`
		ImpactCompanyReputation   string    `json:"impact_company_reputation"`
		CreatedAt                 time.Time `json:"created_at"`
		UpdatedAt                 time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.Category, payload.URL, 
		payload.Mechanism, payload.TargetObject, payload.Steps, payload.ImpactCustomerData, 
		payload.ImpactAttackerScope, payload.ImpactCompanyReputation, threatID).Scan(
		&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism, 
		&threat.TargetObject, &threat.Steps, &threat.ImpactCustomerData, 
		&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation, 
		&threat.CreatedAt, &threat.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update threat: %v", err)
		http.Error(w, "Failed to update threat", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threat)
}

func DeleteThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	threatID := vars["threat_id"]

	query := `DELETE FROM threat_model WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, threatID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete threat: %v", err)
		http.Error(w, "Failed to delete threat", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Threat not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

