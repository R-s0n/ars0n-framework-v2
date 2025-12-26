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

func GetApplicationQuestionsAnswers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, question, answer, created_at, updated_at 
	          FROM application_questions_answers 
	          WHERE scope_target_id = $1 
	          ORDER BY question, created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get application questions answers: %v", err)
		http.Error(w, "Failed to fetch answers", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var answers []map[string]interface{}
	for rows.Next() {
		var answer struct {
			ID        string    `json:"id"`
			Question  string    `json:"question"`
			Answer    string    `json:"answer"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		}

		err := rows.Scan(&answer.ID, &answer.Question, &answer.Answer, &answer.CreatedAt, &answer.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		answers = append(answers, map[string]interface{}{
			"id":         answer.ID,
			"question":   answer.Question,
			"answer":     answer.Answer,
			"created_at": answer.CreatedAt,
			"updated_at": answer.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answers)
}

func CreateApplicationQuestionAnswer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		Question string `json:"question"`
		Answer   string `json:"answer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Question == "" || payload.Answer == "" {
		http.Error(w, "Question and answer are required", http.StatusBadRequest)
		return
	}

	answerID := uuid.New().String()
	query := `INSERT INTO application_questions_answers (id, scope_target_id, question, answer) 
	          VALUES ($1, $2, $3, $4) 
	          RETURNING id, question, answer, created_at, updated_at`

	var answer struct {
		ID        string    `json:"id"`
		Question  string    `json:"question"`
		Answer    string    `json:"answer"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, answerID, scopeTargetID, payload.Question, payload.Answer).Scan(
		&answer.ID, &answer.Question, &answer.Answer, &answer.CreatedAt, &answer.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create application question answer: %v", err)
		http.Error(w, "Failed to create answer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(answer)
}

func UpdateApplicationQuestionAnswer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	answerID := vars["answer_id"]

	var payload struct {
		Answer string `json:"answer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Answer == "" {
		http.Error(w, "Answer is required", http.StatusBadRequest)
		return
	}

	query := `UPDATE application_questions_answers 
	          SET answer = $1, updated_at = NOW() 
	          WHERE id = $2 
	          RETURNING id, question, answer, created_at, updated_at`

	var answer struct {
		ID        string    `json:"id"`
		Question  string    `json:"question"`
		Answer    string    `json:"answer"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.Answer, answerID).Scan(
		&answer.ID, &answer.Question, &answer.Answer, &answer.CreatedAt, &answer.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update application question answer: %v", err)
		http.Error(w, "Failed to update answer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answer)
}

func DeleteApplicationQuestionAnswer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	answerID := vars["answer_id"]

	query := `DELETE FROM application_questions_answers WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, answerID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete application question answer: %v", err)
		http.Error(w, "Failed to delete answer", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Answer not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

