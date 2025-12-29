package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func TestHackerOneAPIKey(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		APIKey string `json:"api_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	parts := strings.Split(requestData.APIKey, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid API key format", http.StatusBadRequest)
		return
	}

	username := parts[0]
	token := parts[1]

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.hackerone.com/v1/hackers/programs?page[size]=1", nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect to HackerOne API", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode == 200 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "API key is valid",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid API credentials",
		})
	}
}

func GetHackerOneProgram(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-HackerOne-API-Key")
	if apiKey == "" {
		http.Error(w, "API key required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(apiKey, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid API key format", http.StatusBadRequest)
		return
	}

	username := parts[0]
	token := parts[1]

	programHandle := r.URL.Query().Get("handle")
	if programHandle == "" {
		http.Error(w, "Program handle required", http.StatusBadRequest)
		return
	}

	client := &http.Client{}
	url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s?include=structured_scopes", programHandle)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect to HackerOne API", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func ListHackerOnePrograms(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-HackerOne-API-Key")
	if apiKey == "" {
		http.Error(w, "API key required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(apiKey, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid API key format", http.StatusBadRequest)
		return
	}

	username := parts[0]
	token := parts[1]

	pageNumber := r.URL.Query().Get("page[number]")
	pageSize := r.URL.Query().Get("page[size]")
	if pageSize == "" {
		pageSize = "100"
	}

	client := &http.Client{}
	url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs?page[size]=%s", pageSize)
	if pageNumber != "" {
		url += fmt.Sprintf("&page[number]=%s", pageNumber)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to connect to HackerOne API", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

