package utils

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type FFUFConfig struct {
	URL                string              `json:"url"`
	Method             string              `json:"method"`
	Headers            []map[string]string `json:"headers"`
	Cookies            string              `json:"cookies"`
	PostData           string              `json:"postData"`
	HTTP2              bool                `json:"http2"`
	FollowRedirects    bool                `json:"followRedirects"`
	Timeout            int                 `json:"timeout"`
	WordlistID         string              `json:"wordlistId"`
	CustomWordlist     string              `json:"customWordlist"`
	WordlistName       string              `json:"wordlistName"`
	Extensions         string              `json:"extensions"`
	Keyword            string              `json:"keyword"`
	MatchStatusCodes   string              `json:"matchStatusCodes"`
	MatchLines         string              `json:"matchLines"`
	MatchSize          string              `json:"matchSize"`
	MatchWords         string              `json:"matchWords"`
	MatchRegex         string              `json:"matchRegex"`
	MatcherMode        string              `json:"matcherMode"`
	FilterStatusCodes  string              `json:"filterStatusCodes"`
	FilterLines        string              `json:"filterLines"`
	FilterSize         string              `json:"filterSize"`
	FilterWords        string              `json:"filterWords"`
	FilterRegex        string              `json:"filterRegex"`
	FilterMode         string              `json:"filterMode"`
	Threads            int                 `json:"threads"`
	RateLimit          int                 `json:"rateLimit"`
	Delay              string              `json:"delay"`
	MaxTime            int                 `json:"maxTime"`
	Verbose            bool                `json:"verbose"`
	AutoCalibrate      bool                `json:"autoCalibrate"`
	Recursion          bool                `json:"recursion"`
	RecursionDepth     int                 `json:"recursionDepth"`
	ProxyURL           string              `json:"proxyURL"`
	ClientCert         string              `json:"clientCert"`
	ClientKey          string              `json:"clientKey"`
}

type FFUFWordlist struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
	Size int    `json:"size"`
}

func SaveFFUFConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var config FFUFConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := `
		INSERT INTO ffuf_configs (scope_target_id, config)
		VALUES ($1, $2)
		ON CONFLICT (scope_target_id)
		DO UPDATE SET config = $2, updated_at = NOW()
	`

	_, err = dbPool.Exec(context.Background(), query, scopeTargetID, configJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func GetFFUFConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var configJSON []byte
	query := `SELECT config FROM ffuf_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&configJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
		return
	}

	var config FFUFConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func UploadFFUFWordlist(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("wordlist")
	if err != nil {
		http.Error(w, "Failed to get file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	wordlistID := uuid.New().String()
	wordlistDir := "/app/wordlists/ffuf"
	
	if err := os.MkdirAll(wordlistDir, 0755); err != nil {
		http.Error(w, "Failed to create wordlist directory", http.StatusInternalServerError)
		return
	}

	filename := filepath.Base(handler.Filename)
	filepath := filepath.Join(wordlistDir, wordlistID+"_"+filename)

	dst, err := os.Create(filepath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	fileInfo, err := dst.Stat()
	if err != nil {
		http.Error(w, "Failed to get file info", http.StatusInternalServerError)
		return
	}

	lineCount := 0
	content, err := os.ReadFile(filepath)
	if err == nil {
		for _, b := range content {
			if b == '\n' {
				lineCount++
			}
		}
	}

	query := `
		INSERT INTO ffuf_wordlists (id, name, path, size, file_size)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err = dbPool.Exec(context.Background(), query, wordlistID, filename, filepath, lineCount, fileInfo.Size())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wordlist := FFUFWordlist{
		ID:   wordlistID,
		Name: filename,
		Path: filepath,
		Size: lineCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wordlist)
}

func GetFFUFWordlists(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT id, name, path, size
		FROM ffuf_wordlists
		ORDER BY created_at DESC
	`

	rows, err := dbPool.Query(context.Background(), query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var wordlists []FFUFWordlist
	for rows.Next() {
		var wl FFUFWordlist
		if err := rows.Scan(&wl.ID, &wl.Name, &wl.Path, &wl.Size); err != nil {
			continue
		}
		wordlists = append(wordlists, wl)
	}

	if wordlists == nil {
		wordlists = []FFUFWordlist{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wordlists)
}

func DeleteFFUFWordlist(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	wordlistID := vars["wordlist_id"]

	var filepath string
	query := `SELECT path FROM ffuf_wordlists WHERE id = $1`
	err := dbPool.QueryRow(context.Background(), query, wordlistID).Scan(&filepath)
	if err != nil {
		http.Error(w, "Wordlist not found", http.StatusNotFound)
		return
	}

	if err := os.Remove(filepath); err != nil {
	}

	deleteQuery := `DELETE FROM ffuf_wordlists WHERE id = $1`
	_, err = dbPool.Exec(context.Background(), deleteQuery, wordlistID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

