package models

import (
	"encoding/base64"
	"time"
)

type APIKey struct {
	ID        string    `json:"id"`
	ToolName  string    `json:"tool_name"`
	KeyName   string    `json:"api_key_name"`
	KeyValues KeyValues `json:"key_values"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type KeyValues struct {
	APIKey    string `json:"api_key,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	AppSecret string `json:"app_secret,omitempty"`
}

func (k *KeyValues) IsValid() bool {
	// For SecurityTrails style (single key)
	if k.APIKey != "" {
		return true
	}
	// For Censys style (dual key)
	if k.AppID != "" && k.AppSecret != "" {
		return true
	}
	return false
}

func (k *KeyValues) GetAuthHeader() (string, string) {
	if k.APIKey != "" {
		return "apikey", k.APIKey
	}
	if k.AppID != "" && k.AppSecret != "" {
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(k.AppID+":"+k.AppSecret))
	}
	return "", ""
}
