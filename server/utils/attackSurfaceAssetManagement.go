package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type AddAttackSurfaceAssetRequest struct {
	ScopeTargetID   string `json:"scope_target_id"`
	AssetType       string `json:"asset_type"`
	AssetIdentifier string `json:"asset_identifier"`
}

func AddAttackSurfaceAsset(w http.ResponseWriter, r *http.Request) {
	var req AddAttackSurfaceAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.ScopeTargetID == "" || req.AssetType == "" || req.AssetIdentifier == "" {
		http.Error(w, "scope_target_id, asset_type, and asset_identifier are required", http.StatusBadRequest)
		return
	}

	validAssetTypes := map[string]bool{
		"asn":             true,
		"network_range":   true,
		"ip_address":      true,
		"fqdn":            true,
		"cloud_asset":     true,
		"live_web_server": true,
	}

	if !validAssetTypes[req.AssetType] {
		http.Error(w, "Invalid asset_type", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	assetID := uuid.New().String()

	switch req.AssetType {
	case "asn":
		if err := addASN(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add ASN: %v", err), http.StatusInternalServerError)
			return
		}

	case "network_range":
		if err := addNetworkRange(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add network range: %v", err), http.StatusInternalServerError)
			return
		}

	case "ip_address":
		if err := addIPAddress(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add IP address: %v", err), http.StatusInternalServerError)
			return
		}

	case "fqdn":
		if err := addFQDN(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add FQDN: %v", err), http.StatusInternalServerError)
			return
		}

	case "cloud_asset":
		if err := addCloudAsset(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add cloud asset: %v", err), http.StatusInternalServerError)
			return
		}

	case "live_web_server":
		if err := addLiveWebServer(ctx, assetID, req.ScopeTargetID, req.AssetIdentifier); err != nil {
			http.Error(w, fmt.Sprintf("Failed to add live web server: %v", err), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Asset added successfully",
		"id":      assetID,
	})
}

func DeleteAttackSurfaceAsset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assetID := vars["asset_id"]

	if assetID == "" {
		http.Error(w, "asset_id is required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	var assetType string
	err := dbPool.QueryRow(ctx, `
		SELECT asset_type FROM consolidated_attack_surface_assets WHERE id = $1
	`, assetID).Scan(&assetType)

	if err != nil {
		http.Error(w, fmt.Sprintf("Asset not found: %v", err), http.StatusNotFound)
		return
	}

	_, err = dbPool.Exec(ctx, `
		DELETE FROM consolidated_attack_surface_assets WHERE id = $1
	`, assetID)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete asset: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Asset deleted successfully",
	})
}

func addASN(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	asnNumber := strings.TrimPrefix(strings.ToUpper(identifier), "AS")

	_, err := dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			asn_number, last_updated
		) VALUES ($1, $2, 'asn', $3, $4, $5)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $5
	`, assetID, scopeTargetID, identifier, asnNumber, time.Now())

	return err
}

func addNetworkRange(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	_, _, err := net.ParseCIDR(identifier)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %v", err)
	}

	_, err = dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			cidr_block, last_updated
		) VALUES ($1, $2, 'network_range', $3, $4, $5)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $5
	`, assetID, scopeTargetID, identifier, identifier, time.Now())

	return err
}

func addIPAddress(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	ip := net.ParseIP(identifier)
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			ip_address, last_updated
		) VALUES ($1, $2, 'ip_address', $3, $4, $5)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $5
	`, assetID, scopeTargetID, identifier, identifier, time.Now())

	return err
}

func addFQDN(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	fqdn := strings.TrimSpace(strings.ToLower(identifier))

	_, err := dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			fqdn, last_updated
		) VALUES ($1, $2, 'fqdn', $3, $4, $5)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $5
	`, assetID, scopeTargetID, identifier, fqdn, time.Now())

	return err
}

func addCloudAsset(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	domain := strings.TrimSpace(strings.ToLower(identifier))

	cloudProvider := ""
	if strings.Contains(domain, "amazonaws.com") || strings.Contains(domain, "s3") {
		cloudProvider = "AWS"
	} else if strings.Contains(domain, "azure") {
		cloudProvider = "Azure"
	} else if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "storage.googleapis.com") {
		cloudProvider = "GCP"
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			domain, cloud_provider, last_updated
		) VALUES ($1, $2, 'cloud_asset', $3, $4, $5, $6)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $6
	`, assetID, scopeTargetID, identifier, domain, cloudProvider, time.Now())

	return err
}

func addLiveWebServer(ctx context.Context, assetID, scopeTargetID, identifier string) error {
	url := strings.TrimSpace(identifier)

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO consolidated_attack_surface_assets (
			id, scope_target_id, asset_type, asset_identifier, 
			url, last_updated
		) VALUES ($1, $2, 'live_web_server', $3, $4, $5)
		ON CONFLICT (scope_target_id, asset_type, asset_identifier) 
		DO UPDATE SET last_updated = $5
	`, assetID, scopeTargetID, identifier, url, time.Now())

	return err
}
