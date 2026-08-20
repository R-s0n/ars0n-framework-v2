package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"ars0n-framework-v2-server/utils"
)

func createTables() {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto;`,
		`DROP TABLE IF EXISTS requests CASCADE;`,

		`CREATE TABLE IF NOT EXISTS scope_targets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			type VARCHAR(50) NOT NULL CHECK (type IN ('Company', 'Wildcard', 'URL')),
			mode VARCHAR(50) NOT NULL CHECK (mode IN ('Passive', 'Active')),
			scope_target TEXT NOT NULL,
			active BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			config_snapshot JSONB NOT NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'pending',
			started_at TIMESTAMP DEFAULT NOW(),
			ended_at TIMESTAMP,
			steps_run JSONB,
			error_message TEXT,
			final_consolidated_subdomains INTEGER,
			final_live_web_servers INTEGER
		);`,

		`CREATE TABLE IF NOT EXISTS user_settings (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			amass_rate_limit INTEGER DEFAULT 10,
			httpx_rate_limit INTEGER DEFAULT 150,
			subfinder_rate_limit INTEGER DEFAULT 20,
			gau_rate_limit INTEGER DEFAULT 10,
			sublist3r_rate_limit INTEGER DEFAULT 10,
			ctl_rate_limit INTEGER DEFAULT 10,
			shuffledns_rate_limit INTEGER DEFAULT 10000,
			cewl_rate_limit INTEGER DEFAULT 10,
			gospider_rate_limit INTEGER DEFAULT 5,
			subdomainizer_rate_limit INTEGER DEFAULT 5,
			nuclei_screenshot_rate_limit INTEGER DEFAULT 20,
			custom_user_agent TEXT,
			custom_header TEXT,
			burp_proxy_ip TEXT DEFAULT '127.0.0.1',
			burp_proxy_port INTEGER DEFAULT 8080,
			burp_api_ip TEXT DEFAULT '127.0.0.1',
			burp_api_port INTEGER DEFAULT 1337,
			burp_api_key TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`INSERT INTO user_settings (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM user_settings LIMIT 1);`,

		`CREATE TABLE IF NOT EXISTS mcp_server_config (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			enabled BOOLEAN DEFAULT TRUE,
			port INTEGER DEFAULT 3001,
			max_results INTEGER DEFAULT 50,
			result_truncation_length INTEGER DEFAULT 3000,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`INSERT INTO mcp_server_config (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM mcp_server_config LIMIT 1);`,

		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tool_name VARCHAR(100) NOT NULL,
			api_key_name VARCHAR(200) NOT NULL,
			api_key_value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tool_name, api_key_name)
		);`,

		`CREATE TABLE IF NOT EXISTS ai_api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			provider VARCHAR(100) NOT NULL,
			api_key_name VARCHAR(200) NOT NULL,
			key_values JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(provider, api_key_name)
		);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_config (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			amass BOOLEAN DEFAULT TRUE,
			sublist3r BOOLEAN DEFAULT TRUE,
			assetfinder BOOLEAN DEFAULT TRUE,
			gau BOOLEAN DEFAULT TRUE,
			ctl BOOLEAN DEFAULT TRUE,
			subfinder BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round1 BOOLEAN DEFAULT TRUE,
			shuffledns BOOLEAN DEFAULT TRUE,
			cewl BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round2 BOOLEAN DEFAULT TRUE,
			gospider BOOLEAN DEFAULT TRUE,
			subdomainizer BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round3 BOOLEAN DEFAULT TRUE,
			nuclei_screenshot BOOLEAN DEFAULT TRUE,
			metadata BOOLEAN DEFAULT TRUE,
			nuclei BOOLEAN DEFAULT TRUE,
			max_consolidated_subdomains INTEGER DEFAULT 2500,
			max_live_web_servers INTEGER DEFAULT 500,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`INSERT INTO auto_scan_config (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM auto_scan_config LIMIT 1);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_state (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			current_step TEXT NOT NULL,
			is_paused BOOLEAN DEFAULT false,
			is_cancelled BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS amass_intel_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS httpx_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS gau_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS sublist3r_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS assetfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS ctl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS subfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shuffledns_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS cewl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shufflednscustom_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS gospider_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS subdomainizer_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS nuclei_screenshots (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS metadata_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL,
			config JSONB
		);`,

		`CREATE TABLE IF NOT EXISTS company_metadata_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL,
			ip_port_scan_id UUID NOT NULL,
			status VARCHAR(50) NOT NULL,
			error_message TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS securitytrails_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS github_recon_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shodan_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS censys_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS metabigor_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_enum_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS katana_url_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS gospider_url_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS linkfinder_url_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS waybackurls_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS gau_url_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS ffuf_url_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS waf_probe_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		// Target Behaviour Probe v2. Config is per scope target, mirroring the ffuf_configs pattern.
		`CREATE TABLE IF NOT EXISTS waf_probe_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		// The exact config a run used, so a result is self-describing and two scans are comparable.
		// Without this, a stored result cannot be interpreted once the saved config has moved on.
		`ALTER TABLE waf_probe_scans ADD COLUMN IF NOT EXISTS config JSONB;`,
		`ALTER TABLE waf_probe_scans ADD COLUMN IF NOT EXISTS schema_version INT DEFAULT 1;`,
		`ALTER TABLE waf_probe_scans ADD COLUMN IF NOT EXISTS posture VARCHAR(32);`,
		`ALTER TABLE waf_probe_scans ADD COLUMN IF NOT EXISTS requests_sent INT DEFAULT 0;`,
		`ALTER TABLE waf_probe_scans ADD COLUMN IF NOT EXISTS trips_used INT DEFAULT 0;`,

		// The probe no longer writes to tool configs, so waf_probe_apply_journal and
		// probe_tool_tuning are no longer created. Automated apply was removed because its failures
		// were silent: a translated value that did not fit the tool's field decoded to zero, and the
		// journal still recorded a successful apply. The probe now reports what it measured and the
		// operator sets it. Existing rows in those tables are left alone rather than dropped, so an
		// install that used apply keeps the record of what it changed.

		// Deliberate blocks cost reputation against the egress IP across every target, not just
		// this one, and the cost outlives the run. Accounting for it per IP over 24h is the only
		// way the trip budget means anything.
		`CREATE TABLE IF NOT EXISTS waf_probe_egress_trips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			egress_fingerprint TEXT NOT NULL,
			scan_id UUID NOT NULL,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE SET NULL,
			trips INT NOT NULL DEFAULT 0,
			vendor TEXT,
			occurred_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_probe_egress_trips
			ON waf_probe_egress_trips(egress_fingerprint, occurred_at DESC);`,

		`CREATE TABLE IF NOT EXISTS ffuf_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS ffuf_wordlists (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			size INTEGER DEFAULT 0,
			file_size BIGINT DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS ffuf_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			config_id UUID REFERENCES ffuf_configs(id) ON DELETE SET NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS application_questions_answers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			question TEXT NOT NULL,
			answer TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS mechanisms_examples (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			mechanism TEXT NOT NULL,
			url TEXT NOT NULL,
			notes TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS notable_objects (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			object_name TEXT NOT NULL,
			object_json TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, object_name)
		);`,

		`CREATE TABLE IF NOT EXISTS security_controls_notes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			control_name TEXT NOT NULL,
			note TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS threat_model (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			category TEXT NOT NULL,
			url TEXT NOT NULL,
			mechanism TEXT,
			target_object TEXT,
			steps TEXT,
			security_controls TEXT,
			impact_customer_data TEXT,
			impact_attacker_scope TEXT,
			impact_company_reputation TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS nuclei_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			targets TEXT[] NOT NULL DEFAULT '{}',
			templates TEXT[] NOT NULL DEFAULT '{}',
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS investigate_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS ip_port_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_network_ranges INT DEFAULT 0,
			processed_network_ranges INT DEFAULT 0,
			total_ips_discovered INT DEFAULT 0,
			total_ports_scanned INT DEFAULT 0,
			live_web_servers_found INT DEFAULT 0,
			error_message TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS discovered_live_ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			network_range TEXT NOT NULL,
			ping_time_ms FLOAT,
			discovered_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS live_web_servers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			port INT NOT NULL,
			protocol VARCHAR(10) NOT NULL,
			url TEXT NOT NULL,
			status_code INT,
			title TEXT,
			server_header TEXT,
			content_length BIGINT,
			technologies JSONB,
			response_time_ms FLOAT,
			screenshot_path TEXT,
			ssl_info JSONB,
			http_response_headers JSONB,
			findings_json JSONB,
			last_checked TIMESTAMP DEFAULT NOW(),
			UNIQUE(scan_id, ip_address, port, protocol)
		);`,

		`CREATE TABLE IF NOT EXISTS target_urls (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			url TEXT NOT NULL,
			screenshot TEXT,
			status_code INTEGER,
			title TEXT,
			web_server TEXT,
			technologies TEXT[],
			content_length INTEGER,
			newly_discovered BOOLEAN DEFAULT false,
			no_longer_live BOOLEAN DEFAULT false,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			has_deprecated_tls BOOLEAN DEFAULT false,
			has_expired_ssl BOOLEAN DEFAULT false,
			has_mismatched_ssl BOOLEAN DEFAULT false,
			has_revoked_ssl BOOLEAN DEFAULT false,
			has_self_signed_ssl BOOLEAN DEFAULT false,
			has_untrusted_root_ssl BOOLEAN DEFAULT false,
			has_wildcard_tls BOOLEAN DEFAULT false,
			findings_json JSONB,
			http_response TEXT,
			http_response_headers JSONB,
			dns_a_records TEXT[],
			dns_aaaa_records TEXT[],
			dns_cname_records TEXT[],
			dns_mx_records TEXT[],
			dns_txt_records TEXT[],
			dns_ns_records TEXT[],
			dns_ptr_records TEXT[],
			dns_srv_records TEXT[],
			katana_results JSONB,
			ffuf_results JSONB,
			roi_score INTEGER DEFAULT 50,
			ip_address TEXT,
			UNIQUE(url, scope_target_id)
		);`,

		`CREATE TABLE IF NOT EXISTS dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			ip_address TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azu')),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS asns (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			number TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS subnets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS service_providers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			provider TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, subdomain)
		);`,

		`CREATE TABLE IF NOT EXISTS intel_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			description TEXT,
			country TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_intel_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS intel_asn_data (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			asn_number TEXT NOT NULL,
			organization TEXT,
			description TEXT,
			country TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_intel_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS google_dorking_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS reverse_whois_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_company_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			source TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			description TEXT,
			country TEXT,
			source TEXT NOT NULL,
			scan_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, cidr_block, source)
		);`,

		`CREATE TABLE IF NOT EXISTS metabigor_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			country TEXT,
			scan_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES metabigor_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azure', 'unknown')),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_raw_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			raw_output TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			wildcard_domains JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS amass_intel_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_network_ranges JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			wildcard_domains JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES dnsx_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_raw_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			raw_output TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES dnsx_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_domain_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			last_scan_id UUID,
			raw_output TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES dnsx_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, record, record_type)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_domain_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			last_scan_id UUID,
			raw_output TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			cloud_domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azure', 'unknown')),
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES amass_enum_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, cloud_domain)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES amass_enum_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, record, record_type)
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			selected_wildcard_domains JSONB DEFAULT '[]',
			selected_live_web_servers JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		// URL-workflow crawler configs. Each holds one jsonb `config` under a unique scope_target_id,
		// which is the shape the probe's apply path already knows how to merge into and revert, so
		// a measured rate can reach the tool that has to obey it.
		`CREATE TABLE IF NOT EXISTS katana_url_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS gospider_url_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS linkfinder_url_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_enum_configs (
			id SERIAL PRIMARY KEY,
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			keywords TEXT[],
			threads INTEGER DEFAULT 5,
			enabled_platforms JSONB DEFAULT '{"aws": true, "azure": true, "gcp": true}',
			custom_dns_server TEXT DEFAULT '',
			dns_resolver_mode TEXT DEFAULT 'multiple',
			resolver_config TEXT DEFAULT 'default',
			additional_resolvers TEXT DEFAULT '',
			mutations_file_path TEXT DEFAULT '',
			brute_file_path TEXT DEFAULT '',
			resolver_file_path TEXT DEFAULT '',
			selected_services JSONB DEFAULT '{"aws": ["s3"], "azure": ["storage-accounts"], "gcp": ["gcp-buckets"]}',
			selected_regions JSONB DEFAULT '{"aws": ["us-east-1"], "azure": ["eastus"], "gcp": ["us-central1"]}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_cloud_assets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			asset_domain TEXT NOT NULL,
			asset_url TEXT NOT NULL,
			asset_type TEXT NOT NULL,
			service TEXT NOT NULL,
			description TEXT,
			source_url TEXT,
			region TEXT,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, root_domain, asset_url, asset_type)
		);`,

		// Column defaults come from utils.DefaultNucleiTemplates / DefaultNucleiSeverities so the
		// schema cannot disagree with the API and the UI about what "default" means.
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS nuclei_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			targets TEXT[] NOT NULL DEFAULT '{}',
			templates TEXT[] NOT NULL DEFAULT %s,
			severities TEXT[] DEFAULT %s,
			uploaded_templates JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,
			utils.PostgresArrayLiteral(utils.DefaultNucleiTemplates),
			utils.PostgresArrayLiteral(utils.DefaultNucleiSeverities)),

		// CREATE TABLE IF NOT EXISTS leaves an existing table's defaults alone, so an install that
		// predates a change to the lists above would keep the old ones. Existing rows are not
		// touched: a target that already has a saved config keeps the categories it was given.
		fmt.Sprintf(`ALTER TABLE nuclei_configs ALTER COLUMN templates SET DEFAULT %s;`,
			utils.PostgresArrayLiteral(utils.DefaultNucleiTemplates)),
		fmt.Sprintf(`ALTER TABLE nuclei_configs ALTER COLUMN severities SET DEFAULT %s;`,
			utils.PostgresArrayLiteral(utils.DefaultNucleiSeverities)),

		`ALTER TABLE nuclei_configs ADD COLUMN IF NOT EXISTS target_mode VARCHAR(50) DEFAULT 'attack_surface';`,
		`ALTER TABLE nuclei_configs ADD COLUMN IF NOT EXISTS template_ids TEXT[] DEFAULT '{}';`,
		`ALTER TABLE nuclei_configs ADD COLUMN IF NOT EXISTS exclude_ids TEXT[] DEFAULT '{}';`,
		`ALTER TABLE nuclei_configs ADD COLUMN IF NOT EXISTS exclude_tags TEXT[] DEFAULT '{}';`,
		`ALTER TABLE nuclei_configs ADD COLUMN IF NOT EXISTS advanced_config JSONB DEFAULT '{}';`,

		`ALTER TABLE auto_scan_config ADD COLUMN IF NOT EXISTS nuclei BOOLEAN DEFAULT TRUE;`,

		`CREATE TABLE IF NOT EXISTS httpx_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,

		// Migration: Drop unused Katana Company tables
		`DROP TABLE IF EXISTS katana_company_cloud_findings CASCADE;`,
		`DROP TABLE IF EXISTS katana_company_domain_results CASCADE;`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_assets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN ('asn', 'network_range', 'ip_address', 'live_web_server', 'cloud_asset', 'fqdn')),
			asset_identifier TEXT NOT NULL,
			asset_subtype VARCHAR(50),
			
			-- ASN specific fields
			asn_number TEXT,
			asn_organization TEXT,
			asn_description TEXT,
			asn_country TEXT,
			
			-- Network range specific fields
			cidr_block TEXT,
			subnet_size INTEGER,
			responsive_ip_count INTEGER,
			responsive_port_count INTEGER,
			
			-- IP address specific fields
			ip_address TEXT,
			ip_type TEXT,
			dnsx_a_records TEXT[],
			amass_a_records TEXT[],
			httpx_sources TEXT[],
			
			-- Live web server specific fields
			url TEXT,
			domain TEXT,
			port INTEGER,
			protocol TEXT,
			status_code INTEGER,
			title TEXT,
			web_server TEXT,
			technologies TEXT[],
			content_length INTEGER,
			response_time_ms FLOAT,
			screenshot_path TEXT,
			ssl_info JSONB,
			http_response_headers JSONB,
			findings_json JSONB,
			
			-- Cloud asset specific fields
			cloud_provider VARCHAR(50),
			cloud_service_type VARCHAR(100),
			cloud_region TEXT,
			
			-- FQDN specific fields
			fqdn TEXT,
			root_domain TEXT,
			subdomain TEXT,
			registrar TEXT,
			creation_date DATE,
			expiration_date DATE,
			updated_date DATE,
			name_servers TEXT[],
			status TEXT[],
			whois_info JSONB,
			ssl_certificate JSONB,
			ssl_expiry_date DATE,
			ssl_issuer TEXT,
			ssl_subject TEXT,
			ssl_version TEXT,
			ssl_cipher_suite TEXT,
			ssl_protocols TEXT[],
			resolved_ips TEXT[],
			mail_servers TEXT[],
			spf_record TEXT,
			dkim_record TEXT,
			dmarc_record TEXT,
			caa_records TEXT[],
			txt_records TEXT[],
			mx_records TEXT[],
			ns_records TEXT[],
			a_records TEXT[],
			aaaa_records TEXT[],
			cname_records TEXT[],
			ptr_records TEXT[],
			srv_records TEXT[],
			soa_record JSONB,
			last_dns_scan TIMESTAMP,
			last_ssl_scan TIMESTAMP,
			last_whois_scan TIMESTAMP,
			
			-- Common fields
			last_updated TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			
			UNIQUE(scope_target_id, asset_type, asset_identifier)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_relationships (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			parent_asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			child_asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			relationship_type VARCHAR(50) NOT NULL,
			relationship_data JSONB,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(parent_asset_id, child_asset_id, relationship_type)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			record_type VARCHAR(10) NOT NULL,
			record_value TEXT NOT NULL,
			ttl INTEGER,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(asset_id, record_type, record_value)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_metadata (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			metadata_type VARCHAR(50) NOT NULL,
			metadata_key TEXT NOT NULL,
			metadata_value TEXT,
			metadata_json JSONB,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(asset_id, metadata_type, metadata_key)
		);`,

		// Add missing columns to user_settings table for existing installations
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_proxy_ip TEXT DEFAULT '127.0.0.1';`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_proxy_port INTEGER DEFAULT 8080;`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_ip TEXT DEFAULT '127.0.0.1';`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_port INTEGER DEFAULT 1337;`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_key TEXT DEFAULT '';`,

		// Add config column to metadata_scans table for existing installations
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS config JSONB;`,
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN DEFAULT false;`,
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS current_step VARCHAR(100);`,
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS total_urls INTEGER DEFAULT 0;`,
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS processed_urls INTEGER DEFAULT 0;`,
		`ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS current_url TEXT;`,

		// Add status_code column to URL scan tables
		`ALTER TABLE katana_url_scans ADD COLUMN IF NOT EXISTS status_code JSONB;`,
		`ALTER TABLE linkfinder_url_scans ADD COLUMN IF NOT EXISTS status_code JSONB;`,
		`ALTER TABLE waybackurls_scans ADD COLUMN IF NOT EXISTS status_code JSONB;`,
		`ALTER TABLE gau_url_scans ADD COLUMN IF NOT EXISTS status_code JSONB;`,

		`CREATE TABLE IF NOT EXISTS discovered_endpoints (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			scan_type VARCHAR(50) NOT NULL,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			domain TEXT NOT NULL,
			path TEXT NOT NULL,
			normalized_path TEXT NOT NULL,
			status_code INTEGER,
			is_direct BOOLEAN DEFAULT true,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scan_id, url)
		);`,

		`CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON discovered_endpoints(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_scope_target_id ON discovered_endpoints(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_is_direct ON discovered_endpoints(is_direct);`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_normalized_path ON discovered_endpoints(normalized_path);`,

		`CREATE TABLE IF NOT EXISTS endpoint_parameters (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			endpoint_id UUID NOT NULL REFERENCES discovered_endpoints(id) ON DELETE CASCADE,
			param_type VARCHAR(20) NOT NULL,
			param_name TEXT NOT NULL,
			example_value TEXT,
			position INTEGER,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(endpoint_id, param_type, param_name, position)
		);`,

		`CREATE INDEX IF NOT EXISTS idx_parameters_endpoint_id ON endpoint_parameters(endpoint_id);`,
		`CREATE INDEX IF NOT EXISTS idx_parameters_type ON endpoint_parameters(param_type);`,

		`CREATE TABLE IF NOT EXISTS manual_crawl_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			target_url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			started_at TIMESTAMP DEFAULT NOW(),
			ended_at TIMESTAMP,
			request_count INTEGER DEFAULT 0,
			endpoint_count INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS manual_crawl_captures (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_id UUID NOT NULL REFERENCES manual_crawl_sessions(id) ON DELETE CASCADE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			method VARCHAR(10) NOT NULL,
			status_code INTEGER,
			headers JSONB,
			response_headers JSONB,
			post_data TEXT,
			response_body TEXT,
			get_params JSONB,
			post_params JSONB,
			body_type TEXT,
			timestamp TIMESTAMP DEFAULT NOW(),
			mime_type TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_sessions_scope_target ON manual_crawl_sessions(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_sessions_status ON manual_crawl_sessions(status);`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_session ON manual_crawl_captures(session_id);`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_scope_target ON manual_crawl_captures(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_endpoint ON manual_crawl_captures(endpoint);`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_method ON manual_crawl_captures(method);`,

		`CREATE TABLE IF NOT EXISTS consolidated_url_endpoints (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			url TEXT NOT NULL,
			normalized_url TEXT NOT NULL,
			domain TEXT NOT NULL,
			path TEXT NOT NULL,
			method VARCHAR(10) DEFAULT 'GET',
			is_direct BOOLEAN DEFAULT true,
			origin_url TEXT,
			status_codes JSONB DEFAULT '[]',
			headers JSONB DEFAULT '{}',
			response_headers JSONB DEFAULT '{}',
			request_count INTEGER DEFAULT 1,
			first_seen TIMESTAMP DEFAULT NOW(),
			last_seen TIMESTAMP DEFAULT NOW(),
			sources TEXT[] DEFAULT '{}',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, url, method)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_url_parameters (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			endpoint_id UUID NOT NULL REFERENCES consolidated_url_endpoints(id) ON DELETE CASCADE,
			param_type VARCHAR(20) NOT NULL,
			param_name TEXT NOT NULL,
			example_values JSONB DEFAULT '[]',
			frequency INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(endpoint_id, param_type, param_name)
		);`,

		`CREATE TABLE IF NOT EXISTS endpoint_investigation_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_endpoints INTEGER DEFAULT 0,
			processed_endpoints INTEGER DEFAULT 0,
			result TEXT,
			error TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE INDEX IF NOT EXISTS idx_consolidated_endpoints_scope_target ON consolidated_url_endpoints(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_endpoints_domain ON consolidated_url_endpoints(domain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_endpoints_is_direct ON consolidated_url_endpoints(is_direct);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_endpoints_normalized ON consolidated_url_endpoints(normalized_url);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_parameters_endpoint ON consolidated_url_parameters(endpoint_id);`,

		// Migration: Fix example_values column type if it exists as TEXT[]
		`DO $$ 
		BEGIN 
			IF EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name='consolidated_url_parameters' 
				AND column_name='example_values' 
				AND data_type='ARRAY'
			) THEN
				ALTER TABLE consolidated_url_parameters ALTER COLUMN example_values TYPE JSONB USING example_values::text::jsonb;
			END IF;
		END $$;`,

		// Migration: Add new columns to manual_crawl_captures if they don't exist
		`DO $$ 
		BEGIN 
			IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='manual_crawl_captures' AND column_name='get_params') THEN
				ALTER TABLE manual_crawl_captures ADD COLUMN get_params JSONB;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='manual_crawl_captures' AND column_name='post_params') THEN
				ALTER TABLE manual_crawl_captures ADD COLUMN post_params JSONB;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='manual_crawl_captures' AND column_name='body_type') THEN
				ALTER TABLE manual_crawl_captures ADD COLUMN body_type TEXT;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='manual_crawl_captures' AND column_name='response_body') THEN
				ALTER TABLE manual_crawl_captures ADD COLUMN response_body TEXT;
			END IF;
		END $$;`,

		// Manual crawl liveness + provenance. `last_heartbeat_at` lets the framework tell a session
		// that is genuinely recording from one whose extension died (MV3 service workers get
		// terminated), instead of trusting status='active' forever. `tab_id` records where a request
		// came from now that capture is scoped by host rather than by tab.
		`ALTER TABLE manual_crawl_sessions ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMP;`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS tab_id INTEGER;`,

		// Extracts the hostname from a stored URL. Used wherever an endpoint's identity depends on
		// its host, which is anywhere direct and adjacent traffic are counted separately.
		`CREATE OR REPLACE FUNCTION capture_host(u TEXT) RETURNS TEXT AS $func$
		   SELECT lower(COALESCE(substring(u from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)'), ''));
		 $func$ LANGUAGE SQL IMMUTABLE;`,

		// Direct (the target host itself) vs adjacent (any other in-scope host), matching how every
		// other URL-workflow tool splits its results. Applications routinely serve their API from a
		// different host than the one being tested, and those requests are the interesting ones.
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS is_direct BOOLEAN;`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_is_direct ON manual_crawl_captures(scope_target_id, is_direct);`,
		// Backfill captures recorded before the column existed by comparing their host to the scope
		// target's, handling scope targets stored with or without a scheme.
		`UPDATE manual_crawl_captures c
		 SET is_direct = (
		   lower(substring(c.url from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)')) =
		   lower(COALESCE(
		     substring(st.scope_target from '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)'),
		     st.scope_target
		   ))
		 )
		 FROM scope_targets st
		 WHERE st.id = c.scope_target_id AND c.is_direct IS NULL;`,
		// Hosts the extension saw and rejected as out of scope, with hit counts. Reported on the
		// heartbeat so the framework can explain missing traffic without the user opening the popup.
		`ALTER TABLE manual_crawl_sessions ADD COLUMN IF NOT EXISTS observed_out_of_scope JSONB DEFAULT '{}'::jsonb;`,
		`UPDATE manual_crawl_sessions SET last_heartbeat_at = started_at WHERE last_heartbeat_at IS NULL;`,

		// Per-target host decisions, which is how an adjacent host becomes something the framework
		// may send requests to.
		//
		// A row can point either way, and that is the whole reason this is a table rather than a
		// list of accepted hosts. Manual-crawl hosts are in scope by default because the extension
		// refuses to record a host nobody authorized, so their presence already implies consent. An
		// explicit EXCLUDE still has to be representable for where that default is wrong: recording
		// with includeSubdomains on scopes a whole base domain, which can sweep in an analytics or
		// CDN host the operator never intended to probe.
		`CREATE TABLE IF NOT EXISTS scope_target_scope_hosts (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    host TEXT NOT NULL,
		    in_scope BOOLEAN NOT NULL DEFAULT TRUE,
		    source TEXT NOT NULL DEFAULT 'manual_crawl',
		    note TEXT,
		    created_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (scope_target_id, host)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_scope_target_scope_hosts_target
		   ON scope_target_scope_hosts(scope_target_id);`,

		// Capture provenance and the richer fields the multi-source extension produces.
		// `sources` records which of webrequest/hook/debugger contributed, which is how you tell a
		// metadata-only record from one that carries real bodies.
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS sources TEXT[] DEFAULT '{}';`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS graphql_operation TEXT DEFAULT '';`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS resource_type TEXT DEFAULT '';`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS initiator TEXT DEFAULT '';`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS redirect_chain JSONB DEFAULT '[]'::jsonb;`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS error TEXT DEFAULT '';`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS duration_ms INTEGER DEFAULT 0;`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS request_body_truncated BOOLEAN DEFAULT FALSE;`,
		`ALTER TABLE manual_crawl_captures ADD COLUMN IF NOT EXISTS response_body_truncated BOOLEAN DEFAULT FALSE;`,
		`CREATE INDEX IF NOT EXISTS idx_manual_crawl_captures_graphql ON manual_crawl_captures(graphql_operation) WHERE graphql_operation <> '';`,

		// Create indexes for performance
		`CREATE INDEX IF NOT EXISTS target_urls_url_idx ON target_urls (url);`,
		`CREATE INDEX IF NOT EXISTS target_urls_scope_target_id_idx ON target_urls (scope_target_id);`,
		// Composite index backing GetTargetURLsForScopeTarget's WHERE + ORDER BY roi_score DESC,
		// created_at DESC (+ LIMIT/OFFSET pagination) — audit §1.1/G1.1.
		`CREATE INDEX IF NOT EXISTS target_urls_scope_roi_idx ON target_urls (scope_target_id, roi_score DESC, created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_live_ips_scan_id ON discovered_live_ips(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_scan_id ON live_web_servers(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_ip_port ON live_web_servers(ip_address, port);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_scope_target ON consolidated_attack_surface_assets(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_asset_type ON consolidated_attack_surface_assets(asset_type);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_asset_identifier ON consolidated_attack_surface_assets(asset_identifier);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_ip_address ON consolidated_attack_surface_assets(ip_address);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_domain ON consolidated_attack_surface_assets(domain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_fqdn ON consolidated_attack_surface_assets(fqdn);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_root_domain ON consolidated_attack_surface_assets(root_domain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_subdomain ON consolidated_attack_surface_assets(subdomain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_registrar ON consolidated_attack_surface_assets(registrar);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_ssl_expiry_date ON consolidated_attack_surface_assets(ssl_expiry_date);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_relationships_parent ON consolidated_attack_surface_relationships(parent_asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_relationships_child ON consolidated_attack_surface_relationships(child_asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_dns_records_asset_id ON consolidated_attack_surface_dns_records(asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_metadata_asset_id ON consolidated_attack_surface_metadata(asset_id);`,

		`CREATE TABLE IF NOT EXISTS arjun_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS arjun_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_endpoints INT DEFAULT 0,
			processed_endpoints INT DEFAULT 0,
			parameters_found INT DEFAULT 0,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		// parameth was removed from the framework on 2026-08-06: its one-baseline detection model
		// misreports on dynamic APIs, producing 94,888 false findings on a corpus where Arjun found
		// 2 and x8 found 0. Its parameth_configs and parameth_scans tables are dropped below rather
		// than merely left uncreated, because a CREATE TABLE IF NOT EXISTS that is simply deleted
		// leaves the tables standing on every database that already ran it.
		`DROP TABLE IF EXISTS parameth_scans;`,
		`DROP TABLE IF EXISTS parameth_configs;`,

		`CREATE TABLE IF NOT EXISTS x8_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS x8_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_endpoints INT DEFAULT 0,
			processed_endpoints INT DEFAULT 0,
			parameters_found INT DEFAULT 0,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS parameter_enumeration_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			scan_type VARCHAR(50) NOT NULL,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			endpoint_url TEXT NOT NULL,
			parameter_name TEXT NOT NULL,
			parameter_type VARCHAR(50) NOT NULL,
			example_value TEXT,
			confidence VARCHAR(50),
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE INDEX IF NOT EXISTS idx_parameter_enumeration_results_scan_id ON parameter_enumeration_results(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_parameter_enumeration_results_scope_target ON parameter_enumeration_results(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_parameter_enumeration_results_endpoint ON parameter_enumeration_results(endpoint_url);`,

		// The verb the parameter was found under. Without it a finding on POST /accounts is
		// indistinguishable from one on GET /accounts, and a scan that runs verb groups in sequence
		// cannot report which pass produced what.
		`ALTER TABLE parameter_enumeration_results ADD COLUMN IF NOT EXISTS http_method VARCHAR(10) NOT NULL DEFAULT 'GET';`,
		// Which pass of the scan produced the row, e.g. "POST (JSON body)". Arjun runs the same
		// endpoints twice under different body encodings, so the group is what distinguishes them.
		`ALTER TABLE parameter_enumeration_results ADD COLUMN IF NOT EXISTS verb_group TEXT;`,
		// Re-running a tool used to append a second full copy of its findings, because nothing
		// deduplicated and nothing deleted first. One row per scan/endpoint/verb/parameter.
		`DELETE FROM parameter_enumeration_results a USING parameter_enumeration_results b
		 WHERE a.ctid < b.ctid AND a.scan_id = b.scan_id AND a.endpoint_url = b.endpoint_url
		   AND a.http_method = b.http_method AND a.parameter_name = b.parameter_name;`,
		// Why the parameter was reported: x8 distinguishes a reflected value from a changed status
		// code from a changed body, and collapsing all three into one confidence label threw away
		// the operator's main lead on whether a hit is worth chasing.
		`ALTER TABLE parameter_enumeration_results ADD COLUMN IF NOT EXISTS detection_reason TEXT;`,
		// The unique key now includes parameter_type, which RELAXES it.
		//
		// x8 runs up to four injection places per endpoint inside one scan, all from the same
		// wordlist, so "debug" found in the query and "debug" found in a cookie on the same
		// GET /path are two different findings. Under the old key the second one hit
		// ON CONFLICT DO NOTHING, was silently dropped, and was not counted. Arjun's form and JSON
		// passes both store type 'body', so its original dedupe still holds.
		`DROP INDEX IF EXISTS idx_parameter_enumeration_results_unique;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_parameter_enumeration_results_uniq_place
		   ON parameter_enumeration_results(scan_id, endpoint_url, http_method, parameter_name,
		                                    parameter_type);`,

		// Which endpoints each parameter tool runs against.
		//
		// A row is written only when the operator makes an explicit choice, and an absent row means
		// enabled. That is what makes "every valid endpoint is scanned by default" true without a
		// backfill, and it keeps a newly discovered endpoint in scope automatically instead of
		// silently excluded because it was not present when the operator last opened the modal.
		`CREATE TABLE IF NOT EXISTS param_enum_endpoint_selection (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    tool VARCHAR(20) NOT NULL,
		    endpoint_id UUID NOT NULL REFERENCES consolidated_url_endpoints(id) ON DELETE CASCADE,
		    enabled BOOLEAN NOT NULL DEFAULT TRUE,
		    updated_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (scope_target_id, tool, endpoint_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_param_enum_selection_lookup
		   ON param_enum_endpoint_selection(scope_target_id, tool);`,
		// Which of a tool's request shapes an endpoint is tested with. NULL means "whatever the
		// auto-categoriser decides", so a newly consolidated endpoint is classified from its own
		// recorded request rather than inheriting a stale choice. Only Arjun uses this today: its
		// -m takes GET/POST/JSON/XML, which are body encodings rather than HTTP verbs.
		`ALTER TABLE param_enum_endpoint_selection ADD COLUMN IF NOT EXISTS mode VARCHAR(10);`,

		// Purge anything the removed parameth tool left behind. Placed here, after both tables
		// exist, because the runner log.Fatalf's on any error that is not "already exists", so a
		// DELETE against a not-yet-created table would stop a fresh database from starting at all.
		`DELETE FROM parameter_enumeration_results WHERE scan_type = 'parameth';`,
		`DELETE FROM param_enum_endpoint_selection WHERE tool = 'parameth';`,

		// === The fuzz composer: how FFUF and x8 are configured and run =========================
		//
		// The stored artifact is the RAW HTTP REQUEST TEXT, not a structured model that renders to
		// one. Both tools consume exactly this file (ffuf -request, x8 -r), so the bytes the
		// operator edits are the bytes on the wire and there is no second copy to drift from the
		// preview. That is the same rule paramEnumPreview.go is built on.
		//
		// One flow per scope target.
		`CREATE TABLE IF NOT EXISTS fuzz_flows (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
		    created_at TIMESTAMP DEFAULT NOW(),
		    updated_at TIMESTAMP DEFAULT NOW()
		);`,
		// Settings applied to every step of this flow that does not set them itself. Same vocabulary as
		// a step's own options, one place, so the operator sets a rate limit or a filter once for the
		// target instead of on each round. A step still wins where the two disagree: the default is
		// what to do absent an instruction, not an override.
		`ALTER TABLE fuzz_flows ADD COLUMN IF NOT EXISTS default_options JSONB NOT NULL DEFAULT '{}'::jsonb;`,

		// A round. tool decides which fields matter: ffuf uses ffuf_mode and many positions, x8 uses
		// x8_place and has no per-position payloads at all, because its -w is a list of parameter
		// NAMES rather than values.
		`CREATE TABLE IF NOT EXISTS fuzz_steps (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    flow_id UUID NOT NULL REFERENCES fuzz_flows(id) ON DELETE CASCADE,
		    ordinal INT NOT NULL,
		    tool VARCHAR(10) NOT NULL CHECK (tool IN ('ffuf','x8')),
		    name TEXT,
		    enabled BOOLEAN NOT NULL DEFAULT TRUE,
		    seed_endpoint_id UUID REFERENCES consolidated_url_endpoints(id) ON DELETE SET NULL,
		    raw_request TEXT NOT NULL,
		    scheme TEXT NOT NULL DEFAULT 'https',
		    port INT,
		    target_host TEXT NOT NULL,
		    ffuf_mode VARCHAR(20),
		    x8_place VARCHAR(10),
		    options JSONB NOT NULL DEFAULT '{}'::jsonb,
		    created_at TIMESTAMP DEFAULT NOW(),
		    updated_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (flow_id, ordinal)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_steps_flow ON fuzz_steps(flow_id, ordinal);`,

		// A marked span inside raw_request. role is derived from where the token sits so the UI can
		// describe it, but ffuf itself only knows four containers (method, headers, URL, body):
		// substitution is one strings.ReplaceAll per container, so a cookie position IS a header
		// position and a path position IS a URL position.
		`CREATE TABLE IF NOT EXISTS fuzz_positions (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    step_id UUID NOT NULL REFERENCES fuzz_steps(id) ON DELETE CASCADE,
		    token TEXT NOT NULL,
		    ordinal INT NOT NULL,
		    role TEXT,
		    resting_value TEXT NOT NULL DEFAULT '',
		    wordlist TEXT,
		    encoder TEXT,
		    created_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (step_id, token)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_positions_step ON fuzz_positions(step_id, ordinal);`,

		`CREATE TABLE IF NOT EXISTS fuzz_runs (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    flow_id UUID NOT NULL REFERENCES fuzz_flows(id) ON DELETE CASCADE,
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    tool VARCHAR(10),
		    status VARCHAR(20) NOT NULL DEFAULT 'pending',
		    steps_total INT DEFAULT 0,
		    steps_done INT DEFAULT 0,
		    findings_new INT DEFAULT 0,
		    error TEXT,
		    execution_time TEXT,
		    created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_runs_flow ON fuzz_runs(flow_id, created_at DESC);`,

		`CREATE TABLE IF NOT EXISTS fuzz_step_runs (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    run_id UUID NOT NULL REFERENCES fuzz_runs(id) ON DELETE CASCADE,
		    step_id UUID REFERENCES fuzz_steps(id) ON DELETE SET NULL,
		    ordinal INT,
		    status VARCHAR(30) NOT NULL DEFAULT 'pending',
		    command TEXT,
		    requests_estimated BIGINT,
		    findings_new INT DEFAULT 0,
		    detail TEXT,
		    stdout TEXT,
		    created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_step_runs_run ON fuzz_step_runs(run_id, ordinal);`,

		// Findings ACCUMULATE. finding_key is the stable identity, so re-running a flow updates
		// last_seen and leaves genuinely new hits as inserts, the same pattern
		// consolidated_url_endpoints uses on endpoint_key. first_seen_run_id is what makes
		// "what is new since last time" answerable at all.
		`CREATE TABLE IF NOT EXISTS fuzz_findings (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    flow_id UUID REFERENCES fuzz_flows(id) ON DELETE CASCADE,
		    step_id UUID REFERENCES fuzz_steps(id) ON DELETE SET NULL,
		    tool VARCHAR(10) NOT NULL,
		    finding_key TEXT NOT NULL,
		    url TEXT,
		    method VARCHAR(10),
		    position_token TEXT,
		    payload TEXT,
		    param_name TEXT,
		    http_status INT,
		    response_size BIGINT,
		    response_words INT,
		    response_lines INT,
		    content_type TEXT,
		    redirect_location TEXT,
		    reason TEXT,
		    triage VARCHAR(20) NOT NULL DEFAULT 'new',
		    notes TEXT,
		    first_seen_run_id UUID REFERENCES fuzz_runs(id) ON DELETE SET NULL,
		    last_seen_run_id UUID REFERENCES fuzz_runs(id) ON DELETE SET NULL,
		    first_seen TIMESTAMP DEFAULT NOW(),
		    last_seen TIMESTAMP DEFAULT NOW(),
		    times_seen INT NOT NULL DEFAULT 1,
		    UNIQUE (scope_target_id, tool, finding_key)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_findings_target ON fuzz_findings(scope_target_id, tool);`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_findings_run ON fuzz_findings(last_seen_run_id);`,

		// What a finding used to answer, so the transition its identity exists to capture survives.
		//
		// finding_key deliberately excludes status and size, because "a 403 that becomes a 200 is the
		// SAME finding changing" is the most valuable thing this can report. That was true and then
		// the change was thrown away: the upsert overwrote http_status in place and nothing recorded
		// the previous value, so times_seen going up was the only trace.
		`ALTER TABLE fuzz_findings ADD COLUMN IF NOT EXISTS previous_http_status INT;`,
		`ALTER TABLE fuzz_findings ADD COLUMN IF NOT EXISTS previous_response_size BIGINT;`,
		`ALTER TABLE fuzz_findings ADD COLUMN IF NOT EXISTS changed_at TIMESTAMP;`,
		// Which run the change happened in. changed_at alone is never cleared, so "changed" drifted
		// into meaning "moved at some point ever", which made the notable count climb forever and let
		// one long-ago flip hold the whole first page of the changed-first ordering.
		`ALTER TABLE fuzz_findings ADD COLUMN IF NOT EXISTS changed_in_run_id UUID;`,

		// The bytes ffuf actually sent and received for a finding.
		//
		// Separate from fuzz_findings because it is large and optional: a response can be megabytes,
		// findings accumulate forever, and most rows are never opened. Keyed one-to-one on the finding
		// so a re-run REPLACES the evidence with the latest, and cascaded so deleting a finding, a
		// flow or a target cannot leave orphaned bodies behind.
		`CREATE TABLE IF NOT EXISTS fuzz_finding_evidence (
		    finding_id UUID PRIMARY KEY REFERENCES fuzz_findings(id) ON DELETE CASCADE,
		    run_id UUID REFERENCES fuzz_runs(id) ON DELETE SET NULL,
		    request_bytes TEXT NOT NULL DEFAULT '',
		    response_bytes TEXT NOT NULL DEFAULT '',
		    response_total_bytes BIGINT DEFAULT 0,
		    truncated BOOLEAN NOT NULL DEFAULT FALSE,
		    captured_at TIMESTAMP DEFAULT NOW()
		);`,
		// One request carrying user-controlled input the application processes: a verb, a host, a path,
		// the parameter combination in play and the single place a payload goes.
		//
		// The confidence columns exist because three of the upstream sources cannot actually observe
		// what they report. Crawlers and archives have no verb at all and consolidation writes GET;
		// consolidated_url_parameters holds the UNION of every parameter ever seen on an endpoint
		// rather than a set observed together; and Arjun derives its insertion point from the verb
		// instead of measuring it. Recording that on the row is the difference between a list an
		// operator can plan from and one that quietly wastes their afternoon.
		`CREATE TABLE IF NOT EXISTS attack_vectors (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    vector_key TEXT NOT NULL,
		    method TEXT NOT NULL,
		    method_confidence TEXT NOT NULL DEFAULT 'observed',
		    scheme TEXT NOT NULL DEFAULT 'https',
		    domain TEXT NOT NULL,
		    port INT,
		    path TEXT NOT NULL DEFAULT '/',
		    insertion_point TEXT NOT NULL,
		    insertion_confidence TEXT NOT NULL DEFAULT 'observed',
		    parameters TEXT[] NOT NULL DEFAULT '{}',
		    parameters_origin TEXT NOT NULL DEFAULT 'observed',
		    sources TEXT[] NOT NULL DEFAULT '{}',
		    evidence_url TEXT,
		    raw_request TEXT,
		    notes TEXT,
		    manual_added BOOLEAN NOT NULL DEFAULT FALSE,
		    edited_at TIMESTAMP,
		    deleted_at TIMESTAMP,
		    first_seen TIMESTAMP DEFAULT NOW(),
		    last_seen TIMESTAMP DEFAULT NOW(),
		    times_seen INT NOT NULL DEFAULT 1,
		    UNIQUE (scope_target_id, vector_key)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_attack_vectors_target ON attack_vectors(scope_target_id)
		    WHERE deleted_at IS NULL;`,
		// The keys this row USED to have. Editing a vector changes its identity, which frees the old
		// key for consolidation to insert all over again: the operator corrects a row and the next run
		// quietly puts the uncorrected version back beside it. Remembering what was replaced is what
		// makes an edit stick, the same way deleted_at makes a deletion stick.
		`ALTER TABLE attack_vectors ADD COLUMN IF NOT EXISTS superseded_keys TEXT[] NOT NULL DEFAULT '{}';`,
		// Why a span is worth testing: jwt, uuid, high_entropy, numeric_id, custom_header. A row that
		// says "this header carries a JWT" is a different proposition from one that says "this header
		// exists", and the operator sorts by it.
		`ALTER TABLE attack_vectors ADD COLUMN IF NOT EXISTS signals TEXT[] NOT NULL DEFAULT '{}';`,

		// The vector-testing sections (XSS, SQL injection, and the ten planned after them) share these
		// four tables rather than owning four each. category is the discriminator.
		//
		// The xss_* tables these replace are dropped below: they existed for one session, carried no
		// findings worth keeping, and leaving them would leave two places for a scan to be recorded.
		`CREATE TABLE IF NOT EXISTS vector_tool_settings (
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    tool TEXT NOT NULL,
		    settings JSONB NOT NULL DEFAULT '{}',
		    updated_at TIMESTAMP DEFAULT NOW(),
		    PRIMARY KEY (scope_target_id, tool)
		);`,

		// One run of one tool over a target's attack vectors.
		//
		// eligible_vectors is stored beside total_vectors rather than derived, because eligibility
		// depends on the settings AT THE TIME, and a later settings change would otherwise silently
		// rewrite what a finished scan claims to have covered.
		`CREATE TABLE IF NOT EXISTS vector_scans (
		    id UUID PRIMARY KEY,
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    category TEXT NOT NULL DEFAULT '',
		    tool TEXT NOT NULL,
		    status TEXT NOT NULL DEFAULT 'running',
		    total_vectors INT NOT NULL DEFAULT 0,
		    eligible_vectors INT NOT NULL DEFAULT 0,
		    completed_vectors INT NOT NULL DEFAULT 0,
		    finding_count INT NOT NULL DEFAULT 0,
		    current_host TEXT NOT NULL DEFAULT '',
		    skipped_reasons JSONB NOT NULL DEFAULT '{}',
		    settings_snapshot JSONB NOT NULL DEFAULT '{}',
		    error TEXT,
		    created_at TIMESTAMP DEFAULT NOW(),
		    completed_at TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_vector_scans_target ON vector_scans(scope_target_id, tool, created_at DESC);`,

		// What happened to each vector in a scan, INCLUDING the ones that were never sent.
		//
		// The skipped rows are the reason this table exists. domdig handed a header vector scans its
		// query string, finds nothing and exits 0; SQLiDetector handed a body vector does the same.
		// Without a row saying "skipped, and here is the reason", the operator reads a clean result
		// for something that was never tested.
		`CREATE TABLE IF NOT EXISTS vector_scan_vectors (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scan_id UUID NOT NULL REFERENCES vector_scans(id) ON DELETE CASCADE,
		    vector_id UUID REFERENCES attack_vectors(id) ON DELETE CASCADE,
		    status TEXT NOT NULL,
		    reason TEXT NOT NULL DEFAULT '',
		    finding_count INT NOT NULL DEFAULT 0,
		    created_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (scan_id, vector_id)
		);`,

		// kind holds the tool's OWN class rather than a flattened "finding", because they mean
		// different things and collapsing them misleads. dalfox V is "the payload reached an
		// executable position in a parsed response", which v3 does NOT verify in a browser. sqlmap's
		// "stacked queries" and "time-based blind" are both injections and one of them is an
		// afternoon of work while the other is arbitrary statement execution.
		`CREATE TABLE IF NOT EXISTS vector_findings (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scan_id UUID NOT NULL REFERENCES vector_scans(id) ON DELETE CASCADE,
		    vector_id UUID REFERENCES attack_vectors(id) ON DELETE CASCADE,
		    tool TEXT NOT NULL,
		    kind TEXT NOT NULL DEFAULT '',
		    severity TEXT NOT NULL DEFAULT '',
		    confidence TEXT NOT NULL DEFAULT '',
		    insertion_point TEXT NOT NULL DEFAULT '',
		    param TEXT NOT NULL DEFAULT '',
		    payload TEXT NOT NULL DEFAULT '',
		    method TEXT NOT NULL DEFAULT '',
		    url TEXT NOT NULL DEFAULT '',
		    evidence TEXT NOT NULL DEFAULT '',
		    detection_method TEXT NOT NULL DEFAULT '',
		    inject_type TEXT NOT NULL DEFAULT '',
		    raw_request TEXT NOT NULL DEFAULT '',
		    raw_response TEXT NOT NULL DEFAULT '',
		    triage TEXT NOT NULL DEFAULT 'new',
		    created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_vector_findings_scan ON vector_findings(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_vector_findings_vector ON vector_findings(vector_id);`,

		// The access control bypass section does not scan attack vectors, so it needs its own targets.
		//
		// Every other section tests a parameter: a payload goes into a named input and something
		// happens. A 403 bypass has no parameter. What is being tested is whether an access control
		// decision can be avoided at all, and the interesting URLs are exactly the ones that already
		// answered 401 or 403 to something this framework sent earlier.
		//
		// Those live scattered across six tables that record an HTTP status: endpoint discovery,
		// endpoint validation, the manual crawl, the fuzzer, the consolidated attack surface and the
		// target URL list. Consolidating them here rather than querying the union at scan time gives
		// the operator a list to look at, prune and re-run against, which is how every other
		// consolidation step in this framework already works.
		//
		// They are NOT put into attack_vectors, which would be the lazy way. Every other section loads
		// that table wholesale, so a few hundred 403 URLs would silently become XSS, SQL injection and
		// file inclusion targets as well.
		`CREATE TABLE IF NOT EXISTS access_bypass_targets (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    url TEXT NOT NULL,
		    status_code INT NOT NULL,
		    sources TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
		    notes TEXT NOT NULL DEFAULT '',
		    deleted_at TIMESTAMP,
		    first_seen TIMESTAMP DEFAULT NOW(),
		    last_seen TIMESTAMP DEFAULT NOW(),
		    UNIQUE (scope_target_id, url)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_access_bypass_targets_target ON access_bypass_targets(scope_target_id) WHERE deleted_at IS NULL;`,
		// The operator's own judgement about scope, which beats any heuristic the framework can apply.
		//
		// Guessing from the hostname is not good enough and it was measured not being good enough: on a
		// real target the guess held back 27 of 29 URLs, including the company's own S3 bucket and its
		// own API on a second domain, while correctly holding back Vimeo and TransUnion. Only the
		// person who read the programme's scope knows which is which, so NULL means "use the guess"
		// and true/false is the operator overruling it.
		`ALTER TABLE access_bypass_targets ADD COLUMN IF NOT EXISTS in_scope_override BOOLEAN;`,

		// A scan row and a finding point at EITHER an attack vector or a bypass target, never both.
		// Added as columns rather than a parallel set of tables so the runner, the progress display
		// and the results modal stay one implementation.
		`ALTER TABLE vector_scan_vectors ADD COLUMN IF NOT EXISTS bypass_target_id UUID REFERENCES access_bypass_targets(id) ON DELETE CASCADE;`,
		`ALTER TABLE vector_findings ADD COLUMN IF NOT EXISTS bypass_target_id UUID REFERENCES access_bypass_targets(id) ON DELETE CASCADE;`,
		// Postgres treats NULLs as distinct in a UNIQUE constraint, so UNIQUE (scan_id, vector_id)
		// does not stop a bypass target being recorded twice: its vector_id is always NULL. This is
		// the equivalent guard for the other identity.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vector_scan_vectors_bypass ON vector_scan_vectors(scan_id, bypass_target_id) WHERE bypass_target_id IS NOT NULL;`,

		// A target that exists in NO table needs somewhere to be named.
		//
		// The GraphQL section is why. Its endpoints are not rows anywhere: the list IS the tool's
		// settings, because the operator marks endpoints by hand in each tool's own config. So neither
		// foreign key applies, and without this column the per-endpoint progress rows would all be
		// (NULL, NULL) and the screen could not say which endpoint it was on.
		`ALTER TABLE vector_scan_vectors ADD COLUMN IF NOT EXISTS target_url TEXT;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vector_scan_vectors_url ON vector_scan_vectors(scan_id, target_url) WHERE target_url IS NOT NULL;`,

		// The sensitive data leak section scans DIRECTORIES, not endpoints.
		//
		// An exposed .git, .env or backup sits wherever the application was deployed, which is usually
		// a subdirectory, so scanning only the site root misses most of them. Every URL the framework
		// knows contributes the directories that contain it: /app/admin/users.php contributes
		// /app/admin/, /app/ and /.
		//
		// A table rather than a query at scan time because the cost has to be visible first. Measured:
		// snallygaster sends 189 requests per directory, and one real scope target's 1232 known URLs
		// expand to 1378 directories. That is a quarter of a million requests, which is a decision
		// rather than a default.
		`CREATE TABLE IF NOT EXISTS leak_targets (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    url TEXT NOT NULL,
		    depth INT NOT NULL DEFAULT 0,
		    sources TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
		    notes TEXT NOT NULL DEFAULT '',
		    deleted_at TIMESTAMP,
		    first_seen TIMESTAMP DEFAULT NOW(),
		    last_seen TIMESTAMP DEFAULT NOW(),
		    UNIQUE (scope_target_id, url)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_leak_targets_target ON leak_targets(scope_target_id) WHERE deleted_at IS NULL;`,
		`ALTER TABLE vector_scan_vectors ADD COLUMN IF NOT EXISTS leak_target_id UUID REFERENCES leak_targets(id) ON DELETE CASCADE;`,
		`ALTER TABLE vector_findings ADD COLUMN IF NOT EXISTS leak_target_id UUID REFERENCES leak_targets(id) ON DELETE CASCADE;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vector_scan_vectors_leak ON vector_scan_vectors(scan_id, leak_target_id) WHERE leak_target_id IS NOT NULL;`,

		// Settings that belong to a SECTION rather than to one tool.
		//
		// The open redirect and SSRF section needs a webhook: one URL the payloads point at, and a
		// second the framework polls to find out whether anything actually arrived. Both tools in that
		// section use the same pair, so storing it per tool would mean configuring it twice and having
		// it disagree with itself.
		`CREATE TABLE IF NOT EXISTS vector_section_settings (
		    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
		    category TEXT NOT NULL,
		    settings JSONB NOT NULL DEFAULT '{}',
		    updated_at TIMESTAMP DEFAULT NOW(),
		    PRIMARY KEY (scope_target_id, category)
		);`,
		`DROP TABLE IF EXISTS xss_findings;`,
		`DROP TABLE IF EXISTS xss_scan_vectors;`,
		`DROP TABLE IF EXISTS xss_scans;`,
		`DROP TABLE IF EXISTS xss_tool_settings;`,

		// The same request with a value that cannot exist, so a finding can be read against a control
		// rather than on its own. A 403 for /admin means nothing until /rs0n is also a 403.
		//
		// Keyed by the rendered request rather than by the finding, because the canary collapses every
		// finding of a step onto ONE request: replace the payload with rs0n and /admin, /login and
		// /backup are all the same bytes. One baseline per step instead of one per finding is the
		// difference between five requests and five thousand.
		`CREATE TABLE IF NOT EXISTS fuzz_baselines (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    step_id UUID REFERENCES fuzz_steps(id) ON DELETE CASCADE,
		    run_id UUID REFERENCES fuzz_runs(id) ON DELETE SET NULL,
		    position_token TEXT NOT NULL DEFAULT '',
		    request_key TEXT NOT NULL,
		    http_status INT,
		    response_size BIGINT,
		    response_words INT,
		    response_lines INT,
		    content_type TEXT,
		    request_bytes TEXT NOT NULL DEFAULT '',
		    response_bytes TEXT NOT NULL DEFAULT '',
		    response_total_bytes BIGINT DEFAULT 0,
		    truncated BOOLEAN NOT NULL DEFAULT FALSE,
		    captured_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE (step_id, request_key)
		);`,
		`ALTER TABLE fuzz_findings ADD COLUMN IF NOT EXISTS baseline_id UUID
		    REFERENCES fuzz_baselines(id) ON DELETE SET NULL;`,

		// The request has its own caps and so needs its own truncation flag. Reporting only the
		// response's meant a request cut at 16KB was displayed as if it were the complete thing.
		`ALTER TABLE fuzz_finding_evidence ADD COLUMN IF NOT EXISTS request_total_bytes BIGINT DEFAULT 0;`,
		`ALTER TABLE fuzz_finding_evidence ADD COLUMN IF NOT EXISTS request_truncated BOOLEAN NOT NULL DEFAULT FALSE;`,

		// A run the operator asked to stop. Checked between steps and used to kill the ffuf process
		// currently executing, because the step timeout kills the docker client and not the tool.
		`ALTER TABLE fuzz_runs ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT FALSE;`,
		// Steps refused before the run started. They used to be returned once in the start response
		// and then forgotten, so a three-step flow that ran one step reported success.
		`ALTER TABLE fuzz_runs ADD COLUMN IF NOT EXISTS steps_blocked INT NOT NULL DEFAULT 0;`,
		`ALTER TABLE fuzz_runs ADD COLUMN IF NOT EXISTS blocked_detail TEXT;`,

		`CREATE TABLE IF NOT EXISTS auth_flows (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			category VARCHAR(50) NOT NULL CHECK (category IN ('register','login','mfa_otp','reset')),
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			auth_type VARCHAR(50) DEFAULT '',
			base_url TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS auth_flow_steps (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			auth_flow_id UUID NOT NULL REFERENCES auth_flows(id) ON DELETE CASCADE,
			step_order INTEGER NOT NULL,
			name TEXT DEFAULT '',
			raw_request TEXT NOT NULL,
			response_status INTEGER,
			response_headers JSONB,
			response_body TEXT,
			response_time_ms FLOAT,
			error TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		// What this step captures out of its own response for a later step to use.
		//
		// An auth flow could not log into anything with a per-request CSRF token without it, which is
		// most applications: the shared cookie jar carries the session, but the token lives in the
		// response body and a step is otherwise sent verbatim. A JSONB column rather than its own
		// table because the rules are only ever read, written and deleted with the step they belong
		// to, and a separate table would buy a foreign key nobody needs at the cost of a join on
		// every step read.
		`ALTER TABLE auth_flow_steps ADD COLUMN IF NOT EXISTS extractions JSONB NOT NULL DEFAULT '[]'::jsonb;`,
		`CREATE INDEX IF NOT EXISTS idx_auth_flows_scope_target ON auth_flows(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_flow_steps_flow ON auth_flow_steps(auth_flow_id);`,

		// Replay order has to be a fact, not a tie-break. Every read orders by step_order alone, so
		// two steps sharing a number made the order of those two whatever the planner returned, and
		// an auth flow whose steps can swap is an auth flow that fails intermittently.
		//
		// Built concurrently-safe: existing installs may already hold duplicates, so the index is
		// created only if it can be, and the append path claims its number atomically regardless.
		`DO $$
		 BEGIN
		   IF NOT EXISTS (
		     SELECT 1 FROM auth_flow_steps a
		     JOIN auth_flow_steps b ON a.auth_flow_id = b.auth_flow_id
		       AND a.step_order = b.step_order AND a.id <> b.id
		   ) THEN
		     CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_flow_steps_order
		       ON auth_flow_steps(auth_flow_id, step_order);
		   END IF;
		 END $$;`,

		// magic_link joins the category list. The extension records it, so the modal has to be able
		// to show it; a recorded flow with nowhere to appear is a flow the operator cannot use.
		// Rewritten rather than added to because a CHECK constraint cannot be extended in place.
		`ALTER TABLE auth_flows DROP CONSTRAINT IF EXISTS auth_flows_category_check;`,
		`ALTER TABLE auth_flows ADD CONSTRAINT auth_flows_category_check
		   CHECK (category IN ('register','login','mfa_otp','magic_link','reset'));`,
		// How the flow was produced. Recorded flows come from the browser extension and carry the
		// recording they came from; manual flows were typed in as raw requests or curl.
		`ALTER TABLE auth_flows
		   ADD COLUMN IF NOT EXISTS source VARCHAR(16) NOT NULL DEFAULT 'manual',
		   ADD COLUMN IF NOT EXISTS recording_id UUID;`,

		// ---------------------------------------------------------------- extension recording
		//
		// A recording is the raw, ordered truth of what the browser did during one authentication.
		// It is deliberately unfiltered by scope: an auth flow routinely crosses to an identity
		// provider on another domain, and a scope filter would cut the flow in half exactly where
		// the interesting part is.
		`CREATE TABLE IF NOT EXISTS auth_recordings (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			category VARCHAR(50) NOT NULL
			  CHECK (category IN ('register','login','mfa_otp','magic_link','reset')),
			status VARCHAR(24) NOT NULL DEFAULT 'recording',
			base_url TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			request_count INTEGER DEFAULT 0,
			auth_flow_id UUID,
			started_at TIMESTAMP DEFAULT NOW(),
			stopped_at TIMESTAMP,
			last_seen_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS auth_recorded_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			recording_id UUID NOT NULL REFERENCES auth_recordings(id) ON DELETE CASCADE,
			seq INTEGER NOT NULL,
			method VARCHAR(16) NOT NULL DEFAULT 'GET',
			url TEXT NOT NULL,
			host TEXT DEFAULT '',
			raw_request TEXT NOT NULL,
			request_headers JSONB DEFAULT '{}'::jsonb,
			request_body TEXT DEFAULT '',
			response_status INTEGER,
			response_headers JSONB DEFAULT '{}'::jsonb,
			response_body TEXT DEFAULT '',
			set_cookies JSONB DEFAULT '[]'::jsonb,
			resource_type VARCHAR(32) DEFAULT '',
			duration_ms INTEGER DEFAULT 0,
			-- Excluded requests stay in the recording and are skipped on import. Deleting them would
			-- destroy the sequence, and the sequence is what makes a replay reproduce the flow.
			included BOOLEAN DEFAULT TRUE,
			occurred_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_recorded_seq
		   ON auth_recorded_requests(recording_id, seq);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_recordings_target
		   ON auth_recordings(scope_target_id, created_at DESC);`,

		// ---------------------------------------------------------------- session tokens
		//
		// Every token is tied to the auth flow that can produce another one. Without that link a
		// token is a dead end: when it expires there is no way to get a new one, and the operator
		// discovers it only by watching a scan report a login wall on every endpoint.
		`CREATE TABLE IF NOT EXISTS session_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			auth_flow_id UUID REFERENCES auth_flows(id) ON DELETE SET NULL,
			name TEXT NOT NULL,
			token_type VARCHAR(24) NOT NULL DEFAULT 'header'
			  CHECK (token_type IN ('header','cookie','api_key','bearer','query')),
			-- Exactly how it goes on the wire. header_name for a header, cookie_name for a cookie,
			-- param_name for a query parameter, and value_prefix for the "Bearer " style prefix.
			header_name TEXT DEFAULT '',
			cookie_name TEXT DEFAULT '',
			param_name TEXT DEFAULT '',
			value_prefix TEXT DEFAULT '',
			token_value TEXT NOT NULL DEFAULT '',
			-- Host scoping. Empty means the scope target's own registrable domain.
			scope_domains TEXT[] DEFAULT '{}',
			cookie_path TEXT DEFAULT '/',
			cookie_domain TEXT DEFAULT '',
			cookie_secure BOOLEAN DEFAULT FALSE,
			cookie_httponly BOOLEAN DEFAULT FALSE,
			cookie_samesite VARCHAR(16) DEFAULT '',
			expires_at TIMESTAMP,
			is_active BOOLEAN DEFAULT FALSE,
			notes TEXT DEFAULT '',
			last_validated_at TIMESTAMP,
			last_validation_status VARCHAR(24) DEFAULT '',
			last_validation_detail TEXT DEFAULT '',
			last_refreshed_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		// What the value IS, as opposed to how it travels.
		//
		// credential: the thing that proves who you are. companion: a value that is not a credential
		// but without which the credential does not work, which in practice means a load balancer
		// affinity cookie. Measured on a real target: GET /my-account with a valid session cookie
		// returned 302 to the login page, and the identical request carrying the AWSALB cookie from
		// the same login response returned 200. The session store was per backend, so without the
		// routing cookie the request reached a backend that had never seen the login.
		//
		// The failure that makes this worth a column is silent and inverts a whole scan: every
		// authenticated endpoint answers as if anonymous and the scanner fingerprints the login wall
		// as the application. Registering the routing cookie as an ordinary token was the only way to
		// get it onto the wire, and it then reported not_honoured forever, because on its own it
		// changes nothing.
		`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS token_role VARCHAR(16)
		   NOT NULL DEFAULT 'credential';`,
		`DO $$
		 BEGIN
		   IF NOT EXISTS (
		     SELECT 1 FROM pg_constraint WHERE conname = 'session_tokens_token_role_check'
		   ) THEN
		     ALTER TABLE session_tokens ADD CONSTRAINT session_tokens_token_role_check
		       CHECK (token_role IN ('credential','companion'));
		   END IF;
		 END $$;`,
		`CREATE INDEX IF NOT EXISTS idx_session_tokens_target
		   ON session_tokens(scope_target_id, is_active);`,
		`CREATE TABLE IF NOT EXISTS session_token_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_token_id UUID NOT NULL REFERENCES session_tokens(id) ON DELETE CASCADE,
			kind VARCHAR(24) NOT NULL,
			status VARCHAR(24) NOT NULL DEFAULT '',
			detail TEXT DEFAULT '',
			evidence JSONB DEFAULT '{}'::jsonb,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_session_token_events
		   ON session_token_events(session_token_id, created_at DESC);`,

		`CREATE TABLE IF NOT EXISTS authz_client_identifiers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			endpoint_url TEXT NOT NULL,
			method VARCHAR(10) DEFAULT 'GET',
			value TEXT NOT NULL,
			source VARCHAR(20) DEFAULT 'request',
			label TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_client_identifiers_target ON authz_client_identifiers(scope_target_id);`,

		// Auto-detection re-runs over the same traffic, so the same identifier must not be inserted
		// twice. Duplicates from before this constraint existed are collapsed first, keeping the
		// earliest row of each group.
		`DELETE FROM authz_client_identifiers a
		 USING authz_client_identifiers b
		 WHERE a.ctid > b.ctid
		   AND a.scope_target_id = b.scope_target_id
		   AND a.endpoint_url = b.endpoint_url
		   AND a.method = b.method
		   AND a.value = b.value;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS authz_client_identifiers_unique
		 ON authz_client_identifiers (scope_target_id, endpoint_url, method, value);`,

		// ---------------------------------------------------------------- identity patterns
		//
		// How the server decides which client is asking, demonstrated by one real request and its
		// response. The category is the whole point of the record, because it ranks how much of the
		// identity the attacker actually controls:
		//
		//   parameter            the id is in a query, path or body parameter, so it is directly
		//                        controllable. This is the best case for IDOR testing.
		//   signed_token         the id lives inside a signed token, usually a JWT, so the signature
		//                        has to fail first before the id can be moved.
		//   user_context_object  the server validates the session and builds the identity itself,
		//                        passing it to downstream services. The attacker controls nothing,
		//                        which is the worst case for IDOR.
		`CREATE TABLE IF NOT EXISTS authz_identity_patterns (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			category VARCHAR(32) NOT NULL
			  CHECK (category IN ('user_context_object','signed_token','parameter')),
			description TEXT DEFAULT '',
			raw_request TEXT NOT NULL DEFAULT '',
			response_status INTEGER,
			response_headers JSONB DEFAULT '{}'::jsonb,
			response_body TEXT DEFAULT '',
			response_time_ms DOUBLE PRECISION,
			-- Where the identifier sits and what it is called, so a test can move it.
			identifier_location VARCHAR(24) DEFAULT ''
			  CHECK (identifier_location IN ('','query','path','body','header','cookie','token_claim','server_side')),
			identifier_name TEXT DEFAULT '',
			identifier_value TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_identity_patterns
		   ON authz_identity_patterns(scope_target_id, category);`,

		// ---------------------------------------------------------------- policy based
		//
		// An application that lets an administrator grant or withhold each action individually. The
		// operator models the entity, enumerates every permission it has, then records specific
		// instances with specific configurations. Testing later asks whether the application really
		// enforces the configuration it claims for that instance.
		`CREATE TABLE IF NOT EXISTS authz_policy_entities (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS authz_policy_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			entity_id UUID NOT NULL REFERENCES authz_policy_entities(id) ON DELETE CASCADE,
			key TEXT NOT NULL,
			name TEXT DEFAULT '',
			description TEXT DEFAULT '',
			sort_order INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_policy_permission
		   ON authz_policy_permissions(entity_id, key);`,
		`CREATE TABLE IF NOT EXISTS authz_policy_instances (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			entity_id UUID NOT NULL REFERENCES authz_policy_entities(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			subject TEXT DEFAULT '',
			description TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		// One row per permission per instance. 'unset' is kept distinct from 'deny' because an
		// application that never granted a permission and one that explicitly revoked it can behave
		// differently, and the difference is exactly what a test is looking for.
		`CREATE TABLE IF NOT EXISTS authz_policy_instance_settings (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			instance_id UUID NOT NULL REFERENCES authz_policy_instances(id) ON DELETE CASCADE,
			permission_id UUID NOT NULL REFERENCES authz_policy_permissions(id) ON DELETE CASCADE,
			value VARCHAR(16) NOT NULL DEFAULT 'unset'
			  CHECK (value IN ('allow','deny','unset')),
			notes TEXT DEFAULT '',
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_policy_setting
		   ON authz_policy_instance_settings(instance_id, permission_id);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_policy_entities
		   ON authz_policy_entities(scope_target_id);`,

		// ---------------------------------------------------------------- role based
		//
		// Roles down one axis, actions across the other, one verdict per cell.
		//
		// Three values, not two, and the third is the one that matters. 'cannot_do' is a role that
		// is simply not given the action; 'forbidden_to_do' is a role that must never be able to
		// perform it under any circumstances. Both look identical in a UI that greys the button out,
		// and only the second is a finding when it turns out to be reachable.
		`CREATE TABLE IF NOT EXISTS authz_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			sort_order INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS authz_actions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			sort_order INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS authz_role_action_matrix (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			role_id UUID NOT NULL REFERENCES authz_roles(id) ON DELETE CASCADE,
			action_id UUID NOT NULL REFERENCES authz_actions(id) ON DELETE CASCADE,
			value VARCHAR(20) NOT NULL DEFAULT 'cannot_do'
			  CHECK (value IN ('can_do','cannot_do','forbidden_to_do')),
			notes TEXT DEFAULT '',
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_role_action
		   ON authz_role_action_matrix(role_id, action_id);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_roles ON authz_roles(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_actions ON authz_actions(scope_target_id);`,

		// ---------------------------------------------------------------- discretionary
		//
		// Access a holder can pass on, up to their own level. A Figma board is the canonical shape:
		// the creator is an admin, an admin can invite someone as admin or as user, a user can only
		// invite other users.
		//
		// grant_ceiling_rank encodes that rule. A level may grant any level whose rank is at or below
		// its ceiling, so admin(rank 2, ceiling 2) can create admins, and user(rank 1, ceiling 1)
		// cannot. A user who succeeds in granting rank 2 is the privilege escalation this models.
		`CREATE TABLE IF NOT EXISTS authz_dac_objects (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS authz_dac_levels (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			object_id UUID NOT NULL REFERENCES authz_dac_objects(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			rank INTEGER NOT NULL DEFAULT 0,
			grant_ceiling_rank INTEGER,
			can_grant BOOLEAN DEFAULT TRUE,
			description TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_authz_dac_level
		   ON authz_dac_levels(object_id, name);`,
		`CREATE INDEX IF NOT EXISTS idx_authz_dac_objects
		   ON authz_dac_objects(scope_target_id);`,

		// Consolidated endpoints carry the recorded request body so the raw request rebuilt for
		// IDOR work and auth-flow import is the real one, not just a request line and headers.
		`ALTER TABLE consolidated_url_endpoints ADD COLUMN IF NOT EXISTS request_body TEXT DEFAULT '';`,
		`ALTER TABLE consolidated_url_endpoints ADD COLUMN IF NOT EXISTS content_type TEXT DEFAULT '';`,

		// ---------------------------------------------------------------------------------------
		// Endpoint workflow: Consolidate -> Validate -> Investigate -> Manage.
		//
		// endpoint_key is the single identity for a row and every downstream table joins on it.
		// It survives re-consolidation, which the row id does not, so a validation verdict or an
		// operator override is not lost the next time Consolidate runs.
		`ALTER TABLE consolidated_url_endpoints
		   ADD COLUMN IF NOT EXISTS endpoint_key TEXT,
		   ADD COLUMN IF NOT EXISTS scheme TEXT DEFAULT 'https',
		   ADD COLUMN IF NOT EXISTS schemes TEXT[] DEFAULT '{}',
		   ADD COLUMN IF NOT EXISTS port INTEGER,
		   ADD COLUMN IF NOT EXISTS canonical_path TEXT,
		   ADD COLUMN IF NOT EXISTS identity_query TEXT DEFAULT '',
		   ADD COLUMN IF NOT EXISTS client_route TEXT DEFAULT '',
		   ADD COLUMN IF NOT EXISTS templated_path TEXT,
		   ADD COLUMN IF NOT EXISTS template_key TEXT,
		   ADD COLUMN IF NOT EXISTS template_group_size INTEGER DEFAULT 1,
		   ADD COLUMN IF NOT EXISTS is_template_exemplar BOOLEAN DEFAULT TRUE,
		   ADD COLUMN IF NOT EXISTS case_group_key TEXT,
		   ADD COLUMN IF NOT EXISTS method_confidence TEXT DEFAULT 'implied',
		   ADD COLUMN IF NOT EXISTS observed_methods TEXT[] DEFAULT '{}',
		   ADD COLUMN IF NOT EXISTS graphql_operation TEXT DEFAULT '',
		   ADD COLUMN IF NOT EXISTS content_class TEXT DEFAULT 'unknown',
		   ADD COLUMN IF NOT EXISTS source_counts JSONB DEFAULT '{}'::jsonb,
		   ADD COLUMN IF NOT EXISTS capture_count INTEGER DEFAULT 0,
		   ADD COLUMN IF NOT EXISTS normalization_flags JSONB DEFAULT '{}'::jsonb,
		   ADD COLUMN IF NOT EXISTS dropped_params JSONB DEFAULT '{}'::jsonb,
		   ADD COLUMN IF NOT EXISTS manual_added BOOLEAN NOT NULL DEFAULT FALSE,
		   ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE,
		   ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '',
		   ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP,
		   ADD COLUMN IF NOT EXISTS deleted_reason TEXT,
		   ADD COLUMN IF NOT EXISTS last_run_id UUID,
		   ADD COLUMN IF NOT EXISTS last_consolidated_at TIMESTAMP,
		   ADD COLUMN IF NOT EXISTS unseen_since TIMESTAMP,
		   ADD COLUMN IF NOT EXISTS validation_status TEXT NOT NULL DEFAULT 'not_validated',
		   ADD COLUMN IF NOT EXISTS validation_reason_code TEXT,
		   ADD COLUMN IF NOT EXISTS validation_reason TEXT,
		   ADD COLUMN IF NOT EXISTS validation_confidence TEXT,
		   ADD COLUMN IF NOT EXISTS validation_testable BOOLEAN,
		   ADD COLUMN IF NOT EXISTS validation_scan_id UUID,
		   ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP,
		   ADD COLUMN IF NOT EXISTS override_status TEXT,
		   ADD COLUMN IF NOT EXISTS override_note TEXT,
		   ADD COLUMN IF NOT EXISTS investigated_at TIMESTAMP,
		   ADD COLUMN IF NOT EXISTS interest_score INTEGER DEFAULT 0;`,

		// endpoint_key replaces (scope_target_id, url, method) as the identity.
		//
		// The old constraint has to go, not just be superseded: an upgrading install has rows with
		// a NULL endpoint_key, and re-consolidating would hit the old (url, method) constraint,
		// which the new ON CONFLICT does not name, so the insert would fail rather than update.
		`ALTER TABLE consolidated_url_endpoints
		   DROP CONSTRAINT IF EXISTS consolidated_url_endpoints_scope_target_id_url_method_key;`,
		// Not partial. A partial unique index cannot be inferred by ON CONFLICT without repeating
		// its predicate at every call site, and it is unnecessary here because Postgres already
		// treats NULLs as distinct, so legacy rows with no endpoint_key coexist happily.
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_cue_endpoint_key
		   ON consolidated_url_endpoints(scope_target_id, endpoint_key);`,
		`CREATE INDEX IF NOT EXISTS idx_cue_template ON consolidated_url_endpoints(scope_target_id, template_key);`,
		`CREATE INDEX IF NOT EXISTS idx_cue_verdict ON consolidated_url_endpoints(scope_target_id, validation_status) WHERE deleted_at IS NULL;`,
		`CREATE INDEX IF NOT EXISTS idx_cue_deleted ON consolidated_url_endpoints(scope_target_id, deleted_at);`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_scope_scantype ON discovered_endpoints(scope_target_id, scan_type);`,

		`CREATE TABLE IF NOT EXISTS endpoint_consolidation_runs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			endpoint_count INTEGER DEFAULT 0,
			rows_read INTEGER DEFAULT 0,
			skipped JSONB DEFAULT '{}'::jsonb,
			result TEXT,
			error TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidation_runs_target
		   ON endpoint_consolidation_runs(scope_target_id, created_at DESC);`,

		// Validation verdicts are authoritative here and cached onto consolidated_url_endpoints
		// for the list query. endpoint_key is denormalised so a verdict outlives a re-consolidation.
		`CREATE TABLE IF NOT EXISTS endpoint_validation_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			total_endpoints INTEGER DEFAULT 0,
			processed_endpoints INTEGER DEFAULT 0,
			requests_sent INTEGER DEFAULT 0,
			calibration JSONB DEFAULT '{}'::jsonb,
			probe_inputs JSONB DEFAULT '{}'::jsonb,
			assumptions JSONB DEFAULT '[]'::jsonb,
			counts JSONB DEFAULT '{}'::jsonb,
			abort_reason TEXT,
			result TEXT,
			error TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_validation_scans_target
		   ON endpoint_validation_scans(scope_target_id, created_at DESC);`,

		`CREATE TABLE IF NOT EXISTS endpoint_validation_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			endpoint_id UUID,
			endpoint_key TEXT NOT NULL,
			url TEXT NOT NULL,
			method VARCHAR(16) NOT NULL DEFAULT 'GET',
			status TEXT NOT NULL,
			reason_code TEXT NOT NULL,
			reason TEXT,
			confidence TEXT NOT NULL DEFAULT 'measured',
			testable BOOLEAN,
			rule_fired TEXT,
			falsifier TEXT,
			http_status INTEGER,
			response_size INTEGER,
			response_ms INTEGER,
			content_type TEXT,
			location TEXT,
			title TEXT,
			structure_hash TEXT,
			simhash TEXT,
			control_url TEXT,
			flags TEXT[] DEFAULT '{}',
			evidence JSONB DEFAULT '{}'::jsonb,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_validation_result
		   ON endpoint_validation_results(scan_id, endpoint_key);`,
		`CREATE INDEX IF NOT EXISTS idx_validation_result_target
		   ON endpoint_validation_results(scope_target_id, scan_id);`,

		// The frozen work queue. Snapshotted at run start so a Consolidate midway through cannot
		// insert rows the cursor has already walked past, which would leave a silent gap.
		`CREATE TABLE IF NOT EXISTS endpoint_validation_queue (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			endpoint_id UUID NOT NULL,
			endpoint_key TEXT NOT NULL,
			ordinal INTEGER NOT NULL,
			group_key TEXT,
			state VARCHAR(24) NOT NULL DEFAULT 'queued',
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_validation_queue ON endpoint_validation_queue(scan_id, endpoint_key);`,
		`CREATE INDEX IF NOT EXISTS idx_validation_queue_state ON endpoint_validation_queue(scan_id, state, ordinal);`,

		// One row per combined Investigate run. It owns the ordering (validate, then investigate
		// what validation did not rule out) and the record of why a phase was skipped, which is the
		// part an operator most needs and the part two independent scan tables cannot express.
		`CREATE TABLE IF NOT EXISTS endpoint_scan_runs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			run_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(32) NOT NULL DEFAULT 'pending',
			phase VARCHAR(32) NOT NULL DEFAULT 'pending',
			total_endpoints INTEGER DEFAULT 0,
			eligible_endpoints INTEGER DEFAULT 0,
			eligible_breakdown JSONB DEFAULT '{}'::jsonb,
			validation_scan_id UUID,
			investigation_scan_id UUID,
			note TEXT,
			error TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE INDEX IF NOT EXISTS idx_endpoint_scan_runs_target
		 ON endpoint_scan_runs(scope_target_id, created_at DESC);`,
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query)
		if err != nil {
			log.Printf("[ERROR] Failed to execute query: %s, error: %v", query, err)
			if !strings.Contains(err.Error(), "already exists") {
				log.Fatalf("[ERROR] Failed to create database schema: %v", err)
			}
		}
	}

	deletePendingScansQuery := `
		DELETE FROM amass_scans WHERE status = 'pending';
		DELETE FROM amass_intel_scans WHERE status = 'pending';
		DELETE FROM httpx_scans WHERE status = 'pending';
		DELETE FROM gau_scans WHERE status = 'pending';
		DELETE FROM sublist3r_scans WHERE status = 'pending';
		DELETE FROM assetfinder_scans WHERE status = 'pending';
		DELETE FROM ctl_scans WHERE status = 'pending';
		DELETE FROM subfinder_scans WHERE status = 'pending';
		DELETE FROM shuffledns_scans WHERE status = 'pending';
		DELETE FROM cewl_scans WHERE status = 'pending';
		DELETE FROM shufflednscustom_scans WHERE status = 'pending';
		DELETE FROM gospider_scans WHERE status = 'pending';
		DELETE FROM subdomainizer_scans WHERE status = 'pending';
		DELETE FROM nuclei_screenshots WHERE status = 'pending';
		DELETE FROM metadata_scans WHERE status = 'pending';
		DELETE FROM ip_port_scans WHERE status = 'pending';
		DELETE FROM katana_company_scans WHERE status = 'pending' OR status = 'running';
		DELETE FROM amass_enum_company_scans WHERE status = 'pending' OR status = 'running';
		DELETE FROM nuclei_scans WHERE status = 'pending' OR status = 'running';`

	_, err := dbPool.Exec(context.Background(), deletePendingScansQuery)
	if err != nil {
		log.Printf("[WARN] Failed to delete pending scans: %v", err)
	} else {
		log.Println("[INFO] Deleted any scans with status 'pending'")
	}

	// Metadata scans are cancelled cooperatively: CancelMetaDataScan only sets cancel_requested=true
	// and the running goroutine flips the status to 'cancelled' at its next checkpoint. If the API
	// restarts mid-scan, that goroutine dies and the row is stranded in 'running' (rendered as a
	// permanent "Cancelling" in the UI). On startup there is no goroutine left to finish them, so
	// resolve any such orphaned scans to a terminal 'cancelled' state here.
	cancelStuckMetaDataScansQuery := `
		UPDATE metadata_scans
		SET status = 'cancelled',
			error = 'Scan was interrupted by a server restart and automatically cancelled on startup.'
		WHERE status = 'running';`
	if tag, err := dbPool.Exec(context.Background(), cancelStuckMetaDataScansQuery); err != nil {
		log.Printf("[WARN] Failed to cancel stuck metadata scans on startup: %v", err)
	} else if n := tag.RowsAffected(); n > 0 {
		log.Printf("[INFO] Cancelled %d stuck metadata scan(s) left in 'running' after a restart", n)
	}

	// FFUF URL and WAF Probe scans run via a detached `docker exec` goroutine with no persisted PID.
	// If the API restarts mid-scan, that goroutine dies and the row is stranded in 'pending' or
	// 'running', leaving the URL-workflow card spinning forever. Resolve any orphaned scans to a
	// terminal 'error' on startup so the card can recover.
	//
	// x8 and Arjun are in the same sweep for a second reason on top of the spinning card:
	// RequestIssuingScansRunning (paceBudget.go) treats a pending or running row in either table as
	// live traffic at the target and refuses to start Validate or the endpoint-key backfill while one
	// exists. A row stranded by a restart therefore blocks those two operations permanently, with no
	// way to clear it from the UI.
	resolveStuckURLScansQuery := `
		UPDATE ffuf_url_scans SET status = 'error',
			error = 'Scan was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE waf_probe_scans SET status = 'error',
			error = 'Probe was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE x8_scans SET status = 'error',
			error = 'Scan was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE arjun_scans SET status = 'error',
			error = 'Scan was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE fuzz_step_runs SET status = 'error',
			detail = 'Step was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE fuzz_runs SET status = 'error',
			error = 'Run was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');`
	if _, err := dbPool.Exec(context.Background(), resolveStuckURLScansQuery); err != nil {
		log.Printf("[WARN] Failed to resolve stuck FFUF/WAF-probe/x8/Arjun/fuzz scans on startup: %v", err)
	} else {
		log.Println("[INFO] Resolved any stuck FFUF/WAF-probe/x8/Arjun/fuzz scans left running after a restart")
	}

	log.Println("[INFO] Database schema created successfully")
}
