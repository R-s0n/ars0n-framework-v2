package main

import (
	"context"
	"log"
	"strings"
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

		// Per-field apply journal. Makes apply reversible and, more importantly, answerable: an
		// operator who later finds threads=8 in the FFUF config can see that the probe set it, when,
		// from which scan, and with what confidence, instead of "fixing" it back to 40.
		`CREATE TABLE IF NOT EXISTS waf_probe_apply_journal (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			scan_id UUID NOT NULL,
			tool TEXT NOT NULL,
			field TEXT NOT NULL,
			-- Which store the value actually landed in. A tool's own config table and the shared
			-- probe_tool_tuning table both receive writes, and revert has to put the value back
			-- where it came from rather than guess from the tool name.
			store TEXT NOT NULL DEFAULT 'tool_config',
			before_value JSONB,
			after_value JSONB,
			finding_id TEXT,
			confidence TEXT,
			bundle TEXT,
			applied_at TIMESTAMP DEFAULT NOW(),
			reverted_at TIMESTAMP
		);`,
		`ALTER TABLE waf_probe_apply_journal
			ADD COLUMN IF NOT EXISTS store TEXT NOT NULL DEFAULT 'tool_config';`,
		`CREATE INDEX IF NOT EXISTS idx_waf_probe_apply_journal_target
			ON waf_probe_apply_journal(scope_target_id, tool, field);`,

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

		// Tuning for tools that have no config table of their own (katana_url, gospider_url,
		// endpoint replay, and the framework-wide shared token bucket).
		`CREATE TABLE IF NOT EXISTS probe_tool_tuning (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			tool TEXT NOT NULL,
			config JSONB NOT NULL,
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, tool)
		);`,

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

		`CREATE TABLE IF NOT EXISTS nuclei_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			targets TEXT[] NOT NULL DEFAULT '{}',
			templates TEXT[] NOT NULL DEFAULT '{cves,vulnerabilities,exposures,technologies,misconfiguration,takeovers,network,dns,headless}',
			severities TEXT[] DEFAULT '{critical,high,medium,low,info}',
			uploaded_templates JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,

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

		`CREATE TABLE IF NOT EXISTS parameth_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			config JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS parameth_scans (
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
		`CREATE INDEX IF NOT EXISTS idx_auth_flows_scope_target ON auth_flows(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_flow_steps_flow ON auth_flow_steps(auth_flow_id);`,

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

		// Consolidated endpoints carry the recorded request body so the raw request rebuilt for
		// IDOR work and auth-flow import is the real one, not just a request line and headers.
		`ALTER TABLE consolidated_url_endpoints ADD COLUMN IF NOT EXISTS request_body TEXT DEFAULT '';`,
		`ALTER TABLE consolidated_url_endpoints ADD COLUMN IF NOT EXISTS content_type TEXT DEFAULT '';`,
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
	resolveStuckURLScansQuery := `
		UPDATE ffuf_url_scans SET status = 'error',
			error = 'Scan was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');
		UPDATE waf_probe_scans SET status = 'error',
			error = 'Probe was interrupted by a server restart and automatically failed on startup.'
		WHERE status IN ('pending','running');`
	if _, err := dbPool.Exec(context.Background(), resolveStuckURLScansQuery); err != nil {
		log.Printf("[WARN] Failed to resolve stuck FFUF/WAF-probe scans on startup: %v", err)
	} else {
		log.Println("[INFO] Resolved any stuck FFUF/WAF-probe scans left running after a restart")
	}

	log.Println("[INFO] Database schema created successfully")
}
