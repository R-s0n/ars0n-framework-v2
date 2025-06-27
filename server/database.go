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
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`INSERT INTO user_settings (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM user_settings LIMIT 1);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tool_name VARCHAR(100) NOT NULL,
			api_key_name VARCHAR(200) NOT NULL,
			api_key_value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tool_name, api_key_name)
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
		`CREATE TABLE IF NOT EXISTS consolidated_subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, subdomain)
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS auto_scan_state (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			current_step TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id),
			is_paused BOOLEAN DEFAULT false,
			is_cancelled BOOLEAN DEFAULT false
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
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
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
			UNIQUE(url, scope_target_id)
		);`,
		`CREATE INDEX IF NOT EXISTS target_urls_url_idx ON target_urls (url);`,
		`CREATE INDEX IF NOT EXISTS target_urls_scope_target_id_idx ON target_urls (scope_target_id);`,

		// Add migration queries for new columns
		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS http_response TEXT;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column http_response already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS http_response_headers JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column http_response_headers already exists in target_urls.';
			END;
		END $$;`,

		// Add migration queries for new DNS columns
		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_a_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_aaaa_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_cname_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_mx_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_txt_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_ns_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_ptr_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_srv_records TEXT[];
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'DNS columns already exist in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS katana_results JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column katana_results already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS ffuf_results JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column ffuf_results already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS roi_score INTEGER DEFAULT 50;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column roi_score already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS custom_user_agent TEXT;
				ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS custom_header TEXT;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Custom HTTP columns already exist in user_settings.';
			END;
		END $$;`,

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
			max_consolidated_subdomains INTEGER DEFAULT 2500,
			max_live_web_servers INTEGER DEFAULT 500,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,
		`INSERT INTO auto_scan_config (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM auto_scan_config LIMIT 1);`,

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

		// Add auto_scan_session_id to all scan tables
		`DO $$ BEGIN BEGIN ALTER TABLE amass_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE httpx_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE gau_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE sublist3r_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE assetfinder_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE ctl_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE subfinder_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE shuffledns_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE cewl_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE shufflednscustom_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE gospider_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE subdomainizer_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE nuclei_screenshots ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,
		`DO $$ BEGIN BEGIN ALTER TABLE metadata_scans ADD COLUMN IF NOT EXISTS auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_column THEN RAISE NOTICE 'Column already exists.'; END; END $$;`,

		`CREATE TABLE IF NOT EXISTS amass_enum_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
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
			wildcard_targets JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		// IP/Port scan tables
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
			network_range TEXT NOT NULL,
			ping_time_ms FLOAT,
			discovered_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS live_web_servers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
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
			last_checked TIMESTAMP DEFAULT NOW(),
			UNIQUE(scan_id, ip_address, port, protocol)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_live_ips_scan_id ON discovered_live_ips(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_scan_id ON live_web_servers(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_ip_port ON live_web_servers(ip_address, port);`,
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query)
		if err != nil {
			log.Printf("[ERROR] Failed to execute query: %s, error: %v", query, err)
			// Don't fatally exit on migration errors
			if !strings.Contains(query, "ALTER TABLE") {
				log.Fatalf("[ERROR] Failed to execute query: %s, error: %v", query, err)
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
		DELETE FROM ip_port_scans WHERE status = 'pending';`
	_, err := dbPool.Exec(context.Background(), deletePendingScansQuery)
	if err != nil {
		log.Fatalf("[ERROR] Failed to delete pending scans: %v", err)
	}
	log.Println("[INFO] Deleted any scans with status 'pending'")

	_, err = dbPool.Exec(context.Background(), `
		-- Add new columns to auto_scan_state table
		ALTER TABLE auto_scan_state 
		ADD COLUMN IF NOT EXISTS is_paused BOOLEAN DEFAULT false,
		ADD COLUMN IF NOT EXISTS is_cancelled BOOLEAN DEFAULT false;
	`)
	if err != nil {
		log.Printf("Error adding columns to auto_scan_state: %v", err)
	}
}
