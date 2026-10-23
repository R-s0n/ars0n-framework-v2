module ars0n-framework-v2-server

go 1.26.0

// Keep the Go 1.21 runtime defaults this module was written against (TLS/x509/HTTP compatibility
// with the legacy hosts the scanners talk to), except for two Go security fixes that stay on: the
// per-request cookie and query-parameter limits (CVE-2025-58186, CVE-2025-61726).
godebug (
	default=go1.21
	httpcookiemaxnum=3000
	urlmaxqueryparams=10000
)

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
