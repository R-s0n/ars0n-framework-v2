package utils

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// Repairing the rows that predate endpoint_key.
//
// The identity migration added endpoint_key, dropped the old (scope_target_id, url, method)
// constraint, and created a unique index on (scope_target_id, endpoint_key). The comment left in
// database.go said legacy rows with a NULL key "coexist happily". They do not.
//
// Postgres treats NULLs as distinct, so ON CONFLICT (scope_target_id, endpoint_key) can never match
// a row whose key is NULL. The first Consolidate after the upgrade therefore inserted a brand new
// row for every endpoint and orphaned the original. On a live install that produced 2282 rows for
// 1140 real endpoints: every scan validated the corpus twice, thirty URLs came back with two
// contradictory verdicts in the same run because the copies carried different content_class, and
// deleting or overriding one copy left the other untouched and still eligible for testing.
//
// The repair is not a DELETE. Each orphan is re-keyed; where a keyed row already holds that key the
// orphan is a duplicate, so anything the operator owns is merged onto the survivor first and the
// orphan is soft-deleted with a reason. Nothing an operator typed is lost, and a soft delete can be
// restored from Manage Endpoints if this gets something wrong.

// BackfillEndpointKeys repairs every scope target. Safe to run repeatedly, and genuinely converges:
// every row it looks at either gains a key or is retired, and retired rows are not looked at again.
//
// Endpoints whose scope target no longer exists are skipped. The live install carried rows for a
// target deleted days earlier and reprocessed them on every boot, which is work that can never
// finish and can never matter.
func BackfillEndpointKeys() {
	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT e.scope_target_id
		FROM consolidated_url_endpoints e
		JOIN scope_targets t ON t.id = e.scope_target_id
		WHERE e.endpoint_key IS NULL AND e.deleted_at IS NULL`)
	if err != nil {
		log.Printf("[KEY-BACKFILL] could not look for legacy rows: %v", err)
		return
	}
	var targets []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			targets = append(targets, id)
		}
	}
	rows.Close()

	if len(targets) == 0 {
		return
	}
	log.Printf("[KEY-BACKFILL] %d scope target(s) have endpoints from before endpoint_key existed", len(targets))
	for _, id := range targets {
		res := BackfillEndpointKeysFor(id)
		log.Printf("[KEY-BACKFILL] %s: %d keyed, %d duplicates retired, %d unusable, %d merged fields",
			id, res.Keyed, res.Retired, res.Unusable, res.Merged)
	}
}

type BackfillResult struct {
	Scanned  int `json:"scanned"`
	Keyed    int `json:"keyed"`
	Retired  int `json:"retired"`
	Unusable int `json:"unusable"`
	Merged   int `json:"merged"`
}

func BackfillEndpointKeysFor(scopeTargetID string) BackfillResult {
	var out BackfillResult

	defaultScheme := "https"
	if s, _, _ := ScopeTargetBase(scopeTargetID); s != "" {
		defaultScheme = s
	}

	// Rows already retired are excluded. The unique index on (scope_target_id, endpoint_key) is not
	// partial, so a retired duplicate cannot be given the survivor's key and therefore can never
	// leave a selection of "endpoint_key IS NULL". Without this the same rows were re-read, re-merged
	// and re-counted on every boot forever: the live install reported "1135 duplicates retired" at
	// each start having retired them once, days earlier, and doing nothing since. A repair that
	// cannot converge is worse than one that does nothing, because it reports success either way.
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, url, COALESCE(method,'GET'), manual_added, pinned, COALESCE(notes,''),
		       override_status, COALESCE(override_note,''), deleted_at IS NOT NULL
		FROM consolidated_url_endpoints
		WHERE scope_target_id = $1 AND endpoint_key IS NULL AND deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		log.Printf("[KEY-BACKFILL] read failed for %s: %v", scopeTargetID, err)
		return out
	}

	type legacy struct {
		id, rawURL, method, notes, overrideNote string
		overrideStatus                          *string
		manual, pinned, deleted                 bool
	}
	var legacyRows []legacy
	for rows.Next() {
		var l legacy
		if rows.Scan(&l.id, &l.rawURL, &l.method, &l.manual, &l.pinned, &l.notes,
			&l.overrideStatus, &l.overrideNote, &l.deleted) != nil {
			continue
		}
		legacyRows = append(legacyRows, l)
	}
	rows.Close()
	out.Scanned = len(legacyRows)

	for _, l := range legacyRows {
		id, ok := CanonicalizeEndpoint(l.rawURL, l.method, defaultScheme)
		if !ok || id.Key == "" {
			// A row whose URL cannot be canonicalised at all. It stays unkeyed and is marked so it
			// stops being silently re-validated on every run: the live corpus holds a handful,
			// including "https://wss://web.onepay.com/iojs/star", where a websocket URL had a
			// scheme prefixed onto it upstream.
			out.Unusable++
			_, _ = dbPool.Exec(context.Background(), `
				UPDATE consolidated_url_endpoints
				SET deleted_at = COALESCE(deleted_at, NOW()),
				    deleted_reason = COALESCE(NULLIF(deleted_reason,''),
				      'URL could not be parsed, so it has no identity and cannot be tested')
				WHERE id = $1`, l.id)
			continue
		}

		// Does a keyed row already own this identity?
		var survivorID string
		err := dbPool.QueryRow(context.Background(), `
			SELECT id FROM consolidated_url_endpoints
			WHERE scope_target_id = $1 AND endpoint_key = $2`, scopeTargetID, id.Key).Scan(&survivorID)

		if err != nil {
			// Nobody holds it. This row simply gains its key and carries on, verdicts and all.
			if _, uerr := dbPool.Exec(context.Background(), `
				UPDATE consolidated_url_endpoints SET endpoint_key = $1 WHERE id = $2`,
				id.Key, l.id); uerr != nil {
				log.Printf("[KEY-BACKFILL] could not key %s: %v", l.id, uerr)
				continue
			}
			out.Keyed++
			continue
		}
		if survivorID == l.id {
			continue
		}

		// A duplicate. Move anything the operator owns onto the survivor before retiring it, so a
		// pin, a note or an override typed against the old copy is not quietly discarded.
		merged := mergeOperatorState(survivorID, l.manual, l.pinned, l.notes,
			l.overrideStatus, l.overrideNote)
		out.Merged += merged

		// Counted from what the statement actually changed, not from having reached this line. The
		// COALESCE makes a re-run a no-op on an already-retired row, so incrementing unconditionally
		// reported the same retirements again on every pass.
		tag, derr := dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints
			SET deleted_at = COALESCE(deleted_at, NOW()),
			    deleted_reason = COALESCE(NULLIF(deleted_reason,''),
			      'duplicate of the same endpoint, left behind by the endpoint_key migration')
			WHERE id = $1 AND deleted_at IS NULL`, l.id)
		if derr != nil {
			log.Printf("[KEY-BACKFILL] could not retire duplicate %s: %v", l.id, derr)
			continue
		}
		out.Retired += int(tag.RowsAffected())
	}
	return out
}

// mergeOperatorState copies operator-owned state from a duplicate onto the survivor, and only ever
// adds. A pin is never removed, a note is appended rather than replaced, and an existing override
// on the survivor wins because it is the more recent decision.
func mergeOperatorState(survivorID string, manual, pinned bool, notes string,
	overrideStatus *string, overrideNote string) int {

	changed := 0
	if manual || pinned {
		if _, err := dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints
			SET manual_added = manual_added OR $2, pinned = pinned OR $3
			WHERE id = $1`, survivorID, manual, pinned); err == nil {
			changed++
		}
	}
	if strings.TrimSpace(notes) != "" {
		if _, err := dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints
			SET notes = CASE
			      WHEN COALESCE(notes,'') = '' THEN $2
			      WHEN position($2 in notes) > 0 THEN notes
			      ELSE notes || ' | ' || $2 END
			WHERE id = $1`, survivorID, notes); err == nil {
			changed++
		}
	}
	if overrideStatus != nil && *overrideStatus != "" {
		if _, err := dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints
			SET override_status = COALESCE(override_status, $2),
			    override_note = CASE WHEN COALESCE(override_note,'') = ''
			                         THEN $3 ELSE override_note END
			WHERE id = $1`, survivorID, *overrideStatus, overrideNote); err == nil {
			changed++
		}
	}
	return changed
}

// RepairEndpointKeys handles POST /consolidated-endpoints/{scope_target_id}/repair-keys, so the
// repair can be re-run from the UI or over MCP without restarting the API.
func RepairEndpointKeys(scopeTargetID string) (BackfillResult, error) {
	if running := RequestIssuingScansRunning(scopeTargetID); len(running) > 0 {
		return BackfillResult{}, fmt.Errorf(
			"cannot repair while these scans are running: %s. They hold a snapshot of the endpoint "+
				"list and retiring rows underneath them would make the results hard to read",
			strings.Join(running, ", "))
	}
	return BackfillEndpointKeysFor(scopeTargetID), nil
}
