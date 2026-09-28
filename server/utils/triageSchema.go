package utils

import "context"

// The triage layer's own tables. Five of them, and the reason there are five rather than one is
// the whole point of the feature.
//
// =================================================================================================
// WHY THE VECTOR TABLES COULD NOT BE REUSED
// =================================================================================================
//
// vector_scans / vector_scan_vectors / vector_findings model ONE TOOL RUN OVER ONE VECTOR. Their
// unit of work is the vector and their verdict vocabulary is the tool's ('completed', 'skipped',
// plus a findings count). Triage's unit of work is a (vector, slot, class) triple, and a single
// vector in the measured corpus carries up to hundreds of cookie slots. Putting 27 classes times
// 1860 slots into vector_scan_vectors would mean either one row per vector (which is the
// silent-clean bug: a vector with 19 slots of which 7 were never probed reads as one green row) or
// a UNIQUE (scan_id, vector_id) violation on the second slot.
//
// So these are new tables, and they sit BESIDE the vector tables rather than replacing them. A
// triage verdict labels a target for the expensive scanner; a vector_finding is what the expensive
// scanner then found. Two different claims, two different lifetimes.
//
// =================================================================================================
// THE FIVE TABLES AND WHY EACH IS SEPARATE
// =================================================================================================
//
//	triage_runs        one press of the button
//	triage_slots       THE ADDRESSING SCHEME. Every unit of work, named, including path segments
//	triage_coverage    THE DENOMINATOR. Every (unit, class) eligibility says applies here
//	triage_verdicts    THE RESULT. What each class concluded, where it concluded anything
//	triage_fidelity    WHAT WAS ASKED FOR VERSUS WHAT REACHED THE WIRE, one row per probe
//
// triage_coverage and triage_verdicts are the split the operator is paying for. A coverage row with
// no matching verdict is "this class did not run here". A verdict row with state 'clean' is "this
// class ran and found nothing". They are different rows in different tables and no query can
// accidentally read one as the other, which is not true of a single status column: every previous
// version of this idea in this codebase used one column, and every one of them shipped a path that
// rendered an unrun check as a clean one.
//
// =================================================================================================
// CLASS IS A COLUMN, NEVER A TABLE AND NEVER A COLUMN NAME
// =================================================================================================
//
// class_id is a SMALLINT holding utils.ClassID. Adding the 28th class (CSVI is already id 27, and
// CATALOGUE section 5.6 walks through adding it) needs no DDL at all: a new classifier registers
// itself in Go and its rows appear. The alternative, a column per class or a table per class, is
// how the xss_* tables came to exist for one session before being dropped.
//
// There is deliberately NO foreign key from class_id to a lookup table, and no CHECK constraining
// its range. The register lives in triage/types.go where a new class is added next to the
// explanation of what it tests; a database copy would be a second place to change and would add
// nothing to the safety, since nothing but this store writes the column. That is the same ruling
// the insertion_point column on attack_vectors is documented with.
//
// =================================================================================================
// THE VOCABULARY IS NOT COPIED INTO SQL, WITH ONE NAMED EXCEPTION
// =================================================================================================
//
// state, state_kind, reach, survived, provenance and unit_kind are all TEXT with no CHECK. Their
// definitions live in Go (triageStateRules, Reach.String, WireSurvival, TriageProvenance), read by
// the store, the API and the client, because a second copy in SQL is a place for the operator's
// filter and the operator's list to disagree about what a row is. That is the same ruling the
// reflection_status column carries.
//
// THE EXCEPTION IS 'clean', and it is written into a CHECK on purpose. CATALOGUE 4.3 invariant 1
// says a clean with zero probe ordinals is a hard error that fails the run, and notes that "a
// warning in a log is how this shipped the first time". Go's ClassVerdict.Validate enforces it and
// the store calls Validate, but Validate is a function a future caller can forget. The CHECK cannot
// be forgotten. 'clean' is the only value in the whole vocabulary that asserts anything about the
// application, so it is the only one worth a second enforcement point.
//
// =================================================================================================
// EVERY "UNKNOWN" SENTINEL IS DISTINGUISHABLE FROM A MEASUREMENT
// =================================================================================================
//
// segment_index defaults to -1, because 0 is the first path segment and is a real answer.
// decode_depth defaults to -1, because 0 means "measured, and this slot does not percent-decode".
// http_status defaults to -1, because there is no HTTP status 0 and a probe that never got a
// response must not be storable as though it got one. survived defaults to the empty string, which
// is WireSurvivalUnknown and for which WireSurvival.Proven() is false, so a mangled probe cannot
// read as a defended application.
//
// Idempotent, so it is safe to run on every boot. Applied from createTables in database.go beside
// the vector tables, which is where vector_scans and vector_findings are created.
var TriageSchema = []string{

	// ONE PRESS OF THE BUTTON.
	//
	// run_id is the FOUR-CHARACTER marker run id, not the UUID. Every marker this run mints embeds
	// it (triage.MarkerRunIDLen = 4), and CATALOGUE 4.2 caps a hit whose marker carries
	// another run's id at cannot_determine (stale_marker). Storing it here is what lets a stale
	// marker be attributed to the run that actually minted it, instead of being an unexplained
	// string in a response body.
	//
	// Progress is counted in (unit, class) PAIRS and not in vectors, for the same reason
	// vector_reflection_runs.total_probes counts inputs rather than vectors: the 218-vector corpus
	// carries 1860 parameter slots, so a vector-counted progress bar lies by an order of magnitude.
	//
	// cancel_requested is the cooperative shape vector_scans and vector_reflection_runs already
	// use. There was no way to stop a vector scan at all until that column existed, and killing the
	// api left rows on 'running' forever with nothing ever writing a terminal status.
	`CREATE TABLE IF NOT EXISTS triage_runs (
	    id UUID PRIMARY KEY,
	    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
	    run_id TEXT NOT NULL,
	    status TEXT NOT NULL DEFAULT 'running',
	    phase TEXT NOT NULL DEFAULT '',
	    tier TEXT NOT NULL DEFAULT '',
	    planned_pairs INT NOT NULL DEFAULT 0,
	    completed_pairs INT NOT NULL DEFAULT 0,
	    probes_sent INT NOT NULL DEFAULT 0,
	    oob_mode TEXT NOT NULL DEFAULT '',
	    oob_base TEXT NOT NULL DEFAULT '',
	    budget JSONB NOT NULL DEFAULT '{}',
	    settings_snapshot JSONB NOT NULL DEFAULT '{}',
	    cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
	    error TEXT,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    completed_at TIMESTAMPTZ,
	    UNIQUE (run_id)
	);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_runs_target
	    ON triage_runs(scope_target_id, created_at DESC);`,

	// THE ADDRESSING SCHEME. One row per unit of work, written BEFORE anything is probed.
	//
	// This table is why the feature can count. The named-parameter array on attack_vectors holds
	// 1860 entries across 218 vectors and ZERO of them belong to the 51 path vectors, so every loop
	// over that array probes nothing on 23.4% of the corpus and files those vectors as tested. That
	// bug has already shipped here once. SlotsFor derives path slots from the path SEGMENTS instead,
	// and they land here with segment_index set. It is the only function allowed to read that array,
	// which is why this comment does not name the column: triageTypes_test.go scans these files for
	// a second reader and a mention would read as one.
	//
	// segment_index DEFAULTS TO -1 AND NOT TO 0. Segment 0 is the first segment of the path and is
	// a real, common answer. A 0 default would make "this is not a path slot" indistinguishable
	// from "this is the first path segment", which is the counts-that-are-not-counts failure in
	// miniature.
	//
	// unit_kind exists because four classes do not work per slot. HOSTHDR is scoped per HOST,
	// CACHE per vector, PP-SERVER per CONTAINER and MASSASSIGN per body document (CATALOGUE 1.20,
	// 1.21, 1.22, 1.25). Their key goes in slot_key too, and unit_kind says what kind of key it is,
	// so a reader never parses a host name with the slot grammar.
	//
	// vector_id IS TEXT AND CARRIES NO FOREIGN KEY, exactly as vector_scan_traces.vector_id is, and
	// for the recorded reason: a synthetic unit (a GraphQL endpoint, a host key, a canary) fails an
	// attack_vectors foreign key, the error is only logged, and the row silently vanishes. A record
	// that disappears when the run is unusual is worthless, because unusual runs are the ones being
	// diagnosed. Cleanup comes from triage_runs ON DELETE CASCADE instead.
	//
	// observed_value CARRIES WHAT THE CAPTURE HELD, for every slot including the credential ones.
	// Measured: 1555 of the 1655 cookie slots in the corpus are credential or analytics cookies,
	// which is why the effective cookie surface is around 100 and not 1655. is_credential says a
	// class must not PROBE the slot, because injecting into a session cookie produces a 401 that is
	// a perfect differential and invalidates the session the rest of the run depends on. It says
	// nothing about recording: the session token this crawl was carrying is exactly the value an
	// operator needs in front of them.
	//
	// There used to be a value_redacted column here and a blanking rule in RecordTriageSlots. Both
	// are gone. An existing database keeps the column, defaulting FALSE and written by nobody; the
	// insert no longer names it, so nothing depends on it either way.
	`CREATE TABLE IF NOT EXISTS triage_slots (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    run_id UUID NOT NULL REFERENCES triage_runs(id) ON DELETE CASCADE,
	    vector_id TEXT NOT NULL DEFAULT '',
	    unit_kind TEXT NOT NULL DEFAULT 'slot',
	    slot_key TEXT NOT NULL,
	    kind TEXT NOT NULL DEFAULT '',
	    name TEXT NOT NULL DEFAULT '',
	    field_path TEXT NOT NULL DEFAULT '',
	    segment_index INT NOT NULL DEFAULT -1,
	    observed_value TEXT NOT NULL DEFAULT '',
	    value_origin TEXT NOT NULL DEFAULT '',
	    value_kind TEXT NOT NULL DEFAULT '',
	    wrapper TEXT NOT NULL DEFAULT '',
	    encoder TEXT NOT NULL DEFAULT '',
	    method TEXT NOT NULL DEFAULT '',
	    body_media TEXT NOT NULL DEFAULT '',
	    origin TEXT NOT NULL DEFAULT '',
	    server_reachable BOOLEAN NOT NULL DEFAULT TRUE,
	    impossible_bytes BYTEA NOT NULL DEFAULT ''::BYTEA,
	    decode_depth INT NOT NULL DEFAULT -1,
	    pct_rejected BOOLEAN NOT NULL DEFAULT FALSE,
	    field_limit INT NOT NULL DEFAULT 0,
	    is_credential BOOLEAN NOT NULL DEFAULT FALSE,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    UNIQUE (run_id, vector_id, slot_key)
	);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_slots_run ON triage_slots(run_id, kind);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_slots_vector ON triage_slots(vector_id);`,

	// THE DENOMINATOR. One row per (unit, class) the eligibility matrix says applies here.
	//
	// Written when the plan is made, before a single request goes out, and that ordering is the
	// whole value. A run that is cancelled, crashes, or exhausts its budget after 40 pairs still
	// leaves 1800 coverage rows with ran = FALSE, and the report can then say "1840 pairs eligible,
	// 40 measured" rather than showing 40 green ticks and nothing else.
	//
	// ran IS NOT DERIVABLE FROM sent_probes ALONE and is stored separately on purpose. A class can
	// plan probes, send some, and still have measured nothing: the prelude failed, the marker came
	// back corrupted, the detector fired on its own negative control. The CHECK below only stops
	// the one direction that is always a lie (ran with nothing sent). The other direction, probes
	// sent with ran FALSE, is a legitimate and important state.
	//
	// reach_reason is required for reach = 'never'. ValidateClassifier already rejects a never with
	// no reason at registration; this is the same rule at rest, because "the operator sees a class
	// absent from a slot and cannot tell whether it was ruled out or forgotten" is the failure it
	// exists to prevent.
	`CREATE TABLE IF NOT EXISTS triage_coverage (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    run_id UUID NOT NULL REFERENCES triage_runs(id) ON DELETE CASCADE,
	    vector_id TEXT NOT NULL DEFAULT '',
	    slot_key TEXT NOT NULL,
	    class_id SMALLINT NOT NULL,
	    class_name TEXT NOT NULL DEFAULT '',
	    reach TEXT NOT NULL DEFAULT '',
	    reach_reason TEXT NOT NULL DEFAULT '',
	    planned_probes INT NOT NULL DEFAULT 0,
	    sent_probes INT NOT NULL DEFAULT 0,
	    skipped_probes JSONB NOT NULL DEFAULT '[]',
	    ran BOOLEAN NOT NULL DEFAULT FALSE,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    UNIQUE (run_id, vector_id, slot_key, class_id),
	    CONSTRAINT triage_coverage_ran_needs_a_probe
	        CHECK (ran = FALSE OR sent_probes > 0),
	    CONSTRAINT triage_coverage_never_needs_a_reason
	        CHECK (reach <> 'never' OR btrim(reach_reason) <> '')
	);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_coverage_run ON triage_coverage(run_id, ran, class_id);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_coverage_unit ON triage_coverage(run_id, vector_id, slot_key);`,

	// THE RESULT. One row per (unit, class, arm).
	//
	// ARM IS PART OF THE KEY because a class whose arms disagree emits a vector of verdicts rather
	// than a scalar: CATALOGUE 4.3 records that NOSQL emits six. Keying on (unit, class) alone
	// would silently keep whichever arm was written last, which is the worst possible loss, because
	// the arms that disagree are the interesting ones. An empty arm is the ordinary single-verdict case.
	//
	// is_unknown AND state_kind ARE WRITTEN FROM THE GO RULE TABLE, never by the caller, and
	// RecordTriageVerdicts is the only writer. They are stored rather than derived in SQL so the
	// vocabulary stays defined in exactly one place, and the CHECK below ties them to each other so
	// a writer cannot claim a structural state is not unknown. CATALOGUE 4.1 is explicit that
	// not_applicable is "UNKNOWN in effect" and is treated as unknown by every aggregate, which is
	// why state_kind 'structural' sets is_unknown.
	//
	// EVERY FILTER, SORT AND EXPORT USES is_unknown. That column is what makes rule 1 of CATALOGUE
	// 4.5 enforceable at the query layer: there is no path from any unknown to clean, at the slot
	// level, the vector level, the host level or the report level.
	//
	// PROVENANCE IS ON THE VERDICT, not inferred from which table the row is in, because the same
	// class emits verdicts from different sources. A signature match in a body the passive corpus
	// already held and a delta-checked native probe hit are both "SQL says suspicious", and the
	// second must outrank the first. provenance says which it was, provenance_detail names the tool
	// or the prior scan, and delta_checked is the single fact that separates a measured difference
	// from a string that was in the baseline all along. THE RANKING LIVES IN GO
	// (TriageProvenance.Rank), not in an ORDER BY here, for the reason
	// MostInterestingReflectionStatus is documented with.
	//
	// ordinals is BIGINT[] rather than a join table. It is read whole, always, and the CHECK that a
	// clean carries at least one of them is the single most important constraint in this schema.
	`CREATE TABLE IF NOT EXISTS triage_verdicts (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    run_id UUID NOT NULL REFERENCES triage_runs(id) ON DELETE CASCADE,
	    vector_id TEXT NOT NULL DEFAULT '',
	    slot_key TEXT NOT NULL,
	    class_id SMALLINT NOT NULL,
	    class_name TEXT NOT NULL DEFAULT '',
	    arm TEXT NOT NULL DEFAULT '',
	    state TEXT NOT NULL,
	    state_kind TEXT NOT NULL,
	    is_unknown BOOLEAN NOT NULL,
	    reason TEXT NOT NULL DEFAULT '',
	    grade TEXT NOT NULL DEFAULT '',
	    oracle TEXT NOT NULL DEFAULT '',
	    ordinals BIGINT[] NOT NULL DEFAULT '{}',
	    untested JSONB NOT NULL DEFAULT '[]',
	    annotations JSONB NOT NULL DEFAULT '{}',
	    label JSONB NOT NULL DEFAULT '{}',
	    provenance TEXT NOT NULL DEFAULT '',
	    provenance_detail TEXT NOT NULL DEFAULT '',
	    delta_checked BOOLEAN NOT NULL DEFAULT FALSE,
	    evidence_ordinal BIGINT NOT NULL DEFAULT 0,
	    evidence_obs_id TEXT NOT NULL DEFAULT '',
	    evidence_matched BYTEA NOT NULL DEFAULT ''::BYTEA,
	    evidence_offset INT NOT NULL DEFAULT -1,
	    evidence_length INT NOT NULL DEFAULT 0,
	    evidence_phrase TEXT NOT NULL DEFAULT '',
	    evidence_marker_form TEXT NOT NULL DEFAULT '',
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    UNIQUE (run_id, vector_id, slot_key, class_id, arm),
	    CONSTRAINT triage_verdicts_clean_needs_a_probe_record
	        CHECK (state <> 'clean' OR COALESCE(array_length(ordinals, 1), 0) > 0),
	    CONSTRAINT triage_verdicts_unknown_needs_a_reason
	        CHECK (is_unknown = FALSE OR btrim(reason) <> ''),
	    CONSTRAINT triage_verdicts_unknown_carries_no_grade
	        CHECK (is_unknown = FALSE OR grade = ''),
	    CONSTRAINT triage_verdicts_unknown_matches_its_kind
	        CHECK (is_unknown = (state_kind IN ('unknown', 'structural'))),
	    CONSTRAINT triage_verdicts_positive_names_its_source
	        CHECK (state_kind <> 'positive' OR btrim(provenance) <> '')
	);`,
	// The two questions the report asks, in the order it asks them: what is not known on this run,
	// and what did each class conclude.
	`CREATE INDEX IF NOT EXISTS idx_triage_verdicts_run ON triage_verdicts(run_id, is_unknown, state);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_verdicts_class ON triage_verdicts(run_id, class_id, state);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_verdicts_vector ON triage_verdicts(vector_id, class_id);`,

	// WHAT WAS ASKED FOR VERSUS WHAT REACHED THE WIRE. One row per probe attempt.
	//
	// THIS TABLE EXISTS BECAUSE OF A MEASUREMENT ON THIS MACHINE. With s the cookie name:
	//
	//	http.Cookie{Value: 1' OR 1=1; DROP}  serializes to  s="1' OR 1=1 DROP"
	//	http.Cookie{Value: a"b\c}            serializes to  s=abc
	//
	// Go's cookie serializer DROPS the semicolon, the double quote and the backslash, with nothing
	// but a line on the stdlib logger. Those are exactly the SQL injection probe characters, and 75
	// of the 218 vectors in the measured corpus are cookie vectors. A probe built with http.Cookie
	// therefore tests something other than what was asked for, gets a normal 200 back, and records
	// clean. Without a stored comparison of logical against container bytes there is no way,
	// afterwards, to tell that run from one that genuinely found nothing.
	//
	// THREE BYTE COLUMNS, NOT ONE, AND THE THIRD IS THE ONE THAT CATCHES THE BUG. logical is what
	// the class asked for. wire is what the encoder believes it produced. container is the whole
	// serialized container (the Cookie header line, the query string, the JSON body) as it was
	// handed to the transport, and a DROPPED byte is visible ONLY there, because wire is the
	// encoder's own account of itself.
	//
	// survived DEFAULTS TO THE EMPTY STRING, WHICH IS UNKNOWN AND NOT INTACT. WireSurvival.Proven()
	// is false for it, and a classifier is not allowed to say clean from an unproven probe.
	//
	// http_status DEFAULTS TO -1. There is no HTTP status 0, and a probe that never got a response
	// must not be storable as though it got one. transport_err is typed for the same reason: a NUL
	// byte in a header value produces "net/http: invalid header field value" at send time, which is
	// a loud could-not-send and must never read as a silent clean.
	//
	// APPEND-ONLY, keyed by (run, ordinal, attempt), with no upsert. The vector_scan_traces comment
	// records why: a verdict table's ON CONFLICT DO NOTHING silently discarded second writes, which
	// drops the retry attempts of a flaky detector precisely when the retries are the interesting
	// part.
	//
	// THE STRIPE CHECK IS RULING R12 AS A CONSTRAINT. Marker ordinals are striped per class at
	// modulus 64 (ClassStripeModulus), so Marker.ClassID() is ordinal % 64 and a marker from another
	// stripe is a hit for nobody. A fidelity row whose ordinal is outside its own class's stripe
	// means the minter and the recorder disagree about who owns the probe, and every attribution
	// downstream of it is wrong. class_id 0 with ordinal 0 is the unowned control row; NewReplay
	// already refuses a control that carries a class or an ordinal, and this is the same rule at
	// rest.
	`CREATE TABLE IF NOT EXISTS triage_fidelity (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    run_id UUID NOT NULL REFERENCES triage_runs(id) ON DELETE CASCADE,
	    ordinal BIGINT NOT NULL,
	    attempt INT NOT NULL DEFAULT 1,
	    class_id SMALLINT NOT NULL,
	    class_name TEXT NOT NULL DEFAULT '',
	    probe_id TEXT NOT NULL DEFAULT '',
	    vector_id TEXT NOT NULL DEFAULT '',
	    slot_key TEXT NOT NULL DEFAULT '',
	    obs_id TEXT NOT NULL DEFAULT '',
	    obs_kind TEXT NOT NULL DEFAULT '',
	    marker TEXT NOT NULL DEFAULT '',
	    marker_integrity TEXT NOT NULL DEFAULT '',
	    container_name TEXT NOT NULL DEFAULT '',
	    encoder_chain TEXT[] NOT NULL DEFAULT '{}',
	    encoder_version TEXT NOT NULL DEFAULT '',
	    logical BYTEA NOT NULL DEFAULT ''::BYTEA,
	    wire BYTEA NOT NULL DEFAULT ''::BYTEA,
	    container BYTEA NOT NULL DEFAULT ''::BYTEA,
	    logical_len INT NOT NULL DEFAULT 0,
	    wire_len INT NOT NULL DEFAULT 0,
	    container_len INT NOT NULL DEFAULT 0,
	    survived TEXT NOT NULL DEFAULT '',
	    altered_by TEXT NOT NULL DEFAULT '',
	    transport_err TEXT NOT NULL DEFAULT '',
	    transport_msg TEXT NOT NULL DEFAULT '',
	    http_status INT NOT NULL DEFAULT -1,
	    delivered BOOLEAN NOT NULL DEFAULT FALSE,
	    sent_at TIMESTAMPTZ,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    UNIQUE (run_id, ordinal, attempt),
	    CONSTRAINT triage_fidelity_ordinal_is_in_its_own_stripe
	        CHECK ((class_id = 0 AND ordinal = 0) OR (ordinal % 64) = class_id),
	    CONSTRAINT triage_fidelity_delivered_has_no_transport_error
	        CHECK (delivered = FALSE OR transport_err = '')
	);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_fidelity_run ON triage_fidelity(run_id, ordinal);`,
	`CREATE INDEX IF NOT EXISTS idx_triage_fidelity_unit ON triage_fidelity(run_id, vector_id, slot_key);`,
	// "Which probes did not reach the wire as asked" is the question this table was built to answer,
	// and it is asked over the small minority of rows, so it gets a partial index rather than a scan
	// of every probe the run sent.
	//
	// THE INDEX PREDICATE IS DELIBERATELY BROADER THAN THE QUERY PREDICATE. triageUnprovenFidelity in
	// triageStore.go adds "AND (logical_len > 0 OR survived <> '')" so that the unperturbed control,
	// which asks for no payload bytes and therefore has nothing that could have survived, does not
	// mark every run ever recorded as impure. That query predicate implies this index predicate, so
	// the index still serves it, and this expression is NOT narrowed to match: CREATE INDEX IF NOT
	// EXISTS is a no-op on a database that already has the index, so a changed expression here would
	// apply on new installs and silently not on existing ones, which is two different indexes wearing
	// one name.
	//
	// The column this index is on is read by LoadTriageRunCoverage. It was not, for a while: the
	// table recorded in full detail that a payload had been dropped and the roll-up, which touched
	// only triage_coverage and triage_verdicts, reported the vector clean.
	`CREATE INDEX IF NOT EXISTS idx_triage_fidelity_not_proven
	    ON triage_fidelity(run_id, class_id)
	    WHERE survived NOT IN ('intact', 'encoded');`,

	// THE RESPONSES THEMSELVES, ONE COPY PER DISTINCT BODY.
	//
	// =================================================================================================
	// WHY THIS TABLE EXISTS
	// =================================================================================================
	//
	// triage_verdicts records evidence_offset, evidence_length and evidence_matched. Until this
	// table existed those were a span into a body that had been garbage collected before the run
	// finished, so a verdict could say "arithmetic evaluated, 5 bytes at offset 412" and the
	// operator had no way to see the response it appeared in. An offset cannot be pasted into a bug
	// report. The whole layer exists to decide whether a target is worth twenty-eight minutes of
	// sqlmap, and that judgement is made by a human READING the response.
	//
	// =================================================================================================
	// CONTENT ADDRESSED, WHICH IS THE ONLY REASON THIS IS AFFORDABLE
	// =================================================================================================
	//
	// A run sends thousands of probes: run 2n6f sent 5312. Measured on the operator's own corpus,
	// the responses those probes were sent against average 12.7 KiB, so storing every response
	// whole would have cost 64 MB for that one run. Measured on the same corpus, the responses a
	// repeated request to one endpoint gets back are mostly the same bytes: over the 8411 manual
	// crawl captures there are 1420 distinct bodies, and on the endpoints this run actually probed
	// the repeat ratio runs from 12x to 109x. One paper-account positions endpoint was captured 218
	// times and holds TWO distinct bodies.
	//
	// So the key is the body's own SHA-256 and the row is the body. N identical responses cost one
	// copy. The hash is not a new measurement: it is sha256 of exactly the bytes in the body column,
	// computed by the writer over what it is about to store, so the key can never address bytes
	// other than the ones present.
	//
	// KEYED PER RUN AND NOT PER TARGET, deliberately. A global store would dedupe across runs and
	// would then need a reference count to know when a body may be deleted, which is a second
	// counter over the same population maintained by hand, which is the bug family this schema's
	// other comments keep recording. Per run, ON DELETE CASCADE is the whole lifetime rule: delete
	// the run, the bodies go with it, and no count has to be right for that to work.
	//
	// THE LENGTH IS CHECKED AGAINST THE BYTES rather than trusted, because body_len is exactly the
	// shape of a count that is not a count: it would be read as "how big the response was" and a
	// writer that set it from the uncapped response while storing the capped bytes would make every
	// offset arithmetic downstream wrong by an unknown amount. truncated is the field that says the
	// response was larger than triageMaxBodyBytes, and it is separate for that reason.
	`CREATE TABLE IF NOT EXISTS triage_bodies (
	    run_id UUID NOT NULL REFERENCES triage_runs(id) ON DELETE CASCADE,
	    body_sha256 BYTEA NOT NULL,
	    body BYTEA NOT NULL,
	    body_len INT NOT NULL,
	    truncated BOOLEAN NOT NULL DEFAULT FALSE,
	    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	    PRIMARY KEY (run_id, body_sha256),
	    CONSTRAINT triage_bodies_len_is_the_stored_length
	        CHECK (body_len = octet_length(body)),
	    CONSTRAINT triage_bodies_key_is_a_sha256
	        CHECK (octet_length(body_sha256) = 32)
	);`,

	// THE LINK FROM A PROBE TO ITS RESPONSE, ADDED TO triage_fidelity RATHER THAN TO A NEW TABLE.
	//
	// ADD COLUMN IF NOT EXISTS, never a rewrite: the operator has a live database with real
	// engagement data in it and nothing here may drop or rewrite a column that holds captured
	// bytes. Every existing row keeps everything it had and gains body_state = the empty string,
	// which is the UNRECORDED sentinel and is distinguishable from every measured answer, so a run
	// that predates this feature reads as "nobody recorded a body here" and never as "the response
	// was empty".
	//
	// body_state IS THE FIELD THAT STOPS AN ABSENCE READING AS A MEASUREMENT, and it is the reason
	// there is a text column here at all rather than just a hash. Its values, defined in Go beside
	// the writer (TriageBodyStored and the rest), are:
	//
	//	(empty)                nobody recorded anything. A pre-feature row.
	//	stored                 the bytes are in triage_bodies under body_sha256.
	//	no_response            the probe got no response at all, so there was no body to keep.
	//	not_attached           a response arrived and the runner did not hand its body over. A
	//	                       runner defect, named rather than rendered as an empty response.
	//	dropped:<reason>       a response arrived, its body was NOT kept, and the reason says why.
	//	unstorable:<reason>    the database refused the body.
	//
	// A reader that wants the response asks for stored and gets the bytes; anything else is a
	// sentence explaining what is missing. There is no value that means empty: an empty response
	// body is stored with body_len 0, because zero bytes IS a measurement.
	//
	// body_len DEFAULTS TO -1, for the reason http_status does. Zero is a real body length and the
	// commonest one on a 204, so a 0 default would make "nobody measured this" indistinguishable
	// from "the target sent nothing". It is the length of the bytes that were OFFERED for storage,
	// so it still says how big the response was on a row whose body was dropped.
	//
	// resp_headers IS STORED PER ROW AND NOT CONTENT ADDRESSED. Two responses with identical bodies
	// almost never have identical headers, because Date changes every second, so hashing them would
	// dedupe nothing and cost a second key. Measured on the operator's corpus they are 489 bytes
	// each on average, which is 2.6 MB for a 5312 probe run. They are kept because several classes
	// put their evidence in a header and not in the body at all (the SSTI hit record carries a
	// Where field that is either the body or a response header name), and because a reflection with
	// no Content-Type is not a finding anybody can write up.
	`ALTER TABLE triage_fidelity ADD COLUMN IF NOT EXISTS body_sha256 BYTEA NOT NULL DEFAULT ''::BYTEA;`,
	`ALTER TABLE triage_fidelity ADD COLUMN IF NOT EXISTS body_state TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE triage_fidelity ADD COLUMN IF NOT EXISTS body_len INT NOT NULL DEFAULT -1;`,
	`ALTER TABLE triage_fidelity ADD COLUMN IF NOT EXISTS resp_content_type TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE triage_fidelity ADD COLUMN IF NOT EXISTS resp_headers JSONB NOT NULL DEFAULT '[]';`,

	// A ROW THAT CLAIMS THE BYTES ARE THERE HAS TO SAY WHERE.
	//
	// This is the second CHECK in this schema and it earns its place on the same ground the clean
	// one does: stored is the only body_state that asserts an operator can go and read something,
	// and a row asserting it with no key is a row that sends a reader to an empty result and lets
	// them read the emptiness as the response. Every other value is a sentence about what is
	// missing and needs no enforcement.
	//
	// Added through a guarded DO block rather than a bare ADD CONSTRAINT because ADD CONSTRAINT has
	// no IF NOT EXISTS and this DDL runs on every boot. It is satisfied by every pre-existing row
	// by construction: they all carry the unrecorded body_state.
	`DO $$
	BEGIN
	    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'triage_fidelity_stored_body_names_its_key') THEN
	        ALTER TABLE triage_fidelity ADD CONSTRAINT triage_fidelity_stored_body_names_its_key
	            CHECK (body_state <> 'stored' OR octet_length(body_sha256) = 32);
	    END IF;
	END $$;`,

	// "Which probes got this exact response" is the question an operator asks after seeing one
	// interesting body, and it is the reverse of the link the row carries.
	`CREATE INDEX IF NOT EXISTS idx_triage_fidelity_body
	    ON triage_fidelity(run_id, body_sha256)
	    WHERE body_state = 'stored';`,
}

// EnsureTriageSchema applies the DDL. Idempotent, so it is safe to call on every boot.
//
// createTables in database.go appends TriageSchema to its own query list, which is where
// vector_scans and vector_findings are created, so in the running api this is already done by the
// time anything can call the store. It is exported so a test can stand the schema up against the
// real database without booting the api.
func EnsureTriageSchema(ctx context.Context) error {
	for _, stmt := range TriageSchema {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
