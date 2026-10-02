package utils

// EnsureFeatureSchemas creates the per-feature tables that are otherwise made LAZILY, on first use
// of their feature: the replay request-version tree and variant metadata, the session auto-refresh
// run log, and the flow-detection config. It is applied at boot (from main.go) for the same reason
// EnsureRequestFlowBuilderSchema and EnsureDetectedFlowNamesSchema are: a boot-time reader, or a
// .rs0n restore, must not find the table missing.
//
// THE RESTORE BUG THIS CLOSES. The database import skips any table that does not exist in the
// target, by design (you cannot COPY into a table that is not there). On a freshly built framework
// these four tables did not exist until their feature was first touched, so importing a bundle into
// a clean framework silently dropped their rows: 82 request-version rows, two variant labels, three
// session-refresh run records and one flow-detection config row, on the reference export. Creating
// them at boot means a clean framework always has them and the restore lands every row.
//
// Each underlying ensure is guarded by its own sync.Once, so calling them here is safe alongside the
// lazy call sites that still run when a handler reaches them first.
func EnsureFeatureSchemas() {
	EnsureReplayRequestVersionsSchema()
	EnsureReplayVariantMetaSchema()
	ensureSessionRefreshRunsSchema()
	ensureFlowDetectionConfigSchema()
}
