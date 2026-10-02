package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// bundleFakeTx satisfies pgx.Tx by embedding the interface (left nil) and implementing only Exec,
// which is all the bundle import path calls. The exec closure decides what each statement does, so
// a test can make the server reject a whole batch, or one row, without a database. Any pgx.Tx
// method the import path does not use is never called, so the nil embed is safe here.
type bundleFakeTx struct {
	pgx.Tx
	exec func(sql string, arr []byte) (pgconn.CommandTag, error)
}

func (f *bundleFakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	var arr []byte
	if len(args) == 1 {
		if b, ok := args[0].([]byte); ok {
			arr = b
		}
	}
	return f.exec(sql, arr)
}

func bundleRows(n int) []json.RawMessage {
	out := make([]json.RawMessage, n)
	for i := range out {
		out[i] = json.RawMessage([]byte(`{"id":` + strconv.Itoa(i) + `}`))
	}
	return out
}

func bundleRowCount(arr []byte) int {
	var a []json.RawMessage
	_ = json.Unmarshal(arr, &a)
	return len(a)
}

// A batch that fails as a unit but whose rows succeed alone (the bytea-heavy oversized-batch case)
// must be isolated row by row so every row still loads, and a row the server rejects even on its
// own must be COUNTED as failed rather than silently dropped. The second half is the fail-open this
// fix closes: before it, importBundleTable returned nil on a failed batch and the handler reported
// "completed successfully" while rows were missing.
func TestImportBundleBatchIsolatesFailuresAndCountsThem(t *testing.T) {
	ctx := context.Background()
	const sql = "INSERT INTO x SELECT ... FROM jsonb_array_elements($1::jsonb) elem"

	// 1) The whole batch succeeds in one statement: no fallback, no failures.
	okTx := &bundleFakeTx{exec: func(s string, arr []byte) (pgconn.CommandTag, error) {
		if strings.HasPrefix(s, "INSERT") {
			return pgconn.NewCommandTag("INSERT 0 " + strconv.Itoa(bundleRowCount(arr))), nil
		}
		return pgconn.NewCommandTag(""), nil
	}}
	if imp, fail, ferr := importBundleBatch(ctx, okTx, sql, "x", bundleRows(5)); imp != 5 || fail != 0 || ferr != nil {
		t.Errorf("whole-batch success: imported=%d failed=%d err=%v, want 5/0/nil", imp, fail, ferr)
	}

	// 2) The batch is too big to load as a unit but each row loads alone. Every row must still land.
	splitTx := &bundleFakeTx{exec: func(s string, arr []byte) (pgconn.CommandTag, error) {
		if strings.HasPrefix(s, "INSERT") {
			if bundleRowCount(arr) > 1 {
				return pgconn.CommandTag{}, fmt.Errorf("jsonb field value too large")
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}
		return pgconn.NewCommandTag(""), nil
	}}
	if imp, fail, ferr := importBundleBatch(ctx, splitTx, sql, "x", bundleRows(5)); imp != 5 || fail != 0 || ferr != nil {
		t.Errorf("row-by-row fallback: imported=%d failed=%d err=%v, want 5/0/nil", imp, fail, ferr)
	}

	// 3) One row is rejected even on its own. It is counted as failed, the other four land, and the
	//    failure is surfaced rather than swallowed.
	bad := bundleRows(5)
	bad[2] = json.RawMessage([]byte(`{"id":"BAD"}`))
	rejectTx := &bundleFakeTx{exec: func(s string, arr []byte) (pgconn.CommandTag, error) {
		if strings.HasPrefix(s, "INSERT") {
			if bundleRowCount(arr) > 1 || strings.Contains(string(arr), "BAD") {
				return pgconn.CommandTag{}, fmt.Errorf("not-null constraint violation")
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}
		return pgconn.NewCommandTag(""), nil
	}}
	if imp, fail, ferr := importBundleBatch(ctx, rejectTx, sql, "x", bad); imp != 4 || fail != 1 || ferr != nil {
		t.Errorf("one rejected row: imported=%d failed=%d err=%v, want 4/1/nil", imp, fail, ferr)
	}

	// 4) The savepoint machinery itself fails: the transaction is dead, so this surfaces as a fatal
	//    error and is NOT counted as an ordinary per-row failure to be shrugged off.
	deadTx := &bundleFakeTx{exec: func(s string, arr []byte) (pgconn.CommandTag, error) {
		if strings.HasPrefix(s, "SAVEPOINT") {
			return pgconn.CommandTag{}, fmt.Errorf("conn closed")
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	if _, _, ferr := importBundleBatch(ctx, deadTx, sql, "x", bundleRows(3)); ferr == nil {
		t.Error("a savepoint failure must surface as a fatal error, not a silent per-row failure")
	}
}
