package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// attack_vectors.signals is written on every consolidation (the upsert in attackVectors.go) and was,
// until the read path landed, selected by nothing: a write-only column. The IDOR consolidation reads
// it to tell an id-bearing path (signals carrying 'uuid'/'numeric_id') from an ordinary one, so a row
// that STORES signals and a GetAttackVectors that DROPS them is the exact silent gap this guards.
//
// It runs against the real database, through the real handler, for the same reason the pointers tests
// do: the thing under test is a SELECT and its Scan staying in lockstep, which a fake cannot exercise.
func attackVectorsRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/attack-vectors/{scope_target_id}", GetAttackVectors).Methods("GET")
	return r
}

func TestGetAttackVectorsReturnsSignals(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)

	vectorID := uuid.New().String()
	// Inserted verbatim; GetAttackVectors preserves the stored array order, so the read-back must
	// equal this element-for-element.
	want := []string{"uuid", "numeric_id"}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
		                            path, insertion_point, parameters, signals)
		VALUES ($1,$2,$3,'GET','https',$4,443,$5,'path',$6,$7)`,
		vectorID, target, "idor:/api/v1/accounts/{uuid}/details",
		"accounts.example.invalid", "/api/v1/accounts/{uuid}/details",
		[]string{}, want); err != nil {
		t.Fatalf("insert vector with signals: %v", err)
	}

	rec := httptest.NewRecorder()
	attackVectorsRouter().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/attack-vectors/"+target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET attack-vectors: %d %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Vectors []struct {
			ID      string   `json:"id"`
			Signals []string `json:"signals"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rec.Body.String())
	}

	var got []string
	found := false
	for _, v := range body.Vectors {
		if v.ID == vectorID {
			found = true
			got = v.Signals
		}
	}
	if !found {
		t.Fatalf("the inserted vector %s is not in the response at all: %s", vectorID, rec.Body.String())
	}
	// The point of the change: the column is no longer write-only. An empty got here is the pre-fix
	// behaviour (signals selected by nothing), NOT an empty column, since the row stores two values.
	if len(got) != len(want) {
		t.Fatalf("signals not surfaced: got %v, want %v (the column is still write-only)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("signals differ at index %d: got %v, want %v", i, got, want)
		}
	}
}
