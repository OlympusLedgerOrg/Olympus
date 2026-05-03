package api

// Boundary-hardening tests for the input-validation surface of /v1/queue-leaf,
// /v1/queue-leaf-hash, and /v1/queue-leaves.
//
// These tests are intentionally PARANOID about three classes of off-by-one bug
// that history shows are common in Merkle/SMT pipelines:
//
//   1. Exact-length boundaries on identifier fields. The validators use
//      strict >  (not  >=)  comparisons, so the *boundary* values (e.g.
//      256-byte RecordID) must be ACCEPTED while the boundary+1 values
//      (257-byte RecordID) must be REJECTED.
//   2. Specific error strings, not just HTTP 400. Asserting only the status
//      code lets a future refactor accidentally collapse two different
//      validation rules into the same branch (e.g. an empty record_id
//      starts returning "invalid version" because a check moved). The
//      tests below pin the exact line  http.Error  emits.
//   3. Batch-size boundaries N (=1000) and N+1 (=1001) for handleQueueLeaves
//      to ensure neither the cap check nor the per-record loop has an
//      off-by-one or buffer-growth bug at the edge.
//
// NOTE on units: the production validators use  len(s) > N  on a Go string,
// which is a BYTE count. The Merkle key is BLAKE3(... || record_key) and is
// width-independent of  len(record_id) , so the 256/257 boundary in this file
// is a byte boundary on the API surface, NOT a bit-length boundary on the SMT
// key. We name the tests accordingly so future readers don't conflate the two.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// http.Error appends "\n" to the body; pin the exact wire format.
func errLine(s string) string { return s + "\n" }

// ---------------------------------------------------------------------------
// Exact-length boundaries on identifier fields
// ---------------------------------------------------------------------------

// TestQueueLeaf_RecordID_ByteLengthBoundary asserts the strict >256 rule on
// req.RecordID for /v1/queue-leaf:
//   - 256-byte RecordID is ACCEPTED (proceeds past validation; a fake SMT and
//     storage let the request reach 200 OK).
//   - 257-byte RecordID is REJECTED with HTTP 400 and the exact error string
//     "invalid record_id\n".
func TestQueueLeaf_RecordID_ByteLengthBoundary(t *testing.T) {
	// Accept at the boundary.
	t.Run("256_bytes_accepted", func(t *testing.T) {
		seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
		body := makeQueueLeafBody(t, strings.Repeat("a", 256))
		resp := doQueueLeaf(t, seq.Handler(), body)
		if resp.StatusCode != http.StatusOK {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			t.Fatalf("256-byte record_id must be accepted, got status=%d body=%q",
				resp.StatusCode, buf.String())
		}
	})

	// Reject just past the boundary, with EXACT error string.
	t.Run("257_bytes_rejected_with_exact_error", func(t *testing.T) {
		seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
		body := makeQueueLeafBody(t, strings.Repeat("a", 257))
		resp := doQueueLeaf(t, seq.Handler(), body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("257-byte record_id must be rejected with 400, got %d", resp.StatusCode)
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		if buf.String() != errLine("invalid record_id") {
			t.Fatalf("exact error string mismatch: want %q got %q",
				errLine("invalid record_id"), buf.String())
		}
	})
}

// TestQueueLeafHash_RecordID_ByteLengthBoundary mirrors the above for the
// /v1/queue-leaf-hash codepath, which has its own copy of the validator.
func TestQueueLeafHash_RecordID_ByteLengthBoundary(t *testing.T) {
	t.Run("256_bytes_accepted", func(t *testing.T) {
		seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
		body := queueLeafHashBodyForRecordID(t, strings.Repeat("a", 256))
		resp := doQueueLeafHash(t, seq.Handler(), body)
		if resp.StatusCode != http.StatusOK {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			t.Fatalf("256-byte record_id must be accepted, got status=%d body=%q",
				resp.StatusCode, buf.String())
		}
	})

	t.Run("257_bytes_rejected_with_exact_error", func(t *testing.T) {
		seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
		body := queueLeafHashBodyForRecordID(t, strings.Repeat("a", 257))
		resp := doQueueLeafHash(t, seq.Handler(), body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("257-byte record_id must be rejected with 400, got %d", resp.StatusCode)
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		if buf.String() != errLine("invalid record_id") {
			t.Fatalf("exact error string mismatch: want %q got %q",
				errLine("invalid record_id"), buf.String())
		}
	})
}

// TestQueueLeaf_AllIdentifierBoundaries walks every length-bounded field on
// /v1/queue-leaf and asserts BOTH directions of each cap:
//   - boundary value (== cap) is accepted (200)
//   - boundary+1 value (== cap+1) is rejected with the exact error line
//
// This catches refactors that flip > to >= or move a check past another.
func TestQueueLeaf_AllIdentifierBoundaries(t *testing.T) {
	type spec struct {
		field    string
		cap      int
		setter   func(*QueueLeafRequest, string)
		errExact string // expected http.Error body for boundary+1
	}
	specs := []spec{
		{
			field: "shard_id", cap: 128,
			setter:   func(r *QueueLeafRequest, s string) { r.ShardID = s },
			errExact: errLine("invalid shard_id"),
		},
		{
			field: "record_type", cap: 64,
			setter:   func(r *QueueLeafRequest, s string) { r.RecordType = s },
			errExact: errLine("invalid record_type"),
		},
		{
			field: "record_id", cap: 256,
			setter:   func(r *QueueLeafRequest, s string) { r.RecordID = s },
			errExact: errLine("invalid record_id"),
		},
		{
			field: "version", cap: 64,
			// Use only digits so the numeric-format check still passes at
			// the boundary; otherwise the version check would be eclipsed
			// by ParseUint failure and the test would be checking the
			// wrong rule.
			setter:   func(r *QueueLeafRequest, s string) { r.Version = s },
			errExact: errLine("invalid version"),
		},
	}

	for _, sp := range specs {
		sp := sp
		t.Run(sp.field+"/boundary_accepted", func(t *testing.T) {
			seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
			req := baseValidQueueLeaf()
			sp.setter(&req, fillerString(sp.field, sp.cap))
			resp := doQueueLeaf(t, seq.Handler(), mustJSON(t, req))
			if resp.StatusCode != http.StatusOK {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(resp.Body)
				t.Fatalf("%s at boundary len=%d must be accepted, got status=%d body=%q",
					sp.field, sp.cap, resp.StatusCode, buf.String())
			}
		})
		t.Run(sp.field+"/boundary_plus_one_rejected_exact_error", func(t *testing.T) {
			seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
			req := baseValidQueueLeaf()
			sp.setter(&req, fillerString(sp.field, sp.cap+1))
			resp := doQueueLeaf(t, seq.Handler(), mustJSON(t, req))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s at boundary+1 len=%d must be rejected with 400, got %d",
					sp.field, sp.cap+1, resp.StatusCode)
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			if buf.String() != sp.errExact {
				t.Fatalf("%s exact error mismatch: want %q got %q",
					sp.field, sp.errExact, buf.String())
			}
		})
	}
}

// TestQueueLeaf_RequiredFields_ExactErrorStrings pins the exact wire-format
// error for every "must not be empty" / format rule. This is the validation-
// matrix-hardening ask: we know which rule is failing and why, not just that
// *some* rule failed.
func TestQueueLeaf_RequiredFields_ExactErrorStrings(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*QueueLeafRequest)
		errExact string
	}{
		{
			name:     "empty shard_id",
			mutate:   func(r *QueueLeafRequest) { r.ShardID = "" },
			errExact: errLine("invalid shard_id"),
		},
		{
			name:     "empty record_type",
			mutate:   func(r *QueueLeafRequest) { r.RecordType = "" },
			errExact: errLine("invalid record_type"),
		},
		{
			name:     "empty record_id",
			mutate:   func(r *QueueLeafRequest) { r.RecordID = "" },
			errExact: errLine("invalid record_id"),
		},
		{
			name:     "non-numeric version",
			mutate:   func(r *QueueLeafRequest) { r.Version = "abc" },
			errExact: errLine("version must be empty or a base-10 unsigned integer"),
		},
		{
			name:     "empty content",
			mutate:   func(r *QueueLeafRequest) { r.Content = nil },
			errExact: errLine("content must not be empty"),
		},
		{
			name:     "empty parser_id",
			mutate:   func(r *QueueLeafRequest) { r.ParserID = "" },
			errExact: errLine("parser_id must not be empty (required by ADR-0003)"),
		},
		{
			name:     "empty canonical_parser_version",
			mutate:   func(r *QueueLeafRequest) { r.CanonicalParserVersion = "" },
			errExact: errLine("canonical_parser_version must not be empty (required by ADR-0003)"),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
			req := baseValidQueueLeaf()
			tc.mutate(&req)
			resp := doQueueLeaf(t, seq.Handler(), mustJSON(t, req))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", resp.StatusCode)
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			if buf.String() != tc.errExact {
				t.Fatalf("exact error mismatch: want %q got %q", tc.errExact, buf.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Batch-size boundaries: N=1000 (accepted) and N+1=1001 (rejected exact)
// ---------------------------------------------------------------------------

// TestQueueLeaves_BatchSizeBoundary_Exactly1000_Accepted verifies that the
// loop in handleQueueLeaves walks all N=1000 records without an off-by-one,
// and that each is committed (commitCalls == 1000) — i.e. the per-record
// prepare/store/commit sequence runs exactly once per leaf with no buffer
// truncation at the cap.
func TestQueueLeaves_BatchSizeBoundary_Exactly1000_Accepted(t *testing.T) {
	smt := newFakeSMT()
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	const N = 1000
	recs := make([]QueueLeafRequest, N)
	for i := range recs {
		recs[i] = QueueLeafRequest{
			ShardID: "s", RecordType: "doc", RecordID: fmt.Sprintf("%d", i),
			Content: []byte("a"), ContentType: "application/json",
			ParserID: "p@1", CanonicalParserVersion: "v1",
		}
	}
	body := mustJSON(t, QueueLeavesRequest{Records: recs})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("N=1000 batch must be accepted, got status=%d body=%q", rr.Code, rr.Body.String())
	}
	// Exactly one prepare and one commit per leaf — no off-by-one in the loop.
	if got := smt.prepareCalls.Load(); got != N {
		t.Fatalf("PrepareUpdate calls: want %d, got %d", N, got)
	}
	if got := smt.commitCalls.Load(); got != N {
		t.Fatalf("CommitPreparedUpdate calls: want %d, got %d", N, got)
	}
	if got := smt.abortCalls.Load(); got != 0 {
		t.Fatalf("AbortPreparedUpdate calls: want 0 on happy-path batch, got %d", got)
	}
}

// TestQueueLeaves_BatchSizeBoundary_1001_Rejected_ExactError pins the exact
// error wire format for batch-cap+1 and proves the SMT was never touched (no
// canonicalize / prepare leaks past the validator).
func TestQueueLeaves_BatchSizeBoundary_1001_Rejected_ExactError(t *testing.T) {
	smt := newFakeSMT()
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	const N = 1001
	recs := make([]QueueLeafRequest, N)
	for i := range recs {
		recs[i] = QueueLeafRequest{
			ShardID: "s", RecordType: "doc", RecordID: fmt.Sprintf("%d", i),
			Content: []byte("a"), ContentType: "application/json",
			ParserID: "p@1", CanonicalParserVersion: "v1",
		}
	}
	body := mustJSON(t, QueueLeavesRequest{Records: recs})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("N+1=1001 batch must be rejected with 400, got %d", rr.Code)
	}
	if rr.Body.String() != errLine("records exceeds maximum of 1000") {
		t.Fatalf("exact error mismatch: want %q got %q",
			errLine("records exceeds maximum of 1000"), rr.Body.String())
	}
	// No SMT side effects must escape the cap check.
	if got := smt.canonCalls.Load(); got != 0 {
		t.Fatalf("Canonicalize must not be called on rejected batch, got %d calls", got)
	}
	if got := smt.prepareCalls.Load(); got != 0 {
		t.Fatalf("PrepareUpdate must not be called on rejected batch, got %d calls", got)
	}
}

// TestQueueLeaves_PerRecordValidation_LastIndex_ExactError exercises the loop
// at the highest valid index (i == 999) to assert the per-record error
// formatting includes the correct index even at the batch cap. A truncated
// loop would never report "record 999".
func TestQueueLeaves_PerRecordValidation_LastIndex_ExactError(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	const N = 1000
	recs := make([]QueueLeafRequest, N)
	for i := range recs {
		recs[i] = QueueLeafRequest{
			ShardID: "s", RecordType: "doc", RecordID: fmt.Sprintf("%d", i),
			Content: []byte("a"), ContentType: "application/json",
			ParserID: "p@1", CanonicalParserVersion: "v1",
		}
	}
	// Poison the LAST record so we exercise the entire loop body up to the cap.
	recs[N-1].RecordID = ""

	body := mustJSON(t, QueueLeavesRequest{Records: recs})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
	want := errLine(fmt.Sprintf("record %d: invalid record_id", N-1))
	if rr.Body.String() != want {
		t.Fatalf("exact error mismatch: want %q got %q", want, rr.Body.String())
	}
}

// TestQueueLeaves_PerRecord_RecordIDByteLengthBoundary asserts the same 256/257
// boundary inside the batch loop, which is a SEPARATE copy of the validator
// from /v1/queue-leaf and could drift independently. We poison a single
// record with a 257-byte record_id and assert the exact prefixed error.
func TestQueueLeaves_PerRecord_RecordIDByteLengthBoundary(t *testing.T) {
	t.Run("256_bytes_accepted_in_batch", func(t *testing.T) {
		smt := newFakeSMT()
		seq, _ := newTestSequencer(t, smt, &recordingStorage{})
		recs := []QueueLeafRequest{
			{
				ShardID: "s", RecordType: "doc",
				RecordID:    strings.Repeat("a", 256),
				Content:     []byte("x"),
				ContentType: "application/json",
				ParserID:    "p@1", CanonicalParserVersion: "v1",
			},
		}
		body := mustJSON(t, QueueLeavesRequest{Records: recs})
		req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
		rr := httptest.NewRecorder()
		seq.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("256-byte record_id in batch must be accepted, got status=%d body=%q",
				rr.Code, rr.Body.String())
		}
	})
	t.Run("257_bytes_rejected_with_index_prefixed_exact_error", func(t *testing.T) {
		seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
		recs := []QueueLeafRequest{
			{ShardID: "s", RecordType: "doc", RecordID: "1", Content: []byte("x"),
				ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
			// Index 1 is the offender.
			{ShardID: "s", RecordType: "doc", RecordID: strings.Repeat("a", 257),
				Content: []byte("x"), ContentType: "application/json",
				ParserID: "p@1", CanonicalParserVersion: "v1"},
		}
		body := mustJSON(t, QueueLeavesRequest{Records: recs})
		req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
		rr := httptest.NewRecorder()
		seq.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
		want := errLine("record 1: invalid record_id")
		if rr.Body.String() != want {
			t.Fatalf("exact error mismatch: want %q got %q", want, rr.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// baseValidQueueLeaf returns a request that passes ALL validators so a single
// mutation can isolate one rule under test.
func baseValidQueueLeaf() QueueLeafRequest {
	return QueueLeafRequest{
		ShardID:                "s",
		RecordType:             "doc",
		RecordID:               "1",
		Version:                "1",
		Content:                []byte("hello"),
		ContentType:            "application/json",
		ParserID:               "p@1",
		CanonicalParserVersion: "v1",
	}
}

// fillerString returns a string of length n that is valid for the given
// field. For "version" we need a base-10 uint64-parseable digit string: a
// run of zeros parses to 0 regardless of length, which lets us probe the
// 64-byte length cap without colliding with the numeric-format rule (a run
// of nines longer than 20 chars would overflow uint64 first).
func fillerString(field string, n int) string {
	if field == "version" {
		return strings.Repeat("0", n)
	}
	return strings.Repeat("a", n)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// queueLeafHashBodyForRecordID is a thin wrapper that supplies a fixed valid
// 32-byte ValueHash; tests in this file only vary the RecordID length.
func queueLeafHashBodyForRecordID(t *testing.T, recordID string) []byte {
	t.Helper()
	return makeQueueLeafHashBody(t, recordID, bytes.Repeat([]byte{0x01}, 32))
}
