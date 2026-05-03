package api

// Coverage-boost tests for the internal/api package. These exercise
// constructor options, validation branches, and the GET handlers that
// were not reached by the H-2 atomicity suite.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/metrics"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// proofyFakeSMT extends fakeSMT to return a populated ProveInclusion response.
type proofyFakeSMT struct {
	*fakeSMT
	proofErr error
}

func (p *proofyFakeSMT) ProveInclusion(_ context.Context, _ string, _ *pb.RecordKey, _ []byte) (*pb.ProveInclusionResponse, error) {
	p.proveInclusionCalls.Add(1)
	if p.proofErr != nil {
		return nil, p.proofErr
	}
	siblings := make([][]byte, 256)
	for i := range siblings {
		siblings[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	return &pb.ProveInclusionResponse{
		GlobalKey: bytes.Repeat([]byte{0xAA}, 32),
		ValueHash: bytes.Repeat([]byte{0xBB}, 32),
		Siblings:  siblings,
		Root:      bytes.Repeat([]byte{0xCC}, 32),
	}, nil
}

// rootStorage is a storageQuerier that returns a pre-loaded latest root.
type rootStorage struct {
	root     []byte
	treeSize uint64
	err      error
	calls    atomic.Uint64
}

func (s *rootStorage) StoreLeafAndDeltas(_ context.Context, _ []storage.SmtDelta, _ []byte, _ uint64, _ []byte, _ storage.LeafEntry) error {
	return nil
}
func (s *rootStorage) StoreLeafAndDeltasBatch(_ context.Context, _ []storage.BatchLeaf) error {
	return nil
}
func (s *rootStorage) GetLatestRoot(_ context.Context) ([]byte, uint64, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, 0, s.err
	}
	return s.root, s.treeSize, nil
}
func (s *rootStorage) GetRootByTreeSize(_ context.Context, _ uint64) (*storage.SignedRoot, error) {
	return nil, errors.New("not implemented")
}

// ---------------------------------------------------------------------------
// Constructor option tests
// ---------------------------------------------------------------------------

func TestSequencerOptions_Apply(t *testing.T) {
	// WithMetrics + WithStorageCommitTimeout via direct option application.
	// We cannot call NewSequencer (it requires concrete *client.CdhsSmfClient
	// + *storage.PostgresStorage which aren't trivially constructable in a
	// unit test), but we can drive each option function against a Sequencer
	// scaffold to verify it does what it advertises.
	mreg := metrics.New()
	s := &Sequencer{
		metrics:              metrics.New(),
		storageCommitTimeout: time.Second,
	}

	WithMetrics(mreg)(s)
	if s.metrics != mreg {
		t.Fatalf("WithMetrics did not install registry")
	}
	if s.Metrics() != mreg {
		t.Fatalf("Metrics() must return the installed registry")
	}

	// nil registry must not overwrite.
	WithMetrics(nil)(s)
	if s.metrics != mreg {
		t.Fatalf("WithMetrics(nil) must be a no-op")
	}

	// Non-positive timeout must be a no-op (defence against
	// misconfigured env-var parsers passing through 0/-1).
	WithStorageCommitTimeout(0)(s)
	if s.storageCommitTimeout != time.Second {
		t.Fatalf("WithStorageCommitTimeout(0) must be a no-op, got %s", s.storageCommitTimeout)
	}
	WithStorageCommitTimeout(-5 * time.Second)(s)
	if s.storageCommitTimeout != time.Second {
		t.Fatalf("WithStorageCommitTimeout(<0) must be a no-op, got %s", s.storageCommitTimeout)
	}

	WithStorageCommitTimeout(7 * time.Second)(s)
	if s.storageCommitTimeout != 7*time.Second {
		t.Fatalf("WithStorageCommitTimeout(7s) not applied, got %s", s.storageCommitTimeout)
	}
}

func TestDefaultStorageCommitTimeout_BoundsContract(t *testing.T) {
	// The H-2 ordering guarantee depends on this default being strictly
	// less than the Rust LRU TTL (30s, see services/cdhs-smf-rust/src/
	// prepared.rs::DEFAULT_PREPARED_TTL). Lock that contract down here.
	if DefaultStorageCommitTimeout >= 30*time.Second {
		t.Fatalf("DefaultStorageCommitTimeout (%s) must stay strictly less than the Rust LRU TTL of 30s",
			DefaultStorageCommitTimeout)
	}
	if DefaultStorageCommitTimeout <= 0 {
		t.Fatalf("DefaultStorageCommitTimeout (%s) must be positive", DefaultStorageCommitTimeout)
	}
}

// ---------------------------------------------------------------------------
// /v1/queue-leaf-hash coverage
// ---------------------------------------------------------------------------

func makeQueueLeafHashBody(t *testing.T, recordID string, valueHash []byte) []byte {
	t.Helper()
	body, err := json.Marshal(QueueLeafHashRequest{
		ShardID:                "shard-A",
		RecordType:             "doc",
		RecordID:               recordID,
		ValueHash:              valueHash,
		ParserID:               "test@1.0.0",
		CanonicalParserVersion: "v1",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func doQueueLeafHash(t *testing.T, h http.Handler, body []byte) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaf-hash", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result()
}

func TestQueueLeafHash_HappyPath(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, mreg := newTestSequencer(t, smt, store)

	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-1", bytes.Repeat([]byte{0x01}, 32)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// Critically: Canonicalize must NOT be called on the pre-hashed path.
	if smt.canonCalls.Load() != 0 {
		t.Fatalf("Canonicalize must not be called on /v1/queue-leaf-hash, got %d", smt.canonCalls.Load())
	}
	if smt.prepareCalls.Load() != 1 || smt.commitCalls.Load() != 1 {
		t.Fatalf("expected 1 prepare + 1 commit, got prepare=%d commit=%d",
			smt.prepareCalls.Load(), smt.commitCalls.Load())
	}
	if mreg.CommitsAfterDBSuccess.Value() != 1 {
		t.Fatalf("commits_after_db_success: want 1, got %d", mreg.CommitsAfterDBSuccess.Value())
	}
}

func TestQueueLeafHash_StorageFailure_Aborts(t *testing.T) {
	smt := newFakeSMT()
	store := &failingStorage{storeErr: errors.New("pg down")}
	seq, mreg := newTestSequencer(t, smt, store)

	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-1", bytes.Repeat([]byte{0x02}, 32)))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if smt.abortCalls.Load() != 1 {
		t.Fatalf("expected 1 abort, got %d", smt.abortCalls.Load())
	}
	if mreg.AbortsAfterDBFailure.Value() != 1 {
		t.Fatalf("aborts_after_db_failure: want 1, got %d", mreg.AbortsAfterDBFailure.Value())
	}
}

func TestQueueLeafHash_CommitFailure_AfterDurableWrite(t *testing.T) {
	smt := newFakeSMT()
	smt.commitErr = errors.New("rust crashed")
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-1", bytes.Repeat([]byte{0x03}, 32)))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if store.calls != 1 {
		t.Fatalf("storage must be called exactly once before failed commit, got %d", store.calls)
	}
}

func TestQueueLeafHash_PrepareFailure(t *testing.T) {
	smt := newFakeSMT()
	smt.prepareErr = errors.New("nope")
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-1", bytes.Repeat([]byte{0x04}, 32)))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if store.calls != 0 {
		t.Fatalf("storage must not be touched on prepare failure, got %d", store.calls)
	}
	// PrepareUpdate failed before producing a transaction_id, so no Abort.
	if smt.abortCalls.Load() != 0 {
		t.Fatalf("expected 0 aborts when prepare itself failed, got %d", smt.abortCalls.Load())
	}
}

// Validation branches: each rejected request increments the relevant
// 4xx codepath. Drive them as a table.
func TestQueueLeafHash_ValidationErrors(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	cases := []struct {
		name    string
		mutate  func(*QueueLeafHashRequest)
		wantSub string
	}{
		{"empty shard", func(r *QueueLeafHashRequest) { r.ShardID = "" }, "shard_id"},
		{"long shard", func(r *QueueLeafHashRequest) { r.ShardID = strings.Repeat("x", 129) }, "shard_id"},
		{"empty record_type", func(r *QueueLeafHashRequest) { r.RecordType = "" }, "record_type"},
		{"long record_type", func(r *QueueLeafHashRequest) { r.RecordType = strings.Repeat("x", 65) }, "record_type"},
		{"empty record_id", func(r *QueueLeafHashRequest) { r.RecordID = "" }, "record_id"},
		{"long version", func(r *QueueLeafHashRequest) { r.Version = strings.Repeat("9", 65) }, "version"},
		{"non-numeric version", func(r *QueueLeafHashRequest) { r.Version = "abc" }, "version"},
		{"short value_hash", func(r *QueueLeafHashRequest) { r.ValueHash = []byte{0x01} }, "value_hash"},
		{"empty parser_id", func(r *QueueLeafHashRequest) { r.ParserID = "" }, "parser_id"},
		{"empty canonical_parser_version", func(r *QueueLeafHashRequest) { r.CanonicalParserVersion = "" }, "canonical_parser_version"},
	}

	base := QueueLeafHashRequest{
		ShardID:                "s",
		RecordType:             "doc",
		RecordID:               "1",
		ValueHash:              bytes.Repeat([]byte{0x01}, 32),
		ParserID:               "p@1",
		CanonicalParserVersion: "v1",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			resp := doQueueLeafHash(t, seq.Handler(), body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", resp.StatusCode)
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(resp.Body)
			if !strings.Contains(buf.String(), tc.wantSub) {
				t.Errorf("body %q must mention %q", buf.String(), tc.wantSub)
			}
		})
	}
}

func TestQueueLeafHash_BadJSON(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	resp := doQueueLeafHash(t, seq.Handler(), []byte("{not json"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestQueueLeafHash_MethodNotAllowed(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodGet, "/v1/queue-leaf-hash", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Validation branches for /v1/queue-leaf
// ---------------------------------------------------------------------------

func TestQueueLeaf_ValidationErrors(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	cases := []struct {
		name    string
		mutate  func(*QueueLeafRequest)
		wantSub string
	}{
		{"empty shard", func(r *QueueLeafRequest) { r.ShardID = "" }, "shard_id"},
		{"empty record_type", func(r *QueueLeafRequest) { r.RecordType = "" }, "record_type"},
		{"empty record_id", func(r *QueueLeafRequest) { r.RecordID = "" }, "record_id"},
		{"long record_id", func(r *QueueLeafRequest) { r.RecordID = strings.Repeat("x", 257) }, "record_id"},
		{"non-numeric version", func(r *QueueLeafRequest) { r.Version = "abc" }, "version"},
		{"empty content", func(r *QueueLeafRequest) { r.Content = nil }, "content"},
		{"empty parser_id", func(r *QueueLeafRequest) { r.ParserID = "" }, "parser_id"},
		{"empty canonical_parser_version", func(r *QueueLeafRequest) { r.CanonicalParserVersion = "" }, "canonical_parser_version"},
	}

	base := QueueLeafRequest{
		ShardID:                "s",
		RecordType:             "doc",
		RecordID:               "1",
		Content:                []byte("hello"),
		ContentType:            "application/json",
		ParserID:               "p@1",
		CanonicalParserVersion: "v1",
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			resp := doQueueLeaf(t, seq.Handler(), body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", resp.StatusCode)
			}
		})
	}
	if smt.prepareCalls.Load() != 0 {
		t.Fatalf("validation failures must not reach Rust, got %d prepares", smt.prepareCalls.Load())
	}
}

func TestQueueLeaf_MethodNotAllowed(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodGet, "/v1/queue-leaf", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestQueueLeaf_CanonicalizeFailure(t *testing.T) {
	smt := &canonFailFake{fakeSMT: newFakeSMT(), canonErr: errors.New("bad utf8")}
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", resp.StatusCode)
	}
	if smt.prepareCalls.Load() != 0 {
		t.Fatalf("PrepareUpdate must not run if Canonicalize failed, got %d", smt.prepareCalls.Load())
	}
}

type canonFailFake struct {
	*fakeSMT
	canonErr error
}

func (c *canonFailFake) Canonicalize(_ context.Context, _ string, _ []byte) (*pb.CanonicalizeResponse, error) {
	c.canonCalls.Add(1)
	return nil, c.canonErr
}

// ---------------------------------------------------------------------------
// /v1/queue-leaves additional coverage
// ---------------------------------------------------------------------------

func TestQueueLeaves_EmptyBatchRejected(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	body, _ := json.Marshal(QueueLeavesRequest{Records: []QueueLeafRequest{}})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty batch, got %d", rr.Code)
	}
}

func TestQueueLeaves_OversizedBatchRejected(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	recs := make([]QueueLeafRequest, 1001)
	for i := range recs {
		recs[i] = QueueLeafRequest{
			ShardID: "s", RecordType: "doc", RecordID: fmt.Sprintf("%d", i),
			Content: []byte("a"), ContentType: "application/json",
			ParserID: "p@1", CanonicalParserVersion: "v1",
		}
	}
	body, _ := json.Marshal(QueueLeavesRequest{Records: recs})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for oversized batch, got %d", rr.Code)
	}
}

func TestQueueLeaves_PerRecordValidation(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	body, _ := json.Marshal(QueueLeavesRequest{Records: []QueueLeafRequest{
		{ShardID: "s", RecordType: "doc", RecordID: "1", Content: []byte("a"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
		{ShardID: "s", RecordType: "doc", RecordID: "", Content: []byte("a"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
	}})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (record 2 has empty record_id), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "record 1") {
		t.Errorf("error message must identify the offending record index, got %q", rr.Body.String())
	}
}

func TestQueueLeaves_BadJSON(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", strings.NewReader("{nope"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestQueueLeaves_MethodNotAllowed(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodGet, "/v1/queue-leaves", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// /v1/get-latest-root coverage
// ---------------------------------------------------------------------------

func TestGetLatestRoot_HappyPath(t *testing.T) {
	store := &rootStorage{root: bytes.Repeat([]byte{0xAA}, 32), treeSize: 42}
	seq, _ := newTestSequencer(t, newFakeSMT(), store)

	req := httptest.NewRequest(http.MethodGet, "/v1/get-latest-root", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["root"] != strings.Repeat("aa", 32) {
		t.Errorf("root: got %v", got["root"])
	}
	if got["tree_size"].(float64) != 42 {
		t.Errorf("tree_size: got %v", got["tree_size"])
	}
}

func TestGetLatestRoot_StorageError(t *testing.T) {
	store := &rootStorage{err: errors.New("db down")}
	seq, _ := newTestSequencer(t, newFakeSMT(), store)

	req := httptest.NewRequest(http.MethodGet, "/v1/get-latest-root", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rr.Code)
	}
}

func TestGetLatestRoot_MethodNotAllowed(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &rootStorage{})
	req := httptest.NewRequest(http.MethodPost, "/v1/get-latest-root", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestGetLatestRoot_Unauthorized(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &rootStorage{})
	req := httptest.NewRequest(http.MethodGet, "/v1/get-latest-root", nil)
	// no token
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// /v1/get-inclusion-proof coverage
// ---------------------------------------------------------------------------

func TestGetInclusionProof_HappyPath(t *testing.T) {
	smt := &proofyFakeSMT{fakeSMT: newFakeSMT()}
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	req := httptest.NewRequest(http.MethodGet,
		"/v1/get-inclusion-proof?shard_id=s&record_type=doc&record_id=1&version=", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	siblings, ok := got["siblings"].([]any)
	if !ok || len(siblings) != 256 {
		t.Errorf("siblings should be a 256-element array, got %T len=%d", got["siblings"], len(siblings))
	}
	if got["root"] != strings.Repeat("cc", 32) {
		t.Errorf("root: got %v", got["root"])
	}
}

func TestGetInclusionProof_MissingParams(t *testing.T) {
	smt := &proofyFakeSMT{fakeSMT: newFakeSMT()}
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	cases := []string{
		"/v1/get-inclusion-proof",
		"/v1/get-inclusion-proof?shard_id=s",
		"/v1/get-inclusion-proof?shard_id=s&record_type=doc",
	}
	for _, u := range cases {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
		rr := httptest.NewRecorder()
		seq.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", u, rr.Code)
		}
	}
}

func TestGetInclusionProof_RustError(t *testing.T) {
	smt := &proofyFakeSMT{fakeSMT: newFakeSMT(), proofErr: errors.New("not found")}
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	req := httptest.NewRequest(http.MethodGet,
		"/v1/get-inclusion-proof?shard_id=s&record_type=doc&record_id=1", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rr.Code)
	}
}

func TestGetInclusionProof_MethodNotAllowed(t *testing.T) {
	smt := &proofyFakeSMT{fakeSMT: newFakeSMT()}
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})
	req := httptest.NewRequest(http.MethodPost, "/v1/get-inclusion-proof", nil)
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// /v1/healthz coverage (unauthenticated)
// ---------------------------------------------------------------------------

func TestHealthz_OK_NoTokenRequired(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// requireToken coverage
// ---------------------------------------------------------------------------

func TestRequireToken_RejectsWrongToken(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaf",
		bytes.NewReader(makeQueueLeafBody(t, "doc-1")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", "wrong-token")
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestRequireToken_RejectsMissingHeader(t *testing.T) {
	seq, _ := newTestSequencer(t, newFakeSMT(), &recordingStorage{})
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaf",
		bytes.NewReader(makeQueueLeafBody(t, "doc-1")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}
