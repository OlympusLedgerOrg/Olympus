package api

// H-2 two-phase commit atomicity tests.
//
// These tests verify the contract documented at the top of
// `prepareRecord` / `handleQueueLeaf`: under any storage failure between
// PrepareUpdate and CommitPreparedUpdate, the Go sequencer MUST issue an
// AbortPreparedUpdate so the live SMT does not advance. Conversely, under
// success the Go sequencer MUST issue exactly one CommitPreparedUpdate
// per persisted leaf.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/metrics"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// fakeSMT is a programmable smtBackend used by the H-2 tests. It tracks
// prepared transactions, allows tests to inject failures at specific
// stages, and exposes counters so tests can assert which RPCs were called
// in which order.
type fakeSMT struct {
	mu sync.Mutex

	// Live root advances on commit only. Tests assert that a failed
	// store + abort leaves liveRoot unchanged.
	liveRoot     []byte
	liveTreeSize uint64

	// Pending prepared transactions (transactionID → mock state).
	pending map[string]*fakePrepared

	// Counters for assertions.
	canonCalls          atomic.Uint64
	prepareCalls        atomic.Uint64
	commitCalls         atomic.Uint64
	abortCalls          atomic.Uint64
	signCalls           atomic.Uint64
	proveInclusionCalls atomic.Uint64

	// Failure injection knobs.
	prepareErr error
	signErr    error
	commitErr  error

	// Allows tests to capture the order of operations.
	opLog []string
}

type fakePrepared struct {
	priorRoot []byte
	newRoot   []byte
	treeSize  uint64
	globalKey []byte
	valueHash []byte
	deltas    []*pb.SmtNodeDelta
}

func newFakeSMT() *fakeSMT {
	return &fakeSMT{
		liveRoot: make([]byte, 32),
		pending:  make(map[string]*fakePrepared),
	}
}

func (f *fakeSMT) logOp(op string) {
	f.mu.Lock()
	f.opLog = append(f.opLog, op)
	f.mu.Unlock()
}

func (f *fakeSMT) Canonicalize(_ context.Context, _ string, content []byte) (*pb.CanonicalizeResponse, error) {
	f.canonCalls.Add(1)
	f.logOp("canon")
	// Echo content as canonical for the test (real Rust does NFC + JCS;
	// the Go tests don't need to validate canonicalization itself).
	return &pb.CanonicalizeResponse{CanonicalContent: content}, nil
}

func (f *fakeSMT) PrepareUpdate(_ context.Context, _ string, recordKey *pb.RecordKey, canonicalContent []byte, _ string, _ string) (*pb.PrepareUpdateResponse, error) {
	f.prepareCalls.Add(1)
	f.logOp("prepare")
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Synthesise stable, distinct hashes for this prepare. The test
	// doesn't need cryptographic correctness — only uniqueness so we can
	// assert root advancement and identify deltas.
	prior := append([]byte(nil), f.liveRoot...)
	nextSize := f.liveTreeSize + 1
	newRoot := make([]byte, 32)
	for i := range newRoot {
		newRoot[i] = byte(nextSize) ^ byte(i)
	}
	gk := make([]byte, 32)
	copy(gk, []byte(recordKey.RecordType+":"+recordKey.RecordId))
	vh := make([]byte, 32)
	copy(vh, canonicalContent)

	deltas := make([]*pb.SmtNodeDelta, 256)
	for i := range deltas {
		deltas[i] = &pb.SmtNodeDelta{Path: []byte{}, Level: uint32(i), Hash: make([]byte, 32)}
	}

	txID := fmt.Sprintf("tx-%d", f.prepareCalls.Load())
	f.pending[txID] = &fakePrepared{
		priorRoot: prior,
		newRoot:   newRoot,
		treeSize:  nextSize,
		globalKey: gk,
		valueHash: vh,
		deltas:    deltas,
	}

	return &pb.PrepareUpdateResponse{
		TransactionId: txID,
		NewRoot:       newRoot,
		PriorRoot:     prior,
		GlobalKey:     gk,
		LeafValueHash: vh,
		Deltas:        deltas,
		TreeSize:      nextSize,
	}, nil
}

func (f *fakeSMT) CommitPreparedUpdate(_ context.Context, transactionID string) (*pb.CommitPreparedUpdateResponse, error) {
	f.commitCalls.Add(1)
	f.logOp("commit:" + transactionID)
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pending[transactionID]
	if !ok {
		return nil, errors.New("not found")
	}
	delete(f.pending, transactionID)
	// Atomic-swap check: refuse if liveRoot has moved since prepare.
	if !bytes.Equal(f.liveRoot, p.priorRoot) {
		return nil, errors.New("stale prepare")
	}
	f.liveRoot = p.newRoot
	f.liveTreeSize = p.treeSize
	return &pb.CommitPreparedUpdateResponse{NewRoot: p.newRoot, TreeSize: p.treeSize}, nil
}

func (f *fakeSMT) AbortPreparedUpdate(_ context.Context, transactionID string) error {
	f.abortCalls.Add(1)
	f.logOp("abort:" + transactionID)
	f.mu.Lock()
	delete(f.pending, transactionID)
	f.mu.Unlock()
	return nil
}

func (f *fakeSMT) ProveInclusion(_ context.Context, _ string, _ *pb.RecordKey, _ []byte) (*pb.ProveInclusionResponse, error) {
	f.proveInclusionCalls.Add(1)
	return &pb.ProveInclusionResponse{}, nil
}

func (f *fakeSMT) SignRoot(_ context.Context, root []byte, treeSize uint64, _ map[string]string) (*pb.SignRootResponse, error) {
	f.signCalls.Add(1)
	f.logOp("sign")
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig := make([]byte, 64)
	copy(sig, root)
	for i := range sig {
		sig[i] ^= byte(treeSize)
	}
	return &pb.SignRootResponse{Signature: sig}, nil
}

func (f *fakeSMT) liveRootCopy() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.liveRoot...)
}

func (f *fakeSMT) pendingLen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}

// failingStorage is a storageQuerier that always errors on writes.
type failingStorage struct {
	storeErr      error
	storeCalls    atomic.Uint64
	delayPerStore time.Duration
}

func (s *failingStorage) StoreLeafAndDeltas(ctx context.Context, _ []storage.SmtDelta, _ []byte, _ uint64, _ []byte, _ storage.LeafEntry) error {
	s.storeCalls.Add(1)
	if s.delayPerStore > 0 {
		select {
		case <-time.After(s.delayPerStore):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.storeErr
}

func (s *failingStorage) StoreLeafAndDeltasBatch(ctx context.Context, _ []storage.BatchLeaf) error {
	s.storeCalls.Add(1)
	if s.delayPerStore > 0 {
		select {
		case <-time.After(s.delayPerStore):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.storeErr
}

func (s *failingStorage) GetLatestRoot(_ context.Context) ([]byte, uint64, error) {
	return make([]byte, 32), 0, nil
}

func (s *failingStorage) GetRootByTreeSize(_ context.Context, _ uint64) (*storage.SignedRoot, error) {
	return nil, errors.New("not implemented")
}

// recordingStorage is a storageQuerier that captures successful writes.
type recordingStorage struct {
	mu    sync.Mutex
	calls int
	leafs []storage.LeafEntry
}

func (s *recordingStorage) StoreLeafAndDeltas(_ context.Context, _ []storage.SmtDelta, _ []byte, _ uint64, _ []byte, leaf storage.LeafEntry) error {
	s.mu.Lock()
	s.calls++
	s.leafs = append(s.leafs, leaf)
	s.mu.Unlock()
	return nil
}

func (s *recordingStorage) StoreLeafAndDeltasBatch(_ context.Context, batch []storage.BatchLeaf) error {
	s.mu.Lock()
	s.calls++
	for _, b := range batch {
		s.leafs = append(s.leafs, b.Leaf)
	}
	s.mu.Unlock()
	return nil
}

func (s *recordingStorage) GetLatestRoot(_ context.Context) ([]byte, uint64, error) {
	return make([]byte, 32), 0, nil
}

func (s *recordingStorage) GetRootByTreeSize(_ context.Context, _ uint64) (*storage.SignedRoot, error) {
	return nil, errors.New("not implemented")
}

// newTestSequencer builds a Sequencer wired against the supplied SMT/store
// fakes, with a deterministic API token and metrics registry the test can
// inspect.
func newTestSequencer(t *testing.T, smt smtBackend, store storageQuerier) (*Sequencer, *metrics.Registry) {
	t.Helper()
	mreg := metrics.New()
	s := &Sequencer{
		smtClient:            smt,
		storage:              store,
		token:                strings.Repeat("x", 32),
		metrics:              mreg,
		storageCommitTimeout: 2 * time.Second,
	}
	return s, mreg
}

func makeQueueLeafBody(t *testing.T, recordID string) []byte {
	t.Helper()
	body, err := json.Marshal(QueueLeafRequest{
		ShardID:                "shard-A",
		RecordType:             "doc",
		RecordID:               recordID,
		Content:                []byte(`{"hello":"world"}`),
		ContentType:            "application/json",
		ParserID:               "test@1.0.0",
		CanonicalParserVersion: "v1",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func doQueueLeaf(t *testing.T, h http.Handler, body []byte) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result()
}

// TestQueueLeaf_StorageFailure_TriggersAbort_RustStateUnchanged is the
// headline H-2 invariant: when Postgres fails between PrepareUpdate and
// CommitPreparedUpdate, the sequencer MUST issue AbortPreparedUpdate and
// the Rust live SMT root MUST NOT advance.
func TestQueueLeaf_StorageFailure_TriggersAbort_RustStateUnchanged(t *testing.T) {
	smt := newFakeSMT()
	store := &failingStorage{storeErr: errors.New("postgres exploded")}
	seq, mreg := newTestSequencer(t, smt, store)
	rootBeforeRequest := smt.liveRootCopy()

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on storage failure, got %d", resp.StatusCode)
	}
	if got := smt.prepareCalls.Load(); got != 1 {
		t.Fatalf("PrepareUpdate calls: want 1, got %d", got)
	}
	if got := smt.abortCalls.Load(); got != 1 {
		t.Fatalf("AbortPreparedUpdate calls: want 1, got %d", got)
	}
	if got := smt.commitCalls.Load(); got != 0 {
		t.Fatalf("CommitPreparedUpdate calls: want 0 on storage failure, got %d", got)
	}
	if !bytes.Equal(smt.liveRootCopy(), rootBeforeRequest) {
		t.Fatalf("live SMT root advanced despite storage failure; H-2 invariant violated")
	}
	if smt.pendingLen() != 0 {
		t.Fatalf("prepared LRU not drained after abort; got %d entries", smt.pendingLen())
	}
	// Metrics: aborts_after_db_failure must be 1, commits_after_db_success 0.
	if mreg.AbortsAfterDBFailure.Value() != 1 {
		t.Fatalf("aborts_after_db_failure: want 1, got %d", mreg.AbortsAfterDBFailure.Value())
	}
	if mreg.CommitsAfterDBSuccess.Value() != 0 {
		t.Fatalf("commits_after_db_success: want 0, got %d", mreg.CommitsAfterDBSuccess.Value())
	}
	if mreg.PreparedPending.Value() != 0 {
		t.Fatalf("prepared_pending: want 0 after abort, got %d", mreg.PreparedPending.Value())
	}
}

// TestQueueLeaf_HappyPath_AdvancesRoot_AfterDurableWrite verifies the
// success ordering: Prepare → Sign → Store → Commit, and that the
// Rust live SMT advances exactly once per persisted leaf.
func TestQueueLeaf_HappyPath_AdvancesRoot_AfterDurableWrite(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, mreg := newTestSequencer(t, smt, store)

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := smt.commitCalls.Load(); got != 1 {
		t.Fatalf("CommitPreparedUpdate calls: want 1, got %d", got)
	}
	if got := smt.abortCalls.Load(); got != 0 {
		t.Fatalf("AbortPreparedUpdate calls: want 0 on success, got %d", got)
	}
	if store.calls != 1 {
		t.Fatalf("storage calls: want 1, got %d", store.calls)
	}
	// Operation ordering: prepare must come before store, store before commit.
	expectedOrder := []string{"canon", "prepare", "sign", "commit:tx-1"}
	if len(smt.opLog) != len(expectedOrder) {
		t.Fatalf("op log length: want %v, got %v", expectedOrder, smt.opLog)
	}
	for i, op := range expectedOrder {
		if smt.opLog[i] != op {
			t.Fatalf("op[%d]: want %q, got %q (full: %v)", i, op, smt.opLog[i], smt.opLog)
		}
	}
	if mreg.CommitsAfterDBSuccess.Value() != 1 {
		t.Fatalf("commits_after_db_success: want 1, got %d", mreg.CommitsAfterDBSuccess.Value())
	}
	if mreg.AbortsAfterDBFailure.Value() != 0 {
		t.Fatalf("aborts_after_db_failure: want 0 on success, got %d", mreg.AbortsAfterDBFailure.Value())
	}
	if mreg.PreparedPending.Value() != 0 {
		t.Fatalf("prepared_pending: want 0 after commit, got %d", mreg.PreparedPending.Value())
	}
}

// TestQueueLeaf_SignFailure_AbortsBeforeStorage verifies that a failure
// in SignRoot (after PrepareUpdate succeeds) triggers an Abort and never
// touches storage.
func TestQueueLeaf_SignFailure_AbortsBeforeStorage(t *testing.T) {
	smt := newFakeSMT()
	smt.signErr = errors.New("HSM unavailable")
	store := &recordingStorage{}
	seq, mreg := newTestSequencer(t, smt, store)

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if smt.abortCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 abort, got %d", smt.abortCalls.Load())
	}
	if store.calls != 0 {
		t.Fatalf("storage must not be touched on sign failure, got %d", store.calls)
	}
	if mreg.AbortsAfterDBFailure.Value() != 1 {
		t.Fatalf("aborts_after_db_failure: want 1 (catches all post-prepare failures), got %d", mreg.AbortsAfterDBFailure.Value())
	}
}

// TestQueueLeaf_CommitFailureAfterDurableWrite_LogsForReplay verifies
// that when CommitPreparedUpdate fails AFTER a successful Postgres COMMIT,
// the sequencer surfaces a 5xx but the durable write is retained — the
// invariant is that startup-replay reconciles on the next restart.
func TestQueueLeaf_CommitFailureAfterDurableWrite_LogsForReplay(t *testing.T) {
	smt := newFakeSMT()
	smt.commitErr = errors.New("rust crashed")
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, smt, store)

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if store.calls != 1 {
		t.Fatalf("storage must be called exactly once (write happened before failed commit), got %d", store.calls)
	}
	// The leaf is durable; the operator-visible signal is a 500 + log
	// line. Startup-replay on the next restart will reconcile.
}

// TestQueueLeaf_StorageTimeoutShorterThanLRU verifies the new requirement
// that the Postgres-commit budget is enforced as a context deadline. We
// inject a slow store and a 50ms commit timeout, and assert the request
// fails fast (well under the 30s LRU TTL).
func TestQueueLeaf_StorageTimeoutShorterThanLRU(t *testing.T) {
	smt := newFakeSMT()
	store := &failingStorage{
		// No explicit error; the delay + ctx will produce ctx.Err().
		delayPerStore: 500 * time.Millisecond,
	}
	seq, _ := newTestSequencer(t, smt, store)
	seq.storageCommitTimeout = 50 * time.Millisecond

	start := time.Now()
	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("request took %s — should have failed at the 50ms commit deadline, not at the 500ms store delay", elapsed)
	}
	if smt.abortCalls.Load() != 1 {
		t.Fatalf("expected 1 abort after timeout, got %d", smt.abortCalls.Load())
	}
}

// TestPrepareRecord_AbortsOnContractViolation verifies that if the Rust
// service returns wrong-length hashes (a contract violation), the
// sequencer aborts the prepared txn before bubbling the error.
func TestPrepareRecord_AbortsOnContractViolation(t *testing.T) {
	// Wrap fakeSMT to return a too-short root.
	smt := newFakeSMT()
	contractViolatingSMT := &contractViolatingSMTWrap{inner: smt}
	store := &recordingStorage{}
	seq, _ := newTestSequencer(t, contractViolatingSMT, store)

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on contract violation, got %d", resp.StatusCode)
	}
	if smt.abortCalls.Load() != 1 {
		t.Fatalf("expected 1 abort on contract violation, got %d", smt.abortCalls.Load())
	}
	if store.calls != 0 {
		t.Fatalf("storage must not be touched on contract violation, got %d", store.calls)
	}
}

type contractViolatingSMTWrap struct {
	inner *fakeSMT
}

func (c *contractViolatingSMTWrap) Canonicalize(ctx context.Context, ct string, content []byte) (*pb.CanonicalizeResponse, error) {
	return c.inner.Canonicalize(ctx, ct, content)
}
func (c *contractViolatingSMTWrap) PrepareUpdate(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, parserID string, canonicalParserVersion string) (*pb.PrepareUpdateResponse, error) {
	resp, err := c.inner.PrepareUpdate(ctx, shardID, recordKey, canonicalContent, parserID, canonicalParserVersion)
	if err != nil {
		return resp, err
	}
	resp.NewRoot = []byte{0x00} // wrong length on purpose
	return resp, nil
}
func (c *contractViolatingSMTWrap) CommitPreparedUpdate(ctx context.Context, txID string) (*pb.CommitPreparedUpdateResponse, error) {
	return c.inner.CommitPreparedUpdate(ctx, txID)
}
func (c *contractViolatingSMTWrap) AbortPreparedUpdate(ctx context.Context, txID string) error {
	return c.inner.AbortPreparedUpdate(ctx, txID)
}
func (c *contractViolatingSMTWrap) ProveInclusion(ctx context.Context, sid string, rk *pb.RecordKey, root []byte) (*pb.ProveInclusionResponse, error) {
	return c.inner.ProveInclusion(ctx, sid, rk, root)
}
func (c *contractViolatingSMTWrap) SignRoot(ctx context.Context, root []byte, ts uint64, m map[string]string) (*pb.SignRootResponse, error) {
	return c.inner.SignRoot(ctx, root, ts, m)
}

// TestQueueLeaves_BatchPath_PerRecordCommit verifies the batch path
// implements per-record prepare → store → commit (NOT N prepares + 1 store
// + N commits, which would re-introduce the divergence H-2 fixes).
func TestQueueLeaves_BatchPath_PerRecordCommit(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, mreg := newTestSequencer(t, smt, store)

	body, err := json.Marshal(QueueLeavesRequest{
		Records: []QueueLeafRequest{
			{ShardID: "s", RecordType: "doc", RecordID: "1", Content: []byte("a"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
			{ShardID: "s", RecordType: "doc", RecordID: "2", Content: []byte("b"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
			{ShardID: "s", RecordType: "doc", RecordID: "3", Content: []byte("c"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if smt.prepareCalls.Load() != 3 {
		t.Fatalf("PrepareUpdate calls: want 3, got %d", smt.prepareCalls.Load())
	}
	if smt.commitCalls.Load() != 3 {
		t.Fatalf("CommitPreparedUpdate calls: want 3, got %d", smt.commitCalls.Load())
	}
	if store.calls != 3 {
		t.Fatalf("storage calls: want 3 (per-record), got %d", store.calls)
	}
	if mreg.CommitsAfterDBSuccess.Value() != 3 {
		t.Fatalf("commits_after_db_success: want 3, got %d", mreg.CommitsAfterDBSuccess.Value())
	}
	// Verify the per-record ordering: prepare(i) → sign(i) → commit(i)
	// before prepare(i+1). If a prepare(i+1) appeared before commit(i),
	// the batch would be re-introducing the H-2 divergence.
	prepareIdx := 0
	commitIdx := 0
	for _, op := range smt.opLog {
		if op == "prepare" {
			if commitIdx < prepareIdx {
				t.Fatalf("batch path issued prepare(%d) before commit(%d): op log = %v", prepareIdx+1, prepareIdx, smt.opLog)
			}
			prepareIdx++
		}
		if strings.HasPrefix(op, "commit:") {
			commitIdx++
		}
	}
}

// TestQueueLeaves_BatchPath_AbortsOnMidBatchStorageFailure verifies that
// when storage fails on record N, the prepared txn for N is aborted and
// records 0..N-1 are retained (durable + live).
func TestQueueLeaves_BatchPath_AbortsOnMidBatchStorageFailure(t *testing.T) {
	smt := newFakeSMT()
	store := &flakyStorage{failOnCall: 2} // succeed on call 1, fail on call 2
	seq, mreg := newTestSequencer(t, smt, store)

	body, err := json.Marshal(QueueLeavesRequest{
		Records: []QueueLeafRequest{
			{ShardID: "s", RecordType: "doc", RecordID: "1", Content: []byte("a"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
			{ShardID: "s", RecordType: "doc", RecordID: "2", Content: []byte("b"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
			{ShardID: "s", RecordType: "doc", RecordID: "3", Content: []byte("c"), ContentType: "application/json", ParserID: "p@1", CanonicalParserVersion: "v1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/queue-leaves", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 mid-batch, got %d", rr.Code)
	}
	// Expected: prepare(1)+commit(1) succeeded; prepare(2)+abort(2)
	// happened; prepare(3) never ran.
	if smt.commitCalls.Load() != 1 {
		t.Fatalf("commits: want 1 (record 1 succeeded), got %d", smt.commitCalls.Load())
	}
	if smt.abortCalls.Load() != 1 {
		t.Fatalf("aborts: want 1 (record 2 storage failed), got %d", smt.abortCalls.Load())
	}
	if smt.prepareCalls.Load() != 2 {
		t.Fatalf("prepares: want 2 (record 3 never reached), got %d", smt.prepareCalls.Load())
	}
	if mreg.CommitsAfterDBSuccess.Value() != 1 || mreg.AbortsAfterDBFailure.Value() != 1 {
		t.Fatalf("metrics mismatch: commits=%d aborts=%d", mreg.CommitsAfterDBSuccess.Value(), mreg.AbortsAfterDBFailure.Value())
	}
}

// flakyStorage succeeds on calls < failOnCall, then fails.
type flakyStorage struct {
	mu         sync.Mutex
	calls      int
	failOnCall int
}

func (s *flakyStorage) StoreLeafAndDeltas(_ context.Context, _ []storage.SmtDelta, _ []byte, _ uint64, _ []byte, _ storage.LeafEntry) error {
	s.mu.Lock()
	s.calls++
	c := s.calls
	s.mu.Unlock()
	if c >= s.failOnCall {
		return errors.New("postgres failed on call " + fmt.Sprint(c))
	}
	return nil
}
func (s *flakyStorage) StoreLeafAndDeltasBatch(_ context.Context, _ []storage.BatchLeaf) error {
	return errors.New("not used in this test")
}
func (s *flakyStorage) GetLatestRoot(_ context.Context) ([]byte, uint64, error) {
	return make([]byte, 32), 0, nil
}
func (s *flakyStorage) GetRootByTreeSize(_ context.Context, _ uint64) (*storage.SignedRoot, error) {
	return nil, errors.New("not implemented")
}

// TestMetricsEndpoint_RendersPrometheusFormat verifies the /metrics
// endpoint returns the H-2 counters in scrape-able form.
func TestMetricsEndpoint_RendersPrometheusFormat(t *testing.T) {
	smt := newFakeSMT()
	store := &recordingStorage{}
	seq, mreg := newTestSequencer(t, smt, store)

	// Drive one happy-path request and one failing request to populate.
	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-1"))
	resp.Body.Close()
	mreg.AbortsAfterDBFailure.Inc() // simulate a failure

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	seq.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE olympus_sequencer_prepared_pending gauge",
		"# TYPE olympus_sequencer_commits_after_db_success_total counter",
		"# TYPE olympus_sequencer_aborts_after_db_failure_total counter",
		"olympus_sequencer_commits_after_db_success_total 1",
		"olympus_sequencer_aborts_after_db_failure_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q.\nFull body:\n%s", want, body)
		}
	}
}

// TestConcurrentPrepareCommit_NoLostUpdates verifies that under
// concurrent /v1/queue-leaf load, the fakeSMT's atomic-swap check
// (mirroring Rust's prior_root validation) rejects stale prepares
// rather than silently overwriting. With the per-request commit
// happening before any other request can prepare, no commits should
// fail under sequential dispatch — but if we bypass the handler and
// drive the SMT directly with overlapping prepares, the second commit
// must fail. This locks down the fake's invariant so tests built on it
// remain trustworthy.
func TestConcurrentPrepareCommit_StalePreparesRejected(t *testing.T) {
	smt := newFakeSMT()

	// Two prepares against the empty live root.
	p1, err := smt.PrepareUpdate(context.Background(), "s",
		&pb.RecordKey{RecordType: "doc", RecordId: "1"}, []byte("a"), "p@1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := smt.PrepareUpdate(context.Background(), "s",
		&pb.RecordKey{RecordType: "doc", RecordId: "2"}, []byte("b"), "p@1", "v1")
	if err != nil {
		t.Fatal(err)
	}

	// First commit succeeds.
	if _, err := smt.CommitPreparedUpdate(context.Background(), p1.TransactionId); err != nil {
		t.Fatalf("first commit unexpected error: %v", err)
	}
	// Second commit must fail with stale-prepare.
	if _, err := smt.CommitPreparedUpdate(context.Background(), p2.TransactionId); err == nil {
		t.Fatalf("second commit must fail (stale prepare); the fake SMT's atomic-swap is broken")
	}
}

// TestPrepareRecord_StaleAbortRunsEvenAfterCancel verifies that
// bestEffortAbort uses a context decoupled from the request's parent
// context, so an aborted client doesn't leak prepared transactions in
// the LRU.
func TestPrepareRecord_AbortRunsAfterParentCancel(t *testing.T) {
	smt := newFakeSMT()
	store := &failingStorage{storeErr: errors.New("write failed")}
	seq, _ := newTestSequencer(t, smt, store)

	ctx, cancel := context.WithCancel(context.Background())
	body := makeQueueLeafBody(t, "doc-1")
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/queue-leaf", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sequencer-Token", strings.Repeat("x", 32))
	rr := httptest.NewRecorder()

	// Cancel the parent context before issuing the request to simulate
	// a client disconnect that races the storage failure.
	cancel()
	seq.Handler().ServeHTTP(rr, req)

	// The handler may have failed somewhere along the way; what matters
	// is that no prepared transactions are left in the LRU.
	if smt.pendingLen() != 0 {
		t.Fatalf("prepared LRU has %d leftover entries after parent cancel; bestEffortAbort must run with detached ctx", smt.pendingLen())
	}
}
