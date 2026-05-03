// Package api provides the Trillian-shaped log service API
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/client"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/metrics"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// maxRequestBodyBytes caps the size of an HTTP request body for queue-leaf
// and queue-leaves. This MUST stay <= the gRPC max_decoding_message_size
// configured on the Rust CD-HS-ST service (see
// services/cdhs-smf-rust/src/main.rs::GRPC_MAX_MESSAGE_BYTES). 32 MiB is the
// agreed ceiling on both sides; see the matching constant in main.rs.
const maxRequestBodyBytes = 32 << 20 // 32 MiB

// DefaultStorageCommitTimeout is the wall-clock budget the Go sequencer
// allows for the BEGIN; INSERT...; COMMIT step that durably persists a
// prepared two-phase-commit transaction (H-2). It MUST be strictly less
// than the Rust prepared-transaction LRU TTL (default 30s, see
// services/cdhs-smf-rust/src/prepared.rs::DEFAULT_PREPARED_TTL) so that
// the Go side gives up and triggers AbortPreparedUpdate well before the
// Rust LRU could prune the entry on its own. Otherwise we could get into
// a state where:
//
//   - Go is blocked on a slow Postgres COMMIT
//   - the Rust LRU TTL elapses and discards the prepared txn
//   - Postgres COMMIT eventually returns OK
//   - Go calls CommitPreparedUpdate → NOT_FOUND
//
// At that point durable state has the leaf but the live SMT does not, and
// recovery requires a full restart-replay. The 10s default leaves a 3×
// safety margin against the 30s LRU TTL even after the operator widens
// either bound.
const DefaultStorageCommitTimeout = 10 * time.Second

// smtBackend is the subset of *client.CdhsSmfClient that the sequencer
// API depends on. Defining it here lets unit tests substitute a fake
// without dialling a real gRPC server, and (more importantly for H-2)
// lets tests deterministically inject failures between PrepareUpdate and
// CommitPreparedUpdate to validate the rollback path.
type smtBackend interface {
	Canonicalize(ctx context.Context, contentType string, content []byte) (*pb.CanonicalizeResponse, error)
	PrepareUpdate(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, preHashedValueHash []byte, parserID string, canonicalParserVersion string) (*pb.PrepareUpdateResponse, error)
	CommitPreparedUpdate(ctx context.Context, transactionID string) (*pb.CommitPreparedUpdateResponse, error)
	AbortPreparedUpdate(ctx context.Context, transactionID string) error
	ProveInclusion(ctx context.Context, shardID string, recordKey *pb.RecordKey, root []byte) (*pb.ProveInclusionResponse, error)
	SignRoot(ctx context.Context, root []byte, treeSize uint64, contextData map[string]string) (*pb.SignRootResponse, error)
}

// storageQuerier is the persistence contract required by the sequencer API.
// It is satisfied by *storage.PostgresStorage in production and by test
// doubles in unit tests.
type storageQuerier interface {
	StoreLeafAndDeltas(ctx context.Context, deltas []storage.SmtDelta, root []byte, treeSize uint64, signature []byte, leaf storage.LeafEntry) error
	StoreLeafAndDeltasBatch(ctx context.Context, batch []storage.BatchLeaf) error
	GetLatestRoot(ctx context.Context) ([]byte, uint64, error)
	GetRootByTreeSize(ctx context.Context, treeSize uint64) (*storage.SignedRoot, error)
}

// Sequencer provides a Trillian-shaped log service API
type Sequencer struct {
	smtClient            smtBackend
	storage              storageQuerier
	token                string
	metrics              *metrics.Registry
	storageCommitTimeout time.Duration
}

// SequencerOption customises a Sequencer at construction time.
type SequencerOption func(*Sequencer)

// WithMetrics installs an application metrics registry so the sequencer
// can publish the H-2 two-phase-commit counters. If unset, the sequencer
// uses an internal registry whose values are not exported.
func WithMetrics(m *metrics.Registry) SequencerOption {
	return func(s *Sequencer) {
		if m != nil {
			s.metrics = m
		}
	}
}

// WithStorageCommitTimeout overrides the per-request budget for the
// Postgres COMMIT phase of the two-phase commit (H-2). Values <= 0 fall
// back to DefaultStorageCommitTimeout. Operators MUST keep this strictly
// less than the Rust LRU TTL (see DefaultStorageCommitTimeout doc).
func WithStorageCommitTimeout(d time.Duration) SequencerOption {
	return func(s *Sequencer) {
		if d > 0 {
			s.storageCommitTimeout = d
		}
	}
}

// NewSequencer creates a new sequencer service. The variadic options
// preserve backwards compatibility with the original 3-arg constructor.
func NewSequencer(smtClient *client.CdhsSmfClient, storage *storage.PostgresStorage, token string, opts ...SequencerOption) *Sequencer {
	s := &Sequencer{
		smtClient:            smtClient,
		storage:              storage,
		token:                token,
		metrics:              metrics.New(),
		storageCommitTimeout: DefaultStorageCommitTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Metrics returns the metrics registry the sequencer is publishing into.
// Callers (cmd/sequencer/main.go) mount its Handler() at /metrics.
func (s *Sequencer) Metrics() *metrics.Registry { return s.metrics }

// requireToken wraps an HTTP handler with shared-secret token authentication.
// Hashes both tokens with SHA-256 before comparing to prevent timing side-channels
// from length differences (subtle.ConstantTimeCompare short-circuits on unequal lengths).
func requireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	expectedHash := sha256.Sum256([]byte(token))
	return func(w http.ResponseWriter, r *http.Request) {
		providedHash := sha256.Sum256([]byte(r.Header.Get("X-Sequencer-Token")))
		if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Handler returns an HTTP handler for the sequencer API
func (s *Sequencer) Handler() http.Handler {
	mux := http.NewServeMux()

	// Liveness probe. Intentionally unauthenticated and dependency-free so
	// container orchestrators can probe it from a read-only distroless image
	// without holding an API token. Operators MUST keep the sequencer behind
	// an internal network (see docker-compose `backend` network) — exposing
	// /v1/healthz publicly is acceptable, but /v1/queue-leaf etc. must stay
	// token-gated.
	mux.HandleFunc("/v1/healthz", s.handleHealthz)

	// Trillian-shaped API endpoints
	mux.HandleFunc("/v1/queue-leaf", requireToken(s.token, s.handleQueueLeaf))
	// /v1/queue-leaf-hash accepts a pre-computed 32-byte value_hash and bypasses
	// Rust canonicalization. Use this when the caller already holds a canonical
	// content hash (e.g. Python storage_layer sending a pre-hashed value).
	// parser_id and canonical_parser_version are still required (ADR-0003).
	mux.HandleFunc("/v1/queue-leaf-hash", requireToken(s.token, s.handleQueueLeafHash))
	mux.HandleFunc("/v1/queue-leaves", requireToken(s.token, s.handleQueueLeaves))
	mux.HandleFunc("/v1/get-latest-root", requireToken(s.token, s.handleGetLatestRoot))
	mux.HandleFunc("/v1/get-inclusion-proof", requireToken(s.token, s.handleGetInclusionProof))
	// /v1/get-signed-root-pair returns the two signed roots at old_tree_size
	// and new_tree_size for offline comparison. This is *not* an
	// RFC-6962-style consistency proof; the sequencer does not currently
	// produce one. See docs/adr/0001-incremental-tree-reconstruction.md and
	// the SECURITY.md sequencer-token trust model for context.
	mux.HandleFunc("/v1/get-signed-root-pair", requireToken(s.token, s.handleGetSignedRootPair))
	// Deprecated alias for /v1/get-signed-root-pair. Returns HTTP 410 Gone
	// pointing callers to the new path. The old name was misleading: it
	// suggested an RFC-6962 consistency proof but only ever returned a pair
	// of signed roots. Will be removed in the next release after callers
	// have migrated.
	mux.HandleFunc("/v1/get-consistency-proof", requireToken(s.token, s.handleConsistencyProofGone))

	// /metrics is intentionally unauthenticated: it exposes only the H-2
	// two-phase-commit counters and contains no record content, no shard
	// names, and no leaf hashes. Operators that wish to gate it should
	// bind the metrics endpoint to an internal-only port via a reverse
	// proxy. The handler is concurrency-safe.
	mux.Handle("/metrics", s.metrics.Handler())

	return mux
}

// QueueLeafRequest represents a request to append a record.
// Both parser_id and canonical_parser_version are required ADR-0003 fields
// that are bound into the leaf hash domain by the Rust service.
type QueueLeafRequest struct {
	ShardID                string            `json:"shard_id"`
	RecordType             string            `json:"record_type"`
	RecordID               string            `json:"record_id"`
	Version                string            `json:"version,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	Content                []byte            `json:"content"`
	ContentType            string            `json:"content_type"`
	ParserID               string            `json:"parser_id"`
	CanonicalParserVersion string            `json:"canonical_parser_version"`
}

// QueueLeafHashRequest represents a request to append a pre-hashed leaf.
// Use this endpoint (/v1/queue-leaf-hash) when the caller has already computed
// a canonical value hash and wants to bypass Rust canonicalization. The
// value_hash is passed directly as canonical_content to the Rust SMT service.
// parser_id and canonical_parser_version are still required (ADR-0003).
type QueueLeafHashRequest struct {
	ShardID                string            `json:"shard_id"`
	RecordType             string            `json:"record_type"`
	RecordID               string            `json:"record_id"`
	Version                string            `json:"version,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	ValueHash              []byte            `json:"value_hash"`
	ParserID               string            `json:"parser_id"`
	CanonicalParserVersion string            `json:"canonical_parser_version"`
}

// QueueLeafResponse represents the response from queuing a leaf
type QueueLeafResponse struct {
	NewRoot       string `json:"new_root"`
	GlobalKey     string `json:"global_key"`
	LeafValueHash string `json:"leaf_value_hash"`
	TreeSize      uint64 `json:"tree_size"`
}

// QueueLeavesRequest is a batch of records to append atomically.
type QueueLeavesRequest struct {
	Records []QueueLeafRequest `json:"records"`
}

// QueueLeavesResponse returns per-record results plus the shared final root.
type QueueLeavesResponse struct {
	Results   []QueueLeafResponse `json:"results"`
	FinalRoot string              `json:"final_root"`
	TreeSize  uint64              `json:"tree_size"`
}

// preparedRecord bundles everything a handler needs to (a) commit a
// prepared transaction in the Rust SMT and (b) emit a JSON response. It is
// the in-process representation produced by `prepareRecord` between the
// PrepareUpdate RPC and the Postgres write.
type preparedRecord struct {
	transactionID string
	newRoot       []byte
	globalKey     []byte
	leafValueHash []byte
	treeSize      uint64
	deltas        []storage.SmtDelta
	signature     []byte
	parserID      string
	canonicalPV   string
}

// prepareRecord runs the read-only side of the two-phase flow for a single
// record: Canonicalize (optional) → PrepareUpdate → SignRoot. It does NOT
// mutate the live SMT (PrepareUpdate is read-only by design) and it does
// not touch storage.
//
// On any failure the prepared transaction (if one was created) is aborted
// before the error is returned, so callers can treat the helper as
// "all-or-nothing": either they receive a *preparedRecord they may safely
// commit, or they receive an error and the LRU is already cleaned up.
//
// Exactly one of `canonicalContent` and `preHashedValueHash` MUST be
// non-empty:
//   - For /v1/queue-leaf the caller passes Canonicalize's output as
//     `canonicalContent` and `nil` as `preHashedValueHash`.
//   - For /v1/queue-leaf-hash the caller passes `nil` as `canonicalContent`
//     and the user-supplied 32-byte value as `preHashedValueHash`. The
//     Rust service uses it verbatim — it does NOT hash it again — so the
//     leaf value committed to the SMT equals what the caller already
//     published off-band (regression-tested in the Rust suite as
//     `resolve_leaf_value_hash_pre_hashed_is_returned_verbatim`).
//
// `metrics.PreparedPending` is incremented inside this helper as soon as
// PrepareUpdate returns successfully, so that the matching decrement in
// `bestEffortAbort` (called below on contract or sign failure) does not
// underflow the gauge. Callers MUST therefore NOT increment the gauge
// themselves; the matching decrement is provided by either
// `commitPrepared` (success) or `bestEffortAbort` (any failure path).
func (s *Sequencer) prepareRecord(
	ctx context.Context,
	shardID string,
	recordKey *pb.RecordKey,
	canonicalContent []byte,
	preHashedValueHash []byte,
	parserID string,
	canonicalParserVersion string,
) (*preparedRecord, error) {
	prepResp, err := s.smtClient.PrepareUpdate(ctx, shardID, recordKey, canonicalContent, preHashedValueHash, parserID, canonicalParserVersion)
	if err != nil {
		return nil, fmt.Errorf("prepare update: %w", err)
	}

	// PrepareUpdate succeeded → there is now a live entry in the Rust LRU
	// that we own. Bump the gauge BEFORE any branch that may call
	// `bestEffortAbort` (which decrements it). Doing so here, in the one
	// place that creates the prepared transaction, removes the previous
	// race where contract-validation or SignRoot failure decremented the
	// gauge below the matching increment in the caller.
	s.metrics.PreparedPending.Add(1)

	// Validate hash-length contract before anything else; the same
	// invariants we previously checked on UpdateResponse must hold for
	// PrepareUpdateResponse too. On any violation we abort the prepared
	// transaction so it does not linger in the LRU.
	if len(prepResp.NewRoot) != 32 || len(prepResp.GlobalKey) != 32 || len(prepResp.LeafValueHash) != 32 || len(prepResp.Deltas) != 256 {
		s.bestEffortAbort(ctx, prepResp.TransactionId)
		return nil, fmt.Errorf("rust service violated wire contract: new_root=%d global_key=%d leaf_value_hash=%d deltas=%d",
			len(prepResp.NewRoot), len(prepResp.GlobalKey), len(prepResp.LeafValueHash), len(prepResp.Deltas))
	}

	signResp, err := s.smtClient.SignRoot(ctx, prepResp.NewRoot, prepResp.TreeSize, map[string]string{
		"shard_id":    shardID,
		"record_type": recordKey.RecordType,
		"record_id":   recordKey.RecordId,
	})
	if err != nil {
		s.bestEffortAbort(ctx, prepResp.TransactionId)
		return nil, fmt.Errorf("sign root: %w", err)
	}

	deltas := make([]storage.SmtDelta, len(prepResp.Deltas))
	for i, d := range prepResp.Deltas {
		deltas[i] = storage.SmtDelta{Path: d.Path, Level: d.Level, Hash: d.Hash}
	}

	return &preparedRecord{
		transactionID: prepResp.TransactionId,
		newRoot:       prepResp.NewRoot,
		globalKey:     prepResp.GlobalKey,
		leafValueHash: prepResp.LeafValueHash,
		treeSize:      prepResp.TreeSize,
		deltas:        deltas,
		signature:     signResp.Signature,
		parserID:      parserID,
		canonicalPV:   canonicalParserVersion,
	}, nil
}

// bestEffortAbort calls AbortPreparedUpdate, ignoring errors and using a
// fresh background context so the abort survives even when the caller's
// context has been cancelled (e.g. client disconnect mid-request). The
// AbortPreparedUpdate RPC is idempotent on the Rust side, so a duplicate
// abort is harmless.
//
// Increments `aborts_after_db_failure`: every code path that calls this
// helper is, by definition, rolling back a prepared transaction because
// something downstream of PrepareUpdate failed. That is exactly what the
// counter is meant to expose to operators.
func (s *Sequencer) bestEffortAbort(parent context.Context, txID string) {
	if txID == "" {
		return
	}
	// Decouple from the parent context: the abort MUST run even if the
	// parent was cancelled (which is often *why* we're aborting). Cap
	// it at storageCommitTimeout so a wedged Rust service can't hang
	// the handler forever.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.storageCommitTimeout)
	defer cancel()
	if err := s.smtClient.AbortPreparedUpdate(ctx, txID); err != nil {
		log.Printf("AbortPreparedUpdate(%s) failed (entry will TTL-evict from LRU): %v", txID, err)
	}
	s.metrics.AbortsAfterDBFailure.Inc()
	s.metrics.PreparedPending.Add(-1)
}

// commitPrepared runs the second half of the two-phase flow for a single
// prepared transaction: it asks the Rust service to atomically advance the
// live SMT now that durable storage has been written. Increments
// `commits_after_db_success`. On stale-prepare or NOT_FOUND from the Rust
// service the error is returned to the caller, which is responsible for
// surfacing a 5xx — durable state has already been written, so the
// invariant is that startup-replay will reconcile on the next restart.
func (s *Sequencer) commitPrepared(ctx context.Context, txID string) error {
	if _, err := s.smtClient.CommitPreparedUpdate(ctx, txID); err != nil {
		return err
	}
	s.metrics.CommitsAfterDBSuccess.Inc()
	s.metrics.PreparedPending.Add(-1)
	return nil
}

// withStorageTimeout returns a child context bounded by
// s.storageCommitTimeout, used to cap the BEGIN/INSERT/COMMIT phase. The
// timeout MUST stay strictly less than the Rust LRU TTL (see
// DefaultStorageCommitTimeout doc) so storage failure causes the Go side
// to emit AbortPreparedUpdate before the LRU could prune the entry on
// its own.
func (s *Sequencer) withStorageTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, s.storageCommitTimeout)
}

func (s *Sequencer) handleQueueLeaf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req QueueLeafRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.ShardID == "" || len(req.ShardID) > 128 {
		http.Error(w, "invalid shard_id", http.StatusBadRequest)
		return
	}
	if req.RecordType == "" || len(req.RecordType) > 64 {
		http.Error(w, "invalid record_type", http.StatusBadRequest)
		return
	}
	if req.RecordID == "" || len(req.RecordID) > 256 {
		http.Error(w, "invalid record_id", http.StatusBadRequest)
		return
	}
	if len(req.Version) > 64 {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	if req.Version != "" {
		if _, err := strconv.ParseUint(req.Version, 10, 64); err != nil {
			http.Error(w, "version must be empty or a base-10 unsigned integer", http.StatusBadRequest)
			return
		}
	}
	if len(req.Content) == 0 {
		http.Error(w, "content must not be empty", http.StatusBadRequest)
		return
	}
	if req.ParserID == "" {
		http.Error(w, "parser_id must not be empty (required by ADR-0003)", http.StatusBadRequest)
		return
	}
	if req.CanonicalParserVersion == "" {
		http.Error(w, "canonical_parser_version must not be empty (required by ADR-0003)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Step 1: Canonicalize content via Rust service. This is read-only on
	// the SMT, so it is safe to run before PrepareUpdate.
	canonResp, err := s.smtClient.Canonicalize(ctx, req.ContentType, req.Content)
	if err != nil {
		log.Printf("Canonicalization failed: %v", err)
		http.Error(w, "Canonicalization failed", http.StatusInternalServerError)
		return
	}

	recordKey := &pb.RecordKey{
		RecordType: req.RecordType,
		RecordId:   req.RecordID,
		Version:    req.Version,
		Metadata:   req.Metadata,
	}

	// H-2 two-phase commit, step (a): PrepareUpdate. Computes the new root
	// + deltas in the Rust service WITHOUT mutating live state. SignRoot
	// is also done here (also read-only) so the durable row can carry a
	// signature in the same Postgres transaction.
	prepared, err := s.prepareRecord(ctx, req.ShardID, recordKey, canonResp.CanonicalContent, nil, req.ParserID, req.CanonicalParserVersion)
	if err != nil {
		log.Printf("PrepareUpdate / SignRoot failed: %v", err)
		http.Error(w, "SMT prepare failed", http.StatusInternalServerError)
		return
	}

	// H-2 two-phase commit, step (b): durable Postgres write. Bounded by
	// `storageCommitTimeout` (default 10s) so we abort the prepared txn
	// well before the Rust LRU TTL (default 30s) could prune it on its own.
	storeCtx, cancel := s.withStorageTimeout(ctx)
	storeErr := s.storage.StoreLeafAndDeltas(
		storeCtx,
		prepared.deltas,
		prepared.newRoot,
		prepared.treeSize,
		prepared.signature,
		storage.LeafEntry{
			Key:                    prepared.globalKey,
			ValueHash:              prepared.leafValueHash,
			ParserID:               prepared.parserID,
			CanonicalParserVersion: prepared.canonicalPV,
		},
	)
	cancel()
	if storeErr != nil {
		// Rollback path: release the prepared transaction so the Rust LRU
		// does not fill up, and (importantly) so the live SMT root remains
		// at the prior value. This is the H-2 "Abort on storage failure"
		// branch — bestEffortAbort updates aborts_after_db_failure.
		log.Printf("Failed to store leaf and deltas (aborting prepared tx %s): %v", prepared.transactionID, storeErr)
		s.bestEffortAbort(ctx, prepared.transactionID)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// H-2 two-phase commit, step (c): atomically advance the live SMT
	// now that durable state has been persisted. NOT_FOUND or
	// FailedPrecondition here means recovery falls to startup-replay on
	// the next sequencer restart (the leaf is already in Postgres). We
	// surface a 5xx so the client knows the response root is unsafe to
	// publish even though the leaf is durable.
	if err := s.commitPrepared(ctx, prepared.transactionID); err != nil {
		log.Printf("CommitPreparedUpdate(%s) failed AFTER Postgres COMMIT — startup replay will reconcile: %v",
			prepared.transactionID, err)
		s.metrics.PreparedPending.Add(-1)
		http.Error(w, "SMT commit failed after durable write", http.StatusInternalServerError)
		return
	}

	resp := QueueLeafResponse{
		NewRoot:       fmt.Sprintf("%x", prepared.newRoot),
		GlobalKey:     fmt.Sprintf("%x", prepared.globalKey),
		LeafValueHash: fmt.Sprintf("%x", prepared.leafValueHash),
		TreeSize:      prepared.treeSize,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (s *Sequencer) handleQueueLeaves(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req QueueLeavesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if len(req.Records) == 0 {
		http.Error(w, "records must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.Records) > 1000 {
		http.Error(w, "records exceeds maximum of 1000", http.StatusBadRequest)
		return
	}

	// Validate each record
	for i, rec := range req.Records {
		if rec.ShardID == "" || len(rec.ShardID) > 128 {
			http.Error(w, fmt.Sprintf("record %d: invalid shard_id", i), http.StatusBadRequest)
			return
		}
		if rec.RecordType == "" || len(rec.RecordType) > 64 {
			http.Error(w, fmt.Sprintf("record %d: invalid record_type", i), http.StatusBadRequest)
			return
		}
		if rec.RecordID == "" || len(rec.RecordID) > 256 {
			http.Error(w, fmt.Sprintf("record %d: invalid record_id", i), http.StatusBadRequest)
			return
		}
		if len(rec.Version) > 64 {
			http.Error(w, fmt.Sprintf("record %d: invalid version", i), http.StatusBadRequest)
			return
		}
		if rec.Version != "" {
			if _, err := strconv.ParseUint(rec.Version, 10, 64); err != nil {
				http.Error(w, fmt.Sprintf("record %d: version must be empty or a base-10 unsigned integer", i), http.StatusBadRequest)
				return
			}
		}
		if len(rec.Content) == 0 {
			http.Error(w, fmt.Sprintf("record %d: content must not be empty", i), http.StatusBadRequest)
			return
		}
		if rec.ParserID == "" {
			http.Error(w, fmt.Sprintf("record %d: parser_id must not be empty (required by ADR-0003)", i), http.StatusBadRequest)
			return
		}
		if rec.CanonicalParserVersion == "" {
			http.Error(w, fmt.Sprintf("record %d: canonical_parser_version must not be empty (required by ADR-0003)", i), http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()

	// H-2 two-phase commit, batch variant.
	//
	// The pre-H-2 batch path issued N Rust Update() calls (each
	// advancing the live SMT) and ONE Postgres COMMIT at the end. Any
	// Postgres failure left the live SMT N steps ahead of durable
	// state — the failure mode the spec calls out by name as the
	// motivation for H-2 ("Batch mode amplifies this").
	//
	// The fix: process each record with the same per-record
	// `prepare → store → commit` discipline as /v1/queue-leaf. We
	// trade cross-record Postgres atomicity (records 0..i-1 stay
	// durable if record i fails) for SMT-vs-Postgres convergence
	// (the live SMT and durable state advance in lockstep).
	// Operators that need true all-or-nothing batch semantics should
	// send N individual /v1/queue-leaf requests inside their own
	// retry loop — there is no way to recover Postgres-style commit
	// atomicity across an external service without distributed
	// transactions, which is out of scope for v1.0.
	results := make([]QueueLeafResponse, 0, len(req.Records))
	var lastPrepared *preparedRecord

	for i, rec := range req.Records {
		canonResp, err := s.smtClient.Canonicalize(ctx, rec.ContentType, rec.Content)
		if err != nil {
			log.Printf("Canonicalization failed (record %d of %d, partial batch committed: %d records): %v", i+1, len(req.Records), len(results), err)
			http.Error(w, "Canonicalization failed", http.StatusInternalServerError)
			return
		}

		recordKey := &pb.RecordKey{
			RecordType: rec.RecordType,
			RecordId:   rec.RecordID,
			Version:    rec.Version,
			Metadata:   rec.Metadata,
		}

		pr, err := s.prepareRecord(ctx, rec.ShardID, recordKey, canonResp.CanonicalContent, nil, rec.ParserID, rec.CanonicalParserVersion)
		if err != nil {
			log.Printf("PrepareUpdate / SignRoot failed (record %d of %d, partial batch committed: %d records): %v", i+1, len(req.Records), len(results), err)
			http.Error(w, "SMT prepare failed", http.StatusInternalServerError)
			return
		}

		storeCtx, cancel := s.withStorageTimeout(ctx)
		storeErr := s.storage.StoreLeafAndDeltas(
			storeCtx,
			pr.deltas,
			pr.newRoot,
			pr.treeSize,
			pr.signature,
			storage.LeafEntry{
				Key:                    pr.globalKey,
				ValueHash:              pr.leafValueHash,
				ParserID:               pr.parserID,
				CanonicalParserVersion: pr.canonicalPV,
			},
		)
		cancel()
		if storeErr != nil {
			log.Printf("Storage failed (record %d of %d, aborting prepared tx %s; partial batch committed: %d records): %v",
				i+1, len(req.Records), pr.transactionID, len(results), storeErr)
			s.bestEffortAbort(ctx, pr.transactionID)
			http.Error(w, "Storage failed", http.StatusInternalServerError)
			return
		}

		if err := s.commitPrepared(ctx, pr.transactionID); err != nil {
			log.Printf("CommitPreparedUpdate(%s) failed AFTER Postgres COMMIT (record %d of %d, partial batch committed: %d records) — startup replay will reconcile: %v",
				pr.transactionID, i+1, len(req.Records), len(results), err)
			s.metrics.PreparedPending.Add(-1)
			http.Error(w, "SMT commit failed after durable write", http.StatusInternalServerError)
			return
		}

		results = append(results, QueueLeafResponse{
			NewRoot:       fmt.Sprintf("%x", pr.newRoot),
			GlobalKey:     fmt.Sprintf("%x", pr.globalKey),
			LeafValueHash: fmt.Sprintf("%x", pr.leafValueHash),
			TreeSize:      pr.treeSize,
		})
		lastPrepared = pr
	}

	if lastPrepared == nil {
		log.Printf("No records processed - this should not happen")
		http.Error(w, "No records processed", http.StatusInternalServerError)
		return
	}

	resp := QueueLeavesResponse{
		Results:   results,
		FinalRoot: fmt.Sprintf("%x", lastPrepared.newRoot),
		TreeSize:  lastPrepared.treeSize,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

// handleQueueLeafHash handles POST /v1/queue-leaf-hash.
//
// Unlike /v1/queue-leaf (which accepts raw content and delegates canonicalization
// to the Rust service), this endpoint accepts a pre-computed 32-byte value_hash
// and passes it directly to the Rust SMT Update() call as canonical_content,
// bypassing the Canonicalize() round-trip. This is the correct path when the
// Python layer (storage_layer.py) already holds a canonical content hash —
// sending a pre-hashed value as "application/octet-stream" to /v1/queue-leaf
// would be rejected by the Rust canonicalization step (H-3).
//
// parser_id and canonical_parser_version are still required (ADR-0003): they
// are bound into the leaf hash domain by the Rust service on both paths.
func (s *Sequencer) handleQueueLeafHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req QueueLeafHashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.ShardID == "" || len(req.ShardID) > 128 {
		http.Error(w, "invalid shard_id", http.StatusBadRequest)
		return
	}
	if req.RecordType == "" || len(req.RecordType) > 64 {
		http.Error(w, "invalid record_type", http.StatusBadRequest)
		return
	}
	if req.RecordID == "" || len(req.RecordID) > 256 {
		http.Error(w, "invalid record_id", http.StatusBadRequest)
		return
	}
	if len(req.Version) > 64 {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	if req.Version != "" {
		if _, err := strconv.ParseUint(req.Version, 10, 64); err != nil {
			http.Error(w, "version must be empty or a base-10 unsigned integer", http.StatusBadRequest)
			return
		}
	}
	if len(req.ValueHash) != 32 {
		http.Error(w, "value_hash must be exactly 32 bytes", http.StatusBadRequest)
		return
	}
	if req.ParserID == "" {
		http.Error(w, "parser_id must not be empty (required by ADR-0003)", http.StatusBadRequest)
		return
	}
	if req.CanonicalParserVersion == "" {
		http.Error(w, "canonical_parser_version must not be empty (required by ADR-0003)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Build the record key. The pre-computed value hash is passed to
	// prepareRecord via the dedicated `preHashedValueHash` argument so the
	// Rust service uses it as the leaf value verbatim (no second BLAKE3).
	// parser_id + canonical_parser_version are still bound into the leaf
	// hash domain on both code paths.
	recordKey := &pb.RecordKey{
		RecordType: req.RecordType,
		RecordId:   req.RecordID,
		Version:    req.Version,
		Metadata:   req.Metadata,
	}

	// H-2 two-phase commit (a): PrepareUpdate + SignRoot. No SMT mutation.
	// Pass the user's pre-computed value hash via `preHashedValueHash` so
	// the Rust service uses it verbatim. Passing it as `canonicalContent`
	// would cause Rust to BLAKE3 it again, breaking inclusion-proof
	// verification by callers that already hold the leaf value hash.
	prepared, err := s.prepareRecord(ctx, req.ShardID, recordKey, nil, req.ValueHash, req.ParserID, req.CanonicalParserVersion)
	if err != nil {
		log.Printf("PrepareUpdate / SignRoot failed (pre-hashed): %v", err)
		http.Error(w, "SMT prepare failed", http.StatusInternalServerError)
		return
	}

	// (b) durable Postgres write, bounded by storageCommitTimeout.
	storeCtx, cancel := s.withStorageTimeout(ctx)
	storeErr := s.storage.StoreLeafAndDeltas(
		storeCtx,
		prepared.deltas,
		prepared.newRoot,
		prepared.treeSize,
		prepared.signature,
		storage.LeafEntry{
			Key:                    prepared.globalKey,
			ValueHash:              prepared.leafValueHash,
			ParserID:               prepared.parserID,
			CanonicalParserVersion: prepared.canonicalPV,
		},
	)
	cancel()
	if storeErr != nil {
		log.Printf("Failed to store leaf and deltas (aborting prepared tx %s): %v", prepared.transactionID, storeErr)
		s.bestEffortAbort(ctx, prepared.transactionID)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// (c) advance live SMT.
	if err := s.commitPrepared(ctx, prepared.transactionID); err != nil {
		log.Printf("CommitPreparedUpdate(%s) failed AFTER Postgres COMMIT — startup replay will reconcile: %v",
			prepared.transactionID, err)
		s.metrics.PreparedPending.Add(-1)
		http.Error(w, "SMT commit failed after durable write", http.StatusInternalServerError)
		return
	}

	resp := QueueLeafResponse{
		NewRoot:       fmt.Sprintf("%x", prepared.newRoot),
		GlobalKey:     fmt.Sprintf("%x", prepared.globalKey),
		LeafValueHash: fmt.Sprintf("%x", prepared.leafValueHash),
		TreeSize:      prepared.treeSize,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (s *Sequencer) handleGetLatestRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Get latest root from storage
	root, treeSize, err := s.storage.GetLatestRoot(ctx)
	if err != nil {
		log.Printf("Failed to get latest root: %v", err)
		http.Error(w, "Failed to get latest root", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"root":      fmt.Sprintf("%x", root),
		"tree_size": treeSize,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (s *Sequencer) handleGetInclusionProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	shardID := r.URL.Query().Get("shard_id")
	recordType := r.URL.Query().Get("record_type")
	recordID := r.URL.Query().Get("record_id")
	version := r.URL.Query().Get("version")

	if shardID == "" || recordType == "" || recordID == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	recordKey := &pb.RecordKey{
		RecordType: recordType,
		RecordId:   recordID,
		Version:    version,
	}

	// Generate proof via Rust service
	proofResp, err := s.smtClient.ProveInclusion(ctx, shardID, recordKey, nil)
	if err != nil {
		log.Printf("Proof generation failed: %v", err)
		http.Error(w, "Proof generation failed", http.StatusInternalServerError)
		return
	}

	// Convert siblings to hex strings
	siblings := make([]string, len(proofResp.Siblings))
	for i, sib := range proofResp.Siblings {
		siblings[i] = fmt.Sprintf("%x", sib)
	}

	resp := map[string]interface{}{
		"global_key":  fmt.Sprintf("%x", proofResp.GlobalKey),
		"value_hash":  fmt.Sprintf("%x", proofResp.ValueHash),
		"siblings":    siblings,
		"root":        fmt.Sprintf("%x", proofResp.Root),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

// handleGetSignedRootPair returns the signed roots at two tree sizes for
// offline comparison.
//
// IMPORTANT: this is **not** an RFC-6962 / Trillian consistency proof. It
// does not prove that the older root is a prefix of the newer one — it
// simply returns both signed roots and lets the caller verify the
// signatures and compare the hashes. The sequencer does not currently
// produce a real consistency proof (the CD-HS-ST is a sparse Merkle tree
// and the proof shape differs from RFC 6962); see the follow-up issue
// linked from CHANGELOG.md.
//
// The old route /v1/get-consistency-proof is preserved as a deprecated
// alias that returns HTTP 410 Gone to avoid silently misleading any
// external verifier built against the old name.
func (s *Sequencer) handleGetSignedRootPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	oldSizeStr := r.URL.Query().Get("old_tree_size")
	newSizeStr := r.URL.Query().Get("new_tree_size")

	if oldSizeStr == "" || newSizeStr == "" {
		http.Error(w, "Missing required parameters: old_tree_size, new_tree_size", http.StatusBadRequest)
		return
	}

	oldSize, err := strconv.ParseUint(oldSizeStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid old_tree_size", http.StatusBadRequest)
		return
	}

	newSize, err := strconv.ParseUint(newSizeStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid new_tree_size", http.StatusBadRequest)
		return
	}

	if oldSize > newSize {
		http.Error(w, "old_tree_size cannot exceed new_tree_size", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Retrieve the signed root at the old tree size
	oldRoot, err := s.storage.GetRootByTreeSize(ctx, oldSize)
	if err != nil {
		log.Printf("Failed to get root at tree size %d: %v", oldSize, err)
		http.Error(w, "Root not found for old_tree_size", http.StatusNotFound)
		return
	}

	// Retrieve the signed root at the new tree size
	newRoot, err := s.storage.GetRootByTreeSize(ctx, newSize)
	if err != nil {
		log.Printf("Failed to get root at tree size %d: %v", newSize, err)
		http.Error(w, "Root not found for new_tree_size", http.StatusNotFound)
		return
	}

	resp := map[string]interface{}{
		"old_tree_size": oldSize,
		"new_tree_size": newSize,
		"old_root":      fmt.Sprintf("%x", oldRoot.RootHash),
		"old_signature":  fmt.Sprintf("%x", oldRoot.Signature),
		"new_root":      fmt.Sprintf("%x", newRoot.RootHash),
		"new_signature":  fmt.Sprintf("%x", newRoot.Signature),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

// handleHealthz reports liveness. It is intentionally cheap: it does not
// touch the database or the Rust SMT service, so a transient downstream
// stall does not flap the container's health state. Readiness checks (which
// do exercise dependencies) should use /v1/get-latest-root with a valid
// token.
func (s *Sequencer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		log.Printf("Failed to write healthz body: %v", err)
	}
}

// handleConsistencyProofGone returns HTTP 410 Gone for the deprecated
// /v1/get-consistency-proof route.
//
// The original handler was misnamed: it returned a pair of signed roots
// rather than an RFC-6962 consistency proof. Renaming it (rather than
// silently 301-redirecting) ensures any external verifier built against
// the misleading name fails loudly instead of receiving the same response
// under a name that overstates the cryptographic guarantee. See CHANGELOG
// "Breaking changes" for the migration path.
func (s *Sequencer) handleConsistencyProofGone(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Link", "</v1/get-signed-root-pair>; rel=\"successor-version\"")
	w.WriteHeader(http.StatusGone)
	body := map[string]string{
		"error":          "endpoint_renamed",
		"message":        "/v1/get-consistency-proof has been renamed to /v1/get-signed-root-pair. The original name was misleading: this endpoint returns a pair of signed roots for offline comparison, not an RFC-6962 consistency proof.",
		"successor":      "/v1/get-signed-root-pair",
		"removal_notice": "This deprecated alias will be removed in the next release.",
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("Failed to encode 410 Gone body: %v", err)
	}
}
