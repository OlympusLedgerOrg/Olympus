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

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/client"
	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// maxRequestBodyBytes caps the size of an HTTP request body for queue-leaf
// and queue-leaves. This MUST stay <= the gRPC max_decoding_message_size
// configured on the Rust CD-HS-ST service (see
// services/cdhs-smf-rust/src/main.rs::GRPC_MAX_MESSAGE_BYTES). 32 MiB is the
// agreed ceiling on both sides; see the matching constant in main.rs.
const maxRequestBodyBytes = 32 << 20 // 32 MiB

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
	smtClient *client.CdhsSmfClient
	storage   storageQuerier
	token     string
}

// NewSequencer creates a new sequencer service
func NewSequencer(smtClient *client.CdhsSmfClient, storage *storage.PostgresStorage, token string) *Sequencer {
	return &Sequencer{
		smtClient: smtClient,
		storage:   storage,
		token:     token,
	}
}

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

	// Trillian-shaped API endpoints
	mux.HandleFunc("/v1/queue-leaf", requireToken(s.token, s.handleQueueLeaf))
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

	return mux
}

// QueueLeafRequest represents a request to append a record
type QueueLeafRequest struct {
	ShardID     string            `json:"shard_id"`
	RecordType  string            `json:"record_type"`
	RecordID    string            `json:"record_id"`
	Version     string            `json:"version,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Content     []byte            `json:"content"`
	ContentType string            `json:"content_type"`
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

	ctx := r.Context()

	// Step 1: Canonicalize content via Rust service
	canonResp, err := s.smtClient.Canonicalize(ctx, req.ContentType, req.Content)
	if err != nil {
		log.Printf("Canonicalization failed: %v", err)
		http.Error(w, "Canonicalization failed", http.StatusInternalServerError)
		return
	}

	// Step 2: Update SMT via Rust service
	recordKey := &pb.RecordKey{
		RecordType: req.RecordType,
		RecordId:   req.RecordID,
		Version:    req.Version,
		Metadata:   req.Metadata,
	}

	updateResp, err := s.smtClient.Update(ctx, req.ShardID, recordKey, canonResp.CanonicalContent)
	if err != nil {
		log.Printf("SMT update failed: %v", err)
		http.Error(w, "SMT update failed", http.StatusInternalServerError)
		return
	}

	// Fix 2c: Validate returned hash lengths before storage
	if len(updateResp.NewRoot) != 32 {
		log.Printf("Rust service violated hash length contract: NewRoot length %d", len(updateResp.NewRoot))
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	if len(updateResp.GlobalKey) != 32 {
		log.Printf("Rust service violated hash length contract: GlobalKey length %d", len(updateResp.GlobalKey))
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	if len(updateResp.LeafValueHash) != 32 {
		log.Printf("Rust service violated hash length contract: LeafValueHash length %d", len(updateResp.LeafValueHash))
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Fix 2d: Validate delta count before storage
	if len(updateResp.Deltas) != 256 {
		log.Printf("Rust service returned wrong delta count: %d", len(updateResp.Deltas))
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Fix 2b: Sign the new root with tree_size from UpdateResponse
	signResp, err := s.smtClient.SignRoot(ctx, updateResp.NewRoot, updateResp.TreeSize, map[string]string{
		"shard_id":    req.ShardID,
		"record_type": req.RecordType,
		"record_id":   req.RecordID,
	})
	if err != nil {
		log.Printf("Root signing failed: %v", err)
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	// Persist all deltas + root atomically in a single transaction
	deltas := make([]storage.SmtDelta, len(updateResp.Deltas))
	for i, d := range updateResp.Deltas {
		deltas[i] = storage.SmtDelta{
			Path:  d.Path,
			Level: d.Level,
			Hash:  d.Hash,
		}
	}
	if err := s.storage.StoreLeafAndDeltas(ctx, deltas, updateResp.NewRoot, updateResp.TreeSize, signResp.Signature, storage.LeafEntry{Key: updateResp.GlobalKey, ValueHash: updateResp.LeafValueHash}); err != nil {
		log.Printf("Failed to store leaf and deltas: %v", err)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// Return response
	resp := QueueLeafResponse{
		NewRoot:       fmt.Sprintf("%x", updateResp.NewRoot),
		GlobalKey:     fmt.Sprintf("%x", updateResp.GlobalKey),
		LeafValueHash: fmt.Sprintf("%x", updateResp.LeafValueHash),
		TreeSize:      updateResp.TreeSize,
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
	}

	ctx := r.Context()

	// Process all records sequentially (SMT is stateful). The loop fails
	// fast on the first error: a 1000-record batch must never produce
	// 1000 error log lines (P-6). Each error path logs exactly one line
	// that includes the failing record's position (i+1 of N) so the
	// operator can locate the offender without per-record log spam.
	results := make([]QueueLeafResponse, 0, len(req.Records))
	batchLeaves := make([]storage.BatchLeaf, 0, len(req.Records))
	var lastUpdateResp *pb.UpdateResponse

	for i, rec := range req.Records {
		// Step 1: Canonicalize content via Rust service
		canonResp, err := s.smtClient.Canonicalize(ctx, rec.ContentType, rec.Content)
		if err != nil {
			log.Printf("Canonicalization failed (record %d of %d, aborting batch): %v", i+1, len(req.Records), err)
			http.Error(w, "Canonicalization failed", http.StatusInternalServerError)
			return
		}

		// Step 2: Update SMT via Rust service
		recordKey := &pb.RecordKey{
			RecordType: rec.RecordType,
			RecordId:   rec.RecordID,
			Version:    rec.Version,
			Metadata:   rec.Metadata,
		}

		updateResp, err := s.smtClient.Update(ctx, rec.ShardID, recordKey, canonResp.CanonicalContent)
		if err != nil {
			log.Printf("SMT update failed (record %d of %d, aborting batch): %v", i+1, len(req.Records), err)
			http.Error(w, "SMT update failed", http.StatusInternalServerError)
			return
		}

		// Validate returned hash lengths
		if len(updateResp.NewRoot) != 32 {
			log.Printf("Rust service violated hash length contract (record %d of %d): NewRoot length %d", i+1, len(req.Records), len(updateResp.NewRoot))
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if len(updateResp.GlobalKey) != 32 {
			log.Printf("Rust service violated hash length contract (record %d of %d): GlobalKey length %d", i+1, len(req.Records), len(updateResp.GlobalKey))
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if len(updateResp.LeafValueHash) != 32 {
			log.Printf("Rust service violated hash length contract (record %d of %d): LeafValueHash length %d", i+1, len(req.Records), len(updateResp.LeafValueHash))
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// Validate delta count
		if len(updateResp.Deltas) != 256 {
			log.Printf("Rust service returned wrong delta count (record %d of %d): %d", i+1, len(req.Records), len(updateResp.Deltas))
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// Collect result
		results = append(results, QueueLeafResponse{
			NewRoot:       fmt.Sprintf("%x", updateResp.NewRoot),
			GlobalKey:     fmt.Sprintf("%x", updateResp.GlobalKey),
			LeafValueHash: fmt.Sprintf("%x", updateResp.LeafValueHash),
			TreeSize:      updateResp.TreeSize,
		})

		// Collect deltas for batch storage
		deltas := make([]storage.SmtDelta, len(updateResp.Deltas))
		for j, d := range updateResp.Deltas {
			deltas[j] = storage.SmtDelta{
				Path:  d.Path,
				Level: d.Level,
				Hash:  d.Hash,
			}
		}

		// Sign this intermediate root immediately so that GetRootByTreeSize
		// can serve every tree size produced during the batch (H-3/H-7).
		signResp, err := s.smtClient.SignRoot(ctx, updateResp.NewRoot, updateResp.TreeSize, map[string]string{
			"shard_id":    rec.ShardID,
			"record_type": rec.RecordType,
			"record_id":   rec.RecordID,
		})
		if err != nil {
			log.Printf("Root signing failed (record %d of %d, aborting batch): %v", i+1, len(req.Records), err)
			http.Error(w, "Signing failed", http.StatusInternalServerError)
			return
		}

		batchLeaves = append(batchLeaves, storage.BatchLeaf{
			Leaf: storage.LeafEntry{
				Key:       updateResp.GlobalKey,
				ValueHash: updateResp.LeafValueHash,
			},
			Deltas:    deltas,
			Root:      updateResp.NewRoot,
			TreeSize:  updateResp.TreeSize,
			Signature: signResp.Signature,
		})

		lastUpdateResp = updateResp
	}

	// Safety check: should never happen since we validate len(req.Records) > 0
	if lastUpdateResp == nil {
		log.Printf("No records processed - this should not happen")
		http.Error(w, "No records processed", http.StatusInternalServerError)
		return
	}

	// Store all leaves + deltas + per-leaf roots in a single transaction
	if err := s.storage.StoreLeafAndDeltasBatch(ctx, batchLeaves); err != nil {
		log.Printf("Failed to store batch: %v", err)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// Return response
	resp := QueueLeavesResponse{
		Results:   results,
		FinalRoot: fmt.Sprintf("%x", lastUpdateResp.NewRoot),
		TreeSize:  lastUpdateResp.TreeSize,
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
