// Package api provides the Trillian-shaped log service API
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/client"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/storage"
	pb "github.com/wombatvagina69-crypto/olympus/services/sequencer/proto"
)

// Sequencer provides a Trillian-shaped log service API
type Sequencer struct {
	smtClient *client.CdhsSmfClient
	storage   *storage.PostgresStorage
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
	mux.HandleFunc("/v1/get-latest-root", requireToken(s.token, s.handleGetLatestRoot))
	mux.HandleFunc("/v1/get-inclusion-proof", requireToken(s.token, s.handleGetInclusionProof))
	mux.HandleFunc("/v1/get-consistency-proof", requireToken(s.token, s.handleGetConsistencyProof))

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
	NewRoot      string `json:"new_root"`
	GlobalKey    string `json:"global_key"`
	LeafValueHash string `json:"leaf_value_hash"`
	TreeSize     uint64 `json:"tree_size"`
}

func (s *Sequencer) handleQueueLeaf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<20) // 32 MB

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

	// Step 3: Sign the new root
	signResp, err := s.smtClient.SignRoot(ctx, updateResp.NewRoot, map[string]string{
		"shard_id":    req.ShardID,
		"record_type": req.RecordType,
		"record_id":   req.RecordID,
	})
	if err != nil {
		log.Printf("Root signing failed: %v", err)
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	// Step 4: Get current tree size
	rootResp, err := s.smtClient.GetRoot(ctx)
	if err != nil {
		log.Printf("Get root failed: %v", err)
		http.Error(w, "Get root failed", http.StatusInternalServerError)
		return
	}

	// Step 5: Persist all deltas + root atomically in a single transaction
	deltas := make([]storage.SmtDelta, len(updateResp.Deltas))
	for i, d := range updateResp.Deltas {
		deltas[i] = storage.SmtDelta{
			Path:  d.Path,
			Level: d.Level,
			Hash:  d.Hash,
		}
	}
	if err := s.storage.StoreLeafAndDeltas(ctx, deltas, updateResp.NewRoot, rootResp.TreeSize, signResp.Signature); err != nil {
		log.Printf("Failed to store leaf and deltas: %v", err)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// Return response
	resp := QueueLeafResponse{
		NewRoot:      fmt.Sprintf("%x", updateResp.NewRoot),
		GlobalKey:    fmt.Sprintf("%x", updateResp.GlobalKey),
		LeafValueHash: fmt.Sprintf("%x", updateResp.LeafValueHash),
		TreeSize:     rootResp.TreeSize,
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

func (s *Sequencer) handleGetConsistencyProof(w http.ResponseWriter, r *http.Request) {
	// Consistency proofs are not yet implemented (Phase 1+)
	http.Error(w, "Consistency proofs not yet supported", http.StatusNotImplemented)
}
