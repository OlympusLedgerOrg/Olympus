// Package api provides the Trillian-shaped log service API
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/client"
	"github.com/wombatvagina69-crypto/olympus/services/sequencer/internal/storage"
	pb "github.com/wombatvagina69-crypto/olympus/services/sequencer/proto"
)

// Sequencer provides a Trillian-shaped log service API
type Sequencer struct {
	smtClient *client.CdhsSmfClient
	storage   *storage.PostgresStorage
}

// NewSequencer creates a new sequencer service
func NewSequencer(smtClient *client.CdhsSmfClient, storage *storage.PostgresStorage) *Sequencer {
	return &Sequencer{
		smtClient: smtClient,
		storage:   storage,
	}
}

// Handler returns an HTTP handler for the sequencer API
func (s *Sequencer) Handler() http.Handler {
	mux := http.NewServeMux()

	// Trillian-shaped API endpoints
	mux.HandleFunc("/v1/queue-leaf", s.handleQueueLeaf)
	mux.HandleFunc("/v1/get-latest-root", s.handleGetLatestRoot)
	mux.HandleFunc("/v1/get-inclusion-proof", s.handleGetInclusionProof)
	mux.HandleFunc("/v1/get-consistency-proof", s.handleGetConsistencyProof)

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

	var req QueueLeafRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
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

	// Step 3: Persist deltas and root to Postgres
	for _, delta := range updateResp.Deltas {
		if err := s.storage.StoreNodeDelta(ctx, delta.Path, delta.Level, delta.Hash); err != nil {
			log.Printf("Failed to store node delta: %v", err)
			http.Error(w, "Storage failed", http.StatusInternalServerError)
			return
		}
	}

	// Step 4: Sign the new root
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

	// Step 5: Get current tree size
	rootResp, err := s.smtClient.GetRoot(ctx)
	if err != nil {
		log.Printf("Get root failed: %v", err)
		http.Error(w, "Get root failed", http.StatusInternalServerError)
		return
	}

	// Step 6: Store the signed root
	if err := s.storage.StoreRoot(ctx, updateResp.NewRoot, rootResp.TreeSize, signResp.Signature); err != nil {
		log.Printf("Failed to store root: %v", err)
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
	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(resp)
}

func (s *Sequencer) handleGetConsistencyProof(w http.ResponseWriter, r *http.Request) {
	// Consistency proofs are not yet implemented (Phase 1+)
	http.Error(w, "Consistency proofs not yet supported", http.StatusNotImplemented)
}
