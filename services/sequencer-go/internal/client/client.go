// Package client provides a Go client for the CD-HS-ST Rust service
package client

import (
	"context"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"

	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

const defaultSocketPath = "/run/olympus/cdhs-smf.sock"

// CdhsSmfClient wraps the gRPC client for the Rust CD-HS-ST service
type CdhsSmfClient struct {
	conn   *grpc.ClientConn
	client pb.CdhsSmfServiceClient
}

func socketPath() string {
	path := os.Getenv("CDHS_SMF_SOCKET")
	if path == "" {
		return defaultSocketPath
	}
	return path
}

// NewCdhsSmfClient creates a new client connection to the Rust service.
//
// The gRPC target is intentionally `passthrough:///` rather than
// `unix://` + sockPath. Two reasons:
//
//  1. We supply a WithContextDialer below that ignores the resolved address
//     and dials sockPath directly. The target is therefore only used for
//     resolver registration and channel naming — its content does not
//     affect the actual transport.
//  2. The unix:// resolver feeds sockPath through net/url parsing rules.
//     On Windows, sockPath is something like `C:\Users\…\cdhs-smf.sock`,
//     and `unix://C:\Users\…` trips "too many colons in address" because
//     the parser treats `C` as a host and the trailing `\…sock` as a port.
//     The `passthrough` resolver does no URL parsing and works on every
//     OS the rest of the codebase supports.
func NewCdhsSmfClient() (*CdhsSmfClient, error) {
	sockPath := socketPath()
	conn, err := grpc.NewClient(
		"passthrough:///cdhs-smf",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", sockPath)
		}),
		grpc.WithTransportCredentials(local.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return &CdhsSmfClient{
		conn:   conn,
		client: pb.NewCdhsSmfServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection
func (c *CdhsSmfClient) Close() error {
	return c.conn.Close()
}

// Update inserts or updates a record in the global SMT.
//
// parserID and canonicalParserVersion are ADR-0003 parser-provenance fields
// bound into the leaf hash domain by the Rust service. Both must be non-empty;
// the Rust service rejects empty strings with an error.
//
// DEPRECATED for write paths that require crash safety: this method calls
// the single-phase Update RPC, which mutates the in-memory SMT immediately,
// before any external storage durability step. New code SHOULD use
// PrepareUpdate + CommitPreparedUpdate (with an Abort on failure) so that
// durable Postgres state and live SMT state cannot diverge on storage
// failure (H-2).
func (c *CdhsSmfClient) Update(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, parserID string, canonicalParserVersion string) (*pb.UpdateResponse, error) {
	req := &pb.UpdateRequest{
		ShardId:                shardID,
		RecordKey:              recordKey,
		CanonicalContent:       canonicalContent,
		ParserId:               parserID,
		CanonicalParserVersion: canonicalParserVersion,
	}

	resp, err := c.client.Update(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("update failed: %w", err)
	}

	return resp, nil
}

// PrepareUpdate is phase 1 of the two-phase commit between the Rust SMT and
// the sequencer's Postgres layer (H-2). It returns a transaction_id that must
// later be passed to either CommitPreparedUpdate (after the durable storage
// write succeeds) or AbortPreparedUpdate (on any failure).
//
// A successful PrepareUpdate does NOT mutate the live in-memory SMT — the
// new root and deltas it returns reflect what the SMT *will* hold after the
// matching CommitPreparedUpdate runs.
func (c *CdhsSmfClient) PrepareUpdate(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, parserID string, canonicalParserVersion string) (*pb.PrepareUpdateResponse, error) {
	req := &pb.PrepareUpdateRequest{
		ShardId:                shardID,
		RecordKey:              recordKey,
		CanonicalContent:       canonicalContent,
		ParserId:               parserID,
		CanonicalParserVersion: canonicalParserVersion,
	}

	resp, err := c.client.PrepareUpdate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("prepare update failed: %w", err)
	}

	return resp, nil
}

// CommitPreparedUpdate is phase 2 of the two-phase commit (H-2). It atomically
// applies a previously prepared update to the live SMT. Callers MUST only
// invoke this after the corresponding Postgres COMMIT has succeeded; on any
// upstream failure they MUST call AbortPreparedUpdate instead.
//
// Returns a NotFound gRPC error if the transaction id is unknown (already
// committed, aborted, or TTL-evicted). Returns FailedPrecondition if another
// commit advanced the SMT root since the prepare; the caller should then
// Abort and re-prepare.
func (c *CdhsSmfClient) CommitPreparedUpdate(ctx context.Context, transactionID string) (*pb.CommitPreparedUpdateResponse, error) {
	req := &pb.CommitPreparedUpdateRequest{TransactionId: transactionID}

	resp, err := c.client.CommitPreparedUpdate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("commit prepared update failed: %w", err)
	}

	return resp, nil
}

// AbortPreparedUpdate discards a prepared transaction. Idempotent: returns
// nil whether or not the transaction is currently in the prepared store.
// Callers MUST invoke this on any failure path between PrepareUpdate and
// CommitPreparedUpdate so the prepared LRU does not fill up with abandoned
// entries.
func (c *CdhsSmfClient) AbortPreparedUpdate(ctx context.Context, transactionID string) error {
	req := &pb.AbortPreparedUpdateRequest{TransactionId: transactionID}

	if _, err := c.client.AbortPreparedUpdate(ctx, req); err != nil {
		return fmt.Errorf("abort prepared update failed: %w", err)
	}
	return nil
}

// ProveInclusion generates a cryptographic inclusion proof
func (c *CdhsSmfClient) ProveInclusion(ctx context.Context, shardID string, recordKey *pb.RecordKey, root []byte) (*pb.ProveInclusionResponse, error) {
	req := &pb.ProveInclusionRequest{
		ShardId:   shardID,
		RecordKey: recordKey,
		Root:      root,
	}

	resp, err := c.client.ProveInclusion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("prove inclusion failed: %w", err)
	}

	return resp, nil
}

// ProveNonInclusion generates a cryptographic non-inclusion proof
func (c *CdhsSmfClient) ProveNonInclusion(ctx context.Context, shardID string, recordKey *pb.RecordKey, root []byte) (*pb.ProveNonInclusionResponse, error) {
	req := &pb.ProveNonInclusionRequest{
		ShardId:   shardID,
		RecordKey: recordKey,
		Root:      root,
	}

	resp, err := c.client.ProveNonInclusion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("prove non-inclusion failed: %w", err)
	}

	return resp, nil
}

// GetRoot retrieves the current root hash
func (c *CdhsSmfClient) GetRoot(ctx context.Context) (*pb.GetRootResponse, error) {
	req := &pb.GetRootRequest{}

	resp, err := c.client.GetRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get root failed: %w", err)
	}

	return resp, nil
}

// Canonicalize canonicalizes content via the Rust service
func (c *CdhsSmfClient) Canonicalize(ctx context.Context, contentType string, content []byte) (*pb.CanonicalizeResponse, error) {
	req := &pb.CanonicalizeRequest{
		ContentType: contentType,
		Content:     content,
	}

	resp, err := c.client.Canonicalize(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("canonicalize failed: %w", err)
	}

	return resp, nil
}

// SignRoot signs a root hash with Ed25519
func (c *CdhsSmfClient) SignRoot(ctx context.Context, root []byte, treeSize uint64, contextData map[string]string) (*pb.SignRootResponse, error) {
	req := &pb.SignRootRequest{
		Root:     root,
		TreeSize: treeSize,
		Context:  contextData,
	}

	resp, err := c.client.SignRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sign root failed: %w", err)
	}

	return resp, nil
}

// ReplayLeaves replays a sequence of persisted (key, value_hash) leaf pairs
// into the Rust service's in-memory SMT and returns the resulting root hash.
func (c *CdhsSmfClient) ReplayLeaves(ctx context.Context, leaves []*pb.LeafEntry) (*pb.ReplayResponse, error) {
	req := &pb.ReplayRequest{
		Leaves: leaves,
	}

	resp, err := c.client.ReplayLeaves(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("replay leaves failed: %w", err)
	}

	return resp, nil
}
