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

// NewCdhsSmfClient creates a new client connection to the Rust service
func NewCdhsSmfClient() (*CdhsSmfClient, error) {
	sockPath := socketPath()
	conn, err := grpc.NewClient(
		"unix://"+sockPath,
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

// Update inserts or updates a record in the global SMT
func (c *CdhsSmfClient) Update(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte) (*pb.UpdateResponse, error) {
	req := &pb.UpdateRequest{
		ShardId:          shardID,
		RecordKey:        recordKey,
		CanonicalContent: canonicalContent,
	}

	resp, err := c.client.Update(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("update failed: %w", err)
	}

	return resp, nil
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
