// Package client provides a Go client for the CD-HS-SMF Rust service
package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/wombatvagina69-crypto/olympus/services/sequencer/proto"
)

// CdhsSmfClient wraps the gRPC client for the Rust CD-HS-SMF service
type CdhsSmfClient struct {
	conn   *grpc.ClientConn
	client pb.CdhsSmfServiceClient
}

// NewCdhsSmfClient creates a new client connection to the Rust service
func NewCdhsSmfClient(addr string) (*CdhsSmfClient, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
func (c *CdhsSmfClient) SignRoot(ctx context.Context, root []byte, contextData map[string]string) (*pb.SignRootResponse, error) {
	req := &pb.SignRootRequest{
		Root:    root,
		Context: contextData,
	}

	resp, err := c.client.SignRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sign root failed: %w", err)
	}

	return resp, nil
}
