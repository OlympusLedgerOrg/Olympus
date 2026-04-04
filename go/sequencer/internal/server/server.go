// Package server implements the OlympusTree gRPC service.
//
// All handlers currently return codes.Unimplemented.  The package is
// intentionally kept as a thin scaffold so that the compile-time contract is
// established before the handlers are wired to the Rust CD-HS-ST service.
//
// Responsibilities (to be implemented in later phases):
//   - BatchUpdate: batch appends → delegate key/hash derivation to Rust service
//     over the cdhs_smf.proto socket API; persist SMT node deltas to Postgres.
//   - ProveInclusion / ProveNonInclusion: forward to Rust service and return proof.
//   - GetRoot: return the latest signed root (from Postgres or Rust service).
//
// This service listens on a **Unix domain socket** only.  It MUST NOT be
// exposed on a TCP port or to external networks.
package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wombatvagina69-crypto/olympus/go/sequencer/proto"
)

// SequencerServer implements pb.OlympusTreeServer.
type SequencerServer struct {
	pb.UnimplementedOlympusTreeServer
}

// NewSequencerServer returns a new SequencerServer.
func NewSequencerServer() *SequencerServer {
	return &SequencerServer{}
}

// BatchUpdate appends one or more records to the global SMT.
//
// Stub: returns Unimplemented until the Rust CD-HS-ST client is wired up.
func (s *SequencerServer) BatchUpdate(
	_ context.Context, _ *pb.BatchUpdateRequest,
) (*pb.BatchUpdateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "BatchUpdate not yet implemented")
}

// ProveInclusion returns a Merkle inclusion proof for a committed record.
//
// Stub: returns Unimplemented until the Rust CD-HS-ST client is wired up.
func (s *SequencerServer) ProveInclusion(
	_ context.Context, _ *pb.ProveInclusionRequest,
) (*pb.ProveInclusionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ProveInclusion not yet implemented")
}

// ProveNonInclusion returns a Merkle non-inclusion proof for a record.
//
// Stub: returns Unimplemented until the Rust CD-HS-ST client is wired up.
func (s *SequencerServer) ProveNonInclusion(
	_ context.Context, _ *pb.ProveNonInclusionRequest,
) (*pb.ProveNonInclusionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ProveNonInclusion not yet implemented")
}

// GetRoot returns the current signed root of the global SMT.
//
// Stub: returns Unimplemented until the Rust CD-HS-ST client is wired up.
func (s *SequencerServer) GetRoot(
	_ context.Context, _ *pb.GetRootRequest,
) (*pb.GetRootResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetRoot not yet implemented")
}
