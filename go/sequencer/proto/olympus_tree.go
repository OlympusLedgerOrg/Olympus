// Package pb contains hand-written stub types for the OlympusTree service
// defined in proto/olympus.proto.
//
// These stubs are intentionally minimal — they exist so that cmd/sequencer
// and internal/server compile without requiring protoc or a generated-code
// dependency.  Replace this file with generated code once protoc is added to
// the CI toolchain:
//
//	protoc --go_out=. --go_opt=paths=source_relative \
//	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
//	       -I ../../proto ../../proto/olympus.proto
package pb

import (
	"context"

	"google.golang.org/grpc"
)

// ---------------------------------------------------------------------------
// Server-side interface
// ---------------------------------------------------------------------------

// OlympusTreeServer is the server-side interface for the OlympusTree gRPC
// service.  Embed UnimplementedOlympusTreeServer to satisfy forward
// compatibility.
type OlympusTreeServer interface {
	BatchUpdate(context.Context, *BatchUpdateRequest) (*BatchUpdateResponse, error)
	ProveInclusion(context.Context, *ProveInclusionRequest) (*ProveInclusionResponse, error)
	ProveNonInclusion(context.Context, *ProveNonInclusionRequest) (*ProveNonInclusionResponse, error)
	GetRoot(context.Context, *GetRootRequest) (*GetRootResponse, error)
	mustEmbedUnimplementedOlympusTreeServer()
}

// UnimplementedOlympusTreeServer must be embedded to have forward-compatible
// implementations.  All methods return codes.Unimplemented by default.
type UnimplementedOlympusTreeServer struct{}

func (UnimplementedOlympusTreeServer) BatchUpdate(
	_ context.Context, _ *BatchUpdateRequest,
) (*BatchUpdateResponse, error) {
	return nil, errUnimplemented("BatchUpdate")
}

func (UnimplementedOlympusTreeServer) ProveInclusion(
	_ context.Context, _ *ProveInclusionRequest,
) (*ProveInclusionResponse, error) {
	return nil, errUnimplemented("ProveInclusion")
}

func (UnimplementedOlympusTreeServer) ProveNonInclusion(
	_ context.Context, _ *ProveNonInclusionRequest,
) (*ProveNonInclusionResponse, error) {
	return nil, errUnimplemented("ProveNonInclusion")
}

func (UnimplementedOlympusTreeServer) GetRoot(
	_ context.Context, _ *GetRootRequest,
) (*GetRootResponse, error) {
	return nil, errUnimplemented("GetRoot")
}

func (UnimplementedOlympusTreeServer) mustEmbedUnimplementedOlympusTreeServer() {}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

const _OlympusTree_ServiceDesc_ServiceName = "olympus.sequencer.v1.OlympusTree"

// RegisterOlympusTreeServer registers srv with the given gRPC server.
func RegisterOlympusTreeServer(s *grpc.Server, srv OlympusTreeServer) {
	s.RegisterService(&_OlympusTree_serviceDesc, srv)
}

var _OlympusTree_serviceDesc = grpc.ServiceDesc{
	ServiceName: _OlympusTree_ServiceDesc_ServiceName,
	HandlerType: (*OlympusTreeServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "BatchUpdate",
			Handler:    _OlympusTree_BatchUpdate_Handler,
		},
		{
			MethodName: "ProveInclusion",
			Handler:    _OlympusTree_ProveInclusion_Handler,
		},
		{
			MethodName: "ProveNonInclusion",
			Handler:    _OlympusTree_ProveNonInclusion_Handler,
		},
		{
			MethodName: "GetRoot",
			Handler:    _OlympusTree_GetRoot_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "olympus.proto",
}

func _OlympusTree_BatchUpdate_Handler(
	srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := new(BatchUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	return srv.(OlympusTreeServer).BatchUpdate(ctx, in)
}

func _OlympusTree_ProveInclusion_Handler(
	srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := new(ProveInclusionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	return srv.(OlympusTreeServer).ProveInclusion(ctx, in)
}

func _OlympusTree_ProveNonInclusion_Handler(
	srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := new(ProveNonInclusionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	return srv.(OlympusTreeServer).ProveNonInclusion(ctx, in)
}

func _OlympusTree_GetRoot_Handler(
	srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := new(GetRootRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	return srv.(OlympusTreeServer).GetRoot(ctx, in)
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

// BatchUpdateRequest requests appending one or more records.
type BatchUpdateRequest struct {
	Records []*LeafRecord
}

// LeafRecord is a single record to be appended.
type LeafRecord struct {
	ShardID          string
	RecordKey        *RecordKey
	CanonicalContent []byte
}

// RecordKey identifies a record.
type RecordKey struct {
	RecordType string
	RecordID   string
	Version    uint64
}

// BatchUpdateResponse is returned by BatchUpdate.
type BatchUpdateResponse struct {
	NewRoot   []byte
	Signature []byte
	PublicKey []byte
	Results   []*LeafResult
}

// LeafResult holds the per-record outcome of a BatchUpdate.
type LeafResult struct {
	GlobalKey      []byte
	ValueHash      []byte
	SequenceNumber uint64
}

// ProveInclusionRequest requests an inclusion proof.
type ProveInclusionRequest struct {
	ShardID   string
	RecordKey *RecordKey
	Root      []byte
}

// ProveInclusionResponse holds an inclusion proof.
type ProveInclusionResponse struct {
	GlobalKey []byte
	ValueHash []byte
	Siblings  [][]byte
	Root      []byte
}

// ProveNonInclusionRequest requests a non-inclusion proof.
type ProveNonInclusionRequest struct {
	ShardID   string
	RecordKey *RecordKey
	Root      []byte
}

// ProveNonInclusionResponse holds a non-inclusion proof.
type ProveNonInclusionResponse struct {
	GlobalKey []byte
	Siblings  [][]byte
	Root      []byte
}

// GetRootRequest has no parameters.
type GetRootRequest struct{}

// GetRootResponse holds the latest signed root.
type GetRootResponse struct {
	Root      []byte
	TreeSize  uint64
	Signature []byte
	PublicKey []byte
}
