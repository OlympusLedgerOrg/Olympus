package pb

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errUnimplemented returns a gRPC Unimplemented status error for the named
// method.  Used by UnimplementedOlympusTreeServer stub methods.
func errUnimplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "method %s not implemented", method)
}
