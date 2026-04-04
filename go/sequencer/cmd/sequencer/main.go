// Command sequencer starts the OlympusTree gRPC service on a Unix domain socket.
//
// Usage:
//
//	sequencer [--socket PATH]
//
// Flags:
//
//	--socket PATH   Path for the Unix domain socket (default: /run/olympus/sequencer.sock)
//
// The server is strictly local-only: it binds to a Unix domain socket and
// MUST NOT be exposed on a TCP port or to external networks.
//
// # Intended responsibilities (future phases)
//
//   - BatchUpdate: receive canonicalised records, delegate key/hash derivation
//     to the Rust CD-HS-ST service over its cdhs_smf.proto socket, persist
//     SMT node deltas to Postgres, return the new signed root.
//   - ProveInclusion / ProveNonInclusion: forward to Rust service, relay proof.
//   - GetRoot: return the latest committed signed root.
//
// All cryptographic operations are delegated to the Rust service.  The Go
// sequencer NEVER computes Merkle hashes itself.
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/wombatvagina69-crypto/olympus/go/sequencer/internal/server"
	pb "github.com/wombatvagina69-crypto/olympus/go/sequencer/proto"
)

func main() {
	socketPath := flag.String(
		"socket",
		"/run/olympus/sequencer.sock",
		"Unix domain socket path for the OlympusTree gRPC service",
	)
	flag.Parse()

	// Remove any stale socket file so we can bind cleanly.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove stale socket %s: %v", *socketPath, err)
	}

	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("failed to listen on unix://%s: %v", *socketPath, err)
	}
	log.Printf("OlympusTree sequencer listening on unix://%s", *socketPath)

	grpcServer := grpc.NewServer()
	pb.RegisterOlympusTreeServer(grpcServer, server.NewSequencerServer())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("sequencer server failed: %v", err)
	}
}
