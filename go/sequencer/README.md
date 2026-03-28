# go/sequencer — OlympusTree gRPC Sequencer (scaffold)

Trillian-shaped log sequencer for the Olympus append-only ledger.

## Status

**Phase 2 scaffold** — all RPC handlers currently return `codes.Unimplemented`.
This package establishes the compile-time gRPC contract and Unix-socket server
wiring.  Full handler implementations will be added in subsequent phases.

## Architecture

```
Python FastAPI  ──(HTTP/gRPC)──►  go/sequencer  ──(Unix socket, protobuf)──►  Rust CD-HS-SMF service
                                       │
                                       └──(SQL)──► Postgres
```

### Key principles

| Principle | Detail |
|-----------|--------|
| **Local-only** | Listens on a Unix domain socket; MUST NOT be exposed on a TCP port or to external networks. |
| **No hash computation** | Go never computes Merkle hashes.  All SMT operations — key derivation, leaf hashing, node updates, root computation, proof generation — are delegated to the Rust service via `proto/cdhs_smf.proto`. |
| **Single global tree** | The SMT is one global 256-level tree (CD-HS-SMF).  There are no per-shard trees and no separate forest tree. |
| **Protobuf on the wire** | All Go↔Rust communication uses protobuf (see `../../proto/`).  No JSON on internal boundaries. |

## Service API (`proto/olympus.proto`)

| RPC | Description |
|-----|-------------|
| `BatchUpdate` | Append one or more records atomically; delegate hash/key computation to Rust; persist node deltas. |
| `ProveInclusion` | Return a 256-sibling Merkle inclusion proof for a committed record. |
| `ProveNonInclusion` | Return a non-inclusion proof for a key that is absent from the tree. |
| `GetRoot` | Return the latest Ed25519-signed root hash and tree size. |

## Building

```bash
cd go/sequencer
go build ./...
```

## Running

```bash
# Default socket path
./sequencer

# Custom socket path
./sequencer --socket /tmp/olympus-sequencer.sock
```

The Rust CD-HS-SMF service (see `services/cdhs-smf-rust/`) must be running
before the sequencer can process any requests.

## Directory layout

```
go/sequencer/
├── cmd/sequencer/main.go        # Entry point; Unix-socket gRPC server
├── internal/server/server.go    # OlympusTreeServer stub implementation
├── proto/
│   ├── olympus_tree.go          # Hand-written gRPC stubs (replace with protoc output)
│   └── errors.go                # Shared error helpers
├── go.mod
└── README.md
```

## Generating protobuf code

Once `protoc` is available in CI:

```bash
protoc \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  -I ../../proto ../../proto/olympus.proto
```

Delete `proto/olympus_tree.go` and `proto/errors.go` and commit the generated
files in their place.
