# Go Verifier for Olympus

A standalone Go implementation for verifying Olympus commitments.

## Installation

```bash
go get github.com/zeebo/blake3
```

## Usage

```go
package main

import (
    "fmt"
    verifier "path/to/olympus/verifiers/go"
)

func main() {
    // Verify a BLAKE3 hash
    data := []byte("Hello, Olympus!")
    expectedHash := "a1b2c3..."
    isValid := verifier.VerifyBlake3Hash(data, expectedHash)

    // Compute a Merkle root
    leaves := [][]byte{
        []byte("leaf1"),
        []byte("leaf2"),
    }
    root := verifier.ComputeMerkleRoot(leaves)
    fmt.Printf("Merkle root: %s\n", root)
}
```

## Features

- ✅ BLAKE3 hash verification
- ✅ Merkle tree root computation
- ✅ Inclusion proof verification
- ✅ Fast and memory-efficient
- ✅ Standard Go library conventions

## API Reference

See `verifier.go` for full documentation.

## Testing

```bash
go test -v
```
