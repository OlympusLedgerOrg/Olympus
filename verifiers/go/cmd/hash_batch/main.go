package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	verifier "github.com/OlympusLedgerOrg/Olympus/verifiers/go"
)

type hashBatchRequest struct {
	Op         string   `json:"op"`
	RecordsB64 []string `json:"records_b64"`
}

type hashBatchResponse struct {
	Hashes []string `json:"hashes"`
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	var req hashBatchRequest
	if err := json.Unmarshal(input, &req); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse request JSON: %v\n", err)
		os.Exit(1)
	}

	// Default to "blake3" for backward compatibility
	op := req.Op
	if op == "" {
		op = "blake3"
	}

	var hashes []string

	switch op {
	case "blake3":
		hashes = make([]string, len(req.RecordsB64))
		for i, recordB64 := range req.RecordsB64 {
			record, err := base64.StdEncoding.DecodeString(recordB64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid base64 at index %d: %v\n", i, err)
				os.Exit(1)
			}
			hashes[i] = fmt.Sprintf("%x", verifier.ComputeBlake3(record))
		}

	case "merkle_leaf_hash":
		hashes = make([]string, len(req.RecordsB64))
		for i, recordB64 := range req.RecordsB64 {
			record, err := base64.StdEncoding.DecodeString(recordB64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid base64 at index %d: %v\n", i, err)
				os.Exit(1)
			}
			hashes[i] = fmt.Sprintf("%x", verifier.MerkleLeafHash(record))
		}

	case "merkle_root":
		// All records_b64 are leaves of a single tree
		leaves := make([][]byte, len(req.RecordsB64))
		for i, recordB64 := range req.RecordsB64 {
			record, err := base64.StdEncoding.DecodeString(recordB64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid base64 at index %d: %v\n", i, err)
				os.Exit(1)
			}
			leaves[i] = record
		}
		root, err := verifier.ComputeMerkleRoot(leaves)
		if err != nil {
			fmt.Fprintf(os.Stderr, "merkle_root failed: %v\n", err)
			os.Exit(1)
		}
		hashes = []string{root}

	default:
		fmt.Fprintf(os.Stderr, "unknown op: %s\n", op)
		os.Exit(1)
	}

	out, err := json.Marshal(hashBatchResponse{Hashes: hashes})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal response JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
