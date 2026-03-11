package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	verifier "github.com/olympus/verifiers/go"
)

type hashBatchRequest struct {
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

	hashes := make([]string, len(req.RecordsB64))
	for i, recordB64 := range req.RecordsB64 {
		record, err := base64.StdEncoding.DecodeString(recordB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid base64 at index %d: %v\n", i, err)
			os.Exit(1)
		}
		hashes[i] = fmt.Sprintf("%x", verifier.ComputeBlake3(record))
	}

	out, err := json.Marshal(hashBatchResponse{Hashes: hashes})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal response JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
