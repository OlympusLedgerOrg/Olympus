package main

import (
	"fmt"
	"os"

	verifier "github.com/OlympusLedgerOrg/Olympus/verifiers/go"
)

func main() {
if len(os.Args) != 2 {
fmt.Fprintln(os.Stderr, "usage: verify_witness <vector_path>")
os.Exit(2)
}
raw, err := os.ReadFile(os.Args[1])
if err != nil {
fmt.Fprintln(os.Stderr, err)
os.Exit(1)
}
if err := verifier.VerifyWitnessEnvelopeJSON(raw); err != nil {
fmt.Fprintln(os.Stderr, err)
os.Exit(1)
}
}
