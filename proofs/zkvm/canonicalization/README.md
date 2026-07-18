# Olympus canonicalization zkVM guest

This RISC Zero guest executes the canonical Rust implementation
`olympus_crypto::canonical::canonicalize_bytes` over private source JSON and
publishes only the fixed-width `OLYCAN01` claim defined in
`olympus_crypto::canonical_proof`.

The committed ELF is built with pinned RISC Zero `3.0.5` tooling and a running
Docker daemon. The script also pins the `risczero/risc0-guest-builder` image to
`r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3`
and stages the combined user-and-kernel `.bin` bytes that correspond to the
reported image ID:

```bash
bash proofs/zkvm/build_canonicalization_guest.sh
```

The desktop verifier computes the RISC Zero image ID from the committed ELF and
requires an exact match with the committed lowercase-hex `.id`; it never accepts
an image identifier supplied by the caller. Production startup exits instead
of serving with a placeholder or mismatched artifact. Builds compile RISC
Zero's `disable-dev-mode` feature so fake receipts cannot verify.

Native Windows receipt verification is supported. RISC Zero does not
officially provide native Windows proving tooling; proof generation therefore
runs on Linux/WSL2 via the explicit `zkvm-prover` feature and is never silently
delegated to a network service.
