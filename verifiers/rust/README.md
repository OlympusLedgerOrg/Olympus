# Rust Verifier for Olympus

A high-performance Rust implementation for verifying Olympus commitments.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
olympus-verifier = { path = "path/to/olympus/verifiers/rust" }
blake3 = "1.5"
hex = "0.4"
```

## Usage

```rust
use olympus_verifier::{verify_blake3_hash, compute_merkle_root};

fn main() {
    // Verify a BLAKE3 hash
    let data = b"Hello, Olympus!";
    let expected_hash = "a1b2c3...";
    let is_valid = verify_blake3_hash(data, expected_hash);

    // Compute a Merkle root
    let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];
    let root = compute_merkle_root(&leaves).unwrap();
    println!("Merkle root: {}", root);
}
```

## Features

- ✅ BLAKE3 hash verification
- ✅ Merkle tree root computation
- ✅ Inclusion proof verification
- ✅ Zero-copy operations where possible
- ✅ Memory-safe and thread-safe
- ✅ High performance

## Testing

```bash
cargo test
```

## Benchmarking

```bash
cargo bench
```
