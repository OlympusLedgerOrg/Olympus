# CLI Verification Tool for Olympus

A standalone command-line tool for verifying Olympus commitments.

## Installation

The CLI tool is written in Python and uses the core Olympus protocol libraries.

```bash
# From the Olympus repository root
pip install -e .
```

## Usage

### Verify a BLAKE3 Hash

```bash
python verifiers/cli/verify.py blake3 --data "Hello, Olympus!" --hash <expected_hash>
```

### Compute a Merkle Root

```bash
python verifiers/cli/verify.py merkle-root --leaves file1.txt file2.txt file3.txt
```

### Verify a Merkle Proof

```bash
python verifiers/cli/verify.py merkle-proof --proof proof.json
```

### Verify a Poseidon Commitment

```bash
python verifiers/cli/verify.py poseidon --data data.bin --root <expected_root>
```

## Features

- ✅ Verify BLAKE3 hashes
- ✅ Compute and verify Merkle roots
- ✅ Verify Merkle inclusion proofs
- ✅ Verify Poseidon commitments
- ✅ Read data from files or stdin
- ✅ JSON output for scripting
- ✅ Works on Linux, macOS, and Windows

## Examples

```bash
# Verify a document hash
echo "Important document" | python verifiers/cli/verify.py blake3 --stdin --hash abc123...

# Compute Merkle root from multiple files
python verifiers/cli/verify.py merkle-root --leaves *.pdf

# Export verification result as JSON
python verifiers/cli/verify.py blake3 --data "test" --hash abc --json
```
