# Sample Redaction Directory

This directory contains sample redacted documents and their proofs for testing
the Olympus redaction protocol.

## Contents

Examples demonstrating:
- Original committed documents
- Redacted versions
- Zero-knowledge proofs of valid redaction
- Verification workflows

## Usage

```bash
# Verify a redaction proof
python tools/verify_cli.py redaction proof.json content.json
```

## Example Files

### Original Document (`original.json`)
```json
{
  "parts": [
    "Public information part 1",
    "Sensitive information (to be redacted)",
    "Public information part 2"
  ]
}
```

### Redacted Document (`redacted.json`)
```json
{
  "revealed_content": [
    "Public information part 1",
    "Public information part 2"
  ]
}
```

### Proof (`proof.json`)
```json
{
  "original_root": "abc123...",
  "revealed_indices": [0, 2],
  "revealed_hashes": ["def456...", "ghi789..."],
  "merkle_proofs": [...]
}
```

## Testing Workflow

1. Create original document
2. Commit to ledger (generates Merkle tree and root)
3. Create redacted version (select parts to reveal)
4. Generate zero-knowledge proof
5. Verify proof shows redacted version is valid subset
