# Canonicalization Version Management

This document describes the version management system for canonicalization algorithms in Olympus, designed to prevent canonicalization drift.

## Problem Statement

Document hashing only works if identical documents produce identical canonical bytes. If canonicalization changes between versions of the software, this happens:

```
Version 1 → hash A
Version 2 → hash B
Same document.
Different hashes.
```

Now your ledger contains two entries for the same evidence. This isn't theoretical—it has happened in multiple digital archive systems.

## Solution: Version Pinning and Test Vectors

Olympus treats canonicalization like a wire protocol: **once published, it's effectively permanent**.

## Canonicalization Versions

All canonicalization versions are declared in `CANONICALIZER_VERSIONS`:

```python
from protocol.canonicalizer import CANONICALIZER_VERSIONS

# Current versions
CANONICALIZER_VERSIONS = {
    "jcs": "1.2.0-strict-numeric",
    "html": "1.0.1-lxml-pinned-nfc",
    "docx": "1.1.0-c14n-strict",
    "pdf": "1.4.0-pikepdf-10.3.0-linearized",
}
```

## Version History

All versions ever deployed are tracked in `VERSION_HISTORY`:

```python
from protocol.canonicalization_versions import VERSION_HISTORY

VERSION_HISTORY = {
    "jcs": {
        "1.2.0-strict-numeric": {
            "deployed_at": "2024-01-01T00:00:00Z",
            "deprecated_at": None,  # Still active
        },
        # Future versions would be added here
    },
    ...
}
```

## Version Validation

### Get Current Version

```python
from protocol.canonicalization_versions import get_current_version

version = get_current_version("jcs")  # Returns "1.2.0-strict-numeric"
```

### Verify Version Compatibility

```python
from protocol.canonicalization_versions import verify_version_compatibility

is_valid = verify_version_compatibility("jcs", "1.2.0-strict-numeric")  # True
is_valid = verify_version_compatibility("jcs", "999.0.0-fake")  # False
```

### Validate Canonicalization Results

```python
from protocol.canonicalization_versions import validate_canonicalization_result

result = {
    "raw_hash": "abc123",
    "canonical_hash": "def456",
    "mode": "jcs_v1",
    "version": "1.2.0-strict-numeric",
    "fallback_reason": None,
}

validate_canonicalization_result(result)  # Raises if invalid
```

## Test Vectors

Test vectors ensure canonicalization behavior remains stable across versions and implementations.

### Creating Test Vectors

```python
from protocol.canonicalization_versions import CanonicalTestVector

vector = CanonicalTestVector(
    name="jcs_basic_object",
    format_name="jcs",
    version="1.2.0-strict-numeric",
    input_bytes=b'{"b": 2, "a": 1}',
    expected_canonical_hash="d5c6475d8c876eb6cbd33ba5b6d5c97b...",
    description="Basic JCS test - key ordering",
)
```

### Verifying Test Vectors

```python
from protocol.canonicalization_versions import verify_test_vector
from protocol.canonicalizer import Canonicalizer

c = Canonicalizer()
success, message = verify_test_vector(vector, c.json_jcs)

if not success:
    print(f"CANONICALIZATION DRIFT DETECTED: {message}")
```

### Built-in Test Vectors

```python
from protocol.canonicalization_versions import (
    CANONICAL_TEST_VECTORS,
    get_test_vectors_for_format,
)

# Get all test vectors
all_vectors = CANONICAL_TEST_VECTORS

# Get test vectors for a specific format
jcs_vectors = get_test_vectors_for_format("jcs")
```

## Version Manifest

Create a manifest of all canonicalization versions for auditing:

```python
from protocol.canonicalization_versions import create_version_manifest

manifest = create_version_manifest()
# Returns:
# {
#     "current_versions": {...},
#     "version_history": {...},
# }
```

Verify a manifest:

```python
from protocol.canonicalization_versions import verify_version_manifest

is_valid = verify_version_manifest(manifest)
```

## Preventing Canonicalization Drift

### 1. Never Change Canonicalization Rules

Once a canonicalization version is deployed, its behavior must never change. If you need different behavior, create a new version.

### 2. Use Test Vectors

Add test vectors for every canonicalization version:

```python
# In tests/test_canonicalization_versions.py

def test_jcs_canonicalization_stability():
    """Ensure JCS canonicalization hasn't changed."""
    c = Canonicalizer()

    test_input = b'{"b": 2, "a": 1}'
    canonical = c.json_jcs(test_input)
    hash_output = c.get_hash(canonical).hex()

    # This hash must NEVER change
    assert hash_output == "d5c6475d8c876eb6cbd33ba5b6d5c97b..."
```

### 3. Version Bump Protocol

When you must change canonicalization behavior:

1. Create a new version identifier (e.g., `"1.3.0-new-behavior"`)
2. Add the new version to `CANONICALIZER_VERSIONS`
3. Add the old version to `VERSION_HISTORY` with a `deprecated_at` timestamp
4. Add test vectors for the new version
5. Update documentation to explain the change
6. **CRITICAL**: Old versions must remain supported for verification

### 4. Idempotency Checks

All canonicalization functions must be idempotent: `C(x) == C(C(x))`

```python
from protocol.canonicalizer import Canonicalizer

c = Canonicalizer()
input_data = b'{"test": "data"}'

canonical_once = c.json_jcs(input_data)
canonical_twice = c.json_jcs(canonical_once)

assert canonical_once == canonical_twice, "Canonicalization must be idempotent"
```

### 5. Determinism Checks

Canonicalization must be deterministic:

```python
canonical1 = c.json_jcs(input_data)
canonical2 = c.json_jcs(input_data)

assert canonical1 == canonical2, "Canonicalization must be deterministic"
```

## Production Deployment

### Pre-Deployment Checklist

Before deploying a new canonicalization version:

- [ ] All test vectors pass
- [ ] Idempotency tests pass
- [ ] Determinism tests pass
- [ ] Cross-implementation tests pass (Python, Rust, JavaScript if applicable)
- [ ] Version is added to `CANONICALIZER_VERSIONS`
- [ ] Version is added to `VERSION_HISTORY`
- [ ] Documentation is updated
- [ ] Migration plan is documented (if replacing an old version)

### Monitoring in Production

Monitor for canonicalization drift:

```python
from protocol.canonicalization_versions import (
    CANONICAL_TEST_VECTORS,
    verify_test_vector,
)
from protocol.canonicalizer import Canonicalizer

def monitor_canonicalization_health():
    """Run all test vectors and alert on failures."""
    c = Canonicalizer()
    failures = []

    for vector in CANONICAL_TEST_VECTORS:
        if vector.format_name == "jcs":
            success, message = verify_test_vector(vector, c.json_jcs)
            if not success:
                failures.append(message)
        # ... other formats

    if failures:
        # ALERT: Canonicalization drift detected!
        raise RuntimeError(f"Canonicalization drift: {failures}")
```

### Deprecation Policy

When deprecating a canonicalization version:

1. Mark it as deprecated in `VERSION_HISTORY` with a `deprecated_at` timestamp
2. Continue supporting it for verification (read-only)
3. Prevent new canonicalizations using the deprecated version
4. Provide migration tools for re-canonicalizing old documents
5. Document the deprecation reason and migration path

## Cross-Implementation Compatibility

If Olympus is implemented in multiple languages (Python, Rust, Go, etc.), all implementations must produce identical canonical bytes for the same input.

Use test vectors to verify cross-implementation compatibility:

```bash
# Python implementation
python -m pytest tests/test_canonicalization_versions.py

# Rust implementation (hypothetical)
cargo test canonicalization_vectors

# Compare outputs - they must be identical
```

## Security Rationale

Canonicalization version management mitigates:

1. **Hash Drift**: Different software versions producing different hashes for identical documents
2. **Proof Invalidation**: Historical proofs becoming invalid due to canonicalization changes
3. **Ledger Pollution**: Multiple entries for the same document with different hashes
4. **Verification Failures**: Third parties unable to verify historical commitments

## References

- RFC 8785 (JCS - JSON Canonicalization Scheme): https://tools.ietf.org/html/rfc8785
- W3C XML Canonicalization: https://www.w3.org/TR/xml-c14n/
- Olympus Canonicalization Spec: `docs/02_canonicalization.md`
