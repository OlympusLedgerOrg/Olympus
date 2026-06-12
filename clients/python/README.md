# olympus-manifest (Python SDK)

A pip-installable client for **Olympus dataset manifests** (ADR-0027). Verify
record **inclusion / exclusion** proofs offline, hash shards, build a record
index, and talk to an Olympus node — from inside a Python data pipeline.

The cryptographic commitment (`manifest_root`) is produced by the Rust
`olympus` CLI / `olympus-manifest` crate — the source of truth. This package
**re-verifies** it byte-for-byte (the same verify-only split as the JavaScript
verifier); `tests/test_parity.py` pins every primitive and a real proof bundle
against vectors generated from the Rust crate.

## Install

```bash
pip install olympus-manifest            # verification + local hashing
pip install 'olympus-manifest[http]'    # + commit/fetch against a node
```

## Verify a proof (the auditor path)

```python
import json
from olympus_manifest import verify

bundle   = json.load(open("proof.json"))     # produced by `olympus prove`
manifest = json.load(open("manifest.json"))  # the anchored manifest document

verdict = verify(bundle, bytes.fromhex(manifest["manifest_root"]))
assert verdict.is_valid, verdict.value
print(bundle["kind"], "verified for", bundle["record_id"])
```

`verify` re-derives the tree key from the bundle's `(shard_id, record_id,
version)` and checks it against the proof — so a valid proof for one record
cannot be relabelled as another — then folds the SMT path to `manifest_root`.
Returned `Verdict` values: `VALID`, `ROOT_MISMATCH`, `KEY_MISMATCH`,
`CONTENT_MISMATCH`, `KIND_MISMATCH`, `SMT_INVALID`.

## Build an index / commit / pull (the pipeline path)

```python
from olympus_manifest import scan, OlympusClient

# Hash a dataset directory into a record index (round-trips with the Rust CLI).
index = scan("./dataset", shard_from_subdir=True)

# Anchor a manifest's root and pull a committed blob's ledger proof.
client = OlympusClient("https://node.example", api_key="…")  # needs [http]
resp = client.commit("manifest.json", shard="files")
proof = client.fetch_proof(resp["content_hash"])
```

> Producing the `manifest_root` itself is done by the Rust `olympus build`
> (the path-compressed SMT builder lives there). Hand the resulting
> `manifest.json` to this SDK to verify, or use `scan()` to prepare the index
> the Rust CLI seals.

## Command line

```bash
olympus-py verify --proof proof.json --manifest manifest.json
olympus-py hash file.bin
olympus-py scan --data ./dataset --shard-from-subdir --out index.json
olympus-py fetch  --server https://node.example --hash <content_hash>   # [http]
olympus-py commit --manifest manifest.json --server https://node.example  # [http]
```

## Develop / test

```bash
# Regenerate parity vectors from the Rust source of truth after any crypto change:
cargo run -p olympus-manifest --example gen_python_vectors > clients/python/tests/vectors.json

cd clients/python
pip install -e '.[dev]'
pytest -q
```

See ADR-0027 (`docs/adr/ADR-0027-dataset-manifest-commitments.md`) for the
design and the Rust `clients/cli/README.md` for the full builder.
