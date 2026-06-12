# olympus — dataset-manifest client (CLI/SDK)

A `cargo install`-able client for Olympus **dataset manifests** (ADR-0027). It
hashes shards locally, builds a manifest whose `manifest_root` commits millions
of records, commits that root to an Olympus node, and produces / verifies
record-level **inclusion** and **exclusion** proofs — headless, no desktop app,
no GUI. Drop it into a data pipeline.

It is a standalone crate, **not** part of the main Olympus workspace (own release
cadence, like `verifiers/rust`).

## Install / build

```bash
# From this directory:
cargo build --release                 # offline core: build/prove/verify/diff/link/hash
cargo build --release --features server   # adds `commit` and `fetch` (HTTP, rustls)
cargo install --path .                # installs the `olympus` binary
```

The offline core has **zero** extra dependencies beyond the Olympus crates. The
`server` feature pulls a blocking `reqwest` (rustls — no OpenSSL) for talking to
a node.

## The pipeline loop

```bash
# 1. Build a manifest + record index from a local dataset directory.
#    --shard-from-subdir uses each top-level subdir as a shard id.
olympus build --data ./dataset --dataset-id acme-corpus --version 1 \
    --shard-from-subdir --model-hash <sha-of-training-model> \
    --out manifest.json --index index.json

# 2. Commit to an Olympus node. This uploads the full canonical manifest
#    document as the multipart "file" (see `commit` in clients/cli/src/server.rs);
#    the node hashes and stores that blob, which anchors the manifest_root it
#    contains to the ledger and returns a proof_id + content_hash.
olympus commit --manifest manifest.json --server https://node.example --api-key $OLY_KEY

# 3. Prove a record IS in the dataset (inclusion) — or is NOT (exclusion).
olympus prove --manifest manifest.json --index index.json \
    --shard train --record doc-00042.txt --out proof.json     # kind auto-detected

# 4. Verify a proof offline against the manifest root.
olympus verify --proof proof.json --manifest manifest.json
#  -> VALID INCLUSION: train/doc-00042.txt is committed in dataset 'acme-corpus' v1 ...
```

## Incremental versions (`v2 = v1 − removed + added`)

```bash
# Build v2 the same way (against the new dataset state), then seal the diff:
olympus diff \
    --parent-manifest m1.json --parent-index i1.json \
    --child-manifest  m2.json --child-index  i2.json \
    --out-child m2_linked.json --out-diff diff.json
#  -> sealed incremental v2 on parent v1   added: N   removed: M   diff_root: ...

# Verify the version link from committed artifacts alone:
olympus link --child m2_linked.json --parent-version 1 \
    --parent-root <v1 manifest_root> --diff diff.json
```

The record-level guarantee behind a link is established with ordinary proofs:
each *removed* record has an inclusion proof in the parent + an exclusion proof
in the child; each *added* record, the reverse.

## Commands

| Command | Network? | Purpose |
|---|---|---|
| `build` | no | Hash a directory into a manifest + record index |
| `prove` | no | Inclusion/exclusion proof for a record (`--kind inclusion\|exclusion\|auto`) |
| `verify` | no | Verify a proof against a manifest's `manifest_root` |
| `diff` | no | Seal an incremental version + emit the diff artifact |
| `link` | no | Verify the structural version link |
| `hash` | no | BLAKE3-hash a file |
| `commit` | yes (`--features server`) | POST a manifest to a node (`/ingest/files`) |
| `fetch` | yes (`--features server`) | Pull a committed blob's ledger proof by content hash |

Run any command with no arguments to see its flags.

## Library use (SDK)

The commitment logic lives in the `olympus-manifest` crate; the CLI is a thin
wrapper. Depend on it directly to build/verify manifests in your own Rust:

```rust
use olympus_manifest::{commit::seal, DatasetMetadata, RecordIndex};
let sealed = seal("acme-corpus", 1, now, DatasetMetadata::default(), &index)?;
let proof  = sealed.prove_inclusion("train", "doc-00042.txt", 1)?;
let ok     = olympus_manifest::proof::verify(&proof, &sealed.manifest_root())?.is_valid();
```

See ADR-0027 (`docs/adr/ADR-0027-dataset-manifest-commitments.md`) for the design
and `docs/benchmarks/manifest-throughput.md` for performance.
