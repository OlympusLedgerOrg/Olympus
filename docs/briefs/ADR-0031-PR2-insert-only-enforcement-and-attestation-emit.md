# PR2 brief — enforce insert-only + emit transition attestation

> **Agent-ready.** Implements §2 of `docs/adr/ADR-0031-transition-attestations-insert-only-ledger.md`.
> **Hard dependency: PR1 must already be merged** — this PR does
> `use olympus_crypto::{TransitionAttestation, SNAPSHOT_PERSIST_PREFIX, persist_message};`.
> Do **not** stub those locally (CLAUDE.md law). Additive: **no hash/circuit/vkey/
> ceremony change**; one forward-only migration adding nullable columns.

This PR has two independent parts. They can be one PR or two stacked commits, but
both are in scope.

---

## Part A — Make insert-only the enforced ledger invariant

### Current state (verified)

- `src-tauri/src/smt/tree.rs:264` `update_batch_inner(updates, write_once)` already
  rejects rewriting a committed key to a *different* `value_hash` **when
  `write_once == true`** — inside the H-4 write lock, against the leaves
  `build_working_set` just read (no TOCTOU). An identical re-commit falls through
  as a no-op overlay.
- `update_batch_write_once` calls it with `true`; `update_batch` calls it with
  `false`.
- **There is no delete/tombstone path** anywhere (`LeafUpdate` is the only mutation
  entry; no `remove`, no `DELETE FROM smt_*`). Removal is already impossible.

So the only gap is the *mutation* window on callers that use the `write_once == false`
path.

### Change

1. **Audit every caller of `update_batch` (non-write-once).** Identify which are the
   ledger *ingest* path (caller-supplied records that must be append-only) vs. any
   internal/maintenance recompute that legitimately rewrites nodes. Use:
   ```
   rg "update_batch\b" --type rust src-tauri/
   ```
2. **Route ledger ingest through the write-once guard.** For every ingest caller,
   switch to `update_batch_write_once` (or thread `write_once: true`). A rewrite
   attempt must surface to the API as a clean `409 Conflict` (or `400`) with the
   existing "write-once violation" message — not a 500. Find the ingest handler
   (`src-tauri/src/api/ingest.rs`) and map the `anyhow` error to the right status.
3. **Do not change** any path that is a pure internal recompute and genuinely must
   overwrite internal node hashes for the *same* leaf set — the guard only compares
   `value_hash` of *leaves*, so recompute paths are unaffected, but confirm before
   flipping a flag.
4. **Document the invariant.** Add to CLAUDE.md "Critical Invariants":
   > **The ledger is insert-only** — ingest commits go through the write-once guard
   > in `update_batch_inner` (rejects rewriting a committed key to a different
   > `value_hash`), and there is no leaf-delete/tombstone path. A change that
   > introduces either a non-write-once ingest caller or a delete path is a
   > security-policy change.

### Tests (Part A)

- Re-committing the same `(key, value_hash)` is a no-op (still succeeds).
- Committing a *different* `value_hash` for an existing key via the ingest path is
  rejected with the write-once error and the API returns `409`/`400` (not `500`).
- A fresh key still inserts.
- Place these in the existing `tree.rs` test module and an ingest API test.

---

## Part B — Emit a `TransitionAttestation` at checkpoint time

### Where

`src-tauri/src/anchoring/own_checkpoint.rs::build_and_persist` (around line 97). It
already:
- `SELECT original_root, snapshot_root, snapshot_index, snapshot_size, snapshot_path …`
  for the latest ingest snapshot,
- resolves the BJJ authority key + pubkey,
- runs the Groth16 prove, BJJ-signs the Poseidon `snapshot_root`, computes the
  anchor digest, and inserts the `own_checkpoints` row.

### Change

1. **Build the attestation** from the snapshot fields already in hand:
   ```rust
   let attestation = TransitionAttestation {
       original_root: hex_to_bytes32(&snap.original_root)?,
       snapshot_root:  hex_to_bytes32(&snap.snapshot_root)?,
       snapshot_size:  snap.snapshot_size,
   };
   ```
   (`original_root` and `snapshot_root` are stored as hex strings — decode to
   `[u8;32]`; reuse the file's existing hex helpers / add a small one mirroring
   `hex_to_fr`.)
2. **Sign `attestation.message()` reduced mod l with the BJJ authority key** — the
   exact SBT-open signing pattern (`m = BLAKE3(prefix | …) reduced mod l`). Reuse the
   existing BJJ-EdDSA signer used for the checkpoint's `snapshot_root` signature; the
   only difference is the message digest comes from `attestation.message()` instead
   of the Poseidon root. Produce `(r8x, r8y, s)` hex.
3. **Persist alongside the checkpoint row.** Add nullable columns to `own_checkpoints`
   via a **new forward-only migration** (next number after the current max in
   `migrations/`):
   ```sql
   ALTER TABLE own_checkpoints
     ADD COLUMN transition_original_root TEXT,
     ADD COLUMN transition_sig_r8x       TEXT,
     ADD COLUMN transition_sig_r8y       TEXT,
     ADD COLUMN transition_sig_s         TEXT;
   ```
   (`snapshot_root`/`tree_size` already exist on the row as `ledger_root`/`tree_size`;
   only `original_root` + the transition signature are new.) Bind the four values in
   the existing INSERT. Keep them nullable so old rows and no-BJJ-key builds stay
   valid.
4. **Surface it (optional, low-risk):** if `OwnCheckpointRow` is read back for the
   bundle/gossip producer, add the four fields to the struct + `row_to_own_checkpoint`
   so a future verifier/PR3 can read them. Do **not** add them to the `PeerCheckpoint`
   wire format in this PR — that wire change is out of scope and would need a
   `PEER_CHECKPOINT_WIRE_VERSION` bump.

### Tests (Part B)

- `build_and_persist` writes the four transition columns when a BJJ key is present;
  leaves them NULL when no BJJ key is loaded (build must not fail in that case).
- The persisted signature verifies against `persist_message(original_root,
  snapshot_root, snapshot_size)` reduced mod l under the authority pubkey (offline
  BJJ verify) — this is the conformance test that ties PR2 back to PR1's golden
  message.
- Migration applies cleanly on a DB seeded by the previous migration set.

---

## Acceptance (whole PR)

- `cargo test -p olympus-desktop` green (ingest write-once + checkpoint attestation
  tests).
- `cargo clippy --workspace` clean.
- New migration is the highest-numbered file in `migrations/` and only **adds**
  nullable columns (no destructive change, no backfill needed).
- No diff under `proofs/`, no vkey/manifest change, no `PeerCheckpoint` wire change.
- `rg "OLY:SNAPSHOT:PERSIST"` shows the constant **only** in `olympus-crypto` (PR2
  imports, never redefines).
- CLAUDE.md "Critical Invariants" gains the insert-only entry.

## Definition of done

The ledger ingest path is provably insert-only (rewrite → `409`, no delete path),
and every emitted own-checkpoint carries a BJJ-signed `TransitionAttestation`
binding `original_root → snapshot_root over snapshot_size`, verifiable offline
against PR1's `persist_message`.
