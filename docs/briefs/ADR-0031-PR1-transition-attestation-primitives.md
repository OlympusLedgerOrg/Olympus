# PR1 brief — `TransitionAttestation` primitives in `olympus-crypto`

> **Agent-ready.** Implements §1 of `docs/adr/ADR-0031-transition-attestations-insert-only-ledger.md`.
> Land **before** PR2 (PR2 imports these symbols). Pure additive crypto primitive —
> **no hash/circuit/vkey/ceremony change, no migration.**

## Goal

Add a domain-separated transition message + a signable attestation type to
`crates/olympus-crypto`, so the checkpoint producer (PR2) and every reference
verifier derive identical signing bytes. The domain prefix and framing must live
**only** here (CLAUDE.md law: domain constants live in `olympus-crypto`).

## Scope (touch only these)

- `crates/olympus-crypto/src/lib.rs` — new constant, new fn, new struct, new tests.
- `verifiers/rust/` and `verifiers/javascript/` — mirror `persist_message` so the
  offline verifiers can recompute the digest. (Add only if/when PR2 puts the
  attestation on a verifiable artifact; if PR1 ships standalone, a follow-up note
  in each verifier's TODO is acceptable — but the prefix constant must be mirrored.)

Do **not** touch `src-tauri`, circuits, vkeys, manifests, or migrations in PR1.

## Exact changes

### 1. Register the domain prefix

In `crates/olympus-crypto/src/lib.rs`, next to `SBT_OPEN_PREFIX` /
`SBT_COMMIT_BIND_PREFIX`:

```rust
/// Domain prefix for the snapshot-transition (persist) attestation.
/// Signs the relation "original_root → snapshot_root over snapshot_size leaves
/// is an append-only persist". Disjoint from SBT (`OLY:SBT:OPEN:V1`,
/// `OLY:SBT:COMMIT:V1`) and node/leaf prefixes so a signature minted in one
/// role cannot be replayed in another. See ADR-0031 §1.
pub const SNAPSHOT_PERSIST_PREFIX: &[u8] = b"OLY:SNAPSHOT:PERSIST:V1";
```

Add a pinned equality assertion to the **same `#[test]` block** that pins the
other prefixes (the constant-stability test around line 292):

```rust
assert_eq!(SNAPSHOT_PERSIST_PREFIX, b"OLY:SNAPSHOT:PERSIST:V1");
```

### 2. `persist_message`

Use the ADR-0005 length-prefix framing (`lp(x)` = 4-byte BE length || bytes — match
the helper already used by `leaf_hash`/`key_hash` in this file; reuse it, do not
re-invent). `snapshot_size` is encoded as its **8-byte big-endian** representation
of the `i64` value (it is always ≥ 0 in practice; encode the raw `i64` bits as
`u64` BE so the encoding is total and the verifiers can reproduce it without sign
handling).

```rust
/// Digest signed by a [`TransitionAttestation`].
/// `BLAKE3(SNAPSHOT_PERSIST_PREFIX || lp(original_root) || lp(snapshot_root)
///         || lp(snapshot_size as u64 big-endian))`.
/// `lp` is the ADR-0005 length-prefix framing used throughout this crate.
pub fn persist_message(
    original_root: &[u8; 32],
    snapshot_root: &[u8; 32],
    snapshot_size: i64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SNAPSHOT_PERSIST_PREFIX);
    lp_update(&mut h, original_root);            // reuse existing lp helper
    lp_update(&mut h, snapshot_root);
    lp_update(&mut h, &(snapshot_size as u64).to_be_bytes());
    *h.finalize().as_bytes()
}
```

> If the existing `lp` helper takes a `&mut Vec<u8>` rather than a hasher, mirror
> that style instead — match the surrounding code; do not introduce a second
> framing idiom.

### 3. `TransitionAttestation`

Crypto-only. No `sqlx`, no serde-of-DB, no wire envelope (those belong in
`src-tauri`, PR2). It carries the three bound fields and recomputes the digest:

```rust
/// The append-only transition asserted by a checkpoint: `original_root` →
/// `snapshot_root` over `snapshot_size` leaves. The signature (BJJ-EdDSA over
/// `message()` reduced mod l, mirroring the SBT-open pattern) is attached by the
/// caller in `src-tauri`; this type only binds the data and the signing digest.
/// See ADR-0031 §1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionAttestation {
    pub original_root: [u8; 32],
    pub snapshot_root: [u8; 32],
    pub snapshot_size: i64,
}

impl TransitionAttestation {
    /// The 32-byte BLAKE3 digest to sign (before reduction mod l).
    pub fn message(&self) -> [u8; 32] {
        persist_message(&self.original_root, &self.snapshot_root, self.snapshot_size)
    }
}
```

## Tests (in `crates/olympus-crypto`)

1. **Prefix pinned** — extend the constant-stability test (above).
2. **`persist_message` is deterministic + a golden vector** — assert a fixed
   `(original_root, snapshot_root, snapshot_size)` triple hashes to a hard-coded
   32-byte hex. This is the cross-impl conformance anchor; the JS/Rust verifiers
   must reproduce it.
3. **Domain separation** — `persist_message(a, b, n)` ≠ `BLAKE3(lp(a)||lp(b)||lp(n))`
   without the prefix, and ≠ any SBT digest over the same bytes (sanity that the
   prefix actually participates).
4. **Field sensitivity** — flipping any of the three inputs changes the digest.
5. **`TransitionAttestation::message()` == `persist_message(...)`** for the same
   fields.

## Acceptance

- `cargo test -p olympus-crypto` green, including the new golden vector.
- `cargo clippy --workspace` clean.
- No diff under `proofs/`, `migrations/`, or any `*_vkey.json` / `*_manifest.json`.
- `rg "OLY:SNAPSHOT:PERSIST" --type rust` shows the constant defined in exactly one
  place (`crates/olympus-crypto/src/lib.rs`).

## Definition of done

The three symbols `SNAPSHOT_PERSIST_PREFIX`, `persist_message`, and
`TransitionAttestation` are public in `olympus-crypto` with a golden vector, so PR2
can `use olympus_crypto::{TransitionAttestation, SNAPSHOT_PERSIST_PREFIX, persist_message};`
and compile.
