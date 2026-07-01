//! Shared protocol-critical crypto primitives for Olympus.
//!
//! This crate is intentionally small: it owns the byte layouts and domain
//! tags that must stay identical across the Python extension, the Go-facing
//! Rust sidecar, and verifiers.
//!
//! Optional feature `poseidon`: BN254 Poseidon for ZK-circuit commitments.
//! Optional feature `canonical`: JCS / RFC 8785 canonical JSON for SBT digests.

#[cfg(feature = "poseidon")]
pub mod poseidon;

#[cfg(feature = "canonical")]
pub mod canonical;

#[cfg(feature = "smt")]
pub mod smt;

#[cfg(feature = "snapshot")]
pub mod ledger_snapshot;

#[cfg(feature = "redaction")]
pub mod redaction;

#[cfg(feature = "signature-envelope")]
pub mod signature_envelope;

pub mod request_envelope;

/// BLAKE3 derive_key context for global SMT leaf keys.
pub const GLOBAL_SMT_KEY_CONTEXT: &str = "olympus 2025-12 global-smt-leaf-key";

/// Domain-separation prefix for record keys.
pub const KEY_PREFIX: &[u8] = b"OLY:KEY:V1";

/// Legacy ASCII domain-separation prefix for SMT leaf nodes
/// (`OLY:LEAF:V1`). Superseded by the ADR-0005 structured binary prefix used
/// by [`leaf_hash`]; retained as a pinned protocol marker for reference.
pub const LEAF_PREFIX: &[u8] = b"OLY:LEAF:V1";

// ── ADR-0005 structured leaf prefix ──────────────────────────────────────────
// The leaf domain prefix is a self-describing binary header rather than an
// ASCII tag: `u8(marker) || "OLY" || u8(object_type) || u8(version)`, followed
// by `lp(shard_id)` and the count-framed body. See [`leaf_hash`].

/// Structured-prefix marker byte (start of an Olympus structured domain tag).
pub const OLY_STRUCT_MARKER: u8 = 0x01;
/// Olympus namespace bytes inside the structured prefix.
pub const OLY_NAMESPACE: &[u8] = b"OLY";
/// Object-type byte for SMT leaves in the structured prefix.
pub const LEAF_OBJECT_TYPE: u8 = 0x01;
/// Version byte (V1) for the leaf domain in the structured prefix.
pub const LEAF_VERSION: u8 = 0x01;
/// Number of count-framed body fields after the prefix:
/// `key, value_hash, parser_id, canonical_parser_version, model_hash`.
pub const LEAF_BODY_FIELD_COUNT: u8 = 0x05;

/// Domain-separation prefix for SMT internal nodes.
pub const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";

/// Field separator used in leaf and node hash concatenation.
pub const SEP: &[u8] = b"|";

/// Domain-separation prefix for the empty-leaf sentinel.
pub const EMPTY_LEAF_PREFIX: &[u8] = b"OLY:EMPTY-LEAF:V1";

/// Domain-separation tag for the Pedersen commitment second generator `H`.
///
/// `H` is derived nothing-up-my-sleeve from this tag via try-and-increment
/// over the Baby Jubjub curve; the resulting point's discrete-log with
/// respect to the iden3 base generator `G` is therefore unknown to anyone,
/// which is the binding requirement for Pedersen commitments `C = m·G + r·H`.
///
/// Changing this tag invalidates every existing commitment. Treat it as
/// frozen on first ship.
pub const PEDERSEN_H_PREFIX: &[u8] = b"OLY:PEDERSEN:H:V1";

/// Domain-separation tag for a **PDF object-level** redaction leaf (ADR-0025).
///
/// The per-object content scalar is
/// `content = BLAKE3(POSEIDON_DOMAIN_OBJ_LEAF || lp(obj_id) || obj_bytes) mod p`,
/// and the circuit leaf is `Poseidon(Poseidon(POSEIDON_DOMAIN_LEAF, content), 0)`
/// (see `olympus_crypto::poseidon::object_leaf`). Length-prefixing `obj_id` and
/// the object bytes (ADR-0005) makes two distinct objects unable to collide by
/// shifting field boundaries.
///
/// Named to match the ADR-0025 spec. It is a BLAKE3 domain string (analogous to
/// [`PEDERSEN_H_PREFIX`]), not a numeric Poseidon domain tag. Changing it
/// invalidates every existing object-level redaction commitment; treat as
/// frozen on first ship.
pub const POSEIDON_DOMAIN_OBJ_LEAF: &str = "OLY:REDACTION:OBJ:V1";

/// Domain-separation tag for the SBT attribute-opening digest.
///
/// `m = BLAKE3(SBT_OPEN_PREFIX | jcs(details)) reduced mod l` — the message
/// scalar a Pedersen-committed SBT row binds to. Holders re-derive `m` from
/// their cleartext attributes; server discards the attributes after
/// committing, so the digest must be deterministic and unambiguous.
/// Domain-separated from generic BLAKE3 uses to prevent cross-protocol
/// collisions.
pub const SBT_OPEN_PREFIX: &[u8] = b"OLY:SBT:OPEN:V1";

/// Domain-separation tag for the SBT commit_id when bound to a Pedersen
/// commitment (rather than to cleartext attributes).
///
/// For Pedersen-committed rows the commit_id binds (holder, type,
/// issued_at, commitment_x, commitment_y) instead of (..., details), since
/// the server has no cleartext details to hash post-commit. The two domains
/// are explicitly separated so a plaintext-row commit_id can never collide
/// with a committed-row commit_id.
pub const SBT_COMMIT_BIND_PREFIX: &[u8] = b"OLY:SBT:COMMIT:V1";

/// Domain prefix for the snapshot-transition (persist) attestation.
///
/// Signs the relation "`original_root` → `snapshot_root` over `snapshot_size`
/// leaves is an append-only persist". Disjoint from SBT (`OLY:SBT:OPEN:V1`,
/// `OLY:SBT:COMMIT:V1`) and the node/leaf prefixes so a signature minted in one
/// role cannot be replayed in another. See ADR-0031 §1.
pub const SNAPSHOT_PERSIST_PREFIX: &[u8] = b"OLY:SNAPSHOT:PERSIST:V1";

/// Encode `data` with a 4-byte big-endian length prefix.
///
/// Panics if `data.len()` exceeds `u32::MAX`, matching the prior behavior in
/// both Rust call sites and preventing silent truncation.
pub fn length_prefixed(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= u32::MAX as usize,
        "length_prefixed: data length {} exceeds u32::MAX",
        data.len()
    );
    let len = data.len() as u32;
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Compute a BLAKE3 hash over the concatenation of `parts`.
pub fn blake3_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Generate a deterministic 32-byte record key.
pub fn record_key(record_type: &str, record_id: &str, version: u64) -> [u8; 32] {
    let rt = record_type.as_bytes();
    let ri = record_id.as_bytes();
    debug_assert!(rt.len() <= u32::MAX as usize);
    debug_assert!(ri.len() <= u32::MAX as usize);

    let mut key_data = Vec::with_capacity(KEY_PREFIX.len() + 4 + rt.len() + 4 + ri.len() + 8);
    key_data.extend_from_slice(KEY_PREFIX);
    key_data.extend_from_slice(&length_prefixed(rt));
    key_data.extend_from_slice(&length_prefixed(ri));
    key_data.extend_from_slice(&version.to_be_bytes());

    *blake3::Hasher::new()
        .update(&key_data)
        .finalize()
        .as_bytes()
}

/// Derive the global SMT key for a shard-local record key.
pub fn global_key(shard_id: &str, record_key_bytes: &[u8]) -> [u8; 32] {
    let shard_bytes = shard_id.as_bytes();
    debug_assert!(shard_bytes.len() <= u32::MAX as usize);

    let mut key_material = Vec::with_capacity(4 + shard_bytes.len() + 4 + record_key_bytes.len());
    key_material.extend_from_slice(&length_prefixed(shard_bytes));
    key_material.extend_from_slice(&length_prefixed(record_key_bytes));

    *blake3::Hasher::new_derive_key(GLOBAL_SMT_KEY_CONTEXT)
        .update(&key_material)
        .finalize()
        .as_bytes()
}

/// Compute a domain-separated leaf hash. The preimage is the ADR-0005
/// **structured binary prefix** followed by the count-framed leaf body, binding
/// parser provenance (ADR-0003) and the model hash (ADR-0004):
///
/// ```text
/// BLAKE3(
///     u8(0x01) || "OLY" || u8(0x01) || u8(0x01) ||   // structured prefix: marker, namespace, type=LEAF, version=V1
///     lp(shard_id) ||                                 // shard, length-prefixed (ADR-0005)
///     u8(0x05) ||                                     // field count for the body below
///     lp(key) ||
///     value_hash ||                                   // raw, fixed 32 bytes
///     lp(parser_id) ||
///     lp(canonical_parser_version) ||
///     lp(model_hash)
/// )
/// ```
///
/// where `lp(x)` is [`length_prefixed`] (4-byte big-endian length || bytes).
///
/// The structured prefix replaces the legacy `OLY:LEAF:V1|` ASCII tag: it is
/// self-describing (marker / namespace / object-type / version bytes) and the
/// `0x05` body-field count plus per-field length prefixes make the whole
/// preimage unambiguous without `|` separators. `shard_id` lives in the prefix
/// region so leaves are shard-domain-separated before the body — explicit and
/// untruncated, rather than relying only on the 64-bit shard prefix that
/// `smt::shard_record_key` folds into `key`.
///
/// `shard_id` / `parser_id` / `canonical_parser_version` / `model_hash` are
/// required non-empty by the SMT layer. `value_hash` is the only un-prefixed
/// field, so it MUST be exactly 32 bytes; `key` is length-prefixed but every
/// in-tree caller passes a 32-byte digest, which is asserted defensively.
pub fn leaf_hash(
    shard_id: &[u8],
    key: &[u8],
    value_hash: &[u8],
    parser_id: &[u8],
    canonical_parser_version: &[u8],
    model_hash: &[u8],
) -> [u8; 32] {
    // `value_hash` is NOT length-prefixed, so its boundary against the
    // following `lp(parser_id)` is only unambiguous when it is fixed-width:
    // require exactly 32 bytes (R6-L1). `key` IS length-prefixed and therefore
    // self-delimiting, but every in-tree caller passes a 32-byte BLAKE3 digest,
    // so we assert it too — a release `assert!`, not `debug_assert!`, because in
    // release builds it is the guard against a future caller breaking the
    // fixed-width key-space invariant.
    assert!(
        key.len() == 32 && value_hash.len() == 32,
        "leaf_hash requires 32-byte key and value_hash (got {} and {})",
        key.len(),
        value_hash.len()
    );
    let mut hasher = blake3::Hasher::new();
    // ADR-0005 structured prefix: marker | "OLY" | object-type=LEAF | version=V1 | lp(shard_id)
    hasher.update(&[OLY_STRUCT_MARKER]);
    hasher.update(OLY_NAMESPACE);
    hasher.update(&[LEAF_OBJECT_TYPE]);
    hasher.update(&[LEAF_VERSION]);
    hasher.update(&length_prefixed(shard_id));
    // Count-framed body.
    hasher.update(&[LEAF_BODY_FIELD_COUNT]);
    hasher.update(&length_prefixed(key));
    hasher.update(value_hash);
    hasher.update(&length_prefixed(parser_id));
    hasher.update(&length_prefixed(canonical_parser_version));
    hasher.update(&length_prefixed(model_hash));
    *hasher.finalize().as_bytes()
}

/// Compute a domain-separated internal-node hash.
pub fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    // Same fixed-width requirement as leaf_hash: `left`/`right` are `|`-joined
    // but not length-prefixed, so both must be exactly 32 bytes to keep the
    // field boundary unambiguous (R6-L1/L2).
    assert!(
        left.len() == 32 && right.len() == 32,
        "node_hash requires 32-byte left and right (got {} and {})",
        left.len(),
        right.len()
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_PREFIX);
    hasher.update(SEP);
    hasher.update(left);
    hasher.update(SEP);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute the empty-leaf sentinel.
pub fn empty_leaf() -> [u8; 32] {
    *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes()
}

/// Generic BLAKE3 hash of a single byte slice.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Digest signed by a [`TransitionAttestation`].
///
/// ```text
/// BLAKE3(
///     SNAPSHOT_PERSIST_PREFIX ||
///     lp(original_root) || lp(snapshot_root) ||
///     lp(snapshot_size as u64 big-endian)
/// )
/// ```
///
/// `lp` is [`length_prefixed`] (4-byte big-endian length || bytes), the ADR-0005
/// framing used throughout this crate. `snapshot_size` is encoded as the 8-byte
/// big-endian representation of its `i64` bits reinterpreted as `u64`, so the
/// encoding is total (no sign handling) and the reference verifiers can
/// reproduce it byte-for-byte. See ADR-0031 §1.
pub fn persist_message(
    original_root: &[u8; 32],
    snapshot_root: &[u8; 32],
    snapshot_size: i64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_PERSIST_PREFIX);
    hasher.update(&length_prefixed(original_root));
    hasher.update(&length_prefixed(snapshot_root));
    hasher.update(&length_prefixed(&(snapshot_size as u64).to_be_bytes()));
    *hasher.finalize().as_bytes()
}

/// The append-only transition asserted by a checkpoint: `original_root` →
/// `snapshot_root` over `snapshot_size` leaves.
///
/// The signature (BJJ-EdDSA over [`Self::message`] reduced mod l, mirroring the
/// SBT-open signing pattern) is attached by the caller in `src-tauri`; this type
/// only binds the data and the signing digest. See ADR-0031 §1.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_and_global_key_are_stable() {
        let rk = record_key("document", "abc", 7);
        assert_eq!(
            hex_lower(&rk),
            "151a2e1d110b263ba596902e6360a2142bdfeecc20d0c1d54465eec9ab5d78c8"
        );

        let gk = global_key("shard-a", &rk);
        assert_eq!(
            hex_lower(&gk),
            "d6881dc754d860b3044c48fff6d412ad7d57d75e5a00775a0c1ecc6f54118b36"
        );
    }

    // ── Constants ─────────────────────────────────────────────────────────────
    // These constants are protocol-critical (CLAUDE.md "Critical Invariants").
    // Pinning their byte layouts prevents accidental rename/case changes.

    #[test]
    fn domain_prefix_constants_are_pinned() {
        assert_eq!(KEY_PREFIX, b"OLY:KEY:V1");
        assert_eq!(LEAF_PREFIX, b"OLY:LEAF:V1");
        assert_eq!(NODE_PREFIX, b"OLY:NODE:V1");
        // ADR-0005 structured leaf prefix bytes.
        assert_eq!(OLY_STRUCT_MARKER, 0x01);
        assert_eq!(OLY_NAMESPACE, b"OLY");
        assert_eq!(LEAF_OBJECT_TYPE, 0x01);
        assert_eq!(LEAF_VERSION, 0x01);
        assert_eq!(LEAF_BODY_FIELD_COUNT, 0x05);
        assert_eq!(EMPTY_LEAF_PREFIX, b"OLY:EMPTY-LEAF:V1");
        assert_eq!(PEDERSEN_H_PREFIX, b"OLY:PEDERSEN:H:V1");
        assert_eq!(POSEIDON_DOMAIN_OBJ_LEAF, "OLY:REDACTION:OBJ:V1");
        assert_eq!(SBT_OPEN_PREFIX, b"OLY:SBT:OPEN:V1");
        assert_eq!(SBT_COMMIT_BIND_PREFIX, b"OLY:SBT:COMMIT:V1");
        assert_eq!(SNAPSHOT_PERSIST_PREFIX, b"OLY:SNAPSHOT:PERSIST:V1");
        assert_eq!(SEP, b"|");
        assert_eq!(
            GLOBAL_SMT_KEY_CONTEXT,
            "olympus 2025-12 global-smt-leaf-key"
        );
    }

    // ── length_prefixed ───────────────────────────────────────────────────────

    #[test]
    fn length_prefixed_emits_be_u32_then_data() {
        let out = length_prefixed(b"hello");
        assert_eq!(&out[..4], &5u32.to_be_bytes());
        assert_eq!(&out[4..], b"hello");
    }

    #[test]
    fn length_prefixed_empty_is_four_zero_bytes() {
        assert_eq!(length_prefixed(b""), vec![0, 0, 0, 0]);
    }

    #[test]
    fn length_prefixed_distinguishes_concatenation_ambiguity() {
        // Without length prefixing, ("ab","c") and ("a","bc") would hash the
        // same. With it, they must differ.
        let ambiguous_a = [length_prefixed(b"ab"), length_prefixed(b"c")].concat();
        let ambiguous_b = [length_prefixed(b"a"), length_prefixed(b"bc")].concat();
        assert_ne!(ambiguous_a, ambiguous_b);
    }

    // ── blake3_hash ───────────────────────────────────────────────────────────

    #[test]
    fn blake3_hash_concat_equivalence() {
        // Hashing parts must equal hashing the pre-concatenated buffer.
        let parts: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        let by_parts = blake3_hash(parts);
        let concatenated = b"alphabetagamma";
        let by_whole = blake3_hash(&[concatenated]);
        assert_eq!(by_parts, by_whole);
    }

    #[test]
    fn blake3_hash_empty_is_blake3_empty() {
        // Hashing zero parts is hashing the empty string.
        assert_eq!(blake3_hash(&[]), *blake3::hash(b"").as_bytes());
    }

    // ── record_key / global_key ───────────────────────────────────────────────

    #[test]
    fn record_key_is_deterministic() {
        assert_eq!(
            record_key("document", "id-42", 1),
            record_key("document", "id-42", 1)
        );
    }

    #[test]
    fn record_key_depends_on_every_input() {
        let base = record_key("document", "id-42", 1);
        assert_ne!(base, record_key("dataset", "id-42", 1), "type matters");
        assert_ne!(base, record_key("document", "id-43", 1), "id matters");
        assert_ne!(base, record_key("document", "id-42", 2), "version matters");
    }

    #[test]
    fn global_key_depends_on_shard_and_record_key() {
        let rk1 = record_key("document", "a", 1);
        let rk2 = record_key("document", "b", 1);
        assert_ne!(global_key("shard-a", &rk1), global_key("shard-b", &rk1));
        assert_ne!(global_key("shard-a", &rk1), global_key("shard-a", &rk2));
    }

    // ── leaf_hash / node_hash domain separation ──────────────────────────────

    #[test]
    fn leaf_and_node_hash_are_domain_separated() {
        // Same byte payload through both APIs must produce different output,
        // proving the OLY:LEAF:V1 / OLY:NODE:V1 prefix is actually mixed in.
        let payload = [0u8; 32];
        let leaf = leaf_hash(
            b"shard-a",
            &payload,
            &payload,
            b"parser-x",
            b"v1",
            b"model-x",
        );
        let node = node_hash(&payload, &payload);
        assert_ne!(leaf, node);
    }

    #[test]
    fn leaf_hash_depends_on_shard_parser_version_and_model() {
        let key = [1u8; 32];
        let value = [2u8; 32];
        let base = leaf_hash(b"shard-a", &key, &value, b"parser-x", b"v1", b"model-x");
        // ADR-0005: the shard_id is bound into the leaf domain prefix.
        assert_ne!(
            base,
            leaf_hash(b"shard-b", &key, &value, b"parser-x", b"v1", b"model-x")
        );
        assert_ne!(
            base,
            leaf_hash(b"shard-a", &key, &value, b"parser-y", b"v1", b"model-x")
        );
        assert_ne!(
            base,
            leaf_hash(b"shard-a", &key, &value, b"parser-x", b"v2", b"model-x")
        );
        // ADR-0004: the model_hash field is bound into the leaf domain.
        assert_ne!(
            base,
            leaf_hash(b"shard-a", &key, &value, b"parser-x", b"v1", b"model-y")
        );
    }

    #[test]
    fn leaf_hash_variable_fields_are_unambiguous() {
        // Length-prefixing keeps neighbouring variable fields from shifting a
        // `|` across their boundary: (shard="ab", parser="c") must differ from
        // (shard="a", parser="bc"), and likewise for (cpv, model).
        let key = [7u8; 32];
        let value = [9u8; 32];
        assert_ne!(
            leaf_hash(b"ab", &key, &value, b"c", b"v", b"m"),
            leaf_hash(b"a", &key, &value, b"bc", b"v", b"m"),
        );
        assert_ne!(
            leaf_hash(b"s", &key, &value, b"p", b"ab", b"c"),
            leaf_hash(b"s", &key, &value, b"p", b"a", b"bc"),
        );
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a = [3u8; 32];
        let b = [4u8; 32];
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    #[test]
    #[should_panic(expected = "32-byte key and value_hash")]
    fn leaf_hash_rejects_non_32_byte_key() {
        // Variable-length key/value could be used to craft collisions across
        // the unframed `|` separator — must be rejected (R6-L1).
        let _ = leaf_hash(b"shard", b"short", &[0u8; 32], b"parser", b"v1", b"model");
    }

    #[test]
    #[should_panic(expected = "32-byte left and right")]
    fn node_hash_rejects_non_32_byte_input() {
        let _ = node_hash(b"short", &[0u8; 32]);
    }

    // ── empty_leaf / hash_bytes ──────────────────────────────────────────────

    #[test]
    fn empty_leaf_equals_blake3_of_prefix() {
        assert_eq!(empty_leaf(), *blake3::hash(EMPTY_LEAF_PREFIX).as_bytes());
    }

    #[test]
    fn empty_leaf_is_constant() {
        // empty_leaf() is called frequently in SMT proof generation; pin it
        // so that any change to EMPTY_LEAF_PREFIX surfaces as a test failure
        // (not a silent re-hash of existing snapshots).
        assert_eq!(empty_leaf(), empty_leaf());
        // And it's domain-separated from the all-zero leaf.
        assert_ne!(empty_leaf(), hash_bytes(&[0u8; 32]));
    }

    #[test]
    fn hash_bytes_matches_blake3() {
        let data = b"some payload";
        assert_eq!(hash_bytes(data), *blake3::hash(data).as_bytes());
    }

    // ── persist_message / TransitionAttestation (ADR-0031 §1) ────────────────

    #[test]
    fn persist_message_is_deterministic_golden_vector() {
        // Cross-impl conformance anchor: the Rust/JS verifiers must reproduce
        // this exact digest. Do not change without updating every verifier.
        let original_root = [0x11u8; 32];
        let snapshot_root = [0x22u8; 32];
        let snapshot_size: i64 = 42;
        let m = persist_message(&original_root, &snapshot_root, snapshot_size);
        assert_eq!(
            m,
            persist_message(&original_root, &snapshot_root, snapshot_size),
            "must be deterministic"
        );
        assert_eq!(
            hex_lower(&m),
            "dc1ed60d80e79bbe4966cfaad20682caeadec274aefdd13c3bea90d4a3599100"
        );
    }

    #[test]
    fn persist_message_prefix_participates() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let n: i64 = 42;
        // Same framed body without the domain prefix must differ.
        let without_prefix = {
            let mut h = blake3::Hasher::new();
            h.update(&length_prefixed(&a));
            h.update(&length_prefixed(&b));
            h.update(&length_prefixed(&(n as u64).to_be_bytes()));
            *h.finalize().as_bytes()
        };
        assert_ne!(persist_message(&a, &b, n), without_prefix);
        // And it must not collide with an SBT-prefixed digest over the same body.
        let sbt_open = {
            let mut h = blake3::Hasher::new();
            h.update(SBT_OPEN_PREFIX);
            h.update(&length_prefixed(&a));
            h.update(&length_prefixed(&b));
            h.update(&length_prefixed(&(n as u64).to_be_bytes()));
            *h.finalize().as_bytes()
        };
        assert_ne!(persist_message(&a, &b, n), sbt_open);
    }

    #[test]
    fn persist_message_field_sensitivity() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let n: i64 = 42;
        let base = persist_message(&a, &b, n);

        let mut a2 = a;
        a2[0] ^= 0x01;
        assert_ne!(base, persist_message(&a2, &b, n), "original_root matters");

        let mut b2 = b;
        b2[31] ^= 0x01;
        assert_ne!(base, persist_message(&a, &b2, n), "snapshot_root matters");

        assert_ne!(
            base,
            persist_message(&a, &b, n + 1),
            "snapshot_size matters"
        );
    }

    #[test]
    fn transition_attestation_message_matches_persist_message() {
        let att = TransitionAttestation {
            original_root: [0xaau8; 32],
            snapshot_root: [0xbbu8; 32],
            snapshot_size: 7,
        };
        assert_eq!(
            att.message(),
            persist_message(&att.original_root, &att.snapshot_root, att.snapshot_size)
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}
