//! Generate `verifiers/test_vectors/redaction_vectors.json` for the **ADR-0030
//! V3 signed-Merkle redaction bundle**, from the canonical
//! `olympus_crypto::redaction` primitives — the single source of truth shared by
//! the in-process producer (`src-tauri/.../api/redaction/bundle_v3.rs`) and the
//! cross-language offline verifiers (`verifiers/{rust,javascript}`).
//!
//! Run: `cargo run -p olympus-crypto --example gen_redaction_vectors --features redaction`
//!
//! The file MUST regenerate deterministically (run twice, diff — identical): the
//! Ed25519 signing key is a fixed seed and every scalar derives from the pinned
//! `blind_secret` / `content_hash` fixtures.
//!
//! What the vectors pin (ADR-0030 §1/§2/§3/§Security):
//! - the three V3 domain tags + the issuer Ed25519 public key,
//! - a valid revealed-segment bundle for **each of the 5 formats** (incl. the
//!   ADR-0029 Phase B `pdf-textrun` word-run format), carrying the
//!   artifact bytes (hex) so a verifier slices + applies the per-format
//!   `content_bytes` rule and recomputes the revealed leaf,
//! - variable-depth fold roots for N=2, N=3 (Fr(0) padding exercised), and
//!   N=1024 (asserted == the legacy fixed-1024 fold of the same leaves),
//! - all-redacted + none-redacted bundles (both verify),
//! - a byte-dump fixture (segment table → table_hash → signing payload →
//!   signature → nullifier),
//! - negatives (N=0/1/over-cap rejected; flip-flag breaks the signature),
//! - canonical-range negatives (leaf/recipient `< r`; blinding `< l`; reject, no
//!   mod-reduce), and a tampered-revealed-bytes vector (fold != original_root).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::{BigInt, BigUint};
use olympus_crypto::poseidon::poseidon_hash;
use olympus_crypto::redaction::{
    content_scalar, derive_blinding, redaction_leaf, redaction_nullifier,
    redaction_signing_message, redaction_table_hash, subgroup_order, RedactionTableEntry,
    REDACTION_BLIND_PREFIX, REDACTION_BUNDLE_V3_PREFIX, REDACTION_NULLIFIER_V1_PREFIX,
    REDACTION_TABLE_V3_PREFIX,
};

/// The legacy ADR-0025 fixed cap, retained ONLY to assert N=1024 parity in §3.
const LEGACY_MAX_LEAVES: usize = 1024;
const LEGACY_TREE_DEPTH: usize = 10;
const NODE_DOMAIN: u64 = 2; // domain_node(2, l, r) = Poseidon(Poseidon(2, l), r) — audit L-4 NODE=2 split

/// Pinned deterministic Ed25519 issuer seed — its verifying key is emitted so the
/// verifiers check signatures. NOT a production key.
const ED25519_SEED: [u8; 32] = [0x42; 32];
const BLIND_SECRET: [u8; 32] = [0x5a; 32];
const CONTENT_HASH: [u8; 32] = [0x11; 32];

/// BN254 scalar field modulus `r`.
fn bn254_r() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}

/// Fixed 32-byte big-endian lowercase hex of a field element.
fn fr_hex(f: Fr) -> String {
    let be = f.into_bigint().to_bytes_be();
    let mut p = [0u8; 32];
    p[32 - be.len()..].copy_from_slice(&be);
    hex::encode(p)
}

/// `Fr` from a 64-char lowercase-hex string (big-endian).
fn fr_from_hex(s: &str) -> Fr {
    let raw = hex::decode(s).expect("hex");
    Fr::from_be_bytes_mod_order(&raw)
}

/// Variable-depth fold (ADR-0030 §1): the N leaves in ascending segment_id order,
/// padded with `Fr(0)` to `2^⌈log2 N⌉`, folded with `domain_node(1, l, r)`. N must
/// be in [2, 2^20] (the caller enforces; this just folds). Reimplemented here from
/// `olympus_crypto::poseidon::poseidon_hash` because the production fold lives in
/// `src-tauri`, which the cross-language vectors cannot import.
fn variable_depth_fold(leaves: &[Fr]) -> Fr {
    assert!(leaves.len() >= 2, "N must be >= 2");
    let depth = (usize::BITS - (leaves.len() - 1).leading_zeros()) as usize; // ceil(log2 N)
    let width = 1usize << depth;
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(width, Fr::zero());
    for _ in 0..depth {
        level = level
            .chunks(2)
            .map(|p| poseidon_hash(poseidon_hash(Fr::from(NODE_DOMAIN), p[0]), p[1]))
            .collect();
    }
    level[0]
}

/// The legacy ADR-0025 fixed-1024 / depth-10 fold of the same leaves (used only to
/// assert N=1024 parity in §3).
fn legacy_fixed_fold(leaves: &[Fr]) -> Fr {
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(LEGACY_MAX_LEAVES, Fr::zero());
    for _ in 0..LEGACY_TREE_DEPTH {
        level = level
            .chunks(2)
            .map(|p| poseidon_hash(poseidon_hash(Fr::from(NODE_DOMAIN), p[0]), p[1]))
            .collect();
    }
    level[0]
}

/// A revealed segment the verifier reconstructs from artifact bytes.
struct Revealed<'a> {
    segment_id: u32,
    /// The `content_bytes` per ADR-0030 §3 (already the slice for plain-slice
    /// formats; for `pdf-xref-stream` it's the trimmed `obj…endobj` inner; for
    /// `ooxml-part` the leaf binds `lp(label) || payload`, handled below).
    content_bytes: &'a [u8],
    label: &'a str,
}

/// Compute a revealed leaf from its `(segment_id, content_bytes, label)`. For
/// `ooxml-part` the committed content is `lp(label) || payload` (ADR-0030 §3).
fn revealed_leaf(seg: &Revealed) -> (Fr, BigInt) {
    let id_be = seg.segment_id.to_be_bytes();
    let committed: Vec<u8> = if seg.label.is_empty() {
        seg.content_bytes.to_vec()
    } else {
        // ooxml-part: lp(label) || payload
        let mut v = Vec::new();
        v.extend_from_slice(&(seg.label.len() as u32).to_be_bytes());
        v.extend_from_slice(seg.label.as_bytes());
        v.extend_from_slice(seg.content_bytes);
        v
    };
    let content = content_scalar(&id_be, &committed);
    let blinding = derive_blinding(&BLIND_SECRET, &CONTENT_HASH, &id_be);
    let leaf = redaction_leaf(&content, &blinding).expect("revealed leaf");
    (leaf, blinding)
}

/// Compute a redacted leaf (Pedersen-blinded; the bytes are withheld so we commit
/// a placeholder content under the segment's deterministic blinding).
fn redacted_leaf(segment_id: u32, label: &str) -> Fr {
    let id_be = segment_id.to_be_bytes();
    let committed: Vec<u8> = if label.is_empty() {
        b"<<redacted>>".to_vec()
    } else {
        let mut v = Vec::new();
        v.extend_from_slice(&(label.len() as u32).to_be_bytes());
        v.extend_from_slice(label.as_bytes());
        v.extend_from_slice(b"<<redacted>>");
        v
    };
    let content = content_scalar(&id_be, &committed);
    let blinding = derive_blinding(&BLIND_SECRET, &CONTENT_HASH, &id_be);
    redaction_leaf(&content, &blinding).expect("redacted leaf")
}

/// A fully-assembled, signed positive bundle plus the JSON value describing it.
struct Bundle {
    json: serde_json::Value,
}

/// One segment as seen by the bundle JSON + the table-hash input.
struct SegSpec {
    segment_id: u32,
    redacted: bool,
    artifact_offset: u64,
    artifact_length: u64,
    label: String,
    /// revealed: blinding decimal; redacted: leaf hex.
    value_text: String,
    /// The leaf the fold uses (revealed: reconstructed; redacted: from leaf_hex).
    leaf: Fr,
}

/// Assemble + sign a bundle from its ordered segments. Computes the
/// variable-depth fold, table_hash, signing payload, signature, and nullifier.
fn build_bundle(
    sk: &SigningKey,
    format: &str,
    recipient_id_dec: &str,
    artifact: &[u8],
    segs: &[SegSpec],
) -> Bundle {
    let n = segs.len() as u32;
    let leaves: Vec<Fr> = segs.iter().map(|s| s.leaf).collect();
    let original_root = variable_depth_fold(&leaves);
    let original_root_hex = fr_hex(original_root);

    let entries: Vec<RedactionTableEntry> = segs
        .iter()
        .map(|s| RedactionTableEntry {
            segment_id: s.segment_id,
            redacted: s.redacted,
            artifact_offset: s.artifact_offset,
            artifact_length: s.artifact_length,
            label: s.label.as_bytes(),
            value_text: &s.value_text,
        })
        .collect();
    let table_hash = redaction_table_hash(&entries);
    let payload =
        redaction_signing_message(&original_root_hex, format, n, recipient_id_dec, &table_hash);
    let signature = sk.sign(&payload);
    let mut root_raw = [0u8; 32];
    root_raw.copy_from_slice(&hex::decode(&original_root_hex).unwrap());
    let nullifier = redaction_nullifier(&root_raw, &table_hash, recipient_id_dec);

    let segments_json: Vec<serde_json::Value> = segs
        .iter()
        .map(|s| {
            let mut o = serde_json::Map::new();
            o.insert("segment_id".into(), s.segment_id.into());
            o.insert("redacted".into(), s.redacted.into());
            o.insert("artifact_offset".into(), s.artifact_offset.into());
            o.insert("artifact_length".into(), s.artifact_length.into());
            if !s.label.is_empty() {
                o.insert("label".into(), s.label.clone().into());
            }
            if s.redacted {
                o.insert("leaf_hex".into(), s.value_text.clone().into());
            } else {
                o.insert("blinding_decimal".into(), s.value_text.clone().into());
            }
            serde_json::Value::Object(o)
        })
        .collect();

    let json = serde_json::json!({
        "original_root": original_root_hex,
        "format": format,
        "segment_count": n,
        "recipient_id": recipient_id_dec,
        "artifact_hex": hex::encode(artifact),
        "segments": segments_json,
        "table_hash_hex": hex::encode(table_hash),
        "nullifier": hex::encode(nullifier),
        "signature_hex": hex::encode(signature.to_bytes()),
    });
    Bundle { json }
}

fn main() {
    let sk = SigningKey::from_bytes(&ED25519_SEED);
    let issuer_pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

    // ── Per-format positive bundles ─────────────────────────────────────────
    // Each carries an artifact (hex) with a revealed segment whose bytes the
    // verifier slices + reconstructs. A second segment is redacted to exercise
    // the partition + leaf_hex branch (and keep N >= 2).

    let format_bundles = build_format_bundles(&sk);

    // ── Variable-depth fold roots: N=2, N=3, N=1024 (+ legacy parity) ────────
    let fold_vectors = build_fold_vectors();

    // ── all-redacted + none-redacted bundles (both must verify) ──────────────
    let all_redacted = build_all_redacted(&sk);
    let none_redacted = build_none_redacted(&sk);

    // ── Byte-dump fixture (table_hash → payload → signature → nullifier) ─────
    let byte_dump = build_byte_dump(&sk);

    // ── Negative vectors ─────────────────────────────────────────────────────
    let negatives = build_negatives(&sk, &format_bundles);

    let out = serde_json::json!({
        "scheme": "redaction-signed-merkle-adr0030-v3",
        "domain_tags": {
            "bundle": String::from_utf8_lossy(REDACTION_BUNDLE_V3_PREFIX),
            "table": String::from_utf8_lossy(REDACTION_TABLE_V3_PREFIX),
            "nullifier": String::from_utf8_lossy(REDACTION_NULLIFIER_V1_PREFIX),
            "blind": String::from_utf8_lossy(REDACTION_BLIND_PREFIX),
        },
        "obj_domain": olympus_crypto::POSEIDON_DOMAIN_OBJ_LEAF,
        "node_domain": NODE_DOMAIN,
        "max_redaction_segments": 1u32 << 20,
        "blind_secret_hex": hex::encode(BLIND_SECRET),
        "content_hash_hex": hex::encode(CONTENT_HASH),
        "issuer_ed25519_pubkey_hex": issuer_pubkey_hex,
        "format_bundles": format_bundles,
        "fold_vectors": fold_vectors,
        "all_redacted_bundle": all_redacted.json,
        "none_redacted_bundle": none_redacted.json,
        "byte_dump": byte_dump,
        "negatives": negatives,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verifiers/test_vectors/redaction_vectors.json"
    );
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&out).unwrap()),
    )
    .expect("write redaction_vectors.json");
    eprintln!("wrote {path}");
}

/// Build one signed bundle per format. Each has a real revealed segment whose
/// `content_bytes` are sliceable from the artifact per ADR-0030 §3, plus a
/// redacted second segment.
fn build_format_bundles(sk: &SigningKey) -> serde_json::Value {
    let mut bundles = serde_json::Map::new();

    // ---- pdf-object: content_bytes = full untrimmed `N G obj … endobj` span ----
    {
        // Artifact layout: a prefix, then obj 1's full span (revealed), then obj 4
        // redacted (NUL-filled in place). The revealed slice is the literal span.
        let obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        let prefix = b"%PDF-1.7\n";
        let obj4_redacted = b"4 0 obj\n\x00\x00\x00\x00\x00\x00\x00\nendobj\n";
        let mut artifact = Vec::new();
        artifact.extend_from_slice(prefix);
        let off1 = artifact.len() as u64;
        artifact.extend_from_slice(obj1);
        let len1 = obj1.len() as u64;
        artifact.extend_from_slice(obj4_redacted);

        let rev = Revealed {
            segment_id: 1,
            content_bytes: obj1,
            label: "",
        };
        let (leaf1, b1) = revealed_leaf(&rev);
        let leaf4 = redacted_leaf(4, "");
        let segs = vec![
            SegSpec {
                segment_id: 1,
                redacted: false,
                artifact_offset: off1,
                artifact_length: len1,
                label: String::new(),
                value_text: b1.to_string(),
                leaf: leaf1,
            },
            SegSpec {
                segment_id: 4,
                redacted: true,
                artifact_offset: 0,
                artifact_length: 0,
                label: String::new(),
                value_text: fr_hex(leaf4),
                leaf: leaf4,
            },
        ];
        let b = build_bundle(sk, "pdf-object", "11111", &artifact, &segs);
        bundles.insert("pdf-object".into(), b.json);
    }

    // ---- text-line: content_bytes = the line slice INCLUDING the trailing \n ----
    {
        // Lines: "alpha\n" (revealed, id 0), "secret\n" (redacted, id 1, NUL-filled).
        let line0 = b"alpha\n";
        let mut artifact = Vec::new();
        let off0 = artifact.len() as u64;
        artifact.extend_from_slice(line0);
        let len0 = line0.len() as u64;
        artifact.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00"); // redacted "secret\n"

        let rev = Revealed {
            segment_id: 0,
            content_bytes: line0,
            label: "",
        };
        let (leaf0, b0) = revealed_leaf(&rev);
        let leaf1 = redacted_leaf(1, "");
        let segs = vec![
            SegSpec {
                segment_id: 0,
                redacted: false,
                artifact_offset: off0,
                artifact_length: len0,
                label: String::new(),
                value_text: b0.to_string(),
                leaf: leaf0,
            },
            SegSpec {
                segment_id: 1,
                redacted: true,
                artifact_offset: 0,
                artifact_length: 0,
                label: String::new(),
                value_text: fr_hex(leaf1),
                leaf: leaf1,
            },
        ];
        let b = build_bundle(sk, "text-line", "22222", &artifact, &segs);
        bundles.insert("text-line".into(), b.json);
    }

    // ---- pdf-xref-stream: signed range is the full obj…endobj span; the verifier
    // locates inner = slice[find("obj")+3 .. rfind("endobj")] then trims with the
    // pinned whitespace set {0x20,0x09,0x0d,0x0a,0x0c,0x00}. ----
    {
        // The full span has leading/trailing whitespace (incl. a NUL and form-feed)
        // around the inner body so the trim is actually exercised.
        let inner = b"<< /Type /Page /Parent 2 0 R >>";
        // span = "7 0 obj" + WS + inner + WS + "endobj"
        let mut span = Vec::new();
        span.extend_from_slice(b"7 0 obj");
        span.extend_from_slice(&[0x20, 0x09, 0x0d, 0x0a]); // leading ws after "obj"
        span.extend_from_slice(inner);
        span.extend_from_slice(&[0x0c, 0x00, 0x0a]); // trailing ws (form-feed, NUL, lf)
        span.extend_from_slice(b"endobj");

        let prefix = b"%PDF-1.7 xref-stream\n";
        let mut artifact = Vec::new();
        artifact.extend_from_slice(prefix);
        let off = artifact.len() as u64;
        artifact.extend_from_slice(&span);
        let len = span.len() as u64;
        // redacted obj rebuilt with literal token `null`
        artifact.extend_from_slice(b"\n9 0 obj null endobj\n");

        // content_bytes for the leaf = trim(inner) == inner (inner has no edge ws)
        let rev = Revealed {
            segment_id: 7,
            content_bytes: inner,
            label: "",
        };
        let (leaf7, b7) = revealed_leaf(&rev);
        let leaf9 = redacted_leaf(9, "");
        let segs = vec![
            SegSpec {
                segment_id: 7,
                redacted: false,
                artifact_offset: off,
                artifact_length: len,
                label: String::new(),
                value_text: b7.to_string(),
                leaf: leaf7,
            },
            SegSpec {
                segment_id: 9,
                redacted: true,
                artifact_offset: 0,
                artifact_length: 0,
                label: String::new(),
                value_text: fr_hex(leaf9),
                leaf: leaf9,
            },
        ];
        let b = build_bundle(sk, "pdf-xref-stream", "33333", &artifact, &segs);
        bundles.insert("pdf-xref-stream".into(), b.json);
    }

    // ---- ooxml-part: dense ids 0..N-1, every entry labelled; content_bytes is the
    // raw Stored payload at the local-file DATA offset; the leaf binds lp(label)||payload. ----
    {
        let payload0 = b"<?xml version=\"1.0\"?><Types/>";
        let label0 = "[Content_Types].xml";
        let label1 = "word/document.xml";
        // Artifact: a (fake) local-header region, then the DATA payload of part 0
        // (revealed), then part 1's payload region (redacted → emitted empty).
        let mut artifact = Vec::new();
        artifact.extend_from_slice(b"PK..local-header-bytes.."); // pre-DATA
        let off0 = artifact.len() as u64;
        artifact.extend_from_slice(payload0);
        let len0 = payload0.len() as u64;
        artifact.extend_from_slice(b"PK..local-header-1.."); // part 1 header; empty body

        let rev = Revealed {
            segment_id: 0,
            content_bytes: payload0,
            label: label0,
        };
        let (leaf0, b0) = revealed_leaf(&rev);
        let leaf1 = redacted_leaf(1, label1);
        let segs = vec![
            SegSpec {
                segment_id: 0,
                redacted: false,
                artifact_offset: off0,
                artifact_length: len0,
                label: label0.to_string(),
                value_text: b0.to_string(),
                leaf: leaf0,
            },
            SegSpec {
                segment_id: 1,
                redacted: true,
                artifact_offset: 0,
                artifact_length: 0,
                label: label1.to_string(),
                value_text: fr_hex(leaf1),
                leaf: leaf1,
            },
        ];
        let b = build_bundle(sk, "ooxml-part", "44444", &artifact, &segs);
        bundles.insert("ooxml-part".into(), b.json);
    }

    // ---- pdf-textrun: content_bytes = the raw word slice (ADR-0029 Phase B word-
    // run redaction). A revealed word (id 0) is sliced verbatim from the rebuilt
    // content stream; a second word (id 1) is redacted (omitted → span (0,0),
    // leaf_hex authoritative). Same plain-slice rule as text-line / pdf-object. ----
    {
        let word0 = b"alpha";
        let mut artifact = Vec::new();
        artifact.extend_from_slice(b"BT /F1 12 Tf 72 720 Td ("); // content-stream prefix
        let off0 = artifact.len() as u64;
        artifact.extend_from_slice(word0);
        let len0 = word0.len() as u64;
        artifact.extend_from_slice(b" ) Tj ET"); // remainder; the redacted word is omitted

        let rev = Revealed {
            segment_id: 0,
            content_bytes: word0,
            label: "",
        };
        let (leaf0, b0) = revealed_leaf(&rev);
        let leaf1 = redacted_leaf(1, "");
        let segs = vec![
            SegSpec {
                segment_id: 0,
                redacted: false,
                artifact_offset: off0,
                artifact_length: len0,
                label: String::new(),
                value_text: b0.to_string(),
                leaf: leaf0,
            },
            SegSpec {
                segment_id: 1,
                redacted: true,
                artifact_offset: 0,
                artifact_length: 0,
                label: String::new(),
                value_text: fr_hex(leaf1),
                leaf: leaf1,
            },
        ];
        let b = build_bundle(sk, "pdf-textrun", "55556", &artifact, &segs);
        bundles.insert("pdf-textrun".into(), b.json);
    }

    serde_json::Value::Object(bundles)
}

/// N=2, N=3 (Fr(0) padding exercised), N=1024 fold roots, plus the legacy
/// fixed-1024 parity assertion for N=1024.
fn build_fold_vectors() -> serde_json::Value {
    // Deterministic synthetic leaves keyed by a counter; values are real
    // hiding leaves so the verifier can recompute them from leaf_hex parity.
    let leaf_for = |i: u32| -> Fr {
        let id = i.to_be_bytes();
        let content = content_scalar(&id, format!("leaf-content-{i}").as_bytes());
        let blinding = derive_blinding(&BLIND_SECRET, &CONTENT_HASH, &id);
        redaction_leaf(&content, &blinding).expect("fold leaf")
    };

    let mk = |n: u32| -> serde_json::Value {
        let leaves: Vec<Fr> = (0..n).map(leaf_for).collect();
        let root = variable_depth_fold(&leaves);
        let depth = u32::BITS - (n - 1).leading_zeros();
        serde_json::json!({
            "n": n,
            "depth": depth,
            "leaves_hex": leaves.iter().map(|l| fr_hex(*l)).collect::<Vec<_>>(),
            "root_hex": fr_hex(root),
        })
    };

    let n1024 = {
        let leaves: Vec<Fr> = (0..1024u32).map(leaf_for).collect();
        let var_root = variable_depth_fold(&leaves);
        let legacy_root = legacy_fixed_fold(&leaves);
        assert_eq!(
            var_root, legacy_root,
            "N=1024 variable-depth fold must equal the legacy fixed-1024 fold"
        );
        serde_json::json!({
            "n": 1024,
            "depth": 10,
            // The leaves are emitted (folding 1024 bigints with Poseidon is cheap;
            // regenerating 1024 Pedersen commits in a pure-bigint JS verifier is
            // not). Each is the canonical hiding leaf for `leaf-content-{i}` under
            // the pinned blind_secret/content_hash.
            "leaf_rule": "redaction_leaf(content_scalar(be32(i), 'leaf-content-{i}'), derive_blinding(blind_secret, content_hash, be32(i)))",
            "leaves_hex": leaves.iter().map(|l| fr_hex(*l)).collect::<Vec<_>>(),
            "root_hex": fr_hex(var_root),
            "legacy_fixed_1024_root_hex": fr_hex(legacy_root),
            "parity": var_root == legacy_root,
        })
    };

    serde_json::json!({
        "n2": mk(2),
        "n3": mk(3),
        "n1024": n1024,
    })
}

fn build_all_redacted(sk: &SigningKey) -> Bundle {
    let l0 = redacted_leaf(0, "");
    let l1 = redacted_leaf(1, "");
    let segs = vec![
        SegSpec {
            segment_id: 0,
            redacted: true,
            artifact_offset: 0,
            artifact_length: 0,
            label: String::new(),
            value_text: fr_hex(l0),
            leaf: l0,
        },
        SegSpec {
            segment_id: 1,
            redacted: true,
            artifact_offset: 0,
            artifact_length: 0,
            label: String::new(),
            value_text: fr_hex(l1),
            leaf: l1,
        },
    ];
    build_bundle(sk, "text-line", "55555", b"\x00\x00", &segs)
}

fn build_none_redacted(sk: &SigningKey) -> Bundle {
    let line0 = b"first line\n";
    let line1 = b"second line\n";
    let mut artifact = Vec::new();
    let off0 = artifact.len() as u64;
    artifact.extend_from_slice(line0);
    let len0 = line0.len() as u64;
    let off1 = artifact.len() as u64;
    artifact.extend_from_slice(line1);
    let len1 = line1.len() as u64;

    let r0 = Revealed {
        segment_id: 0,
        content_bytes: line0,
        label: "",
    };
    let (leaf0, b0) = revealed_leaf(&r0);
    let r1 = Revealed {
        segment_id: 1,
        content_bytes: line1,
        label: "",
    };
    let (leaf1, b1) = revealed_leaf(&r1);
    let segs = vec![
        SegSpec {
            segment_id: 0,
            redacted: false,
            artifact_offset: off0,
            artifact_length: len0,
            label: String::new(),
            value_text: b0.to_string(),
            leaf: leaf0,
        },
        SegSpec {
            segment_id: 1,
            redacted: false,
            artifact_offset: off1,
            artifact_length: len1,
            label: String::new(),
            value_text: b1.to_string(),
            leaf: leaf1,
        },
    ];
    build_bundle(sk, "text-line", "66666", &artifact, &segs)
}

/// The byte-dump fixture: the exact 2-segment sparse example from the
/// `redaction.rs` golden tests (segment 1 revealed, segment 4 redacted with an
/// ooxml-style label). Emits table_hash → signing payload → signature → nullifier
/// so a from-spec verifier self-checks the byte layout end to end.
fn build_byte_dump(sk: &SigningKey) -> serde_json::Value {
    let original_root_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let recipient_dec = "98765432109876543210";
    let format = "ooxml-part";
    let entries = [
        RedactionTableEntry {
            segment_id: 1,
            redacted: false,
            artifact_offset: 0,
            artifact_length: 17,
            label: b"",
            value_text: "12345678901234567890",
        },
        RedactionTableEntry {
            segment_id: 4,
            redacted: true,
            artifact_offset: 64,
            artifact_length: 0,
            label: b"word/document.xml",
            value_text: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    ];
    let table_hash = redaction_table_hash(&entries);
    let payload =
        redaction_signing_message(original_root_hex, format, 2, recipient_dec, &table_hash);
    let signature = sk.sign(&payload);
    let mut root_raw = [0u8; 32];
    root_raw.copy_from_slice(&hex::decode(original_root_hex).unwrap());
    let nullifier = redaction_nullifier(&root_raw, &table_hash, recipient_dec);

    let seg_json: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let mut o = serde_json::Map::new();
            o.insert("segment_id".into(), e.segment_id.into());
            o.insert("redacted".into(), e.redacted.into());
            o.insert("artifact_offset".into(), e.artifact_offset.into());
            o.insert("artifact_length".into(), e.artifact_length.into());
            if !e.label.is_empty() {
                o.insert(
                    "label".into(),
                    String::from_utf8_lossy(e.label).to_string().into(),
                );
            }
            if e.redacted {
                o.insert("leaf_hex".into(), e.value_text.into());
            } else {
                o.insert("blinding_decimal".into(), e.value_text.into());
            }
            serde_json::Value::Object(o)
        })
        .collect();

    serde_json::json!({
        "original_root": original_root_hex,
        "format": format,
        "segment_count": 2,
        "recipient_id": recipient_dec,
        "segments": seg_json,
        "table_hash_hex": hex::encode(table_hash),
        "signing_payload_hex": hex::encode(&payload),
        "signature_hex": hex::encode(signature.to_bytes()),
        "nullifier": hex::encode(nullifier),
    })
}

/// Negative vectors — each labelled with the reason a verifier must reject.
fn build_negatives(sk: &SigningKey, format_bundles: &serde_json::Value) -> serde_json::Value {
    let r = bn254_r();
    let l = subgroup_order();
    let l_biguint = match l.to_biguint() {
        Some(b) => b,
        None => unreachable!(),
    };

    // r-1 / l-1 canonical accepts, r / l rejects.
    let r_dec = r.to_string();
    let r_minus_1_dec = (&r - 1u32).to_string();
    let l_dec = l_biguint.to_string();
    let l_minus_1_dec = (&l_biguint - 1u32).to_string();
    // Hex of r and r-1 (32-byte big-endian).
    let to_hex32 = |b: &BigUint| -> String {
        let be = b.to_bytes_be();
        let mut p = [0u8; 32];
        p[32 - be.len()..].copy_from_slice(&be);
        hex::encode(p)
    };
    let r_hex = to_hex32(&r);
    let r_minus_1_hex = to_hex32(&(&r - 1u32));

    // ── flip-flag: take the valid text-line bundle, flip segment 0 redacted flag.
    // The signature MUST then fail (table_hash changes). We keep the rest of the
    // bundle (including the now-stale signature) intact.
    let flip_flag = {
        let base = format_bundles
            .get("text-line")
            .expect("text-line bundle")
            .clone();
        let mut b = base.clone();
        let segs = b.get_mut("segments").unwrap().as_array_mut().unwrap();
        // segment 0 was revealed; flip to redacted but DO NOT re-sign. To stay
        // structurally valid (a redacted seg needs leaf_hex, not blinding) we
        // swap the fields: drop blinding_decimal, add the reconstructed leaf_hex.
        let seg0 = segs[0].as_object_mut().unwrap();
        seg0.insert("redacted".into(), true.into());
        // Reconstruct the revealed leaf to supply a valid leaf_hex (so the bundle
        // is structurally well-formed; only the signature check must fail).
        let line0 = b"alpha\n";
        let rev = Revealed {
            segment_id: 0,
            content_bytes: line0,
            label: "",
        };
        let (leaf0, _) = revealed_leaf(&rev);
        seg0.remove("blinding_decimal");
        seg0.insert("leaf_hex".into(), fr_hex(leaf0).into());
        b
    };

    // ── tampered-revealed-bytes: alter the revealed artifact bytes of the
    // text-line bundle; the recomputed fold must != original_root.
    let tampered_bytes = {
        let base = format_bundles
            .get("text-line")
            .expect("text-line bundle")
            .clone();
        let mut b = base.clone();
        let artifact_hex = b.get("artifact_hex").unwrap().as_str().unwrap();
        let mut artifact = hex::decode(artifact_hex).unwrap();
        artifact[0] ^= 0xff; // flip first byte of the revealed slice
        b.as_object_mut()
            .unwrap()
            .insert("artifact_hex".into(), hex::encode(&artifact).into());
        b
    };

    // Helper: a minimal valid 2-seg bundle parameterised so the canonical-range
    // negatives can mutate a single field.
    let mk_pair =
        |recipient: &str, seg0_blinding: &str, seg1_leaf_hex: &str| -> serde_json::Value {
            // Use real leaves so the *valid* sibling truly verifies; for the reject
            // sibling the verifier rejects on the range check before folding.
            let line0 = b"alpha\n";
            let id0_be = 0u32.to_be_bytes();
            let content0 = content_scalar(&id0_be, line0);
            let real_b0 = derive_blinding(&BLIND_SECRET, &CONTENT_HASH, &id0_be);
            let leaf1 = redacted_leaf(1, "");
            // The published seg0 `blinding_decimal` and the folded seg0 leaf MUST agree:
            // for an accept vector (an in-range blinding) the verifier recomputes the
            // leaf from that very blinding, so the fold matches original_root. For a
            // reject vector (out-of-range blinding) the verifier rejects on the range
            // check BEFORE folding, so the leaf value is immaterial — we fold under the
            // real blinding only to keep `original_root` well-formed.
            let b0 = if seg0_blinding == "REAL" {
                real_b0.to_string()
            } else {
                seg0_blinding.to_string()
            };
            // Parse the published blinding back to a scalar; if it's in range, fold the
            // leaf under it (accept path stays consistent), else fall back to real_b0.
            let b0_scalar =
                BigInt::parse_bytes(b0.as_bytes(), 10).unwrap_or_else(|| real_b0.clone());
            let leaf0 = redaction_leaf(&content0, &b0_scalar)
                .unwrap_or_else(|_| redaction_leaf(&content0, &real_b0).unwrap());
            let l1 = if seg1_leaf_hex == "REAL" {
                fr_hex(leaf1)
            } else {
                seg1_leaf_hex.to_string()
            };
            let leaf1_used = if seg1_leaf_hex == "REAL" {
                leaf1
            } else {
                fr_from_hex(seg1_leaf_hex)
            };
            let segs = vec![
                SegSpec {
                    segment_id: 0,
                    redacted: false,
                    artifact_offset: 0,
                    artifact_length: line0.len() as u64,
                    label: String::new(),
                    value_text: b0,
                    leaf: leaf0,
                },
                SegSpec {
                    segment_id: 1,
                    redacted: true,
                    artifact_offset: 0,
                    artifact_length: 0,
                    label: String::new(),
                    value_text: l1,
                    leaf: leaf1_used,
                },
            ];
            // For range-reject vectors, recipient may be out of range; build_bundle
            // signs whatever it's given (the verifier rejects pre-fold).
            build_bundle(sk, "text-line", recipient, line0, &segs).json
        };

    // recipient_id == r (reject) vs r-1 (accept)
    let recipient_r_reject = mk_pair(&r_dec, "REAL", "REAL");
    let recipient_r_minus_1_accept = mk_pair(&r_minus_1_dec, "REAL", "REAL");

    // blinding_decimal == l (reject) vs l-1 (accept). The bundle's seg0 blinding
    // is the mutated value; only the canonical-range check fires.
    let blinding_l_reject = mk_pair("77777", &l_dec, "REAL");
    let blinding_l_minus_1_accept = mk_pair("77777", &l_minus_1_dec, "REAL");

    // leaf_hex == r (reject) vs r-1 (accept) on the redacted segment.
    let leaf_r_reject = mk_pair("88888", "REAL", &r_hex);
    let leaf_r_minus_1_accept = mk_pair("88888", "REAL", &r_minus_1_hex);

    serde_json::json!({
        "n0_rejected": {
            "reason": "segment_count == 0 (ADR-0030 §1: N must be >= 2)",
            "segment_count": 0,
            "segments": [],
        },
        "n1_rejected": {
            "reason": "segment_count == 1 (ADR-0030 §1: N must be >= 2)",
            "segment_count": 1,
            "segments": [{
                "segment_id": 0, "redacted": false,
                "artifact_offset": 0, "artifact_length": 1,
                "blinding_decimal": "1"
            }],
        },
        "over_cap_rejected": {
            "reason": "segment_count > MAX_REDACTION_SEGMENTS (2^20); verifier rejects on the count BEFORE allocating leaves",
            "segment_count": (1u32 << 20) + 1,
            "note": "segments[] intentionally NOT materialized — the reject is on the declared count",
        },
        "flip_flag_signature_fails": {
            "reason": "segment 0's redacted flag flipped on an otherwise-valid bundle; table_hash changes so the (stale) Ed25519 signature MUST fail",
            "bundle": flip_flag,
        },
        "tampered_revealed_bytes_fold_mismatch": {
            "reason": "a revealed segment's artifact bytes were altered; recomputed fold MUST != original_root",
            "bundle": tampered_bytes,
        },
        "canonical_range": {
            "recipient_id_equals_r_rejected": {
                "reason": "recipient_id == r is not a canonical field element (< r); reject, do not mod-reduce",
                "value_dec": r_dec,
                "bundle": recipient_r_reject,
            },
            "recipient_id_equals_r_minus_1_accepted": {
                "reason": "recipient_id == r-1 is canonical (< r); must verify",
                "value_dec": r_minus_1_dec,
                "bundle": recipient_r_minus_1_accept,
            },
            "blinding_equals_l_rejected": {
                "reason": "blinding_decimal == l (BJJ subgroup order) is out of [0,l); reject, do not mod-reduce",
                "value_dec": l_dec,
                "bundle": blinding_l_reject,
            },
            "blinding_equals_l_minus_1_accepted": {
                "reason": "blinding_decimal == l-1 is in [0,l); must verify",
                "value_dec": l_minus_1_dec,
                "bundle": blinding_l_minus_1_accept,
            },
            "leaf_hex_equals_r_rejected": {
                "reason": "leaf_hex decoding to exactly r is not < r; reject, do not mod-reduce",
                "value_hex": r_hex,
                "bundle": leaf_r_reject,
            },
            "leaf_hex_equals_r_minus_1_accepted": {
                "reason": "leaf_hex decoding to r-1 is canonical (< r); must verify",
                "value_hex": r_minus_1_hex,
                "bundle": leaf_r_minus_1_accept,
            },
        },
    })
}
