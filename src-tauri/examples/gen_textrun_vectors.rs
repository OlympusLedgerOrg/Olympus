// SPDX-License-Identifier: Apache-2.0

//! Cross-language test vectors for the ADR-0029 / RFC-0000 `pdf-textrun` format.
//!
//! ```text
//! cargo run -p olympus-desktop --features textrun-segmenter --example gen_textrun_vectors
//!   → verifiers/test_vectors/redaction_textrun_vectors.json
//! ```
//!
//! **Why this lives here and not beside the other redaction vectors.**
//! `crates/olympus-crypto/examples/gen_redaction_vectors.rs` hand-builds every
//! other format's fixture, which works because those artifacts are simple enough
//! to write out by hand. It cannot work for `pdf-textrun`: the artifact is a
//! rebuilt traditional-xref PDF whose exact bytes come from the segmenter's
//! re-emit, and the committed preimages include skeleton leaves whose encoding is
//! the segmenter's own. A hand-written fixture would be a *second* implementation
//! of the producer, in the one place whose whole job is to catch producer/verifier
//! divergence — so it would be pinning a fiction.
//!
//! (The old fixture was exactly that, and worse: it was never a valid PDF at all,
//! just a bare content-stream fragment. That was harmless while the format was
//! rejected outright, and useless the moment it was not.)
//!
//! So this generator drives the **real** [`PdfTextRunSegmenter`], and everything
//! it emits — artifact bytes, spans, leaves, skeleton preimages — is whatever the
//! producer actually produces. Both offline verifiers check themselves against it.
//!
//! Separate file rather than merging into `redaction_vectors.json` so there is no
//! ordering hazard between the two generators: running one can never clobber the
//! other's output.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use olympus_crypto::redaction::{
    derive_blinding, redaction_nullifier, redaction_signing_message, redaction_table_hash,
    RedactionTableEntry,
};

use olympus_tauri_lib::zk::segment::pdf_textrun::PdfTextRunSegmenter;
use olympus_tauri_lib::zk::segment::{SegmentManifest, Segmenter};

/// Same fixed seeds the sibling generator uses, so a verifier can load both files
/// under one issuer key.
const ED25519_SEED: [u8; 32] = [0x42; 32];
const BLIND_SECRET: [u8; 32] = [0x5a; 32];
const RECIPIENT_ID: &str = "55556";

/// A minimal but *real* modern PDF with **two** content-stream objects.
///
/// Two on purpose. `pdf_textrun_spans` assigns words `0..W-1` across *all*
/// content objects and only then the containers, so a single-content-object
/// fixture never exercises the cross-object part of that contract: if a verifier
/// interleaved words per object, or ordered containers differently, every leaf
/// would shift and nothing here would notice until a real two-stream PDF turned
/// up. With two, the id-assignment contract is pinned cross-language.
///
/// Both streams are Flate-compressed, which exercises the property that trips
/// people up: the skeleton is committed over the canonical RE-EMITTED body
/// (uncompressed, fresh `/Length`), not over these original bytes.
fn build_text_pdf(content_a: &[u8], content_b: &[u8]) -> Vec<u8> {
    fn zlib(data: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write as _;
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n");

    let off1 = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    let off2 = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    let off3 = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents [4 0 R 6 0 R] >>\nendobj\n",
    );

    let mut stream_obj = |buf: &mut Vec<u8>, id: u32, content: &[u8]| -> usize {
        let off = buf.len();
        let cs = zlib(content);
        buf.extend_from_slice(
            format!(
                "{id} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
                cs.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&cs);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        off
    };
    let off4 = stream_obj(&mut buf, 4, content_a);
    let off6 = stream_obj(&mut buf, 6, content_b);

    let off5 = buf.len();
    let mut rows: Vec<u8> = Vec::new();
    let mut push = |rows: &mut Vec<u8>, t: u8, a: u32, b: u16| {
        rows.push(t);
        rows.extend_from_slice(&a.to_be_bytes());
        rows.extend_from_slice(&b.to_be_bytes());
    };
    push(&mut rows, 0, 0, 65535);
    push(&mut rows, 1, off1 as u32, 0);
    push(&mut rows, 1, off2 as u32, 0);
    push(&mut rows, 1, off3 as u32, 0);
    push(&mut rows, 1, off4 as u32, 0);
    push(&mut rows, 1, off5 as u32, 0);
    push(&mut rows, 1, off6 as u32, 0);
    let xref = zlib(&rows);
    buf.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Root 1 0 R /Length {} /Filter /FlateDecode >>\nstream\n",
            xref.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(&xref);
    buf.extend_from_slice(b"\nendstream\nendobj\n");
    buf.extend_from_slice(format!("startxref\n{off5}\n%%EOF\n").as_bytes());
    buf
}

/// Build one signed V3 bundle by running the real producer end to end.
fn build_bundle(
    sk: &SigningKey,
    source: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> serde_json::Value {
    let (artifact, spans) = PdfTextRunSegmenter
        .apply_redaction_with_spans(source, manifest, redacted_ids)
        .expect("producer builds the artifact");
    let by_id: BTreeMap<u32, _> = spans.iter().map(|s| (s.segment_id, s)).collect();
    // Blinding is keyed by the ORIGINAL file's content hash, exactly as ingest
    // does — so a verifier recomputing a revealed leaf from the published
    // blinding lands on the committed value.
    let content_hash = blake3::hash(source);

    struct Row {
        segment_id: u32,
        redacted: bool,
        artifact_offset: u64,
        artifact_length: u64,
        value_text: String,
    }
    let rows: Vec<Row> = manifest
        .segments
        .iter()
        .map(|seg| {
            let span = by_id[&seg.segment_id];
            let redacted = redacted_ids.contains(&seg.segment_id);
            Row {
                segment_id: seg.segment_id,
                redacted,
                artifact_offset: span.artifact_offset,
                artifact_length: span.artifact_length,
                value_text: if redacted {
                    seg.leaf_hex.clone()
                } else {
                    derive_blinding(
                        &BLIND_SECRET,
                        content_hash.as_bytes(),
                        &seg.segment_id.to_be_bytes(),
                    )
                    .to_string()
                },
            }
        })
        .collect();

    let entries: Vec<RedactionTableEntry> = rows
        .iter()
        .map(|r| RedactionTableEntry {
            segment_id: r.segment_id,
            redacted: r.redacted,
            artifact_offset: r.artifact_offset,
            artifact_length: r.artifact_length,
            // `pdf-textrun` labels are producer-side UI text; the table commits
            // the empty label, matching every non-ooxml format.
            label: b"",
            value_text: &r.value_text,
        })
        .collect();
    let table_hash = redaction_table_hash(&entries);
    let n = rows.len() as u32;
    let payload = redaction_signing_message(
        &manifest.original_root_hex,
        "pdf-textrun",
        n,
        RECIPIENT_ID,
        &table_hash,
    );
    let signature = sk.sign(&payload);
    let mut root_raw = [0u8; 32];
    root_raw.copy_from_slice(&hex::decode(&manifest.original_root_hex).unwrap());
    let nullifier = redaction_nullifier(&root_raw, &table_hash, RECIPIENT_ID);

    let segments: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let mut o = serde_json::Map::new();
            o.insert("segment_id".into(), r.segment_id.into());
            o.insert("redacted".into(), r.redacted.into());
            o.insert("artifact_offset".into(), r.artifact_offset.into());
            o.insert("artifact_length".into(), r.artifact_length.into());
            let key = if r.redacted {
                "leaf_hex"
            } else {
                "blinding_decimal"
            };
            o.insert(key.into(), r.value_text.clone().into());
            serde_json::Value::Object(o)
        })
        .collect();

    serde_json::json!({
        "format": "pdf-textrun",
        "original_root": manifest.original_root_hex,
        "segment_count": n,
        "recipient_id": RECIPIENT_ID,
        "segments": segments,
        "table_hash_hex": hex::encode(table_hash),
        "nullifier": hex::encode(nullifier),
        "signature_hex": hex::encode(signature.to_bytes()),
        "artifact_hex": hex::encode(&artifact),
    })
}

fn main() {
    let sk = SigningKey::from_bytes(&ED25519_SEED);

    // Object 4 holds literal words AND a hex show-string, so both destruction
    // tokens are pinned. Object 6 holds distinct literal words, so the
    // cross-object id ordering is pinned too.
    let source = build_text_pdf(
        b"BT /F1 12 Tf 72 720 Td (public ALPHA secret) Tj <48656c6c6f> Tj ET",
        b"BT /F1 10 Tf 72 640 Td (second stream words) Tj ET",
    );
    let manifest = PdfTextRunSegmenter
        .extract(&source, &BLIND_SECRET)
        .expect("the fixture segments at word granularity");

    let word_count = manifest
        .segments
        .iter()
        .filter(|s| s.label.is_none())
        .count();
    assert!(word_count >= 4, "fixture must have literal and hex words");

    // Redact one literal word and the hex word: both destruction tokens exercised
    // in a single accepted bundle.
    let hex_word = (word_count - 1) as u32;
    let accepted = build_bundle(&sk, &source, &manifest, &[1, hex_word]);
    let none_redacted = build_bundle(&sk, &source, &manifest, &[]);

    let out = serde_json::json!({
        "description":
            "ADR-0029 / RFC-0000 pdf-textrun cross-language vectors. Generated by \
             src-tauri/examples/gen_textrun_vectors.rs from the REAL PdfTextRunSegmenter — \
             never hand-written, because a hand-written artifact would be a second \
             implementation of the producer in the one place meant to catch divergence.",
        "issuer_ed25519_pubkey_hex": hex::encode(sk.verifying_key().to_bytes()),
        "blind_secret_hex": hex::encode(BLIND_SECRET),
        "content_hash_hex": hex::encode(blake3::hash(&source).as_bytes()),
        "source_pdf_hex": hex::encode(&source),
        "word_count": word_count,
        "segment_count": manifest.segments.len(),
        "bundle": accepted,
        "none_redacted_bundle": none_redacted,
    });

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("verifiers/test_vectors/redaction_textrun_vectors.json");
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&out).unwrap()),
    )
    .expect("write vectors");
    eprintln!(
        "wrote {} ({} words + {} containers)",
        path.display(),
        word_count,
        manifest.segments.len() - word_count
    );
}
