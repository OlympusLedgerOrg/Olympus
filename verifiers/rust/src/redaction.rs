//! ADR-0030 **V3 signed-Merkle redaction bundle** offline verifier (Phase 3).
//!
//! Independent Rust re-fold + re-verify of the cross-language vectors in
//! `verifiers/test_vectors/redaction_vectors.json`, mirroring ADR-0030 §3:
//!
//!   1. structural checks (N == len, 2 ≤ N ≤ 2²⁰, strictly-ascending-unique ids,
//!      ooxml-part dense 0..N-1 + a label per entry),
//!   2. per-format revealed-leaf reconstruction (slice + the §3 `content_bytes`
//!      rule per format),
//!   3. the variable-depth fold (pad `Fr(0)` to `2^⌈log2 N⌉`; `domain_node(2,…)`)
//!      == `original_root`,
//!   4. recompute `table_hash` + the signing payload, verify the Ed25519 issuer
//!      signature, recompute + check the `nullifier`,
//!   plus the canonical-form REJECT rules (no `% l`/`% r` reduction — out-of-range
//!   `leaf_hex` / `blinding_decimal` / `recipient_id` are hard-rejected).
//!
//! Poseidon: the vendored `light-poseidon` (the same impl `olympus_crypto`'s
//! `poseidon_hash` is pinned against). Pedersen: this crate's [`crate::pedersen`]
//! Baby Jubjub code. The genuinely-independent cross-check is the JavaScript
//! (circomlibjs) verifier; this Rust leg independently re-folds + re-verifies the
//! *same* vectors against a second Poseidon/Ed25519 stack.

use std::collections::{BTreeMap, HashSet};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use num_bigint::BigUint;

use crate::pedersen::{parse_dec, Curve};

const OBJ_DOMAIN: &[u8] = b"OLY:REDACTION:OBJ:V1";
const BUNDLE_V3_PREFIX: &[u8] = b"OLY:REDACTION_BUNDLE:V3";
const TABLE_V3_PREFIX: &[u8] = b"OLY:REDACTION:TABLE:V3";
const NULLIFIER_V1_PREFIX: &[u8] = b"OLY:REDACTION:NULLIFIER:V1";

const MAX_REDACTION_SEGMENTS: u64 = 1 << 20;
const FORMATS: [&str; 5] = [
    "pdf-object",
    "pdf-xref-stream",
    "text-line",
    "ooxml-part",
    "pdf-textrun",
];
const REDACTION_TEXT_TOKEN: &[u8] = b"[REDACTED]\n";
/// pdf-xref-stream trim charset (ADR-0030 §3): SP, TAB, CR, LF, FF, NUL. Includes
/// NUL (0x00) and FF (0x0c), which Rust `is_ascii_whitespace` EXCLUDES — hardcode.
const PDF_WS: [u8; 6] = [0x20, 0x09, 0x0d, 0x0a, 0x0c, 0x00];
const ZIP_LOCAL: &[u8; 4] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8; 4] = b"PK\x01\x02";
const ZIP_EOCD: &[u8; 4] = b"PK\x05\x06";

/// A V3 segment row, as carried in the JSON bundle.
#[derive(Debug, Clone)]
pub struct Segment {
    pub segment_id: u32,
    pub redacted: bool,
    pub artifact_offset: u64,
    pub artifact_length: u64,
    pub label: Option<String>,
    pub blinding_decimal: Option<String>,
    pub leaf_hex: Option<String>,
}

/// A V3 bundle. `artifact_hex` is the redacted artifact bytes (present for the
/// fold-bearing vectors; absent for the byte-dump layout fixture).
#[derive(Debug, Clone)]
pub struct Bundle {
    pub original_root: String,
    pub format: String,
    pub segment_count: u64,
    pub recipient_id: String,
    pub artifact_hex: Option<String>,
    pub segments: Vec<Segment>,
    pub nullifier: String,
    pub signature_hex: String,
}

/// Verification failure with a stable reason string (asserted by the tests).
#[derive(Debug, PartialEq, Eq)]
pub struct RejectReason(pub &'static str);

type VResult = Result<(), RejectReason>;

fn reject(r: &'static str) -> VResult {
    Err(RejectReason(r))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactSpan {
    segment_id: u32,
    offset: u64,
    length: u64,
    label: Option<String>,
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn lp(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + b.len());
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
    v
}

fn bn254_r() -> BigUint {
    parse_dec("21888242871839275222246405745257275088548364400416034343698204186575808495617")
        .unwrap()
}

fn bjj_l() -> BigUint {
    parse_dec("2736030358979909402780800718157159386076813972158567259200215660948447373041")
        .unwrap()
}

/// 32-byte big-endian of a `BigUint` (must fit in 32 bytes).
fn biguint_to_be32(n: &BigUint) -> [u8; 32] {
    let be = n.to_bytes_be();
    let mut p = [0u8; 32];
    p[32 - be.len()..].copy_from_slice(&be);
    p
}

/// 32-byte big-endian lowercase hex of an `Fr`.
fn fr_to_hex(f: &Fr) -> String {
    hex::encode(biguint_to_be32(&BigUint::from_bytes_be(
        &f.into_bigint().to_bytes_be(),
    )))
}

// ── canonical-form validators (REJECT, do not reduce) ─────────────────────────

fn is_canonical_decimal(s: &str) -> bool {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !(s.len() > 1 && s.starts_with('0'))
}

fn valid_recipient(s: &str) -> bool {
    is_canonical_decimal(s) && parse_dec(s).map(|v| v < bn254_r()).unwrap_or(false)
}

fn valid_blinding(s: &str) -> bool {
    is_canonical_decimal(s) && parse_dec(s).map(|v| v < bjj_l()).unwrap_or(false)
}

fn valid_field_hex(s: &str) -> bool {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    match hex::decode(s) {
        Ok(raw) => BigUint::from_bytes_be(&raw) < bn254_r(),
        Err(_) => false,
    }
}

// ── Poseidon + Pedersen + fold (mirror olympus_crypto::redaction) ─────────────

/// `Poseidon(a, b)` (circom 2-input, domain 0) — equals `olympus_crypto::poseidon_hash`.
fn poseidon2(a: &Fr, b: &Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom poseidon");
    let bytes = h
        .hash_bytes_be(&[
            &a.into_bigint().to_bytes_be(),
            &b.into_bigint().to_bytes_be(),
        ])
        .expect("poseidon hash");
    Fr::from_be_bytes_mod_order(&bytes)
}

/// `domain_node(d, l, r) = Poseidon(Poseidon(d, l), r)`.
fn domain_node(d: u64, left: &Fr, right: &Fr) -> Fr {
    let inner = poseidon2(&Fr::from(d), left);
    poseidon2(&inner, right)
}

/// Variable-depth fold (ADR-0030 §1): pad `Fr(0)` to `2^⌈log2 N⌉`, fold domain 2.
fn variable_depth_fold(leaves: &[Fr]) -> Result<Fr, RejectReason> {
    if leaves.len() < 2 {
        return Err(RejectReason("fold requires >= 2 leaves"));
    }
    let n = leaves.len();
    let depth = (usize::BITS - (n - 1).leading_zeros()) as usize;
    let width = 1usize << depth;
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(width, Fr::zero());
    for _ in 0..depth {
        level = level
            .chunks(2)
            .map(|p| domain_node(2, &p[0], &p[1])) // NODE=2 (audit L-4 split)
            .collect();
    }
    Ok(level[0])
}

/// `content = reduce_l( BLAKE3_XOF(OBJ_DOMAIN || lp(u32_be(id)) || content_bytes)[..64] )`.
fn content_scalar(segment_id: u32, content_bytes: &[u8]) -> BigUint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OBJ_DOMAIN);
    hasher.update(&lp(&segment_id.to_be_bytes()));
    hasher.update(content_bytes);
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    BigUint::from_bytes_be(&wide) % bjj_l()
}

/// `leaf = Poseidon(C.x, C.y)`, `C = content·G + blinding·H` (Pedersen on BJJ).
fn redaction_leaf(curve: &Curve, content: &BigUint, blinding: &BigUint) -> Fr {
    let c = curve.pedersen_commit(content, blinding);
    let cx = Fr::from_be_bytes_mod_order(&biguint_to_be32(&c.x));
    let cy = Fr::from_be_bytes_mod_order(&biguint_to_be32(&c.y));
    poseidon2(&cx, &cy)
}

/// `content_bytes` for a revealed leaf, per the ADR-0030 §3 per-format table.
fn revealed_content_bytes(
    format: &str,
    slice: &[u8],
    label: &str,
) -> Result<Vec<u8>, RejectReason> {
    match format {
        // Plain-slice formats: the committed content IS the raw artifact slice
        // (text line block / full pdf object span / a pdf-textrun word).
        "pdf-object" | "text-line" | "pdf-textrun" => Ok(slice.to_vec()),
        "ooxml-part" => {
            // committed = lp(label) || payload
            let mut v = lp(label.as_bytes());
            v.extend_from_slice(slice);
            Ok(v)
        }
        "pdf-xref-stream" => {
            let obj_idx = find_sub(slice, b"obj");
            let end_idx = rfind_sub(slice, b"endobj");
            match (obj_idx, end_idx) {
                (Some(o), Some(e)) if e >= o + 3 => {
                    let mut lo = o + 3;
                    let mut hi = e; // exclusive
                    while lo < hi && PDF_WS.contains(&slice[lo]) {
                        lo += 1;
                    }
                    while hi > lo && PDF_WS.contains(&slice[hi - 1]) {
                        hi -= 1;
                    }
                    Ok(slice[lo..hi].to_vec())
                }
                _ => Err(RejectReason("pdf-xref-stream obj/endobj framing not found")),
            }
        }
        _ => Err(RejectReason("unknown format")),
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn rfind_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

// ── artifact replay parsers ──────────────────────────────────────────────────

fn text_line_spans(artifact: &[u8], expected_n: usize) -> Result<Vec<ArtifactSpan>, RejectReason> {
    if artifact.is_empty() {
        return Err(RejectReason("empty text artifact"));
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (i, &b) in artifact.iter().enumerate() {
        if b == b'\n' {
            lines.push((start, i + 1));
            start = i + 1;
        }
    }
    if start < artifact.len() {
        lines.push((start, artifact.len()));
    }
    if lines.is_empty() {
        return Err(RejectReason("empty text artifact"));
    }
    let per_block = if lines.len() <= MAX_REDACTION_SEGMENTS as usize {
        1
    } else {
        lines.len().div_ceil(MAX_REDACTION_SEGMENTS as usize)
    };
    let mut spans = Vec::new();
    for (block_idx, chunk) in lines.chunks(per_block).enumerate() {
        let start = chunk.first().unwrap().0;
        let end = chunk.last().unwrap().1;
        spans.push(ArtifactSpan {
            segment_id: block_idx as u32,
            offset: start as u64,
            length: (end - start) as u64,
            label: None,
        });
    }
    if spans.len() != expected_n {
        return Err(RejectReason("artifact segment count mismatch"));
    }
    assert_spans_tile(artifact.len(), &spans)?;
    Ok(spans)
}

fn read_pdf_uint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&b[start..i])
        .ok()?
        .parse()
        .ok()
        .map(|v| (v, i))
}

fn pdf_object_span(b: &[u8], offset: usize, scan_end: usize) -> Option<(usize, usize)> {
    if offset >= scan_end || scan_end > b.len() {
        return None;
    }
    let region = &b[offset..scan_end];
    let first_endobj = find_sub(region, b"endobj")?;
    let stream_kw = find_sub(region, b"stream");
    let rel_end = match stream_kw {
        Some(s) if s < first_endobj => {
            let after_stream = s + b"stream".len();
            let es = find_sub(&region[after_stream..], b"endstream")?;
            let after_endstream = after_stream + es + b"endstream".len();
            find_sub(&region[after_endstream..], b"endobj").map(|r| after_endstream + r)?
        }
        _ => first_endobj,
    };
    Some((offset, offset + rel_end + b"endobj".len()))
}

fn pdf_xref_spans(artifact: &[u8]) -> Result<Vec<ArtifactSpan>, RejectReason> {
    let sx = rfind_sub(artifact, b"startxref").ok_or(RejectReason("pdf startxref missing"))?;
    let (xref_off, _) =
        read_pdf_uint(artifact, sx + b"startxref".len()).ok_or(RejectReason("bad startxref"))?;
    let xref_off = xref_off as usize;
    if xref_off >= artifact.len() || !artifact[xref_off..].starts_with(b"xref") {
        return Err(RejectReason("pdf xref table missing"));
    }

    let mut i = xref_off + b"xref".len();
    let mut entries: BTreeMap<u32, (u64, u16)> = BTreeMap::new();
    loop {
        while i < artifact.len() && artifact[i].is_ascii_whitespace() {
            i += 1;
        }
        if artifact[i.min(artifact.len())..].starts_with(b"trailer") {
            break;
        }
        let (start_obj, ni) =
            read_pdf_uint(artifact, i).ok_or(RejectReason("bad xref subsection"))?;
        let (count, ni) = read_pdf_uint(artifact, ni).ok_or(RejectReason("bad xref subsection"))?;
        i = ni;
        for k in 0..count {
            let (off, ni) = read_pdf_uint(artifact, i).ok_or(RejectReason("bad xref entry"))?;
            let (gen, ni) = read_pdf_uint(artifact, ni).ok_or(RejectReason("bad xref entry"))?;
            i = ni;
            while i < artifact.len() && artifact[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= artifact.len() {
                return Err(RejectReason("bad xref entry"));
            }
            let ty = artifact[i];
            i += 1;
            if ty == b'n' {
                entries.insert((start_obj + k) as u32, (off, gen as u16));
            }
        }
    }
    if entries.len() < 2 || entries.len() as u64 > MAX_REDACTION_SEGMENTS {
        return Err(RejectReason("artifact segment count mismatch"));
    }
    let mut offsets: Vec<usize> = entries.values().map(|&(off, _)| off as usize).collect();
    offsets.sort_unstable();
    let declared = offsets.len();
    offsets.dedup();
    if offsets.len() != declared {
        return Err(RejectReason("overlapping pdf object offsets"));
    }

    let eof = rfind_sub(artifact, b"%%EOF").ok_or(RejectReason("pdf EOF marker missing"))?;
    let after_eof = eof + b"%%EOF".len();
    if artifact[after_eof..]
        .iter()
        .any(|b| !b.is_ascii_whitespace())
    {
        return Err(RejectReason("hidden bytes after pdf EOF"));
    }

    let mut spans = Vec::with_capacity(entries.len());
    for (&obj_id, &(off, _gen)) in &entries {
        let off = off as usize;
        let pos = offsets
            .binary_search(&off)
            .map_err(|_| RejectReason("pdf object offset missing"))?;
        let scan_end = offsets.get(pos + 1).copied().unwrap_or(xref_off);
        let (start, end) =
            pdf_object_span(artifact, off, scan_end).ok_or(RejectReason("malformed pdf object"))?;
        spans.push(ArtifactSpan {
            segment_id: obj_id,
            offset: start as u64,
            length: (end - start) as u64,
            label: None,
        });
    }
    Ok(spans)
}

fn le_u16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn le_u32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

fn ooxml_payload_spans(artifact: &[u8]) -> Result<Vec<ArtifactSpan>, RejectReason> {
    let mut i = 0usize;
    let mut spans = Vec::new();
    let mut seen = HashSet::new();
    while i + 4 <= artifact.len() {
        let sig = &artifact[i..i + 4];
        if sig == ZIP_CENTRAL || sig == ZIP_EOCD {
            break;
        }
        if sig != ZIP_LOCAL {
            return Err(RejectReason("malformed zip local header"));
        }
        let flags = le_u16(artifact, i + 6).ok_or(RejectReason("malformed zip local header"))?;
        let method = le_u16(artifact, i + 8).ok_or(RejectReason("malformed zip local header"))?;
        let comp_size =
            le_u32(artifact, i + 18).ok_or(RejectReason("malformed zip local header"))? as usize;
        let uncomp_size =
            le_u32(artifact, i + 22).ok_or(RejectReason("malformed zip local header"))? as usize;
        let name_len =
            le_u16(artifact, i + 26).ok_or(RejectReason("malformed zip local header"))? as usize;
        let extra_len =
            le_u16(artifact, i + 28).ok_or(RejectReason("malformed zip local header"))? as usize;
        if flags & 0x0008 != 0 || method != 0 || comp_size != uncomp_size || extra_len != 0 {
            return Err(RejectReason("non-canonical ooxml zip entry"));
        }
        let name_start = i + 30;
        let data_start = name_start
            .checked_add(name_len)
            .and_then(|x| x.checked_add(extra_len))
            .ok_or(RejectReason("malformed zip local header"))?;
        let data_end = data_start
            .checked_add(comp_size)
            .ok_or(RejectReason("malformed zip local header"))?;
        if data_end > artifact.len() {
            return Err(RejectReason("zip data outside artifact"));
        }
        let name = std::str::from_utf8(&artifact[name_start..name_start + name_len])
            .map_err(|_| RejectReason("zip part name not utf8"))?
            .to_string();
        if !seen.insert(name.clone()) {
            return Err(RejectReason("duplicate ooxml part"));
        }
        spans.push(ArtifactSpan {
            segment_id: spans.len() as u32,
            offset: data_start as u64,
            length: comp_size as u64,
            label: Some(name),
        });
        i = data_end;
    }
    if spans.len() < 2 {
        return Err(RejectReason("artifact segment count mismatch"));
    }
    let labels: Vec<String> = spans.iter().map(|s| s.label.clone().unwrap()).collect();
    let sorted = {
        let mut s = labels.clone();
        s.sort();
        s
    };
    if labels != sorted {
        return Err(RejectReason("ooxml parts not deterministically ordered"));
    }
    if let Some(eocd) = rfind_sub(artifact, ZIP_EOCD) {
        let comment_len = le_u16(artifact, eocd + 20).unwrap_or(1);
        if comment_len != 0 {
            return Err(RejectReason("non-canonical ooxml zip entry"));
        }
    }
    Ok(spans)
}

fn pdf_textrun_is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
}

fn scan_literal_string(b: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    let mut depth = 1usize;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    i
}

fn pdf_textrun_show_string_ranges(b: &[u8]) -> Vec<(usize, usize)> {
    let mut shows = Vec::new();
    let mut pending = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if pdf_textrun_is_ws(c) {
            i += 1;
        } else if c == b'(' {
            let end = scan_literal_string(b, i);
            pending.push((i, end));
            i = end;
        } else if c == b'<' {
            if b.get(i + 1) == Some(&b'<') {
                let mut depth = 1usize;
                i += 2;
                while i + 1 < b.len() && depth > 0 {
                    if &b[i..i + 2] == b"<<" {
                        depth += 1;
                        i += 2;
                    } else if &b[i..i + 2] == b">>" {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            } else {
                i += 1;
                while i < b.len() && b[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
        } else if c == b'/' {
            i += 1;
            while i < b.len()
                && !pdf_textrun_is_ws(b[i])
                && !matches!(b[i], b'(' | b'<' | b'[' | b']' | b'/' | b'{' | b'}' | b'%')
            {
                i += 1;
            }
        } else if matches!(c, b'[' | b']' | b'{' | b'}' | b')' | b'>') {
            i += 1;
        } else if c == b'\'' || c == b'"' {
            shows.append(&mut pending);
            i += 1;
        } else if c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.') {
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_digit() || matches!(b[i], b'+' | b'-' | b'.' | b'e' | b'E'))
            {
                i += 1;
            }
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'*') {
                i += 1;
            }
            let op = &b[start..i];
            if op == b"Tj" || op == b"TJ" {
                shows.append(&mut pending);
            } else {
                pending.clear();
            }
        } else {
            i += 1;
        }
    }
    shows
}

fn pdf_textrun_word_ranges(content: &[u8]) -> Vec<(usize, usize)> {
    let mut words = Vec::new();
    for (s, e) in pdf_textrun_show_string_ranges(content) {
        let (cs, ce) = (s + 1, e.saturating_sub(1));
        let mut i = cs;
        while i < ce {
            if pdf_textrun_is_ws(content[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < ce && !pdf_textrun_is_ws(content[i]) {
                i += 1;
            }
            words.push((start, i));
        }
    }
    words
}

fn pdf_textrun_spans(
    artifact: &[u8],
    segments: &[Segment],
) -> Result<Vec<ArtifactSpan>, RejectReason> {
    let words = pdf_textrun_word_ranges(artifact);
    let revealed = segments.iter().filter(|s| !s.redacted).count();
    if words.len() != revealed {
        return Err(RejectReason("artifact segment count mismatch"));
    }
    let mut word_iter = words.into_iter();
    let mut spans = Vec::with_capacity(segments.len());
    for s in segments {
        if s.redacted {
            spans.push(ArtifactSpan {
                segment_id: s.segment_id,
                offset: 0,
                length: 0,
                label: None,
            });
        } else {
            let (start, end) = word_iter
                .next()
                .ok_or(RejectReason("artifact segment count mismatch"))?;
            spans.push(ArtifactSpan {
                segment_id: s.segment_id,
                offset: start as u64,
                length: (end - start) as u64,
                label: None,
            });
        }
    }
    Ok(spans)
}

fn artifact_spans(
    format: &str,
    artifact: &[u8],
    segments: &[Segment],
) -> Result<Vec<ArtifactSpan>, RejectReason> {
    let expected_n = segments.len();
    match format {
        "text-line" => text_line_spans(artifact, expected_n),
        "pdf-object" | "pdf-xref-stream" => {
            let spans = pdf_xref_spans(artifact)?;
            if spans.len() != expected_n {
                return Err(RejectReason("artifact segment count mismatch"));
            }
            Ok(spans)
        }
        "ooxml-part" => {
            let spans = ooxml_payload_spans(artifact)?;
            if spans.len() != expected_n {
                return Err(RejectReason("artifact segment count mismatch"));
            }
            Ok(spans)
        }
        "pdf-textrun" => pdf_textrun_spans(artifact, segments),
        _ => Err(RejectReason("unknown format")),
    }
}

fn validate_redacted_bytes(format: &str, slice: &[u8], _label: &str) -> Result<(), RejectReason> {
    match format {
        "text-line" => {
            if slice == REDACTION_TEXT_TOKEN {
                Ok(())
            } else {
                Err(RejectReason("redacted text bytes not destroyed"))
            }
        }
        "pdf-object" => {
            let obj_idx = find_sub(slice, b"obj").ok_or(RejectReason("malformed pdf object"))?;
            let end_idx =
                rfind_sub(slice, b"endobj").ok_or(RejectReason("malformed pdf object"))?;
            if end_idx < obj_idx + 3 {
                return Err(RejectReason("malformed pdf object"));
            }
            let inner = &slice[obj_idx + 3..end_idx];
            if inner.iter().all(|&b| b == 0 || PDF_WS.contains(&b)) {
                Ok(())
            } else {
                Err(RejectReason("redacted pdf bytes not destroyed"))
            }
        }
        "pdf-xref-stream" => {
            if revealed_content_bytes(format, slice, "")? == b"null" {
                Ok(())
            } else {
                Err(RejectReason("redacted pdf bytes not destroyed"))
            }
        }
        "ooxml-part" => {
            if slice.is_empty() {
                Ok(())
            } else {
                Err(RejectReason("redacted ooxml bytes not destroyed"))
            }
        }
        "pdf-textrun" => {
            if slice.is_empty() {
                Ok(())
            } else {
                Err(RejectReason("redacted pdf text-run bytes not destroyed"))
            }
        }
        _ => Err(RejectReason("unknown format")),
    }
}

fn assert_spans_tile(artifact_len: usize, spans: &[ArtifactSpan]) -> Result<(), RejectReason> {
    let mut pos = 0u64;
    for s in spans {
        if s.offset != pos {
            return Err(RejectReason("artifact bytes not fully covered"));
        }
        pos = s
            .offset
            .checked_add(s.length)
            .ok_or(RejectReason("artifact span overflow"))?;
    }
    if pos != artifact_len as u64 {
        return Err(RejectReason("artifact bytes not fully covered"));
    }
    Ok(())
}

// ── table_hash / payload / nullifier (mirror olympus_crypto::redaction) ───────

fn table_hash(segments: &[Segment]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TABLE_V3_PREFIX);
    for s in segments {
        h.update(&s.segment_id.to_be_bytes());
        h.update(&[u8::from(s.redacted)]);
        h.update(&s.artifact_offset.to_be_bytes());
        h.update(&s.artifact_length.to_be_bytes());
        h.update(&lp(s.label.as_deref().unwrap_or("").as_bytes()));
        let value_text = if s.redacted {
            s.leaf_hex.as_deref().unwrap_or("")
        } else {
            s.blinding_decimal.as_deref().unwrap_or("")
        };
        h.update(&lp(value_text.as_bytes()));
    }
    *h.finalize().as_bytes()
}

fn signing_payload(
    root_hex: &str,
    format: &str,
    n: u32,
    recipient_dec: &str,
    th: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_V3_PREFIX);
    out.extend_from_slice(&lp(root_hex.as_bytes()));
    out.extend_from_slice(&lp(format.as_bytes()));
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&lp(recipient_dec.as_bytes()));
    out.extend_from_slice(th);
    out
}

fn nullifier(root_raw: &[u8; 32], th: &[u8; 32], recipient_dec: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(NULLIFIER_V1_PREFIX);
    h.update(root_raw);
    h.update(th);
    h.update(&lp(recipient_dec.as_bytes()));
    *h.finalize().as_bytes()
}

// ── full V3 verification ──────────────────────────────────────────────────────

/// Verify a V3 bundle per ADR-0030 §3. `verify_fold` is `false` only for the
/// byte-dump layout fixture (whose `original_root` is a fixed anchor, not a fold).
///
/// The verifier never re-derives per-segment blindings: revealed leaves are
/// recomputed from the artifact slice + the **published** `blinding_decimal`
/// (the `blind_secret` is a server-only producer input, ADR-0030 §3), so it is
/// not a verifier parameter.
pub fn verify_bundle(
    curve: &Curve,
    bundle: &Bundle,
    issuer_pubkey: &VerifyingKey,
    verify_fold: bool,
) -> VResult {
    let format = bundle.format.as_str();
    let n = bundle.segment_count;

    // 1. Structural.
    if !FORMATS.contains(&format) {
        return reject("unknown format");
    }
    if !(2..=MAX_REDACTION_SEGMENTS).contains(&n) {
        return reject("N out of [2, 2^20]");
    }
    if bundle.segments.len() as u64 != n {
        return reject("segment_count != segments.len()");
    }
    if !valid_field_hex(&bundle.original_root) {
        return reject("non-canonical original_root");
    }
    if !valid_recipient(&bundle.recipient_id) {
        return reject("non-canonical recipient_id");
    }

    let ooxml = format == "ooxml-part";
    let mut prev: Option<u32> = None;
    for (i, s) in bundle.segments.iter().enumerate() {
        if let Some(p) = prev {
            if s.segment_id <= p {
                return reject("ids not strictly ascending");
            }
        }
        prev = Some(s.segment_id);
        if ooxml
            && (s.segment_id as usize != i || s.label.as_deref().map(str::is_empty).unwrap_or(true))
        {
            return reject("ooxml-part requires dense 0..N-1 ids + label");
        }
        if s.redacted {
            match s.leaf_hex.as_deref() {
                Some(h) if valid_field_hex(h) => {}
                Some(_) => return reject("non-canonical leaf_hex"),
                None => return reject("redacted seg missing leaf_hex"),
            }
            if s.blinding_decimal.is_some() {
                return reject("redacted seg carries blinding");
            }
        } else {
            match s.blinding_decimal.as_deref() {
                Some(b) if valid_blinding(b) => {}
                Some(_) => return reject("non-canonical blinding"),
                None => return reject("revealed seg missing blinding_decimal"),
            }
            if s.leaf_hex.is_some() {
                return reject("revealed seg carries leaf_hex");
            }
        }
    }

    // 2/3. Reconstruct + fold.
    if verify_fold {
        let artifact = match bundle.artifact_hex.as_deref() {
            Some(h) => hex::decode(h).map_err(|_| RejectReason("bad artifact_hex"))?,
            None => return reject("missing artifact_hex"),
        };
        let derived_spans = artifact_spans(format, &artifact, &bundle.segments)?;
        let by_id: BTreeMap<u32, ArtifactSpan> = derived_spans
            .into_iter()
            .map(|span| (span.segment_id, span))
            .collect();
        let mut leaves: Vec<Fr> = Vec::with_capacity(bundle.segments.len());
        for s in &bundle.segments {
            let span = by_id
                .get(&s.segment_id)
                .ok_or(RejectReason("bundle segment absent from artifact"))?;
            if s.artifact_offset != span.offset || s.artifact_length != span.length {
                return reject("bundle offset/length != artifact-derived span");
            }
            if format == "ooxml-part" && s.label.as_deref() != span.label.as_deref() {
                return reject("bundle label != artifact-derived label");
            }
            let off = span.offset as usize;
            let len = span.length as usize;
            if off + len > artifact.len() {
                return reject("byte range outside artifact");
            }
            let slice = &artifact[off..off + len];
            if s.redacted {
                validate_redacted_bytes(format, slice, s.label.as_deref().unwrap_or(""))?;
                let raw = hex::decode(s.leaf_hex.as_deref().unwrap()).unwrap();
                leaves.push(Fr::from_be_bytes_mod_order(&raw));
            } else {
                let cb = revealed_content_bytes(format, slice, s.label.as_deref().unwrap_or(""))?;
                let content = content_scalar(s.segment_id, &cb);
                let blinding = parse_dec(s.blinding_decimal.as_deref().unwrap())
                    .ok_or(RejectReason("bad blinding"))?;
                // Range already enforced in the structural pass (valid_blinding);
                // re-assert as defence-in-depth before the Pedersen commit.
                if blinding >= bjj_l() {
                    return reject("blinding out of range");
                }
                leaves.push(redaction_leaf(curve, &content, &blinding));
            }
        }
        let root = variable_depth_fold(&leaves)?;
        if fr_to_hex(&root) != bundle.original_root {
            return reject("fold != original_root");
        }
    }

    // 4. table_hash + payload + signature + nullifier.
    let th = table_hash(&bundle.segments);
    let payload = signing_payload(
        &bundle.original_root,
        format,
        n as u32,
        &bundle.recipient_id,
        &th,
    );

    let sig_bytes =
        hex::decode(&bundle.signature_hex).map_err(|_| RejectReason("bad signature hex"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| RejectReason("signature not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    if issuer_pubkey.verify(&payload, &sig).is_err() {
        return reject("Ed25519 signature invalid");
    }

    let mut root_raw = [0u8; 32];
    root_raw.copy_from_slice(&hex::decode(&bundle.original_root).unwrap());
    let nf = hex::encode(nullifier(&root_raw, &th, &bundle.recipient_id));
    if nf != bundle.nullifier {
        return reject("nullifier mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    fn load() -> Value {
        let raw = include_str!("../../test_vectors/redaction_vectors.json");
        serde_json::from_str(raw).expect("parse redaction_vectors.json")
    }

    fn opt_str(v: &Value, k: &str) -> Option<String> {
        v.get(k).and_then(Value::as_str).map(str::to_string)
    }

    fn parse_segment(v: &Value) -> Segment {
        Segment {
            segment_id: v["segment_id"].as_u64().unwrap() as u32,
            redacted: v["redacted"].as_bool().unwrap(),
            artifact_offset: v
                .get("artifact_offset")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            artifact_length: v
                .get("artifact_length")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            label: opt_str(v, "label"),
            blinding_decimal: opt_str(v, "blinding_decimal"),
            leaf_hex: opt_str(v, "leaf_hex"),
        }
    }

    fn parse_bundle(v: &Value) -> Bundle {
        Bundle {
            original_root: v["original_root"].as_str().unwrap().to_string(),
            format: v["format"].as_str().unwrap().to_string(),
            segment_count: v["segment_count"].as_u64().unwrap(),
            recipient_id: v["recipient_id"].as_str().unwrap().to_string(),
            artifact_hex: opt_str(v, "artifact_hex"),
            segments: v["segments"]
                .as_array()
                .unwrap()
                .iter()
                .map(parse_segment)
                .collect(),
            nullifier: v
                .get("nullifier")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            signature_hex: v
                .get("signature_hex")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        }
    }

    fn issuer(v: &Value) -> VerifyingKey {
        let pk = hex::decode(v["issuer_ed25519_pubkey_hex"].as_str().unwrap()).unwrap();
        let arr: [u8; 32] = pk.try_into().unwrap();
        VerifyingKey::from_bytes(&arr).unwrap()
    }

    struct Ctx {
        curve: Curve,
        vk: VerifyingKey,
    }

    fn ctx(d: &Value) -> Ctx {
        // blind_secret_hex / content_hash_hex are carried in the vectors as
        // producer-side fixtures; the verifier does not consume them (revealed
        // leaves use the published blinding_decimal).
        Ctx {
            curve: Curve::baby_jubjub(),
            vk: issuer(d),
        }
    }

    fn verify(c: &Ctx, b: &Bundle, fold: bool) -> VResult {
        verify_bundle(&c.curve, b, &c.vk, fold)
    }

    fn text_bundle() -> (Ctx, Bundle) {
        let d = load();
        let c = ctx(&d);
        let b = parse_bundle(&d["format_bundles"]["text-line"]);
        (c, b)
    }

    fn pdf_bundle() -> (Ctx, Bundle) {
        let d = load();
        let c = ctx(&d);
        let b = parse_bundle(&d["format_bundles"]["pdf-object"]);
        (c, b)
    }

    fn ooxml_bundle() -> (Ctx, Bundle) {
        let d = load();
        let c = ctx(&d);
        let b = parse_bundle(&d["format_bundles"]["ooxml-part"]);
        (c, b)
    }

    fn must_reject(c: &Ctx, b: &Bundle, label: &str) {
        assert!(verify(c, b, true).is_err(), "{label} unexpectedly verified");
    }

    #[test]
    fn scheme_and_tags_pinned() {
        let d = load();
        assert_eq!(d["scheme"], "redaction-signed-merkle-adr0030-v3");
        assert_eq!(d["domain_tags"]["bundle"], "OLY:REDACTION_BUNDLE:V3");
        assert_eq!(d["domain_tags"]["table"], "OLY:REDACTION:TABLE:V3");
        assert_eq!(d["domain_tags"]["nullifier"], "OLY:REDACTION:NULLIFIER:V1");
        assert_eq!(d["domain_tags"]["blind"], "OLY:REDACTION:BLIND:V1");
        assert_eq!(
            d["max_redaction_segments"].as_u64().unwrap(),
            MAX_REDACTION_SEGMENTS
        );
    }

    /// Pin light-poseidon == circomlibjs/olympus by reproducing a fold vector root.
    #[test]
    fn poseidon_fold_parity_n2() {
        let d = load();
        let fv = &d["fold_vectors"]["n2"];
        let leaves: Vec<Fr> = fv["leaves_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| Fr::from_be_bytes_mod_order(&hex::decode(h.as_str().unwrap()).unwrap()))
            .collect();
        assert_eq!(
            fr_to_hex(&variable_depth_fold(&leaves).unwrap()),
            fv["root_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn per_format_positive_bundles_verify() {
        let d = load();
        let c = ctx(&d);
        for fmt in [
            "pdf-object",
            "text-line",
            "pdf-xref-stream",
            "ooxml-part",
            "pdf-textrun",
        ] {
            let b = parse_bundle(&d["format_bundles"][fmt]);
            assert_eq!(verify(&c, &b, true), Ok(()), "format {fmt} must verify");
            // table_hash parity with the convenience field.
            let th = hex::encode(table_hash(&b.segments));
            assert_eq!(
                th,
                d["format_bundles"][fmt]["table_hash_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn variable_depth_fold_roots() {
        let d = load();
        for key in ["n2", "n3"] {
            let fv = &d["fold_vectors"][key];
            let leaves: Vec<Fr> = fv["leaves_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| Fr::from_be_bytes_mod_order(&hex::decode(h.as_str().unwrap()).unwrap()))
                .collect();
            assert_eq!(leaves.len() as u64, fv["n"].as_u64().unwrap());
            assert_eq!(
                fr_to_hex(&variable_depth_fold(&leaves).unwrap()),
                fv["root_hex"].as_str().unwrap(),
                "{key}"
            );
        }
        // N=1024 fold == legacy fixed-1024 parity.
        let fv = &d["fold_vectors"]["n1024"];
        let leaves: Vec<Fr> = fv["leaves_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| Fr::from_be_bytes_mod_order(&hex::decode(h.as_str().unwrap()).unwrap()))
            .collect();
        assert_eq!(leaves.len(), 1024);
        let root = variable_depth_fold(&leaves).unwrap();
        assert_eq!(fr_to_hex(&root), fv["root_hex"].as_str().unwrap());
        assert_eq!(fv["root_hex"], fv["legacy_fixed_1024_root_hex"]);
        assert_eq!(fv["parity"].as_bool().unwrap(), true);
    }

    #[test]
    fn all_redacted_and_none_redacted_verify() {
        let d = load();
        let c = ctx(&d);
        assert_eq!(
            verify(&c, &parse_bundle(&d["all_redacted_bundle"]), true),
            Ok(())
        );
        assert_eq!(
            verify(&c, &parse_bundle(&d["none_redacted_bundle"]), true),
            Ok(())
        );
    }

    #[test]
    fn byte_dump_layout_selfcheck() {
        // The byte-dump is a pure BYTE-LAYOUT fixture (ADR-0030 §Security): a fixed
        // segment table → table_hash → signing payload → signature → nullifier. It
        // intentionally reuses the redaction.rs golden sample, which tags
        // `ooxml-part` with SPARSE ids (1, 4) — so it is NOT a structurally-valid
        // bundle and must NOT be run through full §3 verification. We self-check
        // only the byte layout (the same thing the JS verifier does for it).
        let d = load();
        let c = ctx(&d);
        let bd = &d["byte_dump"];
        let b = parse_bundle(bd);
        let th = table_hash(&b.segments);
        assert_eq!(
            hex::encode(th),
            bd["table_hash_hex"].as_str().unwrap(),
            "table_hash"
        );
        let payload = signing_payload(
            &b.original_root,
            &b.format,
            b.segment_count as u32,
            &b.recipient_id,
            &th,
        );
        assert_eq!(
            hex::encode(&payload),
            bd["signing_payload_hex"].as_str().unwrap(),
            "payload"
        );
        // Signature over the payload + recomputed nullifier.
        let sig_arr: [u8; 64] = hex::decode(&b.signature_hex).unwrap().try_into().unwrap();
        assert!(
            c.vk.verify(&payload, &Signature::from_bytes(&sig_arr))
                .is_ok(),
            "signature"
        );
        let mut root_raw = [0u8; 32];
        root_raw.copy_from_slice(&hex::decode(&b.original_root).unwrap());
        assert_eq!(
            hex::encode(nullifier(&root_raw, &th, &b.recipient_id)),
            b.nullifier,
            "nullifier"
        );
    }

    #[test]
    fn negative_count_bounds() {
        let d = load();
        let c = ctx(&d);
        // N=0
        let mut b = parse_bundle(&d["all_redacted_bundle"]);
        b.segment_count = 0;
        b.segments.clear();
        assert_eq!(verify(&c, &b, true), reject("N out of [2, 2^20]"));
        // N=1
        let mut b = parse_bundle(&d["all_redacted_bundle"]);
        b.segment_count = 1;
        b.segments.truncate(1);
        assert_eq!(verify(&c, &b, true), reject("N out of [2, 2^20]"));
        // over-cap: rejected on the declared count before allocating leaves.
        let over = d["negatives"]["over_cap_rejected"]["segment_count"]
            .as_u64()
            .unwrap();
        let mut b = parse_bundle(&d["all_redacted_bundle"]);
        b.segment_count = over;
        // do NOT materialise leaves
        assert_eq!(verify(&c, &b, true), reject("N out of [2, 2^20]"));
    }

    #[test]
    fn negative_flip_flag_breaks_signature() {
        let d = load();
        let c = ctx(&d);
        let b = parse_bundle(&d["negatives"]["flip_flag_signature_fails"]["bundle"]);
        assert!(
            verify(&c, &b, true).is_err(),
            "flip-flag mutation must reject"
        );
    }

    #[test]
    fn negative_tampered_revealed_bytes() {
        let d = load();
        let c = ctx(&d);
        let b = parse_bundle(&d["negatives"]["tampered_revealed_bytes_fold_mismatch"]["bundle"]);
        assert_eq!(verify(&c, &b, true), reject("fold != original_root"));
    }

    #[test]
    fn negative_canonical_range() {
        let d = load();
        let c = ctx(&d);
        let cr = &d["negatives"]["canonical_range"];

        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["recipient_id_equals_r_rejected"]["bundle"]),
                true
            ),
            reject("non-canonical recipient_id")
        );
        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["recipient_id_equals_r_minus_1_accepted"]["bundle"]),
                true
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["blinding_equals_l_rejected"]["bundle"]),
                true
            ),
            reject("non-canonical blinding")
        );
        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["blinding_equals_l_minus_1_accepted"]["bundle"]),
                true
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["leaf_hex_equals_r_rejected"]["bundle"]),
                true
            ),
            reject("non-canonical leaf_hex")
        );
        assert_eq!(
            verify(
                &c,
                &parse_bundle(&cr["leaf_hex_equals_r_minus_1_accepted"]["bundle"]),
                true
            ),
            Ok(())
        );
    }

    /// Defensive: the range validators must NOT mod-reduce — `r`/`l` themselves fail.
    #[test]
    fn range_validators_do_not_reduce() {
        let r = bn254_r();
        let l = bjj_l();
        assert!(!valid_recipient(&r.to_string()));
        assert!(valid_recipient(&(&r - 1u32).to_string()));
        assert!(!valid_blinding(&l.to_string()));
        assert!(valid_blinding(&(&l - 1u32).to_string()));
        assert!(!valid_field_hex(&hex::encode(biguint_to_be32(&r))));
        assert!(valid_field_hex(&hex::encode(biguint_to_be32(&(&r - 1u32)))));
    }

    #[test]
    fn adversarial_segment_table_mutations_reject() {
        let (c, base) = text_bundle();

        let mut swapped = base.clone();
        swapped.segments.swap(0, 1);
        must_reject(&c, &swapped, "swapped segments");

        let mut duplicate = base.clone();
        duplicate.segments[1].segment_id = duplicate.segments[0].segment_id;
        must_reject(&c, &duplicate, "duplicate segment ids");

        let mut duplicate_leaf = base.clone();
        duplicate_leaf.segments[1].leaf_hex = Some("00".repeat(32));
        must_reject(&c, &duplicate_leaf, "duplicate/mutated redacted leaf");

        let mut offset = base.clone();
        offset.segments[0].artifact_offset += 1;
        must_reject(&c, &offset, "offset manipulation");

        let mut length = base.clone();
        length.segments[0].artifact_length -= 1;
        must_reject(&c, &length, "length manipulation");

        let mut overlap = base.clone();
        overlap.segments[1].artifact_offset = 0;
        must_reject(&c, &overlap, "overlapping segments");

        let mut inserted = base.clone();
        inserted.segment_count += 1;
        inserted.segments.push(inserted.segments[1].clone());
        must_reject(&c, &inserted, "segment insertion");

        let mut deleted = base.clone();
        deleted.segment_count -= 1;
        deleted.segments.pop();
        must_reject(&c, &deleted, "segment deletion / bundle truncation");
    }

    #[test]
    fn adversarial_artifact_and_parser_mutations_reject() {
        let (c, base) = text_bundle();

        let mut hidden = base.clone();
        let mut artifact = hex::decode(hidden.artifact_hex.as_deref().unwrap()).unwrap();
        artifact.extend_from_slice(b"hidden\n");
        hidden.artifact_hex = Some(hex::encode(artifact));
        must_reject(&c, &hidden, "hidden bytes");

        let mut malformed = base.clone();
        malformed.artifact_hex = Some("zz".to_string());
        must_reject(&c, &malformed, "malformed artifact");

        let mut parser_substitution = base.clone();
        parser_substitution.format = "pdf-object".to_string();
        must_reject(&c, &parser_substitution, "parser substitution");

        let mut replay = base.clone();
        replay.recipient_id = "99999".to_string();
        must_reject(&c, &replay, "signature replay across recipient");

        let mut downgrade = base.clone();
        downgrade.format = "text-line-v2".to_string();
        must_reject(&c, &downgrade, "protocol/format downgrade");

        let (pc, pdf) = pdf_bundle();
        let mut pdf_hidden = pdf.clone();
        let mut pdf_artifact = hex::decode(pdf_hidden.artifact_hex.as_deref().unwrap()).unwrap();
        pdf_artifact.extend_from_slice(b"not-whitespace-after-eof");
        pdf_hidden.artifact_hex = Some(hex::encode(pdf_artifact));
        must_reject(&pc, &pdf_hidden, "pdf hidden bytes after EOF");

        let (oc, ooxml) = ooxml_bundle();
        let mut label = ooxml.clone();
        label.segments[0].label = Some("word/document.xml".to_string());
        must_reject(&oc, &label, "inconsistent ooxml label");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn mutated_text_bundle_never_verifies(kind in 0u8..8, byte_idx in 0usize..16) {
            let (c, mut b) = text_bundle();
            match kind {
                0 => b.segments[0].artifact_offset = b.segments[0].artifact_offset.saturating_add(1),
                1 => b.segments[0].artifact_length = b.segments[0].artifact_length.saturating_sub(1),
                2 => b.segments[0].blinding_decimal = Some("0".to_string()),
                3 => b.segments.swap(0, 1),
                4 => b.recipient_id = "42".to_string(),
                5 => b.format = "pdf-object".to_string(),
                6 => {
                    let mut artifact = hex::decode(b.artifact_hex.as_deref().unwrap()).unwrap();
                    let idx = byte_idx % artifact.len();
                    artifact[idx] ^= 0x01;
                    b.artifact_hex = Some(hex::encode(artifact));
                }
                _ => {
                    b.segments[1].leaf_hex = Some("01".repeat(32));
                }
            }
            prop_assert!(verify(&c, &b, true).is_err());
        }
    }
}
