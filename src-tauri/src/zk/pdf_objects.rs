//! PDF object-level redaction commitment (ADR-0025 / ADR-0026).
//!
//! Parses a traditional-xref PDF's cross-reference table, extracts every
//! indirect object's raw bytes, computes one **hiding** Poseidon leaf per object
//! (`olympus_crypto::redaction::redaction_leaf` — a blinded Pedersen commitment,
//! ADR-0026), and folds the leaves into the same depth-`TREE_DEPTH` domain-1
//! Poseidon Merkle tree the `redaction_validity` circuit proves over. The root
//! replaces the 16-chunk root as the ledger leaf. Per-object blinding is derived
//! deterministically from a server `blind_secret` + the original file's content
//! hash + obj-id, so a redacted object's content cannot be brute-forced from the
//! pinned root, yet re-ingesting the same file reproduces the same root.
//!
//! Redaction is **in-place zero-fill**: the content bytes of the selected
//! objects (everything strictly between the `obj` and `endobj` keywords) are
//! overwritten with NULs, preserving the file length, every byte offset, the
//! xref table, and every non-redacted object byte-for-byte. That byte identity
//! is what makes non-redacted leaves survive unchanged — the property the
//! chunk scheme could never provide for a re-serialized document (ADR-0023/0024
//! rejection rationale).
//!
//! Scope (v1): traditional xref tables only. PDF 1.5+ cross-reference *streams*
//! (compressed xref) and object streams are out of scope and surface as the
//! typed [`PdfObjectError::NotTraditionalXref`] error. No PDF renderer, no
//! pdfium, no rasterizer — byte-level only.

use std::collections::{BTreeMap, HashSet};

use ark_bn254::Fr;
use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};
use thiserror::Error;

use crate::zk::chunk::fr_to_hex;
use crate::zk::field_validation::validate_be_bytes_to_fr;
use crate::zk::poseidon::domain_node;
use crate::zk::witness::redaction::{MAX_LEAVES, REDACTION_DEPTH};

/// Maximum indirect objects committed, mirroring `REDACTION_MAX_LEAVES` in
/// `proofs/circuits/parameters.circom` and `redaction::MAX_LEAVES`. A typical
/// PDF has 50–200 objects; a complex one up to ~1000. A document with more
/// than this many in-use objects is restricted to the first `MAX_OBJECTS` by
/// object id (and the drop is `tracing::warn!`-logged — never silently
/// truncated). See ADR-0025 "Object count bound".
pub const MAX_OBJECTS: usize = MAX_LEAVES;

/// Merkle depth such that `2^TREE_DEPTH == MAX_OBJECTS`. Mirrors
/// `REDACTION_MERKLE_DEPTH` / `redaction::REDACTION_DEPTH`.
pub const TREE_DEPTH: u8 = REDACTION_DEPTH as u8;

#[derive(Debug, Error)]
pub enum PdfObjectError {
    #[error(
        "not a traditional-xref PDF: the cross-reference at the startxref offset \
         is a cross-reference stream (PDF 1.5+), which is out of scope for v1"
    )]
    NotTraditionalXref,
    #[error("malformed xref / trailer: {0}")]
    MalformedXref(String),
    #[error("object {obj_id} xref offset {offset} is out of file bounds")]
    ObjectOutOfBounds { obj_id: u32, offset: u64 },
    #[error("object id {obj_id} not present in manifest")]
    UnknownObjectId { obj_id: u32 },
    #[error(
        "PDF has {found} in-use objects, exceeding the object-commitment capacity \
         of {max}; it cannot be sealed for object-level redaction (ADR-0025)"
    )]
    TooManyObjects { found: usize, max: usize },
    #[error("leaf computation failed: {0}")]
    LeafComputationFailed(String),
    #[error("Poseidon error: {0}")]
    PoseidonError(String),
}

/// One indirect PDF object's commitment metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfObject {
    /// Indirect object number.
    pub obj_id: u32,
    /// Object generation number (almost always 0).
    pub generation: u16,
    /// Byte offset of the object header (`N G obj`) in the original file.
    pub byte_offset: u64,
    /// Length of the raw object bytes (`byte_offset` through end of `endobj`).
    pub byte_length: u64,
    /// Lower-hex 64-char field element of the object's Poseidon leaf.
    pub leaf_hex: String,
}

/// Full object manifest for a sealed PDF: the per-object metadata plus the
/// Merkle root over all leaves (padded to `MAX_OBJECTS` with zero-leaves).
#[derive(Debug, Clone)]
pub struct PdfObjectManifest {
    /// In-use objects, ascending by `obj_id`.
    pub objects: Vec<PdfObject>,
    /// 64-char lower-hex Merkle root over the object leaves. This is the
    /// ledger leaf and the circuit's `originalRoot`.
    pub original_root_hex: String,
    pub tree_depth: u8,
    pub max_leaves: usize,
}

impl PdfObjectManifest {
    /// Recompute the object-tree root from `self.objects`' `leaf_hex` values and
    /// return it as lower-hex — the same fold the `redaction_validity` circuit
    /// performs over the witness leaves.
    ///
    /// Audit follow-up (redteam F-RD-2): the manifest persists `original_root`
    /// and the per-object leaves side by side in one DB row, and that row is the
    /// *sole* commitment to the object root (it is not separately anchored in a
    /// signed ledger structure). Callers that load a manifest before building a
    /// witness MUST assert this equals the stored `original_root_hex`, so a
    /// corrupt, partially-tampered, or forward-migrated row fails fast and
    /// explicitly here rather than surfacing as an opaque downstream proof
    /// failure. The decode mirrors [`witness_inputs`] byte-for-byte.
    pub fn recompute_root(&self) -> Result<String, PdfObjectError> {
        let mut leaves: Vec<Fr> = Vec::with_capacity(MAX_OBJECTS);
        for o in &self.objects {
            let bytes = hex::decode(&o.leaf_hex)
                .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?;
            let mut padded = [0u8; 32];
            let off = 32usize.saturating_sub(bytes.len());
            padded[off..].copy_from_slice(&bytes);
            // Fail closed: reject a persisted leaf whose 32-byte BE encoding is
            // ≥ the BN254 modulus instead of silently reducing it (F-RD-2
            // tamper hardening). Honest leaves are `fr_to_hex` of a canonical
            // Fr, so this never fires for an untampered manifest.
            leaves.push(
                validate_be_bytes_to_fr(&padded)
                    .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?,
            );
        }
        Ok(fr_to_hex(merkle_root(&leaves)?))
    }
}

// ── Byte-slice helpers ─────────────────────────────────────────────────────

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

// ── Minimal whitespace-tolerant token cursor over the xref region ──────────

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8], at: usize) -> Self {
        Cursor { b, i: at }
    }
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn at_keyword(&self, kw: &[u8]) -> bool {
        self.b[self.i.min(self.b.len())..].starts_with(kw)
    }
    /// Read a run of ASCII digits as a u64. None if no digit at the cursor.
    fn read_u64(&mut self) -> Option<u64> {
        self.skip_ws();
        let start = self.i;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        std::str::from_utf8(&self.b[start..self.i])
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
    }
    /// Read a single non-whitespace token byte (the xref entry type: `n`/`f`).
    fn read_type(&mut self) -> Option<u8> {
        self.skip_ws();
        if self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            Some(c)
        } else {
            None
        }
    }
}

/// True if the bytes at `c` look like an indirect-object header `N G obj`,
/// i.e. the startxref offset points at a cross-reference *stream*, not a table.
fn looks_like_obj_header(b: &[u8], at: usize) -> bool {
    let mut c = Cursor::new(b, at);
    if c.read_u64().is_none() {
        return false;
    }
    if c.read_u64().is_none() {
        return false;
    }
    c.skip_ws();
    c.at_keyword(b"obj")
}

/// Parse the `/Prev <int>` entry of a trailer dictionary starting at `from`,
/// bounded to the rest of the file. Returns None if absent.
fn parse_trailer_prev(b: &[u8], from: usize) -> Option<u64> {
    let region = &b[from.min(b.len())..];
    let pos = find(region, b"/Prev")? + b"/Prev".len();
    let mut c = Cursor::new(region, pos);
    c.read_u64()
}

/// Parse one traditional xref section at `offset`, recording in-use (`n`)
/// entries into `entries` (first-seen wins, so the latest section's entries
/// take precedence over older `/Prev` sections). Returns the `/Prev` offset of
/// an older section, if any.
fn parse_xref_section(
    b: &[u8],
    offset: usize,
    entries: &mut BTreeMap<u32, (u64, u16)>,
) -> Result<Option<u64>, PdfObjectError> {
    if offset >= b.len() {
        return Err(PdfObjectError::MalformedXref(format!(
            "xref offset {offset} is past end of file"
        )));
    }
    let mut c = Cursor::new(b, offset);
    c.skip_ws();
    if !c.at_keyword(b"xref") {
        // A cross-reference stream begins with an indirect-object header.
        if looks_like_obj_header(b, c.i) {
            return Err(PdfObjectError::NotTraditionalXref);
        }
        return Err(PdfObjectError::MalformedXref(
            "expected `xref` keyword at startxref offset".into(),
        ));
    }
    c.i += b"xref".len();

    loop {
        c.skip_ws();
        if c.at_keyword(b"trailer") {
            c.i += b"trailer".len();
            break;
        }
        // Subsection header: <start> <count>.
        let start = c
            .read_u64()
            .ok_or_else(|| PdfObjectError::MalformedXref("missing subsection start".into()))?;
        let count = c
            .read_u64()
            .ok_or_else(|| PdfObjectError::MalformedXref("missing subsection count".into()))?;
        for k in 0..count {
            let off = c.read_u64().ok_or_else(|| {
                PdfObjectError::MalformedXref(format!("missing offset for entry {k}"))
            })?;
            let gen = c.read_u64().ok_or_else(|| {
                PdfObjectError::MalformedXref(format!("missing generation for entry {k}"))
            })?;
            let ty = c
                .read_type()
                .ok_or_else(|| PdfObjectError::MalformedXref("missing entry type".into()))?;
            let obj_id = (start + k) as u32;
            if ty == b'n' {
                entries.entry(obj_id).or_insert((off, gen as u16));
            }
        }
    }

    Ok(parse_trailer_prev(b, c.i))
}

/// Find the `[start, end)` byte span of the indirect object whose header is at
/// `offset`: from the header through the end of its `endobj` keyword.
fn object_span(b: &[u8], obj_id: u32, offset: usize) -> Result<(usize, usize), PdfObjectError> {
    if offset >= b.len() {
        return Err(PdfObjectError::ObjectOutOfBounds {
            obj_id,
            offset: offset as u64,
        });
    }
    let region = &b[offset..];
    let oob = || PdfObjectError::ObjectOutOfBounds {
        obj_id,
        offset: offset as u64,
    };
    let first_endobj = find(region, b"endobj");
    // A content stream's binary payload may itself contain the bytes `endobj`.
    // If a `stream` token precedes the first `endobj`, the real object end is the
    // `endobj` that follows the matching `endstream`, not the first occurrence.
    let stream_kw = find(region, b"stream");
    let rel_end = match (stream_kw, first_endobj) {
        (Some(s), Some(e)) if s < e => {
            let after_stream = s + b"stream".len();
            let es = find(&region[after_stream..], b"endstream").ok_or_else(oob)?;
            let after_endstream = after_stream + es + b"endstream".len();
            find(&region[after_endstream..], b"endobj").map(|r| after_endstream + r)
        }
        _ => first_endobj,
    };
    let rel = rel_end.ok_or_else(oob)?;
    Ok((offset, offset + rel + b"endobj".len()))
}

/// Fold `leaves` (padded to `MAX_OBJECTS` with zero-leaves) into a depth-
/// `TREE_DEPTH` domain-1 Poseidon Merkle root — identical node hashing to the
/// circuit and `chunk.rs::root_of_16`, only wider/deeper.
fn merkle_root(leaves: &[Fr]) -> Result<Fr, PdfObjectError> {
    debug_assert!(leaves.len() <= MAX_OBJECTS);
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(MAX_OBJECTS, Fr::from(0u64));
    for _ in 0..TREE_DEPTH {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(
                domain_node(1, pair[0], pair[1])
                    .map_err(|e| PdfObjectError::PoseidonError(e.to_string()))?,
            );
        }
        level = next;
    }
    debug_assert_eq!(level.len(), 1);
    Ok(level[0])
}

/// Parse a PDF's traditional xref table, extract all in-use indirect objects,
/// compute the per-object Poseidon leaf, and fold the Merkle root.
///
/// Returns [`PdfObjectError::NotTraditionalXref`] for PDF 1.5+ cross-reference
/// stream files so the caller can surface a clear "unsupported PDF" message.
/// Span of one in-use indirect object — produced by [`extract_object_spans`]
/// for callers (audit-side `verify_redaction_binding`) that need the byte
/// ranges without recomputing per-object Pedersen leaves.
#[derive(Debug, Clone, Copy)]
pub struct ObjectSpan {
    pub obj_id: u32,
    pub generation: u16,
    pub byte_start: usize,
    pub byte_end: usize,
}

/// Parse the traditional xref table + `/Prev` chain and return one [`ObjectSpan`]
/// per in-use indirect object in obj-id-ascending order. The leaf-computing
/// counterpart is [`extract_objects`]; the auditor uses the spans-only path
/// because it gets per-revealed-object blindings from the bundle rather than
/// re-deriving them from a (server-only) `blind_secret`.
pub fn extract_object_spans(pdf_bytes: &[u8]) -> Result<Vec<ObjectSpan>, PdfObjectError> {
    // 1. Locate the last `startxref` → xref table offset.
    let sx = rfind(pdf_bytes, b"startxref")
        .ok_or_else(|| PdfObjectError::MalformedXref("no startxref marker".into()))?;
    let mut c = Cursor::new(pdf_bytes, sx + b"startxref".len());
    let xref_off = c
        .read_u64()
        .ok_or_else(|| PdfObjectError::MalformedXref("no offset after startxref".into()))?
        as usize;

    // 2. Walk the xref section + /Prev chain (latest section wins).
    let mut entries: BTreeMap<u32, (u64, u16)> = BTreeMap::new();
    let mut visited: HashSet<usize> = HashSet::new();
    let mut next = Some(xref_off);
    while let Some(off) = next {
        if !visited.insert(off) {
            break; // /Prev cycle guard
        }
        let prev = parse_xref_section(pdf_bytes, off, &mut entries)?;
        next = prev.map(|p| p as usize);
    }

    let mut spans = Vec::with_capacity(entries.len());
    for (&obj_id, &(offset, generation)) in &entries {
        let (start, end) = object_span(pdf_bytes, obj_id, offset as usize)?;
        spans.push(ObjectSpan {
            obj_id,
            generation,
            byte_start: start,
            byte_end: end,
        });
    }
    Ok(spans)
}

pub fn extract_objects(
    pdf_bytes: &[u8],
    blind_secret: &[u8],
) -> Result<PdfObjectManifest, PdfObjectError> {
    // The per-object blinding is derived from the ORIGINAL file's content hash
    // (ADR-0026): it is pinned at ingest and re-derivable, so re-ingesting the
    // same bytes under the same secret reproduces the same root.
    let content_hash = blake3::hash(pdf_bytes);

    // 1. Walk the xref + spans (factored out for the auditor's spans-only path).
    let spans = extract_object_spans(pdf_bytes)?;

    // 2. Re-key by obj_id for the leaf loop; the obj-id-ascending order is
    //    preserved because `extract_object_spans` iterates a `BTreeMap`.
    let mut objects: Vec<(PdfObject, Fr)> = Vec::with_capacity(spans.len());
    for s in &spans {
        let obj_id = s.obj_id;
        let generation = s.generation;
        let offset = s.byte_start as u64;
        let (start, end) = (s.byte_start, s.byte_end);
        // Hiding leaf (ADR-0026): Poseidon(C.x, C.y), C = content·G + b·H, with a
        // deterministic per-object blinding so a redacted object's content can't
        // be brute-forced from the pinned root. `segment_id` = obj_id big-endian.
        let id_be = obj_id.to_be_bytes();
        let content = content_scalar(&id_be, &pdf_bytes[start..end]);
        let blinding = derive_blinding(blind_secret, content_hash.as_bytes(), &id_be);
        let leaf_fr = redaction_leaf(&content, &blinding)
            .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?;
        objects.push((
            PdfObject {
                obj_id,
                generation,
                byte_offset: offset,
                byte_length: (end - start) as u64,
                leaf_hex: fr_to_hex(leaf_fr),
            },
            leaf_fr,
        ));
    }

    // 4. Reject (never truncate) when the in-use object count exceeds capacity.
    // Truncating would fold only the first MAX_OBJECTS leaves into the root,
    // leaving objects MAX_OBJECTS+1.. uncommitted: unbindable by the proof and
    // un-redactable (apply_redaction can only zero-fill objects in the manifest),
    // so their plaintext would survive in the "redacted" artifact. Fail closed
    // so the caller learns the document can't be sealed. ADR-0025.
    if objects.len() > MAX_OBJECTS {
        return Err(PdfObjectError::TooManyObjects {
            found: objects.len(),
            max: MAX_OBJECTS,
        });
    }

    let leaves: Vec<Fr> = objects.iter().map(|(_, f)| *f).collect();
    let root = merkle_root(&leaves)?;

    Ok(PdfObjectManifest {
        objects: objects.into_iter().map(|(o, _)| o).collect(),
        original_root_hex: fr_to_hex(root),
        tree_depth: TREE_DEPTH,
        max_leaves: MAX_OBJECTS,
    })
}

/// Zero-fill the content bytes of `redacted_obj_ids` in `pdf_bytes`.
///
/// Overwrites everything strictly between each object's `obj` and `endobj`
/// keywords with NULs, leaving the `N G obj` header and `endobj` trailer (and
/// every other byte in the file) untouched — so the output is the same length,
/// every offset and the xref table are preserved, and non-redacted objects are
/// byte-for-byte identical to the input. The redacted object remains re-parsable
/// (its framing survives), but its content — and therefore its recomputed leaf —
/// is destroyed; the true leaf is carried only in the bundle.
///
/// # Errors
/// Returns [`PdfObjectError::UnknownObjectId`] if any `obj_id` is not present in
/// `manifest.objects`, and [`PdfObjectError::ObjectOutOfBounds`] /
/// [`PdfObjectError::MalformedXref`] if an object's recorded span no longer
/// matches `pdf_bytes`.
pub fn apply_redaction(
    pdf_bytes: &[u8],
    manifest: &PdfObjectManifest,
    redacted_obj_ids: &[u32],
) -> Result<Vec<u8>, PdfObjectError> {
    let mut out = pdf_bytes.to_vec();
    for &id in redacted_obj_ids {
        let obj = manifest
            .objects
            .iter()
            .find(|o| o.obj_id == id)
            .ok_or(PdfObjectError::UnknownObjectId { obj_id: id })?;
        let start = obj.byte_offset as usize;
        let end = start + obj.byte_length as usize;
        if end > out.len() {
            return Err(PdfObjectError::ObjectOutOfBounds {
                obj_id: id,
                offset: obj.byte_offset,
            });
        }
        let seg = &pdf_bytes[start..end];
        // Content lies strictly between the first `obj` and the last `endobj`.
        let obj_kw = find(seg, b"obj").ok_or_else(|| {
            PdfObjectError::MalformedXref(format!("object {id}: no `obj` keyword"))
        })? + b"obj".len();
        let endobj_kw = rfind(seg, b"endobj").ok_or_else(|| {
            PdfObjectError::MalformedXref(format!("object {id}: no `endobj` keyword"))
        })?;
        for byte in out.iter_mut().take(start + endobj_kw).skip(start + obj_kw) {
            *byte = 0;
        }
    }
    Ok(out)
}

/// Build the `redaction_validity` witness inputs from an object manifest:
/// the `MAX_OBJECTS`-padded leaf vector and the per-leaf Merkle
/// `(path_elements, path_indices)` in the shape `RedactionWitness` expects.
///
/// This is the object-level replacement for
/// `chunk::{chunk_hex_to_leaf, paths_for_chunk_tree}` — the witness builder
/// calls `extract_objects` and then this, instead of chunking raw bytes. The
/// Merkle path computation is identical to the chunk path, only deeper/wider.
#[allow(clippy::type_complexity)]
pub fn witness_inputs(
    manifest: &PdfObjectManifest,
) -> Result<(Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<u8>>), PdfObjectError> {
    // Padded leaf vector (real leaves in obj-id order, then zero-leaves).
    let mut leaves: Vec<Fr> = Vec::with_capacity(MAX_OBJECTS);
    for o in &manifest.objects {
        let bytes = hex::decode(&o.leaf_hex)
            .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?;
        let mut padded = [0u8; 32];
        let off = 32usize.saturating_sub(bytes.len());
        padded[off..].copy_from_slice(&bytes);
        // Fail closed on a non-canonical (≥ modulus) persisted leaf rather than
        // silently reducing it — same F-RD-2 guard as `recompute_root`.
        leaves.push(
            validate_be_bytes_to_fr(&padded)
                .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?,
        );
    }
    leaves.resize(MAX_OBJECTS, Fr::from(0u64));

    // Pre-compute every tree level once; each leaf's path is the sibling at the
    // right index per level (same algorithm as `chunk::paths_for_chunk_tree`).
    let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(TREE_DEPTH as usize + 1);
    levels.push(leaves.clone());
    for d in 0..TREE_DEPTH as usize {
        let cur = &levels[d];
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks(2) {
            next.push(
                domain_node(1, pair[0], pair[1])
                    .map_err(|e| PdfObjectError::PoseidonError(e.to_string()))?,
            );
        }
        levels.push(next);
    }

    let mut path_elements = Vec::with_capacity(MAX_OBJECTS);
    let mut path_indices = Vec::with_capacity(MAX_OBJECTS);
    for leaf_i in 0..MAX_OBJECTS {
        let mut idx = leaf_i;
        let mut pe = Vec::with_capacity(TREE_DEPTH as usize);
        let mut pi = Vec::with_capacity(TREE_DEPTH as usize);
        for level in levels.iter().take(TREE_DEPTH as usize) {
            let sibling = idx ^ 1;
            pe.push(level[sibling]);
            pi.push((idx & 1) as u8);
            idx /= 2;
        }
        path_elements.push(pe);
        path_indices.push(pi);
    }
    Ok((leaves, path_elements, path_indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed server blinding secret for deterministic test vectors.
    const TEST_BLIND_SECRET: &[u8] = &[0x5au8; 32];

    /// Build a minimal valid traditional-xref PDF from object body strings
    /// (object `i+1`'s body is `bodies[i]`), computing exact byte offsets so
    /// the xref table is correct. Returns the file bytes.
    fn build_pdf(bodies: &[&str]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            offsets.push(buf.len());
            buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            buf.extend_from_slice(body.as_bytes());
            buf.extend_from_slice(b"\nendobj\n");
        }
        let xref_off = buf.len();
        let n = bodies.len() + 1; // include free object 0
        buf.extend_from_slice(format!("xref\n0 {n}\n").as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
        buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    fn sample_pdf() -> Vec<u8> {
        build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        ])
    }

    #[test]
    fn extract_round_trip_object_count() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        assert_eq!(m.objects.len(), 3, "three in-use objects");
        assert_eq!(m.objects[0].obj_id, 1);
        assert_eq!(m.objects[2].obj_id, 3);
        assert_eq!(m.tree_depth, TREE_DEPTH);
        assert_eq!(m.max_leaves, MAX_OBJECTS);
        assert_eq!(m.original_root_hex.len(), 64);
        // Each object's bytes start at `N 0 obj` and end with `endobj`.
        for o in &m.objects {
            let seg = &pdf[o.byte_offset as usize..(o.byte_offset + o.byte_length) as usize];
            assert!(seg.ends_with(b"endobj"));
            assert!(super::find(seg, b"obj").is_some());
        }
    }

    #[test]
    fn recompute_root_matches_stored_and_detects_tamper() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        // Honest manifest: recomputed fold equals the stored root.
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);

        // Tamper one persisted leaf without updating the stored root — the
        // recompute now diverges, which is exactly what load_object_manifest's
        // cross-check rejects (F-RD-2).
        let mut tampered = m.clone();
        let mut b = hex::decode(&tampered.objects[0].leaf_hex).unwrap();
        b[31] ^= 0x01;
        tampered.objects[0].leaf_hex = hex::encode(b);
        assert_ne!(
            tampered.recompute_root().unwrap(),
            tampered.original_root_hex
        );
    }

    #[test]
    fn extract_is_deterministic() {
        let pdf = sample_pdf();
        let a = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let b = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        assert_eq!(a.original_root_hex, b.original_root_hex);
        assert_eq!(
            a.objects
                .iter()
                .map(|o| o.leaf_hex.clone())
                .collect::<Vec<_>>(),
            b.objects
                .iter()
                .map(|o| o.leaf_hex.clone())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn apply_redaction_zeroes_content_preserves_length_and_others() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        // Redact object 2.
        let redacted = apply_redaction(&pdf, &m, &[2]).unwrap();
        assert_eq!(redacted.len(), pdf.len(), "file length must be identical");

        let obj2 = m.objects.iter().find(|o| o.obj_id == 2).unwrap();
        let start = obj2.byte_offset as usize;
        let end = start + obj2.byte_length as usize;
        let seg = &redacted[start..end];
        // Framing survives; content between obj/endobj is all NUL.
        let obj_kw = super::find(seg, b"obj").unwrap() + 3;
        let endobj_kw = super::rfind(seg, b"endobj").unwrap();
        assert!(
            seg[obj_kw..endobj_kw].iter().all(|&b| b == 0),
            "content must be zeroed"
        );
        assert!(seg.ends_with(b"endobj"));

        // Objects 1 and 3 are byte-identical to the original.
        for id in [1u32, 3] {
            let o = m.objects.iter().find(|o| o.obj_id == id).unwrap();
            let s = o.byte_offset as usize;
            let e = s + o.byte_length as usize;
            assert_eq!(&redacted[s..e], &pdf[s..e], "object {id} must be untouched");
        }
    }

    /// Recompute a revealed object's committed leaf from its (byte-identical)
    /// post-redaction bytes + the deterministic blinding — exactly what a
    /// recipient does to verify a revealed segment (ADR-0026). The blinding is
    /// pinned to the ORIGINAL file's content hash, so re-extracting the redacted
    /// file would use a different hash; the recipient instead uses the published
    /// blinding, which is what this models.
    #[test]
    fn revealed_leaf_recomputes_from_bytes_and_blinding() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);
        let redacted = apply_redaction(&pdf, &m, &[2]).unwrap();

        let recompute = |id: u32, bytes: &[u8]| {
            let id_be = id.to_be_bytes();
            let content = content_scalar(&id_be, bytes);
            let blinding = derive_blinding(TEST_BLIND_SECRET, content_hash.as_bytes(), &id_be);
            fr_to_hex(redaction_leaf(&content, &blinding).unwrap())
        };

        // Revealed objects: bytes survive redaction, so the leaf recomputes and
        // matches the committed manifest leaf.
        for id in [1u32, 3] {
            let o = m.objects.iter().find(|o| o.obj_id == id).unwrap();
            let (s, e) = (
                o.byte_offset as usize,
                (o.byte_offset + o.byte_length) as usize,
            );
            assert_eq!(
                &redacted[s..e],
                &pdf[s..e],
                "revealed object {id} bytes unchanged"
            );
            assert_eq!(
                recompute(id, &redacted[s..e]),
                o.leaf_hex,
                "object {id} leaf"
            );
        }

        // Redacted object: its content is destroyed, so recomputing from the
        // redacted bytes no longer matches the committed leaf.
        let o2 = m.objects.iter().find(|o| o.obj_id == 2).unwrap();
        let (s, e) = (
            o2.byte_offset as usize,
            (o2.byte_offset + o2.byte_length) as usize,
        );
        assert_ne!(
            recompute(2, &redacted[s..e]),
            o2.leaf_hex,
            "redacted leaf differs"
        );
    }

    #[test]
    fn cross_reference_stream_pdf_returns_not_traditional() {
        // A PDF 1.5 file whose startxref points at a cross-reference *stream*
        // (an indirect object), not an `xref` table.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.5\n");
        let xref_off = buf.len();
        buf.extend_from_slice(
            b"7 0 obj\n<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R >>\nstream\n",
        );
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        let err = extract_objects(&buf, TEST_BLIND_SECRET).unwrap_err();
        assert!(
            matches!(err, PdfObjectError::NotTraditionalXref),
            "got {err:?}"
        );
    }

    #[test]
    fn missing_startxref_is_malformed() {
        let err = extract_objects(b"%PDF-1.4\nnot a pdf", TEST_BLIND_SECRET).unwrap_err();
        assert!(
            matches!(err, PdfObjectError::MalformedXref(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn witness_inputs_paths_reach_root() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let (leaves, pe, pi) = witness_inputs(&m).unwrap();
        assert_eq!(leaves.len(), MAX_OBJECTS);
        assert_eq!(pe.len(), MAX_OBJECTS);
        let root = super::merkle_root(&leaves).unwrap();
        let root_hex = fr_to_hex(root);
        assert_eq!(root_hex, m.original_root_hex);
        // Every leaf's path must reconstruct the root (parity with the circuit).
        for i in 0..MAX_OBJECTS {
            let computed =
                crate::zk::poseidon::compute_merkle_root(leaves[i], &pe[i], &pi[i], 1).unwrap();
            assert_eq!(computed, root, "leaf {i} path must reach root");
        }
    }

    /// Emit `verifiers/test_vectors/redaction_vectors.json` from this Rust
    /// reference implementation. Run with the env flag set, e.g.
    /// `OLYMPUS_EMIT_REDACTION_VECTORS=1 cargo test -p olympus-desktop \
    ///   pdf_objects::tests::emit_redaction_vectors -- --ignored --nocapture`.
    /// The JS verifier (`verifiers/javascript/test_redaction.js`) reproduces
    /// every value byte-for-byte; `object_leaf_conformance_locked` pins the
    /// first leaf so drift fails CI without regenerating.
    #[test]
    #[ignore]
    fn emit_redaction_vectors() {
        if std::env::var("OLYMPUS_EMIT_REDACTION_VECTORS").is_err() {
            return;
        }
        use crate::zk::poseidon::redaction_commitment;
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            "<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (SECRET) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ];
        let pdf = build_pdf(&bodies);
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);
        // Redact object 4 (the content stream holding "SECRET").
        let reveal_mask_real: Vec<bool> = m.objects.iter().map(|o| o.obj_id != 4).collect();

        // Full 1024-wide padded leaves + mask, matching the circuit witness.
        let (leaves, _, _) = witness_inputs(&m).unwrap();
        let mut full_mask = vec![false; MAX_OBJECTS];
        for (i, &b) in reveal_mask_real.iter().enumerate() {
            full_mask[i] = b;
        }
        let revealed_count = full_mask.iter().filter(|&&b| b).count() as u64;
        let commit = redaction_commitment(revealed_count, &leaves, &full_mask).unwrap();
        let commit_dec = {
            use ark_ff::{BigInteger, PrimeField};
            num_bigint::BigUint::from_bytes_be(&commit.into_bigint().to_bytes_be()).to_string()
        };

        let objs_json: Vec<serde_json::Value> = m
            .objects
            .iter()
            .map(|o| {
                let bytes = &pdf[o.byte_offset as usize..(o.byte_offset + o.byte_length) as usize];
                // Per-object blinding (decimal) so the JS verifier can recompute
                // the hiding leaf Poseidon(commit(content, blinding)).
                let blinding = derive_blinding(
                    TEST_BLIND_SECRET,
                    content_hash.as_bytes(),
                    &o.obj_id.to_be_bytes(),
                );
                serde_json::json!({
                    "obj_id": o.obj_id,
                    "bytes_hex": hex::encode(bytes),
                    "blinding_decimal": blinding.to_string(),
                    "leaf_hex": o.leaf_hex,
                })
            })
            .collect();

        let out = serde_json::json!({
            "scheme": "pdf-object-level-redaction-adr0026",
            "obj_domain": olympus_crypto::POSEIDON_DOMAIN_OBJ_LEAF,
            "blind_prefix": String::from_utf8_lossy(olympus_crypto::redaction::REDACTION_BLIND_PREFIX),
            "blind_secret_hex": hex::encode(TEST_BLIND_SECRET),
            "content_hash_hex": hex::encode(content_hash.as_bytes()),
            "tree_depth": m.tree_depth,
            "max_leaves": m.max_leaves,
            "objects": objs_json,
            "original_root_hex": m.original_root_hex,
            "reveal_mask": reveal_mask_real.iter().map(|&b| b as u8).collect::<Vec<u8>>(),
            "revealed_count": revealed_count,
            "redacted_commitment_decimal": commit_dec,
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verifiers/test_vectors/redaction_vectors.json"
        );
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
        eprintln!("wrote {path}");
    }

    /// The (objects → leaves → root) pipeline uses the shared
    /// `olympus_crypto::redaction` hiding-leaf primitive and folds to the
    /// manifest root. The cross-language byte-pin (against
    /// `verifiers/test_vectors/redaction_vectors.json`, asserted by
    /// `verifiers/javascript/test_redaction.js`) is regenerated via
    /// `emit_redaction_vectors`; the hiding leaf depends on the per-file blinding
    /// so the vectors carry the blindings (ADR-0026 Phase 3).
    #[test]
    fn leaves_match_shared_primitive_and_root_folds() {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            "<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (SECRET) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ];
        let pdf = build_pdf(&bodies);
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);

        // Every manifest leaf is exactly the shared hiding-leaf primitive.
        for o in &m.objects {
            let (s, e) = (
                o.byte_offset as usize,
                (o.byte_offset + o.byte_length) as usize,
            );
            let id_be = o.obj_id.to_be_bytes();
            let content = content_scalar(&id_be, &pdf[s..e]);
            let blinding = derive_blinding(TEST_BLIND_SECRET, content_hash.as_bytes(), &id_be);
            let leaf = redaction_leaf(&content, &blinding).unwrap();
            assert_eq!(fr_to_hex(leaf), o.leaf_hex, "object {} leaf", o.obj_id);
        }

        // The padded witness leaves fold to the manifest's committed root.
        let (leaves, _, _) = witness_inputs(&m).unwrap();
        assert_eq!(
            fr_to_hex(super::merkle_root(&leaves).unwrap()),
            m.original_root_hex
        );
    }

    /// Lockstep JS↔Rust pin (FE-4 / ADR-0026): the Rust pipeline must produce
    /// the pinned `redacted_commitment_decimal` against
    /// `verifiers/test_vectors/redaction_vectors.json` AND the file's value
    /// must equal that pinned literal. The Vitest test
    /// `redactionBinding.conformance.test.ts` asserts against the same JSON
    /// file with the same expectations, so any drift on either side fails
    /// both suites and both must be updated in the same commit.
    ///
    /// If this assertion fires after an intentional change, regenerate the
    /// vectors via `OLYMPUS_EMIT_REDACTION_VECTORS=1 cargo test … emit_redaction_vectors --
    /// --ignored --nocapture`, then update the literal here and in
    /// `redactionBinding.conformance.test.ts` in the same commit.
    #[test]
    fn js_conformance_fixture_locked() {
        use crate::zk::poseidon::redaction_commitment;
        use ark_ff::{BigInteger, PrimeField};

        // Pinned: must match `redacted_commitment_decimal` in
        // `verifiers/test_vectors/redaction_vectors.json` and the Vitest
        // assertion in `redactionBinding.conformance.test.ts`.
        const PINNED_COMMIT_DEC: &str =
            "19347202431527259502706873285849425419111639863482880635915169646652198331279";

        let vectors_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verifiers/test_vectors/redaction_vectors.json"
        );
        let raw = std::fs::read_to_string(vectors_path).expect("read redaction_vectors.json");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");

        assert_eq!(
            v["scheme"].as_str(),
            Some("pdf-object-level-redaction-adr0026"),
            "vector scheme drift"
        );
        assert_eq!(v["max_leaves"].as_u64(), Some(MAX_OBJECTS as u64));
        assert_eq!(v["tree_depth"].as_u64(), Some(TREE_DEPTH as u64));
        assert_eq!(
            v["redacted_commitment_decimal"].as_str(),
            Some(PINNED_COMMIT_DEC),
            "vectors file disagrees with the JS↔Rust pinned literal"
        );

        // Recompute the commitment via the Rust pipeline against the same vector
        // inputs and assert byte-identity. This is what guarantees that any
        // change to the Rust primitives (Pedersen, content_scalar, fold order,
        // Poseidon parameters, …) trips this pin even if the vectors file
        // happens to still parse.
        let objs = v["objects"].as_array().expect("objects[]");
        let mut real_leaves: Vec<Fr> = Vec::with_capacity(objs.len());
        for o in objs {
            let obj_id = o["obj_id"].as_u64().expect("obj_id") as u32;
            let bytes =
                hex::decode(o["bytes_hex"].as_str().expect("bytes_hex")).expect("hex bytes");
            let blinding = num_bigint::BigInt::parse_bytes(
                o["blinding_decimal"]
                    .as_str()
                    .expect("blinding_decimal")
                    .as_bytes(),
                10,
            )
            .expect("blinding decimal");
            let id_be = obj_id.to_be_bytes();
            let content = content_scalar(&id_be, &bytes);
            let leaf = redaction_leaf(&content, &blinding).expect("leaf");
            assert_eq!(
                fr_to_hex(leaf),
                o["leaf_hex"].as_str().expect("leaf_hex"),
                "object {obj_id} leaf drift"
            );
            real_leaves.push(leaf);
        }

        let mut padded = real_leaves.clone();
        padded.resize(MAX_OBJECTS, Fr::from(0u64));

        let mask_in = v["reveal_mask"].as_array().expect("reveal_mask");
        let mut mask = vec![false; MAX_OBJECTS];
        for (i, b) in mask_in.iter().enumerate() {
            mask[i] = b.as_u64() == Some(1);
        }
        let revealed_count = mask.iter().filter(|&&b| b).count() as u64;
        let commit = redaction_commitment(revealed_count, &padded, &mask).expect("commit");
        let commit_dec =
            num_bigint::BigUint::from_bytes_be(&commit.into_bigint().to_bytes_be()).to_string();
        assert_eq!(
            commit_dec, PINNED_COMMIT_DEC,
            "Rust pipeline drift — JS↔Rust fixture broken"
        );
    }

    #[test]
    fn object_span_skips_endobj_inside_stream_payload() {
        // Object 1's stream payload literally contains the bytes `endobj`; the
        // span must extend to the real `endobj` after `endstream`, not the
        // first occurrence inside the stream.
        let pdf = build_pdf(&[
            "<< /Length 20 >>\nstream\nhi endobj here\nendstream",
            "<< /Type /Catalog >>",
        ]);
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let o1 = m.objects.iter().find(|o| o.obj_id == 1).unwrap();
        let seg = &pdf[o1.byte_offset as usize..(o1.byte_offset + o1.byte_length) as usize];
        assert!(seg.ends_with(b"endobj"));
        assert!(
            super::find(seg, b"endstream").is_some(),
            "must include the stream"
        );
    }

    #[test]
    fn apply_redaction_errors_on_unknown_obj_id() {
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let err = apply_redaction(&pdf, &m, &[999]).unwrap_err();
        assert!(
            matches!(err, PdfObjectError::UnknownObjectId { obj_id: 999 }),
            "got {err:?}"
        );
    }

    #[test]
    fn extract_objects_fails_closed_above_max_objects() {
        // MAX_OBJECTS + 1 in-use objects must be rejected — truncating would
        // leave the overflow objects uncommitted (unbindable + un-redactable).
        let bodies: Vec<String> = (0..=MAX_OBJECTS)
            .map(|i| format!("<< /Type /Test /N {i} >>"))
            .collect();
        let body_refs: Vec<&str> = bodies.iter().map(String::as_str).collect();
        let pdf = build_pdf(&body_refs);
        let err = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap_err();
        assert!(
            matches!(
                err,
                PdfObjectError::TooManyObjects { found, max }
                    if found == MAX_OBJECTS + 1 && max == MAX_OBJECTS
            ),
            "got {err:?}"
        );
    }
}
