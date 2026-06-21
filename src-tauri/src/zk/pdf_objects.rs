//! PDF object-level redaction commitment (ADR-0025 / ADR-0026).
//!
//! Parses a traditional-xref PDF's cross-reference table, extracts every
//! indirect object's raw bytes, computes one **hiding** Poseidon leaf per object
//! (`olympus_crypto::redaction::redaction_leaf` — a blinded Pedersen commitment,
//! ADR-0026), and folds the leaves into the ADR-0030 variable-depth domain-1
//! Poseidon Merkle commitment the V3 signed-Merkle bundle proves over. The root
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
use crate::zk::segment::{variable_depth_fold_root, variable_geometry, MAX_REDACTION_SEGMENTS};

/// Maximum indirect objects committed — the ADR-0030 variable-depth fold cap. A
/// document with more in-use objects than this is rejected
/// ([`PdfObjectError::TooManyObjects`], never silently truncated).
pub const MAX_OBJECTS: usize = MAX_REDACTION_SEGMENTS;

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

impl PdfObjectError {
    /// Map a [`crate::zk::segment::SegmentError`] from the shared variable-depth
    /// fold back into a PDF-specific error (the fold can only raise
    /// `TooFewSegments` / `TooManySegments` / `Poseidon` here).
    fn from_segment(e: crate::zk::segment::SegmentError) -> Self {
        use crate::zk::segment::SegmentError;
        match e {
            SegmentError::TooManySegments { found, max } => {
                PdfObjectError::TooManyObjects { found, max }
            }
            SegmentError::Poseidon(s) => PdfObjectError::PoseidonError(s),
            other => PdfObjectError::LeafComputationFailed(other.to_string()),
        }
    }
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
/// ADR-0030 variable-depth Merkle root over the object leaves.
#[derive(Debug, Clone)]
pub struct PdfObjectManifest {
    /// In-use objects, ascending by `obj_id`.
    pub objects: Vec<PdfObject>,
    /// 64-char lower-hex variable-depth Merkle root over the object leaves. This
    /// is the ledger leaf and the bundle's `original_root`.
    pub original_root_hex: String,
    /// `⌈log2 N⌉` for `N` objects (ADR-0030 §1).
    pub tree_depth: u8,
    /// The real object count `N` (ADR-0030 §1 — no fixed padding).
    pub max_leaves: usize,
}

impl PdfObjectManifest {
    /// Recompute the object-tree root from `self.objects`' `leaf_hex` values and
    /// return it as lower-hex — the ADR-0030 §1 variable-depth domain-1 fold the
    /// V3 signed-Merkle bundle proves over.
    ///
    /// Audit follow-up (redteam F-RD-2): the manifest persists `original_root`
    /// and the per-object leaves side by side in one DB row, and that row is the
    /// *sole* commitment to the object root (it is not separately anchored in a
    /// signed ledger structure). Callers that load a manifest before issuing a
    /// bundle MUST assert this equals the stored `original_root_hex`, so a
    /// corrupt, partially-tampered, or forward-migrated row fails fast and
    /// explicitly here rather than surfacing as an opaque downstream failure.
    pub fn recompute_root(&self) -> Result<String, PdfObjectError> {
        let leaves = self.leaves()?;
        Ok(fr_to_hex(
            variable_depth_fold_root(&leaves).map_err(PdfObjectError::from_segment)?,
        ))
    }

    /// Decode every object's persisted `leaf_hex` into the `N` **real** leaves
    /// (ADR-0030 §1 — no fixed padding), in obj-id order. Fails closed on a
    /// non-canonical (`≥ modulus`) or over-long leaf (F-RD-2 tamper hardening).
    fn leaves(&self) -> Result<Vec<Fr>, PdfObjectError> {
        let mut leaves: Vec<Fr> = Vec::with_capacity(self.objects.len());
        for o in &self.objects {
            let bytes = hex::decode(&o.leaf_hex)
                .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?;
            if bytes.len() > 32 {
                return Err(PdfObjectError::LeafComputationFailed(format!(
                    "leaf_hex decodes to {} bytes (> 32)",
                    bytes.len()
                )));
            }
            let mut padded = [0u8; 32];
            let off = 32usize.saturating_sub(bytes.len());
            padded[off..].copy_from_slice(&bytes);
            leaves.push(
                validate_be_bytes_to_fr(&padded)
                    .map_err(|e| PdfObjectError::LeafComputationFailed(e.to_string()))?,
            );
        }
        Ok(leaves)
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
                // DoS guard (audit redaction-dos-01): cap the in-use object
                // count DURING the walk so a table declaring millions of
                // entries is rejected before we ever build a giant map or run a
                // single per-object scan.
                if entries.len() > MAX_OBJECTS {
                    return Err(PdfObjectError::TooManyObjects {
                        found: entries.len(),
                        max: MAX_OBJECTS,
                    });
                }
            }
        }
    }

    Ok(parse_trailer_prev(b, c.i))
}

/// Find the `[start, end)` byte span of the indirect object whose header is at
/// `offset`: from the header through the end of its `endobj` keyword.
fn object_span(
    b: &[u8],
    obj_id: u32,
    offset: usize,
    scan_end: usize,
) -> Result<(usize, usize), PdfObjectError> {
    // DoS guard (audit redaction-dos-01): bound the `endobj` search to
    // `scan_end` — the next in-use object's offset. In-use objects occupy
    // disjoint byte ranges, so an object's `endobj` always lies before the next
    // object starts; bounding here caps the TOTAL scan across all objects at
    // O(filesize) instead of O(objects × filesize), which a crafted xref table
    // (many entries → one offset, `endobj` at EOF) would otherwise exploit.
    let end_bound = scan_end.min(b.len());
    if offset >= end_bound {
        return Err(PdfObjectError::ObjectOutOfBounds {
            obj_id,
            offset: offset as u64,
        });
    }
    let region = &b[offset..end_bound];
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

    // DoS guard (audit redaction-dos-01), part 1: reject before the per-object
    // scan if the table declares more in-use objects than the commitment cap.
    // (parse_xref_section also bails mid-walk; this covers the /Prev-chain total.)
    if entries.len() > MAX_OBJECTS {
        return Err(PdfObjectError::TooManyObjects {
            found: entries.len(),
            max: MAX_OBJECTS,
        });
    }
    // Part 2: in-use objects occupy disjoint byte ranges, so their offsets are
    // distinct. Duplicate offsets are malformed — and are precisely the
    // redaction-bomb's signature (millions of obj-ids → one offset, `endobj` at
    // EOF). Reject them, which lets us bound each object's `endobj` scan to the
    // NEXT distinct offset → disjoint windows → total scan O(filesize).
    let mut offsets: Vec<usize> = entries.values().map(|&(off, _)| off as usize).collect();
    offsets.sort_unstable();
    let declared = offsets.len();
    offsets.dedup();
    if offsets.len() != declared {
        return Err(PdfObjectError::MalformedXref(
            "duplicate in-use object offsets (overlapping objects) — refusing to scan".into(),
        ));
    }
    let file_len = pdf_bytes.len();

    let mut spans = Vec::with_capacity(entries.len());
    for (&obj_id, &(offset, generation)) in &entries {
        let offset = offset as usize;
        // Upper-bound the scan at the next distinct object offset (EOF for the
        // last). `offsets` is sorted+distinct and contains `offset` (it was
        // built from these same entries and the duplicate-offset guard above
        // already returned on any collision), so the search always hits `Ok`.
        // Treat a miss as the invariant violation it is rather than silently
        // degrading to an unbounded `file_len` scan — that would reopen the very
        // DoS this guard closes.
        let scan_end = match offsets.binary_search(&offset) {
            Ok(i) => offsets.get(i + 1).copied().unwrap_or(file_len),
            Err(_) => unreachable!(
                "object offset {offset} absent from the distinct-offset set it was derived from"
            ),
        };
        let (start, end) = object_span(pdf_bytes, obj_id, offset, scan_end)?;
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
    // leaving objects MAX_OBJECTS+1.. uncommitted: unbindable and un-redactable
    // (apply_redaction can only zero-fill objects in the manifest), so their
    // plaintext would survive in the "redacted" artifact. Fail closed so the
    // caller learns the document can't be sealed. ADR-0030 §1.
    if objects.len() > MAX_OBJECTS {
        return Err(PdfObjectError::TooManyObjects {
            found: objects.len(),
            max: MAX_OBJECTS,
        });
    }

    // ADR-0030 §1: fold the real leaves at variable depth. N<2 surfaces as a
    // fold error so the ingest caller routes to the (non-redactable) chunk
    // fallback, exactly as the text segmenter does for a single-line file.
    let leaves: Vec<Fr> = objects.iter().map(|(_, f)| *f).collect();
    let root = variable_depth_fold_root(&leaves).map_err(PdfObjectError::from_segment)?;
    let (tree_depth, max_leaves) = variable_geometry(objects.len());

    Ok(PdfObjectManifest {
        objects: objects.into_iter().map(|(o, _)| o).collect(),
        original_root_hex: fr_to_hex(root),
        tree_depth,
        max_leaves,
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

// ── Segmenter adapter (ADR-0026 §2) ───────────────────────────────────────────
//
// The PDF object scheme is one `Segmenter` implementation. `extract_objects` /
// `apply_redaction` are unchanged; this only adapts their types to the
// format-agnostic `SegmentManifest` the generalised producer consumes.

use crate::zk::segment::{Segment, SegmentError, SegmentFormat, SegmentManifest, Segmenter};

impl From<PdfObjectError> for SegmentError {
    fn from(e: PdfObjectError) -> Self {
        match e {
            // A cross-reference-stream (PDF 1.5+) file is "not parseable as the
            // traditional-xref pdf-object format" — the ingest caller treats this
            // as the chunk fallback, exactly as before.
            PdfObjectError::NotTraditionalXref => SegmentError::Unsupported("pdf-object"),
            PdfObjectError::MalformedXref(detail) => SegmentError::Malformed {
                format: "pdf-object",
                detail,
            },
            PdfObjectError::ObjectOutOfBounds { obj_id, .. } => SegmentError::OutOfBounds(obj_id),
            PdfObjectError::UnknownObjectId { obj_id } => SegmentError::UnknownSegment(obj_id),
            PdfObjectError::TooManyObjects { found, max } => {
                SegmentError::TooManySegments { found, max }
            }
            PdfObjectError::LeafComputationFailed(s) => SegmentError::LeafComputationFailed(s),
            PdfObjectError::PoseidonError(s) => SegmentError::Poseidon(s),
        }
    }
}

impl From<PdfObjectManifest> for SegmentManifest {
    fn from(m: PdfObjectManifest) -> Self {
        let segments = m
            .objects
            .into_iter()
            .map(|o| Segment {
                segment_id: o.obj_id,
                label: None, // the obj-id is already the producer-facing label
                byte_offset: o.byte_offset,
                byte_length: o.byte_length,
                leaf_hex: o.leaf_hex,
            })
            .collect();
        SegmentManifest {
            format: SegmentFormat::PdfObject,
            segments,
            original_root_hex: m.original_root_hex,
            tree_depth: m.tree_depth,
            max_leaves: m.max_leaves,
        }
    }
}

impl PdfObjectManifest {
    /// Rebuild the PDF-specific manifest from a loaded [`SegmentManifest`] so the
    /// existing [`apply_redaction`] byte-span logic can be reused unchanged.
    /// `apply_redaction` only reads `obj_id` + `byte_offset` + `byte_length`, so
    /// the synthesised `generation` / `leaf_hex` are immaterial.
    fn from_segments(m: &SegmentManifest) -> Self {
        let objects = m
            .segments
            .iter()
            .map(|s| PdfObject {
                obj_id: s.segment_id,
                generation: 0,
                byte_offset: s.byte_offset,
                byte_length: s.byte_length,
                leaf_hex: s.leaf_hex.clone(),
            })
            .collect();
        PdfObjectManifest {
            objects,
            original_root_hex: m.original_root_hex.clone(),
            tree_depth: m.tree_depth,
            max_leaves: m.max_leaves,
        }
    }
}

/// The traditional-xref PDF [`Segmenter`].
pub struct PdfSegmenter;

impl Segmenter for PdfSegmenter {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::PdfObject
    }

    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError> {
        Ok(extract_objects(bytes, blind_secret)?.into())
    }

    fn apply_redaction(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<Vec<u8>, SegmentError> {
        let pdf_manifest = PdfObjectManifest::from_segments(manifest);
        Ok(apply_redaction(bytes, &pdf_manifest, redacted_ids)?)
    }
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
        // ADR-0030 §1 variable-depth geometry: N=3 → depth 2, max_leaves N=3.
        assert_eq!(m.tree_depth, 2);
        assert_eq!(m.max_leaves, 3);
        assert_eq!(m.original_root_hex.len(), 64);
        // Each object's bytes start at `N 0 obj` and end with `endobj`.
        for o in &m.objects {
            let seg = &pdf[o.byte_offset as usize..(o.byte_offset + o.byte_length) as usize];
            assert!(seg.ends_with(b"endobj"));
            assert!(super::find(seg, b"obj").is_some());
        }
    }

    /// A crafted xref table declaring many in-use entries that all point at the
    /// SAME byte offset — the redaction-bomb signature (audit redaction-dos-01).
    /// `n_entries` includes the free object 0.
    fn duplicate_offset_bomb(n_entries: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n"); // 9 bytes → object 1 would be at offset 9
        buf.extend_from_slice(b"1 0 obj\n<< >>\nendobj\n");
        let xref_off = buf.len();
        buf.extend_from_slice(format!("xref\n0 {n_entries}\n").as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n"); // free object 0
        for _ in 1..n_entries {
            buf.extend_from_slice(b"0000000009 00000 n \n"); // ALL point at offset 9
        }
        buf.extend_from_slice(b"trailer\n<< /Size 2 /Root 1 0 R >>\n");
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    #[test]
    fn redaction_dos_duplicate_offsets_rejected_fast() {
        // Audit redaction-dos-01: tens of thousands of entries at one offset must
        // be rejected by the distinct-offset guard BEFORE any per-object scan,
        // not drive an O(objects × filesize) `endobj` search.
        let bomb = duplicate_offset_bomb(50_000);
        let r = extract_object_spans(&bomb);
        assert!(
            matches!(
                r,
                Err(PdfObjectError::MalformedXref(_)) | Err(PdfObjectError::TooManyObjects { .. })
            ),
            "duplicate-offset bomb must be rejected, got {r:?}"
        );
    }

    #[test]
    fn object_span_is_bounded_to_next_offset() {
        // Sanity: a normal multi-object PDF still parses correctly with the
        // next-offset scan bound, and each object's bytes are framed obj..endobj.
        let pdf = sample_pdf();
        let mut spans = extract_object_spans(&pdf).unwrap();
        assert_eq!(spans.len(), 3);
        // `extract_object_spans` yields spans in object-id order (BTreeMap
        // iteration), which is not necessarily byte order. Sort by `byte_start`
        // first so this asserts the actual property — the spans tile the file
        // disjointly — regardless of how the objects are laid out.
        spans.sort_by_key(|s| s.byte_start);
        for w in spans.windows(2) {
            assert!(
                w[0].byte_end <= w[1].byte_start,
                "object spans must not overlap"
            );
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

    #[test]
    fn apply_redaction_destroys_secret_bytes() {
        // SECURITY regression gate: the redacted object's plaintext must be
        // ABSENT from the output, not merely zeroed within a parsed span.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 3 0 R >>",
            "<< /Type /Page /Note (TOP SECRET DATA) >>",
            "<< /Type /Pages /Kids [2 0 R] /Count 1 >>",
        ]);
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        assert!(
            super::find(&pdf, b"TOP SECRET DATA").is_some(),
            "secret present before redaction"
        );
        let redacted = apply_redaction(&pdf, &m, &[2]).unwrap();
        assert!(
            super::find(&redacted, b"TOP SECRET DATA").is_none(),
            "redacted plaintext must be absent from the artifact"
        );
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
    fn spans_locate_revealed_object_leaves() {
        use crate::zk::segment::{SegmentManifest, Segmenter};
        // ADR-0030 §2a/§3 `pdf-object`: in-place NUL-fill ⇒ the output span equals
        // the committed full `N G obj … endobj` span, and the verifier recomputes
        // the leaf over the whole (untrimmed) slice.
        let pdf = sample_pdf();
        let seg: SegmentManifest = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap().into();
        let content_hash = blake3::hash(&pdf);
        let (artifact, spans) = PdfSegmenter
            .apply_redaction_with_spans(&pdf, &seg, &[2])
            .unwrap();
        assert_eq!(artifact.len(), pdf.len(), "in-place: length preserved");
        assert_eq!(spans.len(), seg.segments.len());
        for (s, span) in seg.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, s.segment_id);
            assert_eq!(span.artifact_offset, s.byte_offset);
            assert_eq!(span.artifact_length, s.byte_length);
            if s.segment_id == 2 {
                continue; // redacted
            }
            let st = span.artifact_offset as usize;
            let en = st + span.artifact_length as usize;
            let id_be = s.segment_id.to_be_bytes();
            // pdf-object content_bytes = the full untrimmed object span.
            let content = content_scalar(&id_be, &artifact[st..en]);
            let blinding = derive_blinding(TEST_BLIND_SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, s.leaf_hex,
                "revealed object leaf recomputes from span"
            );
        }
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
    fn objects_fold_to_manifest_root() {
        // ADR-0030 §1: the manifest's real object leaves fold (variable-depth) to
        // its committed root — the V3 producer's F-RD-2 cross-check.
        let pdf = sample_pdf();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);
    }

    /// The (objects → leaves → root) pipeline uses the shared
    /// `olympus_crypto::redaction` hiding-leaf primitive and folds (ADR-0030 §1
    /// variable-depth) to the manifest root.
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

        // The real leaves fold (variable-depth) to the manifest's committed root.
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);
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
    fn single_object_pdf_routes_to_fallback() {
        // ADR-0030 §1: a PDF with a single in-use object (N=1) has no reveal/hide
        // partition, so `extract_objects` fails (the ingest caller then routes it
        // to the non-redactable chunk fallback). The over-cap rejection is unit-
        // tested cheaply in `segment::variable_depth_fold_rejects_over_cap`.
        let pdf = build_pdf(&["<< /Type /Catalog >>"]);
        assert!(
            extract_objects(&pdf, TEST_BLIND_SECRET).is_err(),
            "a single-object PDF is not object-redactable"
        );
    }
}
