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
//! Redaction is a **width-hiding rebuild** (ADR-0034): the file is re-emitted
//! with every revealed object copied **byte-for-byte verbatim** (its full
//! `N G obj … endobj` span) at new offsets, each redacted object replaced by the
//! fixed `N G obj\nnull\nendobj` structural null, and a fresh xref/trailer/
//! `startxref` repairing the shifted offsets. Verbatim revealed bytes are what
//! make non-redacted leaves survive unchanged (the `pdf-object` leaf commits the
//! whole span); the `null` token's size depends only on the public object number,
//! so the artifact never discloses a redacted object's original byte length —
//! closing the size oracle of the superseded in-place fill. (Re-serialising
//! revealed objects, as the modern xref-stream path does for its *trimmed* body,
//! would change their bytes and break the binding — hence verbatim.)
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
    #[error("object {obj_id} is a structural skeleton object ({kind}); redacting it to `null` would corrupt the document")]
    StructuralObject { obj_id: u32, kind: &'static str },
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

/// Best-effort `/Root` indirect reference (`b"N G R"`) for the rebuilt trailer,
/// read from the **last** `/Root` in the original file (the most recent
/// incremental trailer wins). `None` if absent / unparsable — the rebuild then
/// omits `/Root` (a degenerate redacted artifact, but the commitment still binds).
fn find_root_ref(pdf_bytes: &[u8]) -> Option<Vec<u8>> {
    let pos = rfind(pdf_bytes, b"/Root")?;
    let mut c = Cursor::new(pdf_bytes, pos + b"/Root".len());
    c.skip_ws();
    let obj = c.read_u64()?;
    c.skip_ws();
    let generation = c.read_u64()?;
    c.skip_ws();
    if !c.at_keyword(b"R") {
        return None;
    }
    Some(format!("{obj} {generation} R").into_bytes())
}

/// One emitted object's span in the rebuilt artifact: `(obj_id, artifact_offset,
/// artifact_length)`. The length equals the object's committed `byte_length` for a
/// revealed object (verbatim), or the `null`-token length for a redacted one.
type ObjectSpanTriple = (u32, u64, u64);

/// Re-emit the PDF as a normalised traditional-xref file, **hiding redacted object
/// sizes** (ADR-0034 format-specific sanitization).
///
/// REVEALED objects are emitted **byte-for-byte verbatim** — their original full
/// `N G obj … endobj` span — at new offsets. The `pdf-object` leaf commits the
/// **whole** span (the verifier hashes the untrimmed slice), so verbatim emission
/// is what keeps every revealed leaf recomputable; re-serialising them (as the
/// modern xref-stream path does for its *trimmed* logical body) would change their
/// bytes and break the binding. REDACTED objects become a fixed
/// `N G obj\nnull\nendobj` — the PDF structural null — whose size depends only on
/// the (public) object number, never on the hidden content, so the artifact never
/// discloses the redacted object's original byte length. A fresh `xref` table +
/// trailer (`/Root` carried over from the original) + `startxref` repairs the byte
/// offsets the relocation shifts.
///
/// Returns the artifact plus each object's `(obj_id, artifact_offset,
/// artifact_length)` span in it (revealed length == original `byte_length`).
///
/// # Errors
/// [`PdfObjectError::UnknownObjectId`] if any redacted id is not a committed
/// object; [`PdfObjectError::ObjectOutOfBounds`] if a revealed object's recorded
/// span no longer fits `pdf_bytes`.
fn rebuild_redacted(
    pdf_bytes: &[u8],
    manifest: &PdfObjectManifest,
    redacted_obj_ids: &[u32],
) -> Result<(Vec<u8>, Vec<ObjectSpanTriple>), PdfObjectError> {
    let redacted: std::collections::HashSet<u32> = redacted_obj_ids.iter().copied().collect();
    // Fail closed BEFORE producing any bytes: every redacted id must be a
    // committed object, and must NOT be a structural skeleton object
    // (Catalog/Pages/Page) — replacing it with `null` would corrupt the document.
    // Enforced HERE (not only in `PdfSegmenter`) so no entry point, including the
    // public `apply_redaction`, can bypass the invariant.
    for &id in &redacted {
        let obj = manifest
            .objects
            .iter()
            .find(|o| o.obj_id == id)
            .ok_or(PdfObjectError::UnknownObjectId { obj_id: id })?;
        let start = obj.byte_offset as usize;
        let end = start.saturating_add(obj.byte_length as usize);
        if let Some(body) = pdf_bytes.get(start..end) {
            if let Some(kind) = crate::zk::segment::pdf_structural_object_type(body) {
                return Err(PdfObjectError::StructuralObject { obj_id: id, kind });
            }
        }
    }

    let mut out: Vec<u8> = Vec::with_capacity(pdf_bytes.len());
    out.extend_from_slice(b"%PDF-1.7\n");

    // (obj_id, byte offset in `out`, generation) in ascending obj-id order.
    let mut offsets: Vec<(u32, u64, u16)> = Vec::with_capacity(manifest.objects.len());
    let mut spans: Vec<(u32, u64, u64)> = Vec::with_capacity(manifest.objects.len());
    for obj in &manifest.objects {
        let start = out.len() as u64;
        offsets.push((obj.obj_id, start, obj.generation));
        let length = if redacted.contains(&obj.obj_id) {
            // Fixed structural null — size depends only on the public obj/gen.
            let null_obj = format!("{} {} obj\nnull\nendobj", obj.obj_id, obj.generation);
            out.extend_from_slice(null_obj.as_bytes());
            null_obj.len() as u64
        } else {
            let s = obj.byte_offset as usize;
            let e = s
                .checked_add(obj.byte_length as usize)
                .filter(|&e| e <= pdf_bytes.len())
                .ok_or(PdfObjectError::ObjectOutOfBounds {
                    obj_id: obj.obj_id,
                    offset: obj.byte_offset,
                })?;
            out.extend_from_slice(&pdf_bytes[s..e]);
            obj.byte_length
        };
        // The committed span is exactly the emitted object; the `\n` separator is
        // outside it (objects are located by xref offset, so it is cosmetic).
        spans.push((obj.obj_id, start, length));
        out.push(b'\n');
    }

    // /Size = one past the largest object number (PDF §7.5.4).
    let size = offsets
        .iter()
        .map(|&(id, _, _)| id as u64)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1);

    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    // Object 0 is the free-list head; in-use objects follow as ascending
    // contiguous-run subsections (unlisted numbers are implicitly free).
    out.extend_from_slice(b"0 1\n0000000000 65535 f \n");
    let ids: Vec<u32> = offsets.iter().map(|&(id, _, _)| id).collect(); // ascending
    let mut i = 0;
    while i < ids.len() {
        let run_start = ids[i];
        let mut j = i;
        while j + 1 < ids.len() && ids[j + 1] == ids[j] + 1 {
            j += 1;
        }
        out.extend_from_slice(format!("{run_start} {}\n", j - i + 1).as_bytes());
        for &(_, off, generation) in &offsets[i..=j] {
            out.extend_from_slice(format!("{off:010} {generation:05} n \n").as_bytes());
        }
        i = j + 1;
    }

    out.extend_from_slice(b"trailer\n<< /Size ");
    out.extend_from_slice(size.to_string().as_bytes());
    if let Some(r) = find_root_ref(pdf_bytes) {
        out.extend_from_slice(b" /Root ");
        out.extend_from_slice(&r);
    }
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(xref_off.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");

    Ok((out, spans))
}

/// Produce a redacted PDF (artifact only — see [`rebuild_redacted`] for the
/// span-bearing core). Width-hiding rebuild: revealed objects verbatim, redacted
/// objects → the `null` structural token, fresh xref (ADR-0034).
pub fn apply_redaction(
    pdf_bytes: &[u8],
    manifest: &PdfObjectManifest,
    redacted_obj_ids: &[u32],
) -> Result<Vec<u8>, PdfObjectError> {
    Ok(rebuild_redacted(pdf_bytes, manifest, redacted_obj_ids)?.0)
}

// ── Segmenter adapter (ADR-0026 §2) ───────────────────────────────────────────
//
// The PDF object scheme is one `Segmenter` implementation. `extract_objects` /
// `apply_redaction` are unchanged; this only adapts their types to the
// format-agnostic `SegmentManifest` the generalised producer consumes.

use crate::zk::segment::{
    Segment, SegmentError, SegmentFormat, SegmentManifest, SegmentSpan, Segmenter,
};

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
            PdfObjectError::StructuralObject { obj_id, kind } => {
                SegmentError::StructuralObject { id: obj_id, kind }
            }
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

    /// The structural-object guard (no nulling Catalog/Pages/Page) is enforced
    /// inside [`rebuild_redacted`] and surfaces here as
    /// [`SegmentError::StructuralObject`] via the `From<PdfObjectError>` mapping —
    /// so the invariant holds on every entry point, not just this one.
    fn apply_redaction(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<Vec<u8>, SegmentError> {
        let pdf_manifest = PdfObjectManifest::from_segments(manifest);
        Ok(apply_redaction(bytes, &pdf_manifest, redacted_ids)?)
    }

    /// Traditional PDF is a **re-emit** format under ADR-0034 (the `null` token +
    /// fresh xref shift every offset), so it overrides the default in-place span
    /// impl and returns the produced offsets. The verifier slices
    /// `artifact[offset..offset+length]` and recomputes each revealed object's leaf
    /// over the whole (verbatim) span.
    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        let pdf_manifest = PdfObjectManifest::from_segments(manifest);
        let (artifact, spans) = rebuild_redacted(bytes, &pdf_manifest, redacted_ids)?;
        let spans = spans
            .into_iter()
            .map(
                |(segment_id, artifact_offset, artifact_length)| SegmentSpan {
                    segment_id,
                    artifact_offset,
                    artifact_length,
                },
            )
            .collect();
        Ok((artifact, spans))
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

    /// A PDF whose object 4 is a non-structural (redactable) Annot; objects 1-3
    /// are the Catalog/Pages/Page skeleton the structural guard protects.
    fn sample_pdf_with_content() -> Vec<u8> {
        build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /Type /Annot /Subtype /Widget /Contents (classified) >>",
        ])
    }

    #[test]
    fn apply_redaction_rebuilds_with_null_and_verbatim_revealed() {
        let pdf = sample_pdf_with_content();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        // Redact the non-structural Annot (obj 4); structural objects are rejected.
        let (artifact, spans) = rebuild_redacted(&pdf, &m, &[4]).unwrap();

        // Redacted object 4 → the fixed `null` structural token at its span.
        let (_, off4, len4) = *spans.iter().find(|(id, _, _)| *id == 4).unwrap();
        assert_eq!(
            &artifact[off4 as usize..(off4 + len4) as usize],
            b"4 0 obj\nnull\nendobj",
            "redacted object becomes the null token"
        );

        // Revealed objects 1-3 are byte-for-byte verbatim at their new spans, and
        // the span keeps the committed `byte_length` (so the leaf recomputes).
        for id in [1u32, 2, 3] {
            let o = m.objects.iter().find(|o| o.obj_id == id).unwrap();
            let (_, off, len) = *spans.iter().find(|(i, _, _)| *i == id).unwrap();
            assert_eq!(len, o.byte_length, "revealed span keeps committed length");
            let orig = &pdf[o.byte_offset as usize..(o.byte_offset + o.byte_length) as usize];
            assert_eq!(
                &artifact[off as usize..(off + len) as usize],
                orig,
                "object {id} emitted verbatim"
            );
        }

        // The rebuilt artifact is a valid traditional-xref PDF: it re-parses to the
        // same object set.
        let re = extract_objects(&artifact, TEST_BLIND_SECRET).unwrap();
        assert_eq!(re.objects.len(), m.objects.len(), "object count preserved");
        assert_eq!(
            re.objects.iter().map(|o| o.obj_id).collect::<Vec<_>>(),
            m.objects.iter().map(|o| o.obj_id).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn rebuild_rejects_structural_objects_on_every_entry_point() {
        // CodeRabbit #1311: the structural guard must be enforced in the rebuild
        // helper itself, so the PUBLIC `apply_redaction` (not just `PdfSegmenter`)
        // refuses to null a Catalog/Pages/Page. Object 1 is the Catalog.
        let pdf = sample_pdf_with_content();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        for id in [1u32, 2, 3] {
            assert!(
                matches!(
                    apply_redaction(&pdf, &m, &[id]),
                    Err(PdfObjectError::StructuralObject { obj_id, .. }) if obj_id == id
                ),
                "structural object {id} must be rejected by the public path",
            );
        }
        // The non-structural Annot (obj 4) is still allowed.
        assert!(apply_redaction(&pdf, &m, &[4]).is_ok());
    }

    #[test]
    fn redacted_object_length_independent_of_content() {
        // ADR-0034 size oracle: two PDFs differing only in the redacted object's
        // body size must yield the same redacted-object token (`N G obj null
        // endobj`) — the artifact never discloses the hidden object's byte length.
        let small = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Annot /Contents (x) >>",
        ]);
        let big = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            &format!("<< /Type /Annot /Contents ({}) >>", "x".repeat(4096)),
        ]);
        for pdf in [&small, &big] {
            let m = extract_objects(pdf, TEST_BLIND_SECRET).unwrap();
            let (artifact, spans) = rebuild_redacted(pdf, &m, &[3]).unwrap();
            let (_, off, len) = *spans.iter().find(|(id, _, _)| *id == 3).unwrap();
            assert_eq!(
                &artifact[off as usize..(off + len) as usize],
                b"3 0 obj\nnull\nendobj",
                "redacted token is fixed regardless of original object size"
            );
        }
    }

    #[test]
    fn apply_redaction_destroys_secret_bytes() {
        // SECURITY regression gate: the redacted object's plaintext must be
        // ABSENT from the output, not merely zeroed within a parsed span.
        // The secret lives in a non-structural Annot (obj 2) so the structural
        // guard permits redacting it.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 3 0 R >>",
            "<< /Type /Annot /Contents (TOP SECRET DATA) >>",
            "<< /Type /Pages /Kids [] /Count 0 >>",
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
        let pdf = sample_pdf_with_content();
        let m = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);
        // Re-emit (offsets shift), so slice revealed objects at their PRODUCED span.
        // Redact the non-structural Annot (obj 4).
        let (redacted, spans) = rebuild_redacted(&pdf, &m, &[4]).unwrap();

        let recompute = |id: u32, bytes: &[u8]| {
            let id_be = id.to_be_bytes();
            let content = content_scalar(&id_be, bytes);
            let blinding = derive_blinding(TEST_BLIND_SECRET, content_hash.as_bytes(), &id_be);
            fr_to_hex(redaction_leaf(&content, &blinding).unwrap())
        };

        // Revealed objects: bytes survive verbatim, so the leaf recomputes from the
        // produced span and matches the committed manifest leaf.
        for id in [1u32, 2, 3] {
            let o = m.objects.iter().find(|o| o.obj_id == id).unwrap();
            let (_, off, len) = *spans.iter().find(|(i, _, _)| *i == id).unwrap();
            assert_eq!(
                &redacted[off as usize..(off + len) as usize],
                &pdf[o.byte_offset as usize..(o.byte_offset + o.byte_length) as usize],
                "revealed object {id} bytes unchanged"
            );
            assert_eq!(
                recompute(id, &redacted[off as usize..(off + len) as usize]),
                o.leaf_hex,
                "object {id} leaf"
            );
        }

        // Redacted object: its content is destroyed (→ null token), so recomputing
        // from the redacted bytes no longer matches the committed leaf.
        let o4 = m.objects.iter().find(|o| o.obj_id == 4).unwrap();
        let (_, off4, len4) = *spans.iter().find(|(i, _, _)| *i == 4).unwrap();
        assert_ne!(
            recompute(4, &redacted[off4 as usize..(off4 + len4) as usize]),
            o4.leaf_hex,
            "redacted leaf differs"
        );
    }

    #[test]
    fn spans_locate_revealed_object_leaves() {
        use crate::zk::segment::{SegmentManifest, Segmenter};
        // ADR-0030 §2a/§3 `pdf-object` (ADR-0034 re-emit): the output spans are the
        // PRODUCED offsets of the rebuilt file, and the verifier recomputes each
        // revealed leaf over the whole (untrimmed, verbatim) object span.
        //
        // Build a PDF with a non-structural content leaf (obj 4 = Annot) so the
        // structural guard permits redaction. Objects 1-3 are skeleton (Catalog /
        // Pages / Page) and must NOT be in the redacted-ids set.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /Type /Annot /Subtype /Widget /Contents (classified) >>",
        ]);
        let seg: SegmentManifest = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap().into();
        let content_hash = blake3::hash(&pdf);
        let (artifact, spans) = PdfSegmenter
            .apply_redaction_with_spans(&pdf, &seg, &[4])
            .unwrap();
        assert_eq!(spans.len(), seg.segments.len());
        for (s, span) in seg.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, s.segment_id);
            let st = span.artifact_offset as usize;
            let en = st + span.artifact_length as usize;
            if s.segment_id == 4 {
                // Redacted → the fixed null token at its produced span.
                assert_eq!(&artifact[st..en], b"4 0 obj\nnull\nendobj");
                continue;
            }
            // Revealed span keeps its committed length and is byte-verbatim.
            assert_eq!(span.artifact_length, s.byte_length);
            let orig = &pdf[s.byte_offset as usize..(s.byte_offset + s.byte_length) as usize];
            assert_eq!(&artifact[st..en], orig, "revealed object emitted verbatim");
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
        // The whole redacted artifact re-parses as a valid traditional-xref PDF.
        let re = extract_objects(&artifact, TEST_BLIND_SECRET).unwrap();
        assert_eq!(re.objects.len(), seg.segments.len());
    }

    #[test]
    fn redacted_artifact_folds_to_original_root() {
        use crate::zk::segment::{variable_depth_fold_root, SegmentManifest, Segmenter};
        // The load-bearing binding (ADR-0030 §3): the rebuilt artifact's revealed
        // objects (at their produced spans) + the committed redacted leaf fold back
        // to the on-ledger `original_root`. Proves the offset shift + verbatim
        // emission keep the binding intact. Redact the non-structural Annot (obj 4).
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
            "<< /Type /Annot /Subtype /Widget /Contents (classified) >>",
        ]);
        let seg: SegmentManifest = extract_objects(&pdf, TEST_BLIND_SECRET).unwrap().into();
        let content_hash = blake3::hash(&pdf);
        let (artifact, spans) = PdfSegmenter
            .apply_redaction_with_spans(&pdf, &seg, &[4])
            .unwrap();

        let mut leaves = Vec::with_capacity(seg.segments.len());
        for s in &seg.segments {
            let id_be = s.segment_id.to_be_bytes();
            let blinding = derive_blinding(TEST_BLIND_SECRET, content_hash.as_bytes(), &id_be);
            let bytes: Vec<u8> = if s.segment_id == 4 {
                // Redacted: the committed leaf (bundle `leaf_hex`) recomputes from
                // the ORIGINAL object bytes — gone from the artifact by design.
                pdf[s.byte_offset as usize..(s.byte_offset + s.byte_length) as usize].to_vec()
            } else {
                let span = spans
                    .iter()
                    .find(|sp| sp.segment_id == s.segment_id)
                    .unwrap();
                let st = span.artifact_offset as usize;
                artifact[st..st + span.artifact_length as usize].to_vec()
            };
            let content = content_scalar(&id_be, &bytes);
            leaves.push(redaction_leaf(&content, &blinding).unwrap());
        }
        let root = variable_depth_fold_root(&leaves).unwrap();
        assert_eq!(
            fr_to_hex(root),
            seg.original_root_hex,
            "artifact + committed redacted leaf fold back to the on-ledger root"
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
    fn pdf_segmenter_rejects_structural_objects() {
        // Regression: NUL-filling a Catalog (1) / Pages (2) / Page (3) dictionary
        // corrupts the document (the page tree points at a NUL non-dictionary). The
        // `Segmenter` redaction entry point fails closed; content objects pass.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
            "<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (SECRET) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]);
        let m = PdfSegmenter.extract(&pdf, TEST_BLIND_SECRET).unwrap();
        for id in [1u32, 2, 3] {
            assert!(
                matches!(
                    PdfSegmenter.apply_redaction(&pdf, &m, &[id]),
                    Err(SegmentError::StructuralObject { .. })
                ),
                "structural object {id} must be guarded"
            );
        }
        // The content stream (4) and font (5) remain redactable.
        assert!(PdfSegmenter.apply_redaction(&pdf, &m, &[4]).is_ok());
        assert!(PdfSegmenter.apply_redaction(&pdf, &m, &[5]).is_ok());
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
