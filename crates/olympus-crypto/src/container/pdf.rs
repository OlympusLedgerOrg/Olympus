// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! The canonical traditional-cross-reference PDF skeleton (ADR-0034).
//!
//! See the [module docs](super) for why this is shared. This file owns the
//! bytes outside the objects: the `%PDF-1.7` header, the `\n` separators, the
//! `xref` table, the trailer, `startxref`, and `%%EOF`.

/// One object exactly as it should appear in the output, together with the
/// cross-reference metadata needed to point at it.
///
/// `bytes` is the complete `N G obj … endobj` span **without** the trailing
/// separator newline — the writer appends that. Callers own the framing because
/// they source bodies differently (verbatim committed spans vs. re-framed parsed
/// bodies); see the [module docs](super).
#[derive(Debug, Clone)]
pub struct EmittedObject {
    /// PDF object number. Callers MUST supply objects in ascending order.
    pub id: u32,
    /// PDF generation number, written into the xref entry.
    pub generation: u16,
    /// The exact `N G obj … endobj` bytes to emit.
    pub bytes: Vec<u8>,
}

/// A written object's location in the output: `(id, artifact_offset, artifact_length)`.
///
/// The span covers the full `N G obj … endobj` framing and **excludes** the
/// separator newline, matching the `pdf-object` / `pdf-xref-stream` contract in
/// ADR-0030 §3: a verifier slices this span and locates
/// `inner = slice[find("obj")+3 .. rfind("endobj")]` to reconstruct the leaf.
pub type ObjectSpan = (u32, u64, u64);

/// Write a traditional-xref PDF around `objects`.
///
/// `root_ref` is the raw `/Root` indirect reference (e.g. `b"1 0 R"`); when
/// `None` the trailer omits `/Root` entirely. Returns the artifact and one
/// [`ObjectSpan`] per object, in the order supplied.
///
/// Objects MUST be supplied in ascending `id` order — the xref table is written
/// as ascending contiguous-run subsections and does not sort on the caller's
/// behalf. Debug builds assert this; in release an unsorted call would emit an
/// xref whose subsection headers disagree with the entries that follow.
#[must_use]
pub fn write_traditional_xref(
    objects: &[EmittedObject],
    root_ref: Option<&[u8]>,
) -> (Vec<u8>, Vec<ObjectSpan>) {
    debug_assert!(
        objects.windows(2).all(|w| w[0].id < w[1].id),
        "objects must be supplied in strictly ascending id order"
    );

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.7\n");

    let mut spans: Vec<ObjectSpan> = Vec::with_capacity(objects.len());
    // (offset in `out`, generation), parallel to `objects`.
    let mut offsets: Vec<(u64, u16)> = Vec::with_capacity(objects.len());
    for obj in objects {
        let start = out.len() as u64;
        offsets.push((start, obj.generation));
        out.extend_from_slice(&obj.bytes);
        spans.push((obj.id, start, obj.bytes.len() as u64));
        // The separator sits outside the committed span: objects are located by
        // xref offset, so it is cosmetic.
        out.push(b'\n');
    }

    // /Size is one past the largest object number (PDF §7.5.4).
    let size = objects
        .iter()
        .map(|o| o.id as u64)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1);

    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    // Object 0 is always the free-list head, emitted as its own subsection. The
    // in-use objects follow as ascending contiguous-run subsections; gaps are
    // implicitly free (our parser and standard readers treat unlisted numbers
    // as free).
    out.extend_from_slice(b"0 1\n0000000000 65535 f \n");
    let mut i = 0usize;
    while i < objects.len() {
        let mut j = i;
        while j + 1 < objects.len() && objects[j + 1].id == objects[j].id + 1 {
            j += 1;
        }
        out.extend_from_slice(format!("{} {}\n", objects[i].id, j - i + 1).as_bytes());
        for &(off, generation) in &offsets[i..=j] {
            out.extend_from_slice(format!("{off:010} {generation:05} n \n").as_bytes());
        }
        i = j + 1;
    }

    out.extend_from_slice(b"trailer\n<< /Size ");
    out.extend_from_slice(size.to_string().as_bytes());
    if let Some(r) = root_ref {
        out.extend_from_slice(b" /Root ");
        out.extend_from_slice(r);
    }
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(xref_off.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");

    (out, spans)
}

/// Frame a body as a PDF indirect object: `N G obj\n<body>\nendobj`.
///
/// Convenience for callers that hold a bare body rather than a committed span.
#[must_use]
pub fn frame_object(id: u32, generation: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{id} {generation} obj\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(b"\nendobj");
    bytes
}

/// The structural-null body a redacted object is rebuilt as (ADR-0034 §2).
pub const NULL_BODY: &[u8] = b"null";

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(id: u32, generation: u16, body: &[u8]) -> EmittedObject {
        EmittedObject {
            id,
            generation,
            bytes: frame_object(id, generation, body),
        }
    }

    /// The span a writer reports must be the span a verifier can slice: cutting
    /// the artifact at `(offset, length)` has to land exactly on the object's
    /// `N G obj … endobj` framing, separator excluded.
    #[test]
    fn reported_spans_slice_back_to_the_emitted_objects() {
        let objects = vec![obj(1, 0, b"<< /Type /Catalog >>"), obj(2, 0, b"(hello)")];
        let (artifact, spans) = write_traditional_xref(&objects, Some(b"1 0 R"));

        assert_eq!(spans.len(), 2);
        for (span, source) in spans.iter().zip(&objects) {
            let (id, offset, length) = *span;
            assert_eq!(id, source.id);
            let slice = &artifact[offset as usize..(offset + length) as usize];
            assert_eq!(slice, source.bytes.as_slice());
            assert!(slice.starts_with(format!("{id} 0 obj").as_bytes()));
            assert!(slice.ends_with(b"endobj"));
            // The separator is outside the span.
            assert_eq!(artifact[(offset + length) as usize], b'\n');
        }
    }

    /// The xref offsets must actually point at their objects — the property that
    /// makes the artifact openable at all.
    #[test]
    fn xref_offsets_point_at_their_objects() {
        let objects = vec![obj(1, 0, b"<< /Type /Catalog >>"), obj(4, 3, b"(gap)")];
        let (artifact, _) = write_traditional_xref(&objects, Some(b"1 0 R"));

        let text = String::from_utf8_lossy(&artifact).into_owned();
        let xref_at = text.find("xref\n").expect("xref table");
        let table = &text[xref_at..];
        // Non-contiguous ids ⇒ two subsections after the free-list head.
        assert!(table.contains("\n1 1\n"), "subsection for id 1: {table}");
        assert!(table.contains("\n4 1\n"), "subsection for id 4: {table}");

        for obj in &objects {
            let needle = format!("{} {} obj", obj.id, obj.generation);
            let want = artifact
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
                .expect("object present");
            let entry = format!("{want:010} {:05} n ", obj.generation);
            assert!(
                text.contains(&entry),
                "xref entry {entry:?} for object {} missing from:\n{table}",
                obj.id
            );
        }
    }

    /// `/Size` is one past the largest object number even when ids are sparse —
    /// it is not the object count.
    #[test]
    fn size_is_one_past_the_largest_id_not_the_count() {
        let objects = vec![obj(1, 0, b"<< /Type /Catalog >>"), obj(9, 0, b"(sparse)")];
        let (artifact, _) = write_traditional_xref(&objects, Some(b"1 0 R"));
        let text = String::from_utf8_lossy(&artifact).into_owned();
        assert!(text.contains("/Size 10"), "expected /Size 10 in:\n{text}");
    }

    /// `startxref` must resolve to the `xref` keyword, or no reader can find the
    /// table.
    #[test]
    fn startxref_points_at_the_xref_keyword() {
        let objects = vec![obj(1, 0, b"<< /Type /Catalog >>")];
        let (artifact, _) = write_traditional_xref(&objects, None);
        let text = String::from_utf8_lossy(&artifact).into_owned();
        let declared: usize = text
            .rsplit("startxref\n")
            .next()
            .and_then(|tail| tail.split('\n').next())
            .and_then(|n| n.trim().parse().ok())
            .expect("startxref offset");
        assert_eq!(&artifact[declared..declared + 5], b"xref\n");
    }

    /// `None` omits `/Root` rather than emitting an empty or dangling reference.
    #[test]
    fn absent_root_ref_omits_the_key() {
        let objects = vec![obj(1, 0, b"(no catalog)")];
        let (artifact, _) = write_traditional_xref(&objects, None);
        let text = String::from_utf8_lossy(&artifact).into_owned();
        assert!(!text.contains("/Root"), "unexpected /Root in:\n{text}");
        assert!(text.contains("<< /Size 2 >>"), "trailer shape: {text}");
    }

    /// Non-zero generations reach the xref entry, five-digit padded.
    #[test]
    fn generations_are_written_into_xref_entries() {
        let objects = vec![obj(1, 0, b"<< /Type /Catalog >>"), obj(2, 7, b"(gen 7)")];
        let (artifact, _) = write_traditional_xref(&objects, Some(b"1 0 R"));
        let text = String::from_utf8_lossy(&artifact).into_owned();
        assert!(text.contains(" 00007 n "), "generation 7 entry: {text}");
    }
}
