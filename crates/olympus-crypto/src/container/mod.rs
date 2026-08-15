// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical container writers shared by the redaction producer and the
//! conformance-vector generator (audit V6 `I-01`, second route).
//!
//! # Why this module exists
//!
//! The redaction bundle commits to *segments of a container file*, so the exact
//! bytes a producer emits are part of the protocol: an offline verifier slices
//! the artifact at the signed offsets and reconstructs leaves from what it finds
//! there. Until this module, every writer of those containers was a separate
//! implementation:
//!
//! - `src-tauri`'s `zk::pdf_objects::rebuild_redacted` (traditional-xref PDFs),
//! - `src-tauri`'s `zk::segment::pdf_xref::rebuild_traditional_with_spans`
//!   (modern PDFs rebuilt down to a traditional xref), and
//! - `olympus-crypto`'s own `examples/gen_redaction_vectors.rs`, which built the
//!   conformance vectors both offline verifiers are tested against.
//!
//! The three agreed only because their constants had been *updated to match*
//! each other by hand. Audit V6 `I-01` recorded that as the root cause of
//! `A1-01` (the offline verifiers rejecting every genuine producer bundle while
//! the whole suite stayed green) and asked for the writers to be relocated here
//! so the producer and the generator share one implementation. Vectors emitted
//! through this module are *derived* from production code rather than
//! hand-matched to it.
//!
//! # What is shared, and what deliberately is not
//!
//! Only the **container skeleton** lives here — the parts every writer agreed on
//! byte for byte. Object *bodies* stay with the callers, because they legitimately
//! differ: `pdf_objects` copies each revealed object's committed span verbatim to
//! preserve its exact original bytes, while `pdf_xref` re-frames objects it parsed
//! out of cross-reference and object streams. Forcing those through one body
//! policy would change artifact bytes for no protocol reason. So the writers here
//! take **already-emitted object bytes** and own only the framing around them.

#[cfg(feature = "container")]
pub mod ooxml;
#[cfg(feature = "container")]
pub mod pdf;
