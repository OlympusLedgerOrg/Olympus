// SPDX-License-Identifier: Apache-2.0

//! Content-addressed dataset commitments (RFC-0000 draft,
//! `docs/rfcs/0000-content-addressed-dataset-commitments.md`).
//!
//! Unlike ADR-0027 manifests, which key records by a committer-chosen
//! `record_id`, this format keys every item by a hash of its canonical
//! content, so anyone holding a work can compute its key and ask whether a
//! committed dataset version contains it.
//!
//! **Status: P1 core, draft format.** This module implements the exact layer:
//! canonicalization profiles, item commitments with blinded provenance
//! metadata, the partitioned hoisted tree, the global root, and the M1 / M1-open
//! / N1 / MD1 statements as plain proofs. Not yet here: extraction profiles
//! and `uri-sanitize/1`, the signed header, sidecar persistence, the CLI,
//! cross-language vectors, and anything from the near-duplicate layer. The
//! context strings and byte layouts follow the RFC draft and may still change
//! before it is accepted; nothing here touches a ledger hash.
//!
//! What a result means is set by the RFC's guarantee classes: M1/N1 are class
//! A (cryptographic commitment), MD1 is class C (the committer's recorded
//! statement — evidence, not proof that the statement is true).

pub mod canon;
pub mod commit;
pub mod dataset;
pub mod domains;
pub mod error;
pub mod tree;
pub mod version;
pub mod wire;

pub use canon::CanonProfile;
pub use commit::{MetaEntry, OptOutStatus};
pub use dataset::{
    verify_m1_open, verify_md1, verify_n1, AddOutcome, BuiltVersion, DatasetBuilder,
    MetaDisclosure, OpenedItem,
};
pub use error::ContentError;
