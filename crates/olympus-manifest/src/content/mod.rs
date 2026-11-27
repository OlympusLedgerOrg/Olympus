// SPDX-License-Identifier: Apache-2.0

//! Content-addressed dataset commitments (RFC-0000 draft,
//! `docs/rfcs/0000-content-addressed-dataset-commitments.md`).
//!
//! Unlike ADR-0027 manifests, which key records by a committer-chosen
//! `record_id`, this format keys every item by a hash of its canonical
//! content, so anyone holding a work can compute its key and ask whether a
//! committed dataset version contains it.
//!
//! **Status: P1 exact layer + P2 text near-duplicates, draft format.** P1:
//! canonicalization profiles, item commitments with blinded provenance
//! metadata, the partitioned hoisted tree, the global root, and the M1 / M1-open
//! / N1 / MD1 statements as plain proofs. P2 (`docs/rfcs/dataset-similarity.md`):
//! the `text/minhash-120` v1 fingerprint profile, per-item fingerprint sets,
//! the LSH similarity index, and plain M2. Not yet here: extraction profiles
//! and `uri-sanitize/1`, the signed header, sidecar persistence, the CLI,
//! cross-language vectors (which RFC §0a requires before a profile may appear
//! in a header), image fingerprints, and N2 (out of v1). The context strings
//! and byte layouts follow the RFC draft and may still change before it is
//! accepted; nothing here touches a ledger hash.
//!
//! What a result means is set by the RFC's guarantee classes: M1/N1 are class
//! A (cryptographic commitment), M2 is class B (candidate retrieval against a
//! fingerprint the committer computed), and MD1 is class C (the committer's
//! recorded statement — evidence, not proof that the statement is true).

pub mod canon;
pub mod commit;
pub mod dataset;
pub mod domains;
pub mod error;
pub mod fingerprint;
pub mod similarity;
pub mod tree;
pub mod version;
pub mod wire;

pub use canon::CanonProfile;
pub use commit::{MetaEntry, OptOutStatus};
pub use dataset::{
    verify_m1_open, verify_m2, verify_md1, verify_n1, AddOutcome, BuiltVersion, DatasetBuilder,
    M2Match, M2Proof, MetaDisclosure, OpenedItem,
};
pub use error::ContentError;
pub use fingerprint::FpProfile;
