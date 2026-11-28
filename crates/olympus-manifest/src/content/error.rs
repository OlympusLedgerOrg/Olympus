// SPDX-License-Identifier: Apache-2.0

//! Errors for content-addressed dataset commitments.
//!
//! Every rejection has its own variant so that tests (and the shared negative
//! vectors, RFC §13) can assert *why* something was rejected, not merely that
//! it was.

use thiserror::Error;

/// A rejection or construction failure.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ContentError {
    /// Invalid or noncanonical compact proof bytes.
    #[error("invalid compact dataset proof: {0}")]
    InvalidProofEncoding(&'static str),

    /// The input is not valid UTF-8 under a text profile (§1).
    #[error("canonicalization rejected input: invalid UTF-8")]
    InvalidUtf8,

    /// A profile index does not name an entry in the version's table.
    #[error("profile index {0} is out of range")]
    UnknownProfile(u16),

    /// Partition exponent outside `0..=16` (§5).
    #[error("partition exponent p = {0} is outside 0..=16")]
    BadPartitionExponent(u8),

    /// Proof depth exceeds `256 − p` (§4 depth rule).
    #[error("proof depth {depth} exceeds the maximum {max}")]
    DepthOutOfRange {
        /// Depth claimed by the proof.
        depth: usize,
        /// `256 − p`.
        max: usize,
    },

    /// Wrong number of top-tree siblings for `p`.
    #[error("expected {expected} top-tree siblings, got {got}")]
    TopPathLength {
        /// Must equal `p`.
        expected: usize,
        /// Supplied count.
        got: usize,
    },

    /// A terminal leaf's key does not share the path prefix (§4 prefix check).
    #[error("terminal leaf key does not match the path prefix")]
    PrefixMismatch,

    /// A terminal leaf or empty subtree whose deepest sibling is empty: the
    /// subtree should have been hoisted or collapsed (§4 canonical shape).
    #[error("non-canonical proof shape: terminal beside an empty sibling")]
    NonCanonicalShape,

    /// The path does not fold to the expected root.
    #[error("path does not fold to the expected root")]
    RootMismatch,

    /// Membership was asked for but the path ends at another key or empty.
    #[error("key is not a member: path ends at {0}")]
    NotAMember(&'static str),

    /// Non-membership was asked for but the path ends at the queried key.
    #[error("key is a member; non-membership proof refused")]
    IsAMember,

    /// An opened item-commitment preimage does not hash to the committed value.
    #[error("item commitment preimage does not match the committed value")]
    CommitmentMismatch,

    /// The content key does not match the opened profile and digest.
    #[error("content key does not match the opened profile and content digest")]
    ContentKeyMismatch,

    /// Two items with the same content key were added as distinct leaves.
    #[error("duplicate content key in one tree")]
    DuplicateKey,

    /// Some, but not all, occurrences of an item carry metadata (§2).
    #[error("partial metadata set: {with} of {total} occurrences carry metadata")]
    PartialMetadata {
        /// Occurrences with metadata.
        with: u64,
        /// `occurrence_count`.
        total: u64,
    },

    /// Two metadata entries in one dataset version share a blinder (§2
    /// lifecycle rule 2).
    #[error("duplicate metadata blinder")]
    DuplicateBlinder,

    /// A metadata set's size differs from `occurrence_count` (audit check).
    #[error("metadata set has {got} entries, occurrence_count is {expected}")]
    MetaSetSize {
        /// `occurrence_count`.
        expected: u64,
        /// Entries supplied.
        got: u64,
    },

    /// MD1 `n` differs from the opened `occurrence_count`.
    #[error("MD1 set size n = {n} does not equal occurrence_count = {occurrence_count}")]
    MetaCountMismatch {
        /// `n` claimed by the disclosure.
        n: u64,
        /// From the opened item commitment.
        occurrence_count: u64,
    },

    /// MD1 position `j ≥ n`.
    #[error("metadata position {j} out of range for n = {n}")]
    MetaPositionOutOfRange {
        /// Position.
        j: u64,
        /// Set size.
        n: u64,
    },

    /// Wrong number of metadata siblings for the `(j, n)` shape.
    #[error("metadata path has {got} siblings, shape ({j}, {n}) needs {expected}")]
    MetaPathLength {
        /// Position.
        j: u64,
        /// Set size.
        n: u64,
        /// Siblings required by the shape.
        expected: usize,
        /// Siblings supplied.
        got: usize,
    },

    /// The metadata path does not fold to the opened `meta_root`.
    #[error("metadata path does not fold to meta_root")]
    MetaRootMismatch,

    /// `opt_out_status` outside {0, 1, 2}.
    #[error("invalid opt_out_status {0}")]
    InvalidOptOutStatus(u8),

    /// A metadata string is not in Unicode NFC.
    #[error("metadata field {0} is not NFC")]
    NotNfc(&'static str),

    /// A required string field was empty.
    #[error("field {0} must be non-empty")]
    EmptyField(&'static str),

    /// A framed field is too long for its length prefix.
    #[error("field {0} exceeds the u32 length prefix")]
    FieldTooLong(&'static str),

    /// An opened metadata set is not in strictly ascending blinder order.
    #[error("metadata entries are not in strictly ascending blinder order")]
    MetaOrder,

    /// An extraction entry names a parameter twice.
    #[error("duplicate extraction parameter {0:?}")]
    DuplicateParam(String),

    /// A table has more than `u16::MAX` entries.
    #[error("table {0} has more than 65535 entries")]
    TableTooLarge(&'static str),

    /// The operating-system CSPRNG failed; no blinder was produced.
    #[error("entropy source failed: {0}")]
    Entropy(String),

    /// The canonicalization table names one `(profile_id, profile_version)`
    /// twice, which would make the committed profile index depend on add order.
    #[error("canonicalization profile {0:?} appears twice in the table")]
    DuplicateProfile(String),

    /// A metadata entry's `extraction_index` names no row of the version's
    /// extraction table.
    #[error("extraction index {0} is out of range")]
    UnknownExtraction(u16),

    /// An item opening claims `occurrence_count = 0`; every committed item has
    /// at least one occurrence (§2).
    #[error("item opening has occurrence_count = 0")]
    ZeroOccurrences,

    /// A fingerprint-profile table row names a profile this implementation
    /// does not implement; it is never matched under a guessed rule.
    #[error("fingerprint profile {0:?} is not implemented")]
    UnknownFpProfile(String),

    /// A fingerprint-profile row carries band, row or threshold parameters
    /// its profile definition does not allow.
    #[error("fingerprint profile parameters invalid: {0}")]
    InvalidFpParams(&'static str),

    /// The fingerprint table names one `(fp_profile_id, fp_profile_version)`
    /// twice.
    #[error("fingerprint profile {0:?} appears twice in the table")]
    DuplicateFpProfile(String),

    /// A fingerprint-profile index names no row of the version's table.
    #[error("fingerprint profile index {0} is out of range")]
    UnknownFpIndex(u16),

    /// A fingerprint is not the width its profile defines.
    #[error("fingerprint is {got} bytes, its profile defines {expected}")]
    FingerprintWidth {
        /// Profile width.
        expected: usize,
        /// Supplied length.
        got: usize,
    },

    /// M2 fingerprint position `leaf_index ≥ leaf_count`.
    #[error("fingerprint position {j} out of range for leaf_count = {n}")]
    FpPositionOutOfRange {
        /// `leaf_index`.
        j: u32,
        /// `leaf_count`.
        n: u32,
    },

    /// Wrong number of fingerprint siblings for the `(leaf_index, leaf_count)`
    /// shape.
    #[error("fingerprint path has {got} siblings, its shape needs {expected}")]
    FpPathLength {
        /// Siblings required by the shape.
        expected: usize,
        /// Siblings supplied.
        got: usize,
    },

    /// The fingerprint path does not fold to the opened `fp_set_root`.
    #[error("fingerprint path does not fold to fp_set_root")]
    FpRootMismatch,

    /// The candidate fingerprint does not pass the signed profile threshold
    /// against the query fingerprint.
    #[error("candidate matches {matching} slots, the signed threshold is {threshold}")]
    BelowThreshold {
        /// Matching MinHash slots.
        matching: u32,
        /// Threshold from the authenticated fingerprint-profile row.
        threshold: u32,
    },

    /// Bucket entries are not strictly ordered by `(content_key,
    /// fp_profile_index, segment_index)`, or two different fingerprints claim
    /// one position.
    #[error("bucket entries are not strictly ordered or repeat a position")]
    BucketOrder,

    /// The candidate's fingerprint profile does not apply to its
    /// canonicalization profile (a text fingerprint on a non-text item).
    #[error("fingerprint profile {fp:?} does not apply to canonicalization profile {canon:?}")]
    FpProfileNotApplicable {
        /// `fp_profile_id`.
        fp: String,
        /// `profile_id`.
        canon: String,
    },

    /// A similarity bucket holds more entries than its `u32` count can frame.
    #[error("similarity bucket exceeds u32 entries")]
    BucketTooLarge,
}

/// Result alias.
pub type Result<T> = std::result::Result<T, ContentError>;
