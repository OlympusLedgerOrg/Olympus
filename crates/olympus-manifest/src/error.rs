//! Error types for manifest construction and proof verification.

use thiserror::Error;

/// Errors raised while building, serializing, or proving against a dataset
/// manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// A `shard_id` or `record_id` was empty. The leaf domain (ADR-0027)
    /// requires non-empty identifiers.
    #[error("identifier must be non-empty: {0}")]
    EmptyIdentifier(&'static str),

    /// Two records in the same shard shared a `record_id`. Record identity must
    /// be unique within a shard so the sorted-leaf order (and therefore
    /// exclusion proofs) is well-defined.
    #[error("duplicate record_id {record_id:?} in shard {shard_id:?}")]
    DuplicateRecord {
        /// The shard the collision occurred in.
        shard_id: String,
        /// The colliding record identifier.
        record_id: String,
    },

    /// Two shards in the manifest shared a `shard_id`.
    #[error("duplicate shard_id {0:?}")]
    DuplicateShard(String),

    /// A `content_hash` was not exactly 32 bytes of hex.
    #[error("content_hash must be 32 bytes (64 hex chars); got {0}")]
    BadContentHash(String),

    /// A hex field failed to decode.
    #[error("invalid hex in {field}: {source}")]
    Hex {
        /// Which field failed to decode.
        field: &'static str,
        /// The underlying decode error.
        #[source]
        source: hex::FromHexError,
    },

    /// A referenced shard was not present in the manifest.
    #[error("shard {0:?} not found in manifest")]
    ShardNotFound(String),

    /// A referenced record was not present in the named shard.
    #[error("record {record_id:?} not found in shard {shard_id:?}")]
    RecordNotFound {
        /// The shard searched.
        shard_id: String,
        /// The record identifier searched for.
        record_id: String,
    },

    /// The record exists, so an exclusion proof cannot be produced for it.
    #[error("record {record_id:?} is present in shard {shard_id:?}; cannot prove exclusion")]
    RecordPresent {
        /// The shard searched.
        shard_id: String,
        /// The record identifier searched for.
        record_id: String,
    },

    /// (De)serialization failed.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Canonical JSON serialization failed (JCS / RFC 8785).
    #[error("canonical serialization error: {0}")]
    Canonical(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, ManifestError>;
