//! Persistent, scalable Sparse Merkle Tree for the ledger.
//!
//! Wraps the pure in-memory tree in `olympus-crypto::smt` with transactionally
//! atomic PostgreSQL or SQLite path-addressed storage, a write-behind hot cache
//! for the upper levels, shard-parallel batch inserts, and batched proof
//! generation. Roots and proofs are byte-for-byte identical to the in-memory
//! tree, so the offline verifiers are unchanged.

pub mod backend;
pub mod tree;

pub use backend::{
    LeafRecord, MemBackend, NodeBackend, NodePath, NodeRead, NodeReadTransaction,
    NodeWriteTransaction, PgBackend, SmtStorageBackend, SqliteBackend,
};
pub use tree::{LeafUpdate, PersistentSmt, WriteOnceViolation};
