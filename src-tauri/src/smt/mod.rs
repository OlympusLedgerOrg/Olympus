//! Persistent, scalable Sparse Merkle Tree for the ledger.
//!
//! Wraps the pure in-memory tree in `olympus-crypto::smt` with PostgreSQL-
//! backed, path-addressed storage (`smt_nodes` / `smt_leaves`, migration
//! 0032), a write-behind hot cache for the upper levels, shard-parallel batch
//! inserts, and batched proof generation. Roots and proofs are byte-for-byte
//! identical to the in-memory tree, so the offline verifiers are unchanged.

pub mod backend;
pub mod tree;

pub use backend::{LeafRecord, MemBackend, NodeBackend, NodePath, PgBackend};
pub use tree::{LeafUpdate, PersistentSmt};
