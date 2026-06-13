//! `POST /ingest/files` — the only sanctioned commit ingress (server hashes
//! the uploaded bytes). Owns the atomic ingest transaction: per-shard advisory
//! lock, row upsert, Poseidon snapshot build/sign, and the soft parser-bound
//! SMT commit. Split out of the ingest module.
//!
//! Pure code-motion split along the pipeline seams:
//! - [`route`]      — multipart parsing/validation, the unconditional
//!   `api::shards::authorize_write` gate, and the atomic ingest transaction
//! - [`snapshot`]   — per-shard advisory lock + in-transaction Poseidon
//!   snapshot build/sign/persist
//! - [`parser_smt`] — soft parser-bound BLAKE3 SMT commit (ADR-0003/0004)

mod parser_smt;
mod route;
mod snapshot;

pub(super) use route::ingest_file;
