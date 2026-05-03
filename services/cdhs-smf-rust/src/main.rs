//! CD-HS-ST Service
//!
//! Constant-Depth Hierarchical Sparse Tree service.
//!
//! This is a standalone Rust binary that maintains a single global 256-level
//! Sparse Merkle Tree with composite keys encoding both shard identity and
//! record identity.
//!
//! Architecture:
//! - Single global SMT (not per-shard trees)
//! - Composite keys: H(GLOBAL_KEY_PREFIX || shard_id || record_key)
//! - BLAKE3 hashing with domain separation
//! - Ed25519 signing for root commitments
//! - Protobuf API over Unix domain socket

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use cdhs_smf_service::canonicalization;
use cdhs_smf_service::crypto;
use cdhs_smf_service::prepared::{
    PreparedTxStore, DEFAULT_PREPARED_CAPACITY, DEFAULT_PREPARED_TTL,
};
use cdhs_smf_service::smt;

pub use cdhs_smf_service::proto::olympus::cdhs_smf::v1::cdhs_smf_service_server::{
    CdhsSmfService as CdhsSmfServiceTrait, CdhsSmfServiceServer,
};
pub use cdhs_smf_service::proto::olympus::cdhs_smf::v1::*;

use crypto::KeyManager;
use smt::SparseMerkleTree;

/// The main service implementation
pub struct CdhsSmfService {
    /// The global sparse Merkle tree
    smt: SparseMerkleTree,
    /// Key manager for Ed25519 signing (Arc-shared with the SIGHUP handler)
    key_manager: Arc<KeyManager>,
    /// Bounded LRU of prepared two-phase-commit transactions (H-2). See
    /// `prepared` module docs for the lifecycle and Sacred-Law constraints.
    prepared: Arc<PreparedTxStore>,
}

impl CdhsSmfService {
    pub fn new() -> Self {
        Self::with_prepared_config(DEFAULT_PREPARED_CAPACITY, DEFAULT_PREPARED_TTL)
    }

    /// Construct a service with explicit prepared-transaction LRU
    /// capacity / TTL. Used by tests and by env-var-based overrides at
    /// startup.
    pub fn with_prepared_config(capacity: usize, ttl: Duration) -> Self {
        Self {
            smt: SparseMerkleTree::new(),
            key_manager: Arc::new(KeyManager::new()),
            prepared: Arc::new(PreparedTxStore::new(capacity, ttl)),
        }
    }

    /// Return a clone of the `Arc<KeyManager>` so that background tasks
    /// (e.g. the SIGHUP handler) can trigger key rotation.
    pub fn key_manager_handle(&self) -> Arc<KeyManager> {
        Arc::clone(&self.key_manager)
    }
}

const DEFAULT_SOCKET_PATH: &str = "/run/olympus/cdhs-smf.sock";

/// Maximum gRPC message size accepted from the Go sequencer.
///
/// This MUST stay >= the HTTP body cap on the sequencer side
/// (see `services/sequencer-go/internal/api/sequencer.go::maxRequestBodyBytes`).
/// 32 MiB is the agreed ceiling on both sides; the sequencer wraps each
/// HTTP body in `http.MaxBytesReader(..., maxRequestBodyBytes)` and the
/// Rust gRPC server allows the same. Tonic's default of 4 MiB would reject
/// large canonical-content uploads with a misleading "decoded message too
/// large" error.
const GRPC_MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

#[tonic::async_trait]
impl CdhsSmfServiceTrait for CdhsSmfService {
    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let req = request.into_inner();

        info!("Update request for shard: {}", req.shard_id);

        // Compute global key from shard_id and record_key
        let global_key = crypto::compute_global_key(
            &req.shard_id,
            req.record_key
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("record_key required"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("invalid record key: {}", e)))?;

        // Hash the canonical content
        let leaf_value_hash = crypto::hash_canonical_content(&req.canonical_content);

        // ADR-0003: parser_id and canonical_parser_version are bound into
        // the leaf hash domain. Both fields MUST be non-empty strings and
        // are validated here so the request fails with a clear gRPC status
        // before reaching the SMT layer.
        if req.parser_id.is_empty() {
            return Err(Status::invalid_argument(
                "parser_id must be a non-empty string",
            ));
        }
        if req.canonical_parser_version.is_empty() {
            return Err(Status::invalid_argument(
                "canonical_parser_version must be a non-empty string",
            ));
        }

        // Update the SMT
        let (new_root, deltas) = self
            .smt
            .update(
                &global_key,
                &leaf_value_hash,
                &req.parser_id,
                &req.canonical_parser_version,
            )
            .await
            .map_err(|e| Status::internal(format!("SMT update failed: {}", e)))?;

        // Get tree size after update
        let tree_size = self.smt.size().await;

        Ok(Response::new(UpdateResponse {
            new_root: new_root.to_vec(),
            global_key: global_key.to_vec(),
            leaf_value_hash: leaf_value_hash.to_vec(),
            deltas: deltas
                .into_iter()
                .map(|d| SmtNodeDelta {
                    path: d.path,
                    level: d.level,
                    hash: d.hash.to_vec(),
                })
                .collect(),
            tree_size,
        }))
    }

    async fn prepare_update(
        &self,
        request: Request<PrepareUpdateRequest>,
    ) -> Result<Response<PrepareUpdateResponse>, Status> {
        let req = request.into_inner();

        // Same input validation as `update`. We deliberately mirror the
        // single-phase RPC so the two paths are interchangeable from the
        // caller's perspective up to the transaction_id round-trip.
        let global_key = crypto::compute_global_key(
            &req.shard_id,
            req.record_key
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("record_key required"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("invalid record key: {}", e)))?;

        let leaf_value_hash = crypto::hash_canonical_content(&req.canonical_content);

        if req.parser_id.is_empty() {
            return Err(Status::invalid_argument(
                "parser_id must be a non-empty string",
            ));
        }
        if req.canonical_parser_version.is_empty() {
            return Err(Status::invalid_argument(
                "canonical_parser_version must be a non-empty string",
            ));
        }

        // Compute the new root + deltas WITHOUT mutating live state. The
        // result is staged in `self.prepared` until the sequencer has
        // committed Postgres and called CommitPreparedUpdate.
        let prepared = self
            .smt
            .compute_update(
                &global_key,
                &leaf_value_hash,
                &req.parser_id,
                &req.canonical_parser_version,
            )
            .await
            .map_err(|e| Status::internal(format!("compute_update failed: {}", e)))?;

        // Snapshot fields we need to put on the wire BEFORE moving
        // `prepared` into the LRU.
        let new_root = prepared.new_root.to_vec();
        let prior_root = prepared.prior_root.to_vec();
        let global_key_bytes = prepared.key.to_vec();
        let leaf_value_hash_bytes = prepared.value_hash.to_vec();
        let new_tree_size = prepared.new_tree_size;
        let wire_deltas: Vec<SmtNodeDelta> = prepared
            .deltas
            .iter()
            .map(|d| SmtNodeDelta {
                path: d.path.clone(),
                level: d.level,
                hash: d.hash.to_vec(),
            })
            .collect();

        let transaction_id = Uuid::new_v4().to_string();
        let pending = self.prepared.insert(transaction_id.clone(), prepared);
        // `prepared_pending` is exported via the dedicated metrics path; we
        // log here in the structured form the Go layer keys off so that
        // operators can correlate Rust-side LRU pressure with Go counters.
        tracing::debug!(
            target: "cdhs_smf::prepared",
            metric = "prepared_pending",
            value = pending,
            transaction_id = %transaction_id,
            "prepared transaction inserted"
        );

        Ok(Response::new(PrepareUpdateResponse {
            transaction_id,
            new_root,
            prior_root,
            global_key: global_key_bytes,
            leaf_value_hash: leaf_value_hash_bytes,
            deltas: wire_deltas,
            tree_size: new_tree_size,
        }))
    }

    async fn commit_prepared_update(
        &self,
        request: Request<CommitPreparedUpdateRequest>,
    ) -> Result<Response<CommitPreparedUpdateResponse>, Status> {
        let req = request.into_inner();

        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument(
                "transaction_id must be a non-empty string",
            ));
        }

        // `take` removes the entry. Whether the underlying `apply_prepared`
        // succeeds or fails, the transaction is "consumed" at this point —
        // the caller MUST re-prepare to retry. This matches the Go
        // sequencer's flow: the sequencer either holds a committed Postgres
        // row (success) or rolls back via AbortPreparedUpdate (failure).
        let prepared = self.prepared.take(&req.transaction_id).ok_or_else(|| {
            Status::not_found(
                "transaction_id not found (already committed, aborted, or TTL-evicted)",
            )
        })?;

        let new_tree_size = prepared.new_tree_size;
        let new_root = self
            .smt
            .apply_prepared(prepared)
            .await
            .map_err(|e| Status::failed_precondition(format!("apply_prepared failed: {}", e)))?;

        Ok(Response::new(CommitPreparedUpdateResponse {
            new_root: new_root.to_vec(),
            tree_size: new_tree_size,
        }))
    }

    async fn abort_prepared_update(
        &self,
        request: Request<AbortPreparedUpdateRequest>,
    ) -> Result<Response<AbortPreparedUpdateResponse>, Status> {
        let req = request.into_inner();

        if req.transaction_id.is_empty() {
            return Err(Status::invalid_argument(
                "transaction_id must be a non-empty string",
            ));
        }

        // Idempotent: returns OK whether or not the entry was present. The
        // Go sequencer can safely call Abort even on paths where the
        // PrepareUpdate response itself errored (best-effort cleanup).
        let _was_present = self.prepared.discard(&req.transaction_id);
        Ok(Response::new(AbortPreparedUpdateResponse {}))
    }

    async fn prove_inclusion(
        &self,
        request: Request<ProveInclusionRequest>,
    ) -> Result<Response<ProveInclusionResponse>, Status> {
        let req = request.into_inner();

        let global_key = crypto::compute_global_key(
            &req.shard_id,
            req.record_key
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("record_key required"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("invalid record key: {}", e)))?;

        let root = if req.root.is_empty() {
            self.smt.root().await
        } else {
            req.root
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid root length"))?
        };

        let proof = self
            .smt
            .prove_inclusion(&global_key, &root)
            .await
            .map_err(|e| Status::not_found(format!("Key not found: {}", e)))?;

        Ok(Response::new(ProveInclusionResponse {
            global_key: global_key.to_vec(),
            value_hash: proof.value_hash.to_vec(),
            siblings: proof.siblings.iter().map(|s| s.to_vec()).collect(),
            root: root.to_vec(),
            parser_id: proof.parser_id,
            canonical_parser_version: proof.canonical_parser_version,
        }))
    }

    async fn verify_inclusion(
        &self,
        request: Request<VerifyInclusionRequest>,
    ) -> Result<Response<VerifyInclusionResponse>, Status> {
        let req = request.into_inner();

        let global_key: [u8; 32] = req
            .global_key
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid global_key length"))?;
        let value_hash: [u8; 32] = req
            .value_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid value_hash length"))?;
        let root: [u8; 32] = req
            .root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid root length"))?;

        let siblings: Result<Vec<[u8; 32]>, _> = req
            .siblings
            .iter()
            .map(|s| s.as_slice().try_into())
            .collect();
        let siblings = siblings.map_err(|_| Status::invalid_argument("invalid sibling length"))?;

        // ADR-0003: parser_id and canonical_parser_version are bound into
        // the leaf hash domain. Both fields MUST be non-empty strings.
        if req.parser_id.is_empty() {
            return Err(Status::invalid_argument(
                "parser_id must be a non-empty string",
            ));
        }
        if req.canonical_parser_version.is_empty() {
            return Err(Status::invalid_argument(
                "canonical_parser_version must be a non-empty string",
            ));
        }

        let valid = smt::verify_inclusion(
            &global_key,
            &value_hash,
            &req.parser_id,
            &req.canonical_parser_version,
            &siblings,
            &root,
        );

        Ok(Response::new(VerifyInclusionResponse {
            valid,
            error: if valid {
                String::new()
            } else {
                "Proof verification failed".to_string()
            },
        }))
    }

    async fn prove_non_inclusion(
        &self,
        request: Request<ProveNonInclusionRequest>,
    ) -> Result<Response<ProveNonInclusionResponse>, Status> {
        let req = request.into_inner();

        let global_key = crypto::compute_global_key(
            &req.shard_id,
            req.record_key
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("record_key required"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("invalid record key: {}", e)))?;

        let root = if req.root.is_empty() {
            self.smt.root().await
        } else {
            req.root
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid root length"))?
        };

        let proof = self
            .smt
            .prove_non_inclusion(&global_key, &root)
            .await
            .map_err(|e| Status::internal(format!("Non-inclusion proof failed: {}", e)))?;

        Ok(Response::new(ProveNonInclusionResponse {
            global_key: global_key.to_vec(),
            siblings: proof.siblings.iter().map(|s| s.to_vec()).collect(),
            root: root.to_vec(),
        }))
    }

    async fn verify_non_inclusion(
        &self,
        request: Request<VerifyNonInclusionRequest>,
    ) -> Result<Response<VerifyNonInclusionResponse>, Status> {
        let req = request.into_inner();

        let global_key: [u8; 32] = req
            .global_key
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid global_key length"))?;
        let root: [u8; 32] = req
            .root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid root length"))?;

        let siblings: Result<Vec<[u8; 32]>, _> = req
            .siblings
            .iter()
            .map(|s| s.as_slice().try_into())
            .collect();
        let siblings = siblings.map_err(|_| Status::invalid_argument("invalid sibling length"))?;

        let valid = smt::verify_non_inclusion(&global_key, &siblings, &root);

        Ok(Response::new(VerifyNonInclusionResponse {
            valid,
            error: if valid {
                String::new()
            } else {
                "Proof verification failed".to_string()
            },
        }))
    }

    async fn canonicalize(
        &self,
        request: Request<CanonicalizeRequest>,
    ) -> Result<Response<CanonicalizeResponse>, Status> {
        let req = request.into_inner();

        let canonical_content = canonicalization::canonicalize(&req.content_type, &req.content)
            .map_err(|e| Status::invalid_argument(format!("Canonicalization failed: {}", e)))?;

        let content_hash = crypto::hash_bytes(&canonical_content);

        Ok(Response::new(CanonicalizeResponse {
            canonical_content,
            content_hash: content_hash.to_vec(),
        }))
    }

    async fn get_root(
        &self,
        _request: Request<GetRootRequest>,
    ) -> Result<Response<GetRootResponse>, Status> {
        let root = self.smt.root().await;
        let tree_size = self.smt.size().await;

        Ok(Response::new(GetRootResponse {
            root: root.to_vec(),
            tree_size,
        }))
    }

    async fn sign_root(
        &self,
        request: Request<SignRootRequest>,
    ) -> Result<Response<SignRootResponse>, Status> {
        let req = request.into_inner();

        let root: [u8; 32] = req
            .root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid root length"))?;

        let (signature, public_key) = self
            .key_manager
            .sign_root(&root, req.tree_size, &req.context)
            .map_err(|e| Status::internal(format!("Signing failed: {}", e)))?;

        Ok(Response::new(SignRootResponse {
            signature: signature.to_vec(),
            public_key: public_key.to_vec(),
        }))
    }

    async fn replay_leaves(
        &self,
        request: Request<ReplayRequest>,
    ) -> Result<Response<ReplayResponse>, Status> {
        let req = request.into_inner();

        let leaves: Result<Vec<([u8; 32], [u8; 32], String, String)>, Status> = req
            .leaves
            .into_iter()
            .enumerate()
            .map(|(i, entry)| {
                let key_len = entry.key.len();
                let key: [u8; 32] = entry
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument(format!(
                        "leaf[{}]: invalid key length (expected 32 bytes, got {})", i, key_len
                    )))?;
                let vh_len = entry.value_hash.len();
                let value_hash: [u8; 32] = entry
                    .value_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument(format!(
                        "leaf[{}]: invalid value_hash length (expected 32 bytes, got {})", i, vh_len
                    )))?;
                if entry.parser_id.is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "leaf[{}]: parser_id must be a non-empty string",
                        i
                    )));
                }
                if entry.canonical_parser_version.is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "leaf[{}]: canonical_parser_version must be a non-empty string",
                        i
                    )));
                }
                Ok((key, value_hash, entry.parser_id, entry.canonical_parser_version))
            })
            .collect();

        let leaves = leaves?;

        info!("ReplayLeaves: replaying {} leaves", leaves.len());

        let root_hash = self
            .smt
            .replay(leaves)
            .await
            .map_err(|e| Status::internal(format!("Replay failed: {}", e)))?;

        Ok(Response::new(ReplayResponse {
            root_hash: root_hash.to_vec(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let socket_path =
        env::var("CDHS_SMF_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let socket_path = Path::new(&socket_path);
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Try to bind the socket directly. On EADDRINUSE we abort with an
    // operator-actionable message instead of trying to clean up the path
    // ourselves: the previous check-then-delete (`is_socket()` followed by
    // `remove_file()`) was a TOCTOU race — between the check and the unlink
    // another process could swap the file, and we'd unlink the wrong thing.
    // Forcing the operator to remove a stale socket explicitly also avoids
    // accidentally killing a running instance that already owns the path.
    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            return Err(format!(
                "stale socket at {} — remove and restart.",
                socket_path.display()
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    };
    // Restrict the unix socket to the service user and group (rw-/rw-/---).
    // The default file mode after `bind()` follows the process umask, which
    // on many systems is `022` and would leave the socket world-readable —
    // anyone on the host could then send gRPC requests to the CD-HS-ST
    // service (signing, leaf inserts, etc.). Tightening to 0660 means only
    // the owner and group can connect; deployments are expected to set the
    // group to whatever account runs the Go sequencer.
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    let incoming = UnixListenerStream::new(listener);
    let service = CdhsSmfService::new();

    // Spawn a background task that listens for SIGHUP and triggers key rotation.
    let km_handle = service.key_manager_handle();
    tokio::spawn(async move {
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to register SIGHUP handler");
        loop {
            sighup.recv().await;
            info!("SIGHUP received — reloading signing key");
            match km_handle.reload_key() {
                Ok(new_pk) => info!(
                    "Signing key rotated successfully; new public key = {}",
                    hex::encode(new_pk)
                ),
                Err(e) => warn!(
                    "Signing key reload failed (keeping previous key): {e}"
                ),
            }
        }
    });

    info!(
        "CD-HS-ST Service starting on unix socket {}",
        socket_path.display()
    );

    // Configure the gRPC server with the agreed body-size ceiling and a
    // graceful shutdown trigger that drains in-flight requests on
    // SIGTERM/SIGINT. Without `serve_with_incoming_shutdown`, container
    // stop would abandon in-flight `Update` calls mid-tree-mutation —
    // exactly the wrong behaviour for an append-only ledger.
    Server::builder()
        .add_service(
            CdhsSmfServiceServer::new(service)
                .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;

    info!("CD-HS-ST Service shut down cleanly");
    Ok(())
}

/// Resolves when the process receives SIGTERM or SIGINT (Ctrl-C).
///
/// Used by `serve_with_incoming_shutdown` so tonic stops accepting new
/// connections and waits for in-flight RPCs (notably `Update`, which mutates
/// the SMT) to finish before the binary exits. Container orchestrators send
/// SIGTERM on stop; SIGINT is for interactive runs.
async fn shutdown_signal() {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to install SIGTERM handler ({e}); shutdown will rely on SIGINT only");
            // Fall back to waiting on SIGINT alone.
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => {
            info!("SIGTERM received — beginning graceful shutdown");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received — beginning graceful shutdown");
        }
    }
}
