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
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use cdhs_smf_service::canonicalization;
use cdhs_smf_service::crypto;
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
}

impl CdhsSmfService {
    pub fn new() -> Self {
        Self {
            smt: SparseMerkleTree::new(),
            key_manager: Arc::new(KeyManager::new()),
        }
    }

    /// Return a clone of the `Arc<KeyManager>` so that background tasks
    /// (e.g. the SIGHUP handler) can trigger key rotation.
    pub fn key_manager_handle(&self) -> Arc<KeyManager> {
        Arc::clone(&self.key_manager)
    }
}

const DEFAULT_SOCKET_PATH: &str = "/run/olympus/cdhs-smf.sock";

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

        // Update the SMT
        let (new_root, deltas) = self
            .smt
            .update(&global_key, &leaf_value_hash)
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

        let valid = smt::verify_inclusion(&global_key, &value_hash, &siblings, &root);

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

        let leaves: Result<Vec<([u8; 32], [u8; 32])>, Status> = req
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
                Ok((key, value_hash))
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
    if socket_path.exists() {
        let metadata = fs::symlink_metadata(socket_path)?;
        if metadata.file_type().is_socket() {
            fs::remove_file(socket_path)?;
        } else {
            return Err(format!(
                "refusing to remove non-socket path: {}",
                socket_path.display()
            )
            .into());
        }
    }
    let listener = UnixListener::bind(socket_path)?;
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

    Server::builder()
        .add_service(CdhsSmfServiceServer::new(service))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}
