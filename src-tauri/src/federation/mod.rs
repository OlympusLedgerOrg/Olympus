//! P2P federation over Tor hidden services.
//!
//! Each Olympus node exposes a `.onion` endpoint serving checkpoint data.
//! Peers exchange BJJ-signed Groth16 checkpoints and detect equivocation.
//!
//! # v0.9 state (audit H-F1)
//!
//! This module is **feature-gated** (`--features federation`) AND
//! **inert-by-default even when compiled in**: the default ship and CI
//! builds compile the routes for type-coverage but `start_hidden_service`
//! / `gossip::spawn` are not wired into [`crate::main`]. Operators who
//! want federation to actually run must:
//!
//!   1. Build with `--features federation`.
//!   2. Add the Tor bootstrap + gossip spawn calls to `main.rs`.
//!   3. Set `OLYMPUS_FEDERATION_ENABLED=1` and configure peers via the
//!      admin API.
//!
//! See [docs/federation.md](../../../docs/federation.md) for the full
//! operator runbook.

pub mod api;
pub mod checkpoint;
pub mod equivocation;
pub mod gossip;
pub mod peer;
pub mod tor;
pub mod verify;

use serde::{Deserialize, Serialize};

/// Wire-format version for [`checkpoint::PeerCheckpoint`] (audit L-F1).
/// Bump when any field is added, removed, or its semantics change. The
/// verify path rejects non-matching versions instead of silently parsing
/// a different shape as the current one.
pub const PEER_CHECKPOINT_WIRE_VERSION: u8 = 1;

/// Federation configuration, loaded from environment or defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    pub enabled: bool,
    /// This node's .onion address (set after Tor bootstraps).
    pub onion_address: Option<String>,
    /// Gossip sync interval in seconds.
    pub sync_interval_secs: u64,
    /// Auto-block peers that equivocate.
    pub auto_block_equivocators: bool,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("OLYMPUS_FEDERATION_ENABLED")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            onion_address: None,
            sync_interval_secs: std::env::var("OLYMPUS_FEDERATION_SYNC_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .map(|v: u64| v.max(10))
                .unwrap_or(300),
            // Audit H-12 / F-3: default changed from `true` to `false`.
            // Auto-blocking on equivocation is weaponisable by anyone who
            // can push an inbound checkpoint with a peer's pubkey on the
            // envelope (the BJJ signature gate in verify::verify_and_store
            // catches it now, but the default should still be opt-in).
            // Operators who want auto-block must explicitly set
            // `OLYMPUS_FEDERATION_AUTO_BLOCK=1`.
            auto_block_equivocators: std::env::var("OLYMPUS_FEDERATION_AUTO_BLOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }
}
