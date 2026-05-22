//! P2P federation over Tor hidden services.
//!
//! Each Olympus node exposes a `.onion` endpoint serving checkpoint data.
//! Peers exchange BJJ-signed Groth16 checkpoints and detect equivocation.

pub mod api;
pub mod checkpoint;
pub mod equivocation;
pub mod gossip;
pub mod peer;
pub mod tor;

use serde::{Deserialize, Serialize};

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
            auto_block_equivocators: std::env::var("OLYMPUS_FEDERATION_AUTO_BLOCK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
        }
    }
}
