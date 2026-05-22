//! Tor hidden service management.
//!
//! Uses `arti-client` (pure-Rust Tor) to:
//! 1. Bootstrap a Tor connection
//! 2. Create a v3 onion hidden service for inbound peer connections
//! 3. Provide a SOCKS5-backed HTTP client for outbound .onion requests
//!
//! NOTE: arti's API evolves rapidly between 0.x releases. The public interface
//! of this module (TorHandle, start_hidden_service) is stable; the internals
//! will need updating when bumping arti versions.

use std::path::PathBuf;
use std::sync::Arc;

/// Handle to the running Tor instance and hidden service.
pub struct TorHandle {
    pub onion_address: String,
    pub http_client: reqwest::Client,
    // In production: hold Arc<TorClient<R>> + OnionService handle here
    // to keep the hidden service alive for the process lifetime.
}

/// Bootstrap Tor and create a hidden service pointing at `local_port`.
///
/// `state_dir` — persistent directory for Tor state/keys (e.g. app_data_dir/tor/).
/// The onion address is deterministic across restarts because Tor keys are persisted.
pub async fn start_hidden_service(
    state_dir: PathBuf,
    local_port: u16,
) -> Result<TorHandle, Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&state_dir)?;

    tracing::info!("federation: bootstrapping Tor (state_dir={})", state_dir.display());

    // ── arti bootstrap ──────────────────────────────────────────────────
    // arti-client's config and bootstrap API changes between 0.x releases.
    // The scaffold below outlines the sequence; adapt to the pinned version.
    //
    // let config = TorClientConfig::builder()
    //     .storage().cache_dir(state_dir.join("cache"))
    //               .state_dir(state_dir.join("state"))
    //     .build()?;
    // let client = TorClient::create_bootstrapped(config).await?;
    //
    // let svc_cfg = OnionServiceConfigBuilder::default()
    //     .nickname("olympus-federation")
    //     .build()?;
    // let (svc, handle) = client.launch_onion_service(svc_cfg)?;
    // let onion_address = svc.onion_name().to_string();
    //
    // tokio::spawn(proxy_hidden_service_streams(svc, local_port));

    // For now: return a placeholder so the rest of the federation scaffold
    // compiles and is testable over clearnet during development.
    let onion_address = format!("placeholder-{local_port}.onion");
    tracing::warn!(
        "federation: Tor hidden service NOT started (scaffold placeholder). \
         Using clearnet address 127.0.0.1:{local_port} for dev."
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    Ok(TorHandle {
        onion_address,
        http_client,
    })
}

/// Create an HTTP client that routes through the Tor SOCKS proxy.
///
/// In production this uses `arti-hyper` to wrap a `TorClient` as a
/// `hyper::client::connect::Connect` impl, giving transparent .onion routing.
/// During development, returns a plain reqwest client.
pub fn tor_http_client() -> reqwest::Client {
    // TODO: Wire arti-hyper connector for real .onion support.
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client")
}
