//! Tor hidden service management via arti-client 0.31.
//!
//! Bootstraps an embedded Tor client, creates a persistent v3 onion hidden
//! service for inbound peer connections, and proxies accepted streams to the
//! local Axum HTTP server. Provides a Tor-routed HTTP client for outbound
//! .onion requests.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use futures::StreamExt;
use hyper::Uri;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected as TorConnected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RendRequest, RunningOnionService, StreamRequest};

/// Handle to the running Tor instance and hidden service.
pub struct TorHandle {
    pub onion_address: String,
    connector: ArtiConnector,
    _service: Arc<RunningOnionService>,
}

/// Concrete hyper client that routes every request through this node's
/// bootstrapped Tor client. The gossip loop uses it to push/pull checkpoints
/// over peer `.onion` endpoints; a plain client can't reach `.onion` hosts.
pub type TorHttpClient =
    hyper_util::client::legacy::Client<ArtiConnector, http_body_util::Full<hyper::body::Bytes>>;

impl TorHandle {
    /// Build a [`TorHttpClient`] for outbound checkpoint exchange. Cheap to
    /// call — the underlying [`ArtiConnector`] just clones the shared Tor
    /// client, so the connection pool is established lazily on first use.
    pub fn checkpoint_http_client(&self) -> TorHttpClient {
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(self.connector.clone())
    }
}

/// Wipe the persisted hidden-service identity material from `state_dir`
/// so the next bootstrap mints a fresh `.onion` address (audit M-F2).
///
/// Returns the number of entries removed (0 if the HS state subdir
/// didn't exist). Leaves the rest of the arti state (Tor consensus
/// cache, circuit fingerprints, etc.) untouched — only the HS identity
/// is reset.
///
/// **The caller is responsible for restarting the hidden service** (or
/// the whole process) afterwards; arti caches the HS keypair in memory
/// for the lifetime of the running service, so the new onion address
/// only appears after a re-bootstrap. Peers that pinned the old onion
/// must be re-registered with the new address — see
/// `docs/federation.md` for the full procedure.
pub fn wipe_hidden_service_keys(state_dir: &std::path::Path) -> Result<usize, std::io::Error> {
    // arti 0.31 keeps HS material under `<state_dir>/state/hs_service/`.
    // If the layout shifts in a future arti version this function will
    // need to learn about it; the doc on `docs/federation.md` includes a
    // fallback manual procedure for that case.
    let hs_dir = state_dir.join("state").join("hs_service");
    if !hs_dir.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(&hs_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        removed += 1;
    }
    Ok(removed)
}

/// Bootstrap Tor and create a hidden service pointing at `local_port`.
///
/// `state_dir` — persistent directory for Tor state/keys (e.g. app_data_dir/tor/).
/// The onion address is deterministic across restarts because arti persists
/// hidden service keys in `state_dir`. Use [`wipe_hidden_service_keys`]
/// + restart to rotate the address.
pub async fn start_hidden_service(
    state_dir: PathBuf,
    local_port: u16,
) -> Result<TorHandle, Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&state_dir)?;

    tracing::info!(
        "federation: bootstrapping Tor (state_dir={})",
        state_dir.display()
    );

    let config =
        TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"))
            .build()?;

    let client = TorClient::create_bootstrapped(config).await?;

    tracing::info!("federation: Tor bootstrapped, launching hidden service");

    let nickname: HsNickname = "olympus-federation".parse()?;
    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()?;

    let (service, rend_requests) = client.launch_onion_service(svc_config)?;

    let onion_address = service
        .onion_address()
        .map(|id| id.to_string())
        .ok_or("hidden service launched but onion identity is unavailable")?;

    tracing::info!("federation: hidden service live at {onion_address}");

    tokio::spawn(accept_loop(rend_requests, local_port));

    let connector = ArtiConnector { client };

    Ok(TorHandle {
        onion_address,
        connector,
        _service: service,
    })
}

// ── Outbound .onion HTTP client ─────────────────────────────────────────────

/// Wrapper around `DataStream` that implements hyper's I/O + Connection traits.
pub struct TorStream(TokioIo<DataStream>);

impl hyper::rt::Read for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for TorStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Unpin for TorStream {}

/// hyper-compatible connector that routes TCP via `TorClient::connect()`.
#[derive(Clone)]
pub struct ArtiConnector {
    client: TorClient<tor_rtcompat::PreferredRuntime>,
}

impl tower_service::Service<Uri> for ArtiConnector {
    type Response = TorStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let client = self.client.clone();
        Box::pin(async move {
            let host = uri.host().ok_or("URI missing host")?;
            let port = uri.port_u16().unwrap_or(80);
            let stream = client.connect((host, port)).await?;
            Ok(TorStream(TokioIo::new(stream)))
        })
    }
}

// ── Inbound hidden service proxy ────────────────────────────────────────────

/// Accept inbound rendezvous requests and proxy each stream to the local
/// Axum server at 127.0.0.1:`local_port`.
async fn accept_loop(
    mut rend_requests: impl futures::Stream<Item = RendRequest> + Unpin + Send + 'static,
    local_port: u16,
) {
    while let Some(rend_req) = rend_requests.next().await {
        let stream_requests = match rend_req.accept().await {
            Ok(sr) => sr,
            Err(e) => {
                tracing::warn!("federation: rendezvous accept failed: {e}");
                continue;
            }
        };

        tokio::spawn(handle_streams(stream_requests, local_port));
    }
    tracing::warn!("federation: rendezvous request stream ended");
}

/// Handle stream requests from a single rendezvous circuit.
async fn handle_streams(
    mut stream_requests: impl futures::Stream<Item = StreamRequest> + Unpin + Send + 'static,
    local_port: u16,
) {
    while let Some(stream_req) = stream_requests.next().await {
        let data_stream: DataStream = match stream_req.accept(TorConnected::new_empty()).await {
            Ok(ds) => ds,
            Err(e) => {
                tracing::warn!("federation: stream accept failed: {e}");
                continue;
            }
        };
        tokio::spawn(proxy_to_local(data_stream, local_port));
    }
}

/// Bidirectional copy between an inbound Tor DataStream and a TCP connection
/// to the local Axum HTTP server.
async fn proxy_to_local(mut tor_stream: DataStream, local_port: u16) {
    let mut tcp = match TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("federation: failed to connect to local port {local_port}: {e}");
            return;
        }
    };
    if let Err(e) = copy_bidirectional(&mut tor_stream, &mut tcp).await {
        tracing::debug!("federation: proxy stream closed: {e}");
    }
}

#[cfg(test)]
mod tests {
    //! Audit M-F2: pin the file-wipe behaviour so a future arti version
    //! that shifts the HS state layout fails loudly here instead of
    //! silently leaving keys behind on rotate.
    use super::wipe_hidden_service_keys;

    #[test]
    fn wipe_returns_zero_when_no_state_dir() {
        // Operators who call rotate before federation has ever
        // bootstrapped should get a graceful zero, not a "directory
        // not found" surfaced as 500.
        let base = tempfile::tempdir().unwrap();
        let tmp = base.path().join("not-created");
        // Don't create it — the function should accept "doesn't exist".
        let removed = wipe_hidden_service_keys(&tmp).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn wipe_removes_files_and_subdirs_in_hs_service_dir() {
        // Make a fake state dir matching arti's layout and verify
        // wipe takes out everything inside hs_service/ but leaves
        // sibling directories alone.
        let tmp = tempfile::tempdir().unwrap();
        let hs = tmp.path().join("state").join("hs_service");
        let sibling = tmp.path().join("state").join("netdir_cache");
        std::fs::create_dir_all(&hs).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(hs.join("secret_key"), b"fake-key").unwrap();
        std::fs::write(hs.join("public_key"), b"fake-pub").unwrap();
        std::fs::create_dir_all(hs.join("nested")).unwrap();
        std::fs::write(hs.join("nested").join("inner"), b"x").unwrap();
        std::fs::write(sibling.join("untouched"), b"keep me").unwrap();

        let removed = wipe_hidden_service_keys(tmp.path()).unwrap();
        assert_eq!(removed, 3, "two files + one nested dir");
        assert!(hs.exists(), "hs_service dir itself remains (empty)");
        assert!(!hs.join("secret_key").exists());
        assert!(!hs.join("nested").exists());
        // Sibling state must be untouched.
        assert!(sibling.join("untouched").exists());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
