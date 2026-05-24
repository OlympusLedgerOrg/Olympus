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
use tor_cell::relaycell::msg::Connected as TorConnected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RendRequest, RunningOnionService, StreamRequest};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

/// Handle to the running Tor instance and hidden service.
pub struct TorHandle {
    pub onion_address: String,
    connector: ArtiConnector,
    _service: Arc<RunningOnionService>,
}

impl TorHandle {
    /// Build a hyper HTTP client that routes all traffic through Tor.
    pub fn http_client<B>(&self) -> hyper_util::client::legacy::Client<ArtiConnector, B>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        hyper_util::client::legacy::Client::builder(
            hyper_util::rt::TokioExecutor::new(),
        )
        .build(self.connector.clone())
    }
}

/// Bootstrap Tor and create a hidden service pointing at `local_port`.
///
/// `state_dir` — persistent directory for Tor state/keys (e.g. app_data_dir/tor/).
/// The onion address is deterministic across restarts because arti persists
/// hidden service keys in `state_dir`.
pub async fn start_hidden_service(
    state_dir: PathBuf,
    local_port: u16,
) -> Result<TorHandle, Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(&state_dir)?;

    tracing::info!("federation: bootstrapping Tor (state_dir={})", state_dir.display());

    let config = TorClientConfigBuilder::from_directories(
        state_dir.join("state"),
        state_dir.join("cache"),
    )
    .build()?;

    let client = TorClient::create_bootstrapped(config).await?;

    tracing::info!("federation: Tor bootstrapped, launching hidden service");

    let nickname: HsNickname = "olympus-federation".parse()?;
    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(nickname)
        .build()?;

    let (service, rend_requests) = client.launch_onion_service(svc_config)?;

    let onion_address = service
        .onion_name()
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
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
