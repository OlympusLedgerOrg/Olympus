use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod routes;

pub async fn start() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, build_router())
            .await
            .expect("axum server exited unexpectedly");
    });
    Ok(addr)
}

fn build_router() -> Router {
    // CORS: only allow Tauri's built-in origin (tauri://localhost) and the Vite
    // dev server origin.  The server is bound to 127.0.0.1 so network-level
    // access is already loopback-only; this is a defence-in-depth header check.
    let cors = CorsLayer::new().allow_origin(AllowOrigin::predicate(|origin, _| {
        let s = origin.as_bytes();
        s == b"tauri://localhost"
            || s.starts_with(b"http://localhost:")
            || s.starts_with(b"http://127.0.0.1:")
    }));

    Router::new()
        .route("/health", get(routes::health))
        .fallback(routes::not_implemented)
        .layer(cors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_binds_and_returns_addr() {
        let addr = start().await.expect("server should start");
        assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn health_endpoint_returns_200() {
        let addr = start().await.expect("server should start");
        let url = format!("http://{}/health", addr);
        let body = reqwest::get(&url).await.unwrap();
        assert_eq!(body.status(), 200);
    }
}
