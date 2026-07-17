//! Bounded-response readers for outbound anchoring HTTP calls.
//!
//! Red-team **OTS-2 (HIGH, CONFIRMED)**: every outbound `reqwest::Response`
//! in this module's calendar / TSA / Rekor client paths previously read
//! `resp.bytes().await?.to_vec()` with no body-size cap. `reqwest`
//! enforces `.timeout()` but does not enforce a response-size limit, so
//! an adversarial (or buggy) anchoring backend that streams gigabytes of
//! garbage will buffer the whole response into `Vec<u8>` and OOM the
//! desktop process.
//!
//! Real OTS pending/upgraded receipts are <1 KiB. Real RFC 3161 TSRs are
//! a few KiB. Rekor JSON entries are well under 1 MiB. A 10 MiB ceiling
//! is two-to-three orders of magnitude above any honest payload, well
//! below any memory-pressure threshold on the supported platforms, and
//! the SAME cap the in-memory `ots_format::MAX_RECEIPT_BYTES` already
//! uses for the parser. Anything over that is rejected as
//! `AnchorError::Parse` so the caller treats it the same as a malformed
//! payload. Non-success bodies are diagnostics rather than receipts and stop
//! at the separate 8 KiB cap below.

use crate::anchoring::AnchorError;

/// Hard ceiling on anchoring-backend response bodies. Two-to-three
/// orders of magnitude above any legitimate payload; well below the
/// per-request memory pressure threshold. Sized in bytes.
pub const MAX_ANCHOR_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Error bodies are diagnostic only. Keep them much smaller than successful
/// cryptographic receipts so a failing backend cannot consume 10 MiB per
/// retry merely to produce a log message (M-17).
pub const MAX_ANCHOR_ERROR_DETAIL_BYTES: usize = 8 * 1024;

/// Read at most `MAX_ANCHOR_RESPONSE_BYTES` bytes from a streamed
/// `reqwest::Response`. Buffers chunks as they arrive; bails with
/// `AnchorError::Parse` the moment the running total exceeds the cap.
///
/// Why a chunked stream rather than `.bytes()` with a post-check: a
/// post-check still buffers the full response into memory before we can
/// reject it. The chunked path stops fetching when the cap is hit, so
/// even a 10 GB stream costs only 10 MiB of buffered state before the
/// connection is dropped.
pub async fn read_response_capped(
    resp: reqwest::Response,
    context: &'static str,
) -> Result<Vec<u8>, AnchorError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt as _;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AnchorError::Http(e.to_string()))?;
        if buf.len() + chunk.len() > MAX_ANCHOR_RESPONSE_BYTES {
            return Err(AnchorError::Parse(format!(
                "{context}: response exceeded {MAX_ANCHOR_RESPONSE_BYTES} byte cap (red-team \
                 OTS-2: refusing to buffer adversarial-sized anchoring response)"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read a bounded, lossy UTF-8 diagnostic from a non-success response. The
/// stream is dropped as soon as the cap is reached and a truncation marker is
/// appended; no `.text()`/`.bytes()` call can buffer the remainder.
pub async fn read_error_detail_capped(
    resp: reqwest::Response,
    context: &'static str,
) -> Result<String, AnchorError> {
    let mut buf = Vec::with_capacity(MAX_ANCHOR_ERROR_DETAIL_BYTES);
    let mut truncated = false;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt as _;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AnchorError::Http(e.to_string()))?;
        let remaining = MAX_ANCHOR_ERROR_DETAIL_BYTES.saturating_sub(buf.len());
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }

    let mut detail = String::from_utf8_lossy(&buf).into_owned();
    if detail.len() > MAX_ANCHOR_ERROR_DETAIL_BYTES {
        let mut boundary = MAX_ANCHOR_ERROR_DETAIL_BYTES;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
        truncated = true;
    }
    if detail.trim().is_empty() {
        detail = format!("{context}: empty error response");
    }
    if truncated {
        detail.push_str(" [truncated at 8192 bytes]");
    }
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn capped_read_accepts_small_body() {
        let server = MockServer::start().await;
        let body = vec![0x42u8; 4096];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;
        let resp = http().get(server.uri()).send().await.unwrap();
        let got = read_response_capped(resp, "test").await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn capped_read_rejects_oversize_body() {
        // Body strictly larger than the cap — read_response_capped MUST
        // refuse rather than buffer the whole thing.
        let server = MockServer::start().await;
        let body = vec![0x42u8; MAX_ANCHOR_RESPONSE_BYTES + 1024];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let resp = http().get(server.uri()).send().await.unwrap();
        let err = read_response_capped(resp, "test").await.unwrap_err();
        match err {
            AnchorError::Parse(msg) => {
                assert!(
                    msg.contains("OTS-2") || msg.contains("byte cap"),
                    "error must cite the cap: {msg}"
                );
            }
            other => panic!("expected Parse error citing cap, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_detail_stops_at_small_cap() {
        let server = MockServer::start().await;
        let body = format!(
            "{}NEVER_BUFFER_THIS_TAIL",
            "x".repeat(MAX_ANCHOR_ERROR_DETAIL_BYTES + 1024)
        );
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string(body))
            .mount(&server)
            .await;
        let resp = http().get(server.uri()).send().await.unwrap();
        let detail = read_error_detail_capped(resp, "test backend")
            .await
            .unwrap();
        assert!(detail.contains("truncated at 8192 bytes"));
        assert!(!detail.contains("NEVER_BUFFER_THIS_TAIL"));
        assert!(detail.len() < MAX_ANCHOR_ERROR_DETAIL_BYTES + 64);
    }
}
