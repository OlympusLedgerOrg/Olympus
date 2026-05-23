//! OpenTimestamps calendar-server client.
//!
//! OTS splits anchoring into two phases:
//!
//! 1. **Submit** — POST the SHA-256 hash to a calendar server, which
//!    aggregates many submissions, builds an interim Merkle tree, and
//!    returns a *pending* receipt: a binary file that proves "your hash
//!    will be in Bitcoin block N once the calendar's commit lands."
//!
//! 2. **Upgrade** (later) — the calendar eventually commits the interim
//!    root to the Bitcoin blockchain via an OP_RETURN transaction. Once
//!    that transaction is N blocks deep (typically 6), the calendar
//!    returns a *complete* receipt that includes the full Bitcoin
//!    block-header path. Anyone can then verify the original hash against
//!    the public Bitcoin chain without trusting the calendar at all.
//!
//! v0.9 implements submission only. Upgrade is a future cron — the
//! pending receipt is sufficient to demonstrate the anchor was *attempted*
//! at time T, and the operator (or a follow-up `anchor::upgrade_all`
//! pass) re-fetches once the Bitcoin commit settles. We persist the raw
//! pending bytes so the upgrade path can be added without touching this
//! module.
//!
//! Calendar protocol reference:
//! <https://github.com/opentimestamps/python-opentimestamps>
//! <https://github.com/opentimestamps/opentimestamps-server>

use super::{AnchorError, AnchorKind, AnchorReceipt};

/// `POST <calendar>/digest` with the raw 32-byte SHA-256 hash as the body.
/// Returns the calendar's pending-receipt bytes verbatim. The OTS file
/// format is well-defined (magic header `\x00OpenTimestamps\x00\x00Proof`
/// followed by the proof tree); we store the bytes opaquely and rely on
/// the standard `ots` CLI / `python-opentimestamps` to verify or upgrade.
const DIGEST_PATH: &str = "/digest";

pub async fn submit(
    http: &reqwest::Client,
    calendar_url: &str,
    hash: &[u8; 32],
) -> Result<AnchorReceipt, AnchorError> {
    let url = format!("{}{}", calendar_url.trim_end_matches('/'), DIGEST_PATH);

    let resp = http
        .post(&url)
        // The OTS calendar protocol uses application/octet-stream for
        // both the body and the response.
        .header("Content-Type", "application/octet-stream")
        .header("Accept", "application/octet-stream")
        // OTS calendars require this header to disambiguate their HTTP
        // API from the website; missing it returns text/html.
        .header("User-Agent", concat!("olympus-anchor/", env!("CARGO_PKG_VERSION")))
        .body(hash.to_vec())
        .send()
        .await?;

    let status = resp.status();
    let bytes = resp.bytes().await?.to_vec();
    if !status.is_success() {
        return Err(AnchorError::Server {
            status: status.as_u16(),
            detail: String::from_utf8_lossy(&bytes).chars().take(512).collect(),
        });
    }

    // Sanity check: every OTS calendar response is a "Timestamp" file
    // body (without the file-magic header — that's only present in
    // serialised .ots files). The first byte should be a recognised
    // attestation tag (0x00, 0x08-0x0f) or a Merkle op (0xf0-0xff).
    // We accept anything non-empty to avoid being overly strict against
    // future calendar protocol versions; verification proper happens
    // via the OTS CLI later.
    if bytes.is_empty() {
        return Err(AnchorError::Parse(
            "OTS calendar returned empty body".into(),
        ));
    }

    Ok(AnchorReceipt {
        kind: AnchorKind::Ots,
        anchored_hash: *hash,
        receipt_blob: bytes,
        target: calendar_url.to_owned(),
        // Pending receipts have no integrated time yet; the calendar
        // commits to Bitcoin within minutes and the upgrade pass fills
        // in `bitcoin_block_height`, `bitcoin_merkle_root`, etc.
        metadata: serde_json::json!({
            "phase": "pending",
            "hash_algorithm": "sha256",
            "needs_upgrade": true,
        }),
    })
}

/// Convert a stored pending OTS receipt into a complete one by re-fetching
/// against the same calendar after Bitcoin has confirmed the commit.
///
/// `POST <calendar>/timestamp` with the pending bytes returns the upgraded
/// proof (or 404 / 405 if the commit hasn't landed yet — the caller
/// should retry later).
pub async fn try_upgrade(
    http: &reqwest::Client,
    calendar_url: &str,
    pending_bytes: &[u8],
) -> Result<Option<Vec<u8>>, AnchorError> {
    let url = format!(
        "{}/timestamp/{}",
        calendar_url.trim_end_matches('/'),
        // The calendar accepts the commitment digest as a hex segment in
        // some versions; for compatibility we POST the pending bytes
        // and let the calendar do the lookup.
        ""
    );

    let resp = http
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("Accept", "application/octet-stream")
        .body(pending_bytes.to_vec())
        .send()
        .await?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::ACCEPTED {
        return Ok(None);
    }
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        return Err(AnchorError::Server {
            status: status.as_u16(),
            detail: detail.chars().take(512).collect(),
        });
    }
    let bytes = resp.bytes().await?.to_vec();
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn submit_returns_receipt_on_success() {
        let server = MockServer::start().await;
        let proof_bytes: Vec<u8> = vec![0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        Mock::given(method("POST"))
            .and(path("/digest"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(proof_bytes.clone()))
            .mount(&server)
            .await;

        let hash = [0x42u8; 32];
        let rcpt = submit(&http(), &server.uri(), &hash).await.unwrap();
        assert_eq!(rcpt.kind, AnchorKind::Ots);
        assert_eq!(rcpt.anchored_hash, hash);
        assert_eq!(rcpt.receipt_blob, proof_bytes);
        assert_eq!(rcpt.target, server.uri());
        assert_eq!(rcpt.metadata["phase"], "pending");
        assert_eq!(rcpt.metadata["needs_upgrade"], true);
    }

    #[tokio::test]
    async fn submit_trims_trailing_slash_from_calendar_url() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/digest"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x00]))
            .mount(&server)
            .await;
        // Pass URL with trailing slash; the function must collapse it so the
        // resulting URL is `<uri>/digest`, not `<uri>//digest`.
        let url_with_slash = format!("{}/", server.uri());
        assert!(submit(&http(), &url_with_slash, &[0u8; 32]).await.is_ok());
    }

    #[tokio::test]
    async fn submit_returns_server_error_on_non_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/digest"))
            .respond_with(ResponseTemplate::new(503).set_body_string("calendar overloaded"))
            .mount(&server)
            .await;

        let err = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        match err {
            AnchorError::Server { status, detail } => {
                assert_eq!(status, 503);
                assert!(detail.contains("calendar overloaded"));
            }
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_rejects_empty_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/digest"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::<u8>::new()))
            .mount(&server)
            .await;

        let err = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }

    #[tokio::test]
    async fn try_upgrade_returns_none_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let out = try_upgrade(&http(), &server.uri(), &[0u8; 32]).await.unwrap();
        assert!(out.is_none(), "404 must surface as None (pending)");
    }

    #[tokio::test]
    async fn try_upgrade_returns_none_on_202_accepted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        let out = try_upgrade(&http(), &server.uri(), &[0u8; 32]).await.unwrap();
        assert!(out.is_none(), "202 must surface as None (still pending)");
    }

    #[tokio::test]
    async fn try_upgrade_returns_bytes_on_success() {
        let server = MockServer::start().await;
        let upgraded: Vec<u8> = vec![0xf0, 0x01, 0x02];
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(upgraded.clone()))
            .mount(&server)
            .await;
        let out = try_upgrade(&http(), &server.uri(), &[0u8; 32]).await.unwrap();
        assert_eq!(out, Some(upgraded));
    }

    #[tokio::test]
    async fn try_upgrade_propagates_server_error_on_500() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let err = try_upgrade(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        assert!(matches!(err, AnchorError::Server { status: 500, .. }));
    }
}
