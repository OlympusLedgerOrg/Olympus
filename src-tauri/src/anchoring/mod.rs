//! External anchoring of Olympus ledger roots.
//!
//! Olympus signs its own checkpoint roots (Ed25519 + Baby Jubjub), but a
//! signature only proves *we* attest to a root — it doesn't prove the root
//! existed at time T to a court / outside auditor / journalist's lawyer.
//! For that, the root has to be embedded in someone else's transparency
//! mechanism. This module owns the three production anchors:
//!
//! * [`rfc3161`] — IETF RFC 3161 Time-Stamp Protocol. Submit a hash to an
//!   accredited TSA, receive a CMS SignedData "TimeStampToken" you can hand
//!   to opposing counsel. eIDAS-recognised in the EU; admitted as evidence
//!   in US federal cases. The strongest *legal* anchor available.
//!
//! * [`rekor`] — Sigstore Rekor transparency log. POST a signed entry to a
//!   public Rekor instance, receive a UUID + log index + signed entry
//!   timestamp. Append-only; the log itself is monitored by third parties
//!   so an undetected forgery would require compromising Rekor's signing
//!   key *and* its monitoring constituency. Good *cryptographic-community*
//!   anchor.
//!
//! * [`ots`] — OpenTimestamps. POST a hash to a public OTS calendar
//!   server, receive an opaque pending receipt that the calendar will
//!   eventually upgrade with a Bitcoin block-header inclusion path. Once
//!   upgraded, verifiable against the public Bitcoin chain with no further
//!   trust in OTS infrastructure. Slowest (~hours for the Bitcoin commit)
//!   but the *strongest decentralised* anchor.
//!
//! The three are deliberately layered: a court can rely on RFC 3161 alone
//! (accredited authority signed the timestamp); an auditor cross-checks
//! against Rekor (the log shows the same hash entered when claimed); and
//! anyone can independently re-verify against Bitcoin without trusting the
//! Olympus federation, the TSA, or Sigstore. See `docs/court-evidence.md`.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub mod api;
pub mod ots;
pub mod rekor;
pub mod rfc3161;
pub mod store;

/// Three anchor kinds, matching the `anchor_receipts.anchor_kind` CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    Rfc3161,
    Rekor,
    Ots,
}

impl AnchorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnchorKind::Rfc3161 => "rfc3161",
            AnchorKind::Rekor => "rekor",
            AnchorKind::Ots => "ots",
        }
    }
}

/// A receipt fetched from an anchor service. The bytes are opaque to the
/// caller — verification is delegated to the anchor's own client.
#[derive(Debug, Clone)]
pub struct AnchorReceipt {
    pub kind: AnchorKind,
    pub anchored_hash: [u8; 32],
    pub receipt_blob: Vec<u8>,
    pub target: String,
    pub metadata: serde_json::Value,
}

/// Outbound configuration: which anchor services to use.
///
/// `None` for any field disables that anchor. The default config disables
/// all three — anchoring is explicit, not implicit, because each anchor
/// involves an outbound network call to a third party.
#[derive(Debug, Clone, Default)]
pub struct AnchoringConfig {
    /// RFC 3161 TSA URL, e.g. `https://freetsa.org/tsr`.
    pub rfc3161_url: Option<String>,
    /// Rekor server URL, e.g. `https://rekor.sigstore.dev`.
    pub rekor_url: Option<String>,
    /// OpenTimestamps calendar URLs (any successful submission suffices,
    /// but the OTS protocol expects ≥ 3 calendars for fault tolerance).
    pub ots_calendars: Vec<String>,
}

impl AnchoringConfig {
    /// Build from `OLYMPUS_ANCHOR_*` env vars. All three are optional;
    /// each comma-separated for OTS, single URL for RFC 3161 and Rekor.
    pub fn from_env() -> Self {
        Self {
            rfc3161_url: std::env::var("OLYMPUS_ANCHOR_RFC3161_URL").ok(),
            rekor_url: std::env::var("OLYMPUS_ANCHOR_REKOR_URL").ok(),
            ots_calendars: std::env::var("OLYMPUS_ANCHOR_OTS_CALENDARS")
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_owned())
                        .filter(|p| !p.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.rfc3161_url.is_some()
            || self.rekor_url.is_some()
            || !self.ots_calendars.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("HTTP transport: {0}")]
    Http(String),
    #[error("server returned status {status}: {detail}")]
    Server { status: u16, detail: String },
    #[error("response parse: {0}")]
    Parse(String),
    #[error("database: {0}")]
    Db(String),
    #[error("anchor not configured: {0}")]
    NotConfigured(&'static str),
}

impl From<reqwest::Error> for AnchorError {
    fn from(e: reqwest::Error) -> Self {
        AnchorError::Http(e.to_string())
    }
}

impl From<sqlx::Error> for AnchorError {
    fn from(e: sqlx::Error) -> Self {
        AnchorError::Db(e.to_string())
    }
}

/// Anchor a 32-byte hash to every configured anchor service.
///
/// Each anchor is attempted independently — a failure on one does not
/// cancel the others. Returns the list of receipts that were successfully
/// stored, plus a parallel list of errors for the ones that failed. The
/// caller decides whether partial success is acceptable (it usually is —
/// the three anchors are redundant by design).
pub async fn anchor_all(
    pool: &PgPool,
    cfg: &AnchoringConfig,
    http: &reqwest::Client,
    hash: [u8; 32],
    checkpoint_id: Option<Uuid>,
) -> (Vec<Uuid>, Vec<(AnchorKind, AnchorError)>) {
    let mut ids = Vec::new();
    let mut errs: Vec<(AnchorKind, AnchorError)> = Vec::new();

    // RFC 3161 — single TSA submission.
    if let Some(url) = &cfg.rfc3161_url {
        match rfc3161::submit(http, url, &hash).await {
            Ok(rcpt) => match store::insert(pool, &rcpt, checkpoint_id).await {
                Ok(id) => ids.push(id),
                Err(e) => errs.push((AnchorKind::Rfc3161, e)),
            },
            Err(e) => errs.push((AnchorKind::Rfc3161, e)),
        }
    }

    // Rekor — single instance.
    if let Some(url) = &cfg.rekor_url {
        match rekor::submit(http, url, &hash).await {
            Ok(rcpt) => match store::insert(pool, &rcpt, checkpoint_id).await {
                Ok(id) => ids.push(id),
                Err(e) => errs.push((AnchorKind::Rekor, e)),
            },
            Err(e) => errs.push((AnchorKind::Rekor, e)),
        }
    }

    // OTS — try each calendar; persist every successful pending receipt
    // so we have N independent commitments to upgrade.
    for cal in &cfg.ots_calendars {
        match ots::submit(http, cal, &hash).await {
            Ok(rcpt) => match store::insert(pool, &rcpt, checkpoint_id).await {
                Ok(id) => ids.push(id),
                Err(e) => errs.push((AnchorKind::Ots, e)),
            },
            Err(e) => errs.push((AnchorKind::Ots, e)),
        }
    }

    (ids, errs)
}

/// Shared HTTP client used by all three anchor backends. Wrapping in `Arc`
/// lets `AppState::Clone` cheap-clone the underlying connection pool.
pub fn build_http_client(timeout: std::time::Duration) -> Arc<reqwest::Client> {
    Arc::new(
        reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("olympus-anchor/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client should build with default config"),
    )
}
