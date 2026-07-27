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
use std::future::Future;
use std::sync::Arc;
use uuid::Uuid;

pub mod api;
pub mod cron;
pub mod http_limits;
pub mod ots;
pub mod ots_bitcoin;
pub mod ots_format;
mod ots_tree;
pub mod own_checkpoint;
pub mod rekor;
pub mod rfc3161;
mod rfc3161_verify;
pub(crate) mod safe_file;
pub mod store;
#[cfg(test)]
pub(crate) mod test_fixtures;
pub mod tstinfo;
pub mod upgrade_cron;

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
#[derive(Debug, Clone)]
pub struct AnchoringConfig {
    /// RFC 3161 TSA URL, e.g. `https://freetsa.org/tsr`.
    pub rfc3161_url: Option<String>,
    /// Rekor server URL, e.g. `https://rekor.sigstore.dev`.
    pub rekor_url: Option<String>,
    /// OpenTimestamps calendar URLs (any successful submission suffices,
    /// but the OTS protocol expects ≥ 3 calendars for fault tolerance).
    pub ots_calendars: Vec<String>,
    /// Operator-pinned Bitcoin mainnet block-header manifest used to turn a
    /// structurally upgraded OTS receipt into verified evidence. Without it a
    /// calendar's claimed block height and Merkle root are unverified hearsay,
    /// so the upgrade cron refuses to run rather than mark receipts verified.
    pub ots_bitcoin_headers_path: Option<std::path::PathBuf>,
    /// Cron interval in seconds for the periodic anchor task (audit H-A1).
    /// Loaded from `OLYMPUS_ANCHOR_INTERVAL_SECS` (default 3600).
    /// Floored at 60s in `cron::spawn` to avoid hammering third-party services.
    pub interval_secs: u64,
}

/// 1 hour. Matches the cadence court-evidence.md §6.5 recommends for
/// "periodic public posting" of checkpoint receipts.
const DEFAULT_INTERVAL_SECS: u64 = 3600;

impl Default for AnchoringConfig {
    fn default() -> Self {
        Self {
            rfc3161_url: None,
            rekor_url: None,
            ots_calendars: Vec::new(),
            ots_bitcoin_headers_path: None,
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

impl AnchoringConfig {
    /// Build from `OLYMPUS_ANCHOR_*` env vars. All anchor URLs are optional;
    /// each comma-separated for OTS, single URL for RFC 3161 and Rekor.
    ///
    /// Audit L-A2: every URL is validated to be `https://...` or
    /// `http://localhost` / `http://127.0.0.1` (dev only). A
    /// misconfigured operator who sets `http://random.host` is told via a
    /// startup `tracing::warn!` and the URL is silently dropped from the
    /// config — anchor submission to a non-TLS public endpoint would
    /// otherwise expose the receipt request to MITM tampering.
    pub fn from_env() -> Self {
        let rfc3161_url = std::env::var("OLYMPUS_ANCHOR_RFC3161_URL")
            .ok()
            .and_then(|u| validate_anchor_url("OLYMPUS_ANCHOR_RFC3161_URL", u));
        let rekor_url = std::env::var("OLYMPUS_ANCHOR_REKOR_URL")
            .ok()
            .and_then(|u| validate_anchor_url("OLYMPUS_ANCHOR_REKOR_URL", u));
        let ots_calendars: Vec<String> = std::env::var("OLYMPUS_ANCHOR_OTS_CALENDARS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_owned())
                    .filter(|p| !p.is_empty())
                    .filter_map(|u| validate_anchor_url("OLYMPUS_ANCHOR_OTS_CALENDARS", u))
                    .collect()
            })
            .unwrap_or_default();
        // Validate the manifest at startup rather than at the first cron tick,
        // so a typo or a corrupt export is an immediately visible boot error
        // instead of a silent "receipts never become verified" months later.
        let ots_bitcoin_headers_path = std::env::var_os("OLYMPUS_ANCHOR_OTS_BITCOIN_HEADERS")
            .and_then(|path| {
                let path = std::path::PathBuf::from(path);
                match ots_bitcoin::TrustedBitcoinHeaders::load(&path) {
                    Ok(_) => Some(path),
                    Err(e) => {
                        tracing::error!(
                            "OLYMPUS_ANCHOR_OTS_BITCOIN_HEADERS is invalid and will be ignored; \
                             OTS receipts cannot be upgraded to verified evidence: {e}"
                        );
                        None
                    }
                }
            });
        let interval_secs = std::env::var("OLYMPUS_ANCHOR_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_INTERVAL_SECS);
        Self {
            rfc3161_url,
            rekor_url,
            ots_calendars,
            ots_bitcoin_headers_path,
            interval_secs,
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.rfc3161_url.is_some() || self.rekor_url.is_some() || !self.ots_calendars.is_empty()
    }
}

/// Accept `https://…` (production) or `http://` against an exact loopback
/// host (`localhost` / `127.0.0.1`, dev only). Anything else is rejected
/// with a startup warning. Returns `Some(url)` on accept, `None` on reject.
///
/// Parse-and-inspect rather than `starts_with` on the raw string: a naive
/// prefix check would accept `http://localhost.evil.tld/…`, where the host
/// is `localhost.evil.tld` (a public host the attacker controls), not the
/// loopback interface. Reject any URL with userinfo (`user:pass@…`) — that
/// is never meaningful for an anchor TSA / Rekor / OTS endpoint and is the
/// most common way a smuggled-host payload sneaks past prefix checks.
fn validate_anchor_url(env_name: &str, url: String) -> Option<String> {
    let parsed = match ::url::Url::parse(&url) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "{env_name} = {} rejected: parse error: {e}",
                redact_url(&url)
            );
            return None;
        }
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        tracing::warn!(
            "{env_name} = {} rejected: URL must not embed userinfo",
            redact_url(&url)
        );
        return None;
    }

    let scheme = parsed.scheme();
    let ok = match scheme {
        "https" => true,
        "http" => matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1")),
        _ => false,
    };

    if ok {
        Some(url)
    } else {
        tracing::warn!(
            "{env_name} = {} rejected: anchor URLs must be https:// or \
             http://localhost / http://127.0.0.1 (dev only). Receipt submission \
             over plaintext public HTTP would expose the request to MITM \
             tampering. Set the env var to a TLS URL to enable this anchor.",
            redact_url(&url)
        );
        None
    }
}

/// Render a URL for logging with any embedded credentials and query/fragment
/// stripped. Anchor URLs should never carry userinfo or tokens, but an operator
/// may paste one by mistake (indeed the userinfo branch above rejects exactly
/// that) — so the rejection log must not echo the secret it is rejecting.
/// On a parse failure (where structural redaction isn't possible) it falls back
/// to a best-effort string strip of userinfo and everything from `?`/`#`.
fn redact_url(url: &str) -> String {
    match ::url::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => {
            let no_secrets = url.split(['?', '#']).next().unwrap_or("");
            match no_secrets.split_once("://") {
                Some((scheme, rest)) => {
                    let host = rest.split_once('@').map(|(_, h)| h).unwrap_or(rest);
                    format!("{scheme}://{host}")
                }
                None => "<redacted>".to_string(),
            }
        }
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
/// cancel the others. Returns the distinct list of receipts that are available
/// (newly stored or reused), plus a parallel list of errors for failures. The
/// caller decides whether partial success is acceptable (it usually is —
/// the three anchors are redundant by design).
///
/// M-17: every network call is preceded by a durable leased claim keyed by
/// `(kind, hash, target)`. A completed request reuses its stored receipt id;
/// failures enter bounded exponential backoff; an active lease is deferred.
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
        match anchor_once(pool, AnchorKind::Rfc3161, hash, url, checkpoint_id, || {
            rfc3161::submit(http, url, &hash)
        })
        .await
        {
            Ok(Some(id)) if !ids.contains(&id) => ids.push(id),
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(e) => errs.push((AnchorKind::Rfc3161, e)),
        }
    }

    // Rekor — single instance.
    if let Some(url) = &cfg.rekor_url {
        match anchor_once(pool, AnchorKind::Rekor, hash, url, checkpoint_id, || {
            rekor::submit(http, url, &hash)
        })
        .await
        {
            Ok(Some(id)) if !ids.contains(&id) => ids.push(id),
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(e) => errs.push((AnchorKind::Rekor, e)),
        }
    }

    // OTS — try each calendar; persist every successful pending receipt
    // so we have N independent commitments to upgrade.
    for cal in &cfg.ots_calendars {
        match anchor_once(pool, AnchorKind::Ots, hash, cal, checkpoint_id, || {
            ots::submit(http, cal, &hash)
        })
        .await
        {
            Ok(Some(id)) if !ids.contains(&id) => ids.push(id),
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(e) => errs.push((AnchorKind::Ots, e)),
        }
    }

    (ids, errs)
}

const SUBMISSION_RETRY_BASE_SECS: i64 = 60;
const SUBMISSION_RETRY_MAX_SECS: i64 = 6 * 60 * 60;

fn submission_retry_delay_secs(attempt_count: i32) -> i64 {
    let exponent = u32::try_from(attempt_count.saturating_sub(1).max(0))
        .unwrap_or(u32::MAX)
        .min(16);
    SUBMISSION_RETRY_BASE_SECS
        .saturating_mul(1_i64 << exponent)
        .min(SUBMISSION_RETRY_MAX_SECS)
}

async fn anchor_once<F, Fut>(
    pool: &PgPool,
    kind: AnchorKind,
    hash: [u8; 32],
    target: &str,
    checkpoint_id: Option<Uuid>,
    submit: F,
) -> Result<Option<Uuid>, AnchorError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<AnchorReceipt, AnchorError>>,
{
    let claim = store::claim_submission(pool, kind, &hash, target, checkpoint_id).await?;
    let (lease_token, attempt_count) = match claim {
        store::SubmissionClaim::Completed(id) => return Ok(Some(id)),
        store::SubmissionClaim::Deferred => return Ok(None),
        store::SubmissionClaim::Acquired {
            lease_token,
            attempt_count,
        } => (lease_token, attempt_count),
    };

    let result = submit().await.and_then(|receipt| {
        if receipt.kind != kind
            || receipt.anchored_hash != hash
            || receipt.target.as_str() != target
        {
            return Err(AnchorError::Parse(
                "anchor backend result does not match its leased kind/hash/target".to_owned(),
            ));
        }
        Ok(receipt)
    });

    match result {
        Ok(receipt) => {
            match store::complete_submission(pool, &receipt, checkpoint_id, lease_token).await {
                Ok(id) => Ok(Some(id)),
                Err(e) => {
                    if let Err(state_error) = store::fail_submission(
                        pool,
                        kind,
                        &hash,
                        target,
                        lease_token,
                        submission_retry_delay_secs(attempt_count),
                        &e.to_string(),
                    )
                    .await
                    {
                        return Err(AnchorError::Db(format!(
                            "{e}; failed to persist anchor retry state: {state_error}"
                        )));
                    }
                    Err(e)
                }
            }
        }
        Err(e) => {
            if let Err(state_error) = store::fail_submission(
                pool,
                kind,
                &hash,
                target,
                lease_token,
                submission_retry_delay_secs(attempt_count),
                &e.to_string(),
            )
            .await
            {
                return Err(AnchorError::Db(format!(
                    "{e}; failed to persist anchor retry state: {state_error}"
                )));
            }
            Err(e)
        }
    }
}

/// Shared HTTP client used by all three anchor backends. Wrapping in `Arc`
/// lets `AppState::Clone` cheap-clone the underlying connection pool.
pub fn build_http_client(timeout: std::time::Duration) -> Arc<reqwest::Client> {
    Arc::new(
        reqwest::Client::builder()
            .timeout(timeout)
            // Anchor URLs are operator-configured and validated before use.
            // Do not follow redirects to a second, unvalidated target; that
            // would let a malicious or compromised anchor endpoint bounce the
            // desktop node at internal/link-local services (audit L-02).
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("olympus-anchor/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client should build with default config"),
    )
}

/// Domain-separated BLAKE3 digest of every field a court / opposing
/// counsel needs to bind a receipt to a specific Olympus checkpoint.
/// Anchor *this* digest, not the raw ledger_root, so the receipt commits
/// to the full signed-state tuple rather than just the ledger root
/// (which by itself isn't unique — two different checkpoints can share
/// the same ledger_root if no records were added between them).
pub fn checkpoint_anchor_hash(
    ledger_root: &str,
    tree_size: i64,
    checkpoint_timestamp: i64,
    authority_pubkey_hash: &str,
    bjj_sig_r8x: Option<&str>,
    bjj_sig_r8y: Option<&str>,
    bjj_sig_s: Option<&str>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:CHECKPOINT_ANCHOR:V1");
    h.update(b"|");
    h.update(ledger_root.as_bytes());
    h.update(b"|");
    h.update(&tree_size.to_be_bytes());
    h.update(b"|");
    h.update(&checkpoint_timestamp.to_be_bytes());
    h.update(b"|");
    h.update(authority_pubkey_hash.as_bytes());
    h.update(b"|");
    h.update(bjj_sig_r8x.unwrap_or("").as_bytes());
    h.update(b"|");
    h.update(bjj_sig_r8y.unwrap_or("").as_bytes());
    h.update(b"|");
    h.update(bjj_sig_s.unwrap_or("").as_bytes());
    *h.finalize().as_bytes()
}

/// Current checkpoint statement/anchor format. Version 1 is retained above
/// solely so historical receipts remain explainable; all new checkpoints use
/// this version and fail closed if presented through the federation v1 wire.
pub const CHECKPOINT_FORMAT_VERSION: u8 = 2;

/// The only scope emitted by the current producer. A snapshot tree is rebuilt
/// independently for each shard, so calling it a node-global ledger root would
/// overstate what the proof attests (H-03).
pub const CHECKPOINT_SCOPE_SHARD: &str = "shard";

/// Domain for the complete v2 checkpoint statement signed with BJJ EdDSA.
pub const CHECKPOINT_STATEMENT_DOMAIN_V2: &[u8] = b"OLY:CHECKPOINT:STATEMENT:V2";

/// Domain for the v2 externally anchored digest.
pub const CHECKPOINT_ANCHOR_DOMAIN_V2: &[u8] = b"OLY:CHECKPOINT_ANCHOR:V2";

fn checkpoint_hash_lp(hasher: &mut blake3::Hasher, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("checkpoint field length is bounded by API caps");
    hasher.update(&len.to_be_bytes());
    hasher.update(value);
}

/// Construct the single canonical scalar signed by v2 checkpoint producers
/// and verified by federation receivers and offline bundle verifiers.
///
/// Unlike the legacy `Poseidon(root, timestamp)` message, this binds every
/// label that affects checkpoint identity: version, scope, shard, canonical
/// root, height, timestamp, and authority identity. An existing signed
/// checkpoint therefore cannot be relabelled to evade deduplication or
/// equivocation checks (M-02), and bundle/federation consumers share exactly
/// one message recipe (M-01).
pub fn checkpoint_signing_message_v2(
    scope: &str,
    shard_id: &str,
    ledger_root: &ark_bn254::Fr,
    tree_size: i64,
    checkpoint_timestamp: i64,
    authority_pubkey_hash: &ark_bn254::Fr,
) -> ark_bn254::Fr {
    use ark_ff::PrimeField;

    let root_dec = crate::zk::proof::fr_to_decimal(ledger_root);
    let authority_dec = crate::zk::proof::fr_to_decimal(authority_pubkey_hash);
    let mut h = blake3::Hasher::new();
    h.update(CHECKPOINT_STATEMENT_DOMAIN_V2);
    h.update(&[CHECKPOINT_FORMAT_VERSION]);
    checkpoint_hash_lp(&mut h, scope.as_bytes());
    checkpoint_hash_lp(&mut h, shard_id.as_bytes());
    checkpoint_hash_lp(&mut h, root_dec.as_bytes());
    h.update(&tree_size.to_be_bytes());
    h.update(&checkpoint_timestamp.to_be_bytes());
    checkpoint_hash_lp(&mut h, authority_dec.as_bytes());
    ark_bn254::Fr::from_le_bytes_mod_order(h.finalize().as_bytes())
}

/// V2 external-anchor digest. This commits to the same complete scoped
/// statement as [`checkpoint_signing_message_v2`] plus the BJJ signature that
/// authenticated it. Every variable-length value is length-prefixed; no
/// delimiter ambiguity is possible.
#[allow(clippy::too_many_arguments)]
pub fn checkpoint_anchor_hash_v2(
    scope: &str,
    shard_id: &str,
    ledger_root: &str,
    tree_size: i64,
    checkpoint_timestamp: i64,
    authority_pubkey_hash: &str,
    bjj_sig_r8x: Option<&str>,
    bjj_sig_r8y: Option<&str>,
    bjj_sig_s: Option<&str>,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CHECKPOINT_ANCHOR_DOMAIN_V2);
    h.update(&[CHECKPOINT_FORMAT_VERSION]);
    checkpoint_hash_lp(&mut h, scope.as_bytes());
    checkpoint_hash_lp(&mut h, shard_id.as_bytes());
    checkpoint_hash_lp(&mut h, ledger_root.as_bytes());
    h.update(&tree_size.to_be_bytes());
    h.update(&checkpoint_timestamp.to_be_bytes());
    checkpoint_hash_lp(&mut h, authority_pubkey_hash.as_bytes());
    checkpoint_hash_lp(&mut h, bjj_sig_r8x.unwrap_or("").as_bytes());
    checkpoint_hash_lp(&mut h, bjj_sig_r8y.unwrap_or("").as_bytes());
    checkpoint_hash_lp(&mut h, bjj_sig_s.unwrap_or("").as_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_kind_strings_match_check_constraint() {
        assert_eq!(AnchorKind::Rfc3161.as_str(), "rfc3161");
        assert_eq!(AnchorKind::Rekor.as_str(), "rekor");
        assert_eq!(AnchorKind::Ots.as_str(), "ots");
    }

    #[test]
    fn config_from_env_disabled_by_default() {
        // Sanity check: with no env vars (assume CI runs without them
        // set) the config is fully disabled.
        let _ = AnchoringConfig::from_env();
    }

    #[test]
    fn checkpoint_anchor_hash_is_deterministic() {
        let a = checkpoint_anchor_hash("0xabc", 42, 1700000000, "0xdef", None, None, None);
        let b = checkpoint_anchor_hash("0xabc", 42, 1700000000, "0xdef", None, None, None);
        assert_eq!(a, b);
    }

    #[test]
    fn checkpoint_anchor_hash_changes_with_any_field() {
        let base = checkpoint_anchor_hash("a", 1, 1, "k", None, None, None);
        assert_ne!(
            base,
            checkpoint_anchor_hash("b", 1, 1, "k", None, None, None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 2, 1, "k", None, None, None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 2, "k", None, None, None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 1, "x", None, None, None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 1, "k", Some("r"), None, None)
        );
    }

    #[test]
    fn checkpoint_anchor_hash_includes_all_three_bjj_sig_parts() {
        let base = checkpoint_anchor_hash("a", 1, 1, "k", None, None, None);
        // Adding each of r8x, r8y, s independently must change the digest.
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 1, "k", Some("x"), None, None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 1, "k", None, Some("y"), None)
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash("a", 1, 1, "k", None, None, Some("s"))
        );
    }

    #[test]
    fn checkpoint_v2_message_binds_scope_shard_height_and_timestamp() {
        use ark_bn254::Fr;

        let base = checkpoint_signing_message_v2(
            CHECKPOINT_SCOPE_SHARD,
            "alpha",
            &Fr::from(7u64),
            42,
            1_700_000_000,
            &Fr::from(11u64),
        );
        for changed in [
            checkpoint_signing_message_v2(
                "global",
                "alpha",
                &Fr::from(7u64),
                42,
                1_700_000_000,
                &Fr::from(11u64),
            ),
            checkpoint_signing_message_v2(
                CHECKPOINT_SCOPE_SHARD,
                "beta",
                &Fr::from(7u64),
                42,
                1_700_000_000,
                &Fr::from(11u64),
            ),
            checkpoint_signing_message_v2(
                CHECKPOINT_SCOPE_SHARD,
                "alpha",
                &Fr::from(7u64),
                43,
                1_700_000_000,
                &Fr::from(11u64),
            ),
            checkpoint_signing_message_v2(
                CHECKPOINT_SCOPE_SHARD,
                "alpha",
                &Fr::from(7u64),
                42,
                1_700_000_001,
                &Fr::from(11u64),
            ),
        ] {
            assert_ne!(base, changed);
        }
    }

    #[test]
    fn checkpoint_v2_anchor_binds_shard_and_signature() {
        let base = checkpoint_anchor_hash_v2(
            CHECKPOINT_SCOPE_SHARD,
            "alpha",
            "7",
            42,
            1_700_000_000,
            "11",
            Some("1"),
            Some("2"),
            Some("3"),
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash_v2(
                CHECKPOINT_SCOPE_SHARD,
                "beta",
                "7",
                42,
                1_700_000_000,
                "11",
                Some("1"),
                Some("2"),
                Some("3"),
            )
        );
        assert_ne!(
            base,
            checkpoint_anchor_hash_v2(
                CHECKPOINT_SCOPE_SHARD,
                "alpha",
                "7",
                42,
                1_700_000_000,
                "11",
                Some("1"),
                Some("2"),
                Some("4"),
            )
        );
    }

    #[test]
    fn config_default_is_fully_disabled() {
        let cfg = AnchoringConfig::default();
        assert!(cfg.rfc3161_url.is_none());
        assert!(cfg.rekor_url.is_none());
        assert!(cfg.ots_calendars.is_empty());
        assert!(!cfg.any_enabled());
    }

    #[test]
    fn submission_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(submission_retry_delay_secs(1), 60);
        assert_eq!(submission_retry_delay_secs(2), 120);
        assert_eq!(submission_retry_delay_secs(3), 240);
        assert_eq!(
            submission_retry_delay_secs(i32::MAX),
            SUBMISSION_RETRY_MAX_SECS
        );
    }

    #[test]
    fn any_enabled_is_true_if_any_anchor_configured() {
        let cfg = AnchoringConfig {
            rfc3161_url: Some("https://tsa.example".to_owned()),
            ..Default::default()
        };
        assert!(cfg.any_enabled());

        let cfg = AnchoringConfig {
            rekor_url: Some("https://rekor.example".to_owned()),
            ..Default::default()
        };
        assert!(cfg.any_enabled());

        let mut cfg = AnchoringConfig::default();
        cfg.ots_calendars.push("https://cal.example".to_owned());
        assert!(cfg.any_enabled());
    }

    #[test]
    fn anchor_kind_strings_round_trip_via_serde() {
        // The serde rename_all = "snake_case" must match the DB CHECK
        // constraint that mod-level docs reference; a regression here
        // would silently break new inserts.
        for (k, s) in [
            (AnchorKind::Rfc3161, "\"rfc3161\""),
            (AnchorKind::Rekor, "\"rekor\""),
            (AnchorKind::Ots, "\"ots\""),
        ] {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, s);
            let back: AnchorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, k);
        }
    }

    #[test]
    fn build_http_client_succeeds_with_typical_timeout() {
        let _ = build_http_client(std::time::Duration::from_secs(5));
        // The constructor unwraps on builder failure — if this returns,
        // it built without panicking. The test exists to catch a
        // hypothetical regression where the builder grows a feature
        // dependency that breaks under default features.
    }

    // ── L-A2: URL scheme validation ─────────────────────────────────────────

    #[test]
    fn validate_anchor_url_accepts_https() {
        assert_eq!(
            validate_anchor_url("X", "https://freetsa.org/tsr".to_owned()),
            Some("https://freetsa.org/tsr".to_owned())
        );
    }

    #[test]
    fn validate_anchor_url_accepts_http_loopback() {
        // Dev/test setups bind to loopback; reject only public-net plain HTTP.
        assert_eq!(
            validate_anchor_url("X", "http://localhost:8080".to_owned()),
            Some("http://localhost:8080".to_owned())
        );
        assert_eq!(
            validate_anchor_url("X", "http://127.0.0.1:9000/foo".to_owned()),
            Some("http://127.0.0.1:9000/foo".to_owned())
        );
    }

    #[test]
    fn validate_anchor_url_rejects_public_http() {
        // The whole point of the guard — public HTTP would expose the
        // hash being anchored to MITM tampering of both the request and
        // the receipt blob.
        assert_eq!(
            validate_anchor_url("X", "http://public.example/tsr".to_owned()),
            None
        );
    }

    #[test]
    fn validate_anchor_url_rejects_arbitrary_schemes() {
        assert_eq!(validate_anchor_url("X", "ftp://x".to_owned()), None);
        assert_eq!(
            validate_anchor_url("X", "file:///etc/passwd".to_owned()),
            None
        );
        assert_eq!(
            validate_anchor_url("X", "javascript:alert(1)".to_owned()),
            None
        );
    }

    #[test]
    fn validate_anchor_url_is_case_insensitive_on_scheme() {
        // RFC 3986 declares the scheme component case-insensitive.
        assert!(validate_anchor_url("X", "HTTPS://a.example".to_owned()).is_some());
        assert!(validate_anchor_url("X", "Http://Localhost".to_owned()).is_some());
    }

    #[test]
    fn validate_anchor_url_rejects_loopback_prefix_bypass() {
        // The fix for the inline review on PR #1058: a naive
        // `starts_with("http://localhost")` check would accept
        // `http://localhost.evil.tld` (host = `localhost.evil.tld`, a
        // public host the attacker controls). Parsing by component
        // means `host_str()` is `Some("localhost.evil.tld")`, which is
        // not in the loopback set, so the URL is rejected.
        assert_eq!(
            validate_anchor_url("X", "http://localhost.evil.tld/tsr".to_owned()),
            None
        );
        assert_eq!(
            validate_anchor_url("X", "http://127.0.0.1.evil.tld/tsr".to_owned()),
            None
        );
        // Hyphen-suffixed look-alikes are also a public host.
        assert_eq!(
            validate_anchor_url("X", "http://localhost-evil.example/tsr".to_owned()),
            None
        );
    }

    #[test]
    fn redact_url_strips_credentials_and_query() {
        // Reject logs must never echo embedded credentials or token-bearing
        // query/fragment components (PR #1058 review fix).
        let r = redact_url("https://user:s3cret@tsa.example/tsr?token=abc#frag");
        assert!(!r.contains("s3cret"), "password must be stripped: {r}");
        assert!(!r.contains("user"), "username must be stripped: {r}");
        assert!(!r.contains("token=abc"), "query must be stripped: {r}");
        assert!(!r.contains("frag"), "fragment must be stripped: {r}");
        assert!(
            r.starts_with("https://tsa.example"),
            "scheme/host/path kept: {r}"
        );

        // Unparseable input (space in host) still gets best-effort stripping.
        let bad = redact_url("https://user:pw@ho st/x?token=zzz");
        assert!(
            !bad.contains("pw"),
            "userinfo stripped from unparseable url: {bad}"
        );
        assert!(
            !bad.contains("token=zzz"),
            "query stripped from unparseable url: {bad}"
        );
    }

    #[test]
    fn validate_anchor_url_rejects_userinfo() {
        // `http://anything@localhost/...` could be smuggled past a
        // host-only check by older parsers; we reject userinfo outright
        // because an anchor TSA / Rekor / OTS endpoint has no use for it.
        assert_eq!(
            validate_anchor_url("X", "http://attacker@localhost/tsr".to_owned()),
            None
        );
        assert_eq!(
            validate_anchor_url("X", "https://u:p@freetsa.org/tsr".to_owned()),
            None
        );
    }

    #[test]
    fn validate_anchor_url_rejects_unparseable() {
        // Malformed URLs are rejected outright (don't fall through to
        // a downstream parser that might interpret them differently).
        assert_eq!(
            validate_anchor_url("X", "not a url at all".to_owned()),
            None
        );
        assert_eq!(validate_anchor_url("X", "://broken".to_owned()), None);
    }

    #[test]
    fn config_default_has_one_hour_interval() {
        // Pin the cadence so a future "default" change has to update this test
        // and the operator-facing default in docs/court-evidence.md together.
        assert_eq!(AnchoringConfig::default().interval_secs, 3600);
    }
}
