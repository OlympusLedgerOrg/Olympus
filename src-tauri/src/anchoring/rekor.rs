//! Sigstore Rekor transparency-log client.
//!
//! Submits a `hashedrekord/v0.0.1` entry to a Rekor instance. The entry's
//! payload is just the SHA-256 hash we want to anchor; the signature field
//! is over that hash, signed with the node's federation Ed25519 authority
//! key (the same key that signs shard headers). Receiving a UUID + log
//! index from Rekor is proof that the hash entered the log at the
//! returned `integratedTime`, which the log then includes in its periodic
//! signed tree heads.
//!
//! Why hashedrekord and not a richer Rekor schema: hashedrekord is the
//! smallest possible entry shape — hash + signature + signer pubkey — and
//! every Rekor instance supports it. The richer shapes (intoto, rfc3161,
//! cose) require the artifact itself to be expressible in their schema,
//! which adds nothing for us beyond hash + signature.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

use super::{AnchorError, AnchorKind, AnchorReceipt};

/// POST /api/v1/log/entries — Rekor's append endpoint.
const ENTRIES_PATH: &str = "/api/v1/log/entries";

/// Env var name for the operator-supplied Rekor log public key (PEM).
/// Audit M-A2: when set, `submit` verifies the `signedEntryTimestamp`
/// against this key before accepting the receipt. When unset, the
/// receipt is still stored (current behaviour) but the metadata flag
/// `set_verified` is `false` so downstream consumers and the
/// court-evidence packet can see the difference.
pub const REKOR_PUBKEY_ENV: &str = "OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM";

/// Construct the hashedrekord v0.0.1 entry body. We sign the SHA-256 hash
/// with an Ed25519 key (provided by the caller) and ship the public key
/// PEM-encoded as Rekor expects.
fn build_hashedrekord_body(
    sha256_hash: &[u8; 32],
    signature: &[u8; 64],
    ed25519_pubkey_pem: &str,
) -> serde_json::Value {
    let hash_hex = hex::encode(sha256_hash);
    let sig_b64 = B64.encode(signature);
    let pubkey_b64 = B64.encode(ed25519_pubkey_pem);

    serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": hash_hex
                }
            },
            "signature": {
                "content": sig_b64,
                "publicKey": {
                    "content": pubkey_b64
                }
            }
        }
    })
}

/// Rekor's typical response envelope. The single top-level key is the
/// entry UUID; we destructure into a uniform shape below.
#[derive(Debug, Deserialize)]
struct EntryEnvelope {
    #[serde(rename = "logID")]
    log_id: Option<String>,
    #[serde(rename = "logIndex")]
    log_index: Option<i64>,
    #[serde(rename = "integratedTime")]
    integrated_time: Option<i64>,
    #[serde(rename = "verification")]
    verification: Option<serde_json::Value>,
    /// Echoed back so we can re-fetch by UUID later.
    #[serde(default)]
    body: Option<String>,
}

/// Submit a SHA-256 hash to a Rekor instance.
///
/// **Requires a node-level Ed25519 signing key.** v0.9 wires this through
/// `AppState::bjj_authority_key` / federation signing, but the signature
/// itself is Ed25519 on the same key path Sigstore expects.
///
/// For the moment this submission path is a no-op when no Ed25519 signing
/// key is configured for federation; the operator must opt in by setting
/// `OLYMPUS_INGEST_SIGNING_KEY` (or a dedicated `OLYMPUS_ANCHOR_SIGN_KEY`).
pub async fn submit(
    http: &reqwest::Client,
    rekor_url: &str,
    hash: &[u8; 32],
) -> Result<AnchorReceipt, AnchorError> {
    let signing_key_hex = resolve_signing_key()?;
    submit_with_signing_key(http, rekor_url, hash, &signing_key_hex).await
}

/// Resolve the Ed25519 signing key for Rekor entries. Prefers the
/// dedicated `OLYMPUS_ANCHOR_SIGN_KEY`; falls back to
/// `OLYMPUS_INGEST_SIGNING_KEY`.
///
/// Audit L-A1: the fallback used to be silent — operators wanting
/// anchor-signing isolated from ingest-signing wouldn't notice the keys
/// were conflated. The choice is now logged exactly once per process
/// (via `Once`) so a `journalctl | grep anchor` reveals which key Rekor
/// receipts are signed with.
fn resolve_signing_key() -> Result<String, AnchorError> {
    use std::sync::Once;
    static LOG_ONCE: Once = Once::new();
    match std::env::var("OLYMPUS_ANCHOR_SIGN_KEY") {
        Ok(k) => {
            LOG_ONCE.call_once(|| {
                tracing::info!(
                    "rekor: signing receipts with OLYMPUS_ANCHOR_SIGN_KEY (dedicated)"
                );
            });
            Ok(k)
        }
        Err(_) => match std::env::var("OLYMPUS_INGEST_SIGNING_KEY") {
            Ok(k) => {
                LOG_ONCE.call_once(|| {
                    tracing::warn!(
                        "rekor: OLYMPUS_ANCHOR_SIGN_KEY unset; falling back to \
                         OLYMPUS_INGEST_SIGNING_KEY for receipt signing. To isolate \
                         anchor identity from ingest identity, set \
                         OLYMPUS_ANCHOR_SIGN_KEY to a separate 32-byte hex Ed25519 key."
                    );
                });
                Ok(k)
            }
            Err(_) => Err(AnchorError::NotConfigured(
                "OLYMPUS_ANCHOR_SIGN_KEY (or OLYMPUS_INGEST_SIGNING_KEY) must be set \
                 to use the Rekor anchor",
            )),
        },
    }
}

/// Submit using a caller-supplied 32-byte Ed25519 signing key (hex-encoded).
/// Separated from [`submit`] so tests can avoid mutating process env vars.
pub async fn submit_with_signing_key(
    http: &reqwest::Client,
    rekor_url: &str,
    hash: &[u8; 32],
    signing_key_hex: &str,
) -> Result<AnchorReceipt, AnchorError> {
    let (signature, pubkey_pem) = sign_ed25519_with(signing_key_hex, hash)?;
    let body = build_hashedrekord_body(hash, &signature, &pubkey_pem);

    let url = format!("{}{}", rekor_url.trim_end_matches('/'), ENTRIES_PATH);
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
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

    // Rekor returns { "<uuid>": { logID, logIndex, integratedTime, ... } }.
    // We want both the UUID and the metadata fields broken out.
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| AnchorError::Parse(format!("Rekor response: {e}")))?;
    let obj = envelope
        .as_object()
        .ok_or_else(|| AnchorError::Parse("Rekor response not an object".into()))?;
    let (uuid, entry_val) = obj
        .iter()
        .next()
        .ok_or_else(|| AnchorError::Parse("Rekor response is empty".into()))?;
    let entry: EntryEnvelope = serde_json::from_value(entry_val.clone())
        .map_err(|e| AnchorError::Parse(format!("Rekor entry envelope: {e}")))?;

    // Audit M-A2: verify the signedEntryTimestamp if a Rekor public
    // key is configured. Without verification a compromised or MITM'd
    // Rekor response could be accepted as proof; with it, the receipt
    // is only stored after the log's signature checks out.
    //
    // Three outcomes:
    //   - pubkey not configured: receipt stored, `set_verified=false`.
    //     Operator gets a startup warning (logged once via the same
    //     pattern as the L-A1 signing-key fallback).
    //   - pubkey configured + signature valid: stored, `set_verified=true`.
    //   - pubkey configured + signature invalid: NOT stored, hard error.
    //     Treating a Rekor signature failure as fatal is the whole point
    //     of M-A2 — if we accepted the receipt anyway we'd be back to
    //     the unverified-stored-receipt status quo.
    let set_verified = match std::env::var(REKOR_PUBKEY_ENV) {
        Ok(pem) if !pem.trim().is_empty() => {
            log_set_verification_once(true);
            verify_set(&entry, &pem)?;
            true
        }
        _ => {
            log_set_verification_once(false);
            false
        }
    };

    let metadata = serde_json::json!({
        "uuid":            uuid,
        "log_id":          entry.log_id,
        "log_index":       entry.log_index,
        "integrated_time": entry.integrated_time,
        "verification":    entry.verification,
        "hash_algorithm":  "sha256",
        "set_verified":    set_verified,
    });

    Ok(AnchorReceipt {
        kind: AnchorKind::Rekor,
        anchored_hash: *hash,
        // Persist the raw response bytes so we have the full
        // verification envelope (signed entry timestamp included)
        // available for offline checking by opposing counsel.
        receipt_blob: bytes,
        target: rekor_url.to_owned(),
        metadata,
    })
}

/// Verify Rekor's `signedEntryTimestamp` against the configured log
/// public key (audit M-A2).
///
/// The SET is an ECDSA-P-256 signature (DER-encoded, base64-wrapped)
/// over the SHA-256 of the canonical JSON form of the four
/// "what entered the log" fields. Per
/// <https://github.com/sigstore/rekor/blob/main/openapi.yaml>:
///
/// ```text
/// canonical = { "body": <body>, "integratedTime": <int>,
///               "logID": <hex>, "logIndex": <int> }
/// ```
///
/// — keys alphabetically sorted, no whitespace, UTF-8. We pin the
/// canonical encoding to `olympus_crypto::canonical::canonicalize_bytes`
/// (RFC 8785 JCS) so any drift in field ordering between us and Rekor
/// surfaces here rather than as a silent verification skip.
fn verify_set(entry: &EntryEnvelope, pubkey_pem: &str) -> Result<(), AnchorError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let verification = entry
        .verification
        .as_ref()
        .ok_or_else(|| AnchorError::Parse("Rekor response missing verification block".into()))?;
    let set_b64 = verification
        .get("signedEntryTimestamp")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AnchorError::Parse("Rekor response missing verification.signedEntryTimestamp".into())
        })?;
    let body = entry
        .body
        .as_deref()
        .ok_or_else(|| AnchorError::Parse("Rekor response missing body field".into()))?;
    let log_id = entry
        .log_id
        .as_deref()
        .ok_or_else(|| AnchorError::Parse("Rekor response missing logID field".into()))?;
    let log_index = entry
        .log_index
        .ok_or_else(|| AnchorError::Parse("Rekor response missing logIndex field".into()))?;
    let integrated_time = entry.integrated_time.ok_or_else(|| {
        AnchorError::Parse("Rekor response missing integratedTime field".into())
    })?;

    // Build the canonical signed body. JCS sorts keys alphabetically:
    // body < integratedTime < logID < logIndex.
    let canonical_input = serde_json::json!({
        "body": body,
        "integratedTime": integrated_time,
        "logID": log_id,
        "logIndex": log_index,
    });
    let raw = serde_json::to_vec(&canonical_input)
        .map_err(|e| AnchorError::Parse(format!("canonical input serialize: {e}")))?;
    let canonical = olympus_crypto::canonical::canonicalize_bytes(&raw)
        .map_err(|e| AnchorError::Parse(format!("SET canonicalize: {e}")))?;

    let sig_bytes = B64
        .decode(set_b64)
        .map_err(|e| AnchorError::Parse(format!("SET base64: {e}")))?;
    let signature = Signature::from_der(&sig_bytes)
        .map_err(|e| AnchorError::Parse(format!("SET signature parse: {e}")))?;

    let verifying_key = VerifyingKey::from_public_key_pem(pubkey_pem.trim())
        .map_err(|e| AnchorError::Parse(format!("Rekor pubkey parse: {e}")))?;

    verifying_key
        .verify(&canonical, &signature)
        .map_err(|e| {
            AnchorError::Parse(format!(
                "Rekor signedEntryTimestamp verification FAILED ({e}); refusing to accept \
                 receipt. Either the Rekor instance was tampered with, the response was \
                 spliced in transit, or the configured public key (env {REKOR_PUBKEY_ENV}) \
                 does not match the Rekor instance at {}",
                "OLYMPUS_ANCHOR_REKOR_URL"
            ))
        })?;
    Ok(())
}

/// Log the chosen SET-verification path exactly once per process so the
/// operator's `journalctl` shows whether their court-evidence claim is
/// being enforced. Mirrors the `Once` pattern used for the L-A1 signing
/// key fallback.
fn log_set_verification_once(enabled: bool) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if enabled {
            tracing::info!(
                "rekor: signedEntryTimestamp verification ENABLED via {REKOR_PUBKEY_ENV}"
            );
        } else {
            tracing::warn!(
                "rekor: {REKOR_PUBKEY_ENV} not set — signedEntryTimestamp will not be verified. \
                 Receipts will still be stored but a compromised/MITM'd Rekor response would \
                 be accepted. Set {REKOR_PUBKEY_ENV} to the PEM of your Rekor instance's log \
                 public key to enforce verification (audit M-A2)."
            );
        }
    });
}

/// Ed25519-sign the (already SHA-256-hashed) anchor payload using a
/// caller-supplied 32-byte hex key. Decoupled from env-var lookup so tests
/// don't need to mutate global state.
fn sign_ed25519_with(
    hex_key: &str,
    hash: &[u8; 32],
) -> Result<([u8; 64], String), AnchorError> {
    use ed25519_dalek::{Signer, SigningKey};

    let mut secret_bytes = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut secret_bytes)
        .map_err(|e| AnchorError::Parse(format!("anchor signing key hex: {e}")))?;
    let sk = SigningKey::from_bytes(&secret_bytes);
    let sig = sk.sign(hash);

    // PEM-encode the public key as Rekor expects: PKCS#8 SubjectPublicKeyInfo
    // wrapping. For Ed25519 the encoding is fixed:
    //   30 2a — SEQUENCE (42 bytes)
    //     30 05 — SEQUENCE (5 bytes)
    //       06 03 2b 65 70 — OID 1.3.101.112 (id-Ed25519)
    //     03 21 00 <32 bytes>  — BIT STRING (33 bytes, 1 unused-bits byte)
    let pk = sk.verifying_key();
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    spki.extend_from_slice(pk.as_bytes());
    let pem = pem_encode("PUBLIC KEY", &spki);

    Ok((sig.to_bytes(), pem))
}

/// Minimal PEM encoder: header + base64 body wrapped at 64 chars + footer.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let mut out = String::with_capacity(der.len() * 2 + label.len() * 2 + 32);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let b64 = B64.encode(der);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_encode_wraps_at_64() {
        let data = vec![0xabu8; 100];
        let pem = pem_encode("TEST", &data);
        for line in pem.lines() {
            if line.starts_with('-') {
                continue;
            }
            assert!(line.len() <= 64, "line too long: {line:?}");
        }
        assert!(pem.starts_with("-----BEGIN TEST-----"));
        assert!(pem.trim_end().ends_with("-----END TEST-----"));
    }

    #[test]
    fn build_body_emits_required_fields() {
        let body = build_hashedrekord_body(&[0u8; 32], &[0u8; 64], "PEM");
        assert_eq!(body["apiVersion"], "0.0.1");
        assert_eq!(body["kind"], "hashedrekord");
        assert_eq!(body["spec"]["data"]["hash"]["algorithm"], "sha256");
        assert!(body["spec"]["signature"]["content"].is_string());
        assert!(body["spec"]["signature"]["publicKey"]["content"].is_string());
    }

    #[test]
    fn build_body_embeds_hex_of_hash() {
        let hash = [0xabu8; 32];
        let body = build_hashedrekord_body(&hash, &[0u8; 64], "PEM");
        assert_eq!(
            body["spec"]["data"]["hash"]["value"],
            "abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn sign_ed25519_with_rejects_non_hex_key() {
        let r = sign_ed25519_with("not-hex", &[0u8; 32]);
        assert!(matches!(r, Err(AnchorError::Parse(_))));
    }

    #[test]
    fn sign_ed25519_with_rejects_short_hex_key() {
        // Less than 32 bytes of hex (= 64 chars) must fail decode.
        let r = sign_ed25519_with("deadbeef", &[0u8; 32]);
        assert!(matches!(r, Err(AnchorError::Parse(_))));
    }

    #[test]
    fn sign_ed25519_with_valid_key_produces_64_byte_sig_and_pem() {
        // 32 bytes of 0x01 — any 32-byte hex is a valid Ed25519 seed.
        let hex_key = "01".repeat(32);
        let (sig, pem) = sign_ed25519_with(&hex_key, &[0u8; 32]).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        // PEM body contains base64-encoded SPKI; 44 bytes of DER → ~60 chars.
        assert!(pem.len() > 100);
    }

    #[test]
    fn sign_ed25519_with_is_deterministic_for_same_seed_and_hash() {
        let hex_key = "02".repeat(32);
        let (a_sig, a_pem) = sign_ed25519_with(&hex_key, &[7u8; 32]).unwrap();
        let (b_sig, b_pem) = sign_ed25519_with(&hex_key, &[7u8; 32]).unwrap();
        assert_eq!(a_sig, b_sig);
        assert_eq!(a_pem, b_pem);
    }
}

#[cfg(test)]
mod set_verification_tests {
    //! Audit M-A2: verify the signedEntryTimestamp verification path
    //! end-to-end with a self-generated P-256 keypair. These tests are
    //! the safety net for any future refactor of the canonical payload
    //! shape or signature parsing.
    use super::*;
    use p256::ecdsa::{
        signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey,
    };
    use p256::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;

    /// Build a Rekor-shaped EntryEnvelope + a SET signature over the
    /// canonical (body, integratedTime, logID, logIndex) JSON, signed
    /// with the supplied key. Returns the envelope, the corresponding
    /// PEM of the verifying key, and a copy of the canonical bytes
    /// for cross-checks.
    fn signed_envelope(sk: &SigningKey) -> (EntryEnvelope, String) {
        let body = "ZXhhbXBsZQ=="; // base64('example')
        let log_id = "deadbeef";
        let log_index = 42;
        let integrated_time = 1_700_000_000;

        let canonical_input = serde_json::json!({
            "body": body,
            "integratedTime": integrated_time,
            "logID": log_id,
            "logIndex": log_index,
        });
        let raw = serde_json::to_vec(&canonical_input).unwrap();
        let canonical = olympus_crypto::canonical::canonicalize_bytes(&raw).unwrap();

        let sig: Signature = sk.sign(&canonical);
        let set_b64 = B64.encode(sig.to_der().as_bytes());

        let vk: VerifyingKey = *sk.verifying_key();
        let pem = vk.to_public_key_pem(spki::der::pem::LineEnding::LF).unwrap();

        let envelope = EntryEnvelope {
            log_id: Some(log_id.to_owned()),
            log_index: Some(log_index),
            integrated_time: Some(integrated_time),
            verification: Some(serde_json::json!({ "signedEntryTimestamp": set_b64 })),
            body: Some(body.to_owned()),
        };
        (envelope, pem)
    }

    #[test]
    fn verify_set_accepts_valid_signature() {
        let sk = SigningKey::random(&mut OsRng);
        let (envelope, pem) = signed_envelope(&sk);
        assert!(verify_set(&envelope, &pem).is_ok());
    }

    #[test]
    fn verify_set_rejects_signature_under_wrong_key() {
        // Forge a SET with one key, present another's PEM. Must reject.
        let signing = SigningKey::random(&mut OsRng);
        let (envelope, _) = signed_envelope(&signing);
        let attacker_vk = *SigningKey::random(&mut OsRng).verifying_key();
        let attacker_pem = attacker_vk
            .to_public_key_pem(spki::der::pem::LineEnding::LF)
            .unwrap();
        let err = verify_set(&envelope, &attacker_pem).expect_err("must reject");
        assert!(
            matches!(err, AnchorError::Parse(ref msg) if msg.contains("verification FAILED")),
            "got: {err:?}"
        );
    }

    #[test]
    fn verify_set_rejects_tampered_integrated_time() {
        // Sign canonical(t=A), then change integrated_time to B before
        // verification. Must reject because the canonical payload changes.
        let sk = SigningKey::random(&mut OsRng);
        let (mut envelope, pem) = signed_envelope(&sk);
        envelope.integrated_time = Some(9_999_999_999);
        assert!(matches!(
            verify_set(&envelope, &pem),
            Err(AnchorError::Parse(_))
        ));
    }

    #[test]
    fn verify_set_rejects_missing_signature_field() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut envelope, pem) = signed_envelope(&sk);
        envelope.verification = Some(serde_json::json!({}));
        let err = verify_set(&envelope, &pem).expect_err("must reject");
        assert!(matches!(err, AnchorError::Parse(ref msg) if msg.contains("signedEntryTimestamp")));
    }

    #[test]
    fn verify_set_rejects_missing_body_field() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut envelope, pem) = signed_envelope(&sk);
        envelope.body = None;
        let err = verify_set(&envelope, &pem).expect_err("must reject");
        assert!(matches!(err, AnchorError::Parse(ref msg) if msg.contains("body")));
    }

    #[test]
    fn verify_set_rejects_malformed_pem() {
        let sk = SigningKey::random(&mut OsRng);
        let (envelope, _) = signed_envelope(&sk);
        let err = verify_set(&envelope, "not a PEM").expect_err("must reject");
        assert!(matches!(err, AnchorError::Parse(ref msg) if msg.contains("pubkey")));
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn test_signing_key() -> String {
        // Deterministic 32-byte hex key — valid Ed25519 seed.
        "01".repeat(32)
    }

    fn fake_rekor_response_with_uuid(uuid: &str) -> serde_json::Value {
        serde_json::json!({
            uuid: {
                "logID": "deadbeef",
                "logIndex": 42,
                "integratedTime": 1_700_000_000,
                "verification": { "signedEntryTimestamp": "AAAA" }
            }
        })
    }

    #[tokio::test]
    async fn submit_with_signing_key_succeeds_and_returns_receipt_with_uuid() {
        let server = MockServer::start().await;
        let uuid = "abcd1234567890";
        let response = fake_rekor_response_with_uuid(uuid);
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&response))
            .mount(&server)
            .await;

        let rcpt = submit_with_signing_key(&http(), &server.uri(), &[0xa5u8; 32], &test_signing_key())
            .await
            .unwrap();
        assert_eq!(rcpt.kind, AnchorKind::Rekor);
        assert_eq!(rcpt.anchored_hash, [0xa5u8; 32]);
        assert_eq!(rcpt.target, server.uri());
        assert_eq!(rcpt.metadata["uuid"], uuid);
        assert_eq!(rcpt.metadata["log_index"], 42);
        assert_eq!(rcpt.metadata["integrated_time"], 1_700_000_000);
        assert_eq!(rcpt.metadata["hash_algorithm"], "sha256");
    }

    #[tokio::test]
    async fn submit_with_signing_key_trims_trailing_slash() {
        let server = MockServer::start().await;
        let response = fake_rekor_response_with_uuid("xyz");
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&response))
            .mount(&server)
            .await;
        let url = format!("{}/", server.uri());
        assert!(
            submit_with_signing_key(&http(), &url, &[0u8; 32], &test_signing_key())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn submit_returns_server_error_on_rekor_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("rekor down"))
            .mount(&server)
            .await;
        let err = submit_with_signing_key(&http(), &server.uri(), &[0u8; 32], &test_signing_key())
            .await
            .unwrap_err();
        match err {
            AnchorError::Server { status, detail } => {
                assert_eq!(status, 500);
                assert!(detail.contains("rekor down"));
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_rejects_non_object_json_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_string("[1,2,3]"))
            .mount(&server)
            .await;
        let err = submit_with_signing_key(&http(), &server.uri(), &[0u8; 32], &test_signing_key())
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }

    #[tokio::test]
    async fn submit_rejects_empty_object_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_string("{}"))
            .mount(&server)
            .await;
        let err = submit_with_signing_key(&http(), &server.uri(), &[0u8; 32], &test_signing_key())
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }

    #[tokio::test]
    async fn submit_rejects_malformed_inner_entry() {
        let server = MockServer::start().await;
        // Inner value is a string, not an object → can't deserialize as
        // EntryEnvelope.
        let response = serde_json::json!({"uuid-123": "not-an-object"});
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&response))
            .mount(&server)
            .await;
        let err = submit_with_signing_key(&http(), &server.uri(), &[0u8; 32], &test_signing_key())
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }

    #[tokio::test]
    async fn submit_with_invalid_signing_key_returns_parse_error() {
        // No HTTP call is made — sign_ed25519_with fails first.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let err = submit_with_signing_key(&http(), &server.uri(), &[0u8; 32], "not-hex")
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }
}
