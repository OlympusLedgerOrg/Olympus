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
    let (signature, pubkey_pem) = anchor_sign_ed25519(hash)?;
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

    let metadata = serde_json::json!({
        "uuid":            uuid,
        "log_id":          entry.log_id,
        "log_index":       entry.log_index,
        "integrated_time": entry.integrated_time,
        "verification":    entry.verification,
        "hash_algorithm":  "sha256",
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

/// Ed25519-sign the (already SHA-256-hashed) anchor payload using whatever
/// key the operator has configured. v0.9 reads `OLYMPUS_ANCHOR_SIGN_KEY`
/// (32-byte hex) and derives the PEM-encoded public key inline.
///
/// In production this should pull from the AppState; threading state into
/// the anchoring stack is a tomorrow problem.
fn anchor_sign_ed25519(hash: &[u8; 32]) -> Result<([u8; 64], String), AnchorError> {
    use ed25519_dalek::{Signer, SigningKey};

    let hex_key = std::env::var("OLYMPUS_ANCHOR_SIGN_KEY")
        .or_else(|_| std::env::var("OLYMPUS_INGEST_SIGNING_KEY"))
        .map_err(|_| {
            AnchorError::NotConfigured(
                "OLYMPUS_ANCHOR_SIGN_KEY (or OLYMPUS_INGEST_SIGNING_KEY) must be set \
                 to use the Rekor anchor",
            )
        })?;
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
}
