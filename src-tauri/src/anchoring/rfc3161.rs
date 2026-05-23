//! RFC 3161 Time-Stamp Protocol client.
//!
//! Submits a SHA-256 hash to a TSA over HTTP and stores the resulting
//! `TimeStampToken` (a CMS SignedData blob) verbatim. Verification of the
//! token — checking the TSA's certificate chain, validating the
//! `tstInfo.messageImprint`, etc. — is intentionally deferred: at v0.9 we
//! capture the receipt, document its format, and rely on third-party tools
//! (OpenSSL `openssl ts -verify`, freetsa's own verifier) for full
//! cryptographic validation in the expert-witness packet.
//!
//! The TimeStampReq DER is small and stable enough to hand-roll without
//! a full ASN.1 crate; we encode exactly the shape RFC 3161 §2.4.1 requires.
//!
//! ```text
//! TimeStampReq ::= SEQUENCE {
//!     version            INTEGER  { v1(1) },
//!     messageImprint     MessageImprint,
//!     reqPolicy          OBJECT IDENTIFIER  OPTIONAL,
//!     nonce              INTEGER            OPTIONAL,
//!     certReq            BOOLEAN            DEFAULT FALSE,
//!     extensions     [0] IMPLICIT Extensions OPTIONAL
//! }
//! MessageImprint ::= SEQUENCE {
//!     hashAlgorithm      AlgorithmIdentifier,
//!     hashedMessage      OCTET STRING
//! }
//! ```

use super::{AnchorError, AnchorKind, AnchorReceipt};

// SHA-256 OID 2.16.840.1.101.3.4.2.1 in DER form: tag 06, len 09, 9 bytes.
// 60 86 48 01 65 03 04 02 01
const SHA256_OID_DER: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// Encode a DER `LENGTH` field for `n` bytes (short form for n < 128, long
/// form with explicit length-of-length otherwise). Matches X.690 §8.1.3.
fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.push(0x81);
        out.push(n as u8);
    } else if n < 0x10000 {
        out.push(0x82);
        out.push((n >> 8) as u8);
        out.push((n & 0xff) as u8);
    } else {
        // 32-bit length is overkill for a TSP request (max practical
        // size is a few hundred bytes), but cover it for completeness.
        out.push(0x84);
        out.push((n >> 24) as u8);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push((n & 0xff) as u8);
    }
}

/// Wrap `inner` in a DER TLV with the given primitive/constructed tag.
fn der_tlv(tag: u8, inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + inner.len());
    out.push(tag);
    der_len(inner.len(), &mut out);
    out.extend_from_slice(inner);
    out
}

/// Build a `TimeStampReq` DER for a fixed SHA-256 message imprint, requesting
/// the TSA certificate be included in the response (`certReq = TRUE`) and
/// adding a 64-bit random nonce so responses cannot be replayed.
fn build_request_der(sha256_hash: &[u8; 32], nonce: u64) -> Vec<u8> {
    // hashAlgorithm SEQUENCE { OID }
    let hash_alg = der_tlv(0x30, SHA256_OID_DER);

    // hashedMessage OCTET STRING
    let mut hashed_msg = Vec::with_capacity(2 + 32);
    hashed_msg.push(0x04);
    der_len(32, &mut hashed_msg);
    hashed_msg.extend_from_slice(sha256_hash);

    // MessageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let mut imprint_inner = Vec::with_capacity(hash_alg.len() + hashed_msg.len());
    imprint_inner.extend_from_slice(&hash_alg);
    imprint_inner.extend_from_slice(&hashed_msg);
    let imprint = der_tlv(0x30, &imprint_inner);

    // version INTEGER 1
    let version = vec![0x02, 0x01, 0x01];

    // nonce INTEGER. DER signed-integer encoding: prepend 0x00 if MSB set.
    let nonce_be = nonce.to_be_bytes();
    let mut nonce_bytes: Vec<u8> = nonce_be.iter().copied().skip_while(|b| *b == 0).collect();
    if nonce_bytes.is_empty() {
        nonce_bytes.push(0);
    }
    if nonce_bytes[0] & 0x80 != 0 {
        nonce_bytes.insert(0, 0);
    }
    let nonce_int = der_tlv(0x02, &nonce_bytes);

    // certReq BOOLEAN TRUE — request the TSA's certificate inline so the
    // receipt is verifiable without a separate cert fetch.
    let cert_req = vec![0x01, 0x01, 0xff];

    // SEQUENCE { version, messageImprint, nonce, certReq }
    let mut req_inner = Vec::new();
    req_inner.extend_from_slice(&version);
    req_inner.extend_from_slice(&imprint);
    req_inner.extend_from_slice(&nonce_int);
    req_inner.extend_from_slice(&cert_req);
    der_tlv(0x30, &req_inner)
}

/// Submit a SHA-256 hash to a RFC 3161 TSA. Returns the raw response bytes
/// (the `TimeStampResp` DER, which contains the signed `TimeStampToken`)
/// wrapped in an `AnchorReceipt`.
pub async fn submit(
    http: &reqwest::Client,
    tsa_url: &str,
    hash: &[u8; 32],
) -> Result<AnchorReceipt, AnchorError> {
    // Nonce: random 63 bits (keep the top bit clear to avoid sign-encoding
    // surprises across TSAs that misparse signed integers).
    let nonce = {
        use rand::RngCore;
        let mut buf = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut buf);
        u64::from_be_bytes(buf) & 0x7fff_ffff_ffff_ffff
    };
    let req_der = build_request_der(hash, nonce);

    let resp = http
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .body(req_der)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        return Err(AnchorError::Server {
            status: status.as_u16(),
            detail: detail.chars().take(512).collect(),
        });
    }

    let body = resp.bytes().await?.to_vec();
    if body.len() < 8 {
        return Err(AnchorError::Parse(format!(
            "TSA reply too short ({} bytes); expected DER TimeStampResp",
            body.len()
        )));
    }
    // Minimal sanity check: TimeStampResp starts with a SEQUENCE tag 0x30.
    if body[0] != 0x30 {
        return Err(AnchorError::Parse(
            "TSA reply does not start with DER SEQUENCE tag".into(),
        ));
    }

    Ok(AnchorReceipt {
        kind: AnchorKind::Rfc3161,
        anchored_hash: *hash,
        receipt_blob: body,
        target: tsa_url.to_owned(),
        metadata: serde_json::json!({
            "request_nonce": format!("{nonce:016x}"),
            "hash_algorithm": "sha256",
            "cert_req": true,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_len_short_form() {
        let mut out = Vec::new();
        der_len(0, &mut out);
        assert_eq!(out, vec![0]);
        let mut out = Vec::new();
        der_len(127, &mut out);
        assert_eq!(out, vec![127]);
    }

    #[test]
    fn der_len_long_form_1byte() {
        let mut out = Vec::new();
        der_len(128, &mut out);
        assert_eq!(out, vec![0x81, 128]);
        let mut out = Vec::new();
        der_len(255, &mut out);
        assert_eq!(out, vec![0x81, 255]);
    }

    #[test]
    fn der_len_long_form_2byte() {
        let mut out = Vec::new();
        der_len(256, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
        let mut out = Vec::new();
        der_len(65535, &mut out);
        assert_eq!(out, vec![0x82, 0xff, 0xff]);
    }

    #[test]
    fn build_request_der_is_valid_sequence() {
        let der = build_request_der(&[0u8; 32], 0x1234_5678);
        assert_eq!(der[0], 0x30, "outer must be SEQUENCE");
        // Outer length should account for everything that follows.
        // Skip the length encoding bytes and confirm contents reach the end.
        let (len, len_bytes) = if der[1] < 0x80 {
            (der[1] as usize, 1)
        } else {
            let n = (der[1] & 0x7f) as usize;
            let mut v = 0usize;
            for b in &der[2..2 + n] {
                v = (v << 8) | (*b as usize);
            }
            (v, 1 + n)
        };
        assert_eq!(der.len(), 1 + len_bytes + len);
    }

    #[test]
    fn build_request_der_includes_sha256_oid() {
        let der = build_request_der(&[0u8; 32], 1);
        let hay = &der[..];
        let needle = SHA256_OID_DER;
        assert!(
            hay.windows(needle.len()).any(|w| w == needle),
            "TimeStampReq must contain SHA-256 OID"
        );
    }

    #[test]
    fn der_tlv_emits_tag_length_and_inner() {
        let tlv = der_tlv(0x04, &[0xaa, 0xbb, 0xcc]);
        // Tag = 0x04 (OCTET STRING), short-form length = 3, then payload.
        assert_eq!(tlv, vec![0x04, 0x03, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn der_tlv_handles_long_form_length() {
        let inner = vec![0u8; 200]; // > 127 → 0x81 + length byte
        let tlv = der_tlv(0x30, &inner);
        assert_eq!(tlv[0], 0x30);
        assert_eq!(tlv[1], 0x81);
        assert_eq!(tlv[2], 200);
        assert_eq!(tlv.len(), 3 + inner.len());
    }

    #[test]
    fn build_request_der_includes_nonce_bytes_be() {
        // Pass a nonce whose BE encoding we can scan for in the DER blob.
        let nonce: u64 = 0x0102_0304_0506_0708;
        let der = build_request_der(&[0u8; 32], nonce);
        let nonce_be = nonce.to_be_bytes();
        // The nonce is encoded as a DER INTEGER inside the request. Its
        // significant bytes (all 8 since the high bit is clear) must appear
        // contiguously somewhere in the blob.
        assert!(der.windows(nonce_be.len()).any(|w| w == nonce_be));
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn fake_tsr() -> Vec<u8> {
        // Minimal DER SEQUENCE so the sanity check (body[0] == 0x30 and
        // length >= 8) passes. Tag + length + 8 dummy bytes.
        let mut v = vec![0x30, 0x08];
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    #[tokio::test]
    async fn submit_sends_timestamp_query_content_type() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Content-Type", "application/timestamp-query"))
            .and(header("Accept", "application/timestamp-reply"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(fake_tsr()))
            .mount(&server)
            .await;

        let r = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap();
        assert_eq!(r.kind, AnchorKind::Rfc3161);
        assert_eq!(r.target, server.uri());
        assert_eq!(r.metadata["hash_algorithm"], "sha256");
        assert!(r.metadata["request_nonce"].is_string());
    }

    #[tokio::test]
    async fn submit_returns_server_error_on_non_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("tsa offline"))
            .mount(&server)
            .await;

        let err = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        match err {
            AnchorError::Server { status, detail } => {
                assert_eq!(status, 500);
                assert!(detail.contains("tsa offline"));
            }
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_rejects_truncated_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x30, 0x01]))
            .mount(&server)
            .await;
        let err = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }

    #[tokio::test]
    async fn submit_rejects_response_not_starting_with_sequence_tag() {
        let server = MockServer::start().await;
        // 8 bytes of length but wrong tag (0x02 = INTEGER, not 0x30 = SEQUENCE).
        let mut bogus = vec![0x02, 0x08];
        bogus.extend_from_slice(&[0u8; 8]);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bogus))
            .mount(&server)
            .await;
        let err = submit(&http(), &server.uri(), &[0u8; 32]).await.unwrap_err();
        assert!(matches!(err, AnchorError::Parse(_)));
    }
}
