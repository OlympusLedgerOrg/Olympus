//! Signed request envelope digest primitives (ADR-0036).
//!
//! This module owns only the domain-separated bytes. Network extraction,
//! nonce persistence, and route-scope policy live in `src-tauri`.

use crate::length_prefixed;

/// Domain prefix for ADR-0036 signed request envelopes.
pub const REQUEST_V1_PREFIX: &[u8] = REQUEST_V1_DOMAIN_SEPARATOR.as_bytes();

/// Human-readable domain separator used when wrapping [`signed_request_message`]
/// in `SignatureEnvelopeV2`.
pub const REQUEST_V1_DOMAIN_SEPARATOR: &str = "OLY:REQUEST:V1";

/// Compute the ADR-0036 request digest.
///
/// ```text
/// BLAKE3(
///   OLY:REQUEST:V1 ||
///   lp(operator_id) ||
///   lp(key_id) ||
///   lp(method) ||
///   lp(path) ||
///   body_hash_32 ||
///   timestamp_be_i64 ||
///   lp(nonce) ||
///   lp(scope)
/// )
/// ```
#[allow(clippy::too_many_arguments)]
pub fn signed_request_message(
    operator_id: &[u8],
    key_id: &[u8],
    method: &[u8],
    path: &[u8],
    body_hash: &[u8; 32],
    timestamp_utc: i64,
    nonce: &[u8],
    scope: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_V1_PREFIX);
    hasher.update(&length_prefixed(operator_id));
    hasher.update(&length_prefixed(key_id));
    hasher.update(&length_prefixed(method));
    hasher.update(&length_prefixed(path));
    hasher.update(body_hash);
    hasher.update(&timestamp_utc.to_be_bytes());
    hasher.update(&length_prefixed(nonce));
    hasher.update(&length_prefixed(scope));
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_replay_token(suffix: &[u8]) -> Vec<u8> {
        let mut token = Vec::from([b'n', b'o', b'n', b'c', b'e', b'-']);
        token.extend_from_slice(suffix);
        token
    }

    #[test]
    fn signed_request_message_is_pinned() {
        let replay_token = fixture_replay_token(b"123");
        let digest = signed_request_message(
            b"operator-a",
            b"key-1",
            b"POST",
            b"/ingest/files",
            &[0x11; 32],
            1_700_000_000,
            replay_token.as_slice(),
            b"ingest",
        );
        assert_eq!(
            hex::encode(digest),
            "52b866c3c3731d74e143c816b9afa120b6bb4b8a5a322ddf02819416b23a65b0"
        );
    }

    #[test]
    fn signed_request_message_binds_method_path_nonce_and_scope() {
        let replay_token = fixture_replay_token(b"123");
        let other_replay_token = fixture_replay_token(b"456");
        let base = signed_request_message(
            b"operator-a",
            b"key-1",
            b"POST",
            b"/ingest/files",
            &[0x11; 32],
            1_700_000_000,
            replay_token.as_slice(),
            b"ingest",
        );
        assert_ne!(
            base,
            signed_request_message(
                b"operator-a",
                b"key-1",
                b"PUT",
                b"/ingest/files",
                &[0x11; 32],
                1_700_000_000,
                replay_token.as_slice(),
                b"ingest",
            )
        );
        assert_ne!(
            base,
            signed_request_message(
                b"operator-a",
                b"key-1",
                b"POST",
                b"/admin/shards",
                &[0x11; 32],
                1_700_000_000,
                replay_token.as_slice(),
                b"ingest",
            )
        );
        assert_ne!(
            base,
            signed_request_message(
                b"operator-a",
                b"key-1",
                b"POST",
                b"/ingest/files",
                &[0x11; 32],
                1_700_000_000,
                other_replay_token.as_slice(),
                b"ingest",
            )
        );
        assert_ne!(
            base,
            signed_request_message(
                b"operator-a",
                b"key-1",
                b"POST",
                b"/ingest/files",
                &[0x11; 32],
                1_700_000_000,
                replay_token.as_slice(),
                b"admin",
            )
        );
    }
}
