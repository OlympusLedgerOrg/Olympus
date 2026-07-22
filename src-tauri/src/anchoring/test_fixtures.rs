//! Shared RFC 3161 test fixtures.
//!
//! Both `rfc3161.rs` and `tstinfo.rs` exercise the strict TSTInfo parse
//! against the same real `openssl ts -reply` blob. Keeping a single copy here means a
//! future fixture refresh (different TSA reply, regenerated vectors)
//! can't silently diverge between the two test modules.
//!
//! `#[cfg(test)]`-only: nothing in this module is compiled into a release
//! binary.

/// Real `openssl ts -reply` output generated from the test-only CA below.
/// The token embeds its signer and chain. The fixture pins:
///   * messageImprint.hashedMessage =
///     SHA-256("abc") =
///     `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
///   * nonce = `0x5AFF754E092F318F` (big-endian INTEGER body)
///   * policy OID = `1.2.3.4.1`
///   * gen_time = 2026-07-22 13:15:07 UTC (`1784726107` unix)
const FIXTURE_TSR_HEX: &str = include_str!("test_fixtures/rfc3161_response.hex");

/// The nonce embedded in [`FIXTURE_TSR_HEX`].
pub const FIXTURE_NONCE: u64 = 0x5AFF_754E_092F_318F;

/// The RFC 3161 `genTime` embedded in [`FIXTURE_TSR_HEX`].
pub const FIXTURE_GEN_TIME_UNIX_SECS: u64 = 1_784_726_107;

/// SHA-256("abc"), the `messageImprint.hashedMessage` in [`FIXTURE_TSR_HEX`].
const FIXTURE_HASH_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// Decode [`FIXTURE_TSR_HEX`] into the raw `TimeStampResp` DER bytes.
pub fn fixture_tsr() -> Vec<u8> {
    decode_hex(FIXTURE_TSR_HEX)
}

/// The 32-byte SHA-256 imprint the fixture binds to.
pub fn fixture_hash() -> [u8; 32] {
    let bytes = decode_hex(FIXTURE_HASH_HEX);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    h
}

pub fn fixture_root_ca_pem() -> &'static [u8] {
    include_bytes!("test_fixtures/rfc3161_root_ca.pem")
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}
