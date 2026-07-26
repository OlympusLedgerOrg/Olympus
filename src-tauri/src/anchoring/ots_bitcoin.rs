// SPDX-License-Identifier: Apache-2.0

//! Verification of OpenTimestamps Bitcoin attestations against operator-pinned
//! Bitcoin mainnet block headers.
//!
//! An OTS terminal contains only a block height and the message that should be
//! that block's Merkle root. A calendar-supplied height/tag is not evidence by
//! itself. The operator therefore exports headers from a trusted, fully
//! validated Bitcoin Core node and pins them in a local manifest. We verify the
//! exact header hash, proof of work, mainnet target bound, and raw Merkle-root
//! field before an upgraded receipt is allowed to become verified evidence.

use std::collections::BTreeMap;
use std::path::Path;

use num_bigint::BigUint;
use serde::{de, Deserialize, Deserializer};
use sha2::{Digest, Sha256};

const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_HEADERS: usize = 50_000;
const MAINNET_POW_LIMIT_HEX: &[u8] =
    b"00000000ffff0000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum TrustedHeaderError {
    #[error("read trusted Bitcoin header manifest: {0}")]
    Read(String),
    #[error("trusted Bitcoin header manifest exceeds {MAX_MANIFEST_BYTES} bytes")]
    TooLarge,
    #[error("parse trusted Bitcoin header manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported trusted Bitcoin header manifest: {0}")]
    InvalidManifest(String),
    #[error("trusted Bitcoin header {height}: {detail}")]
    InvalidHeader { height: u64, detail: String },
    #[error("trusted Bitcoin header manifest has no entry for height {0}")]
    MissingHeight(u64),
    #[error("OTS Merkle root does not match trusted Bitcoin header at height {height}")]
    MerkleRootMismatch { height: u64 },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderManifest {
    schema_version: u8,
    network: String,
    #[serde(deserialize_with = "deserialize_bounded_headers")]
    headers: Vec<HeaderEntryWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderEntryWire {
    height: u64,
    header_hex: String,
    block_hash_hex: String,
}

#[derive(Debug, Clone)]
struct TrustedHeader {
    raw_merkle_root: [u8; 32],
    block_hash_hex: String,
    block_time: u32,
}

#[derive(Debug, Clone)]
pub struct TrustedBitcoinHeaders {
    headers: BTreeMap<u64, TrustedHeader>,
    manifest_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHeaderVerification {
    pub height: u64,
    pub block_hash_hex: String,
    pub block_time: u32,
    pub manifest_digest_hex: String,
}

impl TrustedBitcoinHeaders {
    pub fn load(path: &Path) -> Result<Self, TrustedHeaderError> {
        let bytes = super::safe_file::read_bounded_regular_file(path, MAX_MANIFEST_BYTES).map_err(
            |error| match error {
                super::safe_file::SafeOperatorFileError::TooLarge { .. } => {
                    TrustedHeaderError::TooLarge
                }
                other => TrustedHeaderError::Read(other.to_string()),
            },
        )?;
        let manifest: HeaderManifest = serde_json::from_slice(&bytes)?;
        if manifest.schema_version != 1 {
            return Err(TrustedHeaderError::InvalidManifest(format!(
                "schema_version {} is not supported (expected 1)",
                manifest.schema_version
            )));
        }
        if manifest.network != "bitcoin-mainnet" {
            return Err(TrustedHeaderError::InvalidManifest(format!(
                "network {:?} is not bitcoin-mainnet",
                manifest.network
            )));
        }
        if manifest.headers.is_empty() {
            return Err(TrustedHeaderError::InvalidManifest(
                "headers must not be empty".to_owned(),
            ));
        }

        let mut headers = BTreeMap::new();
        let mut previous_height = None;
        for entry in manifest.headers {
            if previous_height.is_some_and(|previous| entry.height <= previous) {
                return Err(TrustedHeaderError::InvalidManifest(
                    "headers must be strictly increasing by height".to_owned(),
                ));
            }
            previous_height = Some(entry.height);
            let header = validate_header(&entry)?;
            if headers.insert(entry.height, header).is_some() {
                return Err(TrustedHeaderError::InvalidManifest(format!(
                    "duplicate height {}",
                    entry.height
                )));
            }
        }

        Ok(Self {
            headers,
            manifest_digest: *blake3::hash(&bytes).as_bytes(),
        })
    }

    pub fn verify_attestation(
        &self,
        height: u64,
        ots_merkle_root: &[u8; 32],
    ) -> Result<TrustedHeaderVerification, TrustedHeaderError> {
        let header = self
            .headers
            .get(&height)
            .ok_or(TrustedHeaderError::MissingHeight(height))?;
        if header.raw_merkle_root != *ots_merkle_root {
            return Err(TrustedHeaderError::MerkleRootMismatch { height });
        }
        Ok(TrustedHeaderVerification {
            height,
            block_hash_hex: header.block_hash_hex.clone(),
            block_time: header.block_time,
            manifest_digest_hex: hex::encode(self.manifest_digest),
        })
    }
}

fn deserialize_bounded_headers<'de, D>(deserializer: D) -> Result<Vec<HeaderEntryWire>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedHeadersVisitor;

    impl<'de> de::Visitor<'de> for BoundedHeadersVisitor {
        type Value = Vec<HeaderEntryWire>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_MANIFEST_HEADERS} trusted Bitcoin headers"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let initial_capacity = sequence.size_hint().unwrap_or(0).min(MAX_MANIFEST_HEADERS);
            let mut headers = Vec::with_capacity(initial_capacity);
            while let Some(header) = sequence.next_element()? {
                if headers.len() == MAX_MANIFEST_HEADERS {
                    return Err(de::Error::custom(format!(
                        "trusted Bitcoin header manifest exceeds the {MAX_MANIFEST_HEADERS}-header limit"
                    )));
                }
                headers.push(header);
            }
            Ok(headers)
        }
    }

    deserializer.deserialize_seq(BoundedHeadersVisitor)
}

fn validate_header(entry: &HeaderEntryWire) -> Result<TrustedHeader, TrustedHeaderError> {
    if entry.header_hex.len() != 160
        || !entry
            .header_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_header(
            entry.height,
            "header_hex must be exactly 160 lowercase hexadecimal characters",
        ));
    }
    if entry.block_hash_hex.len() != 64
        || !entry
            .block_hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_header(
            entry.height,
            "block_hash_hex must be exactly 64 lowercase hexadecimal characters",
        ));
    }

    let header_bytes = hex::decode(&entry.header_hex)
        .map_err(|e| invalid_header(entry.height, format!("decode header_hex: {e}")))?;
    let header: [u8; 80] = header_bytes.try_into().map_err(|_| {
        invalid_header(entry.height, "decoded block header is not exactly 80 bytes")
    })?;

    let first = Sha256::digest(header);
    let second = Sha256::digest(first);
    let mut displayed_hash = second.to_vec();
    displayed_hash.reverse();
    let computed_hash_hex = hex::encode(displayed_hash);
    if computed_hash_hex != entry.block_hash_hex {
        return Err(invalid_header(
            entry.height,
            format!("computed block hash {computed_hash_hex} does not match pinned block_hash_hex"),
        ));
    }

    let bits = u32::from_le_bytes(header[72..76].try_into().expect("fixed header slice"));
    let target = target_from_compact(bits)
        .map_err(|detail| invalid_header(entry.height, format!("invalid nBits: {detail}")))?;
    let hash_value = BigUint::from_bytes_le(&second);
    if hash_value > target {
        return Err(invalid_header(
            entry.height,
            "block header does not satisfy its proof-of-work target",
        ));
    }

    let raw_merkle_root = header[36..68]
        .try_into()
        .expect("fixed Bitcoin Merkle-root slice");
    let block_time = u32::from_le_bytes(header[68..72].try_into().expect("fixed header slice"));
    Ok(TrustedHeader {
        raw_merkle_root,
        block_hash_hex: entry.block_hash_hex.clone(),
        block_time,
    })
}

fn target_from_compact(bits: u32) -> Result<BigUint, String> {
    if bits & 0x0080_0000 != 0 {
        return Err("negative compact target".to_owned());
    }
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return Err("zero compact target".to_owned());
    }
    let target = if exponent <= 3 {
        BigUint::from(mantissa >> (8 * (3 - exponent)))
    } else {
        BigUint::from(mantissa) << (8 * (exponent - 3))
    };
    let pow_limit =
        BigUint::parse_bytes(MAINNET_POW_LIMIT_HEX, 16).expect("static mainnet pow limit");
    if target > pow_limit {
        return Err("target exceeds the Bitcoin mainnet proof-of-work limit".to_owned());
    }
    Ok(target)
}

fn invalid_header(height: u64, detail: impl Into<String>) -> TrustedHeaderError {
    TrustedHeaderError::InvalidHeader {
        height,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const GENESIS_HEADER: &str = concat!(
        "01000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49",
        "ffff001d",
        "1dac2b7c"
    );
    const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const GENESIS_MERKLE_ROOT: &str =
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";

    fn manifest(header_hex: &str, block_hash_hex: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp manifest");
        write!(
            file,
            "{{\"schema_version\":1,\"network\":\"bitcoin-mainnet\",\"headers\":[\
             {{\"height\":0,\"header_hex\":\"{header_hex}\",\
             \"block_hash_hex\":\"{block_hash_hex}\"}}]}}"
        )
        .expect("write manifest");
        file.flush().expect("flush manifest");
        file
    }

    #[test]
    fn verifies_ots_root_against_pinned_mainnet_header_and_work() {
        let file = manifest(GENESIS_HEADER, GENESIS_HASH);
        let trusted = TrustedBitcoinHeaders::load(file.path()).expect("load genesis header");
        let root: [u8; 32] = hex::decode(GENESIS_MERKLE_ROOT)
            .unwrap()
            .try_into()
            .unwrap();
        let verified = trusted
            .verify_attestation(0, &root)
            .expect("verify genesis Merkle root");
        assert_eq!(verified.block_hash_hex, GENESIS_HASH);
        assert_eq!(verified.block_time, 1_231_006_505);
        assert_eq!(verified.manifest_digest_hex.len(), 64);
    }

    #[test]
    fn rejects_wrong_merkle_root_or_untrusted_height() {
        let file = manifest(GENESIS_HEADER, GENESIS_HASH);
        let trusted = TrustedBitcoinHeaders::load(file.path()).expect("load genesis header");
        assert!(matches!(
            trusted.verify_attestation(0, &[7u8; 32]),
            Err(TrustedHeaderError::MerkleRootMismatch { height: 0 })
        ));
        assert!(matches!(
            trusted.verify_attestation(1, &[0u8; 32]),
            Err(TrustedHeaderError::MissingHeight(1))
        ));
    }

    #[test]
    fn rejects_header_hash_tampering_and_non_mainnet_target() {
        let mut tampered = GENESIS_HEADER.to_owned();
        tampered.replace_range(152..160, "00000000");
        let file = manifest(&tampered, GENESIS_HASH);
        assert!(matches!(
            TrustedBitcoinHeaders::load(file.path()),
            Err(TrustedHeaderError::InvalidHeader { .. })
        ));

        let mut inflated_target = GENESIS_HEADER.to_owned();
        inflated_target.replace_range(144..152, "ffff7f20");
        let file = manifest(&inflated_target, GENESIS_HASH);
        assert!(matches!(
            TrustedBitcoinHeaders::load(file.path()),
            Err(TrustedHeaderError::InvalidHeader { .. })
        ));
        assert!(target_from_compact(0x207f_ffff).is_err());
    }

    #[test]
    fn rejects_manifest_larger_than_the_preparse_budget() {
        let file = tempfile::NamedTempFile::new().expect("temp manifest");
        file.as_file()
            .set_len(MAX_MANIFEST_BYTES as u64 + 1)
            .expect("size manifest");
        assert!(matches!(
            TrustedBitcoinHeaders::load(file.path()),
            Err(TrustedHeaderError::TooLarge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_manifest_without_reading_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp directory");
        let target = directory.path().join("target.json");
        let link = directory.path().join("linked.json");
        std::fs::write(
            &target,
            format!(
                "{{\"schema_version\":1,\"network\":\"bitcoin-mainnet\",\"headers\":[\
                 {{\"height\":0,\"header_hex\":\"{GENESIS_HEADER}\",\
                 \"block_hash_hex\":\"{GENESIS_HASH}\"}}]}}"
            ),
        )
        .expect("write target");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            TrustedBitcoinHeaders::load(&link),
            Err(TrustedHeaderError::Read(_))
        ));
    }
}
