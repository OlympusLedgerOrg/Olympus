// SPDX-License-Identifier: Apache-2.0

//! Fixed-width public claim emitted by the canonicalization zkVM guest.
//!
//! The guest runs [`crate::canonical::canonicalize_bytes`] over a private JSON
//! byte string, then commits this claim to its public journal. The claim keeps
//! the canonical bytes private while exposing enough deterministic material to
//! bind the result to the existing unified Groth16 section commitment.

use crate::canonical::{canonicalize_bytes, CanonError};

/// RISC Zero journal format marker and version.
pub const CANONICAL_CLAIM_MAGIC: [u8; 8] = *b"OLYCAN01";
/// Maximum source JSON accepted by the proof guest (1 MiB).
pub const MAX_CANONICAL_SOURCE_BYTES: usize = 1_048_576;
/// Maximum canonical output accepted by the proof guest (1 MiB).
pub const MAX_CANONICAL_OUTPUT_BYTES: usize = 1_048_576;
/// Per-proof zkVM user-cycle ceiling. The committed adversarial cycle report
/// peaks at 744,183,696 user cycles, leaving roughly 44% headroom.
pub const MAX_CANONICALIZATION_USER_CYCLES: u64 = 1_073_741_824;
/// Exact byte length of the fixed-width journal encoding.
pub const CANONICAL_CLAIM_ENCODED_LEN: usize = 8 + 8 + 8 + 32 + 32 + 8;

/// Domain for the commitment to the private source JSON bytes.
const SOURCE_DOMAIN: &[u8] = b"OLY:CANONICAL-SOURCE:V1|";

/// Public output of the canonicalization guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalizationClaim {
    /// Original private source length.
    pub source_len: u64,
    /// Canonical JCS/NFC/decimal output length.
    pub canonical_len: u64,
    /// Domain-separated commitment to the original private source bytes.
    pub source_commitment: [u8; 32],
    /// Bare BLAKE3 of canonical bytes, matching ADR-0009's value encoding.
    pub canonical_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalClaimError {
    SourceTooLarge(usize),
    CanonicalTooLarge(usize),
    InvalidEncoding(&'static str),
}

impl std::fmt::Display for CanonicalClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceTooLarge(len) => write!(
                f,
                "source JSON is {len} bytes; maximum is {MAX_CANONICAL_SOURCE_BYTES}"
            ),
            Self::CanonicalTooLarge(len) => write!(
                f,
                "canonical JSON is {len} bytes; maximum is {MAX_CANONICAL_OUTPUT_BYTES}"
            ),
            Self::InvalidEncoding(message) => {
                write!(f, "invalid canonicalization claim: {message}")
            }
        }
    }
}

impl std::error::Error for CanonicalClaimError {}

#[derive(Debug)]
pub enum ProveCanonicalizationError {
    Canonical(CanonError),
    Claim(CanonicalClaimError),
}

impl std::fmt::Display for ProveCanonicalizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(error) => error.fmt(f),
            Self::Claim(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ProveCanonicalizationError {}

impl From<CanonError> for ProveCanonicalizationError {
    fn from(value: CanonError) -> Self {
        Self::Canonical(value)
    }
}

impl From<CanonicalClaimError> for ProveCanonicalizationError {
    fn from(value: CanonicalClaimError) -> Self {
        Self::Claim(value)
    }
}

/// Run the canonical Rust implementation and derive the zkVM journal claim.
pub fn canonicalization_claim(
    source: &[u8],
) -> Result<CanonicalizationClaim, ProveCanonicalizationError> {
    if source.len() > MAX_CANONICAL_SOURCE_BYTES {
        return Err(CanonicalClaimError::SourceTooLarge(source.len()).into());
    }
    let canonical = canonicalize_bytes(source)?;
    claim_from_canonical(source, &canonical).map_err(Into::into)
}

/// Derive the public claim from source and already-canonical bytes.
///
/// This is public for host-side parity tests. Production callers should use
/// [`canonicalization_claim`]; only the zkVM guest makes the derivation trusted.
pub fn claim_from_canonical(
    source: &[u8],
    canonical: &[u8],
) -> Result<CanonicalizationClaim, CanonicalClaimError> {
    if source.is_empty() {
        return Err(CanonicalClaimError::InvalidEncoding(
            "source JSON must not be empty",
        ));
    }
    if source.len() > MAX_CANONICAL_SOURCE_BYTES {
        return Err(CanonicalClaimError::SourceTooLarge(source.len()));
    }
    if canonical.is_empty() {
        return Err(CanonicalClaimError::InvalidEncoding(
            "canonical JSON must not be empty",
        ));
    }
    if canonical.len() > MAX_CANONICAL_OUTPUT_BYTES {
        return Err(CanonicalClaimError::CanonicalTooLarge(canonical.len()));
    }

    Ok(CanonicalizationClaim {
        source_len: source.len() as u64,
        canonical_len: canonical.len() as u64,
        source_commitment: framed_hash(SOURCE_DOMAIN, source),
        canonical_digest: *blake3::hash(canonical).as_bytes(),
    })
}

fn framed_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

impl CanonicalizationClaim {
    /// Encode the journal without a recursive/general-purpose serializer.
    pub fn encode(&self) -> [u8; CANONICAL_CLAIM_ENCODED_LEN] {
        let mut out = [0u8; CANONICAL_CLAIM_ENCODED_LEN];
        let mut cursor = 0usize;
        push(&mut out, &mut cursor, &CANONICAL_CLAIM_MAGIC);
        push(&mut out, &mut cursor, &self.source_len.to_be_bytes());
        push(&mut out, &mut cursor, &self.canonical_len.to_be_bytes());
        push(&mut out, &mut cursor, &self.source_commitment);
        push(&mut out, &mut cursor, &self.canonical_digest);
        out[cursor] = 1; // deterministic one-section circuit recipe
        cursor += 8; // section count plus seven reserved zero bytes
        debug_assert_eq!(cursor, CANONICAL_CLAIM_ENCODED_LEN);
        out
    }

    /// Decode and structurally validate the fixed-width journal claim.
    pub fn decode(bytes: &[u8]) -> Result<Self, CanonicalClaimError> {
        if bytes.len() != CANONICAL_CLAIM_ENCODED_LEN {
            return Err(CanonicalClaimError::InvalidEncoding("wrong encoded length"));
        }
        if bytes[..8] != CANONICAL_CLAIM_MAGIC {
            return Err(CanonicalClaimError::InvalidEncoding("wrong magic/version"));
        }

        let source_len = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
        let canonical_len = u64::from_be_bytes(bytes[16..24].try_into().expect("fixed slice"));
        let source_commitment = bytes[24..56].try_into().expect("fixed slice");
        let canonical_digest = bytes[56..88].try_into().expect("fixed slice");
        if bytes[88] != 1 {
            return Err(CanonicalClaimError::InvalidEncoding(
                "section count must be one",
            ));
        }
        if bytes[89..96].iter().any(|byte| *byte != 0) {
            return Err(CanonicalClaimError::InvalidEncoding(
                "reserved bytes must be zero",
            ));
        }
        if source_len > MAX_CANONICAL_SOURCE_BYTES as u64 {
            return Err(CanonicalClaimError::SourceTooLarge(
                usize::try_from(source_len).unwrap_or(usize::MAX),
            ));
        }
        if source_len == 0 {
            return Err(CanonicalClaimError::InvalidEncoding(
                "source JSON must not be empty",
            ));
        }
        if canonical_len == 0 {
            return Err(CanonicalClaimError::InvalidEncoding(
                "canonical JSON must not be empty",
            ));
        }
        if canonical_len > MAX_CANONICAL_OUTPUT_BYTES as u64 {
            return Err(CanonicalClaimError::CanonicalTooLarge(
                usize::try_from(canonical_len).unwrap_or(usize::MAX),
            ));
        }

        Ok(Self {
            source_len,
            canonical_len,
            source_commitment,
            canonical_digest,
        })
    }
}

fn push<const N: usize>(out: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    out[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_runs_full_canonicalizer_and_roundtrips() {
        let source = br#"{ "z":1.2300e+3, "name":"e\u0301", "a":true }"#;
        let canonical = canonicalize_bytes(source).unwrap();
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            "{\"a\":true,\"name\":\"é\",\"z\":1230}"
        );
        let claim = canonicalization_claim(source).unwrap();
        assert_eq!(claim.canonical_digest, *blake3::hash(&canonical).as_bytes());
        assert_eq!(
            CanonicalizationClaim::decode(&claim.encode()).unwrap(),
            claim
        );
    }

    #[test]
    fn full_canonical_digest_is_the_single_section_preimage() {
        let canonical = vec![b'x'; 1024];
        let claim = claim_from_canonical(b"0", &canonical).unwrap();
        assert_eq!(claim.canonical_len, 1024);
        assert_eq!(claim.canonical_digest, *blake3::hash(&canonical).as_bytes());
    }

    #[test]
    fn decode_rejects_nonzero_padding() {
        let claim = canonicalization_claim(b"0").unwrap();
        let mut encoded = claim.encode();
        encoded[95] = 1;
        assert!(matches!(
            CanonicalizationClaim::decode(&encoded),
            Err(CanonicalClaimError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn claim_encoding_matches_pinned_cross_language_vector() {
        let source = br#"{ "z":1.2300e+3, "name":"e\u0301", "a":true }"#;
        let claim = canonicalization_claim(source).unwrap();
        assert_eq!(
            hex::encode(claim.encode()),
            "4f4c5943414e3031000000000000002d000000000000001f293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c953546711dafbab9471037d55b746ffc7c810af1d5d9f384972498431044f166ddfed0100000000000000"
        );
    }

    #[test]
    fn decode_rejects_u64_lengths_before_platform_casts() {
        let mut encoded = canonicalization_claim(b"0").unwrap().encode();
        encoded[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            CanonicalizationClaim::decode(&encoded),
            Err(CanonicalClaimError::SourceTooLarge(_))
        ));

        let mut encoded = canonicalization_claim(b"0").unwrap().encode();
        encoded[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            CanonicalizationClaim::decode(&encoded),
            Err(CanonicalClaimError::CanonicalTooLarge(_))
        ));
    }

    #[test]
    fn decode_rejects_empty_source_length() {
        let mut encoded = canonicalization_claim(b"0").unwrap().encode();
        encoded[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert!(matches!(
            CanonicalizationClaim::decode(&encoded),
            Err(CanonicalClaimError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn claim_builder_rejects_empty_source() {
        assert!(matches!(
            claim_from_canonical(b"", b"0"),
            Err(CanonicalClaimError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn source_limit_fails_closed_before_parsing() {
        let mut at_limit = vec![b' '; MAX_CANONICAL_SOURCE_BYTES];
        at_limit[MAX_CANONICAL_SOURCE_BYTES - 1] = b'0';
        let claim = canonicalization_claim(&at_limit).unwrap();
        assert_eq!(claim.source_len, MAX_CANONICAL_SOURCE_BYTES as u64);
        assert_eq!(claim.canonical_len, 1);

        let oversized = vec![b'0'; MAX_CANONICAL_SOURCE_BYTES + 1];
        assert!(matches!(
            canonicalization_claim(&oversized),
            Err(ProveCanonicalizationError::Claim(
                CanonicalClaimError::SourceTooLarge(_)
            ))
        ));
    }

    #[test]
    fn size_limits_accept_the_boundary_and_reject_the_next_byte() {
        assert_eq!(MAX_CANONICALIZATION_USER_CYCLES, 1_073_741_824);

        let source_at_limit = vec![b'0'; MAX_CANONICAL_SOURCE_BYTES];
        assert!(claim_from_canonical(&source_at_limit, b"0").is_ok());
        assert!(matches!(
            claim_from_canonical(&[b'0'; MAX_CANONICAL_SOURCE_BYTES + 1], b"0"),
            Err(CanonicalClaimError::SourceTooLarge(_))
        ));

        let canonical_at_limit = vec![b'0'; MAX_CANONICAL_OUTPUT_BYTES];
        assert!(claim_from_canonical(b"0", &canonical_at_limit).is_ok());
        assert!(matches!(
            claim_from_canonical(b"0", &[b'0'; MAX_CANONICAL_OUTPUT_BYTES + 1]),
            Err(CanonicalClaimError::CanonicalTooLarge(_))
        ));
    }

    #[test]
    fn decode_accepts_exact_size_limits() {
        let mut encoded = canonicalization_claim(b"0").unwrap().encode();
        encoded[8..16].copy_from_slice(&(MAX_CANONICAL_SOURCE_BYTES as u64).to_be_bytes());
        encoded[16..24].copy_from_slice(&(MAX_CANONICAL_OUTPUT_BYTES as u64).to_be_bytes());
        let decoded = CanonicalizationClaim::decode(&encoded).unwrap();
        assert_eq!(decoded.source_len, MAX_CANONICAL_SOURCE_BYTES as u64);
        assert_eq!(decoded.canonical_len, MAX_CANONICAL_OUTPUT_BYTES as u64);
    }

    #[test]
    fn errors_have_stable_actionable_messages() {
        assert_eq!(
            CanonicalClaimError::SourceTooLarge(1_048_577).to_string(),
            "source JSON is 1048577 bytes; maximum is 1048576"
        );
        assert_eq!(
            CanonicalClaimError::CanonicalTooLarge(1_048_577).to_string(),
            "canonical JSON is 1048577 bytes; maximum is 1048576"
        );
        assert_eq!(
            CanonicalClaimError::InvalidEncoding("wrong magic/version").to_string(),
            "invalid canonicalization claim: wrong magic/version"
        );

        let canonical_error = canonicalization_claim(b"not-json").unwrap_err();
        assert_eq!(
            canonical_error.to_string(),
            canonicalize_bytes(b"not-json").unwrap_err().to_string()
        );
        let claim_error =
            ProveCanonicalizationError::from(CanonicalClaimError::InvalidEncoding("bad"));
        assert_eq!(
            claim_error.to_string(),
            "invalid canonicalization claim: bad"
        );
    }
}
