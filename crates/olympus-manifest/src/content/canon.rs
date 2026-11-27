// SPDX-License-Identifier: Apache-2.0

//! Canonicalization profiles (RFC §1, §0a).
//!
//! A profile maps raw item bytes to canonical bytes or **rejects** them; it
//! never silently repairs. `(id, version)` names the output function; the
//! `implementation_id` names the software that computed it and is bound into
//! the profile table digest.

use unicode_normalization::{UnicodeNormalization, UNICODE_VERSION};

use super::error::{ContentError, Result};

/// Unicode version pinned by `text/utf8-nfc` v1 (RFC §0a rule 2).
pub const TEXT_UNICODE_VERSION: (u8, u8, u8) = (17, 0, 0);

// Rule 2 makes an implementation built against another Unicode version
// non-conforming even if it passes the vectors. Enforce it at compile time:
// a `cargo update` that moves `unicode-normalization` to a different Unicode
// version fails the build here instead of silently changing canonical bytes.
// The fix is a new profile version, not loosening this check.
const _: () = assert!(
    UNICODE_VERSION.0 == TEXT_UNICODE_VERSION.0
        && UNICODE_VERSION.1 == TEXT_UNICODE_VERSION.1
        && UNICODE_VERSION.2 == TEXT_UNICODE_VERSION.2,
    "unicode-normalization implements a different Unicode version than text/utf8-nfc v1 pins"
);

/// Exact `unicode-normalization` version this build links, named in
/// `implementation_id`. Kept in step with `Cargo.lock` by
/// `implementation_id_matches_locked_dependency`.
pub const UNICODE_NORMALIZATION_VERSION: &str = "0.1.25";

/// The v1 canonicalization profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonProfile {
    /// `bytes/raw` v1: the raw bytes, unchanged.
    BytesRaw,
    /// `text/utf8-nfc` v1: reject invalid UTF-8, strip one leading U+FEFF,
    /// CRLF and lone CR to LF, Unicode 17.0.0 NFC. Nothing else.
    TextUtf8Nfc,
}

impl CanonProfile {
    /// `profile_id`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::BytesRaw => "bytes/raw",
            Self::TextUtf8Nfc => "text/utf8-nfc",
        }
    }

    /// `profile_version`.
    pub const fn version(self) -> u32 {
        1
    }

    /// This implementation's `implementation_id` (§0a): sorted
    /// `name=version` pairs for every component that reaches the output.
    pub fn implementation_id(self) -> String {
        let crate_v = concat!("olympus-manifest=", env!("CARGO_PKG_VERSION"));
        match self {
            Self::BytesRaw => crate_v.to_string(),
            Self::TextUtf8Nfc => format!(
                "{crate_v};unicode={}.{}.{};unicode-normalization={UNICODE_NORMALIZATION_VERSION}",
                UNICODE_VERSION.0, UNICODE_VERSION.1, UNICODE_VERSION.2
            ),
        }
    }

    /// Canonicalize raw item bytes, or reject them.
    pub fn canonicalize(self, raw: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::BytesRaw => Ok(raw.to_vec()),
            Self::TextUtf8Nfc => text_utf8_nfc(raw),
        }
    }
}

fn text_utf8_nfc(raw: &[u8]) -> Result<Vec<u8>> {
    let s = std::str::from_utf8(raw).map_err(|_| ContentError::InvalidUtf8)?;
    let s = s.strip_prefix('\u{FEFF}').unwrap_or(s);
    let mut lf = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            lf.push('\n');
        } else {
            lf.push(c);
        }
    }
    Ok(lf.nfc().collect::<String>().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_raw_is_identity_including_invalid_utf8() {
        let raw = [0xff, 0x00, b'a', 0xc3];
        assert_eq!(CanonProfile::BytesRaw.canonicalize(&raw).unwrap(), raw);
    }

    #[test]
    fn text_rejects_invalid_utf8_rather_than_repairing() {
        assert_eq!(
            CanonProfile::TextUtf8Nfc.canonicalize(&[b'a', 0xff]),
            Err(ContentError::InvalidUtf8)
        );
    }

    #[test]
    fn text_strips_exactly_one_bom() {
        let t = CanonProfile::TextUtf8Nfc;
        assert_eq!(t.canonicalize("\u{FEFF}x".as_bytes()).unwrap(), b"x");
        assert_eq!(
            t.canonicalize("\u{FEFF}\u{FEFF}x".as_bytes()).unwrap(),
            "\u{FEFF}x".as_bytes()
        );
        // A BOM that is not leading is content.
        assert_eq!(
            t.canonicalize("x\u{FEFF}".as_bytes()).unwrap(),
            "x\u{FEFF}".as_bytes()
        );
    }

    #[test]
    fn text_converts_crlf_and_lone_cr_to_lf() {
        let t = CanonProfile::TextUtf8Nfc;
        assert_eq!(t.canonicalize(b"a\r\nb\rc\n\r\n").unwrap(), b"a\nb\nc\n\n");
    }

    #[test]
    fn text_applies_nfc_and_nothing_else() {
        let t = CanonProfile::TextUtf8Nfc;
        // e + COMBINING ACUTE -> U+00E9
        assert_eq!(
            t.canonicalize("e\u{0301}".as_bytes()).unwrap(),
            "\u{00E9}".as_bytes()
        );
        // No trimming, case change, whitespace collapsing, or NFKC folding.
        let kept = "  A\t\u{FB01}  ";
        assert_eq!(t.canonicalize(kept.as_bytes()).unwrap(), kept.as_bytes());
    }

    #[test]
    fn implementation_id_names_the_pinned_unicode_version() {
        assert!(CanonProfile::TextUtf8Nfc
            .implementation_id()
            .contains(";unicode=17.0.0;"));
    }

    #[test]
    fn implementation_id_matches_locked_dependency() {
        let lock = include_str!("../../../../Cargo.lock");
        let needle = format!(
            "name = \"unicode-normalization\"\nversion = \"{UNICODE_NORMALIZATION_VERSION}\""
        );
        assert!(
            lock.replace("\r\n", "\n").contains(&needle),
            "Cargo.lock no longer locks unicode-normalization {UNICODE_NORMALIZATION_VERSION}; \
             update UNICODE_NORMALIZATION_VERSION (and the profile version if output changes)"
        );
    }
}
