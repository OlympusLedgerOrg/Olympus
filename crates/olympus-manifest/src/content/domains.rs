// SPDX-License-Identifier: Apache-2.0

//! Keyed-BLAKE3 domain separation for content-addressed dataset commitments
//! (RFC-0000 "content-addressed dataset commitments", §11).
//!
//! Every hash in the format is `BLAKE3.keyed_hash(K_name, m)` with
//! `K_name = BLAKE3.derive_key("olympus 2026-11 dataset <name> v1", "")`.
//! Derived identifiers (`content-key`, …) use `derive_key` directly with their
//! own context. Context strings are globally unique and never reused; these
//! keys live in a separate input space from the ledger's ASCII-prefixed
//! domains (`OLY:NODE:V1|`, the ADR-0005 leaf prefix), so nothing here can
//! collide with or change a ledger hash.

use std::sync::OnceLock;

use super::error::{ContentError, Result};

/// One keyed-hash domain. The discriminant order is irrelevant to the wire
/// format; only [`Domain::name`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Domain {
    Empty,
    Leaf,
    Node,
    SEmpty,
    SLeaf,
    SNode,
    Part,
    Top,
    Global,
    Item,
    Fp,
    FpNode,
    Meta,
    MetaNode,
    Bucket,
    XTable,
    PTable,
    FpTable,
    Header,
    Diff,
}

const ALL: [Domain; 20] = [
    Domain::Empty,
    Domain::Leaf,
    Domain::Node,
    Domain::SEmpty,
    Domain::SLeaf,
    Domain::SNode,
    Domain::Part,
    Domain::Top,
    Domain::Global,
    Domain::Item,
    Domain::Fp,
    Domain::FpNode,
    Domain::Meta,
    Domain::MetaNode,
    Domain::Bucket,
    Domain::XTable,
    Domain::PTable,
    Domain::FpTable,
    Domain::Header,
    Domain::Diff,
];

impl Domain {
    /// The `<name>` inside the context string. Changing one is a wire-format
    /// change.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Leaf => "leaf",
            Self::Node => "node",
            Self::SEmpty => "s-empty",
            Self::SLeaf => "s-leaf",
            Self::SNode => "s-node",
            Self::Part => "part",
            Self::Top => "top",
            Self::Global => "global",
            Self::Item => "item",
            Self::Fp => "fp",
            Self::FpNode => "fpnode",
            Self::Meta => "meta",
            Self::MetaNode => "metanode",
            Self::Bucket => "bucket",
            Self::XTable => "xtable",
            Self::PTable => "ptable",
            Self::FpTable => "fptable",
            Self::Header => "header",
            Self::Diff => "diff",
        }
    }

    /// The full `derive_key` context string for this domain's key.
    pub fn context(self) -> String {
        format!("olympus 2026-11 dataset {} v1", self.name())
    }

    /// `K_name`, computed once per process.
    pub fn key(self) -> &'static [u8; 32] {
        static KEYS: OnceLock<[[u8; 32]; 20]> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            let mut out = [[0u8; 32]; 20];
            for (slot, d) in out.iter_mut().zip(ALL) {
                *slot = blake3::derive_key(&d.context(), b"");
            }
            out
        });
        let idx = ALL
            .iter()
            .position(|d| *d == self)
            .expect("every domain is in ALL");
        &keys[idx]
    }
}

/// `H_name(parts[0] ‖ parts[1] ‖ …)`.
pub fn h(domain: Domain, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(domain.key());
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// Context for content keys (§3).
pub const CONTENT_KEY_CONTEXT: &str = "olympus 2026-11 dataset content-key v1";

/// Context for MinHash shingle values (similarity companion, `text/minhash-120`).
pub const MINHASH_SHINGLE_CONTEXT: &str = "olympus 2026-11 dataset minhash-shingle v1";

/// Context whose `derive_key` output stream supplies the MinHash coefficients.
pub const MINHASH_COEFFICIENTS_CONTEXT: &str = "olympus 2026-11 dataset minhash-coefficients v1";

/// Context for LSH band keys (similarity companion, "Similarity index").
pub const BAND_KEY_CONTEXT: &str = "olympus 2026-11 dataset band-key v1";

/// Every derived-identifier context, for the disjointness test.
#[cfg(test)]
const DERIVED_CONTEXTS: [&str; 4] = [
    CONTENT_KEY_CONTEXT,
    MINHASH_SHINGLE_CONTEXT,
    MINHASH_COEFFICIENTS_CONTEXT,
    BAND_KEY_CONTEXT,
];

/// The `u32` length prefix for `x`, or [`ContentError::FieldTooLong`].
///
/// Encoders call this *before* sizing or copying anything from `x`, so an
/// oversized field is rejected without first attempting a huge allocation.
pub fn check_lp_len(x: &[u8], field: &'static str) -> Result<u32> {
    u32::try_from(x.len()).map_err(|_| ContentError::FieldTooLong(field))
}

/// `lp(x) = u32_be(len(x)) ‖ x`, appended to `out`.
///
/// Fails with [`ContentError::FieldTooLong`] naming `field` when `x` does not
/// fit the `u32` prefix. Nothing is appended in that case, and nothing ever
/// panics: framed fields can come from untrusted openings.
pub fn lp_into(out: &mut Vec<u8>, x: &[u8], field: &'static str) -> Result<()> {
    let len = check_lp_len(x, field)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn domain_keys_are_distinct_and_names_unique() {
        let names: HashSet<_> = ALL.iter().map(|d| d.name()).collect();
        assert_eq!(names.len(), ALL.len(), "duplicate domain name");
        let keys: HashSet<_> = ALL.iter().map(|d| *d.key()).collect();
        assert_eq!(keys.len(), ALL.len(), "two domains share a key");
        // Derived-identifier contexts are not keyed-hash domains, must not
        // coincide with any domain context, and are unique among themselves.
        for ctx in DERIVED_CONTEXTS {
            assert!(
                ALL.iter().all(|d| d.context() != ctx),
                "{ctx} reuses a domain"
            );
        }
        let derived: HashSet<_> = DERIVED_CONTEXTS.iter().collect();
        assert_eq!(derived.len(), DERIVED_CONTEXTS.len());
    }
}
