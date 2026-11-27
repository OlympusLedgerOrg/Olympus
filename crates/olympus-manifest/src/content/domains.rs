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

/// `lp(x) = u32_be(len(x)) ‖ x`, appended to `out`.
///
/// # Panics
/// If `x` is longer than `u32::MAX` bytes. Every framed field in this format
/// is a short identifier or string; callers validate lengths before framing.
pub fn lp_into(out: &mut Vec<u8>, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("lp field exceeds u32::MAX bytes");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
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
        // The content-key context is a derived identifier, not a keyed-hash
        // domain, and must not coincide with any domain context.
        assert!(ALL.iter().all(|d| d.context() != CONTENT_KEY_CONTEXT));
    }
}
