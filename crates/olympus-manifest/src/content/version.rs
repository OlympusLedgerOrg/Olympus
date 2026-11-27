// SPDX-License-Identifier: Apache-2.0

//! Profile tables and the global root (RFC §5).

use super::domains::{h, lp_into, Domain};
use super::error::{ContentError, Result};

/// Format string bound into every global root.
pub const TREE_FORMAT: &str = "olympus-dataset-tree/v1";

/// A canonicalization-profile table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEntry {
    /// `profile_id`.
    pub id: String,
    /// `profile_version`.
    pub version: u32,
    /// `implementation_id` (§0a).
    pub implementation_id: String,
}

/// A fingerprint-profile table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpProfileEntry {
    /// `fp_profile_id`.
    pub id: String,
    /// `fp_profile_version`.
    pub version: u32,
    /// `implementation_id`.
    pub implementation_id: String,
    /// LSH bands.
    pub bands: u16,
    /// Units per band.
    pub rows: u16,
    /// Threshold in the profile's unit.
    pub threshold: u32,
}

/// An extraction-profile table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionEntry {
    /// `extraction_id`.
    pub id: String,
    /// `extraction_version`.
    pub version: u32,
    /// `implementation_id`.
    pub implementation_id: String,
    /// Parameters; serialized sorted by name, each name once (§0a rule 4).
    pub params: Vec<(String, String)>,
}

fn table_len(n: usize, name: &'static str) -> Result<[u8; 2]> {
    u16::try_from(n)
        .map(u16::to_be_bytes)
        .map_err(|_| ContentError::TableTooLarge(name))
}

fn non_empty(s: &str, field: &'static str) -> Result<()> {
    if s.is_empty() {
        Err(ContentError::EmptyField(field))
    } else {
        Ok(())
    }
}

/// `profile_table` preimage bytes.
pub fn profile_table_bytes(t: &[ProfileEntry]) -> Result<Vec<u8>> {
    let mut b = table_len(t.len(), "profile")?.to_vec();
    for e in t {
        non_empty(&e.id, "profile_id")?;
        non_empty(&e.implementation_id, "implementation_id")?;
        lp_into(&mut b, e.id.as_bytes());
        b.extend_from_slice(&e.version.to_be_bytes());
        lp_into(&mut b, e.implementation_id.as_bytes());
    }
    Ok(b)
}

/// `fp_profile_table` preimage bytes.
pub fn fp_profile_table_bytes(t: &[FpProfileEntry]) -> Result<Vec<u8>> {
    let mut b = table_len(t.len(), "fp_profile")?.to_vec();
    for e in t {
        non_empty(&e.id, "fp_profile_id")?;
        non_empty(&e.implementation_id, "implementation_id")?;
        lp_into(&mut b, e.id.as_bytes());
        b.extend_from_slice(&e.version.to_be_bytes());
        lp_into(&mut b, e.implementation_id.as_bytes());
        b.extend_from_slice(&e.bands.to_be_bytes());
        b.extend_from_slice(&e.rows.to_be_bytes());
        b.extend_from_slice(&e.threshold.to_be_bytes());
    }
    Ok(b)
}

/// `extraction_table` preimage bytes. Parameters are sorted by name here; a
/// repeated name or an empty value is rejected (absent optionals are omitted,
/// never written empty).
pub fn extraction_table_bytes(t: &[ExtractionEntry]) -> Result<Vec<u8>> {
    let mut b = table_len(t.len(), "extraction")?.to_vec();
    for e in t {
        non_empty(&e.id, "extraction_id")?;
        non_empty(&e.implementation_id, "implementation_id")?;
        let mut params = e.params.clone();
        params.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if let Some(w) = params.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(ContentError::DuplicateParam(w[0].0.clone()));
        }
        lp_into(&mut b, e.id.as_bytes());
        b.extend_from_slice(&e.version.to_be_bytes());
        lp_into(&mut b, e.implementation_id.as_bytes());
        b.extend_from_slice(&table_len(params.len(), "extraction params")?);
        for (k, v) in &params {
            non_empty(k, "param_name")?;
            non_empty(v, "param_value")?;
            lp_into(&mut b, k.as_bytes());
            lp_into(&mut b, v.as_bytes());
        }
    }
    Ok(b)
}

/// The three table digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableDigests {
    /// `H_xtable(extraction_table)`.
    pub extraction: [u8; 32],
    /// `H_ptable(profile_table)`.
    pub profile: [u8; 32],
    /// `H_fptable(fp_profile_table)`.
    pub fp_profile: [u8; 32],
}

impl TableDigests {
    /// Compute from the tables.
    pub fn compute(
        extraction: &[ExtractionEntry],
        profiles: &[ProfileEntry],
        fp_profiles: &[FpProfileEntry],
    ) -> Result<Self> {
        Ok(Self {
            extraction: h(Domain::XTable, &[&extraction_table_bytes(extraction)?]),
            profile: h(Domain::PTable, &[&profile_table_bytes(profiles)?]),
            fp_profile: h(Domain::FpTable, &[&fp_profile_table_bytes(fp_profiles)?]),
        })
    }
}

/// Everything `global_root` binds (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalRootInput {
    /// `dataset_id`.
    pub dataset_id: String,
    /// `version`.
    pub version: u64,
    /// Partition exponent.
    pub p: u8,
    /// Leaves in the item tree.
    pub item_count: u64,
    /// Sum of every leaf's `occurrence_count`.
    pub occurrence_total: u64,
    /// Table digests.
    pub tables: TableDigests,
    /// Item-tree root.
    pub item_root: [u8; 32],
    /// Similarity-index root (`E_s` when no fingerprint profile is used).
    pub similarity_root: [u8; 32],
}

impl GlobalRootInput {
    /// `global_root`.
    pub fn compute(&self) -> Result<[u8; 32]> {
        if self.dataset_id.is_empty() {
            return Err(ContentError::EmptyField("dataset_id"));
        }
        if self.p > 16 {
            return Err(ContentError::BadPartitionExponent(self.p));
        }
        let mut m = Vec::with_capacity(256);
        lp_into(&mut m, TREE_FORMAT.as_bytes());
        lp_into(&mut m, self.dataset_id.as_bytes());
        m.extend_from_slice(&self.version.to_be_bytes());
        m.push(self.p);
        m.extend_from_slice(&self.item_count.to_be_bytes());
        m.extend_from_slice(&self.occurrence_total.to_be_bytes());
        m.extend_from_slice(&self.tables.extraction);
        m.extend_from_slice(&self.tables.profile);
        m.extend_from_slice(&self.tables.fp_profile);
        m.extend_from_slice(&self.item_root);
        m.extend_from_slice(&self.similarity_root);
        Ok(h(Domain::Global, &[&m]))
    }
}

/// `E_s`, the empty similarity tree, used as `similarity_root` by a version
/// with no fingerprinted items (v1 exact-only).
pub fn empty_similarity_root() -> [u8; 32] {
    h(Domain::SEmpty, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> GlobalRootInput {
        GlobalRootInput {
            dataset_id: "ds".into(),
            version: 3,
            p: 2,
            item_count: 10,
            occurrence_total: 12,
            tables: TableDigests::compute(&[], &[], &[]).unwrap(),
            item_root: [4; 32],
            similarity_root: empty_similarity_root(),
        }
    }

    #[test]
    fn global_root_binds_every_field() {
        let r = base().compute().unwrap();
        let mutants: Vec<(&str, GlobalRootInput)> = vec![
            (
                "dataset_id",
                GlobalRootInput {
                    dataset_id: "dt".into(),
                    ..base()
                },
            ),
            (
                "version",
                GlobalRootInput {
                    version: 4,
                    ..base()
                },
            ),
            ("p", GlobalRootInput { p: 3, ..base() }),
            (
                "item_count",
                GlobalRootInput {
                    item_count: 11,
                    ..base()
                },
            ),
            (
                "occurrence_total",
                GlobalRootInput {
                    occurrence_total: 13,
                    ..base()
                },
            ),
            (
                "item_root",
                GlobalRootInput {
                    item_root: [5; 32],
                    ..base()
                },
            ),
            (
                "similarity_root",
                GlobalRootInput {
                    similarity_root: [6; 32],
                    ..base()
                },
            ),
        ];
        for (name, m) in mutants {
            assert_ne!(m.compute().unwrap(), r, "{name} is not bound");
        }
        for slot in 0..3 {
            let mut m = base();
            let t = [
                &mut m.tables.extraction,
                &mut m.tables.profile,
                &mut m.tables.fp_profile,
            ];
            t[slot][0] ^= 1;
            assert_ne!(m.compute().unwrap(), r, "table digest {slot} is not bound");
        }
    }

    #[test]
    fn extraction_params_are_order_independent_but_values_are_bound() {
        let e = |params: Vec<(&str, &str)>| ExtractionEntry {
            id: "jsonl/field".into(),
            version: 1,
            implementation_id: "olympus-manifest=0.1.0".into(),
            params: params
                .into_iter()
                .map(|(a, b)| (a.into(), b.into()))
                .collect(),
        };
        let a =
            extraction_table_bytes(&[e(vec![("field", "/text"), ("uri_field", "/url")])]).unwrap();
        let b =
            extraction_table_bytes(&[e(vec![("uri_field", "/url"), ("field", "/text")])]).unwrap();
        assert_eq!(a, b);
        let c =
            extraction_table_bytes(&[e(vec![("field", "/body"), ("uri_field", "/url")])]).unwrap();
        assert_ne!(a, c);
        assert_eq!(
            extraction_table_bytes(&[e(vec![("field", "/a"), ("field", "/b")])]),
            Err(ContentError::DuplicateParam("field".into()))
        );
        assert_eq!(
            extraction_table_bytes(&[e(vec![("field", "")])]),
            Err(ContentError::EmptyField("param_value"))
        );
    }

    #[test]
    fn partition_exponent_above_16_is_rejected() {
        assert_eq!(
            GlobalRootInput { p: 17, ..base() }.compute(),
            Err(ContentError::BadPartitionExponent(17))
        );
    }
}
