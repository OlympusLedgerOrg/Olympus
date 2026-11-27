// SPDX-License-Identifier: Apache-2.0

//! Compact v1 single-proof bodies. The enclosing bundle supplies the verified
//! header and selects this wire version. Decoding alone does not verify a proof.

use super::commit::{promoted_sibling_count, ItemPreimage};
use super::dataset::{M2Proof, OpenedItem};
use super::error::{ContentError, Result};
use super::fingerprint::FpProfile;
use super::tree::{empty_root, fold_item_path, ItemPath, Terminal};
use super::version::FpProfileEntry;

const M1_OPEN: u8 = 1;
const N1: u8 = 2;
const M2: u8 = 3;

impl M2Proof {
    /// `M2 = u8(3) ‖ lp(M1-open) ‖ u16_be(fp_profile_index) ‖ u32_be(segment_index)
    /// ‖ u32_be(leaf_index) ‖ u32_be(leaf_count) ‖ candidate_fingerprint ‖ fingerprint_siblings`.
    pub fn encode(&self, p: u8) -> Result<Vec<u8>> {
        if self.leaf_index >= self.leaf_count {
            return Err(ContentError::FpPositionOutOfRange {
                j: self.leaf_index,
                n: self.leaf_count,
            });
        }
        let expected = promoted_sibling_count(self.leaf_index.into(), self.leaf_count.into());
        if expected != self.fp_path.len() {
            return Err(ContentError::FpPathLength {
                expected,
                got: self.fp_path.len(),
            });
        }
        let inner = ExactProof::Membership(self.item.clone()).encode(p)?;
        let inner_len =
            u32::try_from(inner.len()).map_err(|_| ContentError::FieldTooLong("M1-open"))?;
        let mut bytes = Vec::with_capacity(
            1 + 4 + inner.len() + 14 + self.fingerprint.len() + 32 * self.fp_path.len(),
        );
        bytes.push(M2);
        bytes.extend_from_slice(&inner_len.to_be_bytes());
        bytes.extend_from_slice(&inner);
        bytes.extend_from_slice(&self.fp_profile_index.to_be_bytes());
        bytes.extend_from_slice(&self.segment_index.to_be_bytes());
        bytes.extend_from_slice(&self.leaf_index.to_be_bytes());
        bytes.extend_from_slice(&self.leaf_count.to_be_bytes());
        bytes.extend_from_slice(&self.fingerprint);
        for s in &self.fp_path {
            bytes.extend_from_slice(s);
        }
        Ok(bytes)
    }

    /// Decode a complete M2 body. The authenticated header's fingerprint
    /// table fixes the fingerprint width; the sibling count comes from
    /// `(leaf_index, leaf_count)`. Rejects every noncanonical encoding.
    pub fn decode(p: u8, fp_table: &[FpProfileEntry], mut bytes: &[u8]) -> Result<Self> {
        let [kind] = take(&mut bytes)?;
        if kind != M2 {
            return Err(ContentError::InvalidProofEncoding("unknown statement"));
        }
        let inner_len = u32::from_be_bytes(take(&mut bytes)?) as usize;
        let (inner, rest) = bytes
            .split_at_checked(inner_len)
            .ok_or(ContentError::InvalidProofEncoding("truncated field"))?;
        bytes = rest;
        let ExactProof::Membership(item) = ExactProof::decode(p, inner)? else {
            return Err(ContentError::InvalidProofEncoding(
                "M2 must carry an M1-open body",
            ));
        };
        let fp_profile_index = u16::from_be_bytes(take(&mut bytes)?);
        let segment_index = u32::from_be_bytes(take(&mut bytes)?);
        let leaf_index = u32::from_be_bytes(take(&mut bytes)?);
        let leaf_count = u32::from_be_bytes(take(&mut bytes)?);
        if leaf_index >= leaf_count {
            return Err(ContentError::FpPositionOutOfRange {
                j: leaf_index,
                n: leaf_count,
            });
        }
        let row = fp_table
            .get(usize::from(fp_profile_index))
            .ok_or(ContentError::UnknownFpIndex(fp_profile_index))?;
        let width = FpProfile::from_entry(row)?.width();
        let (fingerprint, rest) = bytes
            .split_at_checked(width)
            .ok_or(ContentError::InvalidProofEncoding("truncated field"))?;
        bytes = rest;
        let fp_path = (0..promoted_sibling_count(leaf_index.into(), leaf_count.into()))
            .map(|_| take(&mut bytes))
            .collect::<Result<Vec<_>>>()?;
        if !bytes.is_empty() {
            return Err(ContentError::InvalidProofEncoding("trailing bytes"));
        }
        Ok(Self {
            item,
            fp_profile_index,
            segment_index,
            leaf_index,
            leaf_count,
            fingerprint: fingerprint.to_vec(),
            fp_path,
        })
    }
}

/// One compact exact proof. Compare its key with the intended query and pass
/// it to the dataset verifier against the authenticated header after decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactProof {
    /// Membership with the item commitment preimage.
    Membership(OpenedItem),
    /// Non-membership at the queried key.
    NonMembership {
        /// Queried content key.
        key: [u8; 32],
        /// Empty or neighboring-leaf path.
        path: ItemPath,
    },
}

impl ExactProof {
    /// Encode a single proof body using the header's partition exponent.
    pub fn encode(&self, p: u8) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Membership(item) => {
                if item.path.terminal
                    != (Terminal::Leaf {
                        key: item.key,
                        commitment: item.preimage.commitment(),
                    })
                {
                    return Err(ContentError::CommitmentMismatch);
                }
                bytes.push(M1_OPEN);
                bytes.extend_from_slice(&item.key);
                bytes.extend_from_slice(&item.preimage.to_bytes());
                encode_path(&mut bytes, p, &item.key, &item.path)?;
            }
            Self::NonMembership { key, path } => {
                bytes.push(N1);
                bytes.extend_from_slice(key);
                match path.terminal {
                    Terminal::Empty => bytes.push(0),
                    Terminal::Leaf {
                        key: neighbor,
                        commitment,
                    } => {
                        if &neighbor == key {
                            return Err(ContentError::IsAMember);
                        }
                        bytes.push(1);
                        bytes.extend_from_slice(&neighbor);
                        bytes.extend_from_slice(&commitment);
                    }
                }
                encode_path(&mut bytes, p, key, path)?;
            }
        }
        Ok(bytes)
    }

    /// Decode a complete single proof body, rejecting noncanonical encodings.
    pub fn decode(p: u8, mut bytes: &[u8]) -> Result<Self> {
        let [kind] = take(&mut bytes)?;
        let key = take(&mut bytes)?;
        let proof = match kind {
            M1_OPEN => {
                let preimage = ItemPreimage {
                    profile_index: u16::from_be_bytes(take(&mut bytes)?),
                    canonical_len: u64::from_be_bytes(take(&mut bytes)?),
                    content_digest: take(&mut bytes)?,
                    fp_set_root: take(&mut bytes)?,
                    occurrence_count: u64::from_be_bytes(take(&mut bytes)?),
                    meta_root: take(&mut bytes)?,
                };
                let terminal = Terminal::Leaf {
                    key,
                    commitment: preimage.commitment(),
                };
                let path = decode_path(&mut bytes, p, terminal)?;
                Self::Membership(OpenedItem {
                    key,
                    path,
                    preimage,
                })
            }
            N1 => {
                let terminal = match take(&mut bytes)? {
                    [0] => Terminal::Empty,
                    [1] => {
                        let neighbor = take(&mut bytes)?;
                        if neighbor == key {
                            return Err(ContentError::IsAMember);
                        }
                        Terminal::Leaf {
                            key: neighbor,
                            commitment: take(&mut bytes)?,
                        }
                    }
                    _ => return Err(ContentError::InvalidProofEncoding("unknown terminal")),
                };
                let path = decode_path(&mut bytes, p, terminal)?;
                Self::NonMembership { key, path }
            }
            _ => return Err(ContentError::InvalidProofEncoding("unknown statement")),
        };
        if !bytes.is_empty() {
            return Err(ContentError::InvalidProofEncoding("trailing bytes"));
        }
        Ok(proof)
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let (prefix, rest) = bytes
        .split_at_checked(N)
        .ok_or(ContentError::InvalidProofEncoding("truncated field"))?;
    *bytes = rest;
    Ok(prefix.try_into().expect("prefix is exactly N bytes"))
}

fn encode_path(bytes: &mut Vec<u8>, p: u8, key: &[u8; 32], path: &ItemPath) -> Result<()> {
    // Reuse the verifier's depth, prefix, and hoisting checks.
    fold_item_path(p, key, path)?;
    let depth = path.siblings.len();
    bytes.extend_from_slice(&path.partition_count.to_be_bytes());
    bytes.extend_from_slice(&(depth as u16).to_be_bytes());
    let bitmap_offset = bytes.len();
    bytes.resize(bitmap_offset + depth.div_ceil(8), 0);
    let empty = empty_root();
    for (level, sibling) in path.siblings.iter().enumerate() {
        if *sibling != empty {
            bytes[bitmap_offset + level / 8] |= 0x80 >> (level % 8);
            bytes.extend_from_slice(sibling);
        }
    }
    for sibling in &path.top_siblings {
        bytes.extend_from_slice(sibling);
    }
    Ok(())
}

fn decode_path(bytes: &mut &[u8], p: u8, terminal: Terminal) -> Result<ItemPath> {
    if p > 16 {
        return Err(ContentError::BadPartitionExponent(p));
    }
    let partition_count = u64::from_be_bytes(take(bytes)?);
    let depth = usize::from(u16::from_be_bytes(take(bytes)?));
    let max = 256 - usize::from(p);
    if depth > max {
        return Err(ContentError::DepthOutOfRange { depth, max });
    }
    let (bitmap, rest) = bytes
        .split_at_checked(depth.div_ceil(8))
        .ok_or(ContentError::InvalidProofEncoding("truncated bitmap"))?;
    *bytes = rest;
    let used_bits = depth % 8;
    if used_bits != 0 && bitmap[bitmap.len() - 1] & (0xff >> used_bits) != 0 {
        return Err(ContentError::InvalidProofEncoding("nonzero bitmap padding"));
    }
    let empty = empty_root();
    let mut siblings = Vec::with_capacity(depth);
    for level in 0..depth {
        if bitmap[level / 8] & (0x80 >> (level % 8)) == 0 {
            siblings.push(empty);
        } else {
            let sibling = take(bytes)?;
            if sibling == empty {
                return Err(ContentError::InvalidProofEncoding("explicit empty sibling"));
            }
            siblings.push(sibling);
        }
    }
    let top_siblings = (0..p).map(|_| take(bytes)).collect::<Result<_>>()?;
    Ok(ItemPath {
        siblings,
        terminal,
        partition_count,
        top_siblings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::tree::{verify_non_membership, ItemTree};

    #[test]
    fn empty_and_maximum_depth_paths_round_trip() {
        let empty = ItemTree::build(0, vec![]).unwrap();
        let left = [0; 32];
        let mut right = left;
        right[31] = 1;
        let tree = ItemTree::build(0, vec![(left, [1; 32]), (right, [2; 32])]).unwrap();
        let mut neighbor_query = left;
        neighbor_query[31] = 2;
        let deep = tree.path(&neighbor_query);
        assert_eq!(deep.siblings.len(), 255);
        assert!(matches!(deep.terminal, Terminal::Empty));

        let max = tree.path(&left);
        assert_eq!(max.siblings.len(), 256);
        let mut encoded_path = Vec::new();
        encode_path(&mut encoded_path, 0, &left, &max).unwrap();
        assert_eq!(encoded_path.len(), 10 + 32 + 32);
        assert_eq!(encoded_path[41], 1);
        assert_eq!(
            decode_path(&mut &encoded_path[..], 0, max.terminal).unwrap(),
            max
        );

        for (tree, key) in [(&empty, left), (&tree, neighbor_query)] {
            let proof = ExactProof::NonMembership {
                key,
                path: tree.path(&key),
            };
            let encoded = proof.encode(0).unwrap();
            let decoded = ExactProof::decode(0, &encoded).unwrap();
            assert_eq!(decoded, proof);
            let ExactProof::NonMembership { key, path } = decoded else {
                unreachable!();
            };
            verify_non_membership(0, &tree.root(), &key, &path).unwrap();
        }
    }

    #[test]
    fn rejects_noncanonical_bytes_and_wrong_root() {
        let member = [0; 32];
        let mut other = member;
        other[0] = 0x80;
        let tree = ItemTree::build(0, vec![(member, [1; 32]), (other, [2; 32])]).unwrap();
        let mut key = member;
        key[31] = 1;
        let proof = ExactProof::NonMembership {
            key,
            path: tree.path(&key),
        };
        let bytes = proof.encode(0).unwrap();
        let bitmap = 1 + 32 + 1 + 64 + 8 + 2;
        assert_eq!(bytes[bitmap], 0x80);

        let mut changed = bytes.clone();
        changed[bitmap] |= 1;
        assert_eq!(
            ExactProof::decode(0, &changed),
            Err(ContentError::InvalidProofEncoding("nonzero bitmap padding"))
        );
        changed[bitmap] &= 0x80;
        changed[bitmap + 1..].copy_from_slice(&empty_root());
        assert_eq!(
            ExactProof::decode(0, &changed),
            Err(ContentError::InvalidProofEncoding("explicit empty sibling"))
        );

        for length in 0..bytes.len() {
            assert!(ExactProof::decode(0, &bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            ExactProof::decode(0, &extra),
            Err(ContentError::InvalidProofEncoding("trailing bytes"))
        );
        extra[0] = 99;
        assert_eq!(
            ExactProof::decode(0, &extra),
            Err(ContentError::InvalidProofEncoding("unknown statement"))
        );

        let mut changed = bytes;
        changed[bitmap + 1] ^= 1;
        let ExactProof::NonMembership { key, path } = ExactProof::decode(0, &changed).unwrap()
        else {
            unreachable!();
        };
        assert_eq!(
            verify_non_membership(0, &tree.root(), &key, &path),
            Err(ContentError::RootMismatch)
        );
    }
}
