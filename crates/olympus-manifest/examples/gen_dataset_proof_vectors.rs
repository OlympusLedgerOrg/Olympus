// SPDX-License-Identifier: Apache-2.0

//! Generate the shared compact exact-proof vectors (RFC-0000 §8, §13).
//! Run with:
//! cargo run -p olympus-manifest --example gen_dataset_proof_vectors > verifiers/test_vectors/dataset_compact_proof_vectors.json
//!
//! Every negative case states the rule it violates and the exact rejection.
//! The generator asserts that rejection before writing it, so a codec change
//! that rejects for a different reason fails here instead of being recorded.

use olympus_manifest::content::{
    commit::{content_digest, content_key, empty_fp_set_root, empty_meta_root, ItemPreimage},
    error::ContentError,
    tree::{empty_root, ItemTree, Terminal},
    wire::ExactProof,
    OpenedItem,
};
use serde_json::{json, Value};

type R<T> = Result<T, ContentError>;

fn preimage(content: &[u8]) -> ItemPreimage {
    ItemPreimage {
        profile_index: 0,
        canonical_len: content.len() as u64,
        content_digest: content_digest(content),
        fp_set_root: empty_fp_set_root(),
        occurrence_count: 1,
        meta_root: empty_meta_root(),
    }
}

fn raw_key(item: &ItemPreimage) -> R<[u8; 32]> {
    content_key("bytes/raw", 1, &item.content_digest)
}

struct Built {
    name: &'static str,
    p: u8,
    root: [u8; 32],
    proof: ExactProof,
    bytes: Vec<u8>,
    /// Whether the key is derived from `bytes/raw` v1 at profile index 0.
    content_derived: bool,
}

impl Built {
    fn new(name: &'static str, tree: &ItemTree, proof: ExactProof, derived: bool) -> R<Self> {
        let bytes = proof.encode(tree.p())?;
        Ok(Self {
            name,
            p: tree.p(),
            root: tree.root(),
            proof,
            bytes,
            content_derived: derived,
        })
    }

    fn statement(&self) -> (&'static str, [u8; 32], &'static str, usize) {
        match &self.proof {
            ExactProof::Membership(item) => ("M1-open", item.key, "leaf", item.path.siblings.len()),
            ExactProof::NonMembership { key, path } => {
                let terminal = match path.terminal {
                    Terminal::Empty => "empty",
                    Terminal::Leaf { .. } => "neighbor",
                };
                ("N1", *key, terminal, path.siblings.len())
            }
        }
    }

    /// Offset of `u64_be(partition_count)` in the encoded body.
    fn path_offset(&self) -> usize {
        match &self.proof {
            ExactProof::Membership(_) => 1 + 32 + 114,
            ExactProof::NonMembership { path, .. } => match path.terminal {
                Terminal::Empty => 1 + 32 + 1,
                Terminal::Leaf { .. } => 1 + 32 + 1 + 64,
            },
        }
    }

    fn bitmap_offset(&self) -> usize {
        self.path_offset() + 8 + 2
    }

    fn depth(&self) -> usize {
        self.statement().3
    }

    fn json(&self) -> Value {
        let (statement, key, terminal, depth) = self.statement();
        json!({
            "name": self.name,
            "p": self.p,
            "item_root": hex::encode(self.root),
            "statement": statement,
            "query_key": hex::encode(key),
            "terminal": terminal,
            "depth": depth,
            "top_siblings": self.p,
            "content_key_profile": if self.content_derived { json!("bytes/raw/1") } else { Value::Null },
            "proof": hex::encode(&self.bytes),
        })
    }
}

fn decode_err(p: u8, bytes: &[u8]) -> ContentError {
    ExactProof::decode(p, bytes).expect_err("negative vector decoded")
}

fn verify_err(p: u8, root: &[u8; 32], bytes: &[u8]) -> ContentError {
    use olympus_manifest::content::tree::{verify_membership, verify_non_membership};
    match ExactProof::decode(p, bytes).expect("verify-stage vector must decode") {
        ExactProof::Membership(item) => {
            verify_membership(p, root, &item.key, &item.path).expect_err("verified")
        }
        ExactProof::NonMembership { key, path } => {
            verify_non_membership(p, root, &key, &path).expect_err("verified")
        }
    }
}

struct Negatives(Vec<Value>);

impl Negatives {
    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        name: &str,
        rule: &str,
        stage: &str,
        p: u8,
        root: &[u8; 32],
        bytes: &[u8],
        expected: ContentError,
    ) {
        let got = match stage {
            "decode" => decode_err(p, bytes),
            "verify" => verify_err(p, root, bytes),
            _ => unreachable!(),
        };
        assert_eq!(got, expected, "{name}: rejected for the wrong reason");
        self.0.push(json!({
            "name": name,
            "rule": rule,
            "stage": stage,
            "p": p,
            "item_root": hex::encode(root),
            "proof": hex::encode(bytes),
            "error": format!("{expected:?}"),
        }));
    }
}

fn main() -> R<()> {
    // Empty tree: N1 with terminal E at depth 0.
    let empty = ItemTree::build(0, vec![])?;
    let query = raw_key(&preimage(b"absent"))?;
    let n1_empty_d0 = Built::new(
        "n1-empty-terminal-depth-0",
        &empty,
        ExactProof::NonMembership {
            key: query,
            path: empty.path(&query),
        },
        true,
    )?;

    // One item: M1-open at depth 0 and N1 with its neighbor at depth 0.
    let only = preimage(b"only item");
    let only_key = raw_key(&only)?;
    let single = ItemTree::build(0, vec![(only_key, only.commitment())])?;
    let m1_d0 = Built::new(
        "m1-open-depth-0",
        &single,
        ExactProof::Membership(OpenedItem {
            key: only_key,
            path: single.path(&only_key),
            preimage: only,
        }),
        true,
    )?;
    let n1_neighbor_d0 = Built::new(
        "n1-neighbor-terminal-depth-0",
        &single,
        ExactProof::NonMembership {
            key: query,
            path: single.path(&query),
        },
        true,
    )?;

    // Two keys that differ only in the last bit: M1-open at depth 256, and an
    // N1 at depth 255 whose 254 omitted siblings are all E. These keys are
    // not content-derived, so the vectors check the tree fold only.
    let left = [0u8; 32];
    let mut right = left;
    right[31] = 1;
    let (left_item, right_item) = (preimage(b"left"), preimage(b"right"));
    let deep = ItemTree::build(
        0,
        vec![
            (left, left_item.commitment()),
            (right, right_item.commitment()),
        ],
    )?;
    let m1_d256 = Built::new(
        "m1-open-depth-256",
        &deep,
        ExactProof::Membership(OpenedItem {
            key: left,
            path: deep.path(&left),
            preimage: left_item,
        }),
        false,
    )?;
    let mut sparse_query = left;
    sparse_query[31] = 2;
    let n1_omitted = Built::new(
        "n1-empty-terminal-omitted-empty-siblings",
        &deep,
        ExactProof::NonMembership {
            key: sparse_query,
            path: deep.path(&sparse_query),
        },
        false,
    )?;
    assert_eq!(m1_d256.depth(), 256);
    assert_eq!(n1_omitted.depth(), 255);

    // p = 2 with 64 content-derived items: every answer carries two nonzero
    // top-tree siblings.
    let items: Vec<_> = (0..64u32)
        .map(|i| preimage(format!("item {i}").as_bytes()))
        .collect();
    let leaves = items
        .iter()
        .map(|item| Ok((raw_key(item)?, item.commitment())))
        .collect::<R<Vec<_>>>()?;
    let part = ItemTree::build(2, leaves)?;
    let member = items[7];
    let member_key = raw_key(&member)?;
    let m1_top = Built::new(
        "m1-open-nonzero-top-path",
        &part,
        ExactProof::Membership(OpenedItem {
            key: member_key,
            path: part.path(&member_key),
            preimage: member,
        }),
        true,
    )?;
    let absent_with = |want_leaf: bool| -> R<[u8; 32]> {
        for i in 0u32.. {
            let key = raw_key(&preimage(format!("absent {i}").as_bytes()))?;
            if matches!(part.path(&key).terminal, Terminal::Leaf { .. }) == want_leaf {
                return Ok(key);
            }
        }
        unreachable!()
    };
    let neighbor_query = absent_with(true)?;
    let n1_top_neighbor = Built::new(
        "n1-neighbor-terminal-nonzero-top-path",
        &part,
        ExactProof::NonMembership {
            key: neighbor_query,
            path: part.path(&neighbor_query),
        },
        true,
    )?;
    let empty_query = absent_with(false)?;
    let n1_top_empty = Built::new(
        "n1-empty-terminal-nonzero-top-path",
        &part,
        ExactProof::NonMembership {
            key: empty_query,
            path: part.path(&empty_query),
        },
        true,
    )?;
    for built in [&m1_top, &n1_top_neighbor, &n1_top_empty] {
        let top = &built.bytes[built.bytes.len() - 64..];
        assert!(top.chunks(32).all(|s| s != empty_root()));
    }

    let positives = [
        &n1_empty_d0,
        &m1_d0,
        &n1_neighbor_d0,
        &m1_d256,
        &n1_omitted,
        &m1_top,
        &n1_top_neighbor,
        &n1_top_empty,
    ];

    let mut neg = Negatives(Vec::new());
    let invalid = |reason| ContentError::InvalidProofEncoding(reason);

    let mut b = m1_top.bytes.clone();
    b[0] = 9;
    neg.push(
        "unknown-statement-tag",
        "§8: reject unknown tags",
        "decode",
        2,
        &m1_top.root,
        &b,
        invalid("unknown statement"),
    );

    let mut b = n1_top_empty.bytes.clone();
    b[33] = 2;
    neg.push(
        "unknown-terminal-tag",
        "§8: reject unknown tags",
        "decode",
        2,
        &n1_top_empty.root,
        &b,
        invalid("unknown terminal"),
    );

    let padded = positives
        .iter()
        .find(|v| v.depth() % 8 != 0)
        .expect("a depth that leaves bitmap padding");
    let mut b = padded.bytes.clone();
    let last = padded.bitmap_offset() + padded.depth().div_ceil(8) - 1;
    b[last] |= 1;
    neg.push(
        "nonzero-bitmap-padding",
        "§8: reject nonzero unused bitmap bits",
        "decode",
        padded.p,
        &padded.root,
        &b,
        invalid("nonzero bitmap padding"),
    );

    // n1_omitted's level 0 is E and its bit is clear; set it and supply E.
    let mut b = n1_omitted.bytes.clone();
    let bitmap = n1_omitted.bitmap_offset();
    assert_eq!(b[bitmap] & 0x80, 0);
    b[bitmap] |= 0x80;
    let hashes = bitmap + n1_omitted.depth().div_ceil(8);
    b.splice(hashes..hashes, empty_root());
    neg.push(
        "explicit-empty-sibling",
        "§8: reject explicit E at a set bit",
        "decode",
        0,
        &n1_omitted.root,
        &b,
        invalid("explicit empty sibling"),
    );

    let mut b = m1_top.bytes.clone();
    let depth_at = m1_top.path_offset() + 8;
    b[depth_at..depth_at + 2].copy_from_slice(&255u16.to_be_bytes());
    neg.push(
        "depth-beyond-256-minus-p",
        "§4/§8: depth at most 256 - p",
        "decode",
        2,
        &m1_top.root,
        &b,
        ContentError::DepthOutOfRange {
            depth: 255,
            max: 254,
        },
    );

    neg.push(
        "partition-exponent-above-16",
        "§5: 0 <= p <= 16",
        "decode",
        17,
        &n1_empty_d0.root,
        &n1_empty_d0.bytes,
        ContentError::BadPartitionExponent(17),
    );

    let mut b = n1_neighbor_d0.bytes.clone();
    b.copy_within(34..66, 1);
    neg.push(
        "n1-neighbor-equals-query",
        "§8: an N1 neighbor must differ from the query key",
        "decode",
        0,
        &n1_neighbor_d0.root,
        &b,
        ContentError::IsAMember,
    );

    // Truncation at representative cut points of a body with every field.
    let full = &m1_top.bytes;
    let bitmap = m1_top.bitmap_offset();
    let hashes = bitmap + m1_top.depth().div_ceil(8);
    for (name, cut, reason) in [
        ("truncated-empty", 0, "truncated field"),
        ("truncated-in-key", 17, "truncated field"),
        ("truncated-in-preimage", 1 + 32 + 50, "truncated field"),
        (
            "truncated-in-partition-count",
            m1_top.path_offset() + 3,
            "truncated field",
        ),
        ("truncated-before-bitmap", bitmap, "truncated bitmap"),
        ("truncated-in-sibling", hashes + 5, "truncated field"),
        (
            "truncated-in-top-sibling",
            full.len() - 40,
            "truncated field",
        ),
        ("truncated-last-byte", full.len() - 1, "truncated field"),
    ] {
        neg.push(
            name,
            "§8: reject missing bytes",
            "decode",
            2,
            &m1_top.root,
            &full[..cut],
            invalid(reason),
        );
    }

    let mut b = m1_top.bytes.clone();
    b.push(0);
    neg.push(
        "appended-byte",
        "§8: reject trailing bytes",
        "decode",
        2,
        &m1_top.root,
        &b,
        invalid("trailing bytes"),
    );

    // Verify-stage rejections: the body is canonical but does not fold.
    let mut b = m1_top.bytes.clone();
    b[hashes] ^= 1;
    neg.push(
        "wrong-root",
        "§8: fold to the authenticated item_root",
        "verify",
        2,
        &m1_top.root,
        &b,
        ContentError::RootMismatch,
    );

    let mut b = n1_top_neighbor.bytes.clone();
    b[34] ^= 0x80;
    neg.push(
        "neighbor-prefix-mismatch",
        "§4: prefix check",
        "verify",
        2,
        &n1_top_neighbor.root,
        &b,
        ContentError::PrefixMismatch,
    );

    // Clear the deepest sibling's bit and drop its hash, leaving E beside the
    // terminal.
    let d = m1_top.depth();
    let mut b = m1_top.bytes.clone();
    let bit_byte = bitmap + (d - 1) / 8;
    let mask = 0x80 >> ((d - 1) % 8);
    assert_ne!(b[bit_byte] & mask, 0);
    b[bit_byte] &= !mask;
    let last_sibling = full.len() - 64 - 32;
    b.drain(last_sibling..last_sibling + 32);
    neg.push(
        "noncanonical-shape",
        "§4: canonical shape where visible",
        "verify",
        2,
        &m1_top.root,
        &b,
        ContentError::NonCanonicalShape,
    );

    let out = json!({
        "format": "olympus-dataset-proof/v1 compact exact bodies",
        "generator": "cargo run -p olympus-manifest --example gen_dataset_proof_vectors",
        "note": "Positive bodies decode, re-encode byte for byte and fold to item_root. Negative bodies must be rejected at `stage` with exactly `error` (Rust ContentError Debug form).",
        "positive": positives.iter().map(|v| v.json()).collect::<Vec<_>>(),
        "negative": neg.0,
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
    Ok(())
}
