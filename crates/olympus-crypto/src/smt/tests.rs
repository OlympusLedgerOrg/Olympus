use super::*;

fn rk(b: u8) -> [u8; 32] {
    [b; 32]
}

#[test]
fn shard_prefix_width_constants_are_pinned() {
    assert_eq!(SHARD_PREFIX_BYTES, 8);
    assert_eq!(SHARD_PREFIX_BITS, 64);
    assert_eq!(SHARD_PREFIX_BITS, SHARD_PREFIX_BYTES * 8);
}

#[test]
fn shard_prefix_is_key_high_bits() {
    let key = shard_record_key("shard-a", &rk(0x11));
    assert_eq!(key[..SHARD_PREFIX_BYTES], shard_prefix("shard-a"));
    assert_eq!(
        key[SHARD_PREFIX_BYTES..],
        rk(0x11)[..32 - SHARD_PREFIX_BYTES]
    );
    // Different shards → different prefixes for the same record_key.
    let key_b = shard_record_key("shard-b", &rk(0x11));
    assert_ne!(key[..SHARD_PREFIX_BYTES], key_b[..SHARD_PREFIX_BYTES]);
}

#[test]
fn shard_id_matches_key_links_shard_to_prefix() {
    // ADR-0005 authority predicate: true iff key[..8] == shard_prefix(shard_id).
    let key = shard_record_key("shard-a", &rk(0x55));
    assert!(shard_id_matches_key("shard-a", &key));
    assert!(!shard_id_matches_key("shard-b", &key));
}

#[test]
fn key_path_roundtrip_preserves_bit_order() {
    let mut key = [0u8; 32];
    key[0] = 0b1000_0001;
    key[17] = 0b0101_0000;
    key[31] = 0b0000_0001;
    let path = key_to_path_bits(&key);
    assert_eq!(path.len(), SMT_DEPTH);
    assert_eq!(&path[..8], &[1, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(path_to_key(&path), key);
}

#[test]
fn empty_subtree_hash_ladder_is_domain_separated() {
    assert_eq!(empty_subtree_hash(0), empty_leaf());
    assert_eq!(
        empty_subtree_hash(1),
        node_hash(&empty_leaf(), &empty_leaf())
    );
    assert_ne!(empty_subtree_hash(0), [0u8; 32]);
    assert_ne!(empty_subtree_hash(0), empty_subtree_hash(1));
    assert_ne!(empty_subtree_hash(SMT_DEPTH), [0u8; 32]);
}

#[test]
fn verify_rejects_shard_id_not_matching_key() {
    // A proof whose shard_id doesn't hash to the key's prefix must be
    // rejected even though everything else is well-formed (ADR-0005).
    let mut t = SparseMerkleTree::new();
    let ka = shard_record_key("shard-a", &rk(1));
    t.update(ka, rk(0xAA), "shard-a", "p", "v1", "m1");
    let root = t.root();
    let Proof::Existence(p) = t.prove(&ka) else {
        panic!("expected existence proof")
    };
    assert!(verify_existence_proof(&p, Some(&root)));
    let mut mismatched = p.clone();
    mismatched.shard_id = "shard-b".to_string();
    assert!(!verify_existence_proof(&mismatched, Some(&root)));
}

#[test]
fn get_returns_stored_value_or_none() {
    let mut t = SparseMerkleTree::new();
    let ka = shard_record_key("shard-a", &rk(1));
    t.update(ka, rk(0xAB), "shard-a", "p", "v1", "m1");
    // Present key returns its stored value_hash (not None, not a constant).
    assert_eq!(t.get(&ka), Some(rk(0xAB)));
    // Absent key returns None.
    assert_eq!(t.get(&shard_record_key("shard-a", &rk(2))), None);
}

#[test]
fn len_and_is_empty_track_leaf_count() {
    let mut t = SparseMerkleTree::new();
    assert_eq!(t.len(), 0);
    assert!(t.is_empty());

    let ka = shard_record_key("shard-a", &rk(1));
    let kb = shard_record_key("shard-a", &rk(2));
    t.update(ka, rk(0xAB), "shard-a", "p", "v1", "m1");
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());

    t.update(ka, rk(0xCD), "shard-a", "p", "v1", "m1");
    assert_eq!(t.len(), 1, "overwriting a key must not add a leaf");
    t.update(kb, rk(0xEF), "shard-a", "p", "v1", "m1");
    assert_eq!(t.len(), 2);
}

#[test]
fn node_count_grows_with_inserts_and_overwrite_is_free() {
    let mut t = SparseMerkleTree::new();
    // Empty tree materialises no nodes.
    assert_eq!(t.node_count(), 0);

    let ka = shard_record_key("shard-a", &rk(1));
    t.update(ka, rk(0xAA), "shard-a", "p", "v1", "m1");
    // A lone leaf writes one node per level along its path.
    assert_eq!(t.node_count(), SMT_DEPTH);

    // Overwriting the same key rewrites the same node paths — no growth.
    t.update(ka, rk(0xBB), "shard-a", "p", "v1", "m1");
    assert_eq!(t.node_count(), SMT_DEPTH);

    // A second, distinct key adds nodes only below the depth where its path
    // diverges from the first, so the tree grows by strictly less than a
    // full SMT_DEPTH but by at least one node.
    let kb = shard_record_key("shard-b", &rk(2));
    let before = t.node_count();
    t.update(kb, rk(0xCC), "shard-b", "p", "v1", "m1");
    let grew = t.node_count() - before;
    assert!((1..=SMT_DEPTH).contains(&grew), "unexpected growth: {grew}");
}

#[test]
fn root_prefers_materialised_root_when_nodes_exist() {
    let mut t = SparseMerkleTree::new();
    let root = [0x5Au8; 32];
    t.nodes.insert(Vec::new(), root);

    assert_eq!(t.root(), root);
}

#[test]
fn heap_bytes_estimate_zero_when_empty_then_positive() {
    fn expected_heap_bytes(t: &SparseMerkleTree) -> usize {
        const ENTRY_OVERHEAD: usize = 16;
        let node_bytes = t
            .nodes
            .keys()
            .map(|path| path.capacity() + 32 + ENTRY_OVERHEAD)
            .sum::<usize>();
        let leaf_bytes = t
            .leaves
            .values()
            .map(|(_value_hash, shard_id, parser_id, cpv, model_hash)| {
                32 + 32
                    + shard_id.capacity()
                    + parser_id.capacity()
                    + cpv.capacity()
                    + model_hash.capacity()
                    + ENTRY_OVERHEAD
            })
            .sum::<usize>();
        node_bytes + leaf_bytes
    }

    let mut t = SparseMerkleTree::new();
    // Nothing stored → nothing counted.
    assert_eq!(t.heap_bytes_estimate(), 0);

    let ka = shard_record_key("shard-a", &rk(7));
    t.update(ka, rk(0x42), "shard-a", "parser", "v1", "model");
    // A populated tree reports a strictly positive, leaf-dominated estimate.
    let one = t.heap_bytes_estimate();
    assert!(one > 0);
    assert_eq!(one, expected_heap_bytes(&t));

    // Adding another leaf can only increase the estimate.
    let kb = shard_record_key("shard-b", &rk(9));
    t.update(kb, rk(0x43), "shard-b", "parser", "v1", "model");
    let two = t.heap_bytes_estimate();
    assert!(two > one);
    assert_eq!(two, expected_heap_bytes(&t));
}

/// Build the self-consistent existence proof for a *lone* leaf at `key`
/// (every sibling is the empty-subtree hash for its level), folding with
/// the field values given. Because the proof folds to its own `root_hash`,
/// a test can hand it an empty provenance field (or a wrong sibling count)
/// and the only reason to reject is `verify_existence_proof`'s input guard
/// — which makes the guard observably distinct from a mutated `&&` that
/// would fall through to the (passing) hash check.
fn lone_leaf_proof(
    shard: &str,
    key: [u8; 32],
    value: [u8; 32],
    parser: &str,
    cpv: &str,
    model: &str,
) -> ExistenceProof {
    let siblings: Vec<[u8; 32]> = (0..SMT_DEPTH).map(empty_subtree_hash).collect();
    let path = key_to_path_bits(&key);
    let mut current = leaf_hash(
        shard.as_bytes(),
        &key,
        &value,
        parser.as_bytes(),
        cpv.as_bytes(),
        model.as_bytes(),
    );
    for (level, sib) in siblings.iter().enumerate() {
        let bit_pos = SMT_DEPTH - 1 - level;
        current = if path[bit_pos] == 0 {
            node_hash(&current, sib)
        } else {
            node_hash(sib, &current)
        };
    }
    ExistenceProof {
        key,
        value_hash: value,
        shard_id: shard.to_string(),
        parser_id: parser.to_string(),
        canonical_parser_version: cpv.to_string(),
        model_hash: model.to_string(),
        siblings,
        root_hash: current,
    }
}

#[test]
fn verify_guards_reject_self_consistent_but_invalid_proofs() {
    // A fully-valid lone-leaf proof verifies (equals what `prove` emits).
    let k = shard_record_key("shard-a", &rk(1));
    assert!(verify_existence_proof(
        &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", "m1"),
        None
    ));

    // Empty parser/cpv/model: the proof still folds to its own root, so the
    // ONLY reason to reject is the empty-field guard — distinguishing the
    // `||` chain from a mutated `&&` that would fall through and accept.
    assert!(!verify_existence_proof(
        &lone_leaf_proof("shard-a", k, rk(0xAA), "", "v1", "m1"),
        None
    ));
    assert!(!verify_existence_proof(
        &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "", "m1"),
        None
    ));
    assert!(!verify_existence_proof(
        &lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", ""),
        None
    ));

    // Empty shard_id: build the key from "" so shard_id_matches_key passes
    // and the empty-shard guard is the sole discriminator.
    let k0 = shard_record_key("", &rk(1));
    assert!(!verify_existence_proof(
        &lone_leaf_proof("", k0, rk(0xAA), "p", "v1", "m1"),
        None
    ));

    // Wrong sibling count (257): fold_to_root `.take(256)`s, so it still
    // reconstructs the root — only the length guard rejects it (a 255-count
    // proof, by contrast, also fails the fold, so it can't distinguish).
    let mut extra = lone_leaf_proof("shard-a", k, rk(0xAA), "p", "v1", "m1");
    extra.siblings.push([0u8; 32]);
    assert_eq!(extra.siblings.len(), SMT_DEPTH + 1);
    assert!(!verify_existence_proof(&extra, None));
}

#[test]
fn existence_roundtrip_verifies() {
    let mut t = SparseMerkleTree::new();
    let ka = shard_record_key("shard-a", &rk(1));
    let kb = shard_record_key("shard-a", &rk(2));
    t.update(ka, rk(0xAA), "shard-a", "docling@2.3.1", "v1", "m1");
    t.update(kb, rk(0xBB), "shard-a", "docling@2.3.1", "v1", "m1");
    let root = t.root();
    for key in [ka, kb] {
        match t.prove(&key) {
            Proof::Existence(p) => assert!(verify_existence_proof(&p, Some(&root))),
            _ => panic!("expected existence proof"),
        }
    }
}

#[test]
fn nonexistence_verifies() {
    let mut t = SparseMerkleTree::new();
    t.update(
        shard_record_key("shard-a", &rk(1)),
        rk(0xAA),
        "shard-a",
        "p",
        "v1",
        "m1",
    );
    let root = t.root();
    let absent = shard_record_key("shard-a", &rk(9));
    match t.prove(&absent) {
        Proof::NonExistence(p) => assert!(verify_nonexistence_proof(&p, Some(&root))),
        _ => panic!("expected non-existence proof"),
    }
}

#[test]
fn verify_proof_dispatches_both_variants() {
    let mut t = SparseMerkleTree::new();
    let present = shard_record_key("s", &rk(1));
    let absent = shard_record_key("s", &rk(9));
    t.update(present, rk(0xAA), "s", "p", "v1", "m1");
    let root = t.root();

    let existence = t.prove(&present);
    let nonexistence = t.prove(&absent);
    assert!(verify_proof(&existence, Some(&root)));
    assert!(verify_proof(&nonexistence, Some(&root)));

    let wrong_root = rk(0xFE);
    assert!(!verify_proof(&existence, Some(&wrong_root)));
    assert!(!verify_proof(&nonexistence, Some(&wrong_root)));
}

#[test]
fn same_record_key_distinct_across_shards() {
    // The same record_key in two shards lands at different tree keys and
    // both are independently provable.
    let mut t = SparseMerkleTree::new();
    let ka = shard_record_key("shard-a", &rk(7));
    let kb = shard_record_key("shard-b", &rk(7));
    assert_ne!(ka, kb);
    t.update(ka, rk(0xAA), "shard-a", "p", "v1", "m1");
    t.update(kb, rk(0xBB), "shard-b", "p", "v1", "m1");
    let root = t.root();
    let Proof::Existence(pa) = t.prove(&ka) else {
        panic!()
    };
    let Proof::Existence(pb) = t.prove(&kb) else {
        panic!()
    };
    assert!(verify_existence_proof(&pa, Some(&root)));
    assert!(verify_existence_proof(&pb, Some(&root)));
    assert_ne!(pa.value_hash, pb.value_hash);
}

#[test]
fn shard_subtree_root_reflects_shard_contents() {
    let mut t = SparseMerkleTree::new();
    // Empty shard → empty-subtree hash at the shard depth.
    let empty_shard = t.shard_subtree_root("shard-a");
    assert_eq!(empty_shard, empty_hashes()[SMT_DEPTH - SHARD_PREFIX_BITS]);
    // Adding a record to shard-a changes shard-a's subtree root but not
    // shard-b's (still empty).
    t.update(
        shard_record_key("shard-a", &rk(1)),
        rk(0xAA),
        "shard-a",
        "p",
        "v1",
        "m1",
    );
    assert_ne!(t.shard_subtree_root("shard-a"), empty_shard);
    assert_eq!(
        t.shard_subtree_root("shard-b"),
        empty_hashes()[SMT_DEPTH - SHARD_PREFIX_BITS]
    );
}

#[test]
fn order_independent_root() {
    let mut a = SparseMerkleTree::new();
    a.update(
        shard_record_key("s", &rk(1)),
        rk(0xAA),
        "s",
        "p",
        "v1",
        "m1",
    );
    a.update(
        shard_record_key("s", &rk(2)),
        rk(0xBB),
        "s",
        "p",
        "v1",
        "m1",
    );
    let mut b = SparseMerkleTree::new();
    b.update(
        shard_record_key("s", &rk(2)),
        rk(0xBB),
        "s",
        "p",
        "v1",
        "m1",
    );
    b.update(
        shard_record_key("s", &rk(1)),
        rk(0xAA),
        "s",
        "p",
        "v1",
        "m1",
    );
    assert_eq!(a.root(), b.root());
}

#[test]
fn tampering_fails() {
    let mut t = SparseMerkleTree::new();
    let ka = shard_record_key("s", &rk(1));
    t.update(ka, rk(0xAA), "s", "p", "v1", "m1");
    t.update(
        shard_record_key("s", &rk(2)),
        rk(0xBB),
        "s",
        "p",
        "v1",
        "m1",
    );
    let root = t.root();
    let Proof::Existence(mut p) = t.prove(&ka) else {
        panic!()
    };
    let mut bad = p.clone();
    bad.value_hash = rk(0xCC);
    assert!(!verify_existence_proof(&bad, Some(&root)));
    assert!(!verify_existence_proof(&p, Some(&rk(0xFF))));
    p.siblings.pop();
    assert!(!verify_existence_proof(&p, Some(&root)));
}

#[test]
fn wrong_length_nonexistence_rejected() {
    let mut t = SparseMerkleTree::new();
    t.update(
        shard_record_key("s", &rk(1)),
        rk(0xAA),
        "s",
        "p",
        "v1",
        "m1",
    );
    let root = t.root();
    let Proof::NonExistence(p) = t.prove(&shard_record_key("s", &rk(9))) else {
        panic!()
    };
    assert!(verify_nonexistence_proof(&p, Some(&root)));
    let mut short = p.clone();
    short.siblings.pop();
    assert!(!verify_nonexistence_proof(&short, Some(&root)));
    let mut long = p.clone();
    long.siblings.push([0u8; 32]);
    assert!(!verify_nonexistence_proof(&long, Some(&root)));
}

// ── shard-scoped verification (ADR-0044 proof-serving) ──────────────────────

/// Build a two-shard tree so the shard-subtree root and the global root are
/// provably distinct values, not just conceptually different fields — a
/// regression that silently re-implemented a full 256-fold instead of the
/// leaf-side 192 would still pass a single-shard test by coincidence.
fn two_shard_tree() -> SparseMerkleTree {
    let mut t = SparseMerkleTree::new();
    t.update(
        shard_record_key("shard-a", &rk(1)),
        rk(0xAA),
        "shard-a",
        "p",
        "v1",
        "m1",
    );
    t.update(
        shard_record_key("shard-b", &rk(2)),
        rk(0xBB),
        "shard-b",
        "p",
        "v1",
        "m1",
    );
    t
}

/// Build a self-consistent shard-scoped existence proof: siblings are all
/// empty-subtree hashes, so the proof folds to its own shard root regardless
/// of the provenance field values — the shard-scoped analogue of
/// `lone_leaf_proof` (see its doc for why this is the trick that isolates
/// each `||` guard as the sole reason for rejection, distinguishing the
/// guard chain from a mutated `&&` that would fall through to a passing
/// hash check). Returns `(proof, shard_root)`.
fn lone_leaf_shard_proof(
    shard: &str,
    key: [u8; 32],
    value: [u8; 32],
    parser: &str,
    cpv: &str,
    model: &str,
) -> (ExistenceProof, [u8; 32]) {
    let siblings: Vec<[u8; 32]> = (0..SMT_DEPTH).map(empty_subtree_hash).collect();
    let path = key_to_path_bits(&key);
    let mut current = leaf_hash(
        shard.as_bytes(),
        &key,
        &value,
        parser.as_bytes(),
        cpv.as_bytes(),
        model.as_bytes(),
    );
    let mut shard_root = [0u8; 32];
    for (level, sib) in siblings.iter().enumerate() {
        let bit_pos = SMT_DEPTH - 1 - level;
        current = if path[bit_pos] == 0 {
            node_hash(&current, sib)
        } else {
            node_hash(sib, &current)
        };
        if level + 1 == SMT_DEPTH - SHARD_PREFIX_BITS {
            shard_root = current;
        }
    }
    (
        ExistenceProof {
            key,
            value_hash: value,
            shard_id: shard.to_string(),
            parser_id: parser.to_string(),
            canonical_parser_version: cpv.to_string(),
            model_hash: model.to_string(),
            siblings,
            root_hash: current,
        },
        shard_root,
    )
}

#[test]
fn shard_scoped_existence_guards_reject_self_consistent_but_invalid_proofs() {
    let k = shard_record_key("shard-a", &rk(1));

    // A fully-valid lone-leaf shard proof verifies.
    let (valid, shard_root) = lone_leaf_shard_proof("shard-a", k, rk(0xAA), "p", "v1", "m1");
    assert!(verify_existence_proof_against_shard_root(
        &valid,
        "shard-a",
        &shard_root
    ));

    // Each empty provenance field, one at a time: the proof still folds to
    // its own shard root, so the ONLY reason to reject is that specific
    // empty-field guard — kills a `||` -> `&&` mutation on any one of them
    // (each of these would otherwise fall through to the passing fold).
    let (bad, root) = lone_leaf_shard_proof("shard-a", k, rk(0xAA), "", "v1", "m1");
    assert!(!verify_existence_proof_against_shard_root(
        &bad, "shard-a", &root
    ));
    let (bad, root) = lone_leaf_shard_proof("shard-a", k, rk(0xAA), "p", "", "m1");
    assert!(!verify_existence_proof_against_shard_root(
        &bad, "shard-a", &root
    ));
    let (bad, root) = lone_leaf_shard_proof("shard-a", k, rk(0xAA), "p", "v1", "");
    assert!(!verify_existence_proof_against_shard_root(
        &bad, "shard-a", &root
    ));

    // Empty shard_id: build the key from "" so shard_id_matches_key passes
    // and the empty-shard guard is the sole discriminator.
    let k0 = shard_record_key("", &rk(1));
    let (bad, root) = lone_leaf_shard_proof("", k0, rk(0xAA), "p", "v1", "m1");
    assert!(!verify_existence_proof_against_shard_root(&bad, "", &root));
}

#[test]
fn verify_proof_against_shard_root_dispatches_rejection() {
    // Kills a "replace verify_proof_against_shard_root with true" mutation:
    // both proof kinds must actually reject a wrong root, not just accept a
    // right one (verify_proof_against_shard_root_dispatches_both_variants
    // only covers the accept path).
    let t = two_shard_tree();
    let existence = t.prove(&shard_record_key("shard-a", &rk(1)));
    let nonexistence = t.prove(&shard_record_key("shard-a", &rk(9)));
    let wrong_root = t.shard_subtree_root("shard-b");
    assert!(!verify_proof_against_shard_root(
        &existence,
        "shard-a",
        &wrong_root
    ));
    assert!(!verify_proof_against_shard_root(
        &nonexistence,
        "shard-a",
        &wrong_root
    ));
}

#[test]
fn existence_proof_verifies_against_shard_subtree_root() {
    let t = two_shard_tree();
    let shard_root = t.shard_subtree_root("shard-a");
    assert_ne!(
        shard_root,
        t.root(),
        "sanity: shard root and global root must differ in a multi-shard tree"
    );
    let Proof::Existence(p) = t.prove(&shard_record_key("shard-a", &rk(1))) else {
        panic!("expected existence proof")
    };
    assert!(verify_existence_proof_against_shard_root(
        &p,
        "shard-a",
        &shard_root
    ));
    // The same proof does NOT fold to the global root under this function —
    // it only ever folds the leaf-side 192 siblings.
    assert!(!verify_existence_proof_against_shard_root(
        &p,
        "shard-a",
        &t.root()
    ));
}

#[test]
fn nonexistence_proof_verifies_against_shard_subtree_root() {
    let t = two_shard_tree();
    let shard_root = t.shard_subtree_root("shard-a");
    let Proof::NonExistence(p) = t.prove(&shard_record_key("shard-a", &rk(9))) else {
        panic!("expected non-existence proof")
    };
    assert!(verify_nonexistence_proof_against_shard_root(
        &p,
        "shard-a",
        &shard_root
    ));
    assert!(!verify_nonexistence_proof_against_shard_root(
        &p,
        "shard-a",
        &t.root()
    ));
}

#[test]
fn verify_proof_against_shard_root_dispatches_both_variants() {
    let t = two_shard_tree();
    let shard_root = t.shard_subtree_root("shard-a");
    let existence = t.prove(&shard_record_key("shard-a", &rk(1)));
    let nonexistence = t.prove(&shard_record_key("shard-a", &rk(9)));
    assert!(verify_proof_against_shard_root(
        &existence,
        "shard-a",
        &shard_root
    ));
    assert!(verify_proof_against_shard_root(
        &nonexistence,
        "shard-a",
        &shard_root
    ));
}

#[test]
fn shard_scoped_existence_rejects_wrong_shard_id() {
    let t = two_shard_tree();
    let Proof::Existence(p) = t.prove(&shard_record_key("shard-a", &rk(1))) else {
        panic!("expected existence proof")
    };
    // Asking for shard-a's proof to verify against shard-b's root (with the
    // caller-asserted shard_id set to "shard-b") must fail on the explicit
    // shard_id mismatch, not just happen to fail the fold.
    let shard_b_root = t.shard_subtree_root("shard-b");
    assert!(!verify_existence_proof_against_shard_root(
        &p,
        "shard-b",
        &shard_b_root
    ));
}

#[test]
fn shard_scoped_nonexistence_rejects_wrong_shard_id() {
    let t = two_shard_tree();
    let Proof::NonExistence(p) = t.prove(&shard_record_key("shard-a", &rk(9))) else {
        panic!("expected non-existence proof")
    };
    let shard_b_root = t.shard_subtree_root("shard-b");
    assert!(!verify_nonexistence_proof_against_shard_root(
        &p,
        "shard-b",
        &shard_b_root
    ));
}

#[test]
fn shard_scoped_existence_rejects_tampered_sibling_and_wrong_length() {
    let t = two_shard_tree();
    let shard_root = t.shard_subtree_root("shard-a");
    let Proof::Existence(p) = t.prove(&shard_record_key("shard-a", &rk(1))) else {
        panic!("expected existence proof")
    };
    let mut tampered = p.clone();
    tampered.siblings[0] = rk(0xFF);
    assert!(!verify_existence_proof_against_shard_root(
        &tampered,
        "shard-a",
        &shard_root
    ));

    let mut short = p.clone();
    short.siblings.pop();
    assert!(!verify_existence_proof_against_shard_root(
        &short,
        "shard-a",
        &shard_root
    ));
}

#[test]
fn shard_scoped_nonexistence_rejects_tampered_sibling_and_wrong_length() {
    let t = two_shard_tree();
    let shard_root = t.shard_subtree_root("shard-a");
    let Proof::NonExistence(p) = t.prove(&shard_record_key("shard-a", &rk(9))) else {
        panic!("expected non-existence proof")
    };
    let mut tampered = p.clone();
    tampered.siblings[0] = rk(0xFF);
    assert!(!verify_nonexistence_proof_against_shard_root(
        &tampered,
        "shard-a",
        &shard_root
    ));

    let mut short = p.clone();
    short.siblings.pop();
    assert!(!verify_nonexistence_proof_against_shard_root(
        &short,
        "shard-a",
        &shard_root
    ));
}
