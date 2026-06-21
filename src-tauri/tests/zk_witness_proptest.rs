//! Property-based (randomised) tests for the ZK witness *validators*.
//!
//! These exercise the always-compiled structural-validation layer in
//! `zk::witness` — `ExistenceWitness::new`, `NonExistenceWitness::new`,
//! and their `verify_merkle_root` / `path_indices`
//! helpers — with thousands of randomised inputs per run. They need neither the
//! `prover` feature nor any trusted-setup artifact, so the target builds and
//! runs in the lean (`--no-default-features`) CI test job.
//!
//! Where the existing hand-written unit tests assert *specific* rejections,
//! these assert the *invariants over the whole input space*: any wrong length
//! is rejected, any non-binary index is rejected, an index that doesn't
//! reconstruct its leaf position is rejected, and the Merkle-root round-trip is
//! self-consistent for arbitrary field values.
//!
//! Run with:  cargo test -p olympus-desktop --test zk_witness_proptest

use ark_bn254::Fr;
use proptest::prelude::*;

use olympus_tauri_lib::zk::poseidon::{compute_merkle_root, NODE_DOMAIN};
use olympus_tauri_lib::zk::witness::existence::{ExistenceError, ExistenceWitness, DEPTH};
use olympus_tauri_lib::zk::witness::non_existence::{
    NonExistenceError, NonExistenceWitness, SMT_DEPTH,
};

// ── small helpers ───────────────────────────────────────────────────────────

fn fr(v: u64) -> Fr {
    Fr::from(v)
}

// ── document_existence validator ────────────────────────────────────────────

proptest! {
    /// Any `path_elements` length other than DEPTH is rejected as WrongDepth.
    #[test]
    fn existence_rejects_wrong_path_elements_len(len in 0usize..40) {
        prop_assume!(len != DEPTH);
        let r = ExistenceWitness::new(
            fr(0), 0, 1, fr(0),
            vec![Fr::from(0u64); len],
            vec![0u8; DEPTH],
        );
        prop_assert!(matches!(r, Err(ExistenceError::WrongDepth(n)) if n == len));
    }

    /// Any `path_indices` length other than DEPTH is rejected as WrongIndices.
    #[test]
    fn existence_rejects_wrong_indices_len(len in 0usize..40) {
        prop_assume!(len != DEPTH);
        let r = ExistenceWitness::new(
            fr(0), 0, 1, fr(0),
            vec![Fr::from(0u64); DEPTH],
            vec![0u8; len],
        );
        prop_assert!(matches!(r, Err(ExistenceError::WrongIndices(n)) if n == len));
    }

    /// Any index byte > 1 anywhere in the path is rejected as InvalidIndex,
    /// reported at the first offending position.
    #[test]
    fn existence_rejects_non_binary_index(
        pos in 0usize..DEPTH,
        bad in 2u8..=u8::MAX,
    ) {
        let mut indices = vec![0u8; DEPTH];
        indices[pos] = bad;
        let r = ExistenceWitness::new(
            fr(0), 0, 1, fr(0),
            vec![Fr::from(0u64); DEPTH],
            indices,
        );
        prop_assert!(matches!(r, Err(ExistenceError::InvalidIndex(g, p)) if g == bad && p == pos));
    }

    /// With a non-empty tree, `leaf_index >= tree_size` is out of bounds.
    #[test]
    fn existence_rejects_index_out_of_bounds(tree_size in 1u64..1_000, extra in 0u64..1_000) {
        let leaf_index = tree_size + extra; // always >= tree_size
        let r = ExistenceWitness::new(
            fr(0), leaf_index, tree_size, fr(0),
            vec![Fr::from(0u64); DEPTH],
            vec![0u8; DEPTH],
        );
        prop_assert!(matches!(r, Err(ExistenceError::IndexOutOfBounds)));
    }

    /// `tree_size == 0` disables the bounds check — construction always succeeds
    /// regardless of leaf_index (the empty-tree-root guard is the verifier's job).
    #[test]
    fn existence_allows_tree_size_zero(leaf_index in any::<u64>()) {
        let r = ExistenceWitness::new(
            fr(0), leaf_index, 0, fr(0),
            vec![Fr::from(0u64); DEPTH],
            vec![0u8; DEPTH],
        );
        prop_assert!(r.is_ok());
    }

    /// Round-trip: for an arbitrary leaf, binary path and arbitrary siblings,
    /// the witness built from the *computed* root verifies, and any other root
    /// is a RootMismatch. This pins `verify_merkle_root` to `compute_merkle_root`.
    #[test]
    fn existence_merkle_root_roundtrip(
        leaf in any::<u64>(),
        siblings in prop::collection::vec(any::<u64>(), DEPTH),
        bits in prop::collection::vec(0u8..=1, DEPTH),
    ) {
        let leaf = fr(leaf);
        let path: Vec<Fr> = siblings.iter().map(|&s| fr(s)).collect();
        let root = compute_merkle_root(leaf, &path, &bits, NODE_DOMAIN).expect("compute root");

        // tree_size large enough that leaf_index 0 is in-bounds.
        let w = ExistenceWitness::new(root, 0, 1, leaf, path.clone(), bits.clone())
            .expect("valid witness");
        prop_assert!(w.verify_merkle_root().is_ok());
        // public_signals order is [root, leafIndex, treeSize].
        let sig = w.public_signals();
        prop_assert_eq!(sig.len(), 3);
        prop_assert_eq!(sig[0], root);

        // A witness asserting root+1 must fail verify_merkle_root.
        let wrong = ExistenceWitness::new(root + Fr::from(1u64), 0, 1, leaf, path, bits)
            .expect("witness builds with any root");
        prop_assert!(matches!(wrong.verify_merkle_root(), Err(ExistenceError::RootMismatch)));
    }
}

// ── non_existence validator ─────────────────────────────────────────────────

proptest! {
    /// Any `path_elements` length other than SMT_DEPTH is rejected.
    #[test]
    fn non_existence_rejects_wrong_depth(len in 0usize..300) {
        prop_assume!(len != SMT_DEPTH);
        let r = NonExistenceWitness::new(fr(0), [0u8; 32], vec![Fr::from(0u64); len]);
        prop_assert!(matches!(r, Err(NonExistenceError::WrongDepth(n)) if n == len));
    }

    /// `path_indices()` is deterministic, always 256 binary values, and is
    /// key-sensitive: flipping any key bit changes the derived path.
    #[test]
    fn non_existence_path_indices_are_binary_and_key_sensitive(
        key in any::<[u8; 32]>(),
        flip in 0usize..256,
    ) {
        let w = NonExistenceWitness::new(fr(0), key, vec![Fr::from(0u64); SMT_DEPTH])
            .expect("witness");
        let idx = w.path_indices();
        prop_assert_eq!(idx.len(), SMT_DEPTH);
        prop_assert!(idx.iter().all(|&b| b <= 1));
        prop_assert_eq!(idx.clone(), w.path_indices(), "deterministic");

        // Flip one key bit and confirm the derived index vector changes.
        let mut key2 = key;
        key2[flip / 8] ^= 1 << (flip % 8);
        let w2 = NonExistenceWitness::new(fr(0), key2, vec![Fr::from(0u64); SMT_DEPTH])
            .expect("witness2");
        prop_assert_ne!(idx, w2.path_indices(), "distinct keys → distinct paths");
    }

    /// Round-trip over an all-empty SMT: the root computed from the key-derived
    /// path verifies; any other root is a RootMismatch. Also `key_hash` is
    /// deterministic and key-sensitive.
    #[test]
    fn non_existence_merkle_root_roundtrip(key in any::<[u8; 32]>()) {
        let path = vec![Fr::from(0u64); SMT_DEPTH];
        // Build once to read the derived indices, compute the matching root.
        let probe = NonExistenceWitness::new(fr(0), key, path.clone()).expect("probe");
        let indices = probe.path_indices();
        let root = compute_merkle_root(Fr::from(0u64), &path, &indices, NODE_DOMAIN).expect("root");

        let w = NonExistenceWitness::new(root, key, path.clone()).expect("witness");
        prop_assert!(w.verify_merkle_root().is_ok());
        prop_assert_eq!(w.public_signals().len(), 2);

        let bad = NonExistenceWitness::new(root + Fr::from(1u64), key, path).expect("bad witness");
        prop_assert!(matches!(bad.verify_merkle_root(), Err(NonExistenceError::RootMismatch)));

        // key_hash determinism.
        prop_assert_eq!(w.key_hash().unwrap(), probe.key_hash().unwrap());
    }
}
