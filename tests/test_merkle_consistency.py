from protocol.hashes import merkle_parent_hash
from protocol.merkle import MerkleTree, merkle_leaf_hash, verify_proof


def test_merkle_root_stable_for_same_inputs():
    leaves = [b"a", b"b", b"c"]

    tree1 = MerkleTree(leaves)
    tree2 = MerkleTree(leaves)

    assert tree1.root() == tree2.root()


def test_merkle_root_changes_if_order_changes():
    leaves1 = [b"a", b"b", b"c"]
    leaves2 = [b"b", b"a", b"c"]

    tree1 = MerkleTree(leaves1)
    tree2 = MerkleTree(leaves2)

    assert tree1.root() != tree2.root()


def test_merkle_leaf_prefix_applied():
    """
    Leaf data must be hashed with LEAF_PREFIX before tree construction.
    The root produced by MerkleTree must differ from a tree built using
    a node prefix for all levels (i.e., the old behavior without domain separation).
    """
    leaves = [b"leaf0", b"leaf1"]
    tree = MerkleTree(leaves)

    # Manually compute what the root should be with LEAF_PREFIX for leaves
    # and NODE_PREFIX for internal nodes.
    leaf0_hash = merkle_leaf_hash(b"leaf0")
    leaf1_hash = merkle_leaf_hash(b"leaf1")

    expected_root = merkle_parent_hash(leaf0_hash, leaf1_hash)

    assert tree.get_root() == expected_root


def test_merkle_proof_verifies_with_domain_separation():
    """Inclusion proofs must verify correctly with the domain-separated leaf scheme."""
    leaves = [b"alpha", b"beta", b"gamma"]
    tree = MerkleTree(leaves)

    for i in range(len(leaves)):
        proof = tree.generate_proof(i)
        assert verify_proof(proof), f"Proof for leaf {i} should verify"


def test_merkle_proof_leaf_hash_uses_leaf_prefix():
    """MerkleProof.leaf_hash must be the LEAF_PREFIX-domain-separated hash."""
    leaves = [b"x", b"y"]
    tree = MerkleTree(leaves)

    proof = tree.generate_proof(0)
    expected_leaf_hash = merkle_leaf_hash(b"x")
    assert proof.leaf_hash == expected_leaf_hash


def test_merkle_tree_leaves_attr_unchanged():
    """tree.leaves must still expose the original raw leaf data (not prefixed)."""
    raw_leaves = [b"raw1", b"raw2"]
    tree = MerkleTree(raw_leaves)
    assert tree.leaves == raw_leaves
