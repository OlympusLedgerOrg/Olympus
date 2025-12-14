from protocol.merkle import MerkleTree

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
