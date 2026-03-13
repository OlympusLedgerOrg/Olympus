from protocol.hashes import (
    CHECKPOINT_PREFIX,
    EVENT_PREFIX,
    FEDERATION_PREFIX,
    FOREST_PREFIX,
    HDR_PREFIX,
    KEY_PREFIX,
    LEAF_PREFIX,
    LEDGER_PREFIX,
    NODE_PREFIX,
    POLICY_PREFIX,
    TREE_HEAD_PREFIX,
)


def test_hash_domain_prefixes_are_frozen():
    """
    These prefixes are protocol-critical.
    Changing them breaks all historical proofs.
    """
    assert KEY_PREFIX == b"OLY:KEY:V1"
    assert LEAF_PREFIX == b"OLY:LEAF:V1"
    assert NODE_PREFIX == b"OLY:NODE:V1"
    assert HDR_PREFIX == b"OLY:HDR:V1"
    assert FOREST_PREFIX == b"OLY:FOREST:V1"
    assert POLICY_PREFIX == b"OLY:POLICY:V1"
    assert LEDGER_PREFIX == b"OLY:LEDGER:V1"
    assert FEDERATION_PREFIX == b"OLY:FEDERATION:V1"
    assert EVENT_PREFIX == b"OLY:EVENT:V1"
    assert CHECKPOINT_PREFIX == b"OLY:CHECKPOINT:V1"
    assert TREE_HEAD_PREFIX == b"OLY:TREE-HEAD:V1"
