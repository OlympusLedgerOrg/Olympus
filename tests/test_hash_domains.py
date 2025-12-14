from protocol.hashes import KEY_PREFIX, LEAF_PREFIX, NODE_PREFIX, HDR_PREFIX, FOREST_PREFIX, POLICY_PREFIX


def test_hash_domain_prefixes_are_frozen():
    """Domain separation must never change without version bumps."""
    assert KEY_PREFIX == b"OLY:KEY:V1"
    assert LEAF_PREFIX == b"OLY:LEAF:V1"
    assert NODE_PREFIX == b"OLY:NODE:V1"
    assert HDR_PREFIX == b"OLY:HDR:V1"
    assert FOREST_PREFIX == b"OLY:FOREST:V1"
    assert POLICY_PREFIX == b"OLY:POLICY:V1"
