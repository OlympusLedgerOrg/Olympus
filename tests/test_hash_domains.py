from protocol.hashes import (
    DOC_PREFIX,
    NS_PREFIX,
    LEAF_PREFIX,
    SHARD_PREFIX,
    ANCHOR_PREFIX,
)

def test_hash_domain_prefixes_are_frozen():
    """
    These prefixes are protocol-critical.
    Changing them breaks all historical proofs.
    """
    assert DOC_PREFIX == b"OLYMPUS_DOC_V1"
    assert NS_PREFIX == b"OLYMPUS_NS_V1"
    assert LEAF_PREFIX == b"OLYMPUS_LEAF_V1"
    assert SHARD_PREFIX == b"OLYMPUS_SHARD_V1"
    assert ANCHOR_PREFIX == b"OLYMPUS_ANCHOR_V1"
