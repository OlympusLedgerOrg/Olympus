from protocol.canonical import CANONICAL_VERSION
from protocol.merkle import MERKLE_VERSION

def test_canonical_version_frozen():
    assert CANONICAL_VERSION == "canonical_v1"


def test_merkle_version_frozen():
    assert MERKLE_VERSION == "merkle_v1"
