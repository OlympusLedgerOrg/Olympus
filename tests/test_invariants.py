from protocol.canonical import CANONICAL_VERSION, SUPPORTED_VERSIONS
from protocol.merkle import MERKLE_VERSION


def test_canonical_version_is_v2():
    assert CANONICAL_VERSION == "canonical_v2"


def test_supported_versions_includes_v1_and_v2():
    assert "canonical_v1" in SUPPORTED_VERSIONS
    assert "canonical_v2" in SUPPORTED_VERSIONS


def test_merkle_version_frozen():
    assert MERKLE_VERSION == "merkle_v1"
