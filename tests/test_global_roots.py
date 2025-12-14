from app.state import OlympusState
from protocol.shards import verify_header


def test_global_root_from_shard_headers():
    state = OlympusState()
    ts = "2025-01-01T00:00:00Z"

    header_a = state.append_record("shard:a", "doc", "a1", "v1", {"foo": "bar"}, ts=ts)
    header_b = state.append_record("shard:b", "doc", "b1", "v1", {"baz": "qux"}, ts=ts)

    roots = state.roots()

    assert verify_header(header_a)
    assert verify_header(header_b)

    assert roots["shards"]["shard:a"] == "1aab1e3248ced9d37ead9c979d43eb2a02af84d0ef653de62f5645ea3143d026"
    assert roots["shards"]["shard:b"] == "0c389a6873a2ab0bb04f5248acbd8417ed6b8025ce23af265fc3a3cffa3d9e5d"
    assert roots["global_root"] == "f55a4fc05f92b7dec37f2397a80e3fb673d230a15f08012b74e5fe61b33b2ea1"
