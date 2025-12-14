from protocol.hashes import hash_string, leaf_hash, record_key
from protocol.canonical import canonicalize_json
from protocol.ssmf import SparseMerkleTree, verify_proof


def test_golden_leaf_and_root():
    record_type = "doc"
    record_id = "example"
    version = "v1"
    value = {"hello": "world"}

    canonical = canonicalize_json(value)
    value_hash = hash_string(canonical)
    key = record_key(record_type, record_id, version)

    tree = SparseMerkleTree()
    tree.set(key, value_hash, version)

    assert key.hex() == "b6451cd8d1d59761218374302e2c0368c688e06aeea0780d7df98a0d0bb1b687"
    assert value_hash.hex() == "2f1d0d2863379dd25974f01cbf5c01ff6eab04d9be86b74fe21d1bf4223526b6"
    assert leaf_hash(key, value_hash).hex() == "11afad3889d89ca9bda6933de7bca0ed1c9fba2910afa559dcf93a04a10fba57"
    assert tree.root().hex() == "940d0c220b69b582f717a0f3d3e41d7bc8abb02435636b75861adb9f8516146f"


def test_existence_and_nonexistence_proofs():
    tree = SparseMerkleTree()
    key = record_key("doc", "example", "v1")
    value_hash = hash_string(canonicalize_json({"hello": "world"}))
    tree.set(key, value_hash, "v1")

    proof = tree.prove_existence(key, "v1")
    assert verify_proof(tree.root(), key, proof, value_hash)

    # Tamper value hash should fail
    bad_value = hash_string("tamper")
    assert not verify_proof(tree.root(), key, proof, bad_value)

    missing_key = record_key("doc", "missing", "v1")
    missing_proof = tree.prove_nonexistence(missing_key, "v1")
    assert verify_proof(tree.root(), missing_key, missing_proof)
