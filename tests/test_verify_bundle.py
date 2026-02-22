"""
Tests for the offline bundle verifier (verify_bundle_cli.py).

All tests run fully offline without network access or a database.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import nacl.signing

from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree
from protocol.shards import create_shard_header, sign_header
from protocol.timestamps import current_timestamp


# Imported from the tool under test
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from verify_bundle_cli import verify_bundle  # noqa: E402


CLI_PATH = Path(__file__).parent.parent / "tools" / "verify_bundle_cli.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bundle(
    *,
    include_token: bool = False,
    include_merkle: bool = False,
    tamper_header: bool = False,
    tamper_signature: bool = False,
    tamper_token_hash: bool = False,
    tamper_merkle_root: bool = False,
):
    """Build a valid (or selectively tampered) verification bundle dict."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    root_hash = hash_bytes(b"test-root-data")
    ts = current_timestamp()

    header = create_shard_header(
        shard_id="test-shard",
        root_hash=root_hash,
        timestamp=ts,
    )

    signature_hex = sign_header(header, signing_key)
    pubkey_hex = verify_key.encode().hex()

    bundle: dict = {
        "shard_header": header,
        "signature": signature_hex,
        "pubkey": pubkey_hex,
    }

    if tamper_header:
        header["header_hash"] = "ff" * 32

    if tamper_signature:
        bundle["signature"] = "00" * 64

    # Optional timestamp token (mock – no real TSA)
    if include_token:
        token_hash = header["header_hash"] if not tamper_token_hash else "ee" * 32
        bundle["timestamp_token"] = {
            "hash_hex": token_hash,
            "tsa_url": "https://freetsa.org/tsr",
            "tst_hex": "3000",  # minimal placeholder
            "timestamp": ts,
        }

    # Optional Merkle proofs
    if include_merkle:
        leaves = [
            hash_bytes(b"doc-part-0"),
            hash_bytes(b"doc-part-1"),
            hash_bytes(b"doc-part-2"),
            hash_bytes(b"doc-part-3"),
        ]
        tree = MerkleTree(leaves)
        proof = tree.generate_proof(1)

        proof_root = tree.get_root().hex() if not tamper_merkle_root else "dd" * 32

        bundle["merkle_proofs"] = [
            {
                "leaf_hash": proof.leaf_hash.hex(),
                "leaf_index": proof.leaf_index,
                "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
                "root_hash": proof_root,
            }
        ]

    return bundle


# ---------------------------------------------------------------------------
# verify_bundle() unit tests
# ---------------------------------------------------------------------------


def test_valid_bundle_minimal():
    """A minimal bundle with header + signature passes."""
    bundle = _make_bundle()
    passed, results = verify_bundle(bundle)
    assert passed is True
    assert len(results) == 2  # header hash + signature


def test_valid_bundle_with_timestamp_token():
    """Bundle with a mock timestamp token passes imprint check."""
    bundle = _make_bundle(include_token=True)
    # Mock rfc3161ng.check_timestamp so no real TST validation
    with patch("rfc3161ng.check_timestamp", return_value=True):
        passed, results = verify_bundle(bundle)
    assert passed is True
    assert len(results) == 3


def test_valid_bundle_with_merkle_proofs():
    """Bundle with Merkle proofs that match a generated tree passes."""
    # Build bundle where root_hash in the header matches the Merkle tree root
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    leaves = [
        hash_bytes(b"doc-part-0"),
        hash_bytes(b"doc-part-1"),
    ]
    tree = MerkleTree(leaves)
    root_hash = tree.get_root()

    ts = current_timestamp()
    header = create_shard_header(shard_id="test-shard", root_hash=root_hash, timestamp=ts)
    sig = sign_header(header, signing_key)

    proof = tree.generate_proof(0)
    bundle = {
        "shard_header": header,
        "signature": sig,
        "pubkey": verify_key.encode().hex(),
        "merkle_proofs": [
            {
                "leaf_hash": proof.leaf_hash.hex(),
                "leaf_index": proof.leaf_index,
                "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
                "root_hash": proof.root_hash.hex(),
            }
        ],
    }
    passed, results = verify_bundle(bundle)
    assert passed is True
    assert any("Merkle proof" in msg for _, msg in results)


def test_tampered_header_hash_fails():
    """Tampered header_hash is detected."""
    bundle = _make_bundle(tamper_header=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("MISMATCH" in msg for _, msg in results)


def test_tampered_signature_fails():
    """Wrong signature is detected."""
    bundle = _make_bundle(tamper_signature=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("INVALID" in msg for _, msg in results)


def test_tampered_token_hash_fails():
    """Timestamp token with wrong hash_hex is detected."""
    bundle = _make_bundle(include_token=True, tamper_token_hash=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("mismatch" in msg.lower() for _, msg in results)


def test_merkle_root_mismatch_fails():
    """Merkle proof whose root doesn't match the shard root is detected."""
    bundle = _make_bundle(include_merkle=True, tamper_merkle_root=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("root mismatch" in msg.lower() or "INVALID" in msg for _, msg in results)


def test_missing_required_field():
    """Missing shard_header field returns failure."""
    passed, results = verify_bundle({"signature": "aa" * 64, "pubkey": "bb" * 32})
    assert passed is False
    assert any("Missing" in msg for _, msg in results)


def test_full_bundle_all_checks():
    """Bundle with all optional fields and valid data passes all checks."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    leaves = [hash_bytes(b"part-a"), hash_bytes(b"part-b")]
    tree = MerkleTree(leaves)
    root_hash = tree.get_root()

    ts = current_timestamp()
    header = create_shard_header(shard_id="full-test", root_hash=root_hash, timestamp=ts)
    sig = sign_header(header, signing_key)

    proof = tree.generate_proof(0)
    bundle = {
        "shard_header": header,
        "signature": sig,
        "pubkey": verify_key.encode().hex(),
        "timestamp_token": {
            "hash_hex": header["header_hash"],
            "tsa_url": "https://freetsa.org/tsr",
            "tst_hex": "3000",
            "timestamp": ts,
        },
        "merkle_proofs": [
            {
                "leaf_hash": proof.leaf_hash.hex(),
                "leaf_index": proof.leaf_index,
                "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
                "root_hash": proof.root_hash.hex(),
            }
        ],
    }

    with patch("rfc3161ng.check_timestamp", return_value=True):
        passed, results = verify_bundle(bundle)

    assert passed is True
    assert len(results) == 4  # header + sig + token + 1 merkle proof


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_cli_valid_bundle(tmp_path):
    """CLI exits 0 for a valid bundle."""
    bundle = _make_bundle()
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(bundle))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(bundle_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PASSED" in result.stdout


def test_cli_invalid_bundle(tmp_path):
    """CLI exits 1 for a tampered bundle."""
    bundle = _make_bundle(tamper_header=True)
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(bundle))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(bundle_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "FAILED" in result.stderr


def test_cli_missing_file():
    """CLI exits 1 when file does not exist."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "/nonexistent/bundle.json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_bad_json(tmp_path):
    """CLI exits 1 for malformed JSON."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json}")

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(bad_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "Error" in result.stderr


def test_cli_no_args():
    """CLI exits with error when no arguments are provided."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
