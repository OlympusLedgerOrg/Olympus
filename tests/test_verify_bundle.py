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

from protocol.canonicalizer import CANONICALIZER_VERSIONS
from protocol.epochs import EpochRecord, SignedTreeHead
from protocol.events import CanonicalEvent
from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree, merkle_leaf_hash
from protocol.shards import create_shard_header, sign_header
from protocol.timestamps import current_timestamp


# Imported from the tool under test
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from verify_bundle_cli import _check_header_hash, verify_bundle  # noqa: E402


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
    omit_signed_tree_head: bool = False,
    tamper_signed_tree_head_signature: bool = False,
    tamper_signed_tree_head_tree_size: bool = False,
    tamper_signed_tree_head_root: bool = False,
):
    """Build a valid (or selectively tampered) verification bundle dict."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    schema_version = "1.0.0"
    canonical_events_raw = [{"id": 1, "body": "event-a"}, {"id": 2, "body": "event-b"}]
    canonical_events = [
        CanonicalEvent.from_raw(evt, schema_version) for evt in canonical_events_raw
    ]
    leaf_hashes = [merkle_leaf_hash(evt.canonical_bytes).hex() for evt in canonical_events]

    tree = MerkleTree([evt.canonical_bytes for evt in canonical_events])
    root_hash = tree.get_root()
    merkle_root_hex = root_hash.hex()
    ts = current_timestamp()
    canonicalization = {
        "format": "application/json",
        "normalization_mode": "canonical_v1",
        "fallback_reason": None,
        "canonicalizer_versions": CANONICALIZER_VERSIONS,
    }

    header = create_shard_header(
        shard_id="test-shard",
        root_hash=root_hash,
        timestamp=ts,
    )

    signature_hex = sign_header(header, signing_key)
    pubkey_hex = verify_key.encode().hex()

    epoch_record = EpochRecord.create(
        epoch_index=0,
        merkle_root=root_hash,
        metadata_hash=hash_bytes(
            json.dumps(
                canonicalization, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ),
    ).to_dict()
    signed_tree_head = SignedTreeHead.create(
        epoch_id=epoch_record["epoch_index"],
        tree_size=len(canonical_events),
        merkle_root=root_hash,
        signing_key=signing_key,
        timestamp=ts,
    ).to_dict()

    bundle: dict = {
        "bundle_version": "1.0.0",
        "schema_version": schema_version,
        "canonical_events": [evt.payload for evt in canonical_events],
        "leaf_hashes": leaf_hashes,
        "merkle_root": merkle_root_hex,
        "canonicalization": canonicalization,
        "shard_header": header,
        "epoch_record": epoch_record,
        "signature": signature_hex,
        "pubkey": pubkey_hex,
    }

    if not omit_signed_tree_head:
        bundle["signed_tree_head"] = signed_tree_head

    if tamper_header:
        header["header_hash"] = "ff" * 32

    if tamper_signature:
        bundle["signature"] = "00" * 64

    if tamper_signed_tree_head_signature and "signed_tree_head" in bundle:
        bundle["signed_tree_head"]["signature"] = "00" * 64

    if tamper_signed_tree_head_tree_size and "signed_tree_head" in bundle:
        bundle["signed_tree_head"]["tree_size"] += 1

    if tamper_signed_tree_head_root and "signed_tree_head" in bundle:
        bundle["signed_tree_head"]["merkle_root"] = "11" * 32

    # Optional timestamp token (mock – no real TSA)
    if include_token:
        token_hash = header["header_hash"] if not tamper_token_hash else "ee" * 32
        bundle["timestamp_token"] = {
            "hash_hex": token_hash,
            "tsa_url": "https://freetsa.org/tsr",
            "tst_hex": "3000",  # minimal placeholder
            "timestamp": ts,
            "tsa_cert_fingerprint": "aa" * 32,
        }

    # Optional Merkle proofs
    if include_merkle:
        proof = tree.generate_proof(1)

        proof_root = merkle_root_hex if not tamper_merkle_root else "dd" * 32

        bundle["merkle_proofs"] = [
            {
                "leaf_hash": proof.leaf_hash.hex(),
                "leaf_index": proof.leaf_index,
                "siblings": [[h.hex(), pos] for h, pos in proof.siblings],
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
    assert all(passed for passed, _ in results)


def test_valid_bundle_with_timestamp_token():
    """Bundle with a mock timestamp token passes imprint check."""
    bundle = _make_bundle(include_token=True)
    # Mock rfc3161ng.check_timestamp so no real TST validation
    with patch("rfc3161ng.check_timestamp", return_value=True):
        passed, results = verify_bundle(bundle)
    assert passed is True
    assert any("timestamp token" in msg.lower() for _, msg in results)


def test_valid_bundle_with_merkle_proofs():
    """Bundle with Merkle proofs that match a generated tree passes."""
    bundle = _make_bundle(include_merkle=True)
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


def test_missing_signed_tree_head_fails():
    """Bundles without a Signed Tree Head are rejected."""
    bundle = _make_bundle(omit_signed_tree_head=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("Signed Tree Head missing" in msg for _, msg in results)


def test_tampered_signed_tree_head_signature_fails():
    """Tampering with the Signed Tree Head signature is detected."""
    bundle = _make_bundle(tamper_signed_tree_head_signature=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("Signed Tree Head signature INVALID" in msg for _, msg in results)


def test_signed_tree_head_tree_size_mismatch_fails():
    """Signed Tree Head tree size must match the bundle leaf count."""
    bundle = _make_bundle(tamper_signed_tree_head_tree_size=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("tree size mismatch" in msg.lower() for _, msg in results)


def test_signed_tree_head_root_mismatch_fails():
    """Signed Tree Head root must match the verified shard root."""
    bundle = _make_bundle(tamper_signed_tree_head_root=True)
    passed, results = verify_bundle(bundle)
    assert passed is False
    assert any("signed tree head merkle root mismatch" in msg.lower() for _, msg in results)


def test_header_validation_requires_consensus_fields():
    """Shard header validation fails cleanly when consensus fields are missing."""
    bundle = _make_bundle()
    header = dict(bundle["shard_header"])
    header.pop("height")

    passed, message = _check_header_hash(header)

    assert passed is False
    assert "missing required fields" in message


def test_full_bundle_all_checks():
    """Bundle with all optional fields and valid data passes all checks."""
    bundle = _make_bundle(include_token=True, include_merkle=True)

    with patch("rfc3161ng.check_timestamp", return_value=True):
        passed, results = verify_bundle(bundle)

    assert passed is True
    assert any("timestamp token" in msg.lower() for _, msg in results)
    assert any("merkle proof" in msg.lower() for _, msg in results)


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


# ---------------------------------------------------------------------------
# Extended tests (Step 2k) — sub-check functions
# ---------------------------------------------------------------------------


def test_check_bundle_version_supported():
    """Supported bundle version passes."""
    from verify_bundle_cli import _check_bundle_version

    passed, msg = _check_bundle_version("1.0.0")
    assert passed is True
    assert "supported" in msg.lower()


def test_check_bundle_version_unsupported():
    """Unsupported bundle version fails."""
    from verify_bundle_cli import _check_bundle_version

    passed, msg = _check_bundle_version("99.0.0")
    assert passed is False
    assert "unsupported" in msg.lower()


def test_check_schema_version_supported():
    """Supported schema version passes."""
    from verify_bundle_cli import _check_schema_version

    passed, msg = _check_schema_version("1.0.0")
    assert passed is True


def test_check_schema_version_unsupported():
    """Unsupported schema version fails."""
    from verify_bundle_cli import _check_schema_version

    passed, msg = _check_schema_version("2.0.0")
    assert passed is False


def test_check_schema_version_empty():
    """Empty schema version fails."""
    from verify_bundle_cli import _check_schema_version

    passed, msg = _check_schema_version("")
    assert passed is False
    assert "missing" in msg.lower()


def test_check_canonicalization_provenance_valid():
    """Valid canonicalization provenance passes."""
    from verify_bundle_cli import _check_canonicalization_provenance

    prov = {
        "format": "application/json",
        "normalization_mode": "canonical_v1",
        "canonicalizer_versions": {"python": "1.0.0"},
        "fallback_reason": None,
    }
    passed, msg = _check_canonicalization_provenance(prov)
    assert passed is True


def test_check_canonicalization_provenance_missing_fields():
    """Missing canonicalization fields fail."""
    from verify_bundle_cli import _check_canonicalization_provenance

    prov = {"format": "application/json"}
    passed, msg = _check_canonicalization_provenance(prov)
    assert passed is False
    assert "missing" in msg.lower()


def test_check_canonicalization_provenance_bad_versions_type():
    """canonicalizer_versions must be a dict."""
    from verify_bundle_cli import _check_canonicalization_provenance

    prov = {
        "format": "application/json",
        "normalization_mode": "canonical_v1",
        "canonicalizer_versions": "not-a-dict",
        "fallback_reason": None,
    }
    passed, msg = _check_canonicalization_provenance(prov)
    assert passed is False
    assert "dict" in msg.lower()


def test_check_root_consistency_matching():
    """Matching roots pass."""
    from verify_bundle_cli import _check_root_consistency

    passed, msg = _check_root_consistency("aa" * 32, "aa" * 32)
    assert passed is True


def test_check_root_consistency_case_insensitive():
    """Root comparison is case-insensitive."""
    from verify_bundle_cli import _check_root_consistency

    passed, msg = _check_root_consistency("AA" * 32, "aa" * 32)
    assert passed is True


def test_check_root_consistency_mismatch():
    """Mismatched roots fail."""
    from verify_bundle_cli import _check_root_consistency

    passed, msg = _check_root_consistency("aa" * 32, "bb" * 32)
    assert passed is False


def test_check_epoch_record_valid():
    """Valid epoch record passes."""
    from verify_bundle_cli import _check_epoch_record

    bundle = _make_bundle()
    epoch_record = bundle["epoch_record"]
    root_hash_hex = bundle["shard_header"]["root_hash"]
    passed, msg = _check_epoch_record(epoch_record, root_hash_hex)
    assert passed is True


def test_check_epoch_record_root_mismatch():
    """Epoch record with wrong root fails."""
    from verify_bundle_cli import _check_epoch_record

    bundle = _make_bundle()
    epoch_record = bundle["epoch_record"]
    passed, msg = _check_epoch_record(epoch_record, "ff" * 32)
    assert passed is False
    assert "mismatch" in msg.lower()


def test_check_canonical_events_valid():
    """Valid canonical events and leaf hashes pass."""
    from verify_bundle_cli import _check_canonical_events

    bundle = _make_bundle()
    results = _check_canonical_events(
        bundle["schema_version"],
        bundle["canonical_events"],
        bundle["leaf_hashes"],
        bundle["merkle_root"],
    )
    assert all(passed for passed, _ in results)


def test_check_canonical_events_leaf_count_mismatch():
    """Mismatched leaf hash count fails."""
    from verify_bundle_cli import _check_canonical_events

    bundle = _make_bundle()
    results = _check_canonical_events(
        bundle["schema_version"],
        bundle["canonical_events"],
        bundle["leaf_hashes"][:1],  # fewer hashes
        bundle["merkle_root"],
    )
    assert any(not passed for passed, _ in results)


def test_check_canonical_events_bad_root():
    """Wrong Merkle root is detected."""
    from verify_bundle_cli import _check_canonical_events

    bundle = _make_bundle()
    results = _check_canonical_events(
        bundle["schema_version"],
        bundle["canonical_events"],
        bundle["leaf_hashes"],
        "ff" * 32,  # wrong root
    )
    assert any(not passed for passed, _ in results)


def test_check_signed_tree_head_valid():
    """Valid Signed Tree Head passes."""
    from verify_bundle_cli import _check_signed_tree_head

    bundle = _make_bundle()
    passed, msg = _check_signed_tree_head(
        bundle["signed_tree_head"],
        root_hash_hex=bundle["shard_header"]["root_hash"],
        leaf_count=len(bundle["canonical_events"]),
        epoch_record=bundle["epoch_record"],
    )
    assert passed is True


def test_verify_bundle_with_consistency_proof():
    """Bundle verification handles consistency proof field gracefully."""
    bundle = _make_bundle()
    passed, results = verify_bundle(bundle)
    assert passed is True


def test_cli_help_text():
    """CLI --help outputs usage info and exits 0."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "bundle" in result.stdout.lower() or "usage" in result.stdout.lower()
