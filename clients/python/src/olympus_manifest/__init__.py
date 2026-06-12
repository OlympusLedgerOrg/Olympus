"""Olympus dataset-manifest Python SDK.

A pip-installable client for verifying Olympus record proofs and talking to a
node. The cryptographic commitment (``manifest_root``) is produced by the Rust
``olympus`` CLI / ``olympus-manifest`` crate — the source of truth — and this
package re-verifies it byte-for-byte (see ``tests/test_parity.py``).

Quick start::

    from olympus_manifest import verify, Verdict
    import json
    bundle   = json.load(open("proof.json"))
    manifest = json.load(open("manifest.json"))
    assert verify(bundle, bytes.fromhex(manifest["manifest_root"])).is_valid
"""

from .proof import Verdict, record_tree_key, verify, verify_against_manifest
from .client import OlympusClient, hash_file, scan
from . import hashing, smt

__all__ = [
    "Verdict",
    "verify",
    "verify_against_manifest",
    "record_tree_key",
    "OlympusClient",
    "hash_file",
    "scan",
    "hashing",
    "smt",
]

__version__ = "0.1.0"
