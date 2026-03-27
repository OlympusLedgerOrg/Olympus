#!/usr/bin/env python3
"""
Dataset provenance CLI for Olympus (ADR-0010).

Implements:
    dataset keygen  -- Generate an Ed25519 signing keypair
    dataset commit  -- Scan a directory, build a signed manifest, emit a commit bundle
    dataset verify  -- Offline verification of a commit bundle
"""

import argparse
import json
import sys
from pathlib import Path


# Allow running as a standalone script or being imported by tools/olympus.py.
sys.path.insert(0, str(Path(__file__).parent.parent))

import blake3 as _blake3
import nacl.encoding
import nacl.exceptions
import nacl.signing

from protocol.canonical import document_to_bytes
from protocol.hashes import compute_dataset_commit_id, dataset_key, hash_bytes
from protocol.merkle import EMPTY_TREE_HASH, MerkleTree


# Read files in 1 MiB chunks to avoid loading large datasets entirely into RAM.
_CHUNK_SIZE = 1 << 20


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _chunked_blake3(path: Path) -> str:
    """Stream *path* through BLAKE3 in chunks and return the hex digest.

    File-content hashes in the manifest are intentionally **raw** BLAKE3
    (no ``LEGACY_BYTES_PREFIX`` domain separation) so that any verifier can
    reproduce them with a standard ``blake3`` tool without Olympus tooling.
    Protocol-level identifiers (manifest hash, commit ID) use ``hash_bytes()``
    / ``compute_dataset_commit_id()`` for domain separation as normal.

    Args:
        path: File to hash.

    Returns:
        Lowercase hex-encoded 32-byte BLAKE3 digest.
    """
    hasher = _blake3.blake3()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _scan_files(directory: Path) -> list[dict]:
    """Recursively scan *directory* and return a deterministically ordered manifest.

    Each entry is ``{"path": str, "hash": str, "size": int}`` where *path* is a
    POSIX-style relative path, *hash* is the hex-encoded BLAKE3 digest of the
    file bytes, and *size* is the byte count reported by the filesystem.

    Ordering contract
    -----------------
    Entries are sorted with a two-level key:

    1. **Primary**: ``rel_path.casefold()`` — Unicode-aware case-folding
       (a superset of ``.lower()``) ensures identical leaf order on
       case-insensitive filesystems (NTFS, APFS) and case-sensitive filesystems
       (ext4) when files share identical content.
    2. **Secondary**: ``rel_path`` (original POSIX path) — breaks ties that
       arise on case-sensitive filesystems where both ``README.md`` and
       ``readme.md`` can coexist; the secondary key makes the sort strict and
       fully deterministic for every possible file pair.

    Without this normalisation the filesystem enumeration order can diverge
    across operating systems, producing different Merkle roots for datasets with
    duplicate-content files.

    Args:
        directory: Root of the dataset directory to scan.

    Returns:
        List of ``{"path": str, "hash": str, "size": int}`` dicts, sorted by
        the two-level key described above.
    """
    entries = []
    for f in directory.rglob("*"):
        if not f.is_file():
            continue
        rel_posix = f.relative_to(directory).as_posix()
        entries.append({
            "path": rel_posix,
            "hash": _chunked_blake3(f),
            "size": f.stat().st_size,
            # Transient sort key — stripped before manifest assembly.
            "sort_key": rel_posix.casefold(),
        })

    # Two-level sort: case-folded primary, original path as tie-breaker.
    entries.sort(key=lambda e: (e["sort_key"], e["path"]))

    # Strip the transient sort_key; it must not appear in the manifest.
    return [{k: v for k, v in e.items() if k != "sort_key"} for e in entries]


def _compute_merkle_root(file_entries: list[dict]) -> str:
    """Compute the Merkle root over the file hashes in *file_entries*.

    Only the ``"hash"`` field of each entry is used as a Merkle leaf; ``"path"``
    and ``"size"`` are manifest metadata, not leaf data.

    Returns the canonical ``EMPTY_TREE_HASH`` for an empty dataset.

    Args:
        file_entries: List of ``{"path": str, "hash": str, "size": int}`` dicts
            (order matters).

    Returns:
        Hex-encoded Merkle root hash.
    """
    if not file_entries:
        return EMPTY_TREE_HASH.hex()
    leaf_bytes = [bytes.fromhex(e["hash"]) for e in file_entries]
    return MerkleTree(leaf_bytes).get_root().hex()


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _cmd_dataset_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 signing keypair and write it to disk.

    Writes two files:
        <output>.priv  -- hex-encoded 32-byte signing (private) key
        <output>.pub   -- hex-encoded 32-byte verify (public) key

    Args:
        args: Parsed CLI arguments with ``output`` and ``overwrite`` fields.

    Returns:
        0 on success, 1 on error.
    """
    priv_path = Path(f"{args.output}.priv")
    pub_path = Path(f"{args.output}.pub")

    if not args.overwrite:
        for p in (priv_path, pub_path):
            if p.exists():
                print(
                    f"Error: Key file already exists: {p} (use --overwrite to replace)",
                    file=sys.stderr,
                )
                return 1

    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    priv_path.write_bytes(signing_key.encode(nacl.encoding.HexEncoder))
    pub_path.write_bytes(verify_key.encode(nacl.encoding.HexEncoder))

    print(f"Keys generated:\n  Private: {priv_path}\n  Public:  {pub_path}")
    return 0


def _cmd_dataset_commit(args: argparse.Namespace) -> int:
    """Scan a directory, build a canonical manifest, sign it, and emit a commit bundle.

    The commit bundle is printed as JSON to stdout (or written to *args.output*
    when provided).  The bundle may be fed directly to ``dataset verify`` for
    offline validation.

    Args:
        args: Parsed CLI arguments.

    Returns:
        0 on success, 1 on error.
    """
    # 1. Load signing key.
    try:
        signing_key = nacl.signing.SigningKey(
            Path(args.private_key).read_bytes(), encoder=nacl.encoding.HexEncoder
        )
    except FileNotFoundError:
        print(f"Error: Private key file not found: {args.private_key}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error loading private key: {exc}", file=sys.stderr)
        return 1

    pubkey_hex = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode()

    # 2. Compute dataset logical identity (scoped by namespace + committer).
    ds_id = dataset_key(args.dataset_name, args.source_uri, args.namespace, pubkey_hex)

    # 3. Scan directory — files are sorted by case-folded POSIX path.
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: Not a directory: {args.directory}", file=sys.stderr)
        return 1

    file_entries = _scan_files(directory)

    # 4. Compute Merkle root over file hashes (EMPTY_TREE_HASH when no files).
    root_hash = _compute_merkle_root(file_entries)

    # 5. Build canonical manifest.
    manifest: dict = {
        "dataset_id": ds_id,
        "files": file_entries,
        "root_hash": root_hash,
        "version": "1.0.0",
    }

    # 6. Canonical hash of the manifest (domain-separated via hash_bytes).
    manifest_bytes = document_to_bytes(manifest)
    manifest_hash = hash_bytes(manifest_bytes).hex()

    # 7. Deterministic commit ID — content only, no timestamp (ADR-0010 v4).
    commit_id = compute_dataset_commit_id(
        ds_id, args.parent or "", manifest_hash, pubkey_hex
    )

    # 8. Sign the commit ID with the Ed25519 signing key.
    signature_hex = signing_key.sign(commit_id.encode()).signature.hex()

    # 9. Assemble the bundle.
    bundle = {
        "dataset_id": ds_id,
        "commit_id": commit_id,
        "parent_id": args.parent or "",
        "manifest": manifest,
        "committer_pubkey": pubkey_hex,
        "signature": signature_hex,
    }

    bundle_json = json.dumps(bundle, indent=2)

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.write_text(bundle_json, encoding="utf-8")
        except OSError as exc:
            print(f"Error writing bundle: {exc}", file=sys.stderr)
            return 1
        print(f"Bundle written to: {output_path}")
    else:
        print(bundle_json)

    return 0


def _cmd_dataset_verify(args: argparse.Namespace) -> int:
    """Offline verification of a dataset commit bundle.

    Checks three independent invariants:
        1. The Merkle root stored in the manifest matches the file hashes.
        2. The commit ID is reproducible from the manifest hash and metadata.
        3. The Ed25519 signature over the commit ID is valid.

    All failures are reported before returning so that a single pass surfaces
    every issue.

    Args:
        args: Parsed CLI arguments with ``bundle_file`` field.

    Returns:
        0 if all checks pass, 1 if any check fails.
    """
    try:
        bundle = json.loads(Path(args.bundle_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: Bundle file not found: {args.bundle_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in bundle file: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []

    # 1. Verify Merkle root is consistent with file_entries.
    manifest = bundle.get("manifest", {})
    file_entries = manifest.get("files", [])
    expected_root = _compute_merkle_root(file_entries)
    if expected_root != manifest.get("root_hash"):
        errors.append("Merkle root_hash mismatch")

    # 2. Verify commit ID is reproducible from manifest content.
    manifest_bytes = document_to_bytes(manifest)
    actual_manifest_hash = hash_bytes(manifest_bytes).hex()
    expected_commit_id = compute_dataset_commit_id(
        bundle["dataset_id"],
        bundle["parent_id"],
        actual_manifest_hash,
        bundle["committer_pubkey"],
    )
    if expected_commit_id != bundle["commit_id"]:
        errors.append("Commit ID mismatch")

    # 3. Verify Ed25519 signature over the commit ID.
    try:
        verify_key = nacl.signing.VerifyKey(
            bundle["committer_pubkey"], encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(bundle["commit_id"].encode(), bytes.fromhex(bundle["signature"]))
    except nacl.exceptions.BadSignatureError:
        errors.append("Ed25519 signature invalid")
    except Exception as exc:
        errors.append(f"Signature verification error: {exc}")

    if errors:
        for msg in errors:
            print(f"\u2717 {msg}")
        return 1

    print("\u2713 Merkle root consistent")
    print("\u2713 Commit ID deterministic")
    print("\u2713 Ed25519 signature valid")
    return 0


# ---------------------------------------------------------------------------
# Argument parser builder (called by tools/olympus.py and standalone __main__)
# ---------------------------------------------------------------------------


def build_dataset_parser(ds_parser: argparse.ArgumentParser) -> None:
    """Attach dataset sub-commands to *ds_parser*.

    Args:
        ds_parser: The ``dataset`` sub-parser to populate.
    """
    ds_sub = ds_parser.add_subparsers(dest="ds_command", required=True)

    # -- keygen ---------------------------------------------------------------
    keygen_p = ds_sub.add_parser("keygen", help="Generate an Ed25519 signing keypair")
    keygen_p.add_argument(
        "-o",
        "--output",
        default="dataset_key",
        help="Key file prefix (default: dataset_key); writes <prefix>.priv and <prefix>.pub",
    )
    keygen_p.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing key files",
    )

    # -- commit ---------------------------------------------------------------
    commit_p = ds_sub.add_parser(
        "commit",
        help="Scan a directory, build a signed manifest, and emit a commit bundle",
    )
    commit_p.add_argument("directory", help="Path to the dataset directory to scan")
    commit_p.add_argument(
        "--private-key",
        required=True,
        help="Path to the .priv key file generated by 'dataset keygen'",
    )
    commit_p.add_argument("--dataset-name", required=True, help="Human-readable dataset name")
    commit_p.add_argument("--source-uri", required=True, help="Origin URI of the dataset")
    commit_p.add_argument(
        "--namespace",
        default="default",
        help="Canonical namespace scoping dataset identity (default: default)",
    )
    commit_p.add_argument(
        "--parent",
        default="",
        help="Parent commit ID (empty string for genesis commit)",
    )
    commit_p.add_argument(
        "-o",
        "--output",
        default="",
        help="Write the commit bundle JSON to this file instead of stdout",
    )

    # -- verify ---------------------------------------------------------------
    verify_p = ds_sub.add_parser(
        "verify",
        help="Offline verification of a dataset commit bundle",
    )
    verify_p.add_argument("bundle_file", help="Path to the commit bundle JSON file")


def dispatch_dataset(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``dataset`` sub-command to the correct handler.

    Args:
        args: Parsed CLI arguments with ``ds_command`` field.

    Returns:
        Exit code (0 = success).
    """
    if args.ds_command == "keygen":
        return _cmd_dataset_keygen(args)
    if args.ds_command == "commit":
        return _cmd_dataset_commit(args)
    if args.ds_command == "verify":
        return _cmd_dataset_verify(args)
    print(f"Unknown dataset sub-command: {args.ds_command}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dataset",
        description="Olympus dataset provenance CLI (ADR-0010)",
    )
    build_dataset_parser(parser)
    args = parser.parse_args()
    return dispatch_dataset(args)


if __name__ == "__main__":
    sys.exit(main())
