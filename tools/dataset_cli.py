#!/usr/bin/env python3
"""
Dataset provenance CLI for Olympus (ADR-0010).

Implements:
    dataset keygen  -- Generate an Ed25519 signing keypair
    dataset commit  -- Scan a directory, build a signed manifest, emit a commit bundle
    dataset push    -- Submit a commit bundle to a running Olympus server
    dataset verify  -- Offline verification of a commit bundle
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# Allow running as a standalone script or being imported by tools/olympus.py.
sys.path.insert(0, str(Path(__file__).parent.parent))

import blake3 as _blake3
import nacl.encoding
import nacl.exceptions
import nacl.signing

from protocol.canonical import document_to_bytes
from protocol.hashes import compute_dataset_commit_id, dataset_key, hash_bytes
from protocol.merkle import EMPTY_TREE_HASH, MerkleTree


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

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

    Only regular files are included.  Symlinks, directories, device nodes, and
    any other non-regular filesystem objects are silently skipped so that the
    manifest represents only transferable file content.

    Ordering contract
    -----------------
    Entries are sorted with a two-level key:

    1. **Primary**: ``rel_path.casefold()`` — Unicode-aware case-folding
       (a superset of ``.lower()``) ensures identical leaf order on
       case-insensitive filesystems (NTFS, APFS) and case-sensitive filesystems
       (ext4) when files share identical content.  Unlike ``.lower()``,
       ``casefold()`` correctly maps German ``ß`` to ``ss``, Greek capital
       ``Σ`` to ``σ``, etc.
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
        the two-level key described above.  Symlinks and special files are not
        included.
    """
    entries = []
    for f in directory.rglob("*"):
        # Symlinks are excluded even when they point to a regular file:
        # is_file() follows symlinks, so we must test is_symlink() first.
        if f.is_symlink() or not f.is_file():
            continue
        rel_posix = f.relative_to(directory).as_posix()
        entries.append(
            {
                "path": rel_posix,
                "hash": _chunked_blake3(f),
                "size": f.stat().st_size,
                # Transient sort key — stripped before manifest assembly.
                "sort_key": rel_posix.casefold(),
            }
        )

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
    commit_id = compute_dataset_commit_id(ds_id, args.parent or "", manifest_hash, pubkey_hex)

    # 8. Sign the commit ID with the Ed25519 signing key.
    #    The commit_id is a hex string; bytes.fromhex converts it to the raw
    #    32-byte hash for signing, matching server-side verification convention.
    signature_hex = signing_key.sign(bytes.fromhex(commit_id)).signature.hex()

    # 9. Assemble the bundle.
    bundle = {
        "dataset_id": ds_id,
        "commit_id": commit_id,
        "parent_id": args.parent or "",
        "manifest": manifest,
        "committer_pubkey": pubkey_hex,
        "signature": signature_hex,
        "dataset_name": args.dataset_name,
        "source_uri": args.source_uri,
        "namespace": args.namespace,
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
        verify_key.verify(bytes.fromhex(bundle["commit_id"]), bytes.fromhex(bundle["signature"]))
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


def _cmd_dataset_push(args: argparse.Namespace) -> int:
    """Submit a commit bundle to a running Olympus server.

    Reads the JSON bundle produced by ``dataset commit``, builds the
    server-side canonical manifest, re-computes the deterministic commit ID
    and signature using the same key, then POSTs the request.

    The CLI and server use different canonical manifest formats, so push
    bridges them by constructing the API-format manifest from the bundle
    metadata and re-signing with the original private key.

    Args:
        args: Parsed CLI arguments.

    Returns:
        0 on success, 1 on error.
    """
    from protocol.canonical_json import canonical_json_bytes
    from protocol.hashes import blake3_hash

    # 1. Read the bundle.
    try:
        bundle = json.loads(Path(args.bundle_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: Bundle file not found: {args.bundle_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in bundle file: {exc}", file=sys.stderr)
        return 1

    # 2. Load signing key (needed to re-sign with the server manifest format).
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
    if pubkey_hex != bundle.get("committer_pubkey"):
        print(
            "Error: Private key does not match committer_pubkey in bundle",
            file=sys.stderr,
        )
        return 1

    # 3. Extract fields from the bundle.
    manifest = bundle.get("manifest", {})
    file_entries = manifest.get("files", [])

    # Metadata may be embedded in the bundle (from recent commit) or supplied
    # via CLI flags.
    dataset_name = args.dataset_name or bundle.get("dataset_name")
    source_uri = args.source_uri or bundle.get("source_uri")
    namespace = args.namespace or bundle.get("namespace", "default")

    if not dataset_name:
        print(
            "Error: --dataset-name is required (not found in bundle)",
            file=sys.stderr,
        )
        return 1
    if not source_uri:
        print(
            "Error: --source-uri is required (not found in bundle)",
            file=sys.stderr,
        )
        return 1

    # 4. Map CLI bundle file entries to API format.
    api_files = []
    for f in file_entries:
        api_files.append(
            {
                "path": f["path"],
                "content_hash": f["hash"],
                "byte_size": f["size"],
                "record_count": None,
            }
        )

    if not api_files:
        print("Error: Bundle manifest contains no files", file=sys.stderr)
        return 1

    # 5. Build the server-side canonical manifest and re-compute identifiers.
    #    The server uses a different manifest schema than the CLI, so we must
    #    build the server-format manifest to get matching hashes.
    server_manifest = {
        "dataset_name": dataset_name,
        "dataset_version": args.dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": namespace,
        "granularity": args.granularity,
        "license_spdx": args.license_spdx,
        "license_uri": None,
        "usage_restrictions": [],
        "file_format": args.file_format,
        "files": api_files,
        "manifest_schema_version": "dataset_manifest_v1",
    }
    server_manifest_hash = blake3_hash([canonical_json_bytes(server_manifest)]).hex()

    ds_id = dataset_key(dataset_name, source_uri, namespace, pubkey_hex)
    parent_id = bundle.get("parent_id") or ""
    commit_id = compute_dataset_commit_id(ds_id, parent_id, server_manifest_hash, pubkey_hex)

    # Re-sign the commit ID using the server convention (raw hash bytes).
    signature_hex = signing_key.sign(bytes.fromhex(commit_id)).signature.hex()

    # 6. Assemble the API request body.
    request_body = {
        "dataset_name": dataset_name,
        "dataset_version": args.dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": namespace,
        "granularity": args.granularity,
        "license_spdx": args.license_spdx,
        "file_format": args.file_format,
        "files": api_files,
        "parent_commit_id": parent_id or None,
        "committer_pubkey": pubkey_hex,
        "commit_signature": signature_hex,
    }

    # 7. POST to the server.
    server = args.server.rstrip("/")
    url = f"{server}/datasets/commit"
    payload = json.dumps(request_body).encode("utf-8")

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if args.api_key:
        headers["X-API-Key"] = args.api_key

    req = Request(url, data=payload, headers=headers, method="POST")

    try:
        with urlopen(req) as resp:  # noqa: S310 -- URL comes from CLI arg
            resp_body = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except Exception:
            detail = str(exc)
        print(f"Error: Server returned {exc.code}: {detail}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"Error: Could not reach server at {server}: {exc.reason}", file=sys.stderr)
        return 1

    # 8. Report success.
    print(f"\u2713 Pushed to {server}")
    print(f"  dataset_id:  {resp_body.get('dataset_id', 'N/A')}")
    print(f"  commit_id:   {resp_body.get('commit_id', 'N/A')}")
    print(f"  merkle_root: {resp_body.get('merkle_root', 'N/A')}")
    print(f"  shard_id:    {resp_body.get('shard_id', 'N/A')}")
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
        description=(
            "Recursively scan a directory for regular files, build a canonical manifest "
            "with a Merkle root, compute a deterministic commit ID, sign it with an "
            "Ed25519 key, and emit a verifiable commit bundle.  "
            "Symlinks and non-regular files (devices, sockets, etc.) are skipped."
        ),
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

    # -- push -----------------------------------------------------------------
    push_p = ds_sub.add_parser(
        "push",
        help="Submit a commit bundle to a running Olympus server",
        description=(
            "Read a commit bundle JSON file (produced by 'dataset commit') and "
            "POST it to a running Olympus server's /datasets/commit endpoint.  "
            "Metadata fields not present in the bundle can be supplied via flags."
        ),
    )
    push_p.add_argument("bundle_file", help="Path to the commit bundle JSON file")
    push_p.add_argument(
        "--server",
        required=True,
        help="Base URL of the Olympus server (e.g. http://localhost:8000)",
    )
    push_p.add_argument(
        "--private-key",
        required=True,
        help="Path to the .priv key file (same key used for 'dataset commit')",
    )
    push_p.add_argument(
        "--api-key",
        default="",
        help="API key for server authentication (sent as X-API-Key header)",
    )
    push_p.add_argument(
        "--dataset-name",
        default="",
        help="Dataset name (overrides value from bundle if set)",
    )
    push_p.add_argument(
        "--source-uri",
        default="",
        help="Source URI (overrides value from bundle if set)",
    )
    push_p.add_argument(
        "--namespace",
        default="",
        help="Canonical namespace (overrides value from bundle if set)",
    )
    push_p.add_argument(
        "--dataset-version",
        default="1.0.0",
        help="Dataset version string (default: 1.0.0)",
    )
    push_p.add_argument(
        "--license-spdx",
        default="MIT",
        help="SPDX license identifier (default: MIT)",
    )
    push_p.add_argument(
        "--file-format",
        default="csv",
        help="Primary file format (default: csv)",
    )
    push_p.add_argument(
        "--granularity",
        default="file",
        choices=["file", "record", "shard"],
        help="Dataset granularity (default: file)",
    )


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
    if args.ds_command == "push":
        return _cmd_dataset_push(args)
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
