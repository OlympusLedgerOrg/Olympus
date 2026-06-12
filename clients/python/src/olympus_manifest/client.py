"""Local hashing helpers and an optional HTTP client for an Olympus node.

The hashing/scan helpers let a pipeline build a record index in Python; the
authoritative manifest *commitment* (``manifest_root``) is produced by the Rust
``olympus`` CLI / ``olympus-manifest`` crate (the cryptographic source of
truth), so this module verifies and transports rather than re-deriving roots —
the same split as the JavaScript verifier.

HTTP calls require the optional ``requests`` dependency (``pip install
olympus-manifest[http]``).
"""

from __future__ import annotations

import os
from typing import Iterator

from blake3 import blake3


def hash_file(path: str, chunk_size: int = 1 << 16) -> tuple[str, int]:
    """Stream a file through BLAKE3; return ``(hex_digest, byte_len)``."""
    h = blake3()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def _walk(root: str) -> Iterator[str]:
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            yield os.path.join(dirpath, name)


def scan(root: str, shard: str = "files", shard_from_subdir: bool = False) -> dict:
    """Hash every file under ``root`` into a record-index dict.

    With ``shard_from_subdir`` the first path component is the shard id; files
    directly under ``root`` use ``_root``. Record ids are POSIX relative paths.
    The shape matches ``olympus_manifest::RecordIndex`` so it round-trips through
    the Rust CLI.
    """
    shards: dict[str, list[dict]] = {}
    for path in sorted(_walk(root)):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        digest, size = hash_file(path)
        if shard_from_subdir:
            head = rel.split("/", 1)
            shard_id = head[0] if len(head) == 2 else "_root"
        else:
            shard_id = shard
        shards.setdefault(shard_id, []).append(
            {"record_id": rel, "content_hash": digest, "version": 1, "byte_size": size}
        )
    return {
        "shards": [
            {"shard_id": sid, "records": recs} for sid, recs in sorted(shards.items())
        ]
    }


class OlympusClient:
    """Thin HTTP client for committing manifests and pulling ledger proofs."""

    def __init__(self, server: str, api_key: str | None = None):
        self.server = server.rstrip("/")
        self.api_key = api_key

    def _requests(self):
        try:
            import requests  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover - exercised only without extra
            raise RuntimeError(
                "HTTP features need the 'requests' extra: pip install olympus-manifest[http]"
            ) from e
        return requests

    def commit(self, manifest_path: str, shard: str = "files") -> dict:
        """POST a manifest blob to ``/ingest/files`` (anchors its root)."""
        requests = self._requests()
        with open(manifest_path, "rb") as f:
            data = f.read()
        import json

        manifest = json.loads(data)
        record_id = f"{manifest['dataset_id']}:v{manifest['version']}"
        headers = {"x-api-key": self.api_key} if self.api_key else {}
        resp = requests.post(
            f"{self.server}/ingest/files",
            files={"file": (f"{manifest['dataset_id']}.manifest.json", data, "application/json")},
            data={"shard_id": shard, "record_id": record_id},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_proof(self, content_hash: str) -> dict:
        """GET a committed blob's snapshot proof by BLAKE3 content hash."""
        requests = self._requests()
        resp = requests.get(
            f"{self.server}/ingest/records/hash/{content_hash}/verify", timeout=60
        )
        resp.raise_for_status()
        return resp.json()
