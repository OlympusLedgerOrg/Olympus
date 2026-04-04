"""
Upload validation helpers — magic-byte MIME type detection and enforcement.

Validates uploaded file content against an allowlist of safe MIME types
rather than trusting the client-supplied ``Content-Type`` header.

**ZIP archives** (``application/zip``) are guarded by three checks before
acceptance:

- **Path guard** — every entry path is resolved under a sentinel root using
  ``os.path.commonpath``; entries that escape the root are rejected
  (Zip Slip / path-traversal prevention).
- **Ratio guard** — no individual entry may have a compression ratio above
  :data:`_MAX_COMPRESSION_RATIO` (50:1), blocking zip-bomb attacks.
  Ratios are computed from central-directory metadata; no decompression occurs.
- **Size guard** — total declared uncompressed size may not exceed
  :data:`_MAX_DECOMPRESSED_BYTES` (100 MB).

**Zstandard streams** (``application/zstd``) are guarded by two checks:

- **Header size guard** — the optional embedded ``content_size`` field in the
  zstd frame header is checked first; if the declared size exceeds the limit
  the archive is rejected without any decompression.
- **Streaming size + ratio guard** — the stream is decompressed in 64 KB
  chunks up to :data:`_MAX_DECOMPRESSED_BYTES`; the decompressor is capped at
  a 64 MB dictionary window (``max_window_size``) to prevent memory bombs.
  The final ratio is checked against :data:`_MAX_COMPRESSION_RATIO` (50:1).
  No Zip Slip check is needed because zstd is a single-stream format with no
  member file paths.

Formats **not** supported for upload:

- ``tar.gz`` / ``.tar.xz`` / ``.tar.bz2`` — no central directory; impossible
  to inspect member sizes without full decompression.
- Brotli (``.br``) — single-stream; no standard multi-file container.
- LZMA (``.xz`` standalone) — very slow decompression creates a CPU-exhaustion
  DoS vector regardless of size limits.
"""

from __future__ import annotations

import io
import logging
import os
import stat
import zipfile

import magic
from fastapi import HTTPException


try:
    import zstandard as zstd  # optional: only needed for application/zstd uploads
except ImportError:  # pragma: no cover
    zstd = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)

# Shared limits applied to both ZIP and Zstandard validation.
# 100 MB total decompressed; 50:1 max ratio (normal DEFLATE/zstd rarely
# exceeds 10:1; values above 50:1 are a reliable bomb indicator).
_MAX_DECOMPRESSED_BYTES: int = 100 * 1024 * 1024
_MAX_COMPRESSION_RATIO: float = 50.0
_MAX_ZSTD_WINDOW_SIZE: int = 2**26  # 64 MB LZ77 back-reference window cap
_ZSTD_CHUNK_SIZE: int = 65536  # 64 KB streaming read chunks

# Sentinel base used solely for ZIP path-containment checks; never written to disk.
_ZIP_SAFETY_BASE: str = "/zip_extract_root"

ALLOWED_MIME_TYPES: set[str] = {
    "application/pdf",
    "text/plain",
    "text/html",
    "application/json",
    "image/png",
    "image/jpeg",
    "image/tiff",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
    "application/zstd",
    "application/xml",
    "text/xml",
}


# ---------------------------------------------------------------------------
# ZIP safety helpers
# ---------------------------------------------------------------------------


def _zip_member_path_is_safe(filename: str) -> bool:
    """Return True when *filename* stays inside :data:`_ZIP_SAFETY_BASE`.

    Uses ``os.path.commonpath`` (the standard recommended technique) to verify
    that the normalised resolved path shares the sentinel base as a common
    prefix.  This correctly rejects:

    * Absolute paths (``/etc/passwd``)
    * Parent-traversal paths (``../../root/.ssh/authorized_keys``)
    * Null-byte injections (``file\\x00.txt``)
    * Mixed-separator tricks on all platforms
    """
    if "\x00" in filename:
        return False
    candidate = os.path.normpath(os.path.join(_ZIP_SAFETY_BASE, filename))
    try:
        return os.path.commonpath([_ZIP_SAFETY_BASE, candidate]) == _ZIP_SAFETY_BASE
    except ValueError:
        return False


def validate_zip_safety(content: bytes) -> None:
    """Validate a ZIP archive against bomb and path-traversal attacks.

    Reads **only** the ZIP central-directory metadata — no actual
    decompression occurs, so even a pathological 42.zip bomb cannot exhaust
    memory during this check.

    **Symlink rejection:** ZIP entries with Unix symlink file modes are
    rejected with HTTP 400. Content is never extracted.

    Args:
        content: Raw bytes of the ZIP archive (magic bytes already verified).

    Raises:
        HTTPException 400: Corrupt archive, path-traversal entry, size limit
            exceeded, suspicious compression ratio, or symlink detected.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as zf:
            total_uncompressed = 0
            for info in zf.infolist():
                # ── Symlink guard ────────────────────────────────────────────
                # external_attr >> 16 gives the Unix file mode; reject symlinks
                unix_mode = info.external_attr >> 16
                if unix_mode and stat.S_ISLNK(unix_mode):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"ZIP entry is a symlink: {info.filename!r} — rejected."
                        ),
                    )

                # ── Path guard (Zip Slip / path traversal) ──────────────────
                if not _zip_member_path_is_safe(info.filename):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"ZIP entry path traversal detected: {info.filename!r} — rejected."
                        ),
                    )

                # ── Ratio guard (zip bomb, per-entry) ────────────────────────
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > _MAX_COMPRESSION_RATIO:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"ZIP entry compression ratio {ratio:.0f}:1 exceeds the "
                                f"{_MAX_COMPRESSION_RATIO:.0f}:1 limit — possible zip bomb."
                            ),
                        )

                # ── Size guard (cumulative uncompressed) ─────────────────────
                total_uncompressed += info.file_size
                if total_uncompressed > _MAX_DECOMPRESSED_BYTES:
                    limit_mb = _MAX_DECOMPRESSED_BYTES // (1024 * 1024)
                    raise HTTPException(
                        status_code=400,
                        detail=f"ZIP total uncompressed size exceeds the {limit_mb} MB limit.",
                    )
    except zipfile.BadZipFile as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid or corrupt ZIP archive.",
        ) from exc


# ---------------------------------------------------------------------------
# Zstandard safety helpers
# ---------------------------------------------------------------------------


def validate_zstd_safety(content: bytes) -> None:
    """Validate a Zstandard stream against decompression-bomb attacks.

    Strategy (two-phase, most conservative first):

    1. **Header check** — reads the optional ``content_size`` field from the
       zstd frame header.  If the declared size is present and already exceeds
       :data:`_MAX_DECOMPRESSED_BYTES`, the stream is rejected instantly with
       zero decompression work.
    2. **Streaming check** — decompresses in 64 KB chunks, aborting as soon as
       the running total exceeds :data:`_MAX_DECOMPRESSED_BYTES`.  The
       decompressor is constrained to a 64 MB dictionary window
       (``max_window_size=2**26``) to prevent memory bombs via crafted large
       window sizes.  After the stream is drained the overall ratio is checked
       against :data:`_MAX_COMPRESSION_RATIO`.

    No path-traversal check is needed: zstd is a single-stream compressor with
    no embedded file paths.

    Args:
        content: Raw bytes of the Zstandard stream (magic bytes already verified).

    Raises:
        HTTPException 400: Corrupt stream, size limit exceeded, or ratio too high.
    """
    if zstd is None:  # pragma: no cover
        raise HTTPException(
            status_code=415,
            detail="Zstandard support is not installed on this server.",
        )

    compressed_size = len(content)
    if compressed_size == 0:
        raise HTTPException(status_code=400, detail="Empty Zstandard stream.")

    # ── Phase 1: header content_size fast-reject ─────────────────────────────
    try:
        params = zstd.get_frame_parameters(content)
        declared = params.content_size
        if declared not in (zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR):
            if declared > _MAX_DECOMPRESSED_BYTES:
                limit_mb = _MAX_DECOMPRESSED_BYTES // (1024 * 1024)
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Zstandard declared content size {declared // (1024 * 1024)} MB "
                        f"exceeds the {limit_mb} MB limit."
                    ),
                )
    except zstd.ZstdError:
        pass  # Malformed header — streaming phase will catch corruption

    # ── Phase 2: streaming decompression with size + ratio guards ────────────
    # max_window_size caps the LZ77 back-reference window; a crafted frame with
    # a huge window can allocate gigabytes of memory before any output is
    # produced.  64 MB (2**26) is well above any legitimate document need.
    dctx = zstd.ZstdDecompressor(max_window_size=_MAX_ZSTD_WINDOW_SIZE)
    total_decompressed = 0
    try:
        with dctx.stream_reader(io.BytesIO(content), closefd=False) as reader:
            while True:
                chunk = reader.read(_ZSTD_CHUNK_SIZE)
                if not chunk:
                    break
                total_decompressed += len(chunk)
                if total_decompressed > _MAX_DECOMPRESSED_BYTES:
                    limit_mb = _MAX_DECOMPRESSED_BYTES // (1024 * 1024)
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Zstandard total decompressed size exceeds the {limit_mb} MB limit."
                        ),
                    )
    except zstd.ZstdError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid or corrupt Zstandard stream.",
        ) from exc

    # ── Ratio guard ──────────────────────────────────────────────────────────
    if compressed_size > 0 and total_decompressed > 0:
        ratio = total_decompressed / compressed_size
        if ratio > _MAX_COMPRESSION_RATIO:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Zstandard compression ratio {ratio:.0f}:1 exceeds the "
                    f"{_MAX_COMPRESSION_RATIO:.0f}:1 limit — possible decompression bomb."
                ),
            )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def validate_file_magic(content: bytes, declared_content_type: str) -> str:
    """Detect MIME type from file content and enforce the allowlist.

    For ZIP archives the file is passed through :func:`validate_zip_safety`
    to block zip-bomb and path-traversal attacks.  For Zstandard streams the
    file is passed through :func:`validate_zstd_safety` to block decompression
    bombs.  Both checks happen before the bytes reach any further processing.

    Args:
        content: Raw file bytes (at least the first 2048 bytes are inspected).
        declared_content_type: The ``Content-Type`` header supplied by the client.

    Returns:
        The detected MIME type string.

    Raises:
        HTTPException 415: Detected MIME type not in :data:`ALLOWED_MIME_TYPES`.
        HTTPException 400: ZIP or Zstandard archive fails safety checks.
    """
    detected = magic.from_buffer(content[:2048], mime=True)

    if detected not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{detected}' is not permitted.",
        )

    if detected != declared_content_type:
        logger.warning(
            "Content-Type mismatch: declared=%s detected=%s",
            declared_content_type,
            detected,
        )

    if detected == "application/zip":
        validate_zip_safety(content)
    elif detected == "application/zstd":
        validate_zstd_safety(content)

    return detected
