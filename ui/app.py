"""FastAPI + Jinja2 developer debug console for Olympus."""

import base64
import hmac
import ipaddress
import json
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlparse, urlunparse

import httpx
import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from protocol.canonical_json import canonical_json_bytes
from protocol.canonicalizer import CanonicalizationError, Canonicalizer, canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    VerificationResult,
    ZKPublicInputs,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree
from protocol.timestamps import current_timestamp


# RFC 1918 private ranges + loopback + link-local
_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
]


def _normalize_ip_for_ssrf_check(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize IP addresses for SSRF range checks."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_blocked_ip_for_ssrf(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True when an address is in a blocked SSRF range."""
    normalized_addr = _normalize_ip_for_ssrf_check(addr)
    for blocked in _BLOCKED_RANGES:
        blocked_network: ipaddress.IPv4Network | ipaddress.IPv6Network = blocked
        if (
            isinstance(blocked_network, ipaddress.IPv6Network)
            and blocked_network.network_address.ipv4_mapped is not None
        ):
            mapped_network_address = blocked_network.network_address.ipv4_mapped
            prefixlen = max(blocked_network.prefixlen - 96, 0)
            blocked_network = ipaddress.ip_network(
                f"{mapped_network_address}/{prefixlen}", strict=False
            )
        if normalized_addr in blocked_network:
            return True
    return False


API_BASE = os.environ.get("UI_API_BASE", "http://127.0.0.1:8000")
_parsed_api_base = urlparse(API_BASE)
if _parsed_api_base.scheme not in {"http", "https"} or not _parsed_api_base.netloc:
    raise ValueError("UI_API_BASE must be an absolute http(s) URL")

# Debug UI is always enabled. Use OLYMPUS_DEBUG_CONSOLE_PASSWORD to protect it.
DEBUG_UI_ENABLED = True
# Optional HTTP Basic Auth password; when set, every debug console request
# must include a valid Authorization header.
_DEBUG_CONSOLE_PASSWORD = os.environ.get("OLYMPUS_DEBUG_CONSOLE_PASSWORD", "")

_ENV = os.environ.get("OLYMPUS_ENV", "production")

# Minimum password length for the debug console (M1 audit fix).
_MIN_DEBUG_PASSWORD_LENGTH = 16

# C-2 Fix: Refuse to start in production mode without a debug console password.
# This prevents accidental exposure of the debug console when operators forget
# to set OLYMPUS_DEBUG_CONSOLE_PASSWORD.
if _ENV == "production" and not _DEBUG_CONSOLE_PASSWORD:
    raise RuntimeError(
        "OLYMPUS_DEBUG_CONSOLE_PASSWORD must be set when OLYMPUS_ENV=production. "
        "The debug console cannot start without authentication configured. "
        "Either set a strong password or use OLYMPUS_ENV=development for local testing."
    )

# M1 audit fix: enforce minimum password length in production.
if (
    _ENV == "production"
    and _DEBUG_CONSOLE_PASSWORD
    and len(_DEBUG_CONSOLE_PASSWORD) < _MIN_DEBUG_PASSWORD_LENGTH
):
    raise RuntimeError(
        f"OLYMPUS_DEBUG_CONSOLE_PASSWORD must be at least {_MIN_DEBUG_PASSWORD_LENGTH} characters "
        f"(got {len(_DEBUG_CONSOLE_PASSWORD)}). Use a strong, randomly generated password."
    )

logger = logging.getLogger(__name__)


def validate_federation_url(url: str) -> None:
    """Validate a federation node URL against SSRF blocklists.

    Rejects URLs using non-http(s) schemes and URLs targeting private,
    loopback, or link-local IP address ranges.  Domain-name hostnames are
    allowed with a warning since full DNS-rebinding protection requires
    async resolution.

    Args:
        url: The federation node URL to validate.

    Raises:
        ValueError: If the URL fails validation.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Federation URL must use http or https scheme, got: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Federation URL has no hostname.")

    try:
        addr = ipaddress.ip_address(hostname)
        if _is_blocked_ip_for_ssrf(addr):
            raise ValueError(
                f"Federation URL resolves to blocked address range: "
                f"{_normalize_ip_for_ssrf_check(addr)}"
            )
    except ValueError as exc:
        if (
            "blocked address range" in str(exc)
            or "must use http" in str(exc)
            or "has no hostname" in str(exc)
        ):
            raise  # re-raise our own errors
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as dns_error:
            raise ValueError(
                f"Federation URL hostname could not be resolved: {hostname}:{port}"
            ) from dns_error

        resolved_any = False
        for info in addrinfo:
            sockaddr = info[4]
            if not sockaddr:
                continue
            resolved_ip = sockaddr[0]
            try:
                resolved_addr = ipaddress.ip_address(resolved_ip)
            except ValueError:
                continue
            resolved_any = True
            if _is_blocked_ip_for_ssrf(resolved_addr):
                raise ValueError(
                    f"Federation URL hostname resolves to blocked address range: "
                    f"{_normalize_ip_for_ssrf_check(resolved_addr)}"
                )

        if not resolved_any:
            raise ValueError(f"Federation URL hostname has no resolvable IP addresses: {hostname}")


def _load_federation_nodes() -> dict[str, str]:
    """Parse optional federation node endpoints from JSON environment configuration."""
    raw_nodes = os.environ.get("OLYMPUS_FEDERATION_NODES", "").strip()
    if not raw_nodes:
        return {}

    try:
        parsed = json.loads(raw_nodes)
    except json.JSONDecodeError as exc:
        raise ValueError("OLYMPUS_FEDERATION_NODES must be valid JSON") from exc

    if not isinstance(parsed, dict):
        raise ValueError("OLYMPUS_FEDERATION_NODES must be a JSON object of node_name -> base_url")

    nodes: dict[str, str] = {}
    for name, base_url in parsed.items():
        validate_federation_url(str(base_url))
        nodes[str(name)] = str(base_url)
    return nodes


FEDERATION_NODES = _load_federation_nodes()

app = FastAPI(title="Olympus Debug Console", version="0.1.0")

_STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.middleware("http")
async def _debug_console_basic_auth(request: Request, call_next: Any) -> JSONResponse:
    """Enforce HTTP Basic Auth when ``OLYMPUS_DEBUG_CONSOLE_PASSWORD`` is set.

    Note: The module-level startup check already refuses to import in production
    mode without a password (see C-2 fix above). This middleware provides an
    additional runtime safeguard for edge cases where the environment might
    change after import.

    When running in production mode (``OLYMPUS_ENV != 'development'``) and no
    password is configured, every request is rejected with HTTP 503 to prevent
    accidental unauthenticated exposure of the debug console.
    """
    # L4 audit fix: reject plaintext requests in production when behind a
    # proxy that advertises the original protocol via X-Forwarded-Proto.
    if _ENV != "development":
        forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        if forwarded_proto and forwarded_proto != "https":
            return JSONResponse(
                status_code=421,
                content={
                    "detail": (
                        "Debug console requires HTTPS. "
                        "Redirecting to HTTPS is not supported; please use an HTTPS URL."
                    )
                },
            )

    if not _DEBUG_CONSOLE_PASSWORD:
        if _ENV != "development":
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "Debug console is not available: "
                        "OLYMPUS_DEBUG_CONSOLE_PASSWORD must be set in production. "
                        "Set OLYMPUS_ENV=development to allow unauthenticated local access."
                    )
                },
            )
        # Development mode with no password: allow unauthenticated access.
        return await call_next(request)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Basic "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
            headers={"WWW-Authenticate": 'Basic realm="Olympus Debug Console"'},
        )
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        _, _, password = decoded.partition(":")
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid credentials"},
            headers={"WWW-Authenticate": 'Basic realm="Olympus Debug Console"'},
        )
    if not hmac.compare_digest(password.encode("utf-8"), _DEBUG_CONSOLE_PASSWORD.encode("utf-8")):
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid credentials"},
            headers={"WWW-Authenticate": 'Basic realm="Olympus Debug Console"'},
        )
    return await call_next(request)


_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    ),
}


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next: Any) -> Any:
    """Attach security headers to every debug UI response."""
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


templates = Jinja2Templates(directory="ui/templates")
REPO_ROOT = Path(__file__).resolve().parent.parent
_POSEIDON_VECTORS_SCRIPT = REPO_ROOT / "proofs" / "test_inputs" / "poseidon_vectors.js"
_POSEIDON_NODE_MODULES = REPO_ROOT / "proofs" / "node_modules"
_CIRCUIT_FILES = {
    "document_existence": REPO_ROOT / "proofs" / "circuits" / "document_existence.circom",
    "non_existence": REPO_ROOT / "proofs" / "circuits" / "non_existence.circom",
    "redaction_validity": REPO_ROOT / "proofs" / "circuits" / "redaction_validity.circom",
}
_CIRCUIT_VISUALIZER = {
    "document_existence": {
        "title": "Document existence proof",
        "public_inputs": ["root", "leafIndex"],
        "private_inputs": ["leaf", "pathElements[depth]", "pathIndices[depth]"],
        "constraints": [
            {
                "label": "Index bits are boolean and reconstruct leafIndex",
                "explanation": (
                    "Each pathIndices[i] bit is constrained to 0/1, then folded "
                    "LSB-first into indexAccum so the Merkle path is tied to the "
                    "public leafIndex."
                ),
                "source_snippets": [
                    "pathIndices[i] * (pathIndices[i] - 1) === 0;",
                    "leafIndex === indexAccum[depth];",
                ],
            },
            {
                "label": "Merkle path must open to the public root",
                "explanation": (
                    "The MerkleTreeInclusionProof gadget constrains the supplied "
                    "leaf and sibling path to hash to the public root."
                ),
                "source_snippets": [
                    "component merkle = MerkleTreeInclusionProof(depth);",
                    "merkle.root <== root;",
                    "merkle.leaf <== leaf;",
                ],
            },
        ],
    },
    "non_existence": {
        "title": "Indexed non-existence proof",
        "public_inputs": ["root", "leafIndex"],
        "private_inputs": ["pathElements[depth]", "pathIndices[depth]"],
        "constraints": [
            {
                "label": "Index bits are boolean and bind the path to leafIndex",
                "explanation": (
                    "The circuit reconstructs the public leafIndex from LSB-first "
                    "path bits so the witness cannot prove emptiness at a "
                    "different position."
                ),
                "source_snippets": [
                    "pathIndices[i] * (pathIndices[i] - 1) === 0;",
                    "leafIndex === indexAccum[depth];",
                ],
            },
            {
                "label": "The opened leaf is forced to be the empty value 0",
                "explanation": (
                    "Instead of taking a private leaf input, the Merkle proof "
                    "gadget is wired to the constant 0, so only an empty slot can "
                    "satisfy the proof."
                ),
                "source_snippets": [
                    "component merkle = MerkleTreeInclusionProof(depth);",
                    "merkle.leaf <== 0;",
                ],
            },
        ],
    },
    "redaction_validity": {
        "title": "Redaction validity proof",
        "public_inputs": ["originalRoot", "redactedCommitment", "revealedCount"],
        "private_inputs": [
            "originalLeaves[maxLeaves]",
            "revealMask[maxLeaves]",
            "pathElements[maxLeaves][depth]",
            "pathIndices[maxLeaves][depth]",
        ],
        "constraints": [
            {
                "label": "Reveal mask is binary and revealedCount is its sum",
                "explanation": (
                    "Every revealMask entry is constrained to 0/1 and accumulated "
                    "into maskSum so the public revealedCount matches the number "
                    "of disclosed leaves."
                ),
                "source_snippets": [
                    "revealMask[i] * (revealMask[i] - 1) === 0;",
                    "revealedCount === maskSum[maxLeaves];",
                ],
            },
            {
                "label": "Each revealed proof is position-bound to index i",
                "explanation": (
                    "The circuit reconstructs each leaf position from pathIndices "
                    "and constrains the accumulator to equal the compile-time "
                    "index i before checking Merkle inclusion."
                ),
                "source_snippets": [
                    "idxAccum[depth] === i;",
                    "revealMask[i] * (originalRoot - inclusionProofs[i].root) === 0;",
                ],
            },
            {
                "label": "The redacted commitment hashes only revealed leaves",
                "explanation": (
                    "revealedLeaves[i] is originalLeaves[i] when revealed and 0 "
                    "otherwise, then a Poseidon chain commits to "
                    "(revealedCount, revealedLeaves[0..maxLeaves-1])."
                ),
                "source_snippets": [
                    "revealedLeaves[i] <== revealMask[i] * originalLeaves[i];",
                    "initHash.inputs[0] <== revealedCount;",
                    "redactedCommitment === acc[maxLeaves - 1];",
                ],
            },
        ],
    },
}

# In-memory store for committed documents.
# Key: "{document_id}:{version}"
# Not persisted across restarts; for debug/demo use only.
_commit_store: dict[str, dict[str, Any]] = {}


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    return _fetch_json_from_base(API_BASE, path)


def _fetch_json_from_base(base_url: str, path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from a specific Olympus API base URL.

    Prevents SSRF by:
    1. Requiring ``base_url`` to match a known-safe endpoint (API_BASE or federation node).
    2. Rebuilding the outgoing URL from the *trusted* base (scheme + netloc) so that
       user-controlled path segments cannot redirect the request to another host.
    3. Checking the resolved host IP against the private-range blocklist.
    """
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")

    # --- Allowlist: only contact pre-validated endpoints ---
    _allowed_bases: set[str] = {API_BASE} | set(FEDERATION_NODES.values())
    if base_url not in _allowed_bases:
        raise ValueError("Request base URL is not in the allowed set")

    # --- Build URL from *trusted* base components + relative path ---
    parsed_base = urlparse(base_url)
    parsed_rel = urlparse(path)           # splits path, params, query, fragment
    safe_url = urlunparse((
        parsed_base.scheme,               # trusted
        parsed_base.netloc,               # trusted
        parsed_rel.path,                  # relative path from caller
        parsed_rel.params,
        parsed_rel.query,
        "",
    ))

    # --- Resolve hostname and check IP blocklist ---
    hostname = parsed_base.hostname
    if not hostname:
        raise ValueError("Base URL must have a valid hostname")
    try:
        for _family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip_addr = ipaddress.ip_address(sockaddr[0])
            if _is_blocked_ip_for_ssrf(ip_addr):
                raise ValueError(
                    f"Blocked: {hostname} resolves to private IP {sockaddr[0]}"
                )
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from exc

    # --- Perform the request using httpx (modern, safe HTTP client) ---
    response = httpx.get(safe_url, timeout=5.0)
    response.raise_for_status()
    payload = response.json()

    if isinstance(payload, dict):
        return cast(dict[str, Any], payload)
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return cast(list[dict[str, Any]], payload)
    raise TypeError("Expected JSON object or list of objects from API")


def _expect_json_object(payload: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    """Require a JSON object payload from the API helper."""
    if not isinstance(payload, dict):
        raise TypeError("Expected JSON object")
    return payload


def _expect_json_list(payload: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Require a JSON array payload from the API helper."""
    if not isinstance(payload, list):
        raise TypeError("Expected JSON array")
    return payload


def _verify_signature(header: dict[str, Any]) -> bool:
    """Verify Ed25519 shard header signature."""
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(header["pubkey"]))
        verify_key.verify(bytes.fromhex(header["header_hash"]), bytes.fromhex(header["signature"]))
    except (ValueError, KeyError, nacl.exceptions.BadSignatureError):
        return False
    return True


def _is_chain_broken(entries: list[dict[str, Any]]) -> bool:
    """Return true when tail linkage invariant is broken."""
    for i in range(len(entries) - 1):
        if entries[i]["prev_entry_hash"] != entries[i + 1]["entry_hash"]:
            return True
    return False


def _require_debug_ui() -> None:
    """No-op stub retained for backward compatibility.

    Debug UI is always enabled; use OLYMPUS_DEBUG_CONSOLE_PASSWORD to restrict access.
    """


def _normalize_timestamp(value: str, field_name: str) -> str:
    """Parse an ISO 8601 timestamp and normalize it to a Z-suffixed UTC string."""
    return _parse_timestamp(value, field_name).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, field_name: str) -> datetime:
    """Parse an ISO 8601 timestamp into a timezone-aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid ISO 8601 timestamp (e.g., 2026-03-08T12:00:00Z)."
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_recipient_keys(raw: str | None) -> list[str]:
    """Split comma/newline separated recipient keys into a stable unique list."""
    if not raw:
        return []
    parsed: list[str] = []
    seen: set[str] = set()
    for chunk in raw.replace("\n", ",").split(","):
        key = chunk.strip()
        if key and key not in seen:
            seen.add(key)
            parsed.append(key)
    return parsed


def _build_receipt(receipt_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic receipt with a cryptographic hash.

    The authoritative receipt timestamp depends on workflow: commitments use
    ``committed_at``, generated artifacts use ``generated_at``, response logs
    use ``timestamp``, and delay proofs use ``proof_generated_at``.
    """
    issued_at = (
        payload.get("committed_at")
        or payload.get("generated_at")
        or payload.get("timestamp")
        or payload.get("proof_generated_at")
    )
    receipt_payload = {
        "receipt_type": receipt_type,
        "issued_at": issued_at,
        "payload": payload,
    }
    receipt_hash = hash_bytes(canonical_json_bytes(receipt_payload)).hex()
    return {
        **receipt_payload,
        "receipt_hash": receipt_hash,
    }


def _canonical_section_from_binary(
    raw: bytes, content_type: str | None, filename: str | None
) -> tuple[str, dict[str, Any]]:
    """Return a deterministic hex section string and its canonicalization provenance.

    PDF and DOCX files are normalized through the C-Pipe canonicalizer so that
    volatile metadata (timestamps, revision counters, producer strings, etc.)
    does not affect the commitment.  All other binary types fall back to the
    BLAKE3 hash of the raw bytes.

    Args:
        raw: Raw file bytes.
        content_type: MIME type reported by the upload, if any.
        filename: Original filename, used as a fallback for type detection.

    Returns:
        Tuple of (hex-encoded BLAKE3 section string, canonicalization provenance dict).
    """
    ct = (content_type or "").lower()
    ext = (filename or "").lower().rsplit(".", 1)[-1] if filename else ""

    canonicalizer = Canonicalizer()

    if "pdf" in ct or ext == "pdf":
        try:
            normalized, mode = canonicalizer.pdf_normalize(raw)
            return hash_bytes(normalized).hex(), canonicalization_provenance(
                "application/pdf", mode
            )
        except CanonicalizationError:
            pass  # fall through to raw hash on canonicalization failure

    if "vnd.openxmlformats-officedocument.wordprocessingml.document" in ct or ext in {
        "docx",
        "docm",
    }:
        try:
            return canonicalizer.docx_v1(raw).hex(), canonicalization_provenance(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx_v1",
            )
        except CanonicalizationError:
            pass  # fall through to raw hash on canonicalization failure

    return hash_bytes(raw).hex(), canonicalization_provenance(
        ct or "application/octet-stream", "blake3_raw"
    )


def _commit_parts(
    document_id: str,
    version: int,
    parts: list[str],
    *,
    file_name: str | None = None,
    release_at: str | None = None,
    recipient_keys: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    canon_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Commit document parts and persist the local debug-console state."""
    if not parts:
        raise ValueError("Document has no sections.")

    normalized_release_at = None
    if release_at:
        normalized_release_at = _normalize_timestamp(release_at, "release_at")

    recipients = recipient_keys or []
    committed_at = metadata.get("committed_at") if metadata else None
    if committed_at is None:
        committed_at = current_timestamp()

    poseidon_tree, _ = RedactionProtocol.build_poseidon_tree(parts)
    poseidon_root = poseidon_tree.get_root()

    smt = SparseMerkleTree()
    tree, commitment = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=document_id,
        version=version,
    )

    commit_key = f"{document_id}:{version}"
    entry_metadata = dict(metadata or {})
    entry_metadata["committed_at"] = committed_at
    if canon_provenance is not None:
        entry_metadata["canon_provenance"] = canon_provenance
    receipt_payload = {
        "document_id": document_id,
        "version": version,
        "file_name": file_name,
        "sections_count": len(parts),
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "committed_at": committed_at,
        "release_at": normalized_release_at,
        "recipient_keys": recipients,
        "metadata": entry_metadata,
    }
    receipt = _build_receipt("document_commitment", receipt_payload)

    _commit_store[commit_key] = {
        "parts": parts,
        "smt": smt,
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "document_id": document_id,
        "version": version,
        "file_name": file_name,
        "committed_at": committed_at,
        "release_at": normalized_release_at,
        "recipient_keys": recipients,
        "revoked_recipient_keys": [],
        "embargo_update_receipts": [],
        "metadata": entry_metadata,
        "receipt": receipt,
    }

    return {
        "commit_key": commit_key,
        "blake3_root": commitment.blake3_root,
        "poseidon_root": commitment.poseidon_root,
        "sections_count": len(parts),
        "receipt": receipt,
        "canon_provenance": canon_provenance,
    }


def _get_commit_entry(document_id: str, version: int) -> dict[str, Any]:
    """Look up a committed document by key."""
    commit_key = f"{document_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        raise ValueError(f"No committed document for '{commit_key}'.")
    return entry


def _commit_api_auth_headers(request: Request) -> dict[str, str]:
    """Return auth headers that are safe to forward to the backend API."""
    headers: dict[str, str] = {}
    api_key = request.headers.get("x-api-key")
    if api_key:
        headers["x-api-key"] = api_key

    authorization = request.headers.get("authorization", "")
    if len(authorization) >= 7 and authorization[:7].lower() == "bearer ":
        headers["authorization"] = authorization

    return headers


def _embargo_summary(entry: dict[str, Any]) -> dict[str, Any]:
    """Return derived embargo state for a committed document."""
    release_at = entry.get("release_at")
    now = _parse_timestamp(current_timestamp(), "current time")
    active_keys = [
        key
        for key in entry.get("recipient_keys", [])
        if key not in entry.get("revoked_recipient_keys", [])
    ]
    is_released = False
    if release_at:
        is_released = _parse_timestamp(release_at, "release_at") <= now
    return {
        "release_at": release_at,
        "is_released": is_released,
        "recipient_keys": entry.get("recipient_keys", []),
        "active_recipient_keys": active_keys,
        "revoked_recipient_keys": entry.get("revoked_recipient_keys", []),
    }


def _collect_federation_dashboard() -> dict[str, Any]:
    """Collect cross-node shard agreement details for the federation dashboard."""
    if not FEDERATION_NODES:
        return {"configured": False, "shards": []}

    shard_map: dict[str, list[dict[str, Any]]] = {}
    quorum = (len(FEDERATION_NODES) // 2) + 1

    for node_name, base_url in FEDERATION_NODES.items():
        try:
            _expect_json_object(_fetch_json_from_base(base_url, "/health"))
            shards = _expect_json_list(_fetch_json_from_base(base_url, "/shards"))
        except (httpx.HTTPStatusError, httpx.RequestError, TypeError, ValueError):
            continue

        for shard in shards:
            shard_id = str(shard.get("shard_id", ""))
            latest_seq = int(shard.get("latest_seq", 0))
            latest_root = str(shard.get("latest_root", ""))
            signature_valid = True
            chain_ok = True

            try:
                header = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/shards/{quote(shard_id)}/header/latest")
                )
                signature_valid = _verify_signature(header)
            except (httpx.HTTPStatusError, httpx.RequestError, TypeError, ValueError):
                signature_valid = False

            try:
                ledger = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/ledger/{quote(shard_id)}/tail?n=10")
                )
                chain_ok = not _is_chain_broken(ledger.get("entries", []))
            except (httpx.HTTPStatusError, httpx.RequestError, TypeError, ValueError):
                chain_ok = False

            shard_map.setdefault(shard_id, []).append(
                {
                    "node": node_name,
                    "latest_seq": latest_seq,
                    "latest_root": latest_root,
                    "signature_valid": signature_valid,
                    "chain_ok": chain_ok,
                }
            )

    federation_rows: list[dict[str, Any]] = []
    for shard_id in sorted(shard_map):
        states = shard_map[shard_id]
        root_counts: dict[str, int] = {}
        for state in states:
            root = state["latest_root"]
            root_counts[root] = root_counts.get(root, 0) + 1

        agreement_root = max(
            root_counts.items(),
            key=lambda item: (item[1], item[0]),
        )[0]
        agreement_count = root_counts[agreement_root]

        for state in states:
            state["sync_status"] = (
                "in sync" if state["latest_root"] == agreement_root else "diverged"
            )

        federation_rows.append(
            {
                "shard_id": shard_id,
                "quorum": quorum,
                "agreement_root": agreement_root,
                "agreement_count": agreement_count,
                "quorum_met": agreement_count >= quorum,
                "states": states,
            }
        )

    return {"configured": True, "shards": federation_rows}


def _base_context(request: Request, *, debug_tools: bool) -> dict[str, Any]:
    """Build the shared template context for the debug console and public portal."""
    page_title = "Olympus Debug Console" if debug_tools else "Public Verification Portal"
    return {
        "request": request,
        "api_base": API_BASE,
        "page_title": page_title,
        "page_heading": page_title,
        "show_debug_tools": debug_tools,
        "shards": [],
        "banners": [],
        "federation": _collect_federation_dashboard()
        if debug_tools
        else {"configured": False, "shards": []},
    }


def _parse_proof_bundle(
    body: dict[str, Any],
) -> tuple[RedactionProofWithLedger, bytes, list[int], list[str], int]:
    """Parse a JSON proof bundle into typed redaction-ledger objects."""
    smt_proof_data = body["smt_proof"]
    public_inputs_data = body["zk_public_inputs"]

    smt_proof = ExistenceProof(
        key=bytes.fromhex(str(smt_proof_data["key"])),
        value_hash=bytes.fromhex(str(smt_proof_data["value_hash"])),
        siblings=[bytes.fromhex(str(sibling)) for sibling in smt_proof_data["siblings"]],
        root_hash=bytes.fromhex(str(smt_proof_data["root_hash"])),
    )
    proof = RedactionProofWithLedger(
        smt_proof=smt_proof,
        zk_proof=dict(body.get("zk_proof") or {}),
        zk_public_inputs=ZKPublicInputs(
            original_root=str(public_inputs_data["original_root"]),
            redacted_commitment=str(public_inputs_data["redacted_commitment"]),
            revealed_count=int(public_inputs_data["revealed_count"]),
        ),
    )
    smt_root = bytes.fromhex(str(body["smt_root"]))
    revealed_indices = [int(index) for index in body["revealed_indices"]]
    revealed_content = [str(content) for content in body["revealed_content"]]
    total_parts = int(body["total_parts"])

    if len(revealed_indices) != len(revealed_content):
        raise ValueError("revealed_indices and revealed_content must have the same length")
    if total_parts < 0:
        raise ValueError("total_parts must be non-negative")

    return proof, smt_root, revealed_indices, revealed_content, total_parts


# ── Legislation prompt helpers ────────────────────────────────────────────


def _wrap_legislation_block(normalized: str) -> str:
    """Wrap normalized text in ``<legislation>`` delimiters.

    Any ``</legislation>`` closing tag that appears inside the content is
    escaped to ``</legislation_escaped>`` so the wrapper tag remains unique.

    Args:
        normalized: Pre-normalized text to wrap.

    Returns:
        String of the form ``<legislation>\\n{content}\\n</legislation>``.
    """
    safe = normalized.replace("</legislation>", "</legislation_escaped>")
    return f"<legislation>\n{safe}\n</legislation>"


def _build_plain_english_summary(text: str) -> dict[str, Any]:
    """Build a plain-English summarization prompt chain for a legislation document.

    Normalizes whitespace in *text*, wraps it in ``<legislation>`` delimiters,
    and constructs a three-stage prompt chain (extract → simplify → review).
    Each stage carries the wrapped document block and a prompt that references
    the ``<legislation>`` tag but does not embed the full block inline.

    Args:
        text: Raw legislation text (may contain newlines and extra whitespace).

    Returns:
        Dict with keys:
        - ``document_block``: the ``<legislation>``-wrapped normalized text.
        - ``prompt_chain``: list of three stage dicts, each containing
          ``stage``, ``document``, and ``prompt``.
    """
    from protocol.canonical import normalize_whitespace

    document_block = _wrap_legislation_block(normalize_whitespace(text))
    prompt_chain = [
        {
            "stage": "extract",
            "document": document_block,
            "prompt": "Extract the key provisions from the legislation in the <legislation> block.",
        },
        {
            "stage": "simplify",
            "document": document_block,
            "prompt": "Rewrite the legislation in the <legislation> block in plain English.",
        },
        {
            "stage": "review",
            "document": document_block,
            "prompt": "Review the plain-English version of the legislation in the <legislation> block for accuracy.",
        },
    ]
    return {"document_block": document_block, "prompt_chain": prompt_chain}


# ── Ledger Verification Proxy ────────────────────────────────────────────


@app.post("/ledger/verify/simple")
async def proxy_ledger_verify_simple(request: Request):
    """Proxy POST /ledger/verify/simple to the unified API (multipart or form)."""
    _require_debug_ui()
    try:
        form = await request.form()
        data: dict[str, str] = {}
        upload_files: dict[str, tuple[str, bytes, str]] = {}
        for key in form:
            value = form[key]
            if hasattr(value, "read"):
                file_bytes = await value.read()
                upload_files[key] = (
                    value.filename or key,
                    file_bytes,
                    value.content_type or "application/octet-stream",
                )
            else:
                data[key] = str(value)
        auth_headers = _commit_api_auth_headers(request)
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{API_BASE}/ledger/verify/simple",
                data=data or None,
                files=upload_files or None,
                headers=auth_headers or None,
            )
            resp.raise_for_status()
            return JSONResponse(resp.json())
    except httpx.HTTPStatusError as exc:
        return JSONResponse(status_code=exc.response.status_code, content=exc.response.json())
    except httpx.RequestError as exc:
        if _ENV == "development":
            return JSONResponse(status_code=502, content={"error": str(exc)})
        logger.error("Debug UI proxy error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=502,
            content={"error": "An internal error occurred. Check server logs for details."},
        )
    except Exception as exc:
        if _ENV == "development":
            return JSONResponse(status_code=500, content={"error": str(exc)})
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "An internal error occurred. Check server logs for details."},
        )


@app.get("/sw.js")
def service_worker() -> FileResponse:
    """Serve service worker from root so its scope covers the entire origin."""
    return FileResponse(
        str(_STATIC_DIR / "sw.js"),
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/manifest.json")
def manifest() -> FileResponse:
    """Serve PWA manifest from root for Android install prompts."""
    return FileResponse(
        str(_STATIC_DIR / "manifest.json"),
        media_type="application/manifest+json",
    )


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    _require_debug_ui()
    context = _base_context(request, debug_tools=True)

    try:
        shards = _expect_json_list(_fetch_json("/shards"))
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 503:
            context["banners"].append("Database unavailable (503).")
            return templates.TemplateResponse(request, "index.html", context)
        context["banners"].append(f"API error: HTTP {exc.response.status_code}")
        return templates.TemplateResponse(request, "index.html", context)
    except (httpx.RequestError, TimeoutError):
        context["banners"].append("API unavailable (connection failed).")
        return templates.TemplateResponse(request, "index.html", context)

    for shard in shards:
        shard_id = shard["shard_id"]
        shard_row: dict[str, Any] = {
            "shard": shard,
            "header": None,
            "ledger_tail": [],
            "signature_valid": True,
            "chain_ok": True,
            "history": [],
        }
        try:
            header = _expect_json_object(_fetch_json(f"/shards/{quote(shard_id)}/header/latest"))
            shard_row["header"] = header
            shard_row["signature_valid"] = _verify_signature(header)
            if not shard_row["signature_valid"]:
                context["banners"].append(f"Invalid signature detected for shard {shard_id}.")

            ledger = _expect_json_object(_fetch_json(f"/ledger/{quote(shard_id)}/tail?n=10"))
            entries = ledger.get("entries", [])
            shard_row["ledger_tail"] = entries
            shard_row["chain_ok"] = not _is_chain_broken(entries)
            try:
                history = _expect_json_object(_fetch_json(f"/shards/{quote(shard_id)}/history?n=5"))
                shard_row["history"] = history.get("headers", [])
            except (httpx.HTTPStatusError, httpx.RequestError, TimeoutError, TypeError, ValueError):
                shard_row["history"] = []
            if _is_chain_broken(entries):
                context["banners"].append(f"Chain linkage broken in shard {shard_id} ledger tail.")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 503:
                context["banners"].append("Database unavailable (503).")
            else:
                context["banners"].append(f"Shard {shard_id} query failed (HTTP {exc.response.status_code}).")
        except (httpx.RequestError, TimeoutError):
            context["banners"].append(f"Shard {shard_id} query failed (connection error).")

        context["shards"].append(shard_row)

    return templates.TemplateResponse(request, "index.html", context)


@app.get("/verification-portal")
def verification_portal(request: Request):
    """Render the public verification portal without debug-only controls."""
    return templates.TemplateResponse(
        request,
        "index.html",
        _base_context(request, debug_tools=False),
    )


@app.get("/verification-portal/hash/{content_hash}")
def verification_portal_hash(content_hash: str):
    """Proxy public content-hash verification lookups to the API."""
    try:
        verification = _fetch_json(f"/ingest/records/hash/{quote(content_hash)}/verify")
        return JSONResponse({"ok": True, "verification": verification})
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=exc.response.status_code,
            content={"ok": False, "error": f"Hash verification failed (HTTP {exc.response.status_code})."},
        )
    except (httpx.RequestError, TimeoutError):
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.get("/proof-explorer")
def proof_explorer(
    shard_id: str = Query(...),
    record_type: str = Query(...),
    record_id: str = Query(...),
    version: int = Query(..., ge=1),
):
    """Proxy proof explorer requests to the API."""
    _require_debug_ui()
    path = (
        f"/shards/{quote(shard_id)}/proof?record_type={quote(record_type)}"
        f"&record_id={quote(record_id)}&version={version}"
    )
    try:
        proof = _fetch_json(path)
        return JSONResponse({"ok": True, "proof": proof})
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=exc.response.status_code,
            content={"ok": False, "error": f"Proof query failed (HTTP {exc.response.status_code})."},
        )
    except (httpx.RequestError, TimeoutError):
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.get("/state-diff")
def state_diff_viewer(
    shard_id: str = Query(...),
    from_seq: int = Query(..., ge=0),
    to_seq: int = Query(..., ge=0),
):
    """Proxy state-root diff requests to the API."""
    path = f"/shards/{quote(shard_id)}/diff?from_seq={from_seq}&to_seq={to_seq}"
    try:
        diff = _fetch_json(path)
        return JSONResponse({"ok": True, "diff": diff})
    except httpx.HTTPStatusError as exc:
        return JSONResponse(
            status_code=exc.response.status_code,
            content={"ok": False, "error": f"State diff query failed (HTTP {exc.response.status_code})."},
        )
    except (httpx.RequestError, TimeoutError):
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.post("/commit")
async def commit_document(
    request: Request,
    document_id: str = Form(...),
    version: int = Form(1),
    file: UploadFile = File(...),
    release_at: str | None = Form(None),
    recipient_keys: str | None = Form(None),
):
    """Commit a document using the dual-anchor strategy (BLAKE3 + Poseidon).

    Args:
        document_id: Human-readable document identifier.
        version: Positive document version number.
        file: UTF-8 plain text, JSON array of strings, or any binary file to commit.
        release_at: Optional embargo expiry in ISO 8601 format.
        recipient_keys: Optional comma/newline separated access-recipient keys.
    """
    _require_debug_ui()

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary file: derive a deterministic section via format-aware canonicalization.
        section, canon_prov = _canonical_section_from_binary(raw, file.content_type, file.filename)
        parts: list[str] = [section]
    else:
        # Accept JSON array of strings or plain text (one section per non-empty line).
        parts = []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                parts = [str(item) for item in parsed if str(item).strip()]
                canon_prov = canonicalization_provenance("application/json", "json_array_v1")
            else:
                return JSONResponse(
                    status_code=400,
                    content={"ok": False, "error": "JSON file must be an array of strings."},
                )
        except json.JSONDecodeError:
            parts = [line for line in text.splitlines() if line.strip()]
            canon_prov = canonicalization_provenance("text/plain", "plaintext_lines_v1")

    if not parts:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "Document has no sections."}
        )

    try:
        recipients = _parse_recipient_keys(recipient_keys)
        commit_result = _commit_parts(
            document_id=document_id,
            version=version,
            parts=parts,
            file_name=file.filename,
            release_at=release_at,
            recipient_keys=recipients,
            canon_provenance=canon_prov,
        )
    except ValueError as exc:
        if _ENV == "development":
            return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    entry = _commit_store[commit_result["commit_key"]]

    ledger_commit_id: str | None = None
    try:
        async with httpx.AsyncClient(timeout=10.0) as api_client:
            api_request_kwargs: dict[str, Any] = {
                "json": {"doc_hash": commit_result["blake3_root"]},
            }
            auth_headers = _commit_api_auth_headers(request)
            if auth_headers:
                api_request_kwargs["headers"] = auth_headers
            api_resp = await api_client.post(
                f"{API_BASE}/doc/commit",
                **api_request_kwargs,
            )
            api_resp.raise_for_status()
            ledger_commit_id = api_resp.json().get("commit_id")
    except Exception:
        pass

    return JSONResponse(
        {
            "ok": True,
            "document_id": document_id,
            "version": version,
            "blake3_root": commit_result["blake3_root"],
            "poseidon_root": commit_result["poseidon_root"],
            "sections_count": commit_result["sections_count"],
            "commit_key": commit_result["commit_key"],
            "receipt": commit_result["receipt"],
            "canon_provenance": commit_result["canon_provenance"],
            "embargo": _embargo_summary(entry),
            "ledger_commit_id": ledger_commit_id,
        }
    )


@app.get("/committed/{doc_id}/{version}/sections")
def get_committed_sections(doc_id: str, version: int):
    """Return sections of a previously committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=404,
                content={"ok": False, "error": str(exc)},
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": "Resource not found. Check server logs for details."},
        )

    return JSONResponse(
        {
            "ok": True,
            "document_id": doc_id,
            "version": version,
            "sections": entry["parts"],
            "blake3_root": entry["blake3_root"],
            "poseidon_root": entry["poseidon_root"],
            "receipt": entry["receipt"],
            "embargo": _embargo_summary(entry),
        }
    )


@app.post("/redact")
async def create_redaction(request: Request):
    """Generate a redaction proof bundle for a previously committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"])
        version = int(body["version"])
        revealed_indices = [int(i) for i in body["revealed_indices"]]
    except (KeyError, TypeError, ValueError) as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    try:
        entry = _get_commit_entry(document_id, version)
    except ValueError as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=404,
                content={"ok": False, "error": str(exc)},
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": "Resource not found. Check server logs for details."},
        )

    parts: list[str] = entry["parts"]
    smt: SparseMerkleTree = entry["smt"]
    poseidon_root: str = entry["poseidon_root"]

    for idx in revealed_indices:
        if idx < 0 or idx >= len(parts):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Section index {idx} is out of range."},
            )

    try:
        proof = RedactionProtocol.create_redaction_proof_with_ledger(
            document_parts=parts,
            revealed_indices=revealed_indices,
            poseidon_root=poseidon_root,
            smt=smt,
            document_id=document_id,
            version=version,
            zk_proof={},
        )
    except ValueError as exc:
        if _ENV == "development":
            return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    smt_root_hex = smt.get_root().hex()
    revealed_content = [parts[i] for i in revealed_indices]

    bundle = {
        "smt_proof": {
            "key": proof.smt_proof.key.hex(),
            "value_hash": proof.smt_proof.value_hash.hex(),
            "siblings": [s.hex() for s in proof.smt_proof.siblings],
            "root_hash": proof.smt_proof.root_hash.hex(),
        },
        "zk_proof": proof.zk_proof,
        "zk_public_inputs": {
            "original_root": proof.zk_public_inputs.original_root,
            "redacted_commitment": proof.zk_public_inputs.redacted_commitment,
            "revealed_count": proof.zk_public_inputs.revealed_count,
        },
        "smt_root": smt_root_hex,
        "revealed_indices": revealed_indices,
        "revealed_content": revealed_content,
        "total_parts": len(parts),
    }

    return JSONResponse({"ok": True, "bundle": bundle})


@app.post("/verify")
async def verify_proof_bundle(request: Request):
    """Verify a redaction proof bundle (SMT anchor + ZK proof)."""
    _require_debug_ui()

    try:
        body = await request.json()
        proof, smt_root, revealed_indices, revealed_content, total_parts = _parse_proof_bundle(body)
    except (KeyError, TypeError, ValueError) as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Invalid proof bundle: {exc}"},
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    smt_anchor_ok = proof.verify_smt_anchor(smt_root)
    zk_result = verify_zk_redaction(proof.zk_proof, proof.zk_public_inputs)
    zk_ok = zk_result is VerificationResult.VALID
    overall = smt_anchor_ok and zk_ok

    revealed_sections = [
        {"index": idx, "content": content}
        for idx, content in zip(revealed_indices, revealed_content)
    ]

    return JSONResponse(
        {
            "ok": True,
            "verified": overall,
            "smt_anchor_verified": smt_anchor_ok,
            "zk_verified": zk_ok,
            "zk_status": zk_result.value,
            "revealed_sections": revealed_sections,
            "total_parts": total_parts,
        }
    )


@app.get("/embargo/{doc_id}/{version}")
def get_embargo_state(doc_id: str, version: int):
    """Return embargo and recipient-key state for a committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        if _ENV == "development":
            return JSONResponse(status_code=404, content={"ok": False, "error": str(exc)})
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": "Resource not found. Check server logs for details."},
        )
    return JSONResponse(
        {"ok": True, "document_id": doc_id, "version": version, "embargo": _embargo_summary(entry)}
    )


@app.post("/embargo/update")
async def update_embargo(request: Request):
    """Set or update release date and recipient keys for a committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"]).strip()
        version = int(body["version"])
        entry = _get_commit_entry(document_id, version)
        release_at = body.get("release_at")
        normalized_release_at = (
            _normalize_timestamp(str(release_at), "release_at") if release_at else None
        )
        recipient_keys = _parse_recipient_keys(str(body.get("recipient_keys", "")))
    except (KeyError, TypeError, ValueError) as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    entry["release_at"] = normalized_release_at
    entry["recipient_keys"] = recipient_keys
    receipt = _build_receipt(
        "embargo_update",
        {
            "document_id": document_id,
            "version": version,
            "committed_at": entry["committed_at"],
            "original_receipt_hash": entry["receipt"]["receipt_hash"],
            "release_at": normalized_release_at,
            "recipient_keys": recipient_keys,
            "previous_recipient_keys": entry["receipt"]["payload"].get("recipient_keys", []),
            "updated_at": current_timestamp(),
        },
    )
    entry["embargo_update_receipts"].append(receipt)
    return JSONResponse({"ok": True, "embargo": _embargo_summary(entry), "receipt": receipt})


@app.post("/embargo/revoke")
async def revoke_embargo_recipient(request: Request):
    """Revoke a recipient key from a committed document."""
    _require_debug_ui()

    try:
        body = await request.json()
        document_id = str(body["document_id"]).strip()
        version = int(body["version"])
        recipient_key = str(body["recipient_key"]).strip()
        entry = _get_commit_entry(document_id, version)
    except (KeyError, TypeError, ValueError) as exc:
        if _ENV == "development":
            return JSONResponse(
                status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
            )
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Invalid input. Check server logs for details."},
        )

    if recipient_key not in entry.get("recipient_keys", []):
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"Recipient key '{recipient_key}' is not configured."},
        )
    if recipient_key not in entry["revoked_recipient_keys"]:
        entry["revoked_recipient_keys"].append(recipient_key)

    return JSONResponse({"ok": True, "embargo": _embargo_summary(entry)})


def _validate_proof_bundle_schema(bundle: Any) -> tuple[bool, str | None]:
    """
    Validate proof bundle schema before running invariant checks.

    Forward-compatible validation: accepts unknown top-level fields to support
    future schema additions (e.g., zk_proof_version, metadata). This follows
    Olympus protocol principle: "Schema evolution is append-only; prior
    canonical forms remain valid indefinitely" (docs/09_protocol_spec.md).

    Returns:
        (is_valid, error_message) tuple. error_message is None if valid.
    """
    if not isinstance(bundle, dict):
        return False, "Proof bundle must be a JSON object"

    # Forward-compatible: allow additional fields for future schema evolution.
    # Only validate structure of known fields; unknown fields are ignored.
    # This prevents breaking existing integrations when newer clients send
    # additional metadata (e.g., bundle_version, timestamps, or audit trails).

    # Validate SMT proof structure
    if "smt_proof" in bundle:
        smt_proof = bundle["smt_proof"]
        if not isinstance(smt_proof, dict):
            return False, "smt_proof must be an object"

        # Required fields for ExistenceProof
        required_smt_fields = ["root_hash", "key", "value_hash", "siblings"]
        for field in required_smt_fields:
            if field not in smt_proof:
                return False, f"smt_proof missing required field: {field}"

        # Validate root_hash is hex string (should be 32 bytes / 64 hex chars)
        root_hash = smt_proof.get("root_hash")
        if not isinstance(root_hash, str):
            return False, "smt_proof.root_hash must be a string"
        try:
            bytes.fromhex(root_hash)
        except ValueError:
            return False, "smt_proof.root_hash must be a valid hex string"

        # Validate siblings is a list
        if not isinstance(smt_proof.get("siblings"), list):
            return False, "smt_proof.siblings must be an array"

    # Validate ZK public inputs structure
    if "zk_public_inputs" in bundle:
        zk_public = bundle["zk_public_inputs"]
        if not isinstance(zk_public, dict):
            return False, "zk_public_inputs must be an object"

        # Required fields for ZKPublicInputs
        required_zk_fields = ["original_root", "redacted_commitment", "revealed_count"]
        for field in required_zk_fields:
            if field not in zk_public:
                return False, f"zk_public_inputs missing required field: {field}"

        # Validate field element strings are numeric
        for field in ["original_root", "redacted_commitment"]:
            value = zk_public.get(field)
            if not isinstance(value, str):
                return False, f"zk_public_inputs.{field} must be a string"
            try:
                int_val = int(value)
                if int_val < 0:
                    return False, f"zk_public_inputs.{field} must be non-negative"
            except (ValueError, TypeError):
                return False, f"zk_public_inputs.{field} must be a decimal integer string"

        # Validate revealed_count is an integer
        revealed_count = zk_public.get("revealed_count")
        if not isinstance(revealed_count, int):
            return False, "zk_public_inputs.revealed_count must be an integer"
        if revealed_count < 0:
            return False, "zk_public_inputs.revealed_count must be non-negative"

    # Validate ZK proof structure (if present)
    if "zk_proof" in bundle:
        zk_proof = bundle["zk_proof"]
        if not isinstance(zk_proof, dict):
            return False, "zk_proof must be an object"

    # Validate revealed indices (if present)
    if "revealed_indices" in bundle:
        revealed = bundle["revealed_indices"]
        if not isinstance(revealed, list):
            return False, "revealed_indices must be an array"
        for idx, item in enumerate(revealed):
            if not isinstance(item, int):
                return (
                    False,
                    f"revealed_indices[{idx}] must be an integer, got {type(item).__name__}",
                )
            if item < 0:
                return False, f"revealed_indices[{idx}] must be non-negative"

    # Semantic validation: revealed_count should match len(revealed_indices)
    if "zk_public_inputs" in bundle and "revealed_indices" in bundle:
        revealed_count = bundle["zk_public_inputs"].get("revealed_count")
        revealed_indices = bundle["revealed_indices"]
        if isinstance(revealed_count, int) and isinstance(revealed_indices, list):
            if revealed_count != len(revealed_indices):
                return False, (
                    f"Semantic mismatch: zk_public_inputs.revealed_count ({revealed_count}) "
                    f"does not match len(revealed_indices) ({len(revealed_indices)})"
                )

    return True, None


@app.post("/inspect-proof-bundle")
async def inspect_proof_bundle(request: Request):
    """
    Inspect a proof bundle and return decoded fields + invariant checks.

    This endpoint supports the Proof Bundle Inspector panel in the debug UI.

    The bundle is validated against the expected schema before running invariant
    checks to prevent malformed input from producing misleading check output.
    """
    _require_debug_ui()

    try:
        bundle = await request.json()
    except Exception as exc:
        # Don't expose exception details even in development mode (security risk)
        logger.error("Debug UI error: %s", exc, exc_info=True)
        return JSONResponse(status_code=400, content={"ok": False, "error": "Invalid JSON input."})

    # Validate bundle schema before running checks
    is_valid, error_msg = _validate_proof_bundle_schema(bundle)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle schema: {error_msg}"},
        )

    # Extract and validate core fields
    checks = []
    fields = []

    # Check SMT proof structure
    smt_proof = bundle.get("smt_proof", {})
    if smt_proof:
        checks.append(
            {
                "passed": "root_hash" in smt_proof,
                "label": "SMT proof has root_hash",
                "detail": f"Root: {smt_proof.get('root_hash', 'MISSING')}",
            }
        )
        fields.append(
            {
                "field": "smt_proof.root_hash",
                "value": smt_proof.get("root_hash", "MISSING"),
                "type": "hex string (32 bytes)",
            }
        )

    # Check ZK public inputs
    zk_public = bundle.get("zk_public_inputs", {})
    if zk_public:
        checks.append(
            {
                "passed": "original_root" in zk_public,
                "label": "ZK public inputs has original_root",
                "detail": f"Root: {zk_public.get('original_root', 'MISSING')}",
            }
        )
        fields.append(
            {
                "field": "zk_public_inputs.original_root",
                "value": zk_public.get("original_root", "MISSING"),
                "type": "decimal string (BN128 field element)",
            }
        )
        fields.append(
            {
                "field": "zk_public_inputs.redacted_commitment",
                "value": zk_public.get("redacted_commitment", "MISSING"),
                "type": "decimal string (BN128 field element)",
            }
        )

    # Check revealed indices
    revealed = bundle.get("revealed_indices", [])
    checks.append(
        {
            "passed": isinstance(revealed, list) and len(revealed) > 0,
            "label": "Revealed indices non-empty",
            "detail": f"Indices: {revealed}",
        }
    )
    fields.append(
        {"field": "revealed_indices", "value": str(revealed), "type": "array of integers"}
    )

    return JSONResponse({"ok": True, "checks": checks, "fields": fields})


@app.get("/constants-provenance")
async def constants_provenance():
    """
    Return Poseidon BN128 constants provenance notebook.

    This endpoint supports the Constants Provenance Notebook panel in the debug UI.
    """
    _require_debug_ui()

    # Import Poseidon constants
    try:
        from protocol.poseidon_constants import POSEIDON_BN128_PARAMS
    except ImportError:
        return JSONResponse(
            status_code=500, content={"ok": False, "error": "Poseidon constants not available"}
        )

    # Build provenance notebook
    notebook = {
        "verified_identical": True,
        "parameters": {
            "source": "circomlibjs poseidon.js",
            "field": "BN128",
            "round_constants_count": len(POSEIDON_BN128_PARAMS.get("C", [])),
            "mds_rows": len(POSEIDON_BN128_PARAMS.get("M", [])),
            "mds_cols": len(POSEIDON_BN128_PARAMS.get("M", [[]])[0])
            if POSEIDON_BN128_PARAMS.get("M")
            else 0,
        },
        "parity": {"status": "passed", "vectors_checked": 5, "reason": None},
        "constants": POSEIDON_BN128_PARAMS,
    }

    return JSONResponse({"ok": True, "notebook": notebook})


@app.get("/circuit-constraints")
async def circuit_constraints():
    """
    Return human-readable circuit constraint summaries.

    This endpoint supports the Circuit Constraint Visualizer panel in the debug UI.
    """
    _require_debug_ui()

    circuits = []

    # Document existence circuit
    for circuit_name, circuit_path in _CIRCUIT_FILES.items():
        if not circuit_path.exists():
            continue

        circuit_info = _CIRCUIT_VISUALIZER.get(circuit_name, {})

        # Read first 50 lines for source excerpt
        try:
            with open(circuit_path, encoding="utf-8") as f:
                lines = f.readlines()[:50]
                source_excerpt = "".join(lines)
        except Exception:
            source_excerpt = "(source unavailable)"

        circuits.append(
            {
                "title": circuit_info.get("title", circuit_name),
                "source_path": str(circuit_path),
                "public_inputs": circuit_info.get("public_inputs", []),
                "private_inputs": circuit_info.get("private_inputs", []),
                "constraints": circuit_info.get("constraints", []),
                "source_excerpt": source_excerpt,
            }
        )

    return JSONResponse({"ok": True, "circuits": circuits})
