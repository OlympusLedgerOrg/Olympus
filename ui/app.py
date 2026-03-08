"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import HASH_SEPARATOR, blake3_to_field_element, hash_bytes
from protocol.poseidon_tree import PoseidonMerkleTree
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    ZKPublicInputs,
    poseidon_root_to_bytes,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree
from protocol.timestamps import current_timestamp


API_BASE = os.environ.get("UI_API_BASE", "http://127.0.0.1:8000")
_parsed_api_base = urlparse(API_BASE)
if _parsed_api_base.scheme not in {"http", "https"} or not _parsed_api_base.netloc:
    raise ValueError("UI_API_BASE must be an absolute http(s) URL")

# Debug UI is disabled by default; set OLYMPUS_DEBUG_UI=true to enable.
DEBUG_UI_ENABLED = os.environ.get("OLYMPUS_DEBUG_UI", "false").lower() == "true"


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
        parsed_base = urlparse(str(base_url))
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise ValueError(f"Federation node '{name}' must use an absolute http(s) URL")
        nodes[str(name)] = str(base_url)
    return nodes


FEDERATION_NODES = _load_federation_nodes()

app = FastAPI(title="Olympus Debug Console", version="0.1.0")
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
_foia_store: dict[str, dict[str, Any]] = {}


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    return _fetch_json_from_base(API_BASE, path)


def _fetch_json_from_base(base_url: str, path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from a specific Olympus API base URL."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")
    with urlopen(f"{base_url}{path}", timeout=5) as response:  # noqa: S310
        payload = json.loads(response.read().decode("utf-8"))
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
    """Raise 404 when the debug console is disabled."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")


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


def _commit_parts(
    document_id: str,
    version: int,
    parts: list[str],
    *,
    file_name: str | None = None,
    release_at: str | None = None,
    recipient_keys: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
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

    leaf_fields = [blake3_to_field_element(part.encode("utf-8")) for part in parts]
    poseidon_tree = PoseidonMerkleTree(leaf_fields)
    poseidon_root = poseidon_tree.get_root()

    smt = SparseMerkleTree()
    tree, blake3_root = RedactionProtocol.commit_document_dual(
        document_parts=parts,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=document_id,
        version=version,
    )

    commit_key = f"{document_id}:{version}"
    entry_metadata = dict(metadata or {})
    entry_metadata["committed_at"] = committed_at
    receipt_payload = {
        "document_id": document_id,
        "version": version,
        "file_name": file_name,
        "sections_count": len(parts),
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
        "committed_at": committed_at,
        "release_at": normalized_release_at,
        "recipient_keys": recipients,
        "metadata": entry_metadata,
    }
    receipt = _build_receipt("document_commitment", receipt_payload)

    _commit_store[commit_key] = {
        "parts": parts,
        "leaf_fields": leaf_fields,
        "tree": tree,
        "smt": smt,
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
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
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
        "sections_count": len(parts),
        "receipt": receipt,
    }


def _get_commit_entry(document_id: str, version: int) -> dict[str, Any]:
    """Look up a committed document by key."""
    commit_key = f"{document_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        raise ValueError(f"No committed document for '{commit_key}'.")
    return entry


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


def _foia_delay_proof(record: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic delay proof from FOIA request/response timestamps."""
    submitted_at = _parse_timestamp(record["submitted_at"], "submitted_at")
    response_at_value = record.get("response_received_at")
    reference_timestamp = response_at_value or current_timestamp()
    reference_at = _parse_timestamp(reference_timestamp, "reference_timestamp")
    elapsed_seconds = int((reference_at - submitted_at).total_seconds())

    due_at_value = record.get("response_due_at")
    delayed = False
    delay_seconds = 0
    if due_at_value:
        due_at = _parse_timestamp(due_at_value, "response_due_at")
        delayed = reference_at > due_at
        delay_seconds = max(0, int((reference_at - due_at).total_seconds()))

    response_receipt = record.get("response_receipt") or {}
    pending = response_at_value is None
    payload = {
        "request_id": record["request_id"],
        "request_receipt_hash": record["request_receipt"]["receipt_hash"],
        "response_receipt_hash": response_receipt.get("receipt_hash"),
        "submitted_at": record["submitted_at"],
        "response_received_at": response_at_value,
        "response_due_at": due_at_value,
        "proof_generated_at": current_timestamp(),
        "reference_timestamp": reference_timestamp,
        "proof_mode": "snapshot" if pending else "response-anchored",
        "pending": pending,
        "elapsed_seconds": elapsed_seconds,
        "delayed": delayed,
        "delay_seconds": delay_seconds,
    }
    receipt_type = "foia_delay_snapshot" if pending else "foia_delay_proof"
    return _build_receipt(receipt_type, payload)


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    _require_debug_ui()
    context: dict[str, Any] = {
        "request": request,
        "api_base": API_BASE,
        "shards": [],
        "banners": [],
        "federation": _collect_federation_dashboard(),
    }

    try:
        shards = _expect_json_list(_fetch_json("/shards"))
    except HTTPError as exc:
        if exc.code == 503:
            context["banners"].append("Database unavailable (503).")
            return templates.TemplateResponse(request, "index.html", context)
        context["banners"].append(f"API error: HTTP {exc.code}")
        return templates.TemplateResponse(request, "index.html", context)
    except URLError:
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
            except (HTTPError, URLError, TypeError, ValueError):
                shard_row["history"] = []
            if _is_chain_broken(entries):
                context["banners"].append(f"Chain linkage broken in shard {shard_id} ledger tail.")
        except HTTPError as exc:
            if exc.code == 503:
                context["banners"].append("Database unavailable (503).")
            else:
                context["banners"].append(f"Shard {shard_id} query failed (HTTP {exc.code}).")
        except URLError:
            context["banners"].append(f"Shard {shard_id} query failed (connection error).")

        context["shards"].append(shard_row)

    return templates.TemplateResponse(request, "index.html", context)


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
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"Proof query failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.get("/state-diff")
def state_diff_viewer(
    shard_id: str = Query(...),
    from_seq: int = Query(..., ge=0),
    to_seq: int = Query(..., ge=0),
):
    """Proxy state-root diff requests to the API."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    path = f"/shards/{quote(shard_id)}/diff?from_seq={from_seq}&to_seq={to_seq}"
    try:
        diff = _fetch_json(path)
        return JSONResponse({"ok": True, "diff": diff})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"State diff query failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.post("/commit")
async def commit_document(
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
        file: UTF-8 plain text or JSON array of strings to commit.
        release_at: Optional embargo expiry in ISO 8601 format.
        recipient_keys: Optional comma/newline separated access-recipient keys.
    """
    _require_debug_ui()

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "File must be valid UTF-8."}
        )

    # Accept JSON array of strings or plain text (one section per non-empty line).
    parts: list[str] = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            parts = [str(item) for item in parsed if str(item).strip()]
        else:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "JSON file must be an array of strings."},
            )
    except json.JSONDecodeError:
        parts = [line for line in text.splitlines() if line.strip()]

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
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    entry = _commit_store[commit_result["commit_key"]]

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
            "embargo": _embargo_summary(entry),
        }
    )


@app.get("/committed/{doc_id}/{version}/sections")
def get_committed_sections(doc_id: str, version: int):
    """Return sections of a previously committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": str(exc)},
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
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    try:
        entry = _get_commit_entry(document_id, version)
    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": str(exc)},
        )

    parts: list[str] = entry["parts"]
    leaf_fields: list[str] = entry["leaf_fields"]
    tree = entry["tree"]
    smt: SparseMerkleTree = entry["smt"]
    poseidon_root: str = entry["poseidon_root"]

    for idx in revealed_indices:
        if idx < 0 or idx >= len(parts):
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": f"Section index {idx} is out of range."},
            )

    # Compute the redacted commitment: Poseidon root over the nullified leaf vector
    # (revealed leaves kept, redacted leaves replaced with field element 0).
    revealed_set = set(revealed_indices)
    nullified = [leaf_fields[i] if i in revealed_set else "0" for i in range(len(parts))]
    redacted_tree = PoseidonMerkleTree(nullified)
    redacted_commitment = redacted_tree.get_root()
    revealed_count = len(revealed_indices)

    proof = RedactionProtocol.create_redaction_proof_with_ledger(
        tree=tree,
        revealed_indices=revealed_indices,
        poseidon_root=poseidon_root,
        smt=smt,
        document_id=document_id,
        version=version,
        zk_proof={},
        redacted_commitment=redacted_commitment,
        revealed_count=revealed_count,
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
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle: {exc}"},
        )

    smt_anchor_ok = proof.verify_smt_anchor(smt_root)
    zk_ok = verify_zk_redaction(proof.zk_proof, proof.zk_public_inputs)
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
            "revealed_sections": revealed_sections,
            "total_parts": total_parts,
        }
    )


@app.post("/foia/request")
async def commit_foia_request(request: Request):
    """Commit a FOIA request submission and return a downloadable receipt."""
    _require_debug_ui()

    try:
        body = await request.json()
        request_id = str(body["request_id"]).strip()
        agency = str(body["agency"]).strip()
        requester = str(body["requester"]).strip()
        description = str(body["description"]).strip()
        submitted_at = _normalize_timestamp(str(body["submitted_at"]), "submitted_at")
        response_due_at = body.get("response_due_at")
        normalized_due_at = (
            _normalize_timestamp(str(response_due_at), "response_due_at")
            if response_due_at
            else None
        )
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    if not all([request_id, agency, requester, description]):
        return JSONResponse(
            status_code=400, content={"ok": False, "error": "All fields are required."}
        )

    metadata = {
        "workflow": "foia_request",
        "request_id": request_id,
        "agency": agency,
        "requester": requester,
        "description": description,
        "submitted_at": submitted_at,
        "response_due_at": normalized_due_at,
    }
    parts = [
        HASH_SEPARATOR.join(["request_id", request_id]),
        HASH_SEPARATOR.join(["agency", agency]),
        HASH_SEPARATOR.join(["requester", requester]),
        HASH_SEPARATOR.join(["submitted_at", submitted_at]),
        HASH_SEPARATOR.join(["response_due_at", normalized_due_at or ""]),
        HASH_SEPARATOR.join(["description", description]),
    ]
    try:
        commit_result = _commit_parts(
            document_id=f"foia-request:{request_id}",
            version=1,
            parts=parts,
            file_name=None,
            metadata=metadata,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    request_receipt = _build_receipt(
        "foia_request_submission",
        {
            "request_id": request_id,
            "agency": agency,
            "requester": requester,
            "description": description,
            "submitted_at": submitted_at,
            "response_due_at": normalized_due_at,
            "request_commit_receipt_hash": commit_result["receipt"]["receipt_hash"],
            "committed_at": _commit_store[commit_result["commit_key"]]["committed_at"],
        },
    )
    _foia_store[request_id] = {
        "request_id": request_id,
        "agency": agency,
        "requester": requester,
        "description": description,
        "submitted_at": submitted_at,
        "response_due_at": normalized_due_at,
        "request_commit_key": commit_result["commit_key"],
        "request_receipt": request_receipt,
        "response_received_at": None,
        "response_summary": None,
        "response_receipt": None,
    }

    return JSONResponse(
        {
            "ok": True,
            "request": _foia_store[request_id],
            "delay_proof": _foia_delay_proof(_foia_store[request_id]),
        }
    )


@app.post("/foia/response")
async def log_foia_response(request: Request):
    """Record a FOIA response timestamp and return an updated delay proof."""
    _require_debug_ui()

    try:
        body = await request.json()
        request_id = str(body["request_id"]).strip()
        response_received_at = _normalize_timestamp(
            str(body["response_received_at"]), "response_received_at"
        )
        response_summary = str(body.get("response_summary", "")).strip()
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )

    metadata = {
        "workflow": "foia_response",
        "request_id": request_id,
        "response_received_at": response_received_at,
        "response_summary": response_summary,
    }
    try:
        commit_result = _commit_parts(
            document_id=f"foia-response:{request_id}",
            version=1,
            parts=[
                HASH_SEPARATOR.join(["request_id", request_id]),
                HASH_SEPARATOR.join(["response_received_at", response_received_at]),
                HASH_SEPARATOR.join(["response_summary", response_summary]),
            ],
            metadata=metadata,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    record["response_received_at"] = response_received_at
    record["response_summary"] = response_summary
    record["response_receipt"] = _build_receipt(
        "foia_response_log",
        {
            "request_id": request_id,
            "response_received_at": response_received_at,
            "response_summary": response_summary,
            "response_commit_receipt_hash": commit_result["receipt"]["receipt_hash"],
            "timestamp": response_received_at,
        },
    )

    return JSONResponse({"ok": True, "request": record, "delay_proof": _foia_delay_proof(record)})


@app.get("/foia/{request_id}")
def get_foia_request(request_id: str):
    """Return the tracked FOIA request state."""
    _require_debug_ui()

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )
    return JSONResponse({"ok": True, "request": record})


@app.get("/foia/{request_id}/delay-proof")
def get_foia_delay_proof(request_id: str):
    """Return the derived FOIA delay proof for a tracked request."""
    _require_debug_ui()

    record = _foia_store.get(request_id)
    if record is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No FOIA request tracked for '{request_id}'."},
        )
    return JSONResponse({"ok": True, "delay_proof": _foia_delay_proof(record), "request": record})


@app.get("/embargo/{doc_id}/{version}")
def get_embargo_state(doc_id: str, version: int):
    """Return embargo and recipient-key state for a committed document."""
    _require_debug_ui()

    try:
        entry = _get_commit_entry(doc_id, version)
    except ValueError as exc:
        return JSONResponse(status_code=404, content={"ok": False, "error": str(exc)})
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
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
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
        return JSONResponse(
            status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"}
        )

    if recipient_key not in entry.get("recipient_keys", []):
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"Recipient key '{recipient_key}' is not configured."},
        )
    if recipient_key not in entry["revoked_recipient_keys"]:
        entry["revoked_recipient_keys"].append(recipient_key)

    return JSONResponse({"ok": True, "embargo": _embargo_summary(entry)})
