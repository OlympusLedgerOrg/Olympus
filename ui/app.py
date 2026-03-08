"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.hashes import blake3_to_field_element, hash_bytes
from protocol.poseidon_tree import PoseidonMerkleTree
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    ZKPublicInputs,
    verify_zk_redaction,
)
from protocol.ssmf import ExistenceProof, SparseMerkleTree


API_BASE = os.environ.get("UI_API_BASE", "http://127.0.0.1:8000")
_parsed_api_base = urlparse(API_BASE)
if _parsed_api_base.scheme not in {"http", "https"} or not _parsed_api_base.netloc:
    raise ValueError("UI_API_BASE must be an absolute http(s) URL")

# Debug UI is disabled by default; set OLYMPUS_DEBUG_UI=true to enable.
DEBUG_UI_ENABLED = os.environ.get("OLYMPUS_DEBUG_UI", "false").lower() == "true"

app = FastAPI(title="Olympus Debug Console", version="0.1.0")
templates = Jinja2Templates(directory="ui/templates")

# In-memory store for committed documents.
# Key: "{document_id}:{version}"
# Not persisted across restarts; for debug/demo use only.
_commit_store: dict[str, dict[str, Any]] = {}

_JURY_DEMO_MODELS: list[dict[str, Any]] = [
    {
        "model": "ollama/llama3.1:70b",
        "weight": 0.5,
        "verdict": "release",
        "confidence": 0.92,
        "reason": "Most passages are factual and already public.",
    },
    {
        "model": "openai/gpt-4.1",
        "weight": 0.3,
        "verdict": "release",
        "confidence": 0.81,
        "reason": "No personal identifiers detected in the cited sections.",
    },
    {
        "model": "anthropic/claude-sonnet-4",
        "weight": 0.2,
        "verdict": "escalate",
        "confidence": 0.63,
        "reason": "One paragraph may still require human redaction review.",
    },
]


def _fetch_json(path: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Fetch JSON from the Olympus API."""
    if not path.startswith("/") or "://" in path:
        raise ValueError("API path must be a relative path")
    with urlopen(f"{API_BASE}{path}", timeout=5) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


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


def _build_jury_demo() -> dict[str, Any]:
    """Build a deterministic demo aggregation for the AI jury dashboard."""
    total_weight = sum(model["weight"] for model in _JURY_DEMO_MODELS)
    weighted_totals: dict[str, float] = {}
    normalized_models: list[dict[str, Any]] = []

    for model in _JURY_DEMO_MODELS:
        normalized_weight = round(model["weight"] / total_weight, 4)
        weighted_support = round(normalized_weight * model["confidence"], 4)
        weighted_totals[model["verdict"]] = round(
            weighted_totals.get(model["verdict"], 0.0) + weighted_support,
            4,
        )
        normalized_models.append({
            **model,
            "normalized_weight": normalized_weight,
            "weighted_support": weighted_support,
        })

    combined_verdict = max(weighted_totals.items(), key=lambda item: (item[1], item[0]))[0]
    commitment_payload = {
        "record_type": "jury_verdict",
        "record_id": "foia-appeal-demo-2026-001",
        "version": 1,
        "aggregation_method": "weighted_confidence_sum",
        "models": [
            {
                "model": item["model"],
                "verdict": item["verdict"],
                "confidence": item["confidence"],
                "normalized_weight": item["normalized_weight"],
                "weighted_support": item["weighted_support"],
            }
            for item in normalized_models
        ],
        "weighted_totals": weighted_totals,
        "combined_verdict": combined_verdict,
    }
    commitment_hash = hash_bytes(
        document_to_bytes(canonicalize_document(commitment_payload))
    ).hex()
    return {
        "case_id": "foia-appeal-demo-2026-001",
        "combined_verdict": combined_verdict,
        "weighted_totals": weighted_totals,
        "models": normalized_models,
        "commitment_payload": commitment_payload,
        "commitment_hash": commitment_hash,
    }


def _base_context(request: Request, *, debug_tools: bool) -> dict[str, Any]:
    """Return common Jinja context for debug and public portal views."""
    title = "Olympus Developer Debug Console" if debug_tools else "Olympus Public Verification Portal"
    return {
        "request": request,
        "api_base": API_BASE,
        "shards": [],
        "banners": [],
        "page_title": title,
        "page_heading": title,
        "show_debug_tools": debug_tools,
        "show_public_verifier": True,
        "show_jury_dashboard": True,
        "jury_demo": _build_jury_demo(),
    }


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    context = _base_context(request, debug_tools=True)

    try:
        shards = _fetch_json("/shards")
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
        shard_row = {"shard": shard, "header": None, "ledger_tail": [], "signature_valid": True}
        try:
            header = _fetch_json(f"/shards/{quote(shard_id)}/header/latest")
            shard_row["header"] = header
            shard_row["signature_valid"] = _verify_signature(header)
            if not shard_row["signature_valid"]:
                context["banners"].append(f"Invalid signature detected for shard {shard_id}.")

            ledger = _fetch_json(f"/ledger/{quote(shard_id)}/tail?n=10")
            entries = ledger.get("entries", [])
            shard_row["ledger_tail"] = entries
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


@app.get("/verification-portal")
def verification_portal(request: Request):
    """Render the public verification portal without debug-only controls."""
    return templates.TemplateResponse(
        request,
        "index.html",
        _base_context(request, debug_tools=False),
    )


@app.get("/proof-explorer")
def proof_explorer(
    shard_id: str = Query(...),
    record_type: str = Query(...),
    record_id: str = Query(...),
    version: int = Query(..., ge=1),
):
    """Proxy proof explorer requests to the API."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
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


@app.get("/verification-portal/hash/{content_hash}")
def verify_committed_hash(content_hash: str):
    """Resolve and verify a committed document hash through the public API."""
    path = f"/ingest/records/hash/{quote(content_hash)}/verify"
    try:
        verification = _fetch_json(path)
        return JSONResponse({"ok": True, "verification": verification})
    except HTTPError as exc:
        return JSONResponse(
            status_code=exc.code,
            content={"ok": False, "error": f"Hash verification failed (HTTP {exc.code})."},
        )
    except URLError:
        return JSONResponse(status_code=503, content={"ok": False, "error": "API unavailable."})


@app.post("/commit")
async def commit_document(
    document_id: str = Form(...),
    version: int = Form(1),
    file: UploadFile = File(...),
):
    """Commit a document using the dual-anchor strategy (BLAKE3 + Poseidon)."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "File must be valid UTF-8."})

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
        return JSONResponse(status_code=400, content={"ok": False, "error": "Document has no sections."})

    # Build Poseidon Merkle tree over field-element leaves derived from each section.
    leaf_fields = [blake3_to_field_element(part.encode("utf-8")) for part in parts]
    poseidon_tree = PoseidonMerkleTree(leaf_fields)
    poseidon_root = poseidon_tree.get_root()

    smt = SparseMerkleTree()
    try:
        tree, blake3_root = RedactionProtocol.commit_document_dual(
            document_parts=parts,
            poseidon_root=poseidon_root,
            smt=smt,
            document_id=document_id,
            version=version,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})

    commit_key = f"{document_id}:{version}"
    _commit_store[commit_key] = {
        "parts": parts,
        "leaf_fields": leaf_fields,
        "tree": tree,
        "smt": smt,
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
        "document_id": document_id,
        "version": version,
    }

    return JSONResponse({
        "ok": True,
        "document_id": document_id,
        "version": version,
        "blake3_root": blake3_root,
        "poseidon_root": poseidon_root,
        "sections_count": len(parts),
        "commit_key": commit_key,
    })


@app.get("/committed/{doc_id}/{version}/sections")
def get_committed_sections(doc_id: str, version: int):
    """Return sections of a previously committed document."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    commit_key = f"{doc_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No committed document for '{commit_key}'."},
        )

    return JSONResponse({
        "ok": True,
        "document_id": doc_id,
        "version": version,
        "sections": entry["parts"],
        "blake3_root": entry["blake3_root"],
        "poseidon_root": entry["poseidon_root"],
    })


@app.post("/redact")
async def create_redaction(request: Request):
    """Generate a redaction proof bundle for a previously committed document."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    try:
        body = await request.json()
        document_id = str(body["document_id"])
        version = int(body["version"])
        revealed_indices = [int(i) for i in body["revealed_indices"]]
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": f"Invalid request: {exc}"})

    commit_key = f"{document_id}:{version}"
    entry = _commit_store.get(commit_key)
    if entry is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"No committed document for '{commit_key}'."},
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
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    try:
        body = await request.json()
        smt_proof_data = body["smt_proof"]
        smt_proof = ExistenceProof(
            key=bytes.fromhex(smt_proof_data["key"]),
            value_hash=bytes.fromhex(smt_proof_data["value_hash"]),
            siblings=[bytes.fromhex(s) for s in smt_proof_data["siblings"]],
            root_hash=bytes.fromhex(smt_proof_data["root_hash"]),
        )
        zk_pi = body["zk_public_inputs"]
        public_inputs = ZKPublicInputs(
            original_root=str(zk_pi["original_root"]),
            redacted_commitment=str(zk_pi["redacted_commitment"]),
            revealed_count=int(zk_pi["revealed_count"]),
        )
        proof = RedactionProofWithLedger(
            smt_proof=smt_proof,
            zk_proof=body["zk_proof"],
            zk_public_inputs=public_inputs,
        )
        smt_root = bytes.fromhex(body["smt_root"])
        revealed_indices: list[int] = body.get("revealed_indices", [])
        revealed_content: list[str] = body.get("revealed_content", [])
        total_parts: int = int(body.get("total_parts", 0))
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

    return JSONResponse({
        "ok": True,
        "verified": overall,
        "smt_anchor_verified": smt_anchor_ok,
        "zk_verified": zk_ok,
        "revealed_sections": revealed_sections,
        "total_parts": total_parts,
    })
