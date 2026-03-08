"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.hashes import blake3_to_field_element
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

# In-memory store for committed documents.
# Key: "{document_id}:{version}"
# Not persisted across restarts; for debug/demo use only.
_commit_store: dict[str, dict[str, Any]] = {}


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


def _sync_status(latest_seq: int, max_seq: int) -> str:
    """Summarize whether a node is caught up with the highest observed sequence."""
    lag = max_seq - latest_seq
    if lag <= 0:
        return "in sync"
    if lag == 1:
        return "lagging by 1 header"
    return f"lagging by {lag} headers"


def _collect_federation_dashboard() -> dict[str, Any]:
    """Fetch multi-node shard health, agreement, and historical snapshots."""
    if not FEDERATION_NODES:
        return {"configured": False, "nodes": [], "shards": []}

    node_snapshots: list[dict[str, Any]] = []
    for node_name, base_url in FEDERATION_NODES.items():
        snapshot: dict[str, Any] = {
            "name": node_name,
            "base_url": base_url,
            "health": None,
            "shards": [],
            "error": None,
        }
        try:
            snapshot["health"] = _expect_json_object(_fetch_json_from_base(base_url, "/health"))
            shards = _expect_json_list(_fetch_json_from_base(base_url, "/shards"))
            for shard in shards:
                shard_id = shard["shard_id"]
                header = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/shards/{quote(shard_id)}/header/latest")
                )
                ledger = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/ledger/{quote(shard_id)}/tail?n=10")
                )
                history = _expect_json_object(
                    _fetch_json_from_base(base_url, f"/shards/{quote(shard_id)}/history?n=5")
                )
                entries = ledger.get("entries", [])
                snapshot["shards"].append(
                    {
                        "shard_id": shard_id,
                        "latest_seq": shard["latest_seq"],
                        "latest_root": shard["latest_root"],
                        "header": header,
                        "history": history.get("headers", []),
                        "chain_ok": not _is_chain_broken(entries),
                        "signature_valid": _verify_signature(header),
                    }
                )
        except (HTTPError, URLError, KeyError, TypeError, ValueError) as exc:
            snapshot["error"] = str(exc)
        node_snapshots.append(snapshot)

    shard_rows: list[dict[str, Any]] = []
    shard_ids = sorted(
        {
            shard["shard_id"]
            for snapshot in node_snapshots
            for shard in snapshot.get("shards", [])
        }
    )
    quorum = (len(node_snapshots) // 2) + 1
    for shard_id in shard_ids:
        states = []
        for snapshot in node_snapshots:
            shard_state = next(
                (candidate for candidate in snapshot.get("shards", []) if candidate["shard_id"] == shard_id),
                None,
            )
            if shard_state is not None:
                states.append({"node": snapshot["name"], **shard_state})

        max_seq = max((state["latest_seq"] for state in states), default=0)
        root_groups: dict[str, list[str]] = {}
        for state in states:
            root_groups.setdefault(state["latest_root"], []).append(state["node"])
        agreement_root = ""
        agreement_nodes: list[str] = []
        if root_groups:
            agreement_root, agreement_nodes = max(
                root_groups.items(), key=lambda item: (len(item[1]), item[0])
            )

        for state in states:
            state["sync_status"] = _sync_status(state["latest_seq"], max_seq)

        shard_rows.append(
            {
                "shard_id": shard_id,
                "quorum": quorum,
                "agreement_root": agreement_root,
                "agreement_nodes": agreement_nodes,
                "agreement_count": len(agreement_nodes),
                "quorum_met": len(agreement_nodes) >= quorum,
                "states": states,
            }
        )

    return {"configured": True, "nodes": node_snapshots, "shards": shard_rows}


@app.get("/")
def debug_console(request: Request):
    """Render the debug console view."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
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
            except (HTTPError, URLError, TypeError, ValueError, AssertionError):
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
