"""FastAPI + Jinja2 developer debug console for Olympus."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import nacl.exceptions
import nacl.signing
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element
from protocol.poseidon_bn128 import poseidon_hash_bn128, poseidon_parameter_summary
from protocol.poseidon_tree import PoseidonMerkleTree
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import (
    RedactionProofWithLedger,
    ZKPublicInputs,
    poseidon_root_to_bytes,
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


def _poseidon_vector_parity_report() -> dict[str, Any]:
    """Check Python Poseidon outputs against the circomlibjs reference vectors."""
    if shutil.which("node") is None:
        return {
            "status": "unavailable",
            "verified": False,
            "reason": "node is not available on PATH",
            "vectors_checked": 0,
            "mismatches": [],
        }
    if not _POSEIDON_NODE_MODULES.is_dir():
        return {
            "status": "unavailable",
            "verified": False,
            "reason": "proofs/node_modules is not installed",
            "vectors_checked": 0,
            "mismatches": [],
        }

    try:
        result = subprocess.run(
            ["node", str(_POSEIDON_VECTORS_SCRIPT)],
            capture_output=True,
            text=True,
            check=True,
            cwd=str(_POSEIDON_VECTORS_SCRIPT.parent),
            timeout=10,
        )
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return {
            "status": "failed",
            "verified": False,
            "reason": f"circomlibjs parity replay failed ({exc.__class__.__name__}: {detail})",
            "vectors_checked": 0,
            "mismatches": [],
        }
    mismatches: list[dict[str, str]] = []
    for vector in payload["vectors"]:
        actual = str(poseidon_hash_bn128(int(vector["a"]), int(vector["b"])))
        if actual != vector["out"]:
            mismatches.append({
                "a": vector["a"],
                "b": vector["b"],
                "expected": vector["out"],
                "actual": actual,
            })

    return {
        "status": "passed" if not mismatches else "failed",
        "verified": not mismatches,
        "reason": "",
        "vectors_checked": len(payload["vectors"]),
        "mismatches": mismatches,
    }


def _poseidon_constants_notebook() -> dict[str, Any]:
    """
    Build the rendered/exportable Poseidon constants provenance notebook payload.

    Returns:
        Dictionary containing source-chain notes, exported parameter tables,
        structural validation checks, the circomlibjs parity replay result, and
        an overall ``verified_identical`` status used by the debug UI.
    """
    parameters = poseidon_parameter_summary()
    structural_checks = [
        {
            "label": "Round-constant count matches state_width × (full_rounds + partial_rounds)",
            "passed": len(parameters["round_constants"])
            == parameters["state_width"] * (parameters["full_rounds"] + parameters["partial_rounds"]),
        },
        {
            "label": "MDS matrix is 3 × 3 for Poseidon(2) / t = 3",
            "passed": len(parameters["mds_matrix"]) == 3
            and all(len(row) == 3 for row in parameters["mds_matrix"]),
        },
    ]
    parity = _poseidon_vector_parity_report()
    return {
        "title": "Poseidon Constants Provenance Notebook",
        "source_chain": [
            {
                "step": "circomlibjs JSON source",
                "detail": (
                    "protocol.poseidon_bn128 documents that its BN128 Poseidon "
                    "parameters are mirrored from circomlibjs/src/poseidon_constants.json."
                ),
            },
            {
                "step": "Python constant export",
                "detail": (
                    "poseidon_parameter_summary() exports the exact round constants and "
                    "MDS matrix as JSON-friendly decimal strings."
                ),
            },
            {
                "step": "Parity verification",
                "detail": (
                    "The notebook replays deterministic circomlibjs reference vectors "
                    "through poseidon_hash_bn128 and records pass/fail status."
                ),
            },
        ],
        "parameters": {
            **parameters,
            "round_constants_count": len(parameters["round_constants"]),
            "mds_rows": len(parameters["mds_matrix"]),
            "mds_cols": len(parameters["mds_matrix"][0]) if parameters["mds_matrix"] else 0,
        },
        "checks": structural_checks,
        "parity": parity,
        "verified_identical": all(check["passed"] for check in structural_checks) and parity["verified"],
    }


def _circuit_constraint_visualizer() -> dict[str, Any]:
    """
    Return human-readable summaries of the circuit constraints backed by source checks.

    Returns:
        Dictionary with one entry per supported Circom file. Each entry includes
        public/private input summaries, human-readable constraint explanations,
        exact source snippets used for verification, and a source excerpt for
        direct inspection in the UI.
    """
    circuits: list[dict[str, Any]] = []
    for name, meta in _CIRCUIT_VISUALIZER.items():
        source = _CIRCUIT_FILES[name].read_text(encoding="utf-8")
        constraints: list[dict[str, Any]] = []
        for constraint in meta["constraints"]:
            snippets = constraint["source_snippets"]
            constraints.append({
                "label": constraint["label"],
                "explanation": constraint["explanation"],
                "source_verified": all(snippet in source for snippet in snippets),
                "source_snippets": snippets,
            })
        circuits.append({
            "name": name,
            "title": meta["title"],
            "public_inputs": meta["public_inputs"],
            "private_inputs": meta["private_inputs"],
            "constraints": constraints,
            "source_path": str(_CIRCUIT_FILES[name].relative_to(REPO_ROOT)),
            "source_excerpt": source,
        })
    return {"circuits": circuits}


def _parse_proof_bundle(
    body: dict[str, Any],
) -> tuple[RedactionProofWithLedger, bytes, list[int], list[str], int]:
    """Parse and validate the structural shape of a proof bundle payload."""
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
    revealed_indices = [int(index) for index in body.get("revealed_indices", [])]
    revealed_content = [str(content) for content in body.get("revealed_content", [])]
    total_parts = int(body.get("total_parts", 0))
    return proof, smt_root, revealed_indices, revealed_content, total_parts


def _proof_bundle_inspection(body: dict[str, Any]) -> dict[str, Any]:
    """Decode a proof bundle into human-readable fields and pass/fail checks."""
    proof, smt_root, revealed_indices, revealed_content, total_parts = _parse_proof_bundle(body)

    try:
        original_root_bytes = poseidon_root_to_bytes(proof.zk_public_inputs.original_root)
        original_root_valid = True
    except ValueError:
        original_root_bytes = b""
        original_root_valid = False

    sibling_lengths = [len(sibling) == 32 for sibling in proof.smt_proof.siblings]
    unique_indices = len(set(revealed_indices)) == len(revealed_indices)
    indices_in_range = all(0 <= index < total_parts for index in revealed_indices)
    smt_anchor_ok = proof.verify_smt_anchor(smt_root)
    zk_ok = verify_zk_redaction(proof.zk_proof, proof.zk_public_inputs)

    checks = [
        {
            "label": "SMT proof root matches bundle.smt_root",
            "passed": proof.smt_proof.root_hash == smt_root,
            "detail": "The membership proof should be tied to the same committed SMT root published in the bundle.",
        },
        {
            "label": "SMT value_hash matches original_root serialized as 32 bytes",
            "passed": original_root_valid and proof.smt_proof.value_hash == original_root_bytes,
            "detail": "The ledger anchor must store the exact Poseidon originalRoot used by the ZK statement.",
        },
        {
            "label": "revealed_count matches revealed_indices/revealed_content lengths",
            "passed": proof.zk_public_inputs.revealed_count == len(revealed_indices) == len(revealed_content),
            "detail": "The public count should match the disclosed positions and plaintext values.",
        },
        {
            "label": "revealed_indices are unique and within total_parts",
            "passed": unique_indices and indices_in_range,
            "detail": "Each revealed section index should be distinct and refer to an existing document part.",
        },
        {
            "label": "All SMT proof sibling hashes are 32 bytes",
            "passed": all(sibling_lengths),
            "detail": "Sparse Merkle proofs in Olympus use 32-byte sibling hashes at every level.",
        },
        {
            "label": "SMT anchor verification passes",
            "passed": smt_anchor_ok,
            "detail": "This runs RedactionProofWithLedger.verify_smt_anchor against the supplied smt_root.",
        },
        {
            "label": "ZK verification passes",
            "passed": zk_ok,
            "detail": "This invokes the Groth16 verifier when verifier artifacts are available; placeholder proofs fail.",
        },
    ]

    fields = [
        {
            "path": "smt_proof.key",
            "value": proof.smt_proof.key.hex(),
            "decoded": f"{len(proof.smt_proof.key)} bytes",
            "explanation": "Deterministic SMT lookup key for the anchored Poseidon root record.",
        },
        {
            "path": "smt_proof.value_hash",
            "value": proof.smt_proof.value_hash.hex(),
            "decoded": f"{len(proof.smt_proof.value_hash)} bytes",
            "explanation": "Stored SMT value; should equal original_root serialized as a 32-byte big-endian field element.",
        },
        {
            "path": "smt_proof.siblings",
            "value": [sibling.hex() for sibling in proof.smt_proof.siblings],
            "decoded": f"{len(proof.smt_proof.siblings)} sibling hash(es)",
            "explanation": "Sparse Merkle authentication path used to anchor the Poseidon root in the ledger tree.",
        },
        {
            "path": "smt_proof.root_hash",
            "value": proof.smt_proof.root_hash.hex(),
            "decoded": f"{len(proof.smt_proof.root_hash)} bytes",
            "explanation": "SMT root proven by the membership path before comparison with bundle.smt_root.",
        },
        {
            "path": "smt_root",
            "value": smt_root.hex(),
            "decoded": f"{len(smt_root)} bytes",
            "explanation": "Committed ledger-side SMT root that the verifier should pin the SMT proof to.",
        },
        {
            "path": "zk_public_inputs.original_root",
            "value": proof.zk_public_inputs.original_root,
            "decoded": (
                "valid BN128 field element"
                if original_root_valid
                and 0 <= int(proof.zk_public_inputs.original_root) < SNARK_SCALAR_FIELD
                else "invalid BN128 field element"
            ),
            "explanation": "Poseidon Merkle root of the original unredacted document committed inside the circuit.",
        },
        {
            "path": "zk_public_inputs.redacted_commitment",
            "value": proof.zk_public_inputs.redacted_commitment,
            "decoded": "decimal field element",
            "explanation": "Poseidon chain commitment over revealedCount and the masked revealed leaf vector.",
        },
        {
            "path": "zk_public_inputs.revealed_count",
            "value": proof.zk_public_inputs.revealed_count,
            "decoded": "integer",
            "explanation": "Public count of how many document sections were disclosed.",
        },
        {
            "path": "revealed_indices",
            "value": revealed_indices,
            "decoded": f"{len(revealed_indices)} index value(s)",
            "explanation": "Document positions disclosed to the verifier; these should align with revealed_content.",
        },
        {
            "path": "revealed_content",
            "value": revealed_content,
            "decoded": f"{len(revealed_content)} plaintext section(s)",
            "explanation": "The cleartext sections revealed by the proof bundle.",
        },
        {
            "path": "total_parts",
            "value": total_parts,
            "decoded": "integer",
            "explanation": "Total number of document sections represented by the original commitment.",
        },
        {
            "path": "zk_proof",
            "value": proof.zk_proof,
            "decoded": (
                f"{len(proof.zk_proof)} top-level field(s)"
                if isinstance(proof.zk_proof, dict)
                else type(proof.zk_proof).__name__
            ),
            "explanation": "Opaque Groth16 proof payload passed through to the verifier.",
        },
    ]

    return {
        "fields": fields,
        "checks": checks,
        "verified": all(check["passed"] for check in checks),
    }


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
    }

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


@app.get("/constants-provenance")
def constants_provenance():
    """Return the rendered/exportable Poseidon constants provenance notebook."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    return JSONResponse({"ok": True, "notebook": _poseidon_constants_notebook()})


@app.get("/circuit-constraints")
def circuit_constraints():
    """Return human-readable circuit constraint visualizations."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")
    return JSONResponse({"ok": True, **_circuit_constraint_visualizer()})


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

    return JSONResponse({
        "ok": True,
        "verified": overall,
        "smt_anchor_verified": smt_anchor_ok,
        "zk_verified": zk_ok,
        "revealed_sections": revealed_sections,
        "total_parts": total_parts,
    })


@app.post("/inspect-proof-bundle")
async def inspect_proof_bundle(request: Request):
    """Decode and explain a proof bundle with pass/fail checks for each invariant."""
    if not DEBUG_UI_ENABLED:
        raise HTTPException(status_code=404, detail="Debug UI is disabled in this environment.")

    try:
        body = await request.json()
        inspection = _proof_bundle_inspection(body)
    except (KeyError, TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"Invalid proof bundle: {exc}"},
        )

    return JSONResponse({"ok": True, **inspection})
