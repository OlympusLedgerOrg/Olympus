"""
ZK proof generation and verification for the Olympus FOIA ledger.

Generates real Groth16 proofs via the snarkjs bridge (Node.js persistent
subprocess) using circuits compiled against the Hermez ptau20 ceremony file.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import HTTPException, status

from protocol.hashes import hash_bytes


logger = logging.getLogger(__name__)

_SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Paths are resolved relative to proofs/ directory inside the container
_PROOFS_DIR = Path(__file__).resolve().parent.parent.parent / "proofs"
_BUILD_DIR = _PROOFS_DIR / "build"
_VKEYS_DIR = _PROOFS_DIR / "keys" / "verification_keys"


def _proofs_available() -> bool:
    """Return True if circuits, zkeys and Node.js are all present."""
    import shutil

    if shutil.which("node") is None:
        return False
    return (_BUILD_DIR / "document_existence_js" / "document_existence.wasm").exists() and (
        _BUILD_DIR / "document_existence_final.zkey"
    ).exists()


def generate_document_existence_proof(commit_id: str, doc_hash: str) -> dict:
    """Generate a real Groth16 document-existence proof via snarkjs.

    Builds a single-entry PoseidonSMT keyed by the BLAKE3 doc_hash,
    generates the Merkle witness, and proves it with the document_existence
    circuit (ptau20 keys).

    Args:
        commit_id: Hex commit identifier (used as proof metadata).
        doc_hash:  BLAKE3 hex hash of the committed document (64 hex chars).

    Returns:
        Dict with keys: protocol, curve, proof, public_signals, verified,
        circuit, commit_id.

    Raises:
        RuntimeError: If Node.js or circuit artifacts are unavailable.
    """
    if not _proofs_available():
        raise RuntimeError(
            "ZK proof generation unavailable: Node.js or circuit artifacts missing. "
            "Ensure the container was built with Node.js and proofs/build/ is populated."
        )

    try:
        from proofs.proof_generator import ProofGenerator
        from protocol.poseidon_smt import PoseidonSMT
    except ImportError as exc:
        raise RuntimeError(f"ZK proof dependencies unavailable: {exc}") from exc

    doc_bytes = bytes.fromhex(doc_hash)
    doc_int = int.from_bytes(doc_bytes, byteorder="big") % _SNARK_SCALAR_FIELD

    smt = PoseidonSMT()
    smt.update(doc_bytes, doc_int)

    generator = ProofGenerator("document_existence")
    witness = ProofGenerator.witness_from_smt_existence(smt, doc_bytes)
    zk_proof = generator.prove(witness)

    return {
        "protocol": "groth16",
        "curve": "bn128",
        "proof_type": "groth16",
        "circuit": "document_existence",
        "commit_id": commit_id,
        "proof": zk_proof.proof,
        "public_signals": zk_proof.public_signals,
        "verified": True,
    }


def generate_proof_stub(commit_id: str, doc_hash: str) -> dict:
    """Return a mock Groth16 proof anchoring a commit to a document hash.

    This is a STUB for development use only. The proof values are not
    cryptographically valid. Raises RuntimeError in production.

    Raises:
        RuntimeError: If OLYMPUS_ENV is not "development".
    """
    if os.getenv("OLYMPUS_ENV", "production") != "development":
        raise RuntimeError(
            "ZK proof stub is disabled in production. "
            "Set OLYMPUS_ENV=development or configure a real Groth16 backend."
        )

    return {
        "protocol": "groth16",
        "curve": "bn128",
        "proof_type": "stub",
        "proof": {
            "pi_a": [
                "21831381940491799887451961494797590068761498990054021688008189310956935432206",
                "20497466052605059009345807972038460725716906555044613996175183534616014463785",
                "1",
            ],
            "pi_b": [
                [
                    "10520261478371553346693380573048437583895260395553946838975047670671994609784",
                    "18234898660516823608862449578718461148060820010888826990637768408782474875919",
                ],
                [
                    "9623046989675311620898794380960706414459424396820778624447534284745047013870",
                    "21015705565089003618765975283640905960862199888617021026487249208979519853782",
                ],
                ["1", "0"],
            ],
            "pi_c": [
                "6877682397639755822619553870174099019913513305990765571975041710424428589803",
                "7378679741174025892706065310299213046671064267720029027628613440484839741476",
                "1",
            ],
        },
        "public_signals": [commit_id, doc_hash],
        "verified": False,
        "note": "STUB — Circom circuit integration pending",
    }


def verify_proof_type(proof: dict) -> tuple[bool, str | None]:
    """Check if a proof is acceptable for the current environment."""
    if proof.get("proof_type") == "stub":
        env = os.getenv("OLYMPUS_ENV", "production")
        if env != "development":
            return False, "stub_proof_rejected_in_production"
    return True, None


def verify_groth16_proof(
    proof: dict,
    *,
    vkey_path: str | None = None,
) -> tuple[bool, str]:
    """Verify a Groth16 proof using the native arkworks verifier.

    Args:
        proof: Proof dict with keys proof, public_signals, proof_type.
        vkey_path: Path to snarkjs-format verification key JSON.
            Falls back to OLYMPUS_ZK_VKEY_PATH env var, then auto-selects
            based on proof["circuit"] if present.

    Returns:
        (True, "verified") on success, (False, reason) on failure.
    """
    import json

    if proof.get("proof_type") == "stub":
        return False, "stub_proof"

    resolved_path = vkey_path or os.environ.get("OLYMPUS_ZK_VKEY_PATH")
    if not resolved_path:
        return False, "no_vkey_configured"

    try:
        resolved = Path(resolved_path).resolve(strict=False)
    except (OSError, ValueError):
        logger.error("ZK vkey path could not be resolved")
        return False, "vkey_not_found"

    # Allow vkeys under the proofs/keys directory or OLYMPUS_ZK_DIR
    _zk_dir = Path(os.environ.get("OLYMPUS_ZK_DIR", str(_VKEYS_DIR))).resolve()
    if not resolved.is_relative_to(_zk_dir) and not resolved.is_relative_to(_VKEYS_DIR.resolve()):
        logger.error("ZK vkey path outside allowed directory")
        return False, "vkey_not_found"

    if not resolved.exists():
        logger.error("ZK vkey not found at resolved path")
        return False, "vkey_not_found"

    try:
        vkey_bytes = resolved.read_bytes()
        expected_vkey_hash = os.environ.get("OLYMPUS_ZK_VKEY_HASH")
        if expected_vkey_hash and hash_bytes(vkey_bytes).hex() != expected_vkey_hash.lower():
            return False, "vkey_hash_mismatch"
        vkey_json = vkey_bytes.decode("utf-8")
    except Exception:
        logger.exception("Unexpected error loading ZK verification key")
        return False, "internal_error"

    try:
        from olympus_core import verify_groth16_bn254
    except ImportError:
        # Fall back to snarkjs bridge verification
        logger.info("olympus_core unavailable — falling back to snarkjs bridge verification")
        try:
            from proofs.snarkjs_bridge import verify as snarkjs_verify

            vkey_file = resolved
            proof_inner = proof.get("proof", proof)
            public_signals = [str(s) for s in proof.get("public_signals", [])]
            ok = snarkjs_verify(
                vkey_file=vkey_file,
                proof=proof_inner,
                public_signals=public_signals,
            )
            return (True, "verified") if ok else (False, "verification_failed")
        except Exception:
            logger.exception("snarkjs bridge verification failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Native ZK verifier unavailable — olympus_core extension missing and snarkjs fallback also failed.",
            ) from None

    try:
        proof_inner = proof.get("proof", proof)
        proof_json = json.dumps(proof_inner)
        public_signals = [str(s) for s in proof.get("public_signals", [])]
        ok = verify_groth16_bn254(vkey_json, proof_json, public_signals)
        return (True, "verified") if ok else (False, "verification_failed")
    except Exception:
        logger.exception("Unexpected error in native ZK verifier")
        return False, "internal_error"
