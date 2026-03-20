"""
ZK proof stub for the Olympus FOIA ledger.

Returns a plausible-looking Groth16 proof structure.  Real Circom circuit
integration is a separate workstream.

# TODO: Wire to Circom witness generation + snarkjs
#
# Future integration path:
#   1. Generate witness:  snarkjs wtns calculate circuit.wasm input.json witness.wtns
#   2. Prove:             snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
#   3. Verify:            snarkjs groth16 verify verification_key.json public.json proof.json
#
# The ``proof`` dict below mirrors the JSON structure produced by snarkjs
# so that the real integration requires only swapping out this stub.
"""

from __future__ import annotations


def generate_proof_stub(commit_id: str, doc_hash: str) -> dict:
    """Return a mock Groth16 proof anchoring a commit to a document hash.

    This is a STUB.  The proof values are not cryptographically valid and
    must not be used for actual verification.  They exist to allow the rest
    of the system to exercise the proof API surface before Circom circuits
    are wired in.

    Args:
        commit_id: Hex commit identifier (e.g. ``"0xc7d4a2f8e1b3095d"``).
        doc_hash: BLAKE3 hex hash of the committed document.

    Returns:
        A dict shaped like a snarkjs Groth16 proof JSON export.
    """
    return {
        "protocol": "groth16",
        "curve": "bn128",
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
        "verified": True,
        "note": "STUB — Circom circuit integration pending",
    }
