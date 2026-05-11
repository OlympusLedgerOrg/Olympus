"""Witness cosignature scaffolds for CT-style operational hardening.

Why this module exists:
    Olympus already anchors keyed inclusion/non-inclusion proofs in signed SMT roots.
    Witness cosigning adds an operational trust layer that makes split-view behavior
    harder by requiring multiple independent observers to attest to each root.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

import nacl.exceptions
import nacl.signing

from protocol.log_sanitization import sanitize_for_log


logger = logging.getLogger(__name__)

_WITNESS_DOMAIN = b"OLY:WITNESS:V1|"


@dataclass(frozen=True, slots=True)
class WitnessCosignature:
    """A witness attestation over a signed-root payload.

    Attributes:
        witness_id: Stable witness identifier.
        signature_hex: Hex-encoded Ed25519 signature bytes.
        public_key_hex: Hex-encoded Ed25519 public key bytes.
    """

    witness_id: str
    signature_hex: str
    public_key_hex: str


class Witness(Protocol):
    """Protocol for witness implementations.

    Why this interface exists:
        The scaffold keeps network transport abstract so production witness
        onboarding can evolve independently (HTTPS pull, libp2p, etc.) while
        tests inject deterministic doubles.
    """

    witness_id: str
    public_key_hex: str

    def verify(self, payload: bytes, signature_hex: str) -> bool:
        """Return True when the signature is valid for payload."""


def witness_payload(root: bytes) -> bytes:
    """Build the domain-separated witness payload for root cosigning."""
    return _WITNESS_DOMAIN + root


def verify_cosignature(
    root: bytes,
    signatures: list[WitnessCosignature],
    threshold: int = 2,
) -> bool:
    """Verify that at least ``threshold`` witness signatures are valid.

    Why this helper exists:
        It encodes the minimum multiparty trust check shared by monitor,
        gossip, and vector tests without baking in transport details.
    """
    try:
        if len(root) != 32:
            raise ValueError("root must be 32 bytes")
        if threshold <= 0:
            raise ValueError("threshold must be >= 1")

        payload = witness_payload(root)
        valid_witnesses: set[str] = set()

        for cosig in signatures:
            if cosig.witness_id in valid_witnesses:
                continue
            try:
                verify_key = nacl.signing.VerifyKey(
                    bytes.fromhex(cosig.public_key_hex),
                )
                verify_key.verify(
                    payload,
                    bytes.fromhex(cosig.signature_hex),
                )
                valid_witnesses.add(cosig.witness_id)
            except (nacl.exceptions.BadSignatureError, ValueError):
                logger.warning(
                    "Rejected malformed/invalid witness signature for witness_id=%s",
                    sanitize_for_log(cosig.witness_id),
                )
            except Exception:
                logger.error(
                    "Failed while verifying witness signature for witness_id=%s",
                    sanitize_for_log(cosig.witness_id),
                    exc_info=True,
                )

        return len(valid_witnesses) >= threshold
    except Exception:
        logger.error("Witness cosignature verification failed", exc_info=True)
        return False
