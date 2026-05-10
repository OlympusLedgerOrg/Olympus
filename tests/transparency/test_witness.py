from __future__ import annotations

from typing import List

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from api.transparency.witness import WitnessCosignature, verify_cosignature


def _cosig(seed: int, root: bytes, witness_id: str) -> WitnessCosignature:
    sk = SigningKey(bytes([seed]) * 32)
    payload = b"OLY:WITNESS:V1|" + root
    return WitnessCosignature(
        witness_id=witness_id,
        signature_hex=sk.sign(payload).signature.hex(),
        public_key_hex=sk.verify_key.encode(encoder=HexEncoder).decode(),
    )


def test_witness_threshold_2_of_3_passes() -> None:
    root = bytes([3]) * 32
    signatures: List[WitnessCosignature] = [
        _cosig(1, root, "w1"),
        _cosig(2, root, "w2"),
        _cosig(3, root, "w3"),
    ]
    assert verify_cosignature(root, signatures, threshold=2)


def test_witness_threshold_above_available_fails() -> None:
    root = bytes([4]) * 32
    signatures = [_cosig(1, root, "w1"), _cosig(2, root, "w2")]
    assert not verify_cosignature(root, signatures, threshold=3)


def test_witness_malformed_signature_rejected() -> None:
    root = bytes([5]) * 32
    good = _cosig(1, root, "w1")
    bad = WitnessCosignature(
        witness_id="w2",
        signature_hex="00" * 64,
        public_key_hex=good.public_key_hex,
    )
    assert not verify_cosignature(root, [good, bad], threshold=2)
