from __future__ import annotations

from typing import List

from api.transparency.gossip import SignedRootEnvelope, detect_equivocation
from api.transparency.witness import WitnessCosignature


def _env(height: int, root_hash: str, signature: str) -> SignedRootEnvelope:
    return SignedRootEnvelope(
        height=height,
        root_hash=root_hash,
        sequencer_signature=signature,
        sequencer_key_id="sequencer-main",
        witness_cosignatures=[
            WitnessCosignature(witness_id="w1", signature_hex="11" * 64, public_key_hex="aa" * 32)
        ],
        timestamp="2026-05-10T21:40:09Z",
    )


def test_detect_equivocation_returns_evidence_for_conflicting_same_height() -> None:
    peer_a: List[SignedRootEnvelope] = [_env(7, "aa" * 32, "ab" * 64)]
    peer_b: List[SignedRootEnvelope] = [_env(7, "bb" * 32, "cd" * 64)]
    evidence = detect_equivocation(peer_a, peer_b)
    assert evidence is not None
    assert evidence.height == 7
    assert evidence.root_a != evidence.root_b


def test_detect_equivocation_none_for_same_root() -> None:
    peer_a = [_env(7, "aa" * 32, "ab" * 64)]
    peer_b = [_env(7, "aa" * 32, "ab" * 64)]
    assert detect_equivocation(peer_a, peer_b) is None
