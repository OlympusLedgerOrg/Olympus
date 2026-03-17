"""Tests for key rotation evolution chains."""

import nacl.signing
from hypothesis import given, strategies as st

from protocol.canonical import CANONICAL_VERSION
from protocol.canonicalizer import canonicalization_provenance
from protocol.key_rotation import KeyEvolutionChain, KeyRotationRecord
from protocol.ledger import Ledger
from protocol.shards import get_signing_key_from_seed


def _signing_key(seed_byte: int) -> nacl.signing.SigningKey:
    return get_signing_key_from_seed(bytes([seed_byte]) * 32)


def _canonicalization() -> dict[str, str]:
    return canonicalization_provenance("application/json", CANONICAL_VERSION)


def test_key_evolution_chain_valid() -> None:
    old_key = _signing_key(1)
    new_key = _signing_key(2)
    newest_key = _signing_key(3)

    chain = KeyEvolutionChain(
        records=[
            KeyRotationRecord.create(
                old_signing_key=old_key,
                new_signing_key=new_key,
                epoch=1,
                timestamp="2026-03-17T00:00:00Z",
            ),
            KeyRotationRecord.create(
                old_signing_key=new_key,
                new_signing_key=newest_key,
                epoch=2,
                timestamp="2026-03-17T00:10:00Z",
            ),
        ]
    )

    assert chain.verify(old_key.verify_key.encode())


def test_key_evolution_chain_broken_signature() -> None:
    old_key = _signing_key(1)
    new_key = _signing_key(2)

    record = KeyRotationRecord.create(
        old_signing_key=old_key,
        new_signing_key=new_key,
        epoch=1,
        timestamp="2026-03-17T00:00:00Z",
    )
    tampered = KeyRotationRecord(
        old_pubkey=record.old_pubkey,
        new_pubkey=record.new_pubkey,
        epoch=record.epoch,
        timestamp=record.timestamp,
        signature_by_old=record.signature_by_old[:-1] + bytes([record.signature_by_old[-1] ^ 0x01]),
        signature_by_new=record.signature_by_new,
    )

    chain = KeyEvolutionChain(records=[tampered])
    assert not chain.verify(old_key.verify_key.encode())


def test_key_evolution_chain_out_of_order_epoch() -> None:
    old_key = _signing_key(1)
    mid_key = _signing_key(2)
    new_key = _signing_key(3)

    chain = KeyEvolutionChain(
        records=[
            KeyRotationRecord.create(
                old_signing_key=old_key,
                new_signing_key=mid_key,
                epoch=2,
                timestamp="2026-03-17T00:00:00Z",
            ),
            KeyRotationRecord.create(
                old_signing_key=mid_key,
                new_signing_key=new_key,
                epoch=1,
                timestamp="2026-03-17T00:10:00Z",
            ),
        ]
    )

    assert not chain.verify(old_key.verify_key.encode())


def test_key_evolution_chain_verify_from_genesis() -> None:
    genesis = _signing_key(11)
    key2 = _signing_key(12)
    chain = KeyEvolutionChain(
        records=[
            KeyRotationRecord.create(
                old_signing_key=genesis,
                new_signing_key=key2,
                epoch=1,
                timestamp="2026-03-17T01:00:00Z",
            )
        ]
    )

    assert chain.verify(genesis.verify_key.encode())
    assert not chain.verify(_signing_key(99).verify_key.encode())


def test_key_rotation_record_can_commit_to_ledger() -> None:
    ledger = Ledger()
    old_key = _signing_key(21)
    new_key = _signing_key(22)
    record = KeyRotationRecord.create(
        old_signing_key=old_key,
        new_signing_key=new_key,
        epoch=1,
        timestamp="2026-03-17T00:00:00Z",
    )

    entry = record.append_to_ledger(
        ledger=ledger,
        shard_id="rotation/shard-a",
        shard_root="00" * 32,
        canonicalization=_canonicalization(),
    )

    assert entry.record_hash == record.record_hash().hex()
    assert ledger.verify_chain()


@given(length=st.integers(min_value=0, max_value=12))
def test_key_evolution_chain_hypothesis_lengths(length: int) -> None:
    keys = [_signing_key(i + 1) for i in range(length + 1)]
    records = [
        KeyRotationRecord.create(
            old_signing_key=keys[i],
            new_signing_key=keys[i + 1],
            epoch=i + 1,
            timestamp=f"2026-03-17T00:{i:02d}:00Z",
        )
        for i in range(length)
    ]

    chain = KeyEvolutionChain(records=records)
    assert chain.verify(keys[0].verify_key.encode())
