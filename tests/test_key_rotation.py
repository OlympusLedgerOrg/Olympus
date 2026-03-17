"""Tests for protocol.key_rotation."""

from dataclasses import replace

import hypothesis.strategies as st
import nacl.signing
import pytest
from hypothesis import given

from protocol.key_rotation import KeyEvolutionChain


def test_valid_chain_three_rotations() -> None:
    genesis = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()
    third = nacl.signing.SigningKey.generate()
    fourth = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    chain.rotate(genesis, second, epoch=1)
    chain.rotate(second, third, epoch=2)
    chain.rotate(third, fourth, epoch=4)

    assert chain.verify(bytes(genesis.verify_key))
    assert chain.current_pubkey() == bytes(fourth.verify_key)


def test_broken_signature_fails_verification() -> None:
    first = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    record = chain.rotate(first, second, epoch=1)
    chain.rotations[0] = replace(record, signature_by_old=b"\x00" * 64)

    assert not chain.verify(bytes(first.verify_key))


def test_out_of_order_epoch_skip_is_valid() -> None:
    first = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()
    third = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    chain.rotate(first, second, epoch=1)
    chain.rotate(second, third, epoch=3)

    assert chain.verify(bytes(first.verify_key))


def test_non_monotonic_epoch_fails() -> None:
    first = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()
    third = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    chain.rotate(first, second, epoch=1)
    record = chain.rotate(second, third, epoch=3)
    chain.rotations[1] = replace(record, epoch=0)

    assert not chain.verify(bytes(first.verify_key))


def test_wrong_genesis_fails_verification() -> None:
    first = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()
    wrong_genesis = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    chain.rotate(first, second, epoch=7)

    assert not chain.verify(bytes(wrong_genesis.verify_key))


def test_single_rotation_verifies() -> None:
    first = nacl.signing.SigningKey.generate()
    second = nacl.signing.SigningKey.generate()

    chain = KeyEvolutionChain()
    chain.rotate(first, second, epoch=1)

    assert chain.verify(bytes(first.verify_key))
    assert chain.current_pubkey() == bytes(second.verify_key)


def test_empty_chain_verify_true() -> None:
    genesis = nacl.signing.SigningKey.generate()
    chain = KeyEvolutionChain()
    assert chain.verify(bytes(genesis.verify_key))
    assert chain.current_pubkey() == bytes(genesis.verify_key)


@given(st.integers(min_value=1, max_value=20))
def test_hypothesis_arbitrary_chain_lengths_verify(length: int) -> None:
    keys = [nacl.signing.SigningKey.generate() for _ in range(length + 1)]
    chain = KeyEvolutionChain()

    epoch = 10
    for index in range(length):
        chain.rotate(keys[index], keys[index + 1], epoch=epoch)
        epoch += 2

    assert chain.verify(bytes(keys[0].verify_key))


def test_current_pubkey_requires_known_genesis_if_no_rotations() -> None:
    chain = KeyEvolutionChain()
    with pytest.raises(ValueError, match="genesis pubkey is unknown"):
        chain.current_pubkey()
