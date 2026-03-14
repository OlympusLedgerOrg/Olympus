from datetime import datetime, timedelta, timezone

import nacl.signing

from protocol.attestations import (
    Attestation,
    issuer_id_from_pubkey,
    sign_attestation,
    verify_attestation,
)


def test_attestation_sign_and_verify_round_trip():
    signing_key = nacl.signing.SigningKey.generate()
    wallet = "wallet-123"
    claims = {"proof_of_personhood": True, "jurisdiction": "us-ny"}

    attestation = sign_attestation(
        issuer="notary.example",
        subject_wallet=wallet,
        claims=claims,
        signing_key=signing_key,
    )

    verify_key = signing_key.verify_key
    assert verify_attestation(attestation, verify_key, expected_wallet=wallet)


def test_attestation_rejects_wrong_wallet_binding():
    signing_key = nacl.signing.SigningKey.generate()
    attestation = sign_attestation(
        issuer="notary.example",
        subject_wallet="correct-wallet",
        claims={"resident": True},
        signing_key=signing_key,
    )

    verify_key = signing_key.verify_key
    assert not verify_attestation(attestation, verify_key, expected_wallet="other-wallet")


def test_attestation_expiry_enforced():
    signing_key = nacl.signing.SigningKey.generate()
    issued = datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    expires = (
        (datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(hours=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    attestation = sign_attestation(
        issuer="notary.example",
        subject_wallet="wallet",
        claims={"resident": True},
        signing_key=signing_key,
        issued_at=issued,
        expires_at=expires,
    )

    verify_key = signing_key.verify_key
    # Before expiry
    now_before = datetime(2025, 1, 1, 0, 30, tzinfo=timezone.utc)
    assert verify_attestation(attestation, verify_key, now=now_before)

    # After expiry
    now_after = datetime(2025, 1, 1, 2, 0, tzinfo=timezone.utc)
    assert not verify_attestation(attestation, verify_key, now=now_after)


def test_attestation_signature_tamper_detected():
    signing_key = nacl.signing.SigningKey.generate()
    attestation = sign_attestation(
        issuer="notary.example",
        subject_wallet="wallet",
        claims={"resident": True},
        signing_key=signing_key,
    )

    tampered = Attestation(
        issuer=attestation.issuer,
        subject_wallet=attestation.subject_wallet,
        claims={"resident": False},
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        signature=attestation.signature,
        scheme=attestation.scheme,
        credential_id=attestation.credential_id,
    )

    verify_key = signing_key.verify_key
    assert not verify_attestation(tampered, verify_key, expected_wallet="wallet")


def test_issuer_id_from_pubkey_federation_pattern():
    """Test using public key as issuer identifier for federation contexts."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    # Use public key as issuer identifier (federation pattern)
    issuer = issuer_id_from_pubkey(verify_key)
    wallet = "wallet-456"
    claims = {"proof_of_personhood": True, "jurisdiction": "eu-de"}

    attestation = sign_attestation(
        issuer=issuer,
        subject_wallet=wallet,
        claims=claims,
        signing_key=signing_key,
    )

    # Verify the attestation
    assert verify_attestation(attestation, verify_key, expected_wallet=wallet)

    # Verify issuer matches the public key
    assert attestation.issuer == verify_key.encode().hex()


def test_issuer_id_from_pubkey_with_raw_bytes():
    """Test issuer_id_from_pubkey accepts raw bytes."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    pubkey_bytes = bytes(verify_key)

    # Both should produce the same issuer ID
    issuer_from_verify_key = issuer_id_from_pubkey(verify_key)
    issuer_from_bytes = issuer_id_from_pubkey(pubkey_bytes)

    assert issuer_from_verify_key == issuer_from_bytes
    assert issuer_from_verify_key == pubkey_bytes.hex()


def test_credential_id_included_in_signature():
    """Test that credential_id is cryptographically bound in the signature."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    wallet = "wallet-789"
    claims = {"resident": True}

    # Create attestation with credential_id
    attestation_with_id = sign_attestation(
        issuer="notary.example",
        subject_wallet=wallet,
        claims=claims,
        signing_key=signing_key,
        credential_id="cred-12345",
    )

    # Verify it works
    assert verify_attestation(attestation_with_id, verify_key, expected_wallet=wallet)

    # Attempt to tamper with credential_id
    tampered = Attestation(
        issuer=attestation_with_id.issuer,
        subject_wallet=attestation_with_id.subject_wallet,
        claims=attestation_with_id.claims,
        issued_at=attestation_with_id.issued_at,
        expires_at=attestation_with_id.expires_at,
        signature=attestation_with_id.signature,  # Original signature
        scheme=attestation_with_id.scheme,
        credential_id="cred-TAMPERED",  # Changed credential_id
    )

    # Verification should fail because credential_id is in the signed payload
    assert not verify_attestation(tampered, verify_key, expected_wallet=wallet)
