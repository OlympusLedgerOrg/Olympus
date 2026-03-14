from datetime import datetime, timedelta, timezone

import nacl.signing

from protocol.attestations import Attestation, sign_attestation, verify_attestation


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
    expires = (datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
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
