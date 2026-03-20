"""
DNS publication helpers for Olympus checkpoints.

Generates deterministic TXT records that witnesses can publish or consume
to provide out-of-band attestations of the latest checkpoint hash. These
records are intentionally compact and avoid external dependencies so they
can be generated in restricted environments.
"""

from __future__ import annotations

from typing import Any

from .checkpoints import SignedCheckpoint


def checkpoint_txt_record(checkpoint: SignedCheckpoint) -> str:
    """
    Build a compact DNS TXT value for a checkpoint.

    Format: ``oly-chk seq=<n>;hash=<hash>;height=<h>;root=<ledger_root>``
    """
    fields = [
        f"seq={checkpoint.sequence}",
        f"hash={checkpoint.checkpoint_hash}",
        f"height={checkpoint.ledger_height}",
        f"root={checkpoint.ledger_head_hash}",
    ]
    return "oly-chk " + ";".join(fields)


def checkpoint_record_set(
    *, domain: str, checkpoint: SignedCheckpoint, label: str | None = None
) -> dict[str, Any]:
    """
    Construct a DNS record payload describing where to publish the TXT value.

    Args:
        domain: Base domain (e.g., ``example.gov``).
        checkpoint: Checkpoint to publish.
        label: Optional label. Defaults to ``oly-chk-<sequence>``.

    Returns:
        Mapping with ``name`` and ``txt`` keys for downstream DNS tooling.
    """
    record_name = label or f"oly-chk-{checkpoint.sequence}"
    fqdn = f"{record_name}.{domain}".rstrip(".")
    return {
        "name": fqdn,
        "txt": checkpoint_txt_record(checkpoint),
    }


def verify_txt_record(record: str, checkpoint: SignedCheckpoint) -> bool:
    """
    Validate that a TXT record matches the supplied checkpoint.

    Returns:
        True if all required fields align with the checkpoint.
    """
    if not record.startswith("oly-chk "):
        return False
    _, payload = record.split(" ", 1)
    components = dict(item.split("=", 1) for item in payload.split(";") if "=" in item)
    required = {
        "seq": str(checkpoint.sequence),
        "hash": checkpoint.checkpoint_hash,
        "height": str(checkpoint.ledger_height),
        "root": checkpoint.ledger_head_hash,
    }
    for key, expected in required.items():
        if components.get(key) != expected:
            return False
    return True
