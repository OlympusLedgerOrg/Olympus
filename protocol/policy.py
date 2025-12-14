"""Waterfall policy engine and hashing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

from .canonical import canonicalize_json
from .hashes import POLICY_PREFIX, blake3_hash


@dataclass
class Policy:
    policy_id: str
    version: str
    ops_cap_cents: int
    rnd_cap_cents: int
    architect_pct: float = 0.10
    fund_pct: float = 0.10
    effective_ts: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    policy_hash: Optional[str] = None

    def canonical_dict(self) -> Dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "ops_cap_cents": int(self.ops_cap_cents),
            "rnd_cap_cents": int(self.rnd_cap_cents),
            "architect_pct": float(self.architect_pct),
            "fund_pct": float(self.fund_pct),
            "effective_ts": self.effective_ts,
        }

    def compute_hash(self) -> str:
        if self.policy_hash:
            return self.policy_hash
        payload = canonicalize_json(self.canonical_dict())
        self.policy_hash = blake3_hash([POLICY_PREFIX, payload]).hex()
        return self.policy_hash


def compute_waterfall(revenue_cents: int, policy: Policy) -> Dict[str, int]:
    """Compute deterministic revenue waterfall according to policy."""
    remaining = int(revenue_cents)

    ops = min(remaining, int(policy.ops_cap_cents))
    remaining -= ops

    architect = int(remaining * policy.architect_pct)
    remaining -= architect

    fund_base = int(remaining * policy.fund_pct)
    remaining -= fund_base

    rnd = min(remaining, int(policy.rnd_cap_cents))
    remaining -= rnd

    remainder = remaining
    fund_total = fund_base + remainder

    return {
        "revenue_cents": int(revenue_cents),
        "ops_cents": ops,
        "architect_cents": architect,
        "fund_cents": fund_total,
        "rnd_cents": rnd,
        "remainder_cents": remainder,
        "policy_hash": policy.compute_hash(),
    }
