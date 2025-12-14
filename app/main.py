from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.state import OlympusState

app = FastAPI(title="Olympus Phase 0", version="0.1.0", docs_url="/")
state = OlympusState(os.getenv("OLY_DB_PATH", ":memory:"))


def require_admin(x_api_key: str = Header(...)):
    if not state.validate_admin(x_api_key):
        raise HTTPException(status_code=403, detail="invalid admin key")
    return True


class AppendRequest(BaseModel):
    shard_id: str
    record_type: str
    record_id: str
    version: str
    value: dict


class PolicyRequest(BaseModel):
    period: str = Field(..., description="period identifier for policy shard")
    policy_id: str
    version: str
    ops_cap_cents: int
    rnd_cap_cents: int
    architect_pct: float = 0.10
    fund_pct: float = 0.10
    effective_ts: Optional[str] = None


class WaterfallRequest(BaseModel):
    period: str
    revenue_cents: int
    policy: PolicyRequest


class ProofVerificationRequest(BaseModel):
    root: str
    key: str
    proof: dict
    value_hash: Optional[str] = None


@app.get("/status")
def status():
    return {"status": "ok", "global_root": state.roots()["global_root"]}


@app.get("/roots")
def roots():
    return state.roots()


@app.get("/shards/{shard_id}/header/latest")
def shard_header_latest(shard_id: str):
    header = state.header_latest(shard_id)
    if not header:
        raise HTTPException(status_code=404, detail="shard not found")
    return header.__dict__


@app.get("/shards/{shard_id}/proof/existence")
def proof_existence(shard_id: str, key: str, version: Optional[str] = None):
    key_bytes = bytes.fromhex(key)
    proof = state.proof_existence(shard_id, key_bytes, version)
    return proof.to_dict()


@app.get("/shards/{shard_id}/proof/nonexistence")
def proof_nonexistence(shard_id: str, key: str, version: Optional[str] = None):
    key_bytes = bytes.fromhex(key)
    proof = state.proof_nonexistence(shard_id, key_bytes, version)
    return proof.to_dict()


@app.post("/verify/proof")
def verify_proof(req: ProofVerificationRequest):
    ok = state.verify_proof(req.root, req.key, req.proof, req.value_hash)
    return {"valid": ok}


@app.post("/admin/policy", dependencies=[Depends(require_admin)])
def admin_policy(req: PolicyRequest):
    payload = req.dict()
    period = payload.pop("period")
    policy = state.create_policy(period, payload)
    return {"policy_hash": policy.policy_hash, "shard_id": f"global:{period}:policy"}


@app.post("/admin/waterfall", dependencies=[Depends(require_admin)])
def admin_waterfall(req: WaterfallRequest):
    allocations = state.record_waterfall(req.period, req.revenue_cents, req.policy.dict(exclude={"period"}))
    return allocations


@app.post("/admin/append", dependencies=[Depends(require_admin)])
def admin_append(req: AppendRequest):
    state.append_record(req.shard_id, req.record_type, req.record_id, req.version, req.value)
    return {"ok": True}
