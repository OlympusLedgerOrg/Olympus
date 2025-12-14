"""Shard headers and signing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

from nacl import signing
from nacl.exceptions import BadSignatureError

from .hashes import shard_header_hash


@dataclass
class ShardHeader:
    shard_id: str
    root: str
    seq: int
    ts: str
    prev_header_hash: str
    header_hash: str
    signature: str
    signer_pubkey: str

    def fields(self) -> Dict[str, object]:
        return {
            "shard_id": self.shard_id,
            "root": self.root,
            "seq": self.seq,
            "ts": self.ts,
            "prev_header_hash": self.prev_header_hash,
        }


def create_header(
    shard_id: str,
    root: bytes,
    seq: int,
    prev_header_hash: str,
    signing_key: signing.SigningKey,
    ts: Optional[str] = None,
) -> ShardHeader:
    timestamp = ts or datetime.utcnow().isoformat() + "Z"
    fields = {
        "shard_id": shard_id,
        "root": root.hex(),
        "seq": seq,
        "ts": timestamp,
        "prev_header_hash": prev_header_hash,
    }
    hh = shard_header_hash(fields)
    sig = signing_key.sign(hh).signature
    return ShardHeader(
        shard_id=shard_id,
        root=root.hex(),
        seq=seq,
        ts=timestamp,
        prev_header_hash=prev_header_hash,
        header_hash=hh.hex(),
        signature=sig.hex(),
        signer_pubkey=signing_key.verify_key.encode().hex(),
    )


def verify_header(header: ShardHeader) -> bool:
    """Verify signature over shard header hash."""
    hh = shard_header_hash(header.fields())
    if hh.hex() != header.header_hash:
        return False
    try:
        verify_key = signing.VerifyKey(bytes.fromhex(header.signer_pubkey))
        verify_key.verify(hh, bytes.fromhex(header.signature))
    except BadSignatureError:
        return False
    return True
