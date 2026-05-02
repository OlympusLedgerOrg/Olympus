"""
ORM model package for the Olympus FOIA backend.

Import all models here so that SQLAlchemy's metadata is fully populated
before Alembic or db.py calls `Base.metadata.create_all()`.
"""

from __future__ import annotations

from api.models.agency import Agency
from api.models.api_key import ApiKey
from api.models.appeal import Appeal
from api.models.base import Base
from api.models.credential import KeyCredential
from api.models.dataset import DatasetArtifact, DatasetArtifactFile, DatasetLineageEvent
from api.models.document import DocCommit
from api.models.ledger import MerkleNode
from api.models.ledger_activity import LedgerActivity
from api.models.purchase import Purchase
from api.models.request import PublicRecordsRequest
from api.models.tsa_job import TsaJob
from api.models.user import User
from api.models.witness import WitnessNonce, WitnessObservation


__all__ = [
    "ApiKey",
    "Base",
    "Agency",
    "Appeal",
    "DatasetArtifact",
    "DatasetArtifactFile",
    "DatasetLineageEvent",
    "DocCommit",
    "KeyCredential",
    "LedgerActivity",
    "MerkleNode",
    "PublicRecordsRequest",
    "Purchase",
    "TsaJob",
    "User",
    "WitnessNonce",
    "WitnessObservation",
]
