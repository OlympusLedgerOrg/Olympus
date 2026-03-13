"""
Storage layer init module.
"""

from .blob import BlobStore
from .postgres import StorageLayer

# Sub-modules for audit-boundary separation:
#   storage.protocol_state   – smt_leaves, smt_nodes, shard_headers, ledger_entries
#   storage.operational_state – rate_limits, ingestion_batches, timestamp_tokens
from . import operational_state, protocol_state  # noqa: F401

__all__ = ["BlobStore", "StorageLayer", "protocol_state", "operational_state"]
