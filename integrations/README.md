# Integrations

This directory contains lightweight interoperability helpers for ecosystems that
commonly sit next to Olympus deployments.

- `ethereum.py` formats Olympus commitments for EVM anchoring contracts.
- `ipfs.py` packages proof bundles as deterministic DAG-JSON payloads and
  computes a CIDv1 preview without requiring an IPFS daemon.

These helpers are intentionally narrow: they make Olympus data easier to bridge
into other ecosystems without changing the core append-only protocol semantics.
