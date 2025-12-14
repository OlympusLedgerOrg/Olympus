# Ledger Protocol

This document describes the ledger protocol for Olympus.

## Overview

The Olympus ledger is an append-only, replicated log of document commitments.

## Entry Format

Each ledger entry contains:
- Timestamp
- Document hash
- Merkle root
- Shard identifier
- Source signature
- Previous entry hash

## Consensus

Olympus uses a federated consensus model:
- Multiple independent nodes
- Threshold signatures for finality
- Fork detection mechanism
- Conflict resolution rules

## Replication

- Pull-based replication
- Merkle proof verification
- Gap detection and recovery
- Byzantine fault tolerance
