# Merkle Forest

This document describes the Merkle forest structure used in Olympus.

## Overview

Olympus uses a Merkle forest rather than a single Merkle tree to enable efficient sharding and parallel verification.

## Structure

- Multiple independent Merkle trees
- Each tree represents a shard of documents
- Cross-shard references via root commitments
- Periodic checkpointing for consistency

## Benefits

- Scalability through sharding
- Parallel proof generation
- Independent verification of subsets
- Fault isolation

## Shard Selection

Documents are assigned to shards based on:
- Document type
- Submission timestamp
- Source agency
- Hash-based distribution
