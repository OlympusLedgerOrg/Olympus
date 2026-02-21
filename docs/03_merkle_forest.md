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

## Merkle Tree Semantic Contract

This section defines the immutable semantics of Merkle trees in Olympus. These rules are normative and must never change without a protocol version bump.

### What a Leaf Represents

A leaf in an Olympus Merkle tree is:
- A raw byte hash (32 bytes, BLAKE3) of a document part or document commitment
- The exact input is the hash itself, not re-hashed
- Leaves are **ordered** and **indexed** starting from position 0
- Each leaf is assigned a specific index position that is semantically meaningful
- The tree is **dense** and **append-only** — no gaps in indices

### What Changes the Root

The Merkle root changes if and only if:
1. **A new leaf is appended** (increases tree size, changes all ancestors)
2. **Any leaf value is modified** (replacement of existing leaf)
3. **Leaf order is changed** (reordering leaves produces a different root)

The root is computed bottom-up:
- Parent hash = BLAKE3(0x01 || left_child_hash || right_child_hash)
- If odd number of leaves, the last leaf is duplicated as its own sibling
- The root is deterministic for a given ordered sequence of leaves

### What is Forbidden

The following operations are **explicitly prohibited** and violate the protocol:

1. **Reordering leaves** — Leaf order is semantically meaningful and cannot be changed
2. **Mutation in place** — Once a leaf is committed, it cannot be silently modified
3. **Silent deletion** — Leaves cannot be removed from the tree
4. **Insertion at arbitrary positions** — Only append operations are permitted
5. **Sparse trees** — All index positions from 0 to N-1 must be filled

Any operation that produces a different root for the same semantic content is a protocol violation unless explicitly versioned.
