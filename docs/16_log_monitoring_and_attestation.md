# Log Monitoring, Attestations, and Public Anchors

Olympus combines append-only Merkle trees, verifiable identity attestations, and external anchors to make tampering obvious.

## Global Log Monitoring

- **Signed Tree Heads (STHs):** Nodes expose `/protocol/sth/latest` so monitors can pull the current root, tree size, timestamp, and signature.
- **Consistency proofs:** When a tree grows, monitors require a CT-style consistency proof linking the previous tree size to the new one. Verification uses `protocol.merkle.verify_consistency_proof` and `protocol.epochs.verify_sth_consistency`.
- **Split-view detection:** `protocol.monitoring.LogMonitor` tracks the latest STH per node+shard and raises `SplitViewEvidence` when two nodes present different roots for the same tree size. This enables gossip networks of independent monitors/auditors.

Example (pseudo-code):

```python
monitor = LogMonitor(sth_fetcher=fetch_sth, consistency_fetcher=fetch_proof)
monitor.poll_node(node_id="guardian-a", shard_id="us-gov-foia")
monitor.poll_node(node_id="guardian-b", shard_id="us-gov-foia")
evidence = monitor.split_view_evidence("us-gov-foia")
```

## Identity Attestation Layer

- **Attest, don’t store identity:** Olympus never ingests passports or SSNs. Instead, an issuer (IDP/notary) signs a credential binding a person to a wallet.
- **Wallet binding:** `protocol.attestations.Attestation` binds `issuer`, `subject_wallet`, and structured `claims` to an Ed25519 signature over a domain-separated BLAKE3 hash.
- **Verification:** `verify_attestation` checks the signature, wallet binding, and expiration without revealing underlying documents. This matches W3C VC-style attestations and prevents custodial identity storage.

Example:

```python
attestation = sign_attestation(
    issuer="civic-notary",
    subject_wallet="wallet-address",
    claims={"proof_of_personhood": True},
    signing_key=issuer_key,
)
verify_attestation(attestation, issuer_key.verify_key, expected_wallet="wallet-address")
```

## Public Anchor Chain

- **Daily immutable commitments:** Publish shard or ledger roots to an external immutable system (Bitcoin/Ethereum/RFC 3161 TSA) so any rewrite attempt is exposed.
- **Anchor commitments:** `protocol.anchors.AnchorCommitment` records the `anchor_chain`, `anchor_reference` (txid/receipt/serial), `anchored_at`, and a domain-separated commitment hash for inclusion in proofs.
- **Verification:** Verifiers recompute the commitment hash locally and check it against the expected Merkle root; the external anchor reference is then resolved on-chain or via TSA receipts.

Example:

```python
commitment = AnchorCommitment.create(
    anchor_chain="ethereum",
    merkle_root=ledger_root,
    anchor_reference="0xdeadbeef...",  # txid or receipt id
    metadata={"network": "holesky"},
)
assert commitment.verify(expected_root=ledger_root)
```

These three layers—consistency proofs with gossip monitoring, wallet-bound attestations, and public anchors—convert tamper-evidence into active tamper-detection.
