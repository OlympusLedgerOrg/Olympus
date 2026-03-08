# Formal Specification

Olympus now includes a small **TLA+ model** for the core append-only semantics at:

- `docs/formal/OlympusAppendOnly.tla`
- `docs/formal/OlympusAppendOnly.cfg`

## Scope of the Model

The model is intentionally narrow. It abstracts away transport, databases, and UI behavior so it can focus on the protocol claims that matter most:

1. **No committed document can be changed**
2. **Every valid proof corresponds to a real document**
3. **The ledger is append-only**

The model tracks a finite set of document identifiers, a committed-state map, a sequence of ledger events, and a set of issued proofs.

## What the Model Checks

The TLA+ module exposes the following invariants for TLC:

- `CommittedDocsDoNotChange`
- `ValidProofsCorrespondToCommittedDocs`
- `AppendOnlyLedger`

Those invariants are written against transition history variables so the checker can verify that each protocol step preserves append-only behavior and proof integrity.

## How to Run TLC

If the TLA+ tools are available locally, run TLC against the bundled config:

```bash
java -cp tla2tools.jar tlc2.TLC /path/to/Olympus/docs/formal/OlympusAppendOnly.tla
```

Or open `docs/formal/OlympusAppendOnly.tla` in the TLA+ Toolbox and use `docs/formal/OlympusAppendOnly.cfg` as the model configuration.

## Interpretation

This model does **not** prove the entire production implementation correct. It proves that the abstract state machine for committing documents and issuing proofs preserves the three core safety properties above.

That is the intended role of the formal spec in this repository: pin the protocol invariants in a machine-checkable form so future implementation work can be compared against them.
