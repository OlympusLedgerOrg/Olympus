# RFC-0000: SCITT-style transparency receipts for Olympus bundles

| Field      | Value                                      |
|------------|--------------------------------------------|
| Status     | **Draft**                                  |
| Author(s)  | Olympus Contributors                       |
| Date       | 2026-07-01                                 |
| Tracking   | TBD                                        |
| Supersedes | None                                       |

## Summary

Add an optional transparency-receipt layer around existing Olympus proof bundles.
The receipt records that a signed Olympus statement was submitted to a
transparency service/log and gives verifiers a compact way to check inclusion in
that service.

## Motivation

Olympus already commits documents, manifests, shard roots, signatures, and
redaction proofs. A receipt layer would make publication/auditability more
explicit without changing the core trust model. The intended shape is borrowed
from SCITT-style flows:

```text
Olympus signed statement -> transparency log/service -> receipt -> verifier check
```

If nothing changes, Olympus bundles remain internally verifiable but do not have
a standard place to carry external transparency-log accountability evidence.

## Detailed design

The proposed receipt is additive metadata. It must not change any existing
hashing domains, ZK circuits, verifier contracts, or bundle semantics.

An Olympus bundle may carry:

- The existing document commitment, shard/global root, operator signature, and
  redaction manifest/proof data.
- A signed statement over the existing Olympus bundle identifier or commitment.
- A transparency service identifier and log/inclusion receipt.
- Verifier metadata describing which receipt profile was used.

Verifiers should treat receipt checking as an optional extra check. A missing or
invalid receipt must not cause a valid Olympus-native proof to be reinterpreted
as valid or invalid unless a caller explicitly requires receipt enforcement.

## Security & invariant impact

This RFC does not change Olympus-native evidence. Receipts are publication and
accountability evidence, not replacements for Olympus signatures, roots,
manifests, or redaction proofs.

The new trust assumptions are limited to the transparency service named by the
receipt profile. A malicious or unavailable transparency service can affect
receipt validation, but it cannot forge Olympus-native verification.

## Alternatives considered

- Make transparency logging mandatory. Rejected for the first version because it
  creates availability and deployment dependencies.
- Anchor receipts directly to a blockchain. Rejected for now; it adds cost and
  operational complexity without a clear user requirement.
- Use C2PA as the receipt layer. Rejected as a core trust layer; C2PA can be a
  supplemental interoperability format after the receipt model is accepted.

## Drawbacks & risks

Receipt profiles can confuse users if the UI does not clearly separate
Olympus-native verification from external transparency evidence. Implementations
must label receipt failures distinctly from proof failures.

## Unresolved questions

- Which transparency service profile should the first implementation target?
- Should receipts be embedded in existing bundle JSON or carried as adjacent
  files?
- What should the verifier CLI/API surface call optional receipt enforcement?
