# zkVM redaction proof-of-concept

Status: non-production experiment.

This lab is reserved for a tiny text redaction/canonicalization proof in a zkVM.
It must not replace the existing Olympus redaction path, circuits, verifier
contracts, or bundle semantics.

Initial target:

```text
input text + byte-span redaction request
  -> deterministic canonical text
  -> deterministic redacted text
  -> commitment to original and redacted outputs
  -> zkVM receipt proving that exact transformation
```

Guardrails:

- No production endpoint.
- No default workspace membership.
- No verifier-visible bundle field.
- No claim that zkVM receipts are Olympus-native evidence.
- No dependency on remote proving for ordinary verification.

Promotion out of this directory requires a reviewed RFC/ADR and conformance
tests against the current redaction segmenter/canonicalizer expectations.
