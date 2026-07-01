# C2PA bridge guardrails

C2PA support is an interoperability bridge, not an Olympus trust boundary.

Any future implementation must follow these rules:

- C2PA manifests are imported as third-party provenance claims.
- C2PA manifests are not treated as Olympus-native evidence.
- C2PA manifests do not satisfy Olympus bundle verification.
- C2PA manifests do not replace Olympus signatures, roots, manifests, redaction
  proofs, or verifier checks.

The intended bridge is supplemental:

- Export selected Olympus proof metadata as a C2PA-compatible assertion for
  downstream tools that understand Content Credentials.
- Import a C2PA manifest as external provenance evidence that can itself be
  committed into Olympus.
- Label imported C2PA evidence distinctly from Olympus-native verification in
  APIs, CLIs, and UI.

Implementation is blocked until the transparency receipt RFC is accepted and the
bridge has a reviewed interface design.
