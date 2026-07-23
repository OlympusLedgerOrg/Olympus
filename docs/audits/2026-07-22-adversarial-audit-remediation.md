# Adversarial audit remediation — 2026-07-22

**Status:** Addressed in this source tree. This is a pre-release hardening
record, not an incident report: the supplied environment has no working
production database, users, or customer data.

## Closure summary

| Area                    | Remediation                                                                                                                                                                                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Checkpoint provenance   | The producer now selects only committed snapshots, rebuilds the complete ordered shard tree, compares the root/size/path, and verifies the ingest snapshot signature before signing or anchoring. Mutable PostgreSQL witness columns are no longer trusted as proof.         |
| Append consistency      | Bundle v3 and federation wire v3 carry the previous root, appended leaf, depth-20 Poseidon path, and an authority-signed transition. Producers and receivers reconstruct both roots and fail closed on any mismatch.                                                         |
| Checkpoint identity     | New checkpoint rows are deduplicated independently of emission timestamp by an evidence-preserving partial unique index. Historical duplicates, if any, are retained.                                                                                                        |
| Historical key rotation | Each checkpoint pins its BJJ public-key coordinates. Bundle export validates and uses those historical coordinates, so later authority rotation does not make old evidence unexportable.                                                                                     |
| Quorum authorization    | API-key scope resolution now verifies the stored M-of-N signatures and requires the trusted issuer to anchor the exact threshold/signer set. A quorum row cannot grant scopes from its single-issuer signature alone.                                                        |
| Federation co-signing   | Peer trust and a valid requester signature are necessary but no longer sufficient. Each peer has an explicit allowlist of credential types it may request; the default is empty/fail-closed.                                                                                 |
| Signed admin replay     | Production always requires the ADR-0036 envelope for high-risk admin mutations. Nonces remain reserved through the entire future-dated acceptance window, and reservation happens only after the presented API key matches the signed key/operator identity.                 |
| Embedded PostgreSQL     | Fresh clusters use a random, persistent 256-bit password with SCRAM and owner-only file permissions. Existing fixed-password clusters are rotated once; connection URIs and secrets are no longer logged. Concurrent first starts use an atomic no-clobber publication step. |
| RFC 3161                | Receipt acceptance now verifies the CMS signature and the signer chain with OpenSSL's timestamp-signing certificate purpose, using system roots plus an optional operator CA bundle. Structural imprint and nonce checks remain mandatory.                                   |
| Tor rate limiting       | Re-verified: limiter keys include listener origin, so public-loopback and Tor traffic do not share one depletion bucket.                                                                                                                                                     |
| Protocol documentation  | Bundle, federation, quorum, environment, threat-model, and court-evidence documentation now match the enforced v3/runtime behavior.                                                                                                                                          |

## Verification added

- Adversarial checkpoint tests cover mutable witness rejection, signed append
  transitions, and missing provenance keys; the bundle producer separately
  validates its persisted historical authority coordinates.
- RFC 3161 tests use a real CMS timestamp response, accept its explicitly
  trusted test root, and reject the same chain when untrusted.
- JavaScript offline-verifier tests reconstruct the append transition and
  reject a tampered path, in addition to the existing checkpoint signature,
  anchor, encoding, and vector suites.
- Embedded-password tests cover persistence, non-legacy randomness,
  permissions, and concurrent initialization.

Rust compilation and the database-backed Rust suites still need to run in an
environment with the repository's Rust 1.94 toolchain and PostgreSQL test
prerequisites. The JavaScript verifier suite is self-contained.
