# ADR-0038: Experimental post-quantum hybrid envelopes

Status: Proposed; experimental only (2026-07-11)

## Context

Olympus needs an experimental path for protecting newly-created, transferable
protocol objects against store-now/decrypt-later attacks without changing any
ledger hash, SMT proof, ZK public input, checkpoint, credential, or existing
signature format. ML-KEM is a key-establishment mechanism, not an identity or
authentication mechanism. The recipient ML-KEM public key must therefore be
bound to the recipient identity by an authenticated key-binding record.

## Decision

The normal experimental suite is:

- signatures: `Ed25519` **and** `ML-DSA-65`;
- KEM: `ML-KEM-768`;
- KDF: `HKDF-SHA-256`;
- AEAD: `XChaCha20-Poly1305`.

The high-assurance experimental suite pairs `ML-DSA-87` with `ML-KEM-1024`.
Suites are explicit and must never be inferred from a key length or an
algorithm default.

Each envelope contains one to 64 recipient entries. Every recipient gets a
separately encapsulated and encrypted payload:

```text
recipient ML-KEM public key
  -> ML-KEM encapsulate
  -> fresh 32-byte shared secret
  -> HKDF-SHA-256
       salt = BLAKE3("OLY:PQ-ENVELOPE:V1:HKDF-SALT")
       info = lp(protocol_version) || lp(recipient_key_id) || lp(object_id)
  -> 32-byte AEAD key
  -> XChaCha20-Poly1305 encrypt(payload, aad = header)
  -> Ed25519 and ML-DSA sign(header || ciphertext)
```

The sender MUST encapsulate afresh for every recipient and every envelope.
The AEAD nonce is a fresh, uniformly random 24-byte value. A nonce is never
reused with the derived AEAD key.

### Wire contract

`olympus-pq-envelope/v1` is a binary, length-prefixed format. Its unsigned
header, in this exact order, is:

```text
lp(schema) ||
lp(protocol_version) ||
lp(signature_suite_id) ||
lp(kem_algorithm_id) ||
lp(kem_parameter_set) ||
lp(kdf_algorithm_id) ||
lp(aead_algorithm_id) ||
lp(sender_identity_id) ||
lp(sender_ed25519_key_id) ||
lp(sender_ml_dsa_key_id) ||
lp(object_id) ||
u16_be(recipient_count) ||
lp(recipient_header_0) || ... || lp(recipient_header_n)
```

`lp(x)` is Olympus's existing unambiguous length-prefix framing. All ID
fields are non-empty UTF-8 and all algorithm IDs are ASCII constants. The
recipient count is in the inclusive range `1..=64`. A `recipient_header` is:

```text
lp(recipient_identity_id) ||
lp(recipient_ml_kem_key_id) ||
lp(recipient_ml_kem_public_key_blake3) ||
lp(kem_ciphertext) ||
lp(aead_nonce)
```

The header is followed by the ciphertext body:

```text
u16_be(recipient_count) ||
lp(aead_ciphertext_and_tag_0) || ... || lp(aead_ciphertext_and_tag_n)
```

The recipient public-key hash is calculated over the exact FIPS encoding of
the ML-KEM encapsulation key. It prevents a key-ID substitution even where
the recipient's key directory changes over time.

The AEAD associated data for recipient `i` is
`lp(unsigned_header) || u16_be(i) || lp(recipient_header_i)`. Both signature
legs sign the following exact digest, and both must verify for an envelope to
be accepted:

```text
BLAKE3(
  "OLY:PQ-ENVELOPE:V1:SIG" ||
  lp(unsigned_header) ||
  lp(ciphertext_body)
)
```

The two signature components carry their algorithm ID, parameter set, sender
key ID, and signature bytes. They are not independently optional: an absent,
malformed, unknown, or invalid leg is a verification failure. A verifier must
reject an envelope whose declared suite is not exactly the supported suite;
there is no classical-only fallback for a PQ-declared envelope.

`verifiers/test_vectors/pq_envelope_v1.json` is the conformance artifact for
this format. It pins the field-level signed-header construction and BLAKE3
digest, every header field, the 64-recipient upper bound, empty/over-limit lists, malformed
length-prefix handling, recipient KEM-key-ID substitution, and a missing
ML-DSA signature downgrade. Future Rust and JavaScript/offline verifiers
must consume these vectors before the experimental runtime is enabled.

### Identity binding

An ML-KEM public key has no authentication property. Before accepting an
envelope, the recipient key resolver MUST verify a versioned key-binding
record containing the recipient identity, ML-KEM algorithm and parameter set,
key ID, exact public-key bytes (or their BLAKE3 digest), validity window, and
rotation predecessor. That record is signed by both the identity's Ed25519
and ML-DSA keys. The envelope's `recipient_ml_kem_key_id` and public-key hash
must match that verified record. Key rotation must retain historical bindings
so old envelopes remain decryptable and auditable.

## Implementation boundary

This is an opt-in Rust-only experimental module in `olympus-crypto`; no
TypeScript component may create, hold, encapsulate, decapsulate, or sign with
these keys. Its intended experimental signature sidecars are identity
bindings, checkpoint bundles, ceremony/protocol manifests, and ciphertext
envelopes. Those sidecars require Ed25519 plus ML-DSA-65; they do not
retrofit or weaken existing production checkpoint, ceremony, credential, or
redaction bundle semantics. Promotion requires dedicated key persistence,
recovery/rotation, authenticated directory, interop/KAT,
cross-implementation verification, fuzzing, and an independent crypto review.

At the time of this ADR, the prospective RustCrypto `ml-kem` implementation
documents that it has not been independently audited. It must remain an
explicit experimental dependency until that review and Olympus's own supply
chain and license gates are complete.

## Consequences

- ML-KEM is never used as an identity proof or a signature substitute.
- Algorithm, parameter-set, key-ID, nonce, encapsulation ciphertext, payload
  ciphertext, object ID, and protocol version are integrity-bound.
- Downgrade attempts fail because a suite that advertises hybrid protection
  requires both signatures and the signed bytes name every algorithm.
- Existing production formats and trust anchors remain byte-for-byte stable.
