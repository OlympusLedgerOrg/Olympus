# ADR-0040: RISC Zero canonicalization receipts composed with Groth16 inclusion

**Status:** Accepted
**Date:** 2026-07-18

## Context

Olympus canonical JSON is JCS / RFC 8785 raw UTF-8 plus the project's exact
decimal-number rules. The normative Rust implementation also NFC-normalizes
string keys and values, sorts object keys by UTF-16 code-unit order, rejects
duplicate keys after normalization, enforces the JSON grammar and nesting
limit, and renders numbers from their exact decimal tokens. This is a real
parser and Unicode transform, not a hash preimage convention.

The historical
`unified_canonicalization_inclusion_root_sign` Circom artifact does not perform
that transform. It proves knowledge of an eight-slot structured section
commitment, inclusion of that commitment in a depth-20 Merkle tree, and
inclusion of the Merkle root in the depth-256 ledger SMT. Its
`canonicalHash` signal is a historical ABI name for the structured section
commitment. Treating the circuit alone as proof of canonicalization would let a
prover choose arbitrary section fields.

Reimplementing general JSON parsing, full Unicode NFC, UTF-16 ordering, and
exact decimal normalization in Circom would create a second canonicalizer with
a large audit and constraint surface. A bounded ASCII or schema-specific
dialect would be easier, but would contradict the repository invariant that
canonical JSON always uses the full Olympus rules.

Olympus therefore needs a proof that the existing Rust canonicalizer executed,
and a precise way to bind that result to the existing Groth16 inclusion proof.

## Decision

Canonicalization is proven by a RISC Zero receipt. The zkVM guest receives the
source JSON bytes as private input and calls
`olympus_crypto::canonical::canonicalize_bytes` directly. It does not carry a
fork, translation, or reduced profile of the canonicalizer. A successful guest
execution commits a fixed-width public claim to the receipt journal; invalid
JSON or any canonicalization error produces no valid claim.

The existing Groth16 circuit remains responsible for the narrower statement it
already proves:

1. knowledge of the eight-slot structured section commitment exposed as
   `canonicalHash`;
2. inclusion of that commitment in the record Merkle tree; and
3. inclusion of that Merkle root in the ledger SMT.

The verifier composes the proofs by deriving the Groth16 section witness from
the verified RISC Zero journal and requiring its resulting structured
commitment to equal the Groth16 public `canonicalHash`. Neither proof is
accepted as a substitute for the other when the API claims canonicalization
plus inclusion. The combined verification request also supplies the expected
`sourceCommitment` as exactly 64 lowercase hexadecimal characters. The
verifier compares it with the authenticated journal value so a valid receipt
for an unrelated private document cannot satisfy the caller's statement. This
comparison binds the proof to a named public commitment; it does not establish
the provenance of that expected value. A relying party that cares about the
exact pre-canonical source must obtain `sourceCommitment` from its own trusted
record or protocol context rather than merely echoing a prover-provided value.

### Guest identity

The accepted program identity is the RISC Zero image ID computed from the
pinned, committed guest ELF. The verifier also requires that computed value to
equal the separate committed lowercase-hex `.id` file produced by the pinned
guest build. It never accepts an image ID supplied alongside a request or
copied from a receipt. CI deterministically rebuilds both artifacts with RISC
Zero 3.0.5 in the guest-builder image pinned by registry digest, stages the
combined user-and-kernel program bytes whose image ID RISC Zero reports, and
byte-compares them with the committed release files. A rebuilt ELF is therefore
an explicit protocol artifact rather than an ambient local build result.

Startup recomputes this identity before the API starts. Development mode warns
and leaves the combined protocol unavailable when the artifact is absent or
inconsistent; `OLYMPUS_ENV=production` exits with status 2 instead of serving
with a placeholder, malformed ELF, or mismatched `.id` file.

Changing the guest ELF changes the image ID. Such a change requires an explicit
compatibility decision, updated verifier constants and fixtures, and review of
the journal/version contract. It does not silently inherit trust from an older
guest merely because both guests call a function with the same Rust name.

## Canonicalization claim journal

The journal is exactly 96 bytes. It uses fixed-width big-endian integers and a
manual encoder/decoder; no general-purpose serializer participates in the
consensus-facing encoding.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic/version `OLYCAN01` |
| 8 | 8 | `source_len`, `u64_be` |
| 16 | 8 | `canonical_len`, `u64_be` |
| 24 | 32 | `source_commitment` |
| 56 | 32 | `canonical_digest` |
| 88 | 1 | `section_count`; MUST equal `1` |
| 89 | 7 | reserved; all bytes MUST be zero |

The fields are defined as follows:

```text
source_commitment = BLAKE3(
    "OLY:CANONICAL-SOURCE:V1|" ||
    u64_be(source_len) ||
    source_bytes
)

canonical_digest = BLAKE3(canonical_bytes)
```

`canonical_digest` deliberately remains the bare BLAKE3 value encoding pinned
by ADR-0009 and used by the existing JavaScript one-section witness recipe.
Only the source commitment introduces a new BLAKE3 domain. Its fixed-width
length prevents concatenation ambiguity and binds the digest to the exact
private input length.

Both source JSON and canonical output are capped at 1 MiB. The source cap is
checked before canonicalization; output expansion is checked before the claim
is committed. Canonical output must be non-empty and `section_count` is fixed
to one because the circuit section contains the canonical digest, not the
canonical bytes themselves.

The decoder rejects the wrong total size, magic/version, non-zero reserved
bytes, either size above 1 MiB, an empty source or canonical output, or a
section count other than one. These checks are part of the public claim
contract, not merely guest-side assertions.

### Binding the journal to Groth16

After receipt verification and journal validation, the host derives the
existing Groth16 inputs deterministically:

1. Interpret `canonical_digest` as one unsigned big-endian integer and reduce
   it modulo the BN254 scalar-field modulus to obtain `documentSections[0]`.
2. Set `sectionCount = 1`, `sectionLengths[0] = canonical_len`, and
   `sectionHashes[0] = Poseidon(1)(documentSections[0])`.
3. Set `documentSections[1..8]` and `sectionLengths[1..8]` to zero, and set each
   corresponding `sectionHashes[i] = Poseidon(1)(0)`, exactly as constrained by
   the existing circuit.
4. Run the existing domain-3 structured chain over all eight slots, starting
   from `sectionCount` and folding each length and section hash in order.
5. Require the resulting field element to equal the Groth16 public
   `canonicalHash` before accepting the composite statement.

The big-endian interpretation and reduction are normative. Implementations may
not truncate, use little-endian packing, omit the seven padded slots, or
replace the existing `DomainPoseidon(3)` chain. The composite commitment's
collision bound is limited by the BN254 field reduction, while the separate
public BLAKE3 digests retain their byte-level definitions.

## Verification and trust boundaries

Verification is fail-closed and ordered:

1. Deserialize the receipt under bounded request limits and require the
   succinct receipt format used by this protocol.
2. Verify it against the pinned Olympus guest image ID with RISC Zero
   development mode explicitly disabled.
3. Only after successful cryptographic verification, read and decode the
   journal and enforce the complete 96-byte structural contract.
4. Require the caller's canonical lowercase-hex `sourceCommitment` to equal the
   receipt's authenticated `source_commitment`.
5. Derive the section commitment and compare it with the Groth16 public
   `canonicalHash`.
6. Verify the Groth16 proof and its existing public-signal rules, including the
   `treeSize = 0` empty-root guard.
7. Verify checkpoint authority or federation signatures in the existing Rust
   layer; neither the receipt nor the Groth16 circuit authenticates a
   checkpoint signer.

Any failure rejects the complete claim. In particular, the host must not parse
an unverified journal and then treat its contents as authenticated, and it must
not accept a locally recomputed claim in place of a receipt.

RISC Zero development-mode or fake receipts are never valid API artifacts.
There is no environment switch, debug-build exception, test credential, or
fallback verifier that may accept one. Tests that exercise claim encoding
without a prover test only that lower-level encoding; they do not establish an
accepted receipt. End-to-end verification uses a cryptographically valid
receipt for the pinned image.

The boundaries are therefore:

- The RISC Zero proof attests execution of the pinned guest over private source
  bytes and authenticates the public journal. Its trust roots are the RISC Zero
  proof system, the pinned image ID, and the guest's dependency/toolchain
  supply chain.
- The shared Rust `canonicalize_bytes` implementation defines JCS/NFC/decimal
  semantics. Host and guest parity tests and the committed canonicalization
  vectors guard against build-feature or dependency drift.
- Groth16 attests only the structured commitment and the two inclusion paths.
  Its trust roots remain the reviewed Circom R1CS and its ceremony artifacts.
- The Rust host orchestrates composition but is not trusted to assert either
  proof's result. An offline verifier can repeat every receipt, journal,
  commitment, and Groth16 check.
- Checkpoint signatures and federation policy remain outside both proofs.

The receipt is zero-knowledge with respect to the source bytes, but the journal
publishes both lengths and deterministic BLAKE3 commitments. These are binding,
not hiding, commitments: low-entropy or guessable documents can be tested by an
observer. Callers must not interpret the receipt as protecting a predictable
plaintext from an offline dictionary attack.

## Platform and operational behavior

Receipt verification is supported by the native Windows desktop. Local RISC
Zero proving is not. On native Windows, a combined canonicalization-proving
request returns an explicit `503 Service Unavailable` unless the binary was
built with the `zkvm-prover` capability on a supported Linux target. It must not
fall back to an unproved host claim, a fake receipt, or an implicit remote
service.

Operators who need local proving on Windows use a supported Linux environment,
including WSL2, as explicit operator tooling. This is not a hidden runtime
network dependency of the desktop verifier. A future hosted or delegated
prover would receive private source bytes and therefore requires a separate
privacy, authentication, availability, and abuse-control decision. Proof
soundness would still be checked locally against the pinned image ID.

The one-MiB source and output caps are protocol limits for this receipt format,
not HTTP body-limit defaults. Requests that exceed them fail before expensive
proving. Raising either cap changes the accepted guest program and requires a
new image ID plus an explicit compatibility/version decision.

Every proving execution also carries the shared 1,073,741,824-user-cycle
session limit (2^30). The committed `cycle-report.json` exercises eight
adversarial shapes at the one-MiB boundary; the maximum is 744,183,696 user
cycles for a reverse-key wide object, leaving roughly 30.7% of the enforced
ceiling unused. Changing the source bound, canonicalizer, guest toolchain, or
guest image requires
regenerating that report and reviewing the ceiling before release. Local
proving remains serialized by the API's single-permit queue so the bounded
per-session cost cannot multiply without limit inside one desktop process.

## Ceremony and release consequences

RISC Zero adds no Olympus circuit-specific Phase-2 ceremony. The guest ELF and
image ID take the place of an application-program identity for the
canonicalization proof, and changing them does not require regenerating the
Circom proving key.

This composition deliberately preserves the existing unified Groth16 R1CS,
five public signals, artifact stem, proving key, verification key, and signed
ceremony manifest. Adding the receipt and host-side linkage alone therefore
does not trigger a Groth16 ceremony.

This does not waive the repository's atomic ceremony rule. Any change to the
Circom source or resulting R1CS—including a constraint cleanup made in the same
release—requires regenerating the affected proving key, verification key, and
signed manifest through the setup/ceremony workflow. Manifests are never
hand-edited. Conversely, a guest-only change updates the guest ELF, image ID,
receipt fixtures, and compatibility/version policy, but not Groth16 artifacts.

## Consequences

- The canonicalization statement now covers the full production Rust
  JCS/NFC/decimal algorithm instead of a second, restricted circuit dialect.
- Canonical bytes and source bytes remain private, while deterministic lengths
  and commitments are public.
- The existing, audited Groth16 inclusion circuit and its public-signal ABI are
  reused; the two proofs are linked by one deterministic section commitment.
- Verification remains available on every desktop target, but proof generation
  requires supported Linux tooling and substantially more compute than plain
  canonicalization.
- Olympus adds the RISC Zero verifier, guest toolchain, ELF, and image ID to its
  cryptographic supply-chain and release-review surface.
- The fixed journal and one-MiB bounds make allocation and cross-implementation
  behavior auditable, at the cost of rejecting larger documents from this proof
  path.

## Alternatives considered

- **Implement full canonicalization in Circom.** Rejected because it duplicates
  the Rust parser, Unicode tables, sorting, and decimal semantics in a circuit,
  creates a large differential-testing surface, and requires a new Groth16
  ceremony for every semantic correction.
- **Define a bounded ASCII or typed-document canonicalization profile.**
  Rejected because a proof of that profile is not a proof of Olympus canonical
  JSON and would violate the single canonicalization invariant.
- **Canonicalize only on the host and hash caller-supplied sections in
  Groth16.** Rejected because the verifier would still have to trust the host's
  unproved transform.
- **Split canonical output into eight separately-domain-separated chunks.**
  Rejected because the existing circuit already commits field elements rather
  than raw bytes. One bare canonical BLAKE3 digest preserves the ADR-0009 and
  JavaScript recipe, avoids a new digest protocol, and still binds up to the
  full one-MiB proof limit.
- **Move inclusion and ledger verification into the zkVM as well.** Deferred.
  It would replace a working, separately auditable Groth16 statement and enlarge
  the guest without improving the immediate canonicalization soundness gap.
- **Use a transparent remote prover automatically on unsupported platforms.**
  Rejected because silently transmitting private source bytes creates a new
  confidentiality and availability boundary. Delegated proving must be
  explicit and separately designed.
