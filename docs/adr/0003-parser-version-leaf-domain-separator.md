# ADR-0003: Parser-Version Binding in the Leaf Hash Domain Separator

| Field       | Value                                                    |
|-------------|----------------------------------------------------------|
| Status      | Proposed (RFC — awaiting maintainer decision)            |
| Date        | 2026-04-18                                               |
| Deciders    | Olympus maintainers                                      |
| Relates to  | OLY:LEAF:V1 open question (canonical_v2 retrospective)   |

## Context

Olympus currently computes leaf hashes as

```
leaf_hash(data) = BLAKE3(b"OLY:LEAF:V1" || b"|" || data)
```

with the prefix `OLY:LEAF:V1` hard-coded in **at least eleven** places
across the codebase: `protocol/hashes.py`, `services/cdhs-smf-rust/src/crypto.rs`,
`src/crypto.rs`, `verifiers/rust/src/lib.rs`, `verifiers/go/verifier.go`,
`verifiers/javascript/verifier.js`, `tools/airgap-verifier.html`,
`frontend/src/components/olympus-full.tsx`, plus golden examples, test
vectors, conformance tests, and benchmarks.

The `data` argument is the canonical-bytes output of the document parser
(currently the Python `protocol/canonical.py` pipeline; production traffic
will go through Docling / docling-core or an equivalent extractor). The
**parser version** — the identity of the software that produced
`canonical_bytes` from the source document — is recorded in the
provenance payload that accompanies the leaf, but it is **not** an input
to the leaf hash itself.

This produces a quiet correctness hazard:

1. **Silent divergence:** if Docling 2.3.1 and Docling 2.4.0 canonicalize
   the same input PDF to different bytes (subtle table-extraction or
   whitespace differences are common across parser releases), the two
   versions produce *different* leaf hashes for the *same source
   document*. The provenance payload tells you *which* parser, but only
   after you fetch the leaf — the leaf hash itself carries no parser
   identity.
2. **Spoofability:** a leaf hash from Docling 2.3.1 is bit-identical to a
   hypothetical leaf hash from any future parser that happens to produce
   the same canonical bytes. There is no cryptographic invariant binding
   `(parser_id, source_document) → leaf_hash`. An attacker who can
   influence which parser version is used for a re-extraction can
   substitute a different extraction at the same leaf hash without any
   chain-level evidence.
3. **No "parser changed → hash changes" guarantee:** the cleanest
   invariant for an auditable system is *if anything that affects the
   bytes changes, the hash changes*. Today, parser version is excluded
   from that invariant.

## Decision (proposed)

Bind the parser identity into the leaf hash domain separator so that
**any change to the parser produces a different leaf hash, even when the
canonical bytes happen to be identical.** The proposed encoding is:

```
parser_id_hash = BLAKE3(b"OLY:PARSER:V1" || parser_id_bytes)
leaf_hash      = BLAKE3(b"OLY:LEAF:V2"   || parser_id_hash || data)
```

This is option **(c)** from the original sketch. The choice over the
alternatives is justified below.

### Why option (c)

| Option | Encoding | Verdict |
|--------|----------|---------|
| (a) | `OLY:LEAF:V2|parser=<id>|<data>` (parser id directly in prefix) | Free-form string in a domain separator. Opens an ambiguity attack: what stops `parser=foo|data=bar` from being parsed two ways? Length-prefix or escape would mitigate, but at that point we have invented a serialization format inside a hash input. |
| (b) | Reuse `OLY:LEAF:V1:parser=...` and rely on existing verifiers' tolerance | Existing verifiers do **byte-exact** prefix comparison. They will reject the longer prefix as malformed, defeating compatibility. |
| **(c)** | `OLY:LEAF:V2 || H("OLY:PARSER:V1" || parser_id) || data` | **Recommended.** Fixed-length prefix (constant 11-byte tag + constant 32-byte digest = 43 bytes). No serialization ambiguity. The `parser_id` string is hashed first under its own domain (`OLY:PARSER:V1`), so the leaf-hash input never contains caller-controlled bytes at the top level. |

### `parser_id` format (proposed)

```
parser_id = "<tool>/<semver>+<build_hash>"
```

where:

- `tool` is a registered short identifier (e.g. `docling`, `tika`,
  `protocol-canonical-py`).
- `semver` is the upstream semantic version of the tool (e.g. `2.3.1`).
- `build_hash` is a short hash (first 12 hex chars of SHA-256) over the
  artifacts that determine the tool's deterministic output: for Docling,
  the model weights and the canonical-pipeline configuration; for the
  in-tree Python pipeline, the git commit of `protocol/canonical.py` and
  the `CANONICAL_VERSION` constant.
- `+` separator chosen because it is illegal in SemVer pre-release but
  legal in build metadata, so we can reuse SemVer parsers if needed.

Example: `docling/2.3.1+a1b2c3d4e5f6`.

The `parser_id` string MUST be ASCII, MUST be ≤ 128 bytes, and MUST be
NFC-normalized. A registry of legal `tool` values lives at
`docs/parser-registry.md` (to be added when this ADR is accepted).

### Where the parser version comes from at hash time

The Rust CD-HS-ST core does **not** currently know the parser version.
Two options:

- **Per-call:** add a required `parser_id` field to every
  `Update`/`Canonicalize` request in `proto/cdhs_smf.proto`. The Go
  sequencer must populate it from the `X-Olympus-Parser-Id` header (or
  from a sequencer-side configuration if the sequencer is the parser).
  This is a `.proto` schema bump.
- **Static:** register a single `parser_id` at sequencer startup and
  reject requests if the header disagrees.

**Recommendation: per-call.** The whole point is to bind parser identity
to the leaf hash; pinning it at startup loses the auditability of
heterogeneous-parser deployments (e.g. a sequencer accepting both
Docling-produced and Tika-produced extractions).

## Open questions for maintainer review

These are blocking — this ADR is **Proposed**, not **Accepted**, until
they are resolved.

1. **Migration story for existing data.** The Phase-0 phasing note in
   `.github/copilot-instructions.md` says "OK to ignore old data" for
   Python SMT/ledger state. Does that license extend to leaf hashes? If
   yes, V1 verifier paths can be removed. If no, all verifiers (Rust
   ×3 crates, Go, JavaScript, the airgap HTML verifier, and the
   frontend) must support both V1 and V2 leaf hashes for the lifetime
   of any V1 leaf that must remain verifiable.

2. **`parser_id` format finalization.** The
   `<tool>/<semver>+<build_hash>` shape above is a strawman. Real
   questions: do we want to embed a SLSA provenance pointer instead?
   Do we want to accept arbitrary `tool` names or require pre-registration?
   What's the canonical source for the Docling `build_hash`?

3. **Wire-format placement.** `.proto` schema bump (per-call) vs.
   sequencer-startup configuration (static) — see above. If per-call,
   does the field belong on `Canonicalize` only, or on `Update` as
   well? (Probably both, since `Update` accepts already-canonicalized
   bytes from clients that may have done the canonicalization
   themselves.)

4. **Test-vector regeneration cadence.** All entries in
   `verifiers/test_vectors/vectors.json`, `examples/pipeline_golden_example.json`,
   and `test_vectors/merkle/` were produced under V1. They will need
   regeneration with a pinned `parser_id` for the new vectors. Should
   the V1 vectors stay (tagged "V1, deprecated") or be removed?

5. **Dual-verifier compatibility window.** If V1 must remain verifiable,
   what's the timeline? Indefinitely, until a chain-level migration
   event, or for a fixed window?

## Consequences

### If accepted

- **Breaking change** to the leaf-hash domain. All Merkle roots computed
  over V2 leaves differ from V1 roots even for identical content. All
  signed roots produced after the cutover are V2-rooted.
- Coordinated update across Python (`protocol/hashes.py`,
  `api/services/merkle.py`), Rust (`services/cdhs-smf-rust/src/crypto.rs`,
  `src/crypto.rs`, `verifiers/rust/src/lib.rs`), Go
  (`verifiers/go/verifier.go`), JavaScript (`verifiers/javascript/verifier.js`,
  `tools/airgap-verifier.html`, `frontend/src/components/olympus-full.tsx`),
  and the cross-language determinism harness
  (`verifiers/cli/test_cross_language_determinism.py`).
- New cryptographic invariant: `(parser_id, canonical_bytes) → leaf_hash`
  is injective; changing either input changes the hash.
- New attack surface: a malicious sequencer could lie about
  `parser_id` to make a leaf appear to have come from a different
  parser. This is **already** within the sequencer-token trust model
  (see `SECURITY.md` § "Sequencer Token Trust Model") but should be
  re-stated explicitly when this ADR ships.

### If rejected

- The current quiet hazard remains: parser-version drift produces
  divergent leaf hashes for the same source document, and there is no
  cryptographic distinction between "Docling 2.3.1 says X" and "Docling
  2.4.0 says X." Provenance is a payload assertion only, not a hash
  invariant.
- No code change required; document the decision and the residual risk
  in `SECURITY.md` § "Known Limitations (Non-Goals)".

## Implementation plan (deferred until this ADR is Accepted)

This ADR is **doc-only**. No code change accompanies it. Implementation
is gated on maintainer answers to the open questions above and would
land as a separate PR with at minimum:

1. `proto/cdhs_smf.proto` — add `parser_id` field (if per-call chosen).
2. `services/cdhs-smf-rust/src/crypto.rs` — add `LEAF_HASH_PREFIX_V2`
   and `PARSER_ID_PREFIX`; new `leaf_hash_v2(parser_id, data)`
   function. Keep V1 path until decision (1) above is resolved.
3. Mirror in `protocol/hashes.py` and all verifier languages.
4. Regenerate `verifiers/test_vectors/vectors.json` and
   `examples/pipeline_golden_example.json`.
5. Extend the cross-language determinism harness to assert byte-equal
   V2 leaf hashes from every language for the same `(parser_id, data)`
   tuple.
6. Update `CHANGELOG.md` under "Breaking Changes."

## References

- `protocol/hashes.py` — current `LEAF_PREFIX` definition.
- `services/cdhs-smf-rust/src/crypto.rs` — Rust core leaf hashing.
- `verifiers/README.md` — cross-language verifier contract.
- `SECURITY.md` § "Sequencer Token Trust Model" — relevant trust
  boundary for parser-id assertion.
- `.github/copilot-instructions.md` § "Phasing and Scope" — Phase-0
  data-migration policy.
