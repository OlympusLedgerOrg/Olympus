# ADR-0030: Redaction via signed Merkle fold (drop the Groth16 circuit) + lower the ceremony to power 17

- **Status:** **Proposed — 2026-06-14.**
- **Builds on:** ADR-0025/0026/0028 (the per-segment **hiding-leaf** commitment +
  the `Segmenter` abstraction), ADR-0029 (visual text-run redaction — *unblocked*
  by this ADR because the 1024-leaf cap disappears).
- **Supersedes (for the redaction producer only):** the **Groth16
  `redaction_validity`** proof. The circuit's *commitment* (per-segment hiding
  leaves folded to a root, committed on the ledger) is **kept**; only the
  *proof mechanism* changes from a SNARK to a **signed Merkle fold**.
- **Leaves ZK in place where it earns its keep:** `document_existence` and
  `non_existence` (privacy-preserving ledger inclusion / non-inclusion) stay on
  Groth16. They are small (~8k and ~70k constraints), so dropping
  `redaction_validity` (~466k–983k, the largest *production* circuit) lets the
  production ceremony drop from **power 20 → power 17**.

## Context

Redaction must let a recipient verify four things about a redacted artifact:

1. **Binding** — it derives from the original committed on the ledger.
2. **Selective disclosure** — *exactly* these segments were removed; the rest is
   unchanged.
3. **Issuer authorization** — the authority key sanctioned this redaction, for
   this recipient.
4. **Hiding** — removed content is unrecoverable from the bundle / root.

None of these need zero-knowledge. The leaves are **already** hiding Pedersen
commitments (ADR-0026 — hiding), the bundle is **already** Ed25519-signed
(authorization), and binding + selective disclosure are a Merkle property. The
SNARK's only extra is hiding the **recipient id** and the **count/positions** of
redacted segments — and the threat model (court-evidence / press-freedom, known
recipient, largely-visible structure) does not require that.

Meanwhile the SNARK imposes two real costs: a hard **1024-leaf cap** (blocks
fine-grained text-run redaction) and a **power-20 trusted-setup ceremony**.
`redaction_validity` is the largest *production* circuit; `unified` /
`federation_quorum` (the other power-20 circuits) are **gated, not shipped**.

## Decision

### 1. Commitment: uncapped per-document segment Merkle tree

At ingest, fold the document's segment leaves into a **variable-depth**
domain-1 Poseidon Merkle tree (depth `⌈log2 N⌉`, padded to the next power of two
with the zero/empty-leaf sentinel) — **no 1024 cap, no fixed padding**. The root
is committed on the ledger as `original_root`, exactly as today; the per-segment
leaves are persisted in `redaction_segment_manifests`, as today. The leaf
function (`olympus_crypto::redaction` hiding commitment) is **unchanged**.

### 2. Bundle: `V3` signed Merkle fold + **signed segment table**

The bundle carries the **full per-segment table** so the verifier can both fold
to the root *and* know exactly which segments the issuer sanctioned redacting.
Crucially, byte ranges are **into the redacted artifact the recipient holds** (not
the original), so the verifier reconstructs revealed leaves by a plain **slice** —
no PDF/ZIP parser required (see §Red-team refinements, finding RT-2).

```jsonc
{
  "content_hash", "original_root", "format", "segment_count": N, "recipient_id",
  "segments": [            // EVERY segment, ascending segment_id, no gaps/overlap
    {
      "segment_id",
      "redacted": <bool>,
      "artifact_offset", "artifact_length",   // byte range IN THE REDACTED ARTIFACT
      "label"?,                                // present for ooxml-part (the part name, bound into the leaf)
      "blinding_decimal"?,                     // revealed only: recipient recomputes the leaf from the slice
      "leaf_hex"?                              // redacted only: the committed blinded leaf (content-safe)
    }
  ],
  "nullifier",      // BLAKE3("OLY:REDACTION:NULLIFIER:V1" || original_root || table_hash || recipient_id)
  "signature_hex"   // Ed25519 over the V3 payload below
}
```

The **signed payload** binds everything a verifier relies on (no vestigial
`redacted_commitment` — dropped, see RT-4):

```
OLY:REDACTION_BUNDLE:V3 || lp(content_hash) || lp(original_root) || lp(format)
  || u32_be(N) || lp(recipient_id) || table_hash
table_hash = BLAKE3( "OLY:REDACTION:TABLE:V3"
  || for each segment in ascending segment_id:
       u32_be(segment_id) || u8(redacted) || u64_be(artifact_offset) || u64_be(artifact_length)
       || lp(label) || lp(redacted ? leaf_hex_bytes : blinding_bytes) )
```

### 3. Verification (slice + hash — no format parser in the verifier)

A recipient, holding the redacted artifact + the bundle:

1. **Structural checks.** The `segments` ids are exactly `0..N-1` (strictly
   ascending, no gaps, no overlap); every entry's `[artifact_offset,
   artifact_offset+artifact_length)` lies within the artifact. Reject otherwise.
2. **Reconstruct each leaf.**
   - **revealed** → `slice = artifact[offset .. offset+length]`; the leaf is
     `redaction_leaf(content_scalar(segment_id, content_bytes), blinding)` where
     `content_bytes` is `trim_body(slice)` for the PDF formats / `lp(label) ||
     slice` for `ooxml-part` / `slice` for `text-line` (the **same** rule the
     segmenter used). No re-segmentation — a direct slice.
   - **redacted** → use the published `leaf_hex`, and confirm the artifact bytes
     in its range are destroyed (NUL / `null`).
3. **Fold** all `N` leaves (domain-1, variable depth) → assert it equals
   `original_root`, **and** that `original_root` is the value committed for
   `content_hash` on the ledger.
4. **Re-derive `table_hash`** from the bundle's `segments` (the mask comes solely
   from each entry's `redacted` flag), recompute the V3 payload, and **verify the
   Ed25519 issuer signature**; recompute and check the `nullifier`.

Why each property holds: **binding/no-tamper** — a revealed leaf is recomputed
from the artifact slice and must match what the root commits (Pedersen binding +
fold-to-on-ledger-root). **No partition downgrade** — the `redacted` flag of every
segment is inside `table_hash`, so relabelling a revealed segment as redacted (or
adding phantom padding-slot redactions / changing `N`/`format`) breaks the
signature (closes RT-1/RT-3/RT-5). **Hiding** — redacted blindings are withheld;
the published `leaf_hex` is a blinded Pedersen commitment, unrecoverable even for
low-entropy content (RT-3 hiding confirmed sound).

### 4. Drop `redaction_validity`; lower the ceremony to power 17

- Remove the Groth16 redaction prove path from the producer (`issue.rs`), the
  redaction witness/circuit usage, and the `redaction_validity` artifacts.
- `setup_circuits.sh`: regenerate **power 17** keys for the only remaining
  production circuits, `document_existence` (~8k) + `non_existence` (~70k) —
  both fit `2^17 = 131,072`. Update PTAU download + BLAKE2b checksums + the
  ceremony manifests. `unified` / `federation_quorum` stay gated (would need
  power 20 again *if* shipped — a future decision).

### 5. Visual text-run redaction falls out for free

With the cap gone, ADR-0029's `pdf-textrun` segmenter can commit one leaf per
text run with no grouping hack — the only reason the cap mattered.

## What is lost vs. the SNARK (accepted)

- The bundle reveals the **recipient id** and the **count/positions** of redacted
  segments (never their content). Acceptable for the stated threat model. If a
  future use case needs ZK redaction, rebuild it on an SMT-inclusion circuit
  (the `document_existence` shape) rather than the 1024-flat-fold — a separate
  decision, not paid for now.
- Because blindings are deterministic per `(document, segment)`, the same
  document redacted for two recipients yields **identical published redacted
  `leaf_hex`** — the two bundles are linkable as the same original (content stays
  hidden). The SNARK did not expose this. Acceptable here; documented.
- Proof size grows from ~constant (~200 B) to O(N) hashes. Negligible: the
  recipient already holds the whole document.

## Security & invariants

- Same hiding-leaf primitive, same domain-1 fold, same Ed25519 signing key
  (persisted). **Domain-separated** new bundle tag `OLY:REDACTION_BUNDLE:V3`
  (disjoint from the `V2` SNARK-bundle tag and the SBT tags), plus
  `OLY:REDACTION:TABLE:V3` for the segment-table hash.
- No GPL; no new ZK. The offline verifiers (`verifiers/{rust,javascript}`)
  **gain `content_scalar` + `redaction_leaf`** (BLAKE3-XOF → subgroup scalar,
  Pedersen on Baby Jubjub, Poseidon) on top of their existing Merkle + Ed25519 +
  Pedersen code; the slice-based reconstruction (§3) needs **no PDF/ZIP parser**.
  Cross-language V3 vectors are added to `verifiers/test_vectors`.
- Greenfield migration (pre-v1, DB wipe): `V2` Groth16 bundles are not retained.

## Red-team refinements (29-agent adversarial review, 2026-06-14)

The initial V3 design was red-teamed before implementation. **No content-recovery
or tamper-passes-as-authentic attack survived** — Pedersen binding + fold-to-on-
ledger-root hold. Six confirmed findings, all design-time, folded into the spec
above:

- **RT-1 / RT-5 (HIGH) — partition unbound.** The root pins leaf values/positions
  but *not* the revealed/redacted labelling, so a holder could downgrade an
  authorized disclosure (hide more than sanctioned). **Resolved:** the per-segment
  `redacted` flag is inside `table_hash`, which the signature covers; the verifier
  derives the mask solely from the signed table.
- **RT-3 (MEDIUM) — `N`/format/padding reinterpretation.** Variable-depth zero
  padding + unsigned `N` allowed phantom "redacted" padding slots. **Resolved:**
  `N` and `format` are signed; the verifier requires ids `0..N-1` dense, rejecting
  padding-slot/extra segments.
- **RT-4 / RT-5 (MEDIUM) — `redacted_commitment` undefined without the circuit.**
  It was a Groth16 public signal with no V3 definition, leaving the signed message
  unimplementable. **Resolved:** dropped entirely; the signature binds the segment
  table directly.
- **RT-2 / RT-6 (MEDIUM) — verifiability gap.** The bundle shipped no byte ranges
  and §3 implied re-segmenting the artifact, which is unsound (text redaction
  zeroes newlines) and infeasible for re-emit formats (the offline verifiers have
  no PDF/ZIP parser). **Resolved:** ship per-segment byte ranges **into the
  redacted artifact** + bind them in `table_hash`; the verifier reconstructs
  revealed leaves by a direct **slice**, no parser. Added: verifiers gain
  `content_scalar`/`redaction_leaf` + cross-language V3 vectors.
- A mandatory regression: a cross-language negative vector that flips one
  segment's revealed/redacted role on an otherwise-valid bundle and asserts the
  signature check **fails**.

## Phased implementation

1. **Commitment**: uncapped Merkle fold in the segmenter/ingest path (replace the
   1024 pad); persist as today. Golden test the root.
2. **Producer**: `V3` bundle (fold + sign), drop the Groth16 prove call.
3. **Verifiers** (Rust + JS) + cross-language vectors: verify `V3`.
4. **FE** (`api.ts` + RedactTab) for the `V3` shape.
5. **Ceremony**: drop `redaction_validity`; regenerate power-17 keys/manifests
   (operator step — `setup_circuits.sh`).
6. **ADR-0029 Phase B** now unblocked (uncapped text runs).

## Alternatives considered

- **Keep Groth16 + add a parallel Merkle path** — double the producer / verifier
  / audit surface for marginal benefit; rejected.
- **Rebuild ZK redaction on SMT inclusion (uncapped + ZK)** — only if recipient/
  structure privacy becomes a hard requirement; deferred.
- **Rasterized tiles (ADR-0023/0024)** — rejected previously; unrelated.
