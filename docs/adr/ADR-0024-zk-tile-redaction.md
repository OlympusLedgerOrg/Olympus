# ADR-0024: Hybrid rasterized **ZK** tile redaction (Groth16 over Poseidon-folded tile leaves)

- **Status:** **REJECTED — 2026-06-08.** Superseded by the #1221 decision that
  rejected ADR-0023's rasterized tile-redaction direction. ADR-0024 builds on
  that same rasterization (it only swaps the verification layer for a Groth16
  circuit), so ADR-0023's *Rejection rationale* (renderer-fidelity trust
  boundary, in-process PDFium RCE surface, loss of semantic/byte provenance)
  applies here unchanged. The chunk-based `redaction_validity` circuit remains
  the canonical redaction primitive. *Historical context: the design + circuit
  landed via #1220 before the direction was reversed; the `tile_redaction_validity`
  circuit was parked, then **removed** from the tree once ADR-0025 was accepted
  (recover from git history if ever revived).*
- **Date proposed:** 2026-06-07
- **Date rejected:** 2026-06-08
- **Supersedes / builds on:**
  - **Replaces** the chunk-based `redaction_validity` scheme
    (`proofs/circuits/redaction_validity.circom`, `src-tauri/src/zk/chunk.rs`,
    the `/redaction/issue` + `/redaction/link` endpoints). That scheme is
    retired (see *Migration*).
  - **Keeps and reuses** ADR-0023's rasterization importers
    (`src-tauri/src/zk/redaction_import.rs`) and Pedersen tile commitment
    (`src-tauri/src/zk/redaction_tile.rs::commit_tile`).
  - **Replaces** ADR-0023's *direct* Ed25519-over-descriptor verification
    (`redaction_tile.rs::build_bundle` / `verify_bundle`) with a Groth16
    proof, so a redaction composes with `document_existence` over a shared
    `original_root` public signal.
- **Related invariants:** ADR-0005 (length-prefix framing, domain separation);
  the Critical-Invariant rule that a commitment-format change moves
  `olympus-crypto` + both verifiers + golden vectors in one commit; the
  ceremony-manifest atomicity rule.

## Context

The shipped `redaction_validity` circuit commits a document as **16
length-proportional raw-byte chunks** (`chunk_size = ceil(filelen / 16)`). ADR-0023
established (with measurements) that this cannot model real document redaction:
length-dependent boundaries shift on any edit, and editor re-serialization of a
PDF/Office file leaves **no surviving bytes** to bind against — making the
trustless property information-theoretically impossible for re-rendered files.

ADR-0023 fixed the *commitment* (rasterize → tile → Pedersen) but verified it
with a **direct** Merkle-root + Ed25519 check, not a ZK proof, so a redaction
could not compose with the ledger-existence proof in zero knowledge, and the
redaction mask / revealed structure was exposed in the clear.

The decision here (operator-selected) is to keep ADR-0023's rasterization but
prove redaction with a **Groth16 circuit**, so:

1. A single verifier check ties the redacted artifact to a **ledger-committed**
   original (`original_root` is shared with `document_existence`), with no trust
   in bundle assembly.
2. Redacted tiles are bound but never revealed (private circuit inputs).

## Decision

### Pipeline

Issuer (Rust, `redact` scope):

1. **Import → canonical raster** — reuse `redaction_import.rs` (PNG/JPEG/BMP/
   TIFF/WebP via `redaction-import`; PDF via `redaction-pdf`/pdfium). Renders to
   canonical page images at a pinned DPI (the universal normalizer — strips
   hidden text, metadata, prior revisions, scripts).
2. **Tile → fixed `N = 1024` grid** (`TILE_REDACTION_MAX_LEAVES`). Pages are
   split into a deterministic, edge-padded tile set; the canonical `(page,y,x)`
   ordering of `redaction_tile.rs::TileCoord` is padded/truncated to exactly
   `N` slots (empty slots commit the empty-tile sentinel).
3. **Commit each tile (hiding)** — `C_i = m_i·G + b_i·H` (ADR-0023
   `commit_tile`, Pedersen on Baby Jubjub, `b_i` random). The **circuit leaf**
   is `leaf_i = Poseidon(C_i.x, C_i.y)` (a field element the SNARK can fold).
4. **Fold → `original_root`** via a depth-10 **Poseidon** Merkle fold — each node
   is a single `Poseidon(1, left, right)` (domain tag 1 in slot 0), NOT ADR-0023's
   BLAKE3 `tiles_root` (BLAKE3 is not SNARK-friendly) and NOT the nested
   `Poseidon(Poseidon(1,left),right)` (~⅓ more constraints). This Poseidon root is
   the ledger leaf; `document_existence` proves it is anchored.
5. **Redactor picks boxes** (frontend sends coordinates only → tile indices).
6. **Blank + re-encode** — Rust overwrites the redacted tiles' pixels (solid
   black, not overlay) and encodes an **image-only** artifact.
7. **Prove + sign** — generate the `tile_redaction_validity` Groth16 proof and
   the bundle (revealed tiles carry `b_i`; redacted tiles carry nothing).

Recipient (no re-render):

- Verify the Groth16 proof (`/zk/verify`, circuit `tile_redaction_validity`).
- Verify `document_existence` for `original_root` (shared public signal).
- Bind the artifact: for each **revealed** tile recompute `C_i` from the
  artifact bytes + published `b_i`, `leaf_i = Poseidon(C_i.x, C_i.y)`, and
  recompute `redactedCommitment`; compare to the proof's public signal. Redacted
  tiles contribute `0` to the chain, so the recipient never needs their content.

### Circuit `tile_redaction_validity(maxLeaves = 1024, depth = 10)`

Mirrors `redaction_validity`'s public-signal contract and domain tags, with two
changes:

- **Flat fold, not per-leaf inclusion.** The circuit already holds all leaves,
  so it recomputes `original_root` once (`maxLeaves − 1` node hashes) and asserts
  equality, instead of running `maxLeaves` Merkle-inclusion proofs. At
  `N = 1024` the flat fold is ≈ 1.35M constraints; per-leaf inclusion would be
  ~depth× larger. The circuit asserts `maxLeaves == 2^depth`.
- **Single-Poseidon(3) domain hash.** Both the fold node hash and the
  redacted-commitment chain use one 3-input `Poseidon(domain, left, right)`
  rather than the nested `Poseidon(Poseidon(domain,left),right)` — same domain
  separation, ~⅓ fewer constraints. This is what keeps `N = 1024` inside the
  power-22 ceremony.
- Public signals unchanged in shape:
  `[nullifier(out), originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]`.
  Commitment chain domain `3`; node domain `1`; `nullifier = Poseidon(originalRoot,
  redactedCommitment, recipientId)`; in-circuit `EdDSAPoseidonVerifier` over the
  nullifier (audit M-2 carried forward).

**Constraint budget / ceremony:** **≈ 1.35M constraints** (with the
single-Poseidon(3) hash) — fits the **power-22** ceremony ptau
(`setup_circuits.sh`; snarkjs Groth16 setup requires `2^power ≥ 2 × constraints`,
i.e. constraints ≤ 2²¹ = 2,097,152). The power-22 ptau covers this and every
other repo circuit, so one Phase-1 file makes them all work; it is pinned against
a verified BLAKE2b-512 checksum. Desktop in-process prove ≈ 15–30 s, ≈ 3–5 GB.

> **Sizing reality (measured in CI).** With the original nested-Poseidon hash the
> counts ran ~2× higher — N=2048 measured 4.25M constraints (needs power-24),
> N=1024 needed power-23, and only N=512 fit power-22. Switching the node/chain
> hash to a single `Poseidon(3)` cut ~⅓ of the cost, bringing **N=1024 (~1.35M)**
> inside **power-22**. Going beyond 1024 is still a deliberate ceremony upgrade:
> N=2048 needs a power-23 ptau (bigger Phase-1 download + new checksum).

### Why the leaf must be a *hiding* commitment (security analysis)

A Merkle root over `N` leaves **pins** any single unknown leaf once all siblings
are known. If a document redacts one tile and reveals the rest, an attacker with
the public `original_root` can compute the exact value the redacted `leaf_i` must
take. A plain `leaf_i = Poseidon(content)` would then be **brute-forceable** for
low-entropy redacted content (e.g. an SSN on white background). Therefore the
leaf binds a **random blinding**: `leaf_i = Poseidon(C_i.x, C_i.y)` with
`C_i = m_i·G + b_i·H` (Pedersen, perfectly hiding). With `b_i` withheld, the
redacted leaf is uniform and reveals nothing about its content — the same
property ADR-0023 relied on, preserved here. This is *why* we keep ADR-0023's
Pedersen `commit_tile` rather than switching to a bare salted hash.

## Migration / circuit disposition

- **New:** `tile_redaction_validity` circuit + vkey + signed manifest;
  `src-tauri/src/zk/witness/tile_redaction.rs`; a Poseidon `tiles_root` variant;
  issuer endpoint `POST /redaction/tile/issue`; the `tile_redaction_validity`
  arm in `/zk/verify`; an IPC binding command + web-auditor JS; both offline
  verifiers + golden vectors; an admin/UI redaction flow.
- **Retired (same epoch):** the chunk path — `redaction_validity.circom`,
  `chunk.rs`, `/redaction/issue`, `/redaction/link`, `redactionBinding.ts`, and
  the old golden vectors. Existing chunk-based records keep their ledger leaves
  (existence proofs unaffected); only the redaction *issue/verify* surface
  changes. No data migration is required because redaction artifacts are not
  ledger state — they are issued on demand.
- **Ceremony:** a vkey/manifest change ⇒ regenerate the manifest in the same
  commit (`build.rs` compile-time check). Pre-setup, `build.rs` ships a
  PLACEHOLDER stub for the new circuit like the others.
- ADR-0023 status is updated to "verification scheme superseded by ADR-0024;
  importers + Pedersen tile commitment retained."

## Consequences

- ✅ Provable PDF/Office redaction (via rasterization) that composes with the
  ledger-existence proof in one verifier flow.
- ✅ Redacted content hidden by Pedersen + ZK; mask not required in the clear to
  verify.
- ⚠️ Image-only artifacts (no selectable text) — inherent to rasterization.
- ⚠️ Heavier than the (broken) chunk path: ≈ 1.35M-constraint prove (~15–30 s,
  ~3–5 GB), larger witness build.
- ⚠️ The shared ptau is power 22; the smaller circuits don't need it but reuse
  the one Phase-1 file.
- ⚠️ Fixed `N = 1024` granularity. Going finer is a ceremony-class event: with
  the optimized hash, N=2048 needs a power-23 ptau (bigger Phase-1 download +
  new checksum).

### Non-goals

This proves the **cryptographic consistency** of an issued redaction artifact
against a ledger-committed original — nothing more. Specifically, it does **not**
decide *what* should be redacted (redaction policy is the operator's, not the
protocol's), does **not** guarantee that the committed document is complete or
that any particular content was preserved, and does **not** assume institutional
honesty or act as a policy/authority over the issuer. A valid proof means "this
visible artifact is a faithful partial disclosure of *that* committed root for
*this* recipient" — it makes no claim about whether the right things were hidden
or whether the original record was itself truthful or complete.
