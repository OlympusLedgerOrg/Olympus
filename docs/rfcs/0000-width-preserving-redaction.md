# RFC-0000: Width-preserving redaction for `pdf-textrun`

| Field      | Value                                                        |
|------------|--------------------------------------------------------------|
| Status     | **Draft**                                                    |
| Author(s)  | OlympusLedgerOrg                                             |
| Date       | 2026-08-02                                                   |
| Tracking   | ADR-0029 Phase B; follows RFC-0001 `textrun-container-commitment` |
| Supersedes | Amends ADR-0029 Phase B (does not supersede it)              |

## Summary

Redacting a word in a `pdf-textrun` document replaces its bytes with a
fixed-width destruction token. The token's glyphs do not have the original word's
advance, so **every following word on the line shifts**. The redacted page no
longer looks like the page that was committed — in a court-evidence artifact,
that is a real defect, not a cosmetic one.

The known fix is a *width-preserving `TJ` move*: follow the token with a numeric
adjustment that buys back exactly the advance the token lost. A throwaway
prototype measured **0.0 glyph units of reflow** doing this with real font
`/Widths` (`docs/plans/visual-box-redaction.md` §6a).

**This RFC exists because that move cannot be made at redaction time.** The plan
doc and the `pdf_textrun` module header both said the remaining blocker was font
`/Widths`. That understated it. RFC-0001's skeleton leaf commits the canonical
content-object body with **only** the word spans and the `/Length` value elided —
every other byte verbatim. An adjustment inserted during redaction lands inside a
committed skeleton run, so the skeleton leaf stops reproducing and the bundle
fails to verify. Font metrics are the easy half; the commitment format is the
blocker.

This RFC proposes committing an **adjustment slot** per word at ingest, placed
inside that word's segment span. A **revealed** word's slot is then bound by that
word's leaf — changing it breaks verification. A **redacted** word's slot is
*not* cryptographically bound; it is left free (within a sanity cap) because that
freedom is the feature. So the only thing a redactor may choose is the advance
consumed by a word they have already destroyed.

## Motivation

Two properties are in tension.

1. **Layout fidelity.** A redacted page should be the original page with regions
   blacked out. Reflowed text invites the obvious question — "what else did they
   change?" — which is precisely the question the ledger exists to foreclose.
2. **Byte commitment.** Every byte of the artifact is covered by exactly one leaf
   (RFC-0001's partition). Nothing in a content stream is unconstrained.

Today Olympus buys (2) at the cost of (1). Preserving width naively would buy (1)
at the cost of (2) — and quietly, which is worse than either.

### The blocker, asserted rather than argued

`src-tauri/src/zk/segment/pdf_textrun.rs::a_width_compensating_kern_breaks_the_skeleton_leaf`
is the executable form of the paragraph above. It:

- computes the skeleton exactly as `ContentObj::skeleton` does;
- shows the **shipped** fixed-token redaction still reproduces it (`secret` →
  `REDACTED` changes the body length and the `/Length` value, and both are
  elided, so the skeleton is untouched);
- inserts the ` -1234` adjustment a `/Widths`-driven implementation would emit
  into the same `TJ` array, confirms the tokenizer still sees the same two words,
  and asserts the skeleton **no longer reproduces**.

The control leg matters: without it the failure could be read as "redaction
breaks the skeleton" rather than "the adjustment does".

## Design

### 1. Canonical show-string form (ingest)

`reemit_content_object` already produces a canonical body. Extend the
canonicalization of the *content* it wraps: every text-show operation becomes a
single `TJ` array in which

- each **word** is its own string element holding exactly that word's bytes,
- each word element is immediately followed by a **numeric adjustment slot**,
  written `0` at ingest,
- inter-word bytes (the whitespace inside the original literal operand) become
  their own string elements with **no** slot.

```
(POSITIVE CHILDHOOD) Tj
  ⇒  [ (POSITIVE) 0 ( ) (CHILDHOOD) 0 ] TJ
```

`Tj`, `'` and `"` all rewrite exactly: `'` is `T*` then the array; `aw ac "` is
`aw Tw ac Tc T*` then the array. Splitting one string into adjacent `TJ` elements
with zero adjustments is **rendering-identical** — `TJ` concatenates element
advances, and the split does not change which bytes are `0x20`, so `Tw` still
applies where it did. Hex operands stay hex, one element, one slot.

That equivalence holds for **single-byte encodings**. For a Type0/CID font a
character code can be two bytes, and the existing tokenizer splits words on raw
`0x20` bytes without consulting the font's encoding — so it can already split
mid-character. Today that mis-tokenization is contained: the word bytes are never
moved, so the re-emitted stream stays byte-valid even when the word boundaries are
nonsense. Splitting each word into its own literal element removes that
containment, turning a bad boundary into a malformed string. See open question 4.

This is a larger canonical re-emit than today's, but not a new *kind* of thing:
the skeleton is already committed over the canonical body rather than the
original, precisely so ingest commits the shape the artifact will have.

### 2. The slot is part of its word's segment

The load-bearing choice. A word's committed preimage and its artifact span both
extend from the word's own bytes to **include its trailing slot**. Note the
asymmetry precisely: *segment membership* is uniform, *cryptographic binding* is
not.

| word is… | leaf comes from | so the slot is… |
|---|---|---|
| revealed | recomputed over the artifact span | **leaf-bound** — a changed slot breaks the word's leaf |
| redacted | the manifest's `leaf_hex` | **not bound** — free within the §4 cap; the redactor picks it |

No verifier needs to *infer* which case it is in. The V3 bundle already carries a
per-segment `redacted` flag, and that flag is folded into the signed geometry
digest (`verifiers/rust/src/redaction.rs`, `redacted seg carries blinding` /
`revealed seg carries leaf_hex`), so the split is authoritative and signed rather
than guessed from the span's contents. The slot simply rides along on machinery
that already exists.

The skeleton changes only in that each word's elision widens to cover its slot —
the run structure and the length-prefixed encoding are untouched.

### 3. Advance computation (producer only)

The slot value is `n` such that the displacement `-n/1000 × Tfs × Th` restores the
lost advance, where `Tfs` is the `Tf` size and `Th` the `Tz` horizontal scale.
Computing the two advances needs `/Widths` + `/FirstChar` + `/MissingWidth` for
simple fonts, `/W` + `/DW` for Type0/CID, plus the active `Tc` and `Tw`.

This lives entirely in the producer. **Verifiers never compute an advance** —
they check the slot's bytes against a leaf (revealed) or a magnitude bound
(redacted). That asymmetry is deliberate: porting font-metric interpretation
byte-exactly into two more languages is the kind of cost that sank the
alternative in §5(a).

### 4. What a verifier checks

Unchanged in shape from RFC-0001, plus:

- a redacted word's span must hold the destruction token followed by a
  well-formed PDF number whose raw magnitude is within a fixed cap;
- a revealed word's span must recompute its leaf, which now covers the slot.

**That is the whole check.** A verifier computes no font metrics, tracks no text
state, and resolves no page geometry, so it cannot and does not certify that a
redacted word's slot *actually* restores the original advance. **Width
preservation is an honest-producer property, not a verified one.** The raw cap is
a sanity bound — it keeps a slot from being absurd; because the on-page
displacement is the slot scaled by `Tfs × Th`, which the verifier never reads, a
capped slot can still shift later text noticeably. What the verifier *does*
guarantee is unchanged by this RFC: every revealed byte, including every revealed
slot, recomputes its committed leaf.

## Threat model — what this gives up

Be plain about it: **this adds an uncommitted quantity where there was none.**
After this change, exactly one thing in a `pdf-textrun` artifact is chooseable
without breaking the commitment: the horizontal advance consumed by each
*redacted* word.

Why that is acceptable:

- the word it displaces is already destroyed — the channel cannot reveal hidden
  content, only move visible content;
- it is scoped to redacted words. Revealed text stays byte-committed, including
  its slot, so no revealed byte can be moved or altered undetected;
- the alternative that avoids it (§5(a)) leaves *every* slot uncommitted, which
  is strictly worse.

What it costs, stated without hedging: a producer who redacts a word may shift
the visible position of *later* text on that line, within the cap, and no
verifier will object. That is a **layout**-integrity loss confined to lines that
were redacted; it is not a content-integrity loss, because the bytes of every
revealed word — and their order — remain committed.

This is a threat-model change, which is why it is an RFC and not a PR
(`docs/rfcs/README.md`). It extends the redaction trust boundary recorded in
[`docs/threat-model.md`](../threat-model.md) §T4 (Over-Redaction or Secret Redaction) and ADR-0029 Phase B: the producer
is already trusted to choose *what* to hide; this additionally trusts it with
*where the hidden word's space goes*. Acceptance of this RFC should carry a
matching amendment to `docs/threat-model.md`.

## 5. Alternatives considered

**(a) Insert the adjustment at redaction time; elide all slots from the
skeleton.** The obvious shape, and the one the plan doc implied. Rejected: eliding
every slot leaves an uncommitted visual channel on *all* text, revealed included,
so a producer could shift any line without breaking a leaf. Constraining it back
would require the verifiers to recompute advances — §3's cost, in two more
languages.

**(b) Choose a same-advance destruction token per font.** No fixed byte string has
the right advance for an arbitrary word, and a font-dependent token destroys the
"the span holds exactly this token" check both verifiers rely on.

**(c) Black-box fill instead of a token.** Re-emitting a `re f` fill has the same
problem as (a) — it inserts operators into committed skeleton runs — and would
need the same slot mechanism to be legal.

**(d) Accept the reflow.** The status quo. Honest, documented, and visibly wrong
output. It is a legitimate disposition if the cost below is judged too high.

## 6. Migration

RFC-0001 declared the `pdf-textrun` migration window **closed**: any further
change to the leaf set, tokenizer, or skeleton encoding is a versioned migration.
This is such a change — the canonical body and the word preimage both move, so
roots differ.

It therefore needs a **new format tag** (`pdf-textrun2`, `SegmentFormat::PdfTextRunV2`),
with `pdf-textrun` retained for already-sealed records exactly as the 16-chunk
scheme is. Documents wanting width-preserving redaction re-ingest under the new
tag, via the existing manifest-geometry re-ingest path.

Real-world exposure is small — `pdf-textrun` became reachable in shipped builds
in #1548 — but the rule does not bend for that, and the record should not imply
it did.

## 7. Cost

| piece | size |
|---|---|
| canonical `TJ` splitting + exact-equivalence tests | M |
| font metrics (`/Widths`, `/W`, `Tc`/`Tw`/`Tz`/`Tf` tracking) | L |
| slot-widened spans + skeleton elisions | S |
| both offline verifiers + cross-language vectors (ADR-0005: one commit) | M |
| new format tag + re-ingest affordance | S |

## 8. Open questions

1. **Magnitude cap.** What bound on a redacted word's slot? A cap in text-space
   units is meaningful but needs `Tfs`; a raw cap on `|n|` is checkable with no
   font state at all. Proposal: raw cap, generous, documented as a sanity bound
   rather than a security boundary.
2. **Escaping across the split.** Today word bytes are never moved, so literal
   string escaping is inherited unchanged. Splitting words into their own elements
   means re-emitting each word as a standalone literal — `(`, `)` and `\` inside a
   word must be re-escaped, and a `\`-newline line continuation spanning a word
   boundary needs a decision. This is the first correctness risk of the change and
   wants property tests against the tokenizer before anything else lands.
3. **Is the trade worth it at all?** §5(d) is a real option. This RFC argues yes,
   but the reflow is cosmetic and the cost in §7 is not small.
4. **CID/Type0 word boundaries.** §1 notes that per-word elements remove the
   containment that currently makes a mid-character split harmless. Either the
   tokenizer becomes encoding-aware for Type0 fonts (expensive, and it would have
   to be ported byte-exactly into both verifiers), or `pdf-textrun2` refuses
   documents whose content streams select a Type0 font and falls back to the
   object scheme — which is honest and cheap, and is the proposal here.
