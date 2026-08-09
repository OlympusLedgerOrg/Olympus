# Feasibility: verifiable 1f916.ai archive with Olympus

**Decision:** **Go**, but as a small, standalone archive project that consumes
the Olympus dataset-manifest CLI at a pinned Olympus revision. Do not add an
1f916-specific ingest type, service, or workflow to this repository.

This is a design note only; it proposes no production-code change.

## Facts established on 2026-08-09

`https://1f916.ai/` is a `text/plain` front door, not the client-rendered
Observatory. Its documented read surface includes:

| Resource | Read endpoint | Archive use |
|---|---|---|
| Constitution / front-door policy | `GET /` | capture as raw text |
| Complete post discovery | `GET /api/changes?since=<ms>` | initial walk and incremental cursor |
| Full post and nested comments | `GET /api/post/{id}` | capture the exact response per discovered post |
| Moderation / identity events | `GET /api/events?kind=moderation` (page with `since`) | snapshot separately, including hashes |
| Treasury | `GET /treasury` | snapshot separately, including hashes |
| Site self-check | `GET /api/attest` | **highest-value packet — see §1.1**; record its reported heads and check result |
| Public metadata | `GET /api/official`, `/api/docket` | optional context packets |

The `/api/changes` response says to advance the cursor to `next_since`, not
wall-clock `now`, to drain pages while `has_more`, and to treat boundary rows as
**upserts by id**, because rows may repeat. The `/api/front` feed is explicitly
not a complete archive. `GET /api/treasury` returned 404 during this check;
`/treasury` is the live documented endpoint.

1f916 already hash-chains its events/identity and treasury ledgers and exposes
`/api/attest` to check those chains. Its own response correctly says that a
self-hosted chain cannot prove history against someone able to rewrite its
database. Normal post/comment payloads are not committed by those two chains;
even an event saying that a bulletin was posted is not a commitment to the
bulletin's complete bytes. Olympus would therefore add an independent custody
record for the forum content, rather than duplicate its ledger.

## 1. Ingest shape and commitment scheme

Use the existing **ADR-0027 dataset-manifest** layer, not `/ingest/files` per
post and not a new leaf type. A manifest root is already the normal
256-height Olympus SMT root and reuses the existing structured leaf domain,
shard binding, parser provenance, and offline proof verifier. A second,
variable-depth redaction tree would add a protocol surface without solving a
problem this archive has.

The important design choice is an **immutable capture packet**, not a mutable
`post/{id}.json` file. Store the literal response bytes from each request under
a collector-generated, non-content-derived name, for example:

```text
post/captures/000001/506.json
events/captures/000001/moderation.json
treasury/captures/000001/treasury.json
site/captures/000001/front-door.txt
site/captures/000001/attest.json
```

Subsequent captures use new sequence directories and never replace old files.
This preserves evidence of later edits, deletions, vote/comment changes, and
the API's volatile `now` fields. The top-level source kind is a manifest shard
(`post`, `events`, `treasury`, `site`); the relative path, including the capture
sequence, is the record identity. Keep collector-generated endpoint, timestamp,
and HTTP metadata in a separate sidecar packet, never by modifying the raw
response body.

Each capture produces a new manifest version over the cumulative packet set.
`ManifestDiff` plus the child `ParentRef` binds it to the preceding
`manifest_root`; this is the requested running root-of-roots. In the normal
case each diff only adds records. A proof can then establish that an exact
packet was present in capture version *N*, and the version links establish the
ordered archive history. The archive should retain manifests, record indexes,
and diffs, since the index is needed to produce later record-level proofs.

This avoids a subtle false claim: a post ID alone is not an immutable record
identity when its rendered thread state can change. It is an upstream locator;
the capture sequence identifies Olympus evidence.

The mutable alternative (`post/{id}.json`, overwritten each capture) is not
merely weaker — the existing tooling would certify it incorrectly. Verified in
source: `scan` assigns `version: 1` to every record and uses the full relative
path as `record_id` (`clients/cli/src/scan.rs`), and `compute_diff` flattens
both indexes to `(shard_id, record_id, version)` and tests **presence only**,
never comparing `content_hash` for a key present on both sides
(`crates/olympus-manifest/src/diff.rs`). An edited post therefore keeps its
tree key and changes its value, landing in neither `added` nor `removed`.
`verify_link` checks the `ParentRef` binding and the diff summary but not that
the change set explains the root delta, so the result is an **empty diff
between two differing manifest roots that verifies as `Valid`** — while the
prior bytes have been overwritten and are gone. Capture sequencing makes every
version strictly additive, so each diff fully explains its root delta and no
observed byte is ever destroyed.

Because nothing is ever replaced, the packet set grows monotonically and each
capture rebuilds the manifest over the **cumulative** set: the build is
`O(total records)`, not `O(new)`. At this scale that is a non-issue for years —
ADR-0027 benchmarks 1M records sealed in ~35 s single-threaded — but the growth
is worth stating rather than discovering. Post packets track real forum
activity (~500 initial, a few per day), so the dominant term is the *periodic*
site/treasury/events captures: hourly runs add roughly 9k packets a year on
their own. Taking §4's stated cost option and capturing those daily instead of
hourly removes most of that growth while leaving post capture at full cadence.

### 1.1 The `/api/attest` packet is the archive's sharpest artifact

`/api/attest` is listed in §0 as a site packet, but it carries more evidentiary
weight than any individual post, and the collector should treat it as a
first-class capture rather than incidental metadata.

1f916's own attest response states that its self-chain proves "Nothing, if you
only ever ask us. Whoever holds the database could rewrite history and recompute
these chains to match, and this endpoint would report a clean chain while
telling you the truth about a history that had changed." That is an accurate
description of an unfalsifiable claim: with only the live endpoint to consult,
no observer can distinguish an honest chain from a consistently rewritten one.

Capturing the heads 1f916 *claimed* at time T, and anchoring that capture
externally (§2), is precisely the witness it says it lacks. It converts the
claim from unfalsifiable to falsifiable: a later rewrite must either reproduce
the previously published heads or contradict a transparency-log record that
predates it and that neither party controls. The archive does not need to
adjudicate whether 1f916 is honest — it only needs to make dishonesty leave a
mark, which is the same property Olympus's anchoring provides for shard roots.
**The packet makes that claim independently testable against retained evidence;
it does not certify that the claim itself was true.**

This costs one extra file per run, since the endpoint is already being captured.
It is also the clearest statement of what the project is for: not "we archived
some posts," but "we made a self-attesting system externally checkable."

## 2. Anchoring

Internal manifests and Git history are worthwhile but insufficient as
independent timing evidence. They make an observed rewrite detectable only to
someone who retained an earlier copy; an archive owner can rewrite unpublished
or force-pushed history. That is the same trust boundary 1f916 documents for
its own self-chain.

For a useful public demo, add **keyless Sigstore/Cosign blob signing in the
scheduled GitHub Action** for each new manifest document, retaining the emitted
Sigstore bundle with the manifest. GitHub OIDC gives the workflow a short-lived
identity; Rekor records the signed artifact digest in a public transparency log.
This needs no operated Olympus node or long-lived signing key. Verification
must pin the expected workflow identity and GitHub OIDC issuer, and check the
bundle rather than merely displaying a log index. Sigstore documents both
`cosign sign-blob` and `cosign verify-blob` for this use case.

Arguments against anchoring are legitimate: it adds an external trust root,
workflow dependency, and operational failure mode to an experiment. If the
goal is only reproducible snapshots for internal research, omit it and label
the result "internally tamper-evident, not independently time-attested." For
the stated disappearance/retroactive-edit value proposition, however, Rekor is
cheap enough to justify. RFC 3161 is a reasonable later second witness; defer
OpenTimestamps/Bitcoin until the archive proves durable value.

## 3. Untrusted-content boundary

Treat every 1f916 response as adversarial bytes, including text that attempts
to instruct the collector. The permitted pipeline is:

```text
HTTPS fetch -> bounded raw-byte write -> Rust manifest hash -> optional signature/anchor
```

It must not render, execute, template, shell-interpolate, summarize, classify,
or send post content to an LLM. Numeric IDs and locally assigned capture
sequences are the only allowed filename inputs; titles, authors, and bodies
never form paths or commands. Set explicit HTTP size/time limits and reject
unexpected content types/oversized responses before writing. The existing
manifest builder is well suited here because it hashes opaque files; unlike the
PDF/OOXML ingest path, it does not parse the content for redaction. This is
compatible with Olympus's hostile-document posture and avoids widening it.

The collector must send a stable, identifying `User-Agent` with a repository
contact URL, use a bounded retry budget with jitter, and honor `429` plus
`Retry-After` before making another request. It is an indefinite guest of
someone else's public infrastructure, not a privileged replication client.

## 4. Ongoing capture

Use a scheduled GitHub Action in the standalone archive repository, initially
hourly or every few hours:

1. Read the committed cursor and drain `/api/changes`, following `next_since`.
2. Deduplicate only discovery rows by post ID within the run; for each newly
   discovered post, fetch `/api/post/{id}` once and preserve that raw response
   in a new capture directory.
3. Capture `/`, `/treasury`, `/api/events?kind=moderation`, and `/api/attest`
   on each non-empty run (or daily, if cost matters).
4. Build and diff a new cumulative manifest only when new packets exist;
   sign the manifest blob with keyless Cosign and retain its bundle.
5. Commit the immutable packets, manifest, index, diff, bundle, and advanced
   cursor together.

The initial snapshot is the same process with `since=0`, drained completely,
then one full-post fetch per discovered ID. Before operational use, run a small
read-only validation to determine whether `/api/changes` reports post edits or
comment-only changes. The live contract confirms new-post discovery and
boundary duplication; it does not by itself establish complete update semantics.
If complete later thread-state history is required, add a bounded periodic
re-fetch policy and record every resulting response as a new packet.

The collector should be a small Rust CLI or a reviewed declarative workflow;
no Python or Go is needed, and all hashing remains in the existing Rust CLI.
Failure is safe: do not advance the cursor until the packet set and associated
artifacts are durably committed. A rerun may refetch a boundary row but never
overwrites evidence.

## 5. Scope and compatibility

Keep this outside `OlympusLedgerOrg/Olympus`. It is an excellent demonstration
of ADR-0027, but 1f916's volatile third-party API should not become part of the
desktop ledger's audit, availability, or release surface. Pin
`clients/cli` to an Olympus commit or release tag: it is an intentionally
standalone crate, but it currently uses workspace-relative path dependencies
and is not a registry-published, independently versioned package. That is
manageable coupling, not a reason to alter the core protocol.

No Olympus invariant is changed: no new leaf layout/domain, no non-transactional
SMT writer, no new shard in the production ledger, no frontend crypto, and no
LLM processing. If a future operator commits manifest blobs to a live Olympus
node, it must use an existing authorized shard and respect the normal
operator-controlled shard and insert-only rules; that is optional and not
needed for this design.

## 6. Commitment vs. payload retention

The immutable-packet design (§1) preserves evidence of upstream edits and
deletions, and §0 captures the moderation log — so the archive will, by
construction, hold content that 1f916 itself later removed. Left unstated, that
reads as a policy of permanently republishing whatever the upstream service once
exposed. The cryptographic design does not require that policy, and this section
states the weaker one it actually needs.

### Two independently governed layers

| Layer | Contents | Governance |
|---|---|---|
| **Commitment** | manifests, record indexes, diffs, proof bundles, external anchors | append-only; never rewritten or withdrawn |
| **Payload** | the captured response bytes | may be withheld or delisted per record |

These are separable because proof verification never reads the payload. A
`RecordProofBundle` carries the committed content hash and the authenticated
tree path; verification re-derives the tree key from
`(shard_id, record_id, version)` and folds that path to `manifest_root`
(`crates/olympus-manifest/src/proof.rs`). Proving reads the sealed manifest,
which is built from the record index — hashes, not bytes. Withholding a payload
therefore invalidates no proof, breaks no version link, and changes no root.

### What survives payload withholding

A proof over a withheld record still establishes that a document with a specific
hash occupied a specific capture path in a specific manifest version, anchored at
a specific time. What is lost is a *new* reader's ability to reconstruct the
content — not anyone's ability to establish what existed. A party who
independently retained the bytes can still verify them against the published
commitment.

**Withholding a payload does not imply that its commitment is invalid, disputed,
or withdrawn.** The commitment stands exactly as it did before; only
redistribution stops.

### Three propositions the archive must keep distinct

1. **Captured** — the collector received these bytes from this endpoint at this
   time. Established by the archive directly.
2. **Committed** — that byte string's hash was incorporated into a named
   manifest version and externally anchored. Established by the archive
   directly.
3. **Truthful** — the bytes accurately describe reality, or even accurately
   represent what the upstream system would say about itself. **Outside the
   archive's authority entirely.**

The archive can prove (1) and (2). It cannot prove (3), and must not present
proofs of (1) and (2) in language that implies it. This distinction belongs in
the archive's own README and in any verification output, not only in a design
note — a reader is far likelier to encounter the archive as an evidentiary
artifact than as a protocol document. In particular: a captured `/api/attest`
packet (§1.1) proves what 1f916 *claimed* at time T, never that the claim was
correct.

### Trigger, authority, and record

Deliberately narrow, and stated as discretion rather than obligation:

- The archive **may** withhold or delist payload bytes. It does not commit to
  honoring every request, and this section is not a promise to do so.
- Withholding is a maintainer decision. Plausible triggers include an upstream
  moderation removal, a credible legal demand, or content whose continued
  republication is indefensible on its own terms — but the enumeration is not a
  guarantee and each is judged individually.
- Every withheld payload is recorded in a public register in the archive repo:
  the record path, the capture version, the date, and a reason category. A
  withheld payload is **visibly** withheld, never silently absent — an archive
  that could quietly drop records would forfeit the property it exists to
  provide.

This is a governance boundary, not a protocol. It intentionally defines no
mechanism, no cryptographic construction, and no automated enforcement.

## Estimate

| Work | Estimate |
|---|---:|
| Read-only collector, bounded fetches, immutable packet layout | 1 day |
| Manifest/diff integration and recovery/idempotency tests | 0.5–1 day |
| Keyless Cosign/Rekor workflow plus independent verification test | 0.5 day |
| Initial capture, documentation, and API-semantics validation | 0.5 day |
| **Total v1** | **2–3 days** |

The only go/no-go caveat is operational intent: proceed if the archive will
publish its verification materials and hold to the captured/committed/truthful
boundary in §6. Do not proceed as a casual scraper that claims independent
timestamps while retaining only its own Git history.
