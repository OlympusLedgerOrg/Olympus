# Sigstore trusted root — vendored trust anchor

`trusted_root.json` is Sigstore's published trust bundle. Olympus uses it to
resolve the **Rekor transparency-log public key** that
`anchoring::rekor::verify_set` checks a signed entry timestamp against, so the
key's provenance is a reviewed artifact in this repository rather than a PEM
transcribed into an environment variable by hand.

Same posture as `proofs/vendor/circomlib` and `crates/light-poseidon`: pin the
upstream artifact, record how it was obtained, and have CI report when the pin
drifts.

That report is **non-blocking**. The `sigstore trust root provenance check` job
runs `continue-on-error: true`, so drift shows up as a visible failed step and an
annotation but does not stop a merge. That is deliberate — Sigstore can rotate
without anyone touching this repository, and a blocking check would fail whatever
PR happened to be open at that moment rather than the change that caused it.
The consequence to be aware of: **nothing forces this pin to be updated**, so
treat a red run as work to schedule, not as noise to ignore.

## Pin

| | |
|---|---|
| file | `trusted_root.json` |
| size | 6787 bytes |
| sha256 | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |
| mediaType | `application/vnd.dev.sigstore.trustedroot+json;version=0.1` |
| retrieved | 2026-07-31 |

## How this pin was obtained

Not "downloaded from GitHub". The bytes are the TUF **target** distributed by
Sigstore's root-signing repository, and the digest was corroborated three ways
before vendoring:

1. **TUF metadata chain.** `timestamp.json` → `165.snapshot.json` →
   `14.targets.json`, whose `targets["trusted_root.json"]` entry declares
   `length: 6787` and
   `sha256: 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
2. **Consistent-snapshot target fetch.** The hashed target
   `https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.trusted_root.json`
   hashes to that same digest — the file in this directory is those bytes.
3. **Independent mirror.**
   `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`
   is byte-identical.

`scripts/check_sigstore_trusted_root.sh` re-runs steps 1 and 2 and is wired into
CI, so upstream publishing a new trusted root turns the check red instead of
letting the pin rot silently.

**What is deliberately NOT done:** TUF signature verification at runtime. Olympus
ships no TUF client. See "Why vendored" below — the trade is intentional, and it
means a human must verify the TUF signatures out-of-band when taking a new pin
(step "Rotating the pin" below).

## What it contains

Two transparency logs, which do **not** share a log-id derivation:

| baseUrl | algorithm | `logId` derivation | validFor.start |
|---|---|---|---|
| `https://rekor.sigstore.dev` | `PKIX_ECDSA_P256_SHA_256` | `sha256(DER SubjectPublicKeyInfo)` | 2021-01-12T11:53:27Z |
| `https://log2025-1.rekor.sigstore.dev` | `PKIX_ED25519` | C2SP signed-note (Rekor v2 tile-backed) | 2025-09-23T00:00:00Z |

That difference is load-bearing and was found by a test, not by reading: the
resolver selects on a recomputed `sha256(SubjectPublicKeyInfo)`, so only the
first log is selectable. Asserting the sha256 relation for *both* fails against
this genuine bundle.

Plus certificate authorities, CT logs, and timestamp authorities, which Olympus
does not consume today — Fulcio/CT are not part of this anchoring path.

An entry from the 2025 log therefore fails closed twice over. Digest-based
selection cannot match it, so the resolver recognises it by its *declared*
`logId` and reports it as declared-but-unselectable — naming the signed-note
derivation alongside the unsupported algorithm — instead of claiming a log this
bundle plainly contains is absent from it. It never yields a key, and
`verify_set` is P-256 only regardless. Supporting that log is a code change (a
signed-note log-id derivation plus an Ed25519 verifier), not a re-vendor.

## Why vendored rather than a runtime TUF client

* **Reproducibility is the product.** These receipts are court evidence. A
  verifier re-checking a 2026 receipt in 2031 must reach the same verdict; a
  runtime fetch of a mutable trust root cannot promise that, and a TUF root that
  has since expired or rotated actively breaks it.
* **Offline by construction.** The desktop app already refuses to depend on the
  network for verification. Embedding the anchor keeps that true.
* **Reviewability.** Rotation becomes a commit with a diff and a digest, which is
  the same discipline applied to ceremony manifests and the other vendored trees.
* **Supply chain.** A TUF client (`tough`, `sigstore-rs`) is a large dependency
  tree through a `deny.toml` with `unknown-registry = "deny"` and a license
  allowlist, in exchange for automating a rotation that happens rarely and
  deserves human review anyway.

The cost is honest and worth stating: **no automatic rotation**. If Sigstore
rotates the Rekor key, receipts from the new log fail to verify until this pin is
updated. The drift check is what makes that loud rather than silent.

## Rotating the pin

1. Re-run `bash scripts/check_sigstore_trusted_root.sh`. It prints the upstream
   digest when it disagrees with the vendored copy.
2. Verify the TUF signatures out-of-band — e.g. `cosign`/`sigstore-python`
   against the new `root.json` — before trusting new bytes. The drift check
   confirms the digest matches what upstream *publishes*; it does not verify who
   signed it.
3. Replace `trusted_root.json`, update the table above (size, digest, retrieved
   date, and the metadata versions under "How this pin was obtained").
4. Confirm `anchoring::sigstore_root` tests still pass — they assert the
   public-good Rekor key resolves and that its `logId` equals
   `sha256(rawBytes)`, which catches a malformed or truncated replacement.
5. Note in the commit whether any previously-resolvable key disappeared:
   receipts already stored against it will stop verifying.

## Upstream

* Trust root: <https://github.com/sigstore/root-signing>
* TUF repository: <https://tuf-repo-cdn.sigstore.dev>
* Bundle format: <https://github.com/sigstore/protobuf-specs> (`TrustedRoot`)
