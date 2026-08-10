# Landing page

`index.html` is the public landing page for Olympus — a single self-contained
file aimed at the readers who will never scroll a README: journalists, lawyers,
and outside evaluators trying to work out in thirty seconds what Olympus claims
and whether it is worth their afternoon.

It has no build step, no dependencies, and no network requests. Every style is
inlined and the only image is a data-URI favicon, so it renders identically from
a file path, a static host, or GitHub Pages. Open it directly to preview:

```bash
# any of these
xdg-open site/index.html      # Linux
open site/index.html          # macOS
start site\index.html         # Windows
```

## What it claims, and where each claim comes from

The page is deliberately narrower than the README. It makes four claims, and
each one is stated at the strength the code actually supports:

| Page says | Backed by |
|---|---|
| Existed at a specific time | External anchoring — RFC 3161, Sigstore Rekor, OpenTimestamps (`src-tauri/src/anchoring/`, [`docs/court-evidence.md`](../docs/court-evidence.md)). The page says "where configured", because anchoring is opt-in per operator |
| Has not been edited | The insert-only ledger invariant (ADR-0031 §2) and the write-once guard in `src-tauri/src/smt/tree.rs` |
| Redactions were honest | The V3 signed Merkle fold over per-segment hiding leaves (ADR-0030), described in plain language as "committed as many small units". The page does **not** call this a zero-knowledge proof, because since ADR-0030 it is an Ed25519 signature over a Poseidon root, not a SNARK |
| Someone else can check it | The offline verifiers in [`verifiers/`](../verifiers) and the Python client SDK in [`clients/python/`](../clients/python) |

The "What Olympus does not promise" section mirrors
[`docs/threat-model.md`](../docs/threat-model.md), and the status band mirrors
[`ROADMAP.md`](../ROADMAP.md) — including that the trusted-setup ceremony has
not happened yet. **If any of those change, this page changes with them.** A
landing page that outlives its own accuracy is worse than no landing page.

The sample document in the hero is fictional and labelled as an illustration on
its face. It must stay that way: never replace it with a real record, or with
anything that could be mistaken for one.

## Publishing

The page is not deployed by CI. To serve it from GitHub Pages, either:

- **Pages workflow** — add a workflow that uploads `site/` as the Pages
  artifact. Note that Pages deployment needs `pages: write` and
  `id-token: write`, which makes the workflow privileged under
  `scripts/check-privileged-action-pins.mjs`: every `uses:` in it must be
  pinned to a full commit SHA with a version comment.
- **Branch folder** — GitHub Pages can serve from a branch's root or `/docs`
  only, so this route needs `index.html` copied to whichever of those the
  repository settings point at.

Either way, enabling Pages is a repository-settings change and is left to a
maintainer.
