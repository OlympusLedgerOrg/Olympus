# Landing page

[`index.html`](index.html) is the public landing page for Olympus — a single
self-contained file aimed at the readers who will never scroll a README:
journalists, lawyers, and outside evaluators trying to work out in thirty
seconds what Olympus claims and whether it is worth their afternoon.

It is served at <https://olympusledgerorg.github.io/Olympus/>. See
[Publishing](#publishing) below for how that is wired.

It has no build step, no dependencies, and no network requests. Every style is
inlined and the only image is a data-URI favicon, so it renders identically from
a file path, a static host, or GitHub Pages. Open it directly to preview:

```bash
# any of these
xdg-open docs/index.html      # Linux
open docs/index.html          # macOS
start docs\index.html         # Windows
```

## What it claims, and where each claim comes from

The page is deliberately narrower than the README. It makes four claims, and
each one is stated at the strength the code actually supports:

| Page says | Backed by |
|---|---|
| Existed at a specific time | External anchoring — RFC 3161, Sigstore Rekor, OpenTimestamps (`src-tauri/src/anchoring/`, [`docs/court-evidence.md`](court-evidence.md)). The page says "where configured", because anchoring is opt-in per operator |
| Has not been edited | The insert-only ledger invariant (ADR-0031 §2) and the write-once guard in `src-tauri/src/smt/tree.rs` |
| Redactions were honest | The V3 signed Merkle fold over per-segment hiding leaves (ADR-0030), described in plain language as "committed as many small units". The page does **not** call this a zero-knowledge proof, because since ADR-0030 it is an Ed25519 signature over a Poseidon root, not a SNARK |
| Someone else can check it | The two offline verifiers in [`verifiers/`](../verifiers) — Rust and JavaScript. The page says the Rust one covers the whole chain and the JavaScript one stops short of the Groth16 step, because [`docs/court-evidence.md`](court-evidence.md) §3 is explicit that `verify.js` *prints* the cargo invocation for that step without running it. The Python package in [`clients/python/`](../clients/python) is a verify-only client SDK that independently re-implements the leaf hash and SMT verifiers; it is not a full court-grade verifier and the page does not present it as one |

Note what is *not* in that list. The page never says a document is "real",
"authentic", or "what you said it was", and the headline says **unaltered**
rather than real for exactly this reason. Olympus proves what happened to a
record after it was committed; it proves nothing about whether the contents are
true or who produced them. `DEVPOST_SUBMISSION.md` states the same boundary —
"not truth, authorship, or changes never committed to a checkpoint" — and
[`docs/threat-model.md`](threat-model.md) lists the malicious submitter who
"submit[s] a forged or altered document and claim[s] it is the authentic
original" as an adversary Olympus does not defeat: they get a proof that their
forgery has not been edited since. The Limits section says so outright, and it
needs to stay there.

The "What Olympus does not promise" section mirrors
[`docs/threat-model.md`](threat-model.md), and the status band mirrors
[`ROADMAP.md`](ROADMAP.md) — including that the trusted-setup ceremony has
not happened yet. **If any of those change, this page changes with them.** A
landing page that outlives its own accuracy is worse than no landing page.

The sample document in the hero is fictional and labelled as an illustration on
its face. It must stay that way: never replace it with a real record, or with
anything that could be mistaken for one.

Its **redaction bars are all one fixed width, and that is load-bearing**. On the
paths this page depicts, the producer replaces a hidden unit with a constant
token — `[REDACTED]\n` for a text block
([`segment/text.rs`](../src-tauri/src/zk/segment/text.rs), commented
"length-independent → no size disclosure") and `REDACTED` for a literal PDF word
([`segment/pdf_textrun.rs`](../src-tauri/src/zk/segment/pdf_textrun.rs)) — so
the published artifact does not encode how long the withheld passage was, and
the surrounding text reflows instead of leaving a gap shaped like the original.
The first version of this page sized each bar to the string underneath it, which
drew a length side channel those paths do not have; for a withheld name, the
width alone narrows the candidate set. If you edit the hero, do not let a bar
take its width from its own content.

**There is one length-preserving exception**, and it is a format constraint
rather than a choice: a PDF *hex* string operand (`<48656c6c6f> Tj`) cannot be
masked with `REDACTED`, because that is not valid hex. `destruction_token` masks
it with a run of ASCII `0` of the same length instead — the content is
destroyed and both offline verifiers check the span holds exactly that, but the
token's length still reflects the hidden string's, and that word does not
reflow. Whether a given PDF is affected depends on how its producer encoded the
text, not on anything the person redacting chooses. The illustration is prose, so
the fixed-width bars are right for what it shows; do not generalise them into a
claim that *no* Olympus redaction can ever disclose a length.

## Publishing

GitHub Pages serves this repository from the **`main` branch, `/docs` folder**
(Settings → Pages → Source: "Deploy from a branch"). That is why the page lives
at `docs/index.html` rather than in a directory of its own: a branch-folder
source can only be a branch's root or `/docs`, and Pages serves that folder's
`index.html` as the site root.

No CI workflow deploys it. Pushing to `main` is the deploy — Pages picks the
folder up on its own, so a change to `docs/index.html` is live once it merges.

`docs/.nojekyll` turns off the Jekyll build, so every file under `docs/` is
served byte-for-byte as committed and there is no build step that can fail. The
landing page needs this least of all — it is plain HTML — but it removes any
question of what Pages might do to the rest of the directory.

Two consequences worth knowing:

- **Everything under `docs/` is published**, not just this page, at
  `https://olympusledgerorg.github.io/Olympus/<path>`. The repository is public,
  so this exposes nothing new; it does mean a file added to `docs/` is a web
  page, not only a repository file.
- **Markdown is served raw.** `.nojekyll` means no Markdown-to-HTML rendering,
  so `…/quickstart.md` returns the source text. Every link out of the landing
  page is an absolute `github.com/OlympusLedgerOrg/Olympus/…/main/…` URL —
  rendered by GitHub — for exactly this reason. Keep it that way.
