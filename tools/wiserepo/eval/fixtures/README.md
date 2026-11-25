# Eval fixtures

`bin/eval.mjs` builds one throwaway git repo from these files per run, commits
`pager.before.js` as `src/pager.js`, then commits `pager.after.js` as a second
commit — so the scored diff is `git diff HEAD~1 HEAD`, a real two-revision diff
of the kind `review_diff` is used on. `review` and `summarize` both run inside
that single repo, so both suites score the same checkout.

Both states are committed on purpose. The two files are the same byte length,
so an *uncommitted* overwrite can land inside git's racy-clean window: `git
diff HEAD` reports a clean tree, the eval scores an empty diff, and the result
reads as a model miss instead of a broken fixture. Committed blobs are compared
by content. `bin/eval.mjs` also refuses to run if the fixture diff is empty.

The two files share an identical header on purpose: any comment difference would
show up in the diff and give the model something to review that isn't the
planted defect.

`pageLabel` and `DEFAULT_PAGE` sit between the two changed functions for the
same reason, inverted: they are identical in both states, and they push the
changes more than 6 lines apart so `git diff -U3` emits **two** hunks instead of
merging them into one. With a single hunk, "does the review cover each changed
function" is not measurable — the model sees one region and gives it one finding.
`test/eval.test.mjs` asserts the separation still holds, because an edit that
closes the gap would silently collapse the diff back to one hunk.

## What the diff is designed to test

| change | intent |
| --- | --- |
| `pageCount` gains `+ 1` | **the planted bug.** Every call reports one page more than the document has. `eval/golden-review.json` requires the answer to name `pageCount` and `extra page`. |
| `clampPage` returns `lastPage` instead of `lastPage - 1` | **a fix**, and the red herring. The diff *removes* the off-by-one; a review that reads deleted lines as still present reports it as a live bug, spends its attention there, and misses the planted one. The golden case requires `clampPage` and `lastPage`, so a review that silently ignores this hunk fails instead of passing on `expect_absent` alone. |

That second row is why this fixture exists: a smoke review in this repo once
reported a removed line as still present. Scoring only "did it find the bug"
would still pass a model that also invents issues, so the golden case is written
so the phantom competes with the real finding.

The phantom case scores *attribution*, not mention: "the diff removes
`lastPage - 1`" is the reading this fixture is meant to reward and passes, while
"`clampPage` returns `lastPage - 1`" fails. It also has a positive `expect`
list, because `expect_absent` alone is satisfied by a review that never mentions
`clampPage` at all — and that list is matched against the answer's prose, so a
pasted diff does not satisfy it. See `src/eval-match.mjs`: attribution is judged
per sentence (removed/replaced/restored/previously returned all count), a
unified-diff `-` line counts as removal, and a present-tense marker such as
"still" overrides attribution in the same sentence.

`test/eval.test.mjs` asserts both properties still hold: the `+ 1` is present in
the after file and absent from the before file, and `lastPage - 1` is present
only in the before file. Editing these fixtures to "fix" the bug would otherwise
quietly turn the review case into a test of an empty diff.

## Changing them

If a prompt or model change alters what a correct review must say, update
`eval/golden-review.json`'s `expect` list and re-record the baseline:

```bash
node bin/eval.mjs --write-baseline
```

Keep the diff small. A fixture that needs more than one screen is measuring
patience, not diff comprehension.
