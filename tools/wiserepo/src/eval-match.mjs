// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Matching an answer against the tokens a golden question expects.
//
// Kept out of bin/eval.mjs so it can be tested without running a model. The
// rule is deliberately narrow: fold case and separator punctuation, nothing
// else. That is because a literal substring match scored a CORRECT answer as a
// failure once — the model wrote "SHA-256 …" against the expectation "sha256"
// and the run reported 5/6 on a set that was really 6/6. Folding
// `-`/`_`/whitespace fixes that class of false negative without letting a
// near-miss through: no stemming, no synonyms, no "most of the characters" fuzz.
export function normaliseForExpect(text) {
  return String(text ?? "")
    .toLowerCase()
    .replace(/[-_\s]+/g, "");
}

/**
 * Which expectations the answer never mentions, after normalisation.
 *
 * An expectation may also be an ARRAY of equivalent phrasings: the group passes
 * when the answer contains any one of them. A correct review of the planted bug
 * can say "extra page", "one page too many" or "one too many", and scoring a
 * single fixed phrase measured the model's vocabulary instead of whether it
 * found the bug.
 *
 * @param {string} answer
 * @param {(string | string[])[]} expect
 * @returns {string[]} the expectations that are genuinely absent
 */
export function missingExpectations(answer, expect) {
  const haystack = normaliseForExpect(answer);
  const missing = [];
  for (const entry of expect ?? []) {
    // The report keeps the caller's spelling (`authorize_write`, not
    // `authorizewrite`); only the comparison is normalised.
    const alternatives = Array.isArray(entry) ? entry : [entry];
    const needles = alternatives.map(normaliseForExpect).filter(Boolean);
    if (needles.length === 0 || !needles.some((needle) => haystack.includes(needle))) {
      missing.push(alternatives.join(" | "));
    }
  }
  return missing;
}

// Normalised fragments (case, spaces and hyphens are folded out) that frame the
// value as removed, replaced, restored, or in the past.
const ATTRIBUTION = [
  "remov",
  "delet",
  "drop",
  "replac",
  // Verb forms only: a review's "**Fix**: change `lastPage - 1` to …" heading is
  // a bug claim, not an attribution, so bare "fix" must not count as one.
  "fixes",
  "fixed",
  "fixing",
  // "restore"/"revert"/"reinstate" describe the diff too ("the diff reverts X to
  // Y"), but as an IMPERATIVE they propose undoing it — see RECOMMENDATION.
  "restore",
  "revert",
  "reinstate",
  "nolonger",
  "previous",
  "usedto",
  "insteadof",
  "changedfrom",
  "prior",
  "formerly",
  // Past-tense and revision framing. A real review of `HEAD~2..HEAD` read the
  // change correctly and then called the pre-diff code "the original code
  // returns `lastPage - 1`": the right reading in wording the list did not
  // know. "original", plain past tense and "was returning" all attribute the
  // value to the earlier revision; present tense ("the current implementation
  // returns …") stays a live claim and must keep scoring as a phantom.
  "original",
  "returned",
  "wasreturn",
  "→",
  "->",
];

// A unified-diff REMOVAL line is the attribution itself: `-  code` says the code
// is gone. Two spaces (or a tab) after the marker separate it from a Markdown
// bullet, which is a live claim and still scores. `+` is deliberately absent:
// `+` is code the diff ADDS, so a `+` line repeating the forbidden value is
// asserting it as the new behaviour, not describing its removal.
const DIFF_LINE = /^-\s{2,}|^-\t/;

// Present-tense markers that beat an attribution in the same sentence: "the diff
// removes a guard, so `clampPage` STILL returns `lastPage - 1`" is a phantom even
// though "removes" is right there.
const CURRENT_OVERRIDES = ["still", "keeps", "continues", "remains"];

// Negation immediately BEFORE the value describes what the code does NOT do:
// "should return the page count without adding an extra page", "never returns
// `lastPage - 1`". A real review of the removed `+ 1` phrased the correct post-
// diff behaviour that way, with no removal word anywhere in the sentence, and
// the case scored it as a live claim.
//
// Proximity, not a marker on the whole sentence: a blanket "without" would
// excuse "clampPage returns `lastPage - 1` without a guard", which is exactly
// the live claim this function exists to catch. The value is searched in the
// text AFTER the negation, so the negation has to precede it.
//
// Matched as WHOLE WORDS in the raw sentence. The haystack is normalised with
// spaces squeezed out, so a substring test for "not" also matches "Note:" —
// which would excuse the very claim this function exists to catch.
/**
 * Whether the sentence PROPOSES undoing the change rather than describing it.
 *
 * "**Recommendation:** Revert the change and add `+ 1` back" asserts the removed
 * value belongs in the new code, so its "revert" must not excuse the mention —
 * that is how a review recommending the restoration of a removed bug scored
 * PASS on the clean-fix case. A sentence that describes a revert ("the diff
 * reverts `clampPage` to `lastPage`") is attribution and stays one: the test is
 * the sentence's mood, which is why this looks at how it STARTS, not at whether
 * a revert word appears.
 */
function isRecommendation(sentence) {
  const stripped = String(sentence ?? "")
    .trimStart()
    // Headings, quotes and bullets, but not "*": bold labels come next.
    .replace(/^[#>\s-]+/, "")
    .replace(/^\*\*[^*]{1,40}\*\*\s*:?/, "")
    .replace(/^[A-Za-z][A-Za-z /-]{0,30}:\s*/, "")
    .replace(/^[:\s]+/, "")
    .trimStart();
  // Base/imperative forms only: "reverted" or "reverting" describes a past
  // action or its consequence, which is attribution.
  return /^(?:revert|restore|reinstate)\b/i.test(stripped);
}

const NEGATION_PATTERN = /\b(?:without|not|never)\b/g;
const NEGATION_WINDOW = 40;

// A negation governs its own clause. "The diff does not touch `clampPage`, so it
// returns `lastPage - 1`" negates the touching, not the return: proximity alone
// excused that live claim. The value has to appear after the negation AND before
// the next clause break.
const CLAUSE_BREAK = /[,;:.!?]|\b(?:so|but|then|therefore|which|while|whereas)\b/;

function negatedBefore(sentence, needle) {
  const raw = String(sentence ?? "").toLowerCase();
  for (const match of raw.matchAll(NEGATION_PATTERN)) {
    const from = match.index + match[0].length;
    const rest = raw.slice(from, from + NEGATION_WINDOW);
    const breakAt = rest.search(CLAUSE_BREAK);
    const clause = breakAt === -1 ? rest : rest.slice(0, breakAt);
    if (normaliseForExpect(clause).includes(needle)) return true;
  }
  return false;
}

function sentencesOf(text) {
  return String(text ?? "")
    .split(/(?<=[.!?])\s+|\n+/)
    .filter((sentence) => sentence.trim());
}

/**
 * Which forbidden strings the answer presents as still true.
 *
 * For a review of a diff the failure worth scoring is reading a deleted line as
 * current: no positive expectation catches it, because an answer can name every
 * real bug correctly and still invent a phantom beside it. A mention alone is
 * not that failure — the failure is an UNATTRIBUTED mention. A value negated just
 * before it ("without adding an extra page") is attributed too, unless the same
 * sentence also claims it is still the case. Judging per
 * sentence, not per occurrence, is deliberate: the score needs "does the review
 * describe this value as gone", and a per-occurrence window made a correct
 * "Restore the line `lastPage - 1`" recommendation read as a live claim.
 *
 * @param {string} answer
 * @param {string[]} absent
 * @returns {string[]} the forbidden strings stated as current
 */
export function unexpectedMentions(answer, absent) {
  const needles = (absent ?? []).map((needle) => [needle, normaliseForExpect(needle)]);
  const phantoms = new Set();
  for (const sentence of sentencesOf(answer)) {
    const haystack = normaliseForExpect(sentence);
    const attributed =
      DIFF_LINE.test(sentence.trimStart()) ||
      ATTRIBUTION.some((marker) => haystack.includes(marker));
    const override = CURRENT_OVERRIDES.some((marker) => haystack.includes(marker));
    const recommendation = isRecommendation(sentence);
    for (const [original, needle] of needles) {
      if (!needle || phantoms.has(original)) continue;
      // A present-tense override beats both: "it never removes the guard, so
      // `clampPage` still returns `lastPage - 1`" is a phantom. So does a
      // recommendation to undo the change, however many attribution words it
      // contains.
      if (
        haystack.includes(needle) &&
        (override || recommendation || (!attributed && !negatedBefore(sentence, needle)))
      ) {
        phantoms.add(original);
      }
    }
  }
  return (absent ?? []).filter((needle) => phantoms.has(needle));
}
