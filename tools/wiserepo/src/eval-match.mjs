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
  // "Restore the removed line" is still describing a change, not citing one.
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
  "→",
  "->",
];

// Present-tense markers that beat an attribution in the same sentence: "the diff
// removes a guard, so `clampPage` STILL returns `lastPage - 1`" is a phantom even
// though "removes" is right there.
const CURRENT_OVERRIDES = ["still", "keeps", "continues", "remains"];

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
 * not that failure — the failure is an UNATTRIBUTED mention. Judging per
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
    const attributed = ATTRIBUTION.some((marker) => haystack.includes(marker));
    const override = CURRENT_OVERRIDES.some((marker) => haystack.includes(marker));
    for (const [original, needle] of needles) {
      if (!needle || phantoms.has(original)) continue;
      if (haystack.includes(needle) && (override || !attributed)) phantoms.add(original);
    }
  }
  return (absent ?? []).filter((needle) => phantoms.has(needle));
}
