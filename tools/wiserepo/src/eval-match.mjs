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
 * @param {string} answer
 * @param {string[]} expect
 * @returns {string[]} the expectations that are genuinely absent
 */
export function missingExpectations(answer, expect) {
  const haystack = normaliseForExpect(answer);
  return (expect ?? []).filter((needle) => !haystack.includes(normaliseForExpect(needle)));
}
