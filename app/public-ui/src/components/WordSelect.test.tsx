// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { MAX_VISIBLE_WORDS, WordSelect } from "./WordSelect";
import type { RedactionSegmentDescription } from "../lib/api";

const PURPLE = "rgba(168,85,247,";
const ACCENT = "#c084fc";

function word(
  segmentId: number,
  text: string | null,
  page: number | null = 1,
): RedactionSegmentDescription {
  return {
    segmentId,
    kind: "word",
    redactable: true,
    objId: 4,
    page,
    text,
    byteLength: text ? text.length : 1,
  };
}

function container(segmentId: number, kind: "skeleton" | "object"): RedactionSegmentDescription {
  return {
    segmentId,
    kind,
    redactable: false,
    objId: segmentId,
    page: null,
    text: null,
    byteLength: 100,
  };
}

function setup(segments: RedactionSegmentDescription[], selectedIds: number[] = []) {
  const onToggle = vi.fn();
  const onClear = vi.fn();
  render(
    <WordSelect
      segments={segments}
      selectedIds={selectedIds}
      onToggle={onToggle}
      onClear={onClear}
      purple={PURPLE}
      accent={ACCENT}
    />,
  );
  return { onToggle, onClear };
}

describe("<WordSelect>", () => {
  it("lists committed words with their text and page", () => {
    setup([word(0, "POSITIVE"), word(1, "CHILDHOOD", 2), container(2, "skeleton")]);
    expect(screen.getByText("POSITIVE")).toBeInTheDocument();
    expect(screen.getByText("CHILDHOOD")).toBeInTheDocument();
    expect(screen.getByText("p2")).toBeInTheDocument();
  });

  it("never offers a container leaf as a checkbox", () => {
    // The server rejects a container id with a bound check, so a checkbox here
    // could only ever produce a 4xx. Counting them instead of listing them is
    // also what keeps the words findable.
    setup([word(0, "alpha"), container(1, "skeleton"), container(2, "object")]);
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    expect(screen.getByText(/2 container leaves bind the document/i)).toBeInTheDocument();
  });

  it("toggles the segment id the row stands for", async () => {
    const user = userEvent.setup();
    // Ids deliberately not 0/1: a row must send its OWN segmentId, not its
    // index, or every selection past the first would hide the wrong word.
    const { onToggle } = setup([word(7, "alpha"), word(9, "beta")]);
    await user.click(screen.getByRole("checkbox", { name: /hide word beta/i }));
    expect(onToggle).toHaveBeenCalledWith(9);
  });

  it("filters by word text", async () => {
    const user = userEvent.setup();
    setup([word(0, "alpha"), word(1, "beta"), word(2, "alphabet")]);
    await user.type(screen.getByRole("searchbox"), "alpha");
    expect(await screen.findByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("alphabet")).toBeInTheDocument();
    expect(screen.queryByText("beta")).not.toBeInTheDocument();
  });

  it("drops a word with no decoded text from a text search, not from the list", async () => {
    const user = userEvent.setup();
    // `text: null` has nothing to match, so a search must exclude it rather than
    // throw — and it must come back the moment the search is cleared, since it
    // is still a committed, hideable word.
    setup([word(0, "alpha"), word(1, null)]);
    await user.type(screen.getByRole("searchbox"), "alpha");
    expect(await screen.findByText("alpha")).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /hide word #1/i })).not.toBeInTheDocument();

    await user.clear(screen.getByRole("searchbox"));
    expect(await screen.findByRole("checkbox", { name: /hide word #1/i })).toBeInTheDocument();
  });

  it("counts selections outside the current filter", async () => {
    const user = userEvent.setup();
    // "clear all" must appear for a selection the search has hidden, or it
    // looks like a no-op and the operator cannot reach their own selection.
    setup([word(0, "alpha"), word(1, "beta")], [1]);
    await user.type(screen.getByRole("searchbox"), "alpha");
    expect(await screen.findByText(/1\/2 hidden/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /clear all/i })).toBeInTheDocument();
  });

  it("shows a word with undecodable text by id rather than dropping it", () => {
    // `text: null` means the bytes did not decode to printable text. The word is
    // still committed and still hideable, so it must stay selectable.
    setup([word(3, null)]);
    expect(screen.getByRole("checkbox", { name: /hide word #3/i })).toBeInTheDocument();
  });

  it("caps the rendered rows and says how many it held back", () => {
    const many = Array.from({ length: MAX_VISIBLE_WORDS + 5 }, (_, i) =>
      word(i, `w${i.toString()}`),
    );
    setup(many);
    expect(screen.getAllByRole("checkbox")).toHaveLength(MAX_VISIBLE_WORDS);
    expect(
      screen.getByText(
        new RegExp(`Showing ${MAX_VISIBLE_WORDS.toString()} of ${many.length.toString()}`),
      ),
    ).toBeInTheDocument();
  });

  it("distinguishes an empty commitment from an empty search", async () => {
    const user = userEvent.setup();
    const { unmount } = render(
      <WordSelect
        segments={[container(0, "object")]}
        selectedIds={[]}
        onToggle={vi.fn()}
        onClear={vi.fn()}
        purple={PURPLE}
        accent={ACCENT}
      />,
    );
    expect(screen.getByText("No words committed.")).toBeInTheDocument();
    unmount();

    setup([word(0, "alpha")]);
    await user.type(screen.getByRole("searchbox"), "zzz");
    expect(await screen.findByText("No words match that search.")).toBeInTheDocument();
  });

  it("narrows the list to one page", async () => {
    const user = userEvent.setup();
    setup([word(0, "alpha", 1), word(1, "beta", 2), word(2, "gamma", 2)]);
    await user.selectOptions(screen.getByRole("combobox", { name: /filter words by page/i }), "p2");
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();
    expect(screen.getByText("gamma")).toBeInTheDocument();
  });

  it("counts the words each page holds", () => {
    setup([word(0, "alpha", 1), word(1, "beta", 2), word(2, "gamma", 2)]);
    expect(screen.getByRole("option", { name: "all pages (3)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "page 1 (1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "page 2 (2)" })).toBeInTheDocument();
  });

  it("omits the page menu when it could narrow nothing", () => {
    // A single-page document is the common case; a one-option menu there is
    // noise next to the search box it competes with for width.
    setup([word(0, "alpha", 1), word(1, "beta", 1)]);
    expect(
      screen.queryByRole("combobox", { name: /filter words by page/i }),
    ).not.toBeInTheDocument();
  });

  it("reaches a word the row cap held back, which is why the filter exists", async () => {
    const user = userEvent.setup();
    // Page 1 alone fills the cap, so the page-2 words are past `visible.slice`
    // and no amount of scrolling reveals them. Without a page filter the only
    // way to reach one is to already know its text — the defect this closes.
    const many = [
      ...Array.from({ length: MAX_VISIBLE_WORDS + 1 }, (_, i) => word(i, `w${i.toString()}`, 1)),
      word(MAX_VISIBLE_WORDS + 1, "buried", 2),
    ];
    setup(many);
    expect(screen.queryByText("buried")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: /filter words by page/i }), "p2");
    expect(screen.getByText("buried")).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
  });

  it("keeps words with no resolved page reachable", async () => {
    const user = userEvent.setup();
    // `describe` is fail-soft on page resolution, so `page: null` is a real
    // committed, hideable word — it must not fall out of every filter state.
    setup([word(0, "alpha", 1), word(1, "orphan", null), word(2, "beta", 2)]);
    await user.selectOptions(
      screen.getByRole("combobox", { name: /filter words by page/i }),
      "unpaged",
    );
    expect(screen.getByText("orphan")).toBeInTheDocument();
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();
  });

  it("falls back to all pages when a new document drops the selected one", async () => {
    const user = userEvent.setup();
    const props = {
      selectedIds: [],
      onToggle: vi.fn(),
      onClear: vi.fn(),
      purple: PURPLE,
      accent: ACCENT,
    };
    const { rerender } = render(
      <WordSelect segments={[word(0, "alpha", 1), word(1, "beta", 2)]} {...props} />,
    );
    await user.selectOptions(screen.getByRole("combobox", { name: /filter words by page/i }), "p2");
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();

    // Describing a different document must not leave the operator staring at an
    // empty list filtered to a page this document does not have.
    rerender(<WordSelect segments={[word(0, "delta", 1)]} {...props} />);
    expect(screen.getByText("delta")).toBeInTheDocument();
  });

  it("says a page is empty rather than blaming the search box", async () => {
    const user = userEvent.setup();
    setup([word(0, "alpha", 1), word(1, "beta", 2)]);
    await user.selectOptions(screen.getByRole("combobox", { name: /filter words by page/i }), "p2");
    await user.type(screen.getByRole("searchbox"), "alpha");
    expect(await screen.findByText("No words on that page match that search.")).toBeInTheDocument();
  });
});
