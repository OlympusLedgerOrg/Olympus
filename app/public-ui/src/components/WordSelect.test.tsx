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
});
