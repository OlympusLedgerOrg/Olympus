import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// HashReveal does some animation work — stub it to a deterministic span
// so HashDisplay's wiring is what's under test, not the reveal animation.
vi.mock("./HashReveal", () => ({
  default: ({ hash, label }: { hash: string; label?: string }) => (
    <div data-testid="hash-reveal-mock" data-hash={hash} data-label={label ?? ""} />
  ),
}));

import HashDisplay from "./HashDisplay";

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<HashDisplay>", () => {
  it("renders the HashReveal child with the supplied hash + label", () => {
    const longHash = "deadbeef".repeat(8);
    render(<HashDisplay hash={longHash} label="CONTENT_HASH" />);
    const reveal = screen.getByTestId("hash-reveal-mock");
    expect(reveal).toHaveAttribute("data-hash", longHash);
    expect(reveal).toHaveAttribute("data-label", "CONTENT_HASH");
  });

  it("omits the label attribute when no label prop is passed", () => {
    render(<HashDisplay hash="aa" />);
    expect(screen.getByTestId("hash-reveal-mock")).toHaveAttribute("data-label", "");
  });

  it("renders a CopyButton wired to the hash value", () => {
    render(<HashDisplay hash="aa" />);
    expect(screen.getByRole("button", { name: /copy to clipboard/i })).toBeInTheDocument();
  });
});
