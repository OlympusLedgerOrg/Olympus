import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import CopyButton from "./CopyButton";

// JSDOM does not implement the async Clipboard API. Stub
// navigator.clipboard.writeText with a vi.fn() so we can assert what
// got copied. We use fireEvent.click rather than userEvent here:
// userEvent v14 wires its own internal Clipboard pipeline and the
// extra plumbing collides with the spy in jsdom.
const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

const IDLE_COLOR = /rgba\(\s*0,\s*255,\s*65,\s*0\.3\s*\)/;
const COPIED_COLOR = /rgb\(\s*0,\s*255,\s*65\s*\)/;

describe("CopyButton", () => {
  it("renders a copy-labelled button", () => {
    render(<CopyButton text="hello" />);
    expect(screen.getByRole("button", { name: /copy to clipboard/i })).toBeTruthy();
  });

  it("writes the provided text to the clipboard on click", async () => {
    render(<CopyButton text="payload-abc" />);
    fireEvent.click(screen.getByRole("button", { name: /copy to clipboard/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith("payload-abc");
  });

  it("toggles to the copied state after a successful write and reverts after 1.5s", async () => {
    vi.useFakeTimers();
    render(<CopyButton text="x" />);
    const btn = screen.getByRole("button", { name: /copy to clipboard/i }) as HTMLButtonElement;
    expect(btn.style.color).toMatch(IDLE_COLOR);

    fireEvent.click(btn);
    // Flush the writeText().then() microtask so setCopied(true) runs.
    await vi.waitFor(() => expect(btn.style.color).toMatch(COPIED_COLOR));

    vi.advanceTimersByTime(1500);
    await vi.waitFor(() => expect(btn.style.color).toMatch(IDLE_COLOR));
  });

  it("stops click propagation so it can be nested in clickable rows", async () => {
    const outerClick = vi.fn();
    render(
      <div onClick={outerClick}>
        <CopyButton text="x" />
      </div>,
    );
    fireEvent.click(screen.getByRole("button", { name: /copy to clipboard/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(outerClick).not.toHaveBeenCalled();
  });
});
