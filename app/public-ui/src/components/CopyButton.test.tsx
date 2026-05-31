import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import CopyButton from "./CopyButton";

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<CopyButton>", () => {
  it("renders the copy icon by default", () => {
    const { container } = render(<CopyButton text="hello" />);
    const btn = screen.getByRole("button", { name: /copy to clipboard/i });
    expect(btn).toBeInTheDocument();
    // Default state: <rect> + 2-path icon (clipboard rectangle)
    expect(container.querySelector("rect")).toBeInTheDocument();
  });

  it("writes the text to navigator.clipboard on click", async () => {
    render(<CopyButton text="oly_secret" />);
    await userEvent.click(screen.getByRole("button", { name: /copy to clipboard/i }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("oly_secret");
  });

  it("swaps to the check-mark icon after copy succeeds", async () => {
    const { container } = render(<CopyButton text="x" />);
    await userEvent.click(screen.getByRole("button", { name: /copy to clipboard/i }));
    // The success state replaces the rect with just a single path (check mark)
    await waitFor(() => {
      expect(container.querySelector("rect")).not.toBeInTheDocument();
    });
  });

  it("stops click event propagation (doesn't bubble to parent)", async () => {
    const onParentClick = vi.fn();
    render(
      <div onClick={onParentClick}>
        <CopyButton text="x" />
      </div>,
    );
    await userEvent.click(screen.getByRole("button", { name: /copy to clipboard/i }));
    expect(onParentClick).not.toHaveBeenCalled();
  });
});
