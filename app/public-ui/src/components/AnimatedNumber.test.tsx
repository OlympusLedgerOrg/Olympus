import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AnimatedNumber from "./AnimatedNumber";

// Drive rAF via vitest's fake timers — toFake: ["requestAnimationFrame"]
// lets advanceTimersByTime run the recursive rAF chain naturally, which
// is the only way to reach the terminal progress=1 frame when the source
// re-schedules itself on every tick.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["requestAnimationFrame", "cancelAnimationFrame"] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("<AnimatedNumber>", () => {
  it("renders 0 on first paint before any rAF tick", () => {
    render(<AnimatedNumber value={1000} />);
    expect(screen.getByText("0")).toBeInTheDocument();
  });

  it("animates up to the target value once the duration elapses", () => {
    render(<AnimatedNumber value={1000} duration={100} />);
    act(() => {
      // Run past the duration so progress reaches 1 and the chain stops.
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByText("1,000")).toBeInTheDocument();
  });

  it("renders the final number with locale grouping", () => {
    render(<AnimatedNumber value={1234567} duration={50} />);
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByText("1,234,567")).toBeInTheDocument();
  });

  it("re-animates when the value prop changes", () => {
    const { rerender } = render(<AnimatedNumber value={100} duration={50} />);
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByText("100")).toBeInTheDocument();

    rerender(<AnimatedNumber value={500} duration={50} />);
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByText("500")).toBeInTheDocument();
  });

  it("cleans up the in-flight rAF chain on unmount (no setState after unmount)", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { unmount } = render(<AnimatedNumber value={1000} duration={100} />);
    act(() => {
      vi.advanceTimersByTime(50); // mid-animation
    });
    unmount();
    act(() => {
      vi.advanceTimersByTime(500); // would complete the animation if not cancelled
    });
    // React logs "Can't perform a React state update on an unmounted component"
    // if cleanup is missing. No such call after the source's
    // cancelAnimationFrame + cancelled-flag guard.
    expect(errSpy).not.toHaveBeenCalled();
    errSpy.mockRestore();
  });
});
