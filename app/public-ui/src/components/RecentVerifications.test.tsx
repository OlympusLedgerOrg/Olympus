import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { addRecentVerification, clearRecentVerifications } from "../lib/storage";
import type { RecentVerificationEntry } from "../lib/types";
import RecentVerifications from "./RecentVerifications";

function entry(overrides: Partial<RecentVerificationEntry> = {}): RecentVerificationEntry {
  return {
    hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    type: "hash",
    verdict: "verified",
    timestamp: Date.now(),
    ...overrides,
  };
}

beforeEach(() => {
  localStorage.clear();
  clearRecentVerifications();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<RecentVerifications>", () => {
  it("renders the empty-state when there are no entries", () => {
    render(<RecentVerifications />);
    expect(screen.getByText(/EMPTY/)).toBeInTheDocument();
    expect(screen.getByText(/No verification logs/)).toBeInTheDocument();
    // No CLEAR button when there's nothing to clear
    expect(screen.queryByRole("button", { name: /CLEAR/i })).not.toBeInTheDocument();
  });

  it("renders one row per stored entry, newest first", () => {
    addRecentVerification(entry({ hash: "aaa".padEnd(64, "a"), timestamp: 1 }));
    addRecentVerification(entry({ hash: "bbb".padEnd(64, "b"), timestamp: 2 }));
    render(<RecentVerifications />);
    const rows = screen.getAllByRole("button").filter((b) => b.className.includes("recent-row"));
    expect(rows).toHaveLength(2);
    // addRecentVerification prepends, so 'bbb' (added 2nd) is first.
    expect(rows[0].textContent).toMatch(/bbb/);
  });

  it("renders the verdict tag for each row", () => {
    addRecentVerification(entry({ verdict: "verified", hash: "a".repeat(64), timestamp: 1 }));
    addRecentVerification(entry({ verdict: "failed", hash: "b".repeat(64), timestamp: 2 }));
    addRecentVerification(entry({ verdict: "unknown", hash: "c".repeat(64), timestamp: 3 }));
    render(<RecentVerifications />);
    expect(screen.getByText("[VERIFIED]")).toBeInTheDocument();
    expect(screen.getByText("[FAILED]")).toBeInTheDocument();
    expect(screen.getByText("[UNKNOWN]")).toBeInTheDocument();
  });

  it("CLEAR wipes the list and removes the button", async () => {
    addRecentVerification(entry());
    render(<RecentVerifications />);
    await userEvent.click(screen.getByRole("button", { name: /CLEAR/i }));
    expect(screen.getByText(/No verification logs/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /CLEAR/i })).not.toBeInTheDocument();
  });

  it("fires onSelect with the entry when a row is clicked", async () => {
    const e = entry({ hash: "d".repeat(64) });
    addRecentVerification(e);
    const onSelect = vi.fn();
    render(<RecentVerifications onSelect={onSelect} />);
    const row = screen.getAllByRole("button").find((b) => b.className.includes("recent-row"));
    expect(row).toBeDefined();
    await userEvent.click(row!);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0].hash).toBe(e.hash);
  });

  it("refreshes when a 'storage' event fires (cross-tab sync)", () => {
    render(<RecentVerifications />);
    expect(screen.getByText(/No verification logs/)).toBeInTheDocument();
    // Add an entry in another tab → addRecentVerification fires a 'storage'
    // event on success — but the in-tab dispatch is what the source listens
    // to. Mirror that here.
    act(() => {
      addRecentVerification(entry({ hash: "e".repeat(64) }));
    });
    // The 'storage' event handler on the component triggers a setState that
    // re-reads from localStorage, so the empty-state should now be gone.
    expect(screen.queryByText(/No verification logs/)).not.toBeInTheDocument();
    expect(screen.getByText("[VERIFIED]")).toBeInTheDocument();
  });
});
