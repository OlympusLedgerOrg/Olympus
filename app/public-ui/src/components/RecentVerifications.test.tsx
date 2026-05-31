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
    // The only non-row button is CLEAR; exclude it by accessible text rather
    // than coupling to the `recent-row` CSS class.
    const rows = screen.getAllByRole("button").filter((b) => b.textContent !== "CLEAR");
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
    const row = screen.getAllByRole("button").find((b) => b.textContent !== "CLEAR");
    expect(row).toBeDefined();
    await userEvent.click(row!);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0].hash).toBe(e.hash);
  });

  it("refreshes on a real cross-tab 'storage' event (another tab wrote an entry)", () => {
    render(<RecentVerifications />);
    expect(screen.getByText(/No verification logs/)).toBeInTheDocument();

    // Simulate another browser tab: write straight to localStorage (bypassing
    // addRecentVerification's in-tab dispatch) and then fire a genuine
    // StorageEvent, exactly as the browser would across tabs. The component's
    // window "storage" listener re-reads from localStorage on this event.
    act(() => {
      localStorage.setItem(
        "olympus_recent_verifications",
        JSON.stringify([entry({ hash: "e".repeat(64) })]),
      );
      window.dispatchEvent(new StorageEvent("storage", { key: "olympus_recent_verifications" }));
    });

    expect(screen.queryByText(/No verification logs/)).not.toBeInTheDocument();
    expect(screen.getByText("[VERIFIED]")).toBeInTheDocument();
  });

  it("refreshes on an in-tab update (addRecentVerification dispatches 'storage')", () => {
    render(<RecentVerifications />);
    expect(screen.getByText(/No verification logs/)).toBeInTheDocument();
    // addRecentVerification both writes to localStorage AND dispatches a
    // same-tab "storage" event (the browser only fires StorageEvent for OTHER
    // tabs, so the helper self-notifies). The component listens to both.
    act(() => {
      addRecentVerification(entry({ hash: "f".repeat(64) }));
    });
    expect(screen.queryByText(/No verification logs/)).not.toBeInTheDocument();
    expect(screen.getByText("[VERIFIED]")).toBeInTheDocument();
  });
});
