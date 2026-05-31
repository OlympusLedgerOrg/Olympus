import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/audio", () => ({
  playGlitchSound: vi.fn(),
}));

import { playGlitchSound } from "../lib/audio";
import VerdictCard from "./VerdictCard";
import type { VerdictDetail } from "../lib/types";

const mockedPlay = vi.mocked(playGlitchSound);

beforeEach(() => {
  mockedPlay.mockReset();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<VerdictCard>", () => {
  it("renders the verified label, icon, and description", () => {
    render(<VerdictCard verdict="verified" />);
    expect(screen.getByText(/ACCESS_GRANTED/)).toBeInTheDocument();
    expect(screen.getByText(/cryptographically valid/i)).toBeInTheDocument();
  });

  it("renders the failed label + description for verdict='failed'", () => {
    render(<VerdictCard verdict="failed" />);
    expect(screen.getByText(/SECURITY_BREACH_DETECTED/)).toBeInTheDocument();
    expect(screen.getByText(/tampering or corrupted/i)).toBeInTheDocument();
  });

  it("renders the unknown label + description for verdict='unknown'", () => {
    render(<VerdictCard verdict="unknown" />);
    expect(screen.getByText(/RECORD_NOT_FOUND/)).toBeInTheDocument();
    expect(screen.getByText(/not committed to the Olympus ledger/i)).toBeInTheDocument();
  });

  it("plays the corresponding audio cue per verdict", () => {
    const { rerender } = render(<VerdictCard verdict="verified" />);
    expect(mockedPlay).toHaveBeenCalledWith("success");

    rerender(<VerdictCard verdict="failed" />);
    expect(mockedPlay).toHaveBeenCalledWith("fail");

    rerender(<VerdictCard verdict="unknown" />);
    expect(mockedPlay).toHaveBeenCalledWith("noise");
  });

  it("renders detail rows with KEY_UPPERCASE labels", () => {
    const details: VerdictDetail[] = [
      { key: "Content Hash", value: "ch-abc", status: "ok", copyable: true },
      { key: "Shard ID", value: "shard-1", status: "neutral" },
      { key: "Merkle Proof", value: "Invalid", status: "err" },
    ];
    render(<VerdictCard verdict="verified" details={details} />);
    expect(screen.getByText(/CONTENT_HASH/)).toBeInTheDocument();
    expect(screen.getByText("ch-abc")).toBeInTheDocument();
    expect(screen.getByText(/SHARD_ID/)).toBeInTheDocument();
    expect(screen.getByText("Invalid")).toBeInTheDocument();
  });

  it("renders a CopyButton next to copyable rows", () => {
    const details: VerdictDetail[] = [
      { key: "Hash", value: "h", status: "ok", copyable: true },
      { key: "Shard", value: "0", status: "neutral" },
    ];
    render(<VerdictCard verdict="verified" details={details} />);
    // Only the copyable row gets a CopyButton.
    expect(screen.getAllByRole("button", { name: /copy to clipboard/i })).toHaveLength(1);
  });

  it("renders no details section when details is empty", () => {
    const { container } = render(<VerdictCard verdict="verified" />);
    expect(container.querySelectorAll("button").length).toBe(0);
  });
});
