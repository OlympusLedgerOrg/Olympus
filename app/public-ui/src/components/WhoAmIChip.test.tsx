import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredAdminKey: vi.fn(),
  hasStoredAdminKey: vi.fn(),
}));

import { apiFetch } from "../lib/api";
import { getStoredAdminKey, hasStoredAdminKey } from "../lib/storage";
import WhoAmIChip from "./WhoAmIChip";

const mockedApiFetch = vi.mocked(apiFetch);
const mockedGetStoredAdminKey = vi.mocked(getStoredAdminKey);
const mockedHasStoredAdminKey = vi.mocked(hasStoredAdminKey);

beforeEach(() => {
  mockedApiFetch.mockReset();
  mockedGetStoredAdminKey.mockReset();
  mockedHasStoredAdminKey.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<WhoAmIChip>", () => {
  it("renders nothing when no admin key is stored", () => {
    mockedHasStoredAdminKey.mockReturnValue(false);
    mockedGetStoredAdminKey.mockReturnValue("");
    const { container } = render(<WhoAmIChip />);
    expect(container).toBeEmptyDOMElement();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("shows 'loading…' while the whoami request is in flight", () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockReturnValue(new Promise(() => {})); // never resolves
    render(<WhoAmIChip />);
    expect(screen.getByText(/loading…/)).toBeInTheDocument();
    expect(mockedApiFetch).toHaveBeenCalledWith(
      "/auth/whoami",
      expect.objectContaining({ headers: { "X-API-Key": "admin-key" } }),
    );
  });

  it("renders the scope list once whoami resolves", async () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      user_id: "u-1",
      email: "user@example.com",
      scopes: ["read", "verify", "ingest"],
      key_fingerprint: "abcdef123456",
    });
    render(<WhoAmIChip />);
    await waitFor(() => expect(screen.getByText(/read verify ingest/i)).toBeInTheDocument());
    // Short fingerprint prefix renders in the OP•… chip
    expect(screen.getByText(/OP•abcdef/)).toBeInTheDocument();
  });

  it("renders 'scopes unknown' on 404 (endpoint not implemented)", async () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockRejectedValue(new Error("HTTP 404: not found"));
    render(<WhoAmIChip />);
    expect(await screen.findByText(/scopes unknown/)).toBeInTheDocument();
  });

  it("renders 'scopes unknown' on 501 (not implemented)", async () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockRejectedValue(
      Object.assign(new Error("server error"), { status: 501 }),
    );
    render(<WhoAmIChip />);
    expect(await screen.findByText(/scopes unknown/)).toBeInTheDocument();
  });

  it("colours the chip green-tinted ccffcc when the admin scope is present", async () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      user_id: "u-1",
      scopes: ["admin", "write"],
      key_fingerprint: "ffffff000000",
    });
    render(<WhoAmIChip />);
    const chip = await screen.findByText(/admin write/i);
    // Walk up to the outer chip div and inspect its colour style.
    const chipRoot = chip.closest("div");
    expect(chipRoot?.style.color).toMatch(/#ccffcc|204,\s*255,\s*204/);
  });
});
