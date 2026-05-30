import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "../lib/api";
import { clearStoredAdminKey, setStoredAdminKey } from "../lib/storage";
import WhoAmIChip from "./WhoAmIChip";

const mockedFetch = vi.mocked(apiFetch);

// Minimal HTTP-like error so errStatus() can fish out the code.
// NB: explicit field + assignment, not a `public status` parameter
// property — the latter emits runtime code and is rejected under
// `erasableSyntaxOnly` (TS1294), which the pre-push `tsc -b` enforces.
class FakeApiError extends Error {
  status: number;
  constructor(status: number) {
    super(`HTTP ${status}`);
    this.status = status;
  }
}

const ADMIN_KEY = "k".repeat(64);

beforeEach(() => {
  clearStoredAdminKey();
  mockedFetch.mockReset();
});

afterEach(() => {
  clearStoredAdminKey();
});

describe("WhoAmIChip", () => {
  it("renders nothing when no admin key is stored", () => {
    const { container } = render(<WhoAmIChip />);
    expect(container.firstChild).toBeNull();
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("queries /auth/whoami with the stored key and shows scopes + fingerprint", async () => {
    setStoredAdminKey(ADMIN_KEY);
    mockedFetch.mockResolvedValue({
      user_id: "u-1",
      email: "op@example.com",
      scopes: ["admin", "ingest"],
      key_fingerprint: "abcdef012345",
    });

    render(<WhoAmIChip />);

    await waitFor(() => expect(mockedFetch).toHaveBeenCalledTimes(1));
    expect(mockedFetch).toHaveBeenCalledWith("/auth/whoami", {
      headers: { "X-API-Key": ADMIN_KEY },
    });

    await screen.findByText("admin ingest");
    // The fingerprint label uses the first six chars of key_fingerprint.
    expect(screen.getByText(/OP•abcdef/)).toBeTruthy();
  });

  it("falls back to 'scopes unknown' on 404 from /auth/whoami", async () => {
    setStoredAdminKey(ADMIN_KEY);
    mockedFetch.mockRejectedValue(new FakeApiError(404));

    render(<WhoAmIChip />);

    await screen.findByText("scopes unknown");
  });

  it("falls back to 'scopes unknown' on 501 (endpoint not implemented)", async () => {
    setStoredAdminKey(ADMIN_KEY);
    mockedFetch.mockRejectedValue(new FakeApiError(501));

    render(<WhoAmIChip />);

    await screen.findByText("scopes unknown");
  });

  it("leaves the chip in 'loading…' on a non-404 error so the operator sees the key is configured", async () => {
    setStoredAdminKey(ADMIN_KEY);
    mockedFetch.mockRejectedValue(new FakeApiError(500));

    render(<WhoAmIChip />);

    // loading… is the default label until either a response lands or a
    // 404/501 flips missingEndpoint.
    expect(screen.getByText("loading…")).toBeTruthy();
    // Give the catch a tick to run; the label must still say loading…
    await new Promise(r => setTimeout(r, 10));
    expect(screen.getByText("loading…")).toBeTruthy();
  });

  it("renders the admin-tinted colour when the key has the admin scope", async () => {
    setStoredAdminKey(ADMIN_KEY);
    mockedFetch.mockResolvedValue({
      scopes: ["admin"],
      key_fingerprint: "deadbeef0000",
    });

    const { container } = render(<WhoAmIChip />);
    await screen.findByText("admin");
    const chip = container.querySelector("div") as HTMLDivElement;
    expect(chip.style.color).toMatch(/rgb\(\s*204,\s*255,\s*204\s*\)/);
  });
});
