import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredAdminKey: vi.fn(() => "admin-key"),
}));

import { apiFetch } from "../lib/api";
import { getStoredAdminKey } from "../lib/storage";
import CredentialsPage from "./CredentialsPage";

const mockedApiFetch = vi.mocked(apiFetch);
const mockedGetStoredAdminKey = vi.mocked(getStoredAdminKey);

const SAMPLE_CRED = {
  id: "cred-1",
  holder_key: "holder-aaa",
  credential_type: "press_credential",
  issued_at: "2026-05-28T00:00:00Z",
  revoked_at: null,
  issuer: "issuer-x",
  commit_id: "commit-1",
  details: {},
  issuer_pubkey: { r8x: "x", r8y: "y" },
  issued_signature: { r8x: "rx", r8y: "ry", s: "s" },
  revoked_signature: null,
  commitment: null,
};

beforeEach(() => {
  mockedApiFetch.mockReset();
  mockedGetStoredAdminKey.mockReturnValue("admin-key");
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<CredentialsPage>", () => {
  it("calls /credentials on mount and renders the heading", async () => {
    mockedApiFetch.mockResolvedValue({ credentials: [] });
    render(<CredentialsPage />);
    expect(await screen.findByRole("heading", { name: /CREDENTIALS/ })).toBeInTheDocument();
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    const firstCall = mockedApiFetch.mock.calls[0][0];
    expect(firstCall).toMatch(/^\/credentials/);
  });

  it("renders an issued credential row", async () => {
    mockedApiFetch.mockResolvedValue({ credentials: [SAMPLE_CRED] });
    render(<CredentialsPage />);
    expect(await screen.findByText("holder-aaa")).toBeInTheDocument();
    expect(screen.getByText(/press_credential/)).toBeInTheDocument();
  });

  it("issues a credential when ISSUE is clicked", async () => {
    mockedApiFetch
      .mockResolvedValueOnce({ credentials: [] })
      .mockResolvedValueOnce(SAMPLE_CRED)
      .mockResolvedValueOnce({ credentials: [SAMPLE_CRED] });

    render(<CredentialsPage />);
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(1));

    // Source placeholder is the literal `user:<uuid>, email:..., bjj:<x>:<y>`.
    await userEvent.type(
      screen.getByPlaceholderText(/user:.*email:/i),
      "holder-new",
    );

    // Default button label is "ISSUE + SIGN" (the source toggles to
    // "ISSUE + COMMIT + SIGN" when `commit: true`).
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ SIGN/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(3));
    const issueCall = mockedApiFetch.mock.calls[1];
    expect(issueCall[0]).toBe("/credentials");
    expect((issueCall[1] as RequestInit)?.method).toBe("POST");
  });

  it("surfaces an error when the refresh call rejects", async () => {
    mockedApiFetch.mockRejectedValue(new Error("server unreachable"));
    render(<CredentialsPage />);
    expect(await screen.findByText(/server unreachable/)).toBeInTheDocument();
  });

  it("calls /credentials/{id}/revoke when REVOKE is clicked + confirmed", async () => {
    // Source calls window.confirm before sending the revoke. Stub it true
    // so the API call actually fires.
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    mockedApiFetch
      .mockResolvedValueOnce({ credentials: [SAMPLE_CRED] })
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce({ credentials: [{ ...SAMPLE_CRED, revoked_at: "now" }] });

    render(<CredentialsPage />);
    const revokeBtn = await screen.findByRole("button", { name: /REVOKE/i });
    await userEvent.click(revokeBtn);
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(3));
    expect(confirmSpy).toHaveBeenCalled();
    expect(mockedApiFetch.mock.calls[1][0]).toBe("/credentials/cred-1/revoke");
    confirmSpy.mockRestore();
  });

  it("calls /credentials/{id}/verify when VERIFY is clicked", async () => {
    mockedApiFetch
      .mockResolvedValueOnce({ credentials: [SAMPLE_CRED] })
      .mockResolvedValueOnce({ valid: true });

    render(<CredentialsPage />);
    const verifyBtn = await screen.findByRole("button", { name: /VERIFY/i });
    await userEvent.click(verifyBtn);
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(2));
    expect(mockedApiFetch.mock.calls[1][0]).toMatch(/^\/credentials\/cred-1\/verify/);
  });
});
