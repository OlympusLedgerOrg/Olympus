import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  const CRED_COMMIT = {
    ...SAMPLE_CRED,
    id: "cred-2",
    commitment: { x: "abcdef0123456789aa", y: "fedcba9876543210bb", version: 1 },
  };

  // Route apiFetch by `METHOD path` so the useEffect-driven refresh fan-out
  // (one GET per filter keystroke) doesn't make call-ordering brittle.
  function routeApi(
    creds: unknown[],
    handlers: Record<string, (url: string, init?: RequestInit) => Promise<unknown>> = {},
  ) {
    mockedApiFetch.mockImplementation((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const key = `${method} ${url.split("?")[0]}`;
      if (handlers[key]) return handlers[key](url, init);
      if (url.startsWith("/credentials") && method === "GET") {
        return Promise.resolve({ credentials: creds });
      }
      return Promise.resolve({});
    });
  }

  it("ISSUE with an empty holder shows the required-fields error and skips the POST", async () => {
    routeApi([]);
    render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ SIGN/i }));
    expect(await screen.findByText(/holder \+ type required/i)).toBeInTheDocument();
    expect(
      mockedApiFetch.mock.calls.some(([, i]) => (i as RequestInit | undefined)?.method === "POST"),
    ).toBe(false);
  });

  it("ISSUE with invalid details JSON surfaces a parse error", async () => {
    routeApi([]);
    const { container } = render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    await userEvent.type(screen.getByPlaceholderText(/user:.*email:/i), "holder-x");
    const textarea = container.querySelector("textarea")!;
    fireEvent.change(textarea, { target: { value: "{not json" } });
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ SIGN/i }));
    expect(await screen.findByText(/details JSON:/i)).toBeInTheDocument();
  });

  it("ISSUE surfaces the server error when the POST rejects", async () => {
    routeApi([], {
      "POST /credentials": () => Promise.reject(new Error("issue denied")),
    });
    render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    await userEvent.type(screen.getByPlaceholderText(/user:.*email:/i), "holder-x");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ SIGN/i }));
    expect(await screen.findByText(/issue denied/i)).toBeInTheDocument();
  });

  it("toggling COMMIT PRIVATELY flips the button label and sends commit:true", async () => {
    let issueBody: string | undefined;
    routeApi([], {
      "POST /credentials": (_url, init) => {
        issueBody = String(init?.body);
        return Promise.resolve({ ...CRED_COMMIT, opening: { m: "1", r: "2" } });
      },
    });
    render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    await userEvent.click(screen.getByLabelText(/COMMIT PRIVATELY/i));
    await userEvent.type(screen.getByPlaceholderText(/user:.*email:/i), "holder-x");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ COMMIT \+ SIGN/i }));
    await waitFor(() => expect(issueBody).toContain('"commit":true'));
  });

  it("issued banner with a private opening exposes COPY OPENING and DISMISS", async () => {
    routeApi([], {
      "POST /credentials": () =>
        Promise.resolve({ ...CRED_COMMIT, opening: { m: "secret-m", r: "secret-r" } }),
    });
    render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    await userEvent.type(screen.getByPlaceholderText(/user:.*email:/i), "holder-x");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE \+ SIGN/i }));
    expect(await screen.findByText(/CREDENTIAL ISSUED/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /COPY OPENING/i }));
    expect(vi.mocked(navigator.clipboard.writeText)).toHaveBeenCalledWith(
      JSON.stringify({ m: "secret-m", r: "secret-r" }),
    );
    await userEvent.click(screen.getByRole("button", { name: /^DISMISS$/i }));
    await waitFor(() => expect(screen.queryByText(/CREDENTIAL ISSUED/i)).not.toBeInTheDocument());
  });

  it("VERIFY on a private credential collects the opening and posts it", async () => {
    const alertSpy = vi.spyOn(window, "alert").mockImplementation(() => {});
    vi.spyOn(window, "prompt").mockReturnValue('{"m":"open-m","r":"open-r"}');
    let verifyBody: string | undefined;
    routeApi([CRED_COMMIT], {
      "POST /credentials/cred-2/verify": (_url, init) => {
        verifyBody = String(init?.body);
        return Promise.resolve({
          commit_id_matches: true,
          issued_signature_valid: true,
          revoked_signature_valid: null,
          is_revoked: false,
          commitment_opens: true,
        });
      },
    });
    render(<CredentialsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /VERIFY/i }));
    await waitFor(() => expect(verifyBody).toContain("open-m"));
    expect(alertSpy).toHaveBeenCalled();
  });

  it("VERIFY rejects a malformed opening before any network call", async () => {
    vi.spyOn(window, "prompt").mockReturnValue('{"m":123}');
    routeApi([CRED_COMMIT]);
    render(<CredentialsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /VERIFY/i }));
    expect(await screen.findByText(/opening must be/i)).toBeInTheDocument();
  });

  it("REVOKE is a no-op when the confirm dialog is cancelled", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    routeApi([SAMPLE_CRED]);
    render(<CredentialsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /REVOKE/i }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(
      mockedApiFetch.mock.calls.some(([u]) => String(u).includes("/revoke")),
    ).toBe(false);
    confirmSpy.mockRestore();
  });

  it("REVOKE surfaces the server error when the revoke POST rejects", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    routeApi([SAMPLE_CRED], {
      "POST /credentials/cred-1/revoke": () => Promise.reject(new Error("revoke failed")),
    });
    render(<CredentialsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /REVOKE/i }));
    expect(await screen.findByText(/revoke failed/i)).toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it("a private-commitment row renders the Pedersen commitment line", async () => {
    routeApi([CRED_COMMIT]);
    render(<CredentialsPage />);
    expect(await screen.findByText(/private commitment \(Pedersen v1\)/i)).toBeInTheDocument();
  });

  it("typing a holder filter issues a scoped /credentials query", async () => {
    routeApi([]);
    render(<CredentialsPage />);
    await screen.findByRole("heading", { name: /CREDENTIALS/ });
    const holderFilter = screen.getAllByRole("textbox").find(
      (el) => el.previousElementSibling?.textContent?.includes("FILTER: HOLDER"),
    );
    fireEvent.change(holderFilter!, { target: { value: "alice" } });
    await waitFor(() =>
      expect(
        mockedApiFetch.mock.calls.some(([u]) => String(u).includes("holder=alice")),
      ).toBe(true),
    );
  });

  it("stringifies a non-Error rejection from the refresh path", async () => {
    mockedApiFetch.mockRejectedValue("plain string failure");
    render(<CredentialsPage />);
    expect(await screen.findByText(/plain string failure/i)).toBeInTheDocument();
  });
});
