import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getApiBase: vi.fn().mockResolvedValue("http://127.0.0.1:3737"),
}));
vi.mock("../lib/safeJson", () => ({
  safeJsonFetch: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn().mockReturnValue(""),
  setStoredApiKey: vi.fn(),
  setStoredAdminKey: vi.fn(),
  clearStoredApiKey: vi.fn(),
  clearStoredAdminKey: vi.fn(),
}));
vi.mock("./LoadingSplash", () => ({
  default: () => <div data-testid="loading-splash" />,
}));

import { safeJsonFetch } from "../lib/safeJson";
import {
  clearStoredAdminKey,
  clearStoredApiKey,
  getStoredApiKey,
  setStoredAdminKey,
  setStoredApiKey,
} from "../lib/storage";
import StartupGate from "./StartupGate";

const mockedSafeJsonFetch = vi.mocked(safeJsonFetch);
const mockedSetStoredApiKey = vi.mocked(setStoredApiKey);
const mockedSetStoredAdminKey = vi.mocked(setStoredAdminKey);
const mockedClearStoredApiKey = vi.mocked(clearStoredApiKey);
const mockedClearStoredAdminKey = vi.mocked(clearStoredAdminKey);

const PROFILE_KEY = "olympus_startup_profile_v1";
const SESSION_KEY = "olympus_startup_unlocked_v1";

// Deterministic crypto stubs so PBKDF2 output is predictable + jsdom-safe.
// Two paths: the SAME output is "password matches"; a DIFFERENT output is
// "password rejected".
function stubCrypto(deriveOutput = new Uint8Array(32).fill(7)) {
  const subtle = {
    importKey: vi.fn().mockResolvedValue("key"),
    deriveBits: vi.fn().mockResolvedValue(deriveOutput.buffer),
  };
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      subtle,
      getRandomValues: (arr: Uint8Array) => {
        arr.fill(1);
        return arr;
      },
    },
  });
  return subtle;
}

function makeProfile(overrides: Partial<{ email: string; operator: string }> = {}) {
  // verifier matches Uint8Array(32).fill(7) → base64 of 32 bytes of 0x07.
  return {
    operator: overrides.operator ?? "op",
    email: overrides.email ?? "op@example.com",
    salt: "AAAA",
    verifier: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
    createdAt: "2026-05-28T00:00:00Z",
  };
}

// Fills out the setup form and submits via fireEvent.submit on the <form>
// element — bypasses jsdom's native form validation (type="email" with an
// invalid value would otherwise block the click-submit path).
async function fillSetupAndSubmit(
  email: string,
  password: string,
  confirm: string = password,
) {
  const emailInput = screen.getByPlaceholderText("you@example.com");
  fireEvent.change(emailInput, { target: { value: email } });
  fireEvent.change(screen.getByPlaceholderText("at least 12 characters"), {
    target: { value: password },
  });
  fireEvent.change(screen.getByPlaceholderText("repeat password"), {
    target: { value: confirm },
  });
  const form = emailInput.closest("form")!;
  fireEvent.submit(form);
  // Allow the async createProfile path (state updates, awaited crypto) to
  // flush before assertions.
  await new Promise((r) => setTimeout(r, 0));
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  mockedSafeJsonFetch.mockReset();
  mockedSetStoredApiKey.mockReset();
  mockedSetStoredAdminKey.mockReset();
  mockedClearStoredApiKey.mockReset();
  mockedClearStoredAdminKey.mockReset();
  stubCrypto();
});

afterEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("<StartupGate>", () => {
  it("does NOT render children before the profile read settles", () => {
    render(
      <StartupGate>
        <div>app body</div>
      </StartupGate>,
    );
    expect(screen.queryByText("app body")).not.toBeInTheDocument();
  });

  it("lands on setup mode with FIRST BOOT when no profile exists", async () => {
    render(<StartupGate><div>app body</div></StartupGate>);
    expect(await screen.findByText("FIRST BOOT")).toBeInTheDocument();
    expect(screen.queryByText("app body")).not.toBeInTheDocument();
  });

  it("lands on unlock mode with STARTUP LOCK when a profile exists + no session", async () => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(makeProfile()));
    render(<StartupGate><div>app body</div></StartupGate>);
    expect(await screen.findByText("STARTUP LOCK")).toBeInTheDocument();
  });

  it("renders children when a profile exists AND the session is already unlocked", async () => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(makeProfile()));
    sessionStorage.setItem(SESSION_KEY, "1");
    render(<StartupGate><div>app body</div></StartupGate>);
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
  });

  it("setup form rejects an invalid email", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("not-an-email", "longenoughpw1234");
    expect(await screen.findByText(/valid email/i)).toBeInTheDocument();
    expect(mockedSafeJsonFetch).not.toHaveBeenCalled();
  });

  it("setup form rejects a password shorter than 12 characters", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "short");
    expect(await screen.findByText(/at least 12 characters/i)).toBeInTheDocument();
  });

  it("setup form rejects mismatched passwords", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234", "differentpw1234");
    expect(await screen.findByText(/Passwords do not match/i)).toBeInTheDocument();
  });

  it("setup happy path: server returns api_key + admin scope → stores both keys", async () => {
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        api_key: "oly_minted_key",
        scopes: ["read", "verify", "ingest", "commit", "write", "admin"],
        user_id: "u-1",
      },
      text: "",
    });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    await waitFor(() => expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_minted_key"));
    expect(mockedSetStoredAdminKey).toHaveBeenCalledWith("oly_minted_key");
    expect(localStorage.getItem(PROFILE_KEY)).not.toBeNull();
  });

  it("setup → 409 'already registered' → switches to login mode", async () => {
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      data: { detail: "Email already registered" },
      text: "",
    });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");

    // After switching, the login form's submit button reads "SIGN IN".
    expect(
      await screen.findByRole("button", { name: /^SIGN IN$/i }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/already registered/i)).toBeInTheDocument();
  });

  it("setup → server unreachable → still enters the console (children render)", async () => {
    // safeJsonFetch never throws — its contract is to catch network errors
    // and return { ok: false, status: 0, data: null, text: <msg> }. Mock
    // that shape so we exercise the source's documented "server unreachable
    // or registration failed" branch (the `!ok && !data?.api_key` else),
    // not the outer try/catch.
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: false,
      status: 0,
      data: null,
      text: "network down",
    });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument(), {
      timeout: 3000,
    });
  });

  it("clicking 'ALREADY HAVE AN ACCOUNT? SIGN IN' swaps to login mode", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await userEvent.click(
      screen.getByRole("button", { name: /ALREADY HAVE AN ACCOUNT/i }),
    );
    // Login submit button text is exactly "SIGN IN".
    expect(
      await screen.findByRole("button", { name: /^SIGN IN$/i }),
    ).toBeInTheDocument();
  });

  it("unlock with wrong password renders the rejection error", async () => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(makeProfile()));
    // Different deriveBits output → verifier mismatch → rejection.
    stubCrypto(new Uint8Array(32).fill(99));
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("STARTUP LOCK");

    const pwField = screen.getByPlaceholderText("enter password");
    fireEvent.change(pwField, { target: { value: "wrongpassword" } });
    await userEvent.click(
      screen.getByRole("button", { name: /UNLOCK CONSOLE/i }),
    );

    expect(
      await screen.findByText(/Startup password rejected/i),
    ).toBeInTheDocument();
  });

  it("RESET / NEW ACCOUNT clears localStorage + stored API/admin keys", async () => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(makeProfile()));
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("STARTUP LOCK");
    await userEvent.click(
      screen.getByRole("button", { name: /RESET.*NEW ACCOUNT/i }),
    );
    expect(localStorage.getItem(PROFILE_KEY)).toBeNull();
    expect(mockedClearStoredApiKey).toHaveBeenCalled();
    expect(mockedClearStoredAdminKey).toHaveBeenCalled();
    expect(await screen.findByText("FIRST BOOT")).toBeInTheDocument();
  });

  it("readProfile swallows a corrupt JSON blob and falls back to setup mode", async () => {
    // Non-JSON in the profile slot → JSON.parse throws → readProfile catch
    // returns null → no profile → setup ("FIRST BOOT"), not a crash.
    localStorage.setItem(PROFILE_KEY, "{not valid json");
    render(<StartupGate><div>x</div></StartupGate>);
    expect(await screen.findByText("FIRST BOOT")).toBeInTheDocument();
  });

  it("setup → 429 rate limit surfaces the saved-profile message and skips the key panel", async () => {
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      data: {},
      text: "",
    });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    expect(await screen.findByText(/Rate limit hit/i)).toBeInTheDocument();
    // Local profile is still persisted so the next visit can unlock offline.
    expect(localStorage.getItem(PROFILE_KEY)).not.toBeNull();
    expect(mockedSetStoredApiKey).not.toHaveBeenCalled();
  });

  it("setup → 403 on the broadest scope set retries with a narrower one", async () => {
    // First scope candidate forbidden (403 → `continue`), second succeeds.
    mockedSafeJsonFetch
      .mockResolvedValueOnce({ ok: false, status: 403, data: {}, text: "" })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { api_key: "oly_narrow", scopes: ["read", "verify"], user_id: "u-2" },
        text: "",
      });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    await waitFor(() =>
      expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_narrow"),
    );
    // Non-admin scope set → admin key NOT stored.
    expect(mockedSetStoredAdminKey).not.toHaveBeenCalled();
  });

  it("setup happy path → COPY button copies the freshly minted API key", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: { api_key: "oly_copy_me", scopes: ["read", "verify"], user_id: "u-3" },
      text: "",
    });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    const copyBtn = await screen.findByRole("button", { name: /^COPY$/i });
    await userEvent.click(copyBtn);
    expect(writeText).toHaveBeenCalledWith("oly_copy_me");
    expect(await screen.findByRole("button", { name: /^COPIED$/i })).toBeInTheDocument();
  });

  it("setup happy path → ENTER CONSOLE dismisses the key panel and renders children", async () => {
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: { api_key: "oly_enter", scopes: ["read", "verify"], user_id: "u-4" },
      text: "",
    });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await fillSetupAndSubmit("user@example.com", "longenoughpw1234");
    await userEvent.click(await screen.findByRole("button", { name: /ENTER CONSOLE/i }));
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
  });

  // ── Login / sign-in flow ───────────────────────────────────────────────
  async function switchToLoginAndSubmit(emailValue: string, pw: string) {
    await userEvent.click(
      screen.getByRole("button", { name: /ALREADY HAVE AN ACCOUNT/i }),
    );
    const emailInput = await screen.findByPlaceholderText("you@example.com");
    fireEvent.change(emailInput, { target: { value: emailValue } });
    fireEvent.change(screen.getByPlaceholderText("your password"), {
      target: { value: pw },
    });
    fireEvent.submit(emailInput.closest("form")!);
    await new Promise((r) => setTimeout(r, 0));
  }

  it("login validates the email before any network call", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("nope", "whatever");
    expect(await screen.findByText(/valid email/i)).toBeInTheDocument();
    expect(mockedSafeJsonFetch).not.toHaveBeenCalled();
  });

  it("login surfaces the server detail when /auth/login rejects", async () => {
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      data: { detail: "Invalid credentials" },
      text: "",
    });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    expect(await screen.findByText(/Invalid credentials/i)).toBeInTheDocument();
  });

  it("login success → reissue-key returns a key → shows it and stores it", async () => {
    mockedSafeJsonFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { email: "user@example.com", user_id: "u-5" },
        text: "",
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { api_key: "oly_reissued", key_id: "k1", scopes: ["read"], expires_at: "" },
        text: "",
      });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    await waitFor(() =>
      expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_reissued"),
    );
    expect(await screen.findByText("oly_reissued")).toBeInTheDocument();
    expect(localStorage.getItem(PROFILE_KEY)).not.toBeNull();
  });

  it("login with a stored key skips reissue and keeps the key", async () => {
    vi.mocked(getStoredApiKey).mockReturnValueOnce("oly_existing_admin_key");
    mockedSafeJsonFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: { email: "user@example.com", user_id: "u-8" },
      text: "",
    });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
    // Only the login call — no reissue, no overwrite of the stored key.
    expect(mockedSafeJsonFetch).toHaveBeenCalledTimes(1);
    expect(mockedSetStoredApiKey).not.toHaveBeenCalled();
  });

  it("reissue requests the union of the account's active key scopes", async () => {
    mockedSafeJsonFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: {
          email: "user@example.com",
          user_id: "u-9",
          keys: [
            { id: "k1", scopes: ["read", "write", "admin"], revoked: false, expires_at: "2099-01-01T00:00:00" },
            { id: "k2", scopes: ["verify"], revoked: true, expires_at: "2099-01-01T00:00:00" },
          ],
        },
        text: "",
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { api_key: "oly_reissued2", key_id: "k3", scopes: ["read", "write", "admin"], expires_at: "" },
        text: "",
      });
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    await waitFor(() =>
      expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_reissued2"),
    );
    const reissueCall = mockedSafeJsonFetch.mock.calls[1];
    const body = JSON.parse((reissueCall[1] as RequestInit).body as string) as { scopes: string[] };
    // Union of ACTIVE keys only — the revoked key's scopes are excluded,
    // and admin is preserved instead of the old hardcoded non-admin list.
    expect(body.scopes).toEqual(["read", "write", "admin"]);
  });

  it("login success → reissue-key fails → enters the console anyway", async () => {
    mockedSafeJsonFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { email: "user@example.com", user_id: "u-6" },
        text: "",
      })
      .mockResolvedValueOnce({ ok: false, status: 500, data: null, text: "" });
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
  });

  it("login success → reissue-key throws → caught, console entered", async () => {
    mockedSafeJsonFetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        data: { email: "user@example.com", user_id: "u-7" },
        text: "",
      })
      .mockRejectedValueOnce(new Error("network blip"));
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await switchToLoginAndSubmit("user@example.com", "rightlength12");
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
  });

  it("login mode → CREATE NEW ACCOUNT returns to setup", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    await userEvent.click(
      screen.getByRole("button", { name: /ALREADY HAVE AN ACCOUNT/i }),
    );
    await screen.findByRole("button", { name: /^SIGN IN$/i });
    await userEvent.click(screen.getByRole("button", { name: /CREATE NEW ACCOUNT/i }));
    expect(await screen.findByText("FIRST BOOT")).toBeInTheDocument();
  });

  it("unlock with the correct password renders children", async () => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(makeProfile()));
    // Default stubCrypto yields fill(7), matching makeProfile's verifier.
    render(<StartupGate><div>app body</div></StartupGate>);
    await screen.findByText("STARTUP LOCK");
    fireEvent.change(screen.getByPlaceholderText("enter password"), {
      target: { value: "correcthorse" },
    });
    fireEvent.submit(screen.getByPlaceholderText("enter password").closest("form")!);
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
    expect(sessionStorage.getItem(SESSION_KEY)).toBe("1");
  });

  it("unlock → SIGN IN AGAIN switches to login with the email prefilled", async () => {
    localStorage.setItem(
      PROFILE_KEY,
      JSON.stringify(makeProfile({ email: "back@example.com" })),
    );
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("STARTUP LOCK");
    await userEvent.click(screen.getByRole("button", { name: /SIGN IN AGAIN/i }));
    await screen.findByRole("button", { name: /^SIGN IN$/i });
    expect(screen.getByPlaceholderText("you@example.com")).toHaveValue("back@example.com");
  });

  it("typing the MAYHEM easter egg swaps in the Project Mayhem manifesto", async () => {
    render(<StartupGate><div>x</div></StartupGate>);
    await screen.findByText("FIRST BOOT");
    for (const ch of "MAYHEM") {
      fireEvent.keyDown(window, { key: ch });
    }
    expect(await screen.findByText(/PROJECT MAYHEM/i)).toBeInTheDocument();
  });
});
