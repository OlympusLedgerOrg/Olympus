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
    mockedSafeJsonFetch.mockRejectedValueOnce(new Error("network down"));
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
});
