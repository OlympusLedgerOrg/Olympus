import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/storage", () => ({
  setStoredAdminKey: vi.fn(),
  setStoredApiKey: vi.fn(),
}));

import { setStoredAdminKey, setStoredApiKey } from "../lib/storage";
import InitialSecretsModal from "./InitialSecretsModal";

const mockedSetStoredAdminKey = vi.mocked(setStoredAdminKey);
const mockedSetStoredApiKey = vi.mocked(setStoredApiKey);

const VALID_KEY = "oly_" + "a".repeat(64);
const VALID_BJJ = "bd1942d22f73d4230163e4c0d7cbf7427db1efad7995a3b84f66756915814b61";

interface TauriShim {
  __TAURI__?: {
    core?: { invoke: (cmd: string) => Promise<unknown> };
  };
}

function stubTauri(invoke: (cmd: string) => Promise<unknown>) {
  (window as unknown as TauriShim).__TAURI__ = { core: { invoke } };
}

function clearTauri() {
  delete (window as unknown as TauriShim).__TAURI__;
}

beforeEach(() => {
  localStorage.clear();
  mockedSetStoredAdminKey.mockReset();
  mockedSetStoredApiKey.mockReset();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  clearTauri();
  vi.restoreAllMocks();
});

describe("<InitialSecretsModal>", () => {
  it("renders nothing when the Tauri runtime is absent (plain browser / vite dev)", async () => {
    clearTauri();
    const { container } = render(<InitialSecretsModal />);
    // Component does a microtask-async probe, so wait a tick before asserting.
    await new Promise((r) => setTimeout(r, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the acknowledgement flag is already in localStorage", async () => {
    localStorage.setItem("olympus_initial_secrets_seen", new Date().toISOString());
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    const { container } = render(<InitialSecretsModal />);
    await new Promise((r) => setTimeout(r, 0));
    expect(invoke).not.toHaveBeenCalled();
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when take_initial_secrets returns null (already taken)", async () => {
    const invoke = vi.fn().mockResolvedValue(null);
    stubTauri(invoke);
    const { container } = render(<InitialSecretsModal />);
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("take_initial_secrets"));
    expect(container).toBeEmptyDOMElement();
  });

  it("renders both secrets when take_initial_secrets returns a payload", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    expect(await screen.findByText(/FIRST LAUNCH/i)).toBeInTheDocument();
    expect(screen.getByText(VALID_KEY)).toBeInTheDocument();
    expect(screen.getByText(VALID_BJJ)).toBeInTheDocument();
    // Pre-fills both storage slots (the dual API/admin role of the system key)
    expect(mockedSetStoredAdminKey).toHaveBeenCalledWith(VALID_KEY);
    expect(mockedSetStoredApiKey).toHaveBeenCalledWith(VALID_KEY);
  });

  it("renders only the BJJ section when the API key is null", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: null,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    expect(await screen.findByText(VALID_BJJ)).toBeInTheDocument();
    expect(screen.queryByText(/ADMIN API KEY/i)).not.toBeInTheDocument();
  });

  it("dismiss button is disabled until both keys are copied or manualAck is checked", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    await screen.findByText(/FIRST LAUNCH/i);
    expect(screen.getByRole("button", { name: /COPY KEYS TO ENABLE/i })).toBeDisabled();
  });

  it("ticking the manual-ack checkbox unblocks the dismiss button", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    await screen.findByText(/FIRST LAUNCH/i);
    await userEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: /I'VE SAVED BOTH KEYS/i })).toBeEnabled();
  });

  it("dismiss writes the acknowledgement timestamp and unmounts the dialog", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    await screen.findByText(/FIRST LAUNCH/i);
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /I'VE SAVED BOTH KEYS/i }));

    expect(localStorage.getItem("olympus_initial_secrets_seen")).not.toBeNull();
    // unmount is timeout-driven (200ms in source); wait for it.
    await waitFor(() => expect(screen.queryByText(/FIRST LAUNCH/i)).not.toBeInTheDocument(), {
      timeout: 1000,
    });
  });

  it("the COPY API-key button writes to clipboard and the dismiss path enables if the BJJ side is also satisfied", async () => {
    const invoke = vi.fn().mockResolvedValue({
      system_api_key: VALID_KEY,
      bjj_authority_key_hex: VALID_BJJ,
    });
    stubTauri(invoke);
    render(<InitialSecretsModal />);
    await screen.findByText(/FIRST LAUNCH/i);

    const copyButtons = screen.getAllByRole("button", { name: /^COPY$/i });
    expect(copyButtons.length).toBeGreaterThanOrEqual(2);
    await userEvent.click(copyButtons[0]);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(VALID_KEY);
    await userEvent.click(copyButtons[1]);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(VALID_BJJ);

    expect(
      await screen.findByRole("button", { name: /I'VE SAVED BOTH KEYS/i }),
    ).toBeEnabled();
  });
});
