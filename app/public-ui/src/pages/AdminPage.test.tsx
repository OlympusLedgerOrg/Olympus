import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => ""),
  getStoredAdminKey: vi.fn(() => ""),
  setStoredAdminKey: vi.fn(),
}));

import { apiFetch } from "../lib/api";
import { getStoredAdminKey, getStoredApiKey, setStoredAdminKey } from "../lib/storage";
import AdminPage from "./AdminPage";

const mockedApiFetch = vi.mocked(apiFetch);
const mockedGetStoredApiKey = vi.mocked(getStoredApiKey);
const mockedGetStoredAdminKey = vi.mocked(getStoredAdminKey);
const mockedSetStoredAdminKey = vi.mocked(setStoredAdminKey);

beforeEach(() => {
  mockedApiFetch.mockReset();
  mockedGetStoredApiKey.mockReturnValue("");
  mockedGetStoredAdminKey.mockReturnValue("");
  mockedSetStoredAdminKey.mockReset();
  // navigator.clipboard isn't implemented in jsdom — stub so CopyField's
  // click handler doesn't throw and the surrounding flow keeps running.
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<AdminPage>", () => {
  it("renders the KEYS heading + ISSUE A KEY section", () => {
    render(<AdminPage />);
    expect(screen.getByRole("heading", { name: /KEYS/i })).toBeInTheDocument();
    expect(screen.getByText(/ISSUE A KEY TO ANOTHER USER/i)).toBeInTheDocument();
  });

  it("renders the YOUR API KEY block when a stored API key is present", () => {
    mockedGetStoredApiKey.mockReturnValue("oly_existing_key");
    render(<AdminPage />);
    // "YOUR API KEY" matches both the section header and "YOUR ADMIN API KEY"
    // input label, so query by the surrounding code element that displays
    // the stored key — only present when the conditional block renders.
    expect(screen.getByText("oly_existing_key")).toBeInTheDocument();
  });

  it("hides the YOUR API KEY block when no stored API key is set", () => {
    render(<AdminPage />);
    expect(screen.queryByText("ACTIVE KEY")).not.toBeInTheDocument();
  });

  it("pre-fills the admin-key field from getStoredAdminKey", () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key-from-storage");
    render(<AdminPage />);
    const adminInput = screen.getByPlaceholderText(/admin key/i) as HTMLInputElement;
    expect(adminInput.value).toBe("admin-key-from-storage");
  });

  it("falls back to the stored API key when no admin key is stored", () => {
    mockedGetStoredApiKey.mockReturnValue("api-as-admin-fallback");
    mockedGetStoredAdminKey.mockReturnValue("");
    render(<AdminPage />);
    const adminInput = screen.getByPlaceholderText(/admin key/i) as HTMLInputElement;
    expect(adminInput.value).toBe("api-as-admin-fallback");
  });

  it("validates that admin key is required before issuing", async () => {
    render(<AdminPage />);
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));
    expect(await screen.findByText(/Admin key required/i)).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("validates that email is required", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-x");
    render(<AdminPage />);
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));
    expect(await screen.findByText(/Email required/i)).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("rejects passwords shorter than 12 characters", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-x");
    render(<AdminPage />);
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "u@x.com");
    const pwInput = screen.getAllByRole("textbox").find(
      (el) => (el as HTMLInputElement).value.length >= 12,
    ) as HTMLInputElement;
    await userEvent.clear(pwInput);
    await userEvent.type(pwInput, "short");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));
    expect(await screen.findByText(/at least 12 characters/i)).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("submits a valid issue request and renders the issued credentials", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      email: "user@example.com",
      api_key: "oly_minted",
      user_id: "u-1",
      scopes: ["read", "verify"],
      role: "user",
    });

    render(<AdminPage />);
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "user@example.com");

    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(1));
    const [path, init] = mockedApiFetch.mock.calls[0];
    expect(path).toBe("/auth/admin/users");
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body.email).toBe("user@example.com");
    expect(body.role).toBe("user");

    expect(await screen.findByText(/KEY ISSUED/i)).toBeInTheDocument();
    expect(screen.getByText("oly_minted")).toBeInTheDocument();
    expect(mockedSetStoredAdminKey).toHaveBeenCalledWith("admin-key");
  });

  it("surfaces an error message when apiFetch rejects", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockRejectedValue(new Error("server says no"));

    render(<AdminPage />);
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "user@example.com");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));

    expect(await screen.findByText(/server says no/i)).toBeInTheDocument();
    expect(screen.queryByText(/KEY ISSUED/i)).not.toBeInTheDocument();
  });

  it("READ ONLY preset clamps scopes to read + verify", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      email: "u@x.com", api_key: "oly_x", user_id: "u-1", scopes: ["read", "verify"], role: "user",
    });

    render(<AdminPage />);
    await userEvent.click(screen.getByRole("button", { name: /READ ONLY/i }));
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "u@x.com");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    const body = JSON.parse(String(mockedApiFetch.mock.calls[0][1]?.body));
    expect(new Set(body.scopes)).toEqual(new Set(["read", "verify"]));
    expect(body.role).toBe("user");
  });

  it("ADMIN preset includes the admin scope and bumps role to admin", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      email: "u@x.com", api_key: "oly_x", user_id: "u-1",
      scopes: ["read", "verify", "ingest", "commit", "write", "admin"], role: "admin",
    });

    render(<AdminPage />);
    // Two buttons render the literal text "admin": the ADMIN preset (uppercase)
    // and the per-scope chip (lowercase). Match by exact text to disambiguate.
    await userEvent.click(screen.getByRole("button", { name: "ADMIN" }));
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "u@x.com");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    const body = JSON.parse(String(mockedApiFetch.mock.calls[0][1]?.body));
    expect(body.scopes).toContain("admin");
    expect(body.role).toBe("admin");
  });

  it("toggling an individual scope chip flips its membership in the request", async () => {
    mockedGetStoredAdminKey.mockReturnValue("admin-key");
    mockedApiFetch.mockResolvedValue({
      email: "u@x.com", api_key: "oly_x", user_id: "u-1", scopes: [], role: "user",
    });

    render(<AdminPage />);
    // Default preset is FULL WRITE (read+verify+ingest+commit+write).
    // Click "write" once to drop it from the set.
    await userEvent.click(screen.getByRole("button", { name: /^write$/ }));
    await userEvent.type(screen.getByPlaceholderText(/user@example.com/i), "u@x.com");
    await userEvent.click(screen.getByRole("button", { name: /ISSUE KEY/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    const body = JSON.parse(String(mockedApiFetch.mock.calls[0][1]?.body));
    expect(body.scopes).not.toContain("write");
  });
});
