import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// adminFetch now prefixes paths with getApiBase() (so the Tauri desktop hits
// the embedded Axum server, not the asset origin). Mock it to an empty base so
// the URL assertions below stay relative-path exact.
vi.mock("../lib/api", () => ({
  getApiBase: () => Promise.resolve(""),
}));

import AdminUsersPage from "./AdminUsersPage";

// Source uses raw `fetch` (with an x-admin-key header), not `apiFetch`,
// because the admin surface has its own authentication path.
function mockFetchOk(body: unknown, init: ResponseInit = {}) {
  const r = new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
  return vi.fn().mockResolvedValue(r);
}

function mockFetchErr(status: number, detail: string) {
  const r = new Response(JSON.stringify({ detail }), {
    status,
    headers: { "content-type": "application/json" },
  });
  return vi.fn().mockResolvedValue(r);
}

const SAMPLE_ROW = {
  user_id: "u-1",
  email: "user@example.com",
  role: "user",
  plan: "free",
  user_created_at: "2026-05-28T00:00:00Z",
  key_id: "key-aaa",
  key_name: "default",
  key_hash_prefix: "deadbe",
  key_scopes: '["read","verify"]',
  key_created_at: "2026-05-28T00:00:00Z",
};

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
  // The page fires a refresh fetch on every adminKey change via useEffect;
  // without a global stub, tests that don't care about fetch still hit a
  // "fetch is not defined" rejection that flips the page into loading state
  // and leaves the LOAD USERS button text as "LOADING…". Default stub
  // returns an empty rows list so the page settles into a stable shape.
  vi.stubGlobal("fetch", mockFetchOk({ rows: [] }));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<AdminUsersPage>", () => {
  it("renders the page heading + admin-key gate", () => {
    render(<AdminUsersPage />);
    expect(screen.getByRole("heading", { name: /ADMIN.*USERS/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /LOAD USERS|LOADING/i })).toBeDisabled();
  });

  it("LOAD USERS becomes available after the refresh settles", async () => {
    render(<AdminUsersPage />);
    // useEffect refires on every keystroke; set the value in one shot
    // via fireEvent.change so we don't fan out N fetches.
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /LOAD USERS$/i })).toBeEnabled(),
    );
  });

  it("GET /admin/users on LOAD USERS click + renders a user row", async () => {
    const fetchSpy = mockFetchOk({ rows: [SAMPLE_ROW] });
    vi.stubGlobal("fetch", fetchSpy);
    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await userEvent.click(screen.getByRole("button", { name: /LOAD USERS|LOADING/i }));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    // Inspect the LAST call (initial useEffect + the explicit click both
    // fire — assert on the most recent so we know LOAD USERS works).
    const calls = fetchSpy.mock.calls;
    const last = calls[calls.length - 1];
    expect(last[0]).toBe("/admin/users");
    expect((last[1]?.headers as Headers).get("x-admin-key")).toBe("admin-key");
    expect(await screen.findByText("user@example.com")).toBeInTheDocument();
  });

  it("surfaces backend error detail when the request fails", async () => {
    vi.stubGlobal("fetch", mockFetchErr(403, "forbidden"));
    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "bad-key" },
    });
    // useEffect → refresh fires automatically when adminKey changes; just
    // wait for the error span to land rather than racing the button click.
    expect(await screen.findByText(/forbidden/, undefined, { timeout: 3000 })).toBeInTheDocument();
  });

  it("shows the empty-state message when no users are returned", async () => {
    vi.stubGlobal("fetch", mockFetchOk({ rows: [] }));
    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    expect(
      await screen.findByText(/No users registered yet/i, undefined, { timeout: 3000 }),
    ).toBeInTheDocument();
  });

  it("mints a key when MINT is clicked and surfaces it in the just-minted banner", async () => {
    // Each fetch call matched by path so we don't have to track ordering
    // (the useEffect-driven refresh fan-out makes call counting brittle).
    const fetchSpy = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/admin/users") {
        return Promise.resolve(
          new Response(JSON.stringify({ rows: [SAMPLE_ROW] }), { status: 200 }),
        );
      }
      if (path === "/admin/users/u-1/keys" && init?.method === "POST") {
        return Promise.resolve(
          new Response(
            JSON.stringify({ raw_key: "oly_mint_xyz", scopes: ["read", "verify"] }),
            { status: 200 },
          ),
        );
      }
      return Promise.resolve(new Response("{}", { status: 200 }));
    });
    vi.stubGlobal("fetch", fetchSpy);

    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await userEvent.click(screen.getByRole("button", { name: /LOAD USERS|LOADING/i }));
    await screen.findByText("user@example.com");

    // The mint form's name input is the only other text input on the page
    // (the admin-key input above is type=password and so not a textbox role).
    const textInputs = screen.getAllByRole("textbox");
    await userEvent.type(textInputs[0], "mobile-app");
    // Button label is "MINT" (the source toggles to "…" while busy).
    await userEvent.click(screen.getByRole("button", { name: /^MINT$/ }));

    expect(await screen.findByText(/KEY MINTED/i)).toBeInTheDocument();
    expect(screen.getByText("oly_mint_xyz")).toBeInTheDocument();
  });

  it("revokes a key when REVOKE is clicked + confirmed", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    const fetchSpy = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/admin/keys/key-aaa" && init?.method === "DELETE") {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      // Default: rows fixture for /admin/users
      return Promise.resolve(
        new Response(JSON.stringify({ rows: [SAMPLE_ROW] }), { status: 200 }),
      );
    });
    vi.stubGlobal("fetch", fetchSpy);

    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await userEvent.click(screen.getByRole("button", { name: /LOAD USERS|LOADING/i }));
    await screen.findByText("user@example.com");

    await userEvent.click(screen.getByRole("button", { name: /^REVOKE$/i }));
    await waitFor(() =>
      expect(
        fetchSpy.mock.calls.some(
          ([p, init]) => p === "/admin/keys/key-aaa" && (init as RequestInit | undefined)?.method === "DELETE",
        ),
      ).toBe(true),
    );
    expect(confirmSpy).toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  // Loads a single user row and returns the path-routing fetch spy so each
  // test can assert on the specific mutation endpoint it exercises.
  async function loadOneUser(
    extra: (path: string, init?: RequestInit) => Response | undefined = () => undefined,
  ) {
    const fetchSpy = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
      const r = extra(path, init);
      if (r) return Promise.resolve(r);
      return Promise.resolve(
        new Response(JSON.stringify({ rows: [SAMPLE_ROW] }), { status: 200 }),
      );
    });
    vi.stubGlobal("fetch", fetchSpy);
    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await screen.findByText("user@example.com");
    return fetchSpy;
  }

  it("PROMOTE → ADMIN issues a PATCH to the role endpoint", async () => {
    const fetchSpy = await loadOneUser((path, init) =>
      path === "/admin/users/u-1/role" && init?.method === "PATCH"
        ? new Response("{}", { status: 200 })
        : undefined,
    );
    await userEvent.click(screen.getByRole("button", { name: /PROMOTE/i }));
    await waitFor(() =>
      expect(
        fetchSpy.mock.calls.some(
          ([p, i]) =>
            p === "/admin/users/u-1/role" &&
            (i as RequestInit | undefined)?.method === "PATCH" &&
            String((i as RequestInit).body).includes("admin"),
        ),
      ).toBe(true),
    );
  });

  it("an admin-role user shows DEMOTE and patches the role back to user", async () => {
    const fetchSpy = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/admin/users/u-1/role" && init?.method === "PATCH") {
        return Promise.resolve(new Response("{}", { status: 200 }));
      }
      return Promise.resolve(
        new Response(JSON.stringify({ rows: [{ ...SAMPLE_ROW, role: "admin" }] }), { status: 200 }),
      );
    });
    vi.stubGlobal("fetch", fetchSpy);
    render(<AdminUsersPage />);
    fireEvent.change(screen.getByPlaceholderText(/OLYMPUS_ADMIN_KEY/i), {
      target: { value: "admin-key" },
    });
    await screen.findByText("user@example.com");
    await userEvent.click(screen.getByRole("button", { name: /^DEMOTE$/i }));
    await waitFor(() =>
      expect(
        fetchSpy.mock.calls.some(
          ([p, i]) =>
            p === "/admin/users/u-1/role" &&
            String((i as RequestInit | undefined)?.body).includes('"user"'),
        ),
      ).toBe(true),
    );
  });

  it("surfaces the role-change error detail when the PATCH fails", async () => {
    await loadOneUser((path, init) =>
      path === "/admin/users/u-1/role" && init?.method === "PATCH"
        ? new Response(JSON.stringify({ detail: "role change denied" }), { status: 403 })
        : undefined,
    );
    await userEvent.click(screen.getByRole("button", { name: /PROMOTE/i }));
    expect(await screen.findByText(/role change denied/i)).toBeInTheDocument();
  });

  it("toggling an existing key's scope checkbox PATCHes the key scopes", async () => {
    const fetchSpy = await loadOneUser((path, init) =>
      path === "/admin/keys/key-aaa/scopes" && init?.method === "PATCH"
        ? new Response("{}", { status: 200 })
        : undefined,
    );
    // The SAMPLE_ROW key has scopes ["read","verify"]; the first 7 checkboxes
    // belong to that key row. Index 2 is "ingest" (unchecked) → enabling it
    // sends a PATCH adding "ingest".
    const checkboxes = screen.getAllByRole("checkbox");
    await userEvent.click(checkboxes[2]);
    await waitFor(() =>
      expect(
        fetchSpy.mock.calls.some(
          ([p, i]) =>
            p === "/admin/keys/key-aaa/scopes" &&
            String((i as RequestInit | undefined)?.body).includes("ingest"),
        ),
      ).toBe(true),
    );
  });

  it("MINT with an empty name shows the inline 'name is required' error", async () => {
    await loadOneUser();
    await userEvent.click(screen.getByRole("button", { name: /^MINT$/ }));
    expect(await screen.findByText(/name is required/i)).toBeInTheDocument();
  });

  it("surfaces the mint error detail when the keys POST fails", async () => {
    await loadOneUser((path, init) =>
      path === "/admin/users/u-1/keys" && init?.method === "POST"
        ? new Response(JSON.stringify({ detail: "quota exceeded" }), { status: 409 })
        : undefined,
    );
    const textInputs = screen.getAllByRole("textbox");
    await userEvent.type(textInputs[0], "laptop");
    await userEvent.click(screen.getByRole("button", { name: /^MINT$/ }));
    expect(await screen.findByText(/quota exceeded/i)).toBeInTheDocument();
  });

  it("toggling mint-form scope checkboxes flips selection both ways", async () => {
    await loadOneUser();
    const checkboxes = screen.getAllByRole("checkbox");
    // Mint-form scope checkboxes follow the 7 existing-key ones; default
    // selection is ["read","verify"]. checkboxes[7] is mint "read" (checked)
    // → unchecking it exercises the filter branch; [9] ("ingest") is
    // unchecked → checking it exercises the add branch of toggleScope.
    expect(checkboxes[7]).toBeChecked();
    await userEvent.click(checkboxes[7]);
    expect(checkboxes[7]).not.toBeChecked();
    await userEvent.click(checkboxes[9]);
    expect(checkboxes[9]).toBeChecked();
  });

  it("REVOKE is a no-op when the confirm dialog is dismissed", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    const fetchSpy = await loadOneUser();
    await userEvent.click(screen.getByRole("button", { name: /^REVOKE$/i }));
    expect(confirmSpy).toHaveBeenCalled();
    // No DELETE should have been issued.
    expect(
      fetchSpy.mock.calls.some(
        ([, i]) => (i as RequestInit | undefined)?.method === "DELETE",
      ),
    ).toBe(false);
    confirmSpy.mockRestore();
  });

  it("surfaces the revoke error detail when the DELETE fails", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    await loadOneUser((path, init) =>
      path === "/admin/keys/key-aaa" && init?.method === "DELETE"
        ? new Response(JSON.stringify({ detail: "key already revoked" }), { status: 404 })
        : undefined,
    );
    await userEvent.click(screen.getByRole("button", { name: /^REVOKE$/i }));
    expect(await screen.findByText(/key already revoked/i)).toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it("COPY writes the minted key to the clipboard and DISMISS clears the banner", async () => {
    await loadOneUser((path, init) =>
      path === "/admin/users/u-1/keys" && init?.method === "POST"
        ? new Response(JSON.stringify({ raw_key: "oly_copy_dismiss", scopes: ["read"] }), { status: 200 })
        : undefined,
    );
    const textInputs = screen.getAllByRole("textbox");
    await userEvent.type(textInputs[0], "key1");
    await userEvent.click(screen.getByRole("button", { name: /^MINT$/ }));
    await screen.findByText(/KEY MINTED/i);

    // The banner's COPY button is the first COPY-labelled control on the page.
    await userEvent.click(screen.getAllByRole("button", { name: /^COPY$/i })[0]);
    expect(vi.mocked(navigator.clipboard.writeText)).toHaveBeenCalledWith("oly_copy_dismiss");

    await userEvent.click(screen.getByRole("button", { name: /^DISMISS$/i }));
    await waitFor(() => expect(screen.queryByText(/KEY MINTED/i)).not.toBeInTheDocument());
  });
});
