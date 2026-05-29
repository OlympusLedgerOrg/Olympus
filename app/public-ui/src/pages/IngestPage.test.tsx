import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithSkin } from "../__tests__/render";
import IngestPage from "./IngestPage";
import { clearStoredApiKey, getStoredApiKey } from "../lib/storage";

// `hashFile` pulls in the BLAKE3 WASM module, which isn't worth loading in a
// unit test — stub it so we control the digest the page renders.
vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));
// `apiFetch` is the only network surface; stub it so COMMIT never hits a server.
vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));

import { hashFile } from "../lib/blake3";
import { apiFetch } from "../lib/api";

const mockHashFile = vi.mocked(hashFile);
const mockApiFetch = vi.mocked(apiFetch);

// A full 64-hex key so `apiKeyProblem()` (/^[0-9a-f]{64}$/i) accepts it and
// SAVE KEY actually persists it into the in-memory store.
const VALID_KEY = "a".repeat(64);
// A distinctive full-length (64-hex) digest. Asserting against the COMPLETE
// value — rather than a permissive `/ff{16,}/`-style substring — means the
// test only passes when the whole digest is rendered.
const MOCKED_DIGEST = "deadbeef".repeat(8);

beforeEach(() => {
  vi.clearAllMocks();
  // The API key lives in a module-level in-memory variable (see storage.ts —
  // it is deliberately NEVER written to localStorage). Reset it between tests.
  clearStoredApiKey();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<IngestPage>", () => {
  it("renders the COMMIT TO LEDGER heading", () => {
    renderWithSkin(<IngestPage />);
    expect(screen.getByRole("heading", { name: /COMMIT TO LEDGER/i })).toBeInTheDocument();
  });

  it("hashes a picked file and renders the full 64-hex BLAKE3 digest", async () => {
    mockHashFile.mockResolvedValue(MOCKED_DIGEST);
    renderWithSkin(<IngestPage />);

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["hello"], "hello.txt", { type: "text/plain" });
    // The file input is `display:none` (clicked via a styled drop zone), so
    // drive it with fireEvent.change rather than user.upload.
    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() => expect(mockHashFile).toHaveBeenCalledTimes(1));

    // Assert the COMPLETE 64-character hex digest is rendered — the matched
    // element's full text must equal MOCKED_DIGEST, so a partial/truncated
    // render would fail this test.
    const matches = await screen.findAllByText(
      (_, el) => el?.textContent === MOCKED_DIGEST,
    );
    expect(matches.length).toBeGreaterThan(0);
  });

  it("CLEAR KEY wipes the API key field and the persisted store", async () => {
    const user = userEvent.setup();
    renderWithSkin(<IngestPage />);

    const keyField = document.querySelector('input[type="password"]') as HTMLInputElement;
    await user.type(keyField, VALID_KEY);

    // Persist the key first via SAVE KEY so the test verifies clearing the
    // *stored* copy, not just the input. `getStoredApiKey()` reads the same
    // in-memory store the page writes to (the documented persistence surface —
    // the key is intentionally never put in localStorage).
    await user.click(screen.getByRole("button", { name: /SAVE KEY/i }));
    await waitFor(() => expect(getStoredApiKey()).toBe(VALID_KEY));

    await user.click(screen.getByRole("button", { name: /CLEAR KEY/i }));

    // Both the UI field and the persisted store must be empty.
    expect(keyField.value).toBe("");
    expect(getStoredApiKey()).toBe("");
  });

  it("gates COMMIT behind a valid API key", async () => {
    mockHashFile.mockResolvedValue(MOCKED_DIGEST);
    renderWithSkin(<IngestPage />);

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: { files: [new File(["hi"], "hi.txt", { type: "text/plain" })] },
    });

    // With no key entered the commit button is disabled and labelled as a prompt.
    const commitBtn = (await screen.findByRole("button", {
      name: /ENTER API KEY ABOVE TO COMMIT/i,
    })) as HTMLButtonElement;
    expect(commitBtn).toBeDisabled();
    expect(mockApiFetch).not.toHaveBeenCalled();
  });
});
